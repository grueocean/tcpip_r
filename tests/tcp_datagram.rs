mod common;
use anyhow::{Context, Result};
use common::{
    check_stdout_pattern, child_wait_with_timeout, cleanup_env, clear_drop, dump_stderr,
    insert_drop, setup_env,
};
use rstest::*;
use serial_test::serial;
use std::ops::Add;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const TCP_CLIENT_PORT: usize = 1200;
const TCP_SERVER_PORT: usize = 2000;
const GATEWAY: &str = "172.20.10.1";
const NETWORK_DEV0: &str = "172.20.10.100";
const NETWORK_DEV1: &str = "172.20.10.101";
const NETWORK_TCPIP0: &str = "172.20.10.110";
const NETWORK_TCPIP1: &str = "172.20.10.111";
const SUBNETMASK: usize = 24;
const TESTAPP_PATH: &str = "./target/debug/examples/";
const TESTAPP_TCP_CLIENT_DATA_RECV: &str = "_test_tcp_client_data_recv";
const TESTAPP_TCP_SERVER_DATA_SEND: &str = "_test_tcp_server_data_send";
const TESTAPP_TCP_CLIENT_DATA_SEND: &str = "_test_tcp_client_data_send";
const TESTAPP_TCP_SERVER_DATA_RECV: &str = "_test_tcp_server_data_recv";
const TEST_INITIALIZE: u64 = 100; // msec
const TEST_TIMEOUT: u64 = 10; // sec
const CLIENT_CONNECTTED: &str = "Socket connected!";
const SERVER_ACCEPTED: &str = "Socket accepted!";
const TEST_DATA_DIR: &str = "./tests/test_data/";

#[rstest]
#[case("rand_10", 10, 10)]
#[case("rand_100", 100, 100)]
#[case("rand_1024", 1024, 1024)]
#[case("rand_4096", 1024, 4096)]
#[case("rand_8192", 1024, 8192)]
#[case("rand_10000", 1024, 10000)]
#[serial]
fn test_normal_datagram_server_to_client(
    #[case] file_name: &str,
    #[case] buffer_size: usize,
    #[case] transfer_size: usize,
) -> Result<()> {
    println!(
        "FILENAME: {} BUF_SIZE: {} SIZE: {}",
        file_name, buffer_size, transfer_size
    );
    pub struct TestResult {
        connect: bool,
        server: bool,
        client: bool,
    }
    let mut result = TestResult {
        connect: false,
        server: false,
        client: false,
    };
    let expected_server_stdout = [SERVER_ACCEPTED];
    let expected_client_stdout = [CLIENT_CONNECTTED];
    let env_num: usize = 1;
    setup_env(env_num)?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut server = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_SERVER_DATA_SEND))
        .arg("--iface")
        .arg("d0")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .arg("--file")
        .arg(format!("{}{}", TEST_DATA_DIR, file_name))
        .arg("--buf")
        .arg(buffer_size.to_string())
        .arg("--size")
        .arg(transfer_size.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to execute {}.",
            TESTAPP_TCP_SERVER_DATA_SEND
        ))?;
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev1")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_DATA_RECV))
        .arg("--iface")
        .arg("d1")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV1, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--dst")
        .arg(NETWORK_DEV0.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .arg("--file")
        .arg(format!("{}{}", TEST_DATA_DIR, file_name))
        .arg("--size")
        .arg(transfer_size.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to execute {}.",
            TESTAPP_TCP_CLIENT_DATA_RECV
        ))?;
    if let Some(server_status) =
        child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("server status: {:?}", server_status);
        if let Some(client_status) =
            child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("client status: {:?}", client_status);
            result.server = server_status.success();
            result.client = client_status.success();
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    if check_stdout_pattern(&mut server, &expected_server_stdout)?
        && check_stdout_pattern(&mut client, &expected_client_stdout)?
    {
        result.connect = true;
    }
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(result.connect, "Failed to establish connection.");
    assert!(result.server, "Server abnormally exited.");
    assert!(result.client, "Client abnormally exited.");
    Ok(())
}

#[rstest]
#[case("rand_10", 10, 10)]
#[case("rand_100", 100, 100)]
#[case("rand_1024", 1024, 1024)]
#[case("rand_4096", 1024, 4096)]
#[case("rand_8192", 1024, 8192)]
#[case("rand_10000", 1024, 10000)]
#[serial]
fn test_normal_datagram_client_to_server(
    #[case] file_name: &str,
    #[case] buffer_size: usize,
    #[case] transfer_size: usize,
) -> Result<()> {
    println!(
        "FILENAME: {} BUF_SIZE: {} SIZE: {}",
        file_name, buffer_size, transfer_size
    );
    pub struct TestResult {
        connect: bool,
        server: bool,
        client: bool,
    }
    let mut result = TestResult {
        connect: false,
        server: false,
        client: false,
    };
    let expected_server_stdout = [SERVER_ACCEPTED];
    let expected_client_stdout = [CLIENT_CONNECTTED];
    let env_num: usize = 1;
    setup_env(env_num)?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut server = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_SERVER_DATA_RECV))
        .arg("--iface")
        .arg("d0")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .arg("--file")
        .arg(format!("{}{}", TEST_DATA_DIR, file_name))
        .arg("--size")
        .arg(transfer_size.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to execute {}.",
            TESTAPP_TCP_SERVER_DATA_SEND
        ))?;
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev1")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_DATA_SEND))
        .arg("--iface")
        .arg("d1")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV1, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--dst")
        .arg(NETWORK_DEV0.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .arg("--file")
        .arg(format!("{}{}", TEST_DATA_DIR, file_name))
        .arg("--buf")
        .arg(buffer_size.to_string())
        .arg("--size")
        .arg(transfer_size.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to execute {}.",
            TESTAPP_TCP_CLIENT_DATA_RECV
        ))?;
    if let Some(server_status) =
        child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("server status: {:?}", server_status);
        if let Some(client_status) =
            child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("client status: {:?}", client_status);
            result.server = server_status.success();
            result.client = client_status.success();
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    if check_stdout_pattern(&mut server, &expected_server_stdout)?
        && check_stdout_pattern(&mut client, &expected_client_stdout)?
    {
        result.connect = true;
    }
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(result.connect, "Failed to establish connection.");
    assert!(result.server, "Server abnormally exited.");
    assert!(result.client, "Client abnormally exited.");
    Ok(())
}

// #[rstest]
// #[case("rand_10", 10, 10)]
// #[case("rand_100", 100, 100)]
// #[case("rand_1024", 1024, 1024)]
// #[case("rand_4096", 1024, 4096)]
// #[case("rand_8192", 1024, 8192)]
// #[case("rand_10000", 1024, 10000)]
// #[serial]
// fn test_normal_datagram_drop(
//     #[case] file_name: &str,
//     #[case] buffer_size: usize,
//     #[case] transfer_size: usize,
// ) -> Result<()> {
//     println!("FILENAME: {} BUF_SIZE: {} SIZE: {}", file_name, buffer_size, transfer_size);
//     pub struct TestResult {
//         connect: bool,
//         server: bool,
//         client: bool,
//     }
//     let mut result = TestResult { connect: false, server: false, client: false };
//     let expected_server_stdout = [SERVER_ACCEPTED];
//     let expected_client_stdout = [CLIENT_CONNECTTED];
//     let env_num: usize = 1;
//     setup_env(env_num)?;
//     insert_drop(env_num, 50)?;
//     thread::sleep(Duration::from_millis(TEST_INITIALIZE));
//     let mut server = Command::new("sudo")
//         .arg("ip")
//         .arg("netns")
//         .arg("exec")
//         .arg("Dev0")
//         .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_SERVER_DATA_SEND))
//         .arg("--iface").arg("d0")
//         .arg("--network").arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
//         .arg("--gateway").arg(GATEWAY.to_string())
//         .arg("--port").arg(TCP_SERVER_PORT.to_string())
//         .arg("--file").arg(format!("{}{}", TEST_DATA_DIR, file_name))
//         .arg("--buf").arg(buffer_size.to_string())
//         .arg("--size").arg(transfer_size.to_string())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .context(format!("Failed to execute {}.", TESTAPP_TCP_SERVER_DATA_SEND))?;
//     let mut client = Command::new("sudo")
//         .arg("ip")
//         .arg("netns")
//         .arg("exec")
//         .arg("Dev1")
//         .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_DATA_RECV))
//         .arg("--iface").arg("d1")
//         .arg("--network").arg(format!("{}/{}", NETWORK_DEV1, SUBNETMASK))
//         .arg("--gateway").arg(GATEWAY.to_string())
//         .arg("--dst").arg(NETWORK_DEV0.to_string())
//         .arg("--port").arg(TCP_SERVER_PORT.to_string())
//         .arg("--file").arg(format!("{}{}", TEST_DATA_DIR, file_name))
//         .arg("--size").arg(transfer_size.to_string())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .context(format!("Failed to execute {}.", TESTAPP_TCP_CLIENT_DATA_RECV))?;
//     if let Some(server_status) = child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))? {
//         println!("server status: {:?}", server_status);
//         if let Some(client_status) = child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))? {
//             println!("client status: {:?}", client_status);
//             if check_stdout_pattern(&mut server, &expected_server_stdout)? && check_stdout_pattern(&mut client, &expected_client_stdout)? {
//                 result.connect = true;
//             }
//             result.server = server_status.success();
//             result.client = client_status.success();
//         }
//     }
//     server.kill()?;
//     server.wait()?;
//     client.kill()?;
//     client.wait()?;
//     dump_stderr(&mut server)?;
//     dump_stderr(&mut client)?;
//     clear_drop(env_num)?;
//     cleanup_env(env_num)?;
//     assert!(result.connect, "Failed to establish connection.");
//     assert!(result.server, "Server abnormally exited.");
//     assert!(result.client, "Client abnormally exited.");
//     Ok(())
// }
