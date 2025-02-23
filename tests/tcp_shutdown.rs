mod common;
use anyhow::{Context, Result};
use common::{
    check_stdout_pattern, child_wait_with_timeout, cleanup_env, dump_stderr, dump_stdout,
    insert_drop, setup_env,
};
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
const TESTAPP_TCP_OPEN_CLIENT: &str = "_test_tcp_open_client";
const TESTAPP_TCP_OPEN_SERVER: &str = "_test_tcp_open_server";
const TESTAPP_TCP_CLOSE_CLIENT: &str = "_test_tcp_close_client";
const TESTAPP_TCP_CLOSE_SERVER: &str = "_test_tcp_close_server";
const TEST_INITIALIZE: u64 = 50; // msec
const TEST_TIMEOUT: u64 = 10; // sec
const TEST_TIMEOUT_DROP: u64 = 30; // sec
const CLIENT_CONNECTTED: &str = "Socket connected!";
const SERVER_ACCEPTED: &str = "Socket accepted!";
const SHUTDOWN: &str = "Socket shutdown.";

#[test]
#[serial]
fn test_normal_shutdown_client() -> Result<()> {
    let mut suc = false;
    let expected_client_stdout = [CLIENT_CONNECTTED, SHUTDOWN];
    let env_num: usize = 1;
    setup_env(env_num)?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut server = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Tcpip0")
        .arg("nc")
        .arg("-l")
        .arg(TCP_SERVER_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to execut server (nc).")?;
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLOSE_CLIENT))
        .arg("--iface")
        .arg("d0")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--dst")
        .arg(NETWORK_TCPIP0.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLOSE_CLIENT))?;
    if let Some(client_status) =
        child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("client status: {:?}", client_status);
        if let Some(server_status) =
            child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("server status: {:?}", server_status);
            if client_status.success()
                && check_stdout_pattern(&mut client, &expected_client_stdout)?
                && server_status.success()
            {
                suc = true;
            }
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(suc, "Connection is not closed correctly.");
    Ok(())
}

#[test]
#[serial]
fn test_normal_shutdown_both() -> Result<()> {
    let mut suc = false;
    let expected_server_stdout = [SERVER_ACCEPTED, SHUTDOWN];
    let expected_client_stdout = [CLIENT_CONNECTTED, SHUTDOWN];
    let env_num: usize = 1;
    setup_env(env_num)?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut server = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLOSE_SERVER))
        .arg("--iface")
        .arg("d0")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--port")
        .arg(TCP_SERVER_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLOSE_SERVER))?;
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev1")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLOSE_CLIENT))
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
        .arg("--lport")
        .arg(TCP_CLIENT_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLOSE_CLIENT))?;
    if let Some(server_status) =
        child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("server_status: {:?}", server_status);
        if let Some(client_status) =
            child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("client_status: {:?}", server_status);
            if server_status.success()
                && check_stdout_pattern(&mut server, &expected_server_stdout)?
                && client_status.success()
                && check_stdout_pattern(&mut client, &expected_client_stdout)?
            {
                suc = true;
            }
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(suc, "Connection is not closed correctly.");
    Ok(())
}

// #[test]
// #[serial]
// fn test_normal_shutdown_client_drop() -> Result<()> {
//     let mut suc = false;
//     let expected_client_stdout = [CLIENT_CONNECTTED, SHUTDOWN];
//     let env_num: usize = 1;
//     setup_env(env_num)?;
//     insert_drop(env_num, 30)?;
//     thread::sleep(Duration::from_millis(TEST_INITIALIZE));
//     let mut server = Command::new("sudo")
//         .arg("ip")
//         .arg("netns")
//         .arg("exec")
//         .arg("Tcpip0")
//         .arg("nc")
//         .arg("-l")
//         .arg(TCP_SERVER_PORT.to_string())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .context("Failed to execut server (nc).")?;
//     let mut client = Command::new("sudo")
//         .arg("ip")
//         .arg("netns")
//         .arg("exec")
//         .arg("Dev0")
//         .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLOSE_CLIENT))
//         .arg("--iface")
//         .arg("d0")
//         .arg("--network")
//         .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
//         .arg("--gateway")
//         .arg(GATEWAY.to_string())
//         .arg("--dst")
//         .arg(NETWORK_TCPIP0.to_string())
//         .arg("--port")
//         .arg(TCP_SERVER_PORT.to_string())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .context(format!("Failed to execute {}.", TESTAPP_TCP_CLOSE_CLIENT))?;
//     if let Some(client_status) =
//         child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT_DROP))?
//     {
//         println!("client status: {:?}", client_status);
//         if let Some(server_status) =
//             child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
//         {
//             println!("server status: {:?}", server_status);
//             if client_status.success()
//                 && check_stdout_pattern(&mut client, &expected_client_stdout)?
//                 && server_status.success()
//             {
//                 suc = true;
//             }
//         }
//     }
//     server.kill()?;
//     server.wait()?;
//     client.kill()?;
//     client.wait()?;
//     dump_stderr(&mut server)?;
//     dump_stderr(&mut client)?;
//     cleanup_env(env_num)?;
//     assert!(suc, "Connection is not closed correctly.");
//     Ok(())
// }