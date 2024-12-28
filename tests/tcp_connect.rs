mod common;
use anyhow::{Context, Result};
use common::{
    check_stdout_pattern, child_wait_with_timeout, cleanup_env, dump_stderr, dump_stdout, setup_env,
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
const TESTAPP_TCP_CLIENT_OPEN: &str = "_test_tcp_client_open";
const TESTAPP_TCP_SERVER_OPEN: &str = "_test_tcp_server_open";
const TEST_INITIALIZE: u64 = 50; // msec
const TEST_TIMEOUT: u64 = 10; // sec
const CLIENT_CONNECTTED: &str = "Socket connected!";
const SERVER_ACCEPTED: &str = "Socket accepted!";

#[test]
#[serial]
fn test_normal_3way_handshake_client() -> Result<()> {
    let mut suc = false;
    let expected_client_stdout = [CLIENT_CONNECTTED];
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
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_OPEN))
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
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLIENT_OPEN))?;
    if let Some(status) = child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))? {
        println!("status: {:?}", status);
        if status.success() && check_stdout_pattern(&mut client, &expected_client_stdout)? {
            suc = true;
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(suc, "Connection is not established correctly.");
    Ok(())
}

#[test]
#[serial]
fn test_normal_3way_handshake_server() -> Result<()> {
    let mut suc = false;
    let expected_server_stdout = [SERVER_ACCEPTED];
    let env_num: usize = 1;
    setup_env(env_num)?;
    let mut server = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_SERVER_OPEN))
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
        .context(format!("Failed to execute {}.", TESTAPP_TCP_SERVER_OPEN))?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Tcpip0")
        .arg("nc")
        .arg(NETWORK_DEV0.to_string())
        .arg(TCP_SERVER_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to execute server (nc).")?;
    if let Some(status) = child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))? {
        println!("status: {:?}", status);
        if status.success() && check_stdout_pattern(&mut server, &expected_server_stdout)? {
            suc = true;
        }
    }
    server.kill()?;
    server.wait()?;
    client.kill()?;
    client.wait()?;
    dump_stderr(&mut server)?;
    dump_stderr(&mut client)?;
    cleanup_env(env_num)?;
    assert!(suc, "Connection is not established correctly.");
    Ok(())
}

#[test]
#[serial]
fn test_normal_3way_handshake_both() -> Result<()> {
    let mut suc = false;
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
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_SERVER_OPEN))
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
        .context(format!("Failed to execute {}.", TESTAPP_TCP_SERVER_OPEN))?;
    let mut client = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev1")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_OPEN))
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLIENT_OPEN))?;
    if let Some(server_status) =
        child_wait_with_timeout(&mut server, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("server status: {:?}", server_status);
        if let Some(client_status) =
            child_wait_with_timeout(&mut client, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("client status: {:?}", client_status);
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
    assert!(suc, "Connection is not established correctly.");
    Ok(())
}

#[test]
#[serial]
fn test_simultaneous_open() -> Result<()> {
    let mut suc = false;
    let expected_stdout = [CLIENT_CONNECTTED];
    let env_num: usize = 1;
    setup_env(env_num)?;
    thread::sleep(Duration::from_millis(TEST_INITIALIZE));
    let mut client1 = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev0")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_OPEN))
        .arg("--iface")
        .arg("d0")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV0, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--dst")
        .arg(NETWORK_DEV1.to_string())
        .arg("--port")
        .arg(TCP_CLIENT_PORT.add(1).to_string())
        .arg("--lport")
        .arg(TCP_CLIENT_PORT.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLIENT_OPEN))?;
    let mut client2 = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg("Dev1")
        .arg(format!("{}{}", TESTAPP_PATH, TESTAPP_TCP_CLIENT_OPEN))
        .arg("--iface")
        .arg("d1")
        .arg("--network")
        .arg(format!("{}/{}", NETWORK_DEV1, SUBNETMASK))
        .arg("--gateway")
        .arg(GATEWAY.to_string())
        .arg("--dst")
        .arg(NETWORK_DEV0.to_string())
        .arg("--port")
        .arg(TCP_CLIENT_PORT.to_string())
        .arg("--lport")
        .arg(TCP_CLIENT_PORT.add(1).to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!("Failed to execute {}.", TESTAPP_TCP_CLIENT_OPEN))?;
    if let Some(status1) = child_wait_with_timeout(&mut client1, Duration::from_secs(TEST_TIMEOUT))?
    {
        println!("client1 status: {:?}", status1);
        if let Some(status2) =
            child_wait_with_timeout(&mut client2, Duration::from_secs(TEST_TIMEOUT))?
        {
            println!("client2 status: {:?}", status1);
            if status1.success()
                && check_stdout_pattern(&mut client1, &expected_stdout)?
                && status2.success()
                && check_stdout_pattern(&mut client2, &expected_stdout)?
            {
                suc = true;
            }
        }
    }
    client1.kill()?;
    client1.wait()?;
    client2.kill()?;
    client2.wait()?;
    dump_stderr(&mut client1)?;
    dump_stderr(&mut client2)?;
    cleanup_env(env_num)?;
    assert!(suc, "Connection is not established correctly.");
    Ok(())
}
