use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Instant, Duration};
use anyhow::{Result, Context};

const SCRIPT_PATH: &str = "./env/";
const SCRIPT_BASE: &str = "env";
const CREATE_COMMAND: &str = "create";
const DELETE_COMMAND: &str = "delete";

fn is_netns_clean() -> Result<()> {
    let out = Command::new("ip")
        .arg("netns")
        .output()
        .context("Failed to check nents")?;

    if out.stdout.len() == 0 && out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("Netns check failed. out={:?}", out)
    }
}

fn create_env(script_num: usize) -> Result<()> {
    let script = format!("{}{}{}.sh", SCRIPT_PATH, SCRIPT_BASE, script_num);
    if !Path::new(&script).exists() {
        anyhow::bail!("No {} found.", script);
    }
    let out = Command::new("sudo")
        .arg("sh")
        .arg(script)
        .arg(CREATE_COMMAND)
        .output()
        .context("Failed to create network namespace.")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("Create netns failed. out={:?}", out)
    }
}

fn delete_env(script_num: usize) -> Result<()> {
    let script = format!("{}{}{}.sh", SCRIPT_PATH, SCRIPT_BASE, script_num);
    if !Path::new(&script).exists() {
        anyhow::bail!("No {} found.", script);
    }
    let out = Command::new("sudo")
        .arg("sh")
        .arg(script)
        .arg(DELETE_COMMAND)
        .output()
        .context("Failed to delete network namespace.")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("Delete netns failed. out={:?}", out)
    }
}

fn build_examples() -> Result<()> {
    let out = Command::new("cargo")
        .arg("build")
        .arg("--examples")
        .output()
        .context("Failed to build examples.")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("Build examples failed. out={:?}", out)
    }
}

pub fn setup_env(script_num: usize) -> Result<()> {
    is_netns_clean()?;
    create_env(script_num)?;
    build_examples()?;
    Ok(())
}

pub fn cleanup_env(script_num: usize) -> Result<()> {
    delete_env(script_num)?;
    is_netns_clean()?;
    Ok(())
}

pub fn child_wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Some(status));
            }
            Ok(None) => {}
            Err(e) => {
                anyhow::bail!("Error waiting for child. {:?}", e)
            }
        }
    }
    Ok(None)
}

pub fn check_stdout_pattern(child: &mut Child, patterns: &[&str]) -> Result<bool> {
    let stdout = child.stdout.take().context("Cannot take stdout from child.")?;
    let output: String = BufReader::new(stdout).lines().collect::<Result<Vec<_>, _>>()?.join("\n");
    println!("output: {}", output);
    Ok(patterns.iter().all(|pattern| output.contains(pattern)))
}

pub fn dump_stderr(child: &mut Child) -> Result<()> {
    println!("=== Dump stderr start id={} ===", child.id());
    let stderr = child.stderr.take().context("Cannot take stderr from child.")?;
    for line in BufReader::new(stderr).lines() {
        println!("{}", line.context("Failed to read line")?);
    }
    println!("=== Dump stderr end id={} ===", child.id());
    Ok(())
}