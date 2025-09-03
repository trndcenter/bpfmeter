use reqwest::blocking::get;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

use crate::common::utils::{ChildGuard, get_next_port};

mod common;

static EXE_BPFMETER: &str = env!("CARGO_BIN_EXE_bpfmeter");

#[test]
fn test_cpu_measurement() {
    let port = get_next_port();
    let mut child = Command::new(EXE_BPFMETER)
        .stdout(Stdio::piped())
        .args(["run", "--cpu-period", "1s", "-P", port.to_string().as_str()])
        .spawn()
        .expect("failed to start casr");

    // Wait for the child to start
    std::thread::sleep(std::time::Duration::from_millis(2000));
    match child.try_wait() {
        Ok(None) => {}
        _ => panic!("Child is not running"),
    };

    let stdout_handler = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout_handler);
    let mut stdout = String::new();
    reader.read_line(&mut stdout).expect("Cannot read stdout");
    reader.read_line(&mut stdout).expect("Cannot read stdout");
    assert!(
        stdout.contains(&format!(
            "Prometheus node exporter is running at port: {port}"
        )),
        "Prometheus node exporter is not started"
    );

    let url = format!("http://localhost:{port}/metrics");
    let response = get(url).expect("Cannot get metrics from prometheus node exporter");

    let reader = BufReader::new(response);
    let mut passed = false;
    for line in reader.lines().map_while(Result::ok) {
        if line.contains("ebpf_run_time") && line.contains("sys_enter_opena") {
            let metric = line
                .rsplit_once(' ')
                .expect("Cannot split metric line")
                .1
                .parse::<f64>()
                .expect("Cannot parse metric value");
            assert!(metric > 0.0, "CPU usage is 0");
            passed = true;
        }
    }
    assert!(passed, "CPU usage is not found for bpftrace program");
}

#[test]
fn test_map_measurement() {
    let port = get_next_port();
    let mut child = Command::new(EXE_BPFMETER)
        .stdout(Stdio::piped())
        .args([
            "run",
            "--disable-cpu",
            "--enable-maps",
            "--map-period",
            "1s",
            "-P",
            port.to_string().as_str(),
            "--export-types",
            "map-size",
        ])
        .spawn()
        .expect("failed to start casr");

    // Wait for the child to start
    std::thread::sleep(std::time::Duration::from_millis(2000));
    match child.try_wait() {
        Ok(None) => {}
        _ => panic!("Child is not running"),
    };

    let stdout_handler = child.stdout.take().unwrap();
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout_handler);
    let mut stdout = String::new();
    reader.read_line(&mut stdout).expect("Cannot read stdout");
    reader.read_line(&mut stdout).expect("Cannot read stdout");
    assert!(
        stdout.contains(&format!(
            "Prometheus node exporter is running at port: {port}"
        )),
        "Prometheus node exporter is not started {}",
        stdout
    );

    let url = format!("http://localhost:{port}/metrics");
    let response = get(url).expect("Cannot get metrics from prometheus node exporter");

    let reader = BufReader::new(response);
    let mut passed = false;
    for line in reader.lines().map_while(Result::ok) {
        if line.contains("ebpf_map_size") && line.contains("bpfmeter_map") {
            let metric = line
                .rsplit_once(' ')
                .expect("Cannot split metric line")
                .1
                .parse::<u64>()
                .expect("Cannot parse metric value");
            assert!(metric > 0, "Map size is 0");
            passed = true;
        }
    }
    assert!(passed, "Map size is not found for bpftrace map");
}
