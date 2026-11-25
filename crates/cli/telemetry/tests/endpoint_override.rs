//! Delivery through the endpoint override in the compiled telemetry library.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use strands_box_cli_telemetry::{
    ContextBuilder, ExitOutcome, InstallationId, Invocation, LaunchOutcome, Session,
};

const CHILD: &str = "BOX_TELEMETRY_ENDPOINT_TEST_CHILD";
const TEST: &str = "endpoint_override_reaches_the_local_receiver";

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("telemetry child did not finish");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn endpoint_override_reaches_the_local_receiver() {
    if std::env::var_os(CHILD).is_some() {
        let directory = tempfile::tempdir().unwrap();
        let started = SystemTime::now();
        let invocation = Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            ContextBuilder::new("1.2.3").unwrap().finish(),
            Instant::now(),
            started,
        )
        .unwrap();
        Session::delivering(invocation, LaunchOutcome::Confirmed(Some(started)))
            .expect("the local endpoint enables delivery")
            .finish_with_timeout(Instant::now(), ExitOutcome::Zero, Duration::from_secs(2));
        return;
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/box/ping", listener.local_addr().unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD, "1")
        .env("BOX_TEST_TELEMETRY_ENDPOINT", &endpoint)
        .env("HTTPS_PROXY", &endpoint)
        .env("https_proxy", &endpoint)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    child.kill().ok();
                    wait(&mut child);
                    panic!("the configured loopback receiver received no request");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept telemetry: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let _ = stream.set_nodelay(true);
    assert!(stream.nodelay().unwrap());
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    let mut length = 0;
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().unwrap();
        }
    }
    assert!(length <= 32 * 1024);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    drop(reader);
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
    drop(stream);
    assert!(wait(&mut child).success());
    assert_eq!(
        request, "POST /box/ping HTTP/1.1\r\n",
        "an ignored override reaches the local HTTPS proxy as CONNECT"
    );
    let events: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "run/1");
    assert_eq!(
        events[0]["data"],
        json!({"box_launched":true,"failure_reason":null,"startup_latency_ms":0})
    );
    assert_eq!(events[1]["event"], "shutdown/1");
    assert_eq!(events[1]["data"]["exit_outcome"], "zero");
    for key in ["v", "installation_id", "run_id", "context"] {
        assert_eq!(events[0][key], events[1][key]);
    }
}

#[test]
#[cfg(unix)]
fn non_utf8_endpoint_override_disables_delivery_in_the_compiled_library() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    if std::env::var_os(CHILD).is_some() {
        let directory = tempfile::tempdir().unwrap();
        let started = SystemTime::now();
        let invocation = Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            ContextBuilder::new("1.2.3").unwrap().finish(),
            Instant::now(),
            started,
        )
        .unwrap();
        assert!(
            Session::delivering(invocation, LaunchOutcome::Confirmed(Some(started))).is_none(),
            "a non-UTF-8 endpoint override must disable delivery"
        );
        return;
    }

    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = format!("http://{}", proxy.local_addr().unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "non_utf8_endpoint_override_disables_delivery_in_the_compiled_library",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD, "1")
        .env("BOX_TEST_TELEMETRY_ENDPOINT", OsStr::from_bytes(b"\xff"))
        .env("HTTPS_PROXY", &endpoint)
        .env("https_proxy", &endpoint)
        .spawn()
        .unwrap();
    assert!(wait(&mut child).success());
}
