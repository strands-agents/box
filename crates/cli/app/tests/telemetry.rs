//! Executable telemetry delivery to a local service.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROBE: &str = include_str!("../../../../test-corpus/profiles/probe/profile.toml");
const PROBE_POLICY: &str =
    r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);"#;

struct Request {
    line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Server {
    endpoint: String,
    requests: mpsc::Receiver<Result<Request, String>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        Self::responding(204)
    }

    fn responding(status: u16) -> Self {
        Self::responding_after(status, Duration::ZERO)
    }

    fn responding_after(status: u16, delay: Duration) -> Self {
        Self::responding_with_shutdown_ack(status, delay, None)
    }

    fn holding_shutdown() -> (Self, mpsc::SyncSender<()>) {
        let (acknowledge, acknowledged) = mpsc::sync_channel(1);
        (
            Self::responding_with_shutdown_ack(204, Duration::ZERO, Some(acknowledged)),
            acknowledge,
        )
    }

    fn responding_with_shutdown_ack(
        status: u16,
        delay: Duration,
        shutdown_ack: Option<mpsc::Receiver<()>>,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/box/ping", listener.local_addr().unwrap());
        let (sent, requests) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_request(&mut stream).map_err(|error| error.to_string());
                        let shutdown = request.as_ref().is_ok_and(|request| {
                            serde_json::from_slice::<Value>(&request.body).is_ok_and(|body| {
                                events_in(body)
                                    .iter()
                                    .any(|event| event["event"] == "shutdown/1")
                            })
                        });
                        let _ = sent.send(request);
                        if shutdown && let Some(acknowledged) = &shutdown_ack {
                            let _ = acknowledged.recv_timeout(Duration::from_secs(5));
                        }
                        let respond_at = Instant::now() + delay;
                        while Instant::now() < respond_at {
                            if stopped.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("accept telemetry request: {error}"),
                }
            }
        });
        Self {
            endpoint,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn invocation(&self) -> Vec<Value> {
        let mut events = Vec::new();
        let mut completed = false;
        loop {
            let wait = if completed {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            };
            let request = match self.requests.recv_timeout(wait) {
                Err(_) if completed => break,
                received => received
                    .expect("telemetry reaches the local service")
                    .expect("a complete HTTP request"),
            };
            assert_eq!(request.line, "POST /box/ping HTTP/1.1");
            assert_eq!(request.headers["content-type"], "application/json");
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("cookie"));
            assert!(request.body.len() <= 32 * 1024);
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert!(validator().is_valid(&body), "{body}");
            for event in events_in(body) {
                assert_eq!(
                    request.headers["user-agent"],
                    format!("box/{}", event["context"]["box_version"].as_str().unwrap()),
                    "{}",
                    event["event"]
                );
                completed |= event["event"] == "shutdown/1";
                events.push(event);
            }
            assert!(events.len() < 16, "bounded short invocation");
        }
        assert_eq!(events[0]["event"], "run/1");
        for event in &events[1..] {
            for field in ["v", "installation_id", "run_id", "context"] {
                assert_eq!(event[field], events[0][field], "{field}");
            }
        }
        self.assert_empty();
        events
    }

    fn assert_empty(&self) {
        assert!(
            self.requests.try_recv().is_err(),
            "unexpected telemetry request"
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim_end().to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if header == "\r\n" {
            break;
        }
        let (key, value) = header
            .split_once(':')
            .ok_or_else(|| io::Error::other("malformed request header"))?;
        headers.insert(key.to_ascii_lowercase(), value.trim().to_string());
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|length| length.parse().ok())
        .filter(|length| *length <= 32 * 1024)
        .ok_or_else(|| io::Error::other("missing or excessive body length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Request {
        line,
        headers,
        body,
    })
}

/// The events in a request body: one event, or each event in a batch.
fn events_in(body: Value) -> Vec<Value> {
    match body {
        Value::Array(events) => events,
        event => vec![event],
    }
}

fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../telemetry/tests/fixtures/box.schema.json"
        ))
        .unwrap();
        jsonschema::draft4::new(&schema).unwrap()
    })
}

struct Scene {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let parent = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".cache");
        std::fs::create_dir_all(&parent).unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("box-telemetry-")
            .tempdir_in(parent)
            .unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let scene = Self {
            _temporary: temporary,
            root,
        };
        std::fs::create_dir_all(scene.workspace()).unwrap();
        std::fs::create_dir_all(scene.box_home()).unwrap();
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.home().join("project")
    }

    fn box_home(&self) -> PathBuf {
        self.root.join("box-data")
    }

    fn profile(&self, name: &str, text: &str) {
        let folder = self.box_home().join("profiles").join(name);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("profile.toml"), text).unwrap();
    }

    fn command(&self, server: &Server) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
        command
            .env_clear()
            .env("HOME", self.home())
            .env("BOX_HOME", self.box_home())
            .env("PATH", "/usr/bin:/bin")
            .env("BOX_TEST_TELEMETRY_ENDPOINT", &server.endpoint)
            .env(
                "BOX_RESOURCES",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../resources"),
            )
            .current_dir(self.workspace())
            .stdin(Stdio::null());
        command
    }

    fn installation_id(&self) -> String {
        let text =
            std::fs::read_to_string(self.home().join(".strands/box/installation.toml")).unwrap();
        let installation: toml::Value = toml::from_str(&text).unwrap();
        installation["installation_id"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn assert_status(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_completed(events: &[Value], outcome: &str, core_outcome: Option<&str>) {
    let shutdown = events.last().unwrap();
    assert_eq!(shutdown["event"], "shutdown/1");
    assert_eq!(shutdown["data"]["exit_outcome"], outcome);
    assert_eq!(shutdown["data"]["core_outcome"], json!(core_outcome));
}

fn assert_core_failure_code(events: &[Value], code: Option<&str>) {
    assert_eq!(
        events.last().unwrap()["data"]["core_failure_code"],
        json!(code)
    );
}

fn decision_count(event: &Value, action: &str, outcome: &str) -> u64 {
    event["data"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|counter| counter["action"] == action && counter["outcome"] == outcome)
        .map(|counter| counter["count"].as_u64().unwrap())
        .sum()
}

#[test]
fn preparation_failures_deliver_run_and_shutdown_with_available_context() {
    let scene = Scene::new();
    let server = Server::start();
    scene.profile("invalid", "[");
    let mut previous_run = Value::Null;
    for (name, reason, profile_hash) in [
        ("bad name", "profile_invalid", Value::Null),
        ("../outside/profile.toml", "profile_missing", Value::Null),
        ("missing", "profile_missing", Value::Null),
        (
            "invalid",
            "profile_invalid",
            json!("245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811"),
        ),
    ] {
        let output = scene
            .command(&server)
            .args(["run", name, "--no-banner"])
            .output()
            .unwrap();
        assert_status(&output, 1);
        let events = server.invocation();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]["data"],
            json!({"box_launched": false, "failure_reason": reason, "startup_latency_ms": null})
        );
        assert_eq!(events[0]["installation_id"], scene.installation_id());
        assert_ne!(events[0]["run_id"], previous_run);
        assert_eq!(events[0]["context"]["profile_hash"], profile_hash);
        assert_completed(&events, "nonzero", None);
        previous_run = events[0]["run_id"].clone();
    }
}

#[test]
fn real_core_runs_flush_only_new_decisions_before_shutdown() {
    let scene = Scene::new();
    let server = Server::start();
    let profile = format!("policies = [\"policy.dw\"]\n{PROBE}");
    scene.profile("probe", &profile);
    std::fs::write(
        scene.box_home().join("profiles/probe/policy.dw"),
        PROBE_POLICY,
    )
    .unwrap();
    let first = scene
        .command(&server)
        .args([
            "run",
            "probe",
            "--no-banner",
            "--",
            "-c",
            "set -e; bash -c 'echo first > first.txt'; printf first",
        ])
        .output()
        .unwrap();
    assert_status(&first, 0);
    assert_eq!(first.stdout, b"first");
    let first_events = server.invocation();
    let runs: Vec<_> = std::fs::read_dir(scene.box_home().join("r"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1);
    let id = runs[0].file_name().unwrap().to_str().unwrap();
    let journal = runs[0].join("records.jsonl");
    let prior_journal = std::fs::read(&journal).unwrap();
    assert!(!prior_journal.is_empty());

    let second = scene
        .command(&server)
        .args([
            "run",
            "probe",
            "--box-id",
            id,
            "--no-banner",
            "--",
            "-c",
            "set -e; bash -c 'echo second > second.txt'; printf second; exit 37",
        ])
        .output()
        .unwrap();
    assert_status(&second, 37);
    assert_eq!(second.stdout, b"second");
    let second_events = server.invocation();
    let final_journal = std::fs::read(&journal).unwrap();
    assert!(final_journal.starts_with(&prior_journal));
    assert!(final_journal.len() > prior_journal.len());
    assert_eq!(
        std::fs::read_to_string(scene.workspace().join("first.txt")).unwrap(),
        "first\n"
    );
    assert_eq!(
        std::fs::read_to_string(scene.workspace().join("second.txt")).unwrap(),
        "second\n"
    );
    for (events, outcome) in [(&first_events, "zero"), (&second_events, "nonzero")] {
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[0]["data"]["box_launched"], true);
        assert!(events[0]["data"]["failure_reason"].is_null());
        assert!(events[0]["data"]["startup_latency_ms"].is_u64());
        assert_eq!(events[0]["installation_id"], scene.installation_id());
        assert_eq!(
            events[0]["context"]["profile_hash"],
            format!("{:x}", Sha256::digest(profile.as_bytes()))
        );
        assert_eq!(events[0]["context"]["profile_policy_present"], true);
        assert_eq!(events[1]["event"], "polling/1");
        assert_eq!(decision_count(&events[1], "fs:write", "permitted"), 1);
        assert!(decision_count(&events[1], "shell:exec", "permitted") >= 1);
        assert_completed(events, outcome, Some("ok"));
    }
    assert_ne!(first_events[0]["run_id"], second_events[0]["run_id"]);
}

#[test]
fn unavailable_identity_preserves_failure_without_delivery() {
    let scene = Scene::new();
    let server = Server::start();
    std::fs::create_dir_all(scene.home().join(".strands/box")).unwrap();
    std::fs::write(
        scene.home().join(".strands/box/installation.toml"),
        "installation_id = \"unavailable\"\n",
    )
    .unwrap();
    let output = scene
        .command(&server)
        .args(["run", "../outside", "--no-banner"])
        .output()
        .unwrap();
    assert_status(&output, 1);
    server.assert_empty();
}

#[test]
fn delivery_failures_preserve_the_workloads_exit_and_output() {
    let scene = Scene::new();
    let server = Server::responding(500);
    scene.profile("probe", PROBE);
    let first = scene
        .command(&server)
        .env_remove("BOX_TEST_TELEMETRY_ENDPOINT")
        .args(["run", "probe", "--no-banner", "--", "-c", "exit 0"])
        .output()
        .unwrap();
    assert_status(&first, 0);
    let runs: Vec<_> = std::fs::read_dir(scene.box_home().join("r"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1);
    let id = runs[0].file_name().unwrap().to_str().unwrap();
    let args = [
        "run",
        "probe",
        "--box-id",
        id,
        "--no-banner",
        "--",
        "-c",
        "printf preserved; printf workload-error >&2; exit 37",
    ];
    let control = scene
        .command(&server)
        .env_remove("BOX_TEST_TELEMETRY_ENDPOINT")
        .args(args)
        .output()
        .unwrap();
    assert_status(&control, 37);
    server.assert_empty();
    let failed_delivery = scene.command(&server).args(args).output().unwrap();
    assert_status(&failed_delivery, 37);
    assert_eq!(failed_delivery.stdout, control.stdout);
    assert_eq!(failed_delivery.stderr, control.stderr);
    assert_completed(&server.invocation(), "nonzero", Some("ok"));
}

#[test]
fn connection_failure_preserves_the_preparation_error_and_output() {
    let scene = Scene::new();
    let server = Server::start();
    let args = ["run", "missing", "--no-banner"];
    let control = scene
        .command(&server)
        .env_remove("BOX_TEST_TELEMETRY_ENDPOINT")
        .args(args)
        .output()
        .unwrap();
    assert_status(&control, 1);
    server.assert_empty();
    let mut command = scene.command(&server);
    drop(server);
    let failed_delivery = command.args(args).output().unwrap();
    assert_status(&failed_delivery, 1);
    assert_eq!(failed_delivery.stdout, control.stdout);
    assert_eq!(failed_delivery.stderr, control.stderr);
}

#[test]
fn loopback_test_delivery_bypasses_proxy_environment() {
    let scene = Scene::new();
    let receiver = Server::start();
    let proxy = Server::start();
    let mut command = scene.command(&receiver);
    for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        command.env(name, &proxy.endpoint);
    }
    for name in ["NO_PROXY", "no_proxy"] {
        command.env(name, "");
    }
    let output = command
        .args(["run", "missing", "--no-banner"])
        .output()
        .unwrap();
    assert_status(&output, 1);
    let events = receiver.invocation();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0]["data"],
        json!({"box_launched": false, "failure_reason": "profile_missing", "startup_latency_ms": null})
    );
    assert_completed(&events, "nonzero", None);
    proxy.assert_empty();
}

#[test]
fn a_stalled_failed_start_batch_is_bounded() {
    let scene = Scene::new();
    let server = Server::responding_after(204, Duration::from_millis(1500));
    let args = ["run", "missing", "--no-banner"];
    let control = scene
        .command(&server)
        .env_remove("BOX_TEST_TELEMETRY_ENDPOINT")
        .args(args)
        .output()
        .unwrap();
    assert_status(&control, 1);
    let mut child = scene
        .command(&server)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = match server.requests.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(request)) => request,
        _ => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "the local service receives the initial event: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "completion exceeds the bounded run and shutdown attempts: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let events = events_in(serde_json::from_slice(&request.body).unwrap());
    assert_eq!(
        events.len(),
        2,
        "a failed start sends its events in one batch"
    );
    assert_eq!(events[0]["event"], "run/1");
    assert_completed(&events, "nonzero", None);
    server.assert_empty();
    assert_status(&output, 1);
    assert_eq!(output.stdout, control.stdout);
    assert_eq!(output.stderr, control.stderr);
}

#[test]
fn sigint_attempts_shutdown_without_waiting_for_a_stalled_response() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    struct Running(std::process::Child);

    impl Drop for Running {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let scene = Scene::new();
    let (server, acknowledge_shutdown) = Server::holding_shutdown();
    scene.profile("probe", PROBE);
    let stdout = scene.root.join("stdout");
    let stderr = scene.root.join("stderr");
    let mut child = Running(
        scene
            .command(&server)
            .args([
                "run",
                "probe",
                "--no-banner",
                "--",
                "-c",
                "printf ready > ready; read -r line",
            ])
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
    );
    let ready = scene.workspace().join("ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "the workload becomes ready: {}",
            std::fs::read_to_string(&stderr).unwrap()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    kill(Pid::from_raw(child.0.id() as i32), Signal::SIGINT).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    acknowledge_shutdown.send(()).unwrap();
    let events = server.invocation();
    let output = Output {
        status: status.expect("the interrupted CLI exits within its 2 s telemetry budget"),
        stdout: std::fs::read(stdout).unwrap(),
        stderr: std::fs::read(stderr).unwrap(),
    };
    assert_status(&output, 130);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["data"]["box_launched"], true);
    assert_eq!(events[1]["event"], "polling/1");
    assert_eq!(events[0]["installation_id"], scene.installation_id());
    assert_completed(&events, "nonzero", Some("ok"));
}

#[test]
fn other_commands_do_not_start_delivery_or_create_identity() {
    let scene = Scene::new();
    let server = Server::start();
    scene.profile("probe", PROBE);
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["profile", "list"],
        vec!["profile", "show", "probe"],
        vec!["profile", "clean", "--all", "--no-ask"],
        vec!["profile", "delete", "probe", "--no-ask"],
    ] {
        let output = scene.command(&server).args(args).output().unwrap();
        assert_status(&output, 0);
        server.assert_empty();
        assert!(!scene.home().join(".strands/box/installation.toml").exists());
    }
}

#[test]
fn a_missing_core_credential_still_delivers_run_and_shutdown() {
    let scene = Scene::new();
    let server = Server::start();
    scene.profile(
        "p",
        &format!(
            "{PROBE}\n[egress.api]\ndestinations = [\"api.example.com\"]\n\
             secret.ref = \"env://BOX_TELEMETRY_MISSING_TEST_CREDENTIAL\"\n"
        ),
    );
    let output = scene
        .command(&server)
        .args([
            "run",
            "p",
            "--no-banner",
            "--",
            "-c",
            "printf should-not-run",
        ])
        .output()
        .unwrap();
    assert_status(&output, 1);
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "credential variable BOX_TELEMETRY_MISSING_TEST_CREDENTIAL is not set, or holds only whitespace"
        ),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = server.invocation();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "run/1");
    assert_eq!(
        events[0]["data"],
        json!({"box_launched": null, "failure_reason": null, "startup_latency_ms": null})
    );
    assert_completed(&events, "nonzero", None);
    // Core refused before it opened telemetry, so no `box_stopped` record exists; the run event
    // channel still names the failure.
    assert_core_failure_code(&events, Some("B0104"));
}

#[test]
fn opting_out_sends_nothing_and_creates_no_identity() {
    for (variables, saved) in [
        (&[("BOX_TELEMETRY", "0")][..], false),
        (&[("DO_NOT_TRACK", "1")][..], false),
        (&[][..], true),
    ] {
        let scene = Scene::new();
        let server = Server::start();
        scene.profile("probe", PROBE);
        if saved {
            let off = scene
                .command(&server)
                .args(["telemetry", "off"])
                .output()
                .unwrap();
            assert_status(&off, 0);
            assert_eq!(
                String::from_utf8_lossy(&off.stdout),
                "Telemetry is off (saved in ~/.strands/box/installation.toml).\n"
            );
        }
        let mut command = scene.command(&server);
        for (name, value) in variables {
            command.env(name, value);
        }
        let output = command
            .args(["run", "probe", "--no-banner", "--", "-c", "printf ran"])
            .output()
            .unwrap();
        assert_status(&output, 0);
        assert_eq!(output.stdout, b"ran", "{variables:?}");
        server.assert_empty();
        let metadata = std::fs::read_to_string(scene.home().join(".strands/box/installation.toml"))
            .unwrap_or_default();
        assert!(!metadata.contains("installation_id"), "{metadata}");
    }
}

#[test]
fn box_telemetry_overrides_a_saved_choice() {
    let scene = Scene::new();
    let server = Server::start();
    scene.profile("probe", PROBE);
    let off = scene
        .command(&server)
        .args(["telemetry", "off"])
        .output()
        .unwrap();
    assert_status(&off, 0);
    let output = scene
        .command(&server)
        .env("BOX_TELEMETRY", "1")
        .args(["run", "probe", "--no-banner", "--", "-c", "printf ran"])
        .output()
        .unwrap();
    assert_status(&output, 0);
    let events = server.invocation();
    assert_eq!(events[0]["installation_id"], scene.installation_id());
    assert_completed(&events, "zero", Some("ok"));
    assert_core_failure_code(&events, None);
}

#[test]
fn a_box_telemetry_value_that_is_not_utf8_sends_nothing_and_creates_no_identity() {
    use std::os::unix::ffi::OsStrExt as _;

    let scene = Scene::new();
    let server = Server::start();
    scene.profile("probe", PROBE);
    let output = scene
        .command(&server)
        .env("BOX_TELEMETRY", std::ffi::OsStr::from_bytes(&[0xff]))
        .args(["run", "probe", "--no-banner", "--", "-c", "printf ran"])
        .output()
        .unwrap();
    assert_status(&output, 0);
    assert_eq!(output.stdout, b"ran");
    std::thread::sleep(Duration::from_millis(300));
    server.assert_empty();
    assert!(!scene.home().join(".strands/box/installation.toml").exists());
}
