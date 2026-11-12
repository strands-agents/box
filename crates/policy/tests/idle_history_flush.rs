//! Exercises idle persistence through Box's real policy facade and killed child processes.

#![cfg(all(feature = "experimental-idle-flush", unix))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use dogwood_language::Value;
use dogwood_local_engine::{DurableLog, Record};
use policy::{
    Decision, DenyReason, FsOperation, FsResult, GovernedBox, HistoryFlusher, Outcome,
    PathResolver, Policy, PolicyEngine, Principal, Request,
};
use serde_json::{Value as Json, json};

const HISTORY_POLICY: &str = r#"
permit(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 1h (
        Box::Action::"fs:read"::response{
            input.operation: Box::FsReadOperation::"read_content"
        }
    )
};
"#;
const WRITE_POLICY: &str = r#"permit(principal, action == Box::Action::"fs:write", resource);"#;
const CHILD_MODE: &str = "BOX_IDLE_FLUSH_CHILD_MODE";
const CHILD_DIR: &str = "BOX_IDLE_FLUSH_CHILD_DIR";
const CHILD_DEADLINE: Duration = Duration::from_secs(25);
const TIMER_INTERVAL: Duration = Duration::from_secs(1);
const BURST_EVENTS: usize = 5;
const WRITERS: usize = 4;
const WRITES_PER_WRITER: usize = 40;

fn open_policy(directory: &Path, source: &str) -> Arc<PolicyEngine> {
    Arc::new(
        PolicyEngine::open(
            vec![Policy {
                origin: directory.join("policy.dw"),
                text: source.to_owned(),
            }],
            &directory.join("history.redb"),
        )
        .expect("the test policy opens"),
    )
}

fn resolver(directory: &Path) -> PathResolver {
    PathResolver::over([directory.to_path_buf()]).expect("the fixture root is absolute")
}

fn write_allowed(policy: &PolicyEngine, directory: &Path) -> bool {
    let path = resolver(directory)
        .approve_host(&directory.join("target.txt"))
        .expect("the target path resolves");
    let (decision, _) = policy.decide(
        &GovernedBox::assigned("idle-flush-test"),
        &Principal::agent(),
        &Request::Fs {
            path: &path,
            operation: FsOperation::WriteContent,
        },
    );
    match decision {
        Decision::Allow { .. } => true,
        Decision::Deny {
            reason: DenyReason::Forbidden,
            ..
        } => false,
        other => panic!("expected an explicit permit or history forbid, received {other:?}"),
    }
}

fn write_file(policy: &PolicyEngine, directory: &Path, filename: &str) {
    let path = resolver(directory)
        .approve_host(&directory.join(filename))
        .expect("the write path resolves");
    let governed = GovernedBox::assigned("idle-flush-test");
    let principal = Principal::agent();
    let (decision, request_id) = policy.decide(
        &governed,
        &principal,
        &Request::Fs {
            path: &path,
            operation: FsOperation::WriteContent,
        },
    );
    assert!(
        decision.is_allow(),
        "the request must be allowed before its effect runs"
    );
    let request_id = request_id.expect("an allowed request has a confirmed history token");
    fs::write(path.as_path(), b"harmless test marker").expect("the allowed file write runs");
    policy
        .record(
            &governed,
            &principal,
            &request_id,
            &Outcome::Fs {
                path: path.as_path(),
                operation: FsOperation::WriteContent,
                result: FsResult::Completed,
            },
        )
        .expect("the completed write records");
}

fn history_burst(policy: &PolicyEngine, directory: &Path) {
    write_file(policy, directory, "target.txt");
    let path = resolver(directory)
        .approve_host(&directory.join("trigger.txt"))
        .expect("the read path resolves");
    let governed = GovernedBox::assigned("idle-flush-test");
    let principal = Principal::agent();
    let (decision, request_id) = policy.decide(
        &governed,
        &principal,
        &Request::Fs {
            path: &path,
            operation: FsOperation::ReadContent,
        },
    );
    assert!(
        decision.is_allow(),
        "the request must be allowed before its effect runs"
    );
    let request_id = request_id.expect("an allowed request has a confirmed history token");
    assert_eq!(
        fs::read(path.as_path()).expect("the allowed read runs"),
        b"read marker"
    );
    policy
        .record(
            &governed,
            &principal,
            &request_id,
            &Outcome::Fs {
                path: path.as_path(),
                operation: FsOperation::ReadContent,
                result: FsResult::Completed,
            },
        )
        .expect("the completed read records");
    assert!(
        !write_allowed(policy, directory),
        "the live history must deny a later write"
    );
    assert_eq!(
        fs::read(directory.join("target.txt")).expect("the target remains readable"),
        b"harmless test marker",
        "the denied write must leave the target unchanged"
    );
}

fn wait_for_flushes(flusher: &HistoryFlusher, minimum: u64) -> Json {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let snapshot = flusher.snapshot();
        assert_eq!(
            snapshot.failures, 0,
            "the timer must not silently fail: {snapshot:?}"
        );
        if snapshot.successes >= minimum {
            return json!({
                "attempts": snapshot.attempts,
                "successes": snapshot.successes,
                "failures": snapshot.failures,
            });
        }
        assert!(
            Instant::now() < deadline,
            "no completed timer flush before the deadline: {snapshot:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn signal_ready(directory: &Path, value: Json) {
    let path = directory.join("ready.tmp");
    let mut file = File::create(&path).expect("the child readiness file opens");
    serde_json::to_writer(&mut file, &value).expect("the readiness report serializes");
    file.flush()
        .expect("the readiness report reaches the parent");
    fs::rename(path, directory.join("ready.json"))
        .expect("the complete readiness report publishes");
}

#[test]
#[ignore = "Subprocess entry point; the parent tests invoke it with an explicit mode."]
fn subprocess_entrypoint() {
    let mode = std::env::var(CHILD_MODE).expect("the parent supplies a child mode");
    let directory =
        PathBuf::from(std::env::var(CHILD_DIR).expect("the parent supplies a fixture directory"));
    let source = if mode == "concurrent" {
        WRITE_POLICY
    } else {
        HISTORY_POLICY
    };
    let policy = open_policy(&directory, source);
    policy
        .set_periodic_history(u32::MAX, Duration::from_secs(3600))
        .expect("the child selects periodic persistence without submission-triggered flushes");
    let started = Instant::now();
    let mut held_flusher = None;
    let report = match mode.as_str() {
        "timer-off" => {
            history_burst(&policy, &directory);
            // This wait is the behavior under test: no submissions arrive during idle time.
            thread::sleep(TIMER_INTERVAL + Duration::from_millis(200));
            json!({"mode": mode, "accepted_events": BURST_EVENTS, "idle_ms": started.elapsed().as_millis()})
        }
        "timer-before-first-tick" => {
            history_burst(&policy, &directory);
            let flusher = policy
                .start_history_flusher(Duration::from_secs(60))
                .expect("the long-interval timer starts");
            let snapshot = flusher.snapshot();
            assert_eq!(
                snapshot.attempts, 0,
                "the first timer deadline has not passed"
            );
            held_flusher = Some(flusher);
            json!({"mode": mode, "accepted_events": BURST_EVENTS, "timer_interval_ms": 60_000, "flushes": {"attempts": snapshot.attempts, "successes": snapshot.successes, "failures": snapshot.failures}})
        }
        "timer-on" => {
            history_burst(&policy, &directory);
            let flusher = policy
                .start_history_flusher(TIMER_INTERVAL)
                .expect("the timer starts");
            let flushes = wait_for_flushes(&flusher, 1);
            held_flusher = Some(flusher);
            json!({"mode": mode, "accepted_events": BURST_EVENTS, "idle_ms": started.elapsed().as_millis(), "flushes": flushes})
        }
        "shutdown" => {
            history_burst(&policy, &directory);
            let flusher = policy
                .start_history_flusher(Duration::from_secs(60))
                .expect("the timer starts");
            assert_eq!(
                flusher.snapshot().attempts,
                0,
                "the first timer deadline has not passed"
            );
            let stop = Instant::now();
            let final_snapshot = flusher
                .shutdown()
                .expect("explicit shutdown returns the final flush result");
            assert!(
                stop.elapsed() < Duration::from_secs(5),
                "shutdown must cancel the 60-second wait"
            );
            json!({"mode": mode, "accepted_events": BURST_EVENTS, "shutdown_ms": stop.elapsed().as_millis(), "final_snapshot": format!("{final_snapshot:?}")})
        }
        "concurrent" => {
            let flusher = policy
                .start_history_flusher(Duration::from_millis(10))
                .expect("the timer starts");
            let barrier = Arc::new(Barrier::new(WRITERS));
            let midpoint = Arc::new(Barrier::new(WRITERS + 1));
            let workers: Vec<_> = (0..WRITERS)
                .map(|writer| {
                    let policy = Arc::clone(&policy);
                    let directory = directory.clone();
                    let barrier = Arc::clone(&barrier);
                    let midpoint = Arc::clone(&midpoint);
                    thread::spawn(move || {
                        barrier.wait();
                        for sequence in 0..WRITES_PER_WRITER {
                            if sequence == WRITES_PER_WRITER / 2 {
                                midpoint.wait();
                                midpoint.wait();
                            }
                            write_file(
                                &policy,
                                &directory,
                                &format!("writer-{writer}-{sequence}.txt"),
                            );
                            thread::sleep(Duration::from_millis(2));
                        }
                    })
                })
                .collect();
            midpoint.wait();
            let midpoint_flushes = wait_for_flushes(&flusher, flusher.snapshot().successes + 2);
            midpoint.wait();
            for worker in workers {
                worker.join().expect("all file producers complete");
            }
            let during_load = flusher.snapshot();
            // One completion could already be in flight. Two ensure a flush started after all producers stopped.
            let flushes = wait_for_flushes(&flusher, during_load.successes + 2);
            held_flusher = Some(flusher);
            json!({"mode": mode, "accepted_events": WRITERS * WRITES_PER_WRITER * 2, "flushes": flushes, "flushes_at_campaign_midpoint": midpoint_flushes})
        }
        _ => panic!("unknown child mode {mode}"),
    };
    signal_ready(&directory, report);
    // Keep the engine and timer alive until the parent kills the process; no Drop may flush it.
    while started.elapsed() < CHILD_DEADLINE {
        std::hint::black_box(&held_flusher);
        std::hint::black_box(&policy);
        thread::sleep(Duration::from_millis(100));
    }
    std::process::exit(9);
}

struct ChildFixture {
    child: Child,
}

impl Drop for ChildFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn killed_child(mode: &str) -> (tempfile::TempDir, Json) {
    let directory = tempfile::Builder::new()
        .prefix(&format!("idle-history-{mode}-"))
        .tempdir()
        .expect("the fixture directory opens");
    fs::write(directory.path().join("trigger.txt"), b"read marker")
        .expect("the read fixture exists");
    let log = File::create(directory.path().join("child.log")).expect("the child log opens");
    let child = Command::new(std::env::current_exe().expect("the current test executable"))
        .args([
            "--exact",
            "subprocess_entrypoint",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_MODE, mode)
        .env(CHILD_DIR, directory.path())
        .stdout(Stdio::from(log.try_clone().expect("the child log clones")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("the child starts");
    let mut fixture = ChildFixture { child };
    let deadline = Instant::now() + Duration::from_secs(20);
    let ready = loop {
        if let Ok(bytes) = fs::read(directory.path().join("ready.json")) {
            break serde_json::from_slice::<Json>(&bytes)
                .expect("the readiness report is complete");
        }
        if let Some(status) = fixture
            .child
            .try_wait()
            .expect("the child status is readable")
        {
            panic!(
                "child {mode} exited before readiness: {status}; {}",
                fs::read_to_string(directory.path().join("child.log")).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "child {mode} readiness timed out; evidence: {}",
            directory.path().display()
        );
        thread::sleep(Duration::from_millis(10));
    };
    fixture.child.kill().expect("the parent sends SIGKILL");
    let status = fixture.child.wait().expect("the killed child exits");
    assert_eq!(
        status.signal(),
        Some(9),
        "the test must use SIGKILL, not clean shutdown"
    );
    (directory, ready)
}

#[derive(Debug)]
struct StoredEvent {
    offset: u64,
    timestamp: i64,
    kind: String,
    action: String,
    path: String,
}

fn stored_events(directory: &Path) -> Vec<StoredEvent> {
    let log = DurableLog::open(directory.join("history.redb"))
        .expect("the killed child's database recovers");
    let mut offsets = Vec::new();
    let mut events = Vec::new();
    log.scan_from(0, |offset, bytes| {
        offsets.push(offset);
        if let Record::Event(event) = Record::decode(bytes).expect("every persisted record decodes")
        {
            let path = match event.field("input", "path") {
                Some(Value::String(path)) => path.clone(),
                other => panic!("the filesystem event must retain its path: {other:?}"),
            };
            events.push(StoredEvent {
                offset,
                timestamp: event.timestamp(),
                kind: event.kind().to_owned(),
                action: event.action().to_owned(),
                path,
            });
        }
    })
    .expect("the recovered log scans");
    assert_eq!(
        offsets,
        (log.base_offset()..log.next_offset()).collect::<Vec<_>>(),
        "every surviving log offset is present exactly once"
    );
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].timestamp < pair[1].timestamp),
        "event timestamps retain their strict total order"
    );
    let recovered = json!({
        "stage": "Persisted log after SIGKILL, before reopening Box PolicyEngine",
        "base_offset": log.base_offset(),
        "next_offset": log.next_offset(),
        "record_offsets": offsets,
        "events": events.iter().map(|event| json!({
            "offset": event.offset,
            "timestamp": event.timestamp,
            "kind": event.kind,
            "action": event.action,
            "path": event.path,
        })).collect::<Vec<_>>(),
    });
    fs::write(
        directory.join("recovered-log-before-box-reopen.json"),
        serde_json::to_vec_pretty(&recovered).expect("the recovered log serializes"),
    )
    .expect("the recovered log evidence is saved");
    events
}

fn save_result(directory: &Path, report: Json) {
    fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report).expect("the result serializes"),
    )
    .expect("the result is saved");
    println!(
        "IDLE_FLUSH_RESULT {}",
        json!({"evidence": directory, "result": report})
    );
}

#[test]
fn idle_without_timer_loses_pending_history_after_sigkill() {
    let (directory, ready) = killed_child("timer-off");
    let events = stored_events(directory.path());
    assert!(
        events.is_empty(),
        "the negative control must not persist its pending history"
    );
    let recovered = open_policy(directory.path(), HISTORY_POLICY);
    assert!(
        write_allowed(&recovered, directory.path()),
        "the missing read history allows a write after recovery"
    );
    save_result(
        directory.path(),
        json!({"case": "idle_without_timer", "ready": ready, "recovered_events": events.len(), "recovered_write_allowed": true, "killed_by_signal": 9}),
    );
}

#[test]
fn killing_before_the_first_timer_tick_still_loses_pending_history() {
    let (directory, ready) = killed_child("timer-before-first-tick");
    assert_eq!(ready["timer_interval_ms"], 60_000);
    assert_eq!(ready["flushes"]["attempts"], 0);
    let events = stored_events(directory.path());
    assert!(
        events.is_empty(),
        "an enabled timer cannot preserve events before its first flush"
    );
    let recovered = open_policy(directory.path(), HISTORY_POLICY);
    assert!(
        write_allowed(&recovered, directory.path()),
        "the missing read history allows a write after recovery"
    );
    save_result(
        directory.path(),
        json!({"case": "crash_before_first_timer_tick", "ready": ready, "recovered_events": events.len(), "recovered_write_allowed": true, "killed_by_signal": 9, "purpose": "Residual process-crash window control; the 60-second interval is not a latency measurement."}),
    );
}

#[test]
fn idle_timer_preserves_history_after_sigkill() {
    let (directory, ready) = killed_child("timer-on");
    let events = stored_events(directory.path());
    assert_eq!(
        events.len(),
        BURST_EVENTS,
        "the timer must preserve the complete idle burst"
    );
    let recovered = open_policy(directory.path(), HISTORY_POLICY);
    assert!(
        !write_allowed(&recovered, directory.path()),
        "the recovered read history still denies writes"
    );
    save_result(
        directory.path(),
        json!({"case": "idle_with_timer", "ready": ready, "recovered_events": events.len(), "recovered_write_allowed": false, "killed_by_signal": 9}),
    );
}

#[test]
fn explicit_shutdown_flushes_before_the_first_timer_deadline() {
    let (directory, ready) = killed_child("shutdown");
    let events = stored_events(directory.path());
    assert_eq!(
        events.len(),
        BURST_EVENTS,
        "explicit shutdown must flush pending events before Drop"
    );
    let recovered = open_policy(directory.path(), HISTORY_POLICY);
    assert!(
        !write_allowed(&recovered, directory.path()),
        "the final flush preserves the read history"
    );
    save_result(
        directory.path(),
        json!({"case": "explicit_shutdown", "ready": ready, "recovered_events": events.len(), "recovered_write_allowed": false, "killed_by_signal": 9}),
    );
}

#[test]
fn concurrent_submissions_keep_each_request_and_outcome_once_in_order() {
    let (directory, ready) = killed_child("concurrent");
    let events = stored_events(directory.path());
    assert_eq!(events.len(), WRITERS * WRITES_PER_WRITER * 2);
    let mut paths: BTreeMap<String, Vec<&StoredEvent>> = BTreeMap::new();
    for event in &events {
        assert_eq!(event.action, "fs:write");
        paths.entry(event.path.clone()).or_default().push(event);
    }
    assert_eq!(paths.len(), WRITERS * WRITES_PER_WRITER);
    let mut observed = BTreeSet::new();
    for (path, pair) in paths {
        assert_eq!(
            pair.len(),
            2,
            "each file has exactly one request and one outcome: {path}"
        );
        assert_eq!(pair[0].kind, "request");
        assert_eq!(pair[1].kind, "response");
        assert!(
            pair[0].offset < pair[1].offset,
            "a request precedes its own outcome"
        );
        observed.insert(
            PathBuf::from(path)
                .file_name()
                .expect("the event has a filename")
                .to_owned(),
        );
    }
    for writer in 0..WRITERS {
        for sequence in 0..WRITES_PER_WRITER {
            assert!(observed.contains(std::ffi::OsStr::new(&format!(
                "writer-{writer}-{sequence}.txt"
            ))));
            assert_eq!(
                fs::read(
                    directory
                        .path()
                        .join(format!("writer-{writer}-{sequence}.txt"))
                )
                .expect("every admitted file write ran"),
                b"harmless test marker"
            );
        }
    }
    save_result(
        directory.path(),
        json!({"case": "concurrent_submissions", "ready": ready, "recovered_events": events.len(), "unique_files": observed.len(), "strict_event_timestamps": true, "request_before_outcome": true, "killed_by_signal": 9}),
    );
}

#[test]
fn a_second_timer_is_rejected_and_shutdown_releases_ownership() {
    let directory = tempfile::Builder::new()
        .prefix("idle-history-timer-ownership-")
        .tempdir()
        .expect("fixture directory");
    let policy = open_policy(directory.path(), WRITE_POLICY);
    policy
        .set_periodic_history(u32::MAX, Duration::from_secs(3600))
        .expect("periodic persistence");
    assert!(
        policy.start_history_flusher(Duration::ZERO).is_err(),
        "a zero interval is rejected before taking timer ownership"
    );
    let first = policy
        .start_history_flusher(Duration::from_secs(60))
        .expect("the first timer starts");
    assert!(
        policy
            .start_history_flusher(Duration::from_secs(60))
            .is_err(),
        "the same policy cannot own two timers"
    );
    first.shutdown().expect("the first timer shuts down");
    let second = policy
        .start_history_flusher(Duration::from_secs(60))
        .expect("shutdown releases timer ownership");
    drop(second);
    let third = policy
        .start_history_flusher(Duration::from_secs(60))
        .expect("Drop also releases timer ownership");
    third.shutdown().expect("the third timer shuts down");
    let weak = Arc::downgrade(&policy);
    drop(policy);
    assert!(
        weak.upgrade().is_none(),
        "stopped timers must not keep the policy alive"
    );
    save_result(
        directory.path(),
        json!({"case": "timer_ownership", "zero_interval_rejected": true, "duplicate_rejected": true, "restarted_after_shutdown": true, "restarted_after_drop": true, "policy_released": true}),
    );
}
