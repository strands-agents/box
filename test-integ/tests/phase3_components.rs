#[path = "phase3/mod.rs"]
mod support;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;
use strands_det_harness::{Route, RunResult};

fn probe() -> &'static Path {
    static COMPILED: OnceLock<(tempfile::TempDir, std::path::PathBuf)> = OnceLock::new();
    &COMPILED
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("probe.rs");
            let binary = dir.path().join("phase3-probe");
            std::fs::write(&source, support::SOURCE).unwrap();
            support::text(
                Command::new("rustc")
                    .args(["--edition=2021", "-O"])
                    .arg(&source)
                    .arg("-o")
                    .arg(&binary)
                    .output()
                    .unwrap(),
            );
            (dir, binary)
        })
        .1
}

fn rejected(body: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(
        std::panic::catch_unwind(body).is_err(),
        "fault was accepted"
    );
}

fn native(out: String) -> RunResult {
    RunResult {
        out: format!("DET_ENTERED\n{out}"),
        rc: 0,
        decisions: vec![],
        route: Route::Native,
    }
}

#[test]
fn unconfined_tool_read_is_detected_in_output_and_host_witness() {
    let dir = tempfile::tempdir().unwrap();
    let own = dir.path().join("own");
    let other = dir.path().join("other");
    let witness = dir.path().join("witness");
    std::fs::write(&own, "own-data").unwrap();
    std::fs::write(&other, "agent-private-data").unwrap();
    let out = support::host(
        probe(),
        &[
            "files",
            own.to_str().unwrap(),
            other.to_str().unwrap(),
            witness.to_str().unwrap(),
        ],
    );
    assert!(out.contains("OWN_CONTENT own-data"));
    assert!(out.contains("OTHER_REACHED agent-private-data"));
    let observer = std::fs::read_to_string(witness).unwrap();
    assert!(observer.contains("OTHER_REACHED agent-private-data"));
    rejected(|| support::require_refusal(&out, "OTHER", &[1, 2, 13]));
    rejected(|| support::require_refusal(&observer, "OTHER", &[1, 2, 13]));
}

#[test]
fn no_entry_setup_error_and_wrong_errno_do_not_count_as_refusals() {
    let bare = RunResult::bare("DET_ENTERED\nSIGNAL_ENTERED\nSIGNAL_REFUSED 1".into(), 0);
    rejected(|| support::native_ok(&bare, "SIGNAL_ENTERED"));
    let no_entry = RunResult {
        out: "SIGNAL_REFUSED 1".into(),
        rc: 126,
        route: Route::Native,
        decisions: vec![],
    };
    rejected(|| support::native_ok(&no_entry, "SIGNAL_ENTERED"));
    let no_probe = native("SIGNAL_REFUSED 1".into());
    rejected(|| support::native_ok(&no_probe, "SIGNAL_ENTERED"));
    let setup = native("SIGNAL_ENTERED\nDET_ERROR: setup failed\nSIGNAL_REFUSED 1\n".into());
    rejected(|| support::native_ok(&setup, "SIGNAL_ENTERED"));
    rejected(|| support::require_refusal("SIGNAL_REFUSED 9", "SIGNAL", &[1, 3]));
    rejected(|| support::require_refusal("SIGNAL_REFUSED 1\nSIGNAL_REACHED", "SIGNAL", &[1, 3]));
}

#[test]
fn host_signal_control_changes_counter_and_permissive_fault_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut marker = support::Marker::start(probe(), dir.path(), false);
    marker.signal_control(1);
    let out = support::host(probe(), &["signal", &marker.pid().to_string()]);
    support::until(
        || marker.count() == 2,
        Duration::from_secs(2),
        "unconfined signal",
    );
    rejected(|| support::require_refusal(&out, "SIGNAL", &[1, 3]));
    marker.signal_control(3);
}

#[cfg(target_os = "linux")]
#[test]
fn host_process_view_finds_marker_and_rejects_permissive_fault() {
    let dir = tempfile::tempdir().unwrap();
    let mut marker = support::Marker::start(probe(), dir.path(), false);
    let out = support::host(probe(), &["view", &marker.token]);
    assert!(out.contains("SELF_VISIBLE "));
    assert!(out.contains("HOST_MARKER_VISIBLE"));
    rejected(|| native(out).assert_absent("HOST_MARKER_VISIBLE"));
    marker.advance();
}

#[cfg(target_os = "linux")]
#[test]
fn host_trace_attaches_detaches_and_rejects_permissive_fault() {
    let dir = tempfile::tempdir().unwrap();
    let mut marker = support::Marker::start(probe(), dir.path(), true);
    let out = support::host(probe(), &["trace", &marker.pid().to_string()]);
    assert!(
        out.contains("TRACE_REACHED") && out.contains("TRACE_DETACHED"),
        "{out}"
    );
    rejected(|| support::require_refusal(&out, "TRACE", &[1, 3]));
    marker.advance();
}

#[cfg(target_os = "linux")]
#[test]
fn host_abstract_listener_observes_payload_and_rejects_permissive_fault() {
    use std::io::Read;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};
    let name = format!("phase3-component-{}", std::process::id());
    let listener =
        UnixListener::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
    let out = support::host(probe(), &["abstract", &name, "owned-payload"]);
    assert!(out.contains("SOCKETPAIR_OK"));
    listener.set_nonblocking(true).unwrap();
    let (mut connection, _) = listener.accept().unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = String::new();
    connection.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "owned-payload");
    rejected(|| support::require_refusal(&out, "ABSTRACT", &[1, 111]));
}

#[cfg(target_os = "linux")]
#[test]
fn host_shared_memory_is_readable_and_rejects_permissive_fault() {
    let memory = support::linux::SharedMemory::new();
    let out = support::host(probe(), &["shm", &memory.id.to_string()]);
    assert!(out.contains("SHM_REACHED PHASE3_SHM_OWNED"), "{out}");
    rejected(|| support::require_refusal(&out, "SHM", &[1, 13, 22]));
    memory.unchanged();
}

#[cfg(target_os = "linux")]
#[test]
fn real_test_pty_observer_and_mismatched_result_faults() {
    use support::linux::{Terminal, terminal_observation};
    let mut tty = Terminal::new();
    tty.control(b"before\n");
    let out = support::text(tty.launch(Command::new(probe()).arg("tty")));
    let input = tty.input(Duration::from_millis(100));
    println!("host PTY: {} ({out})", terminal_observation(&out, &input));
    tty.control(b"after\n");
    rejected(|| {
        terminal_observation("TTY_STDIN_OK\nTIOCSTI_REACHED", b"");
    });
    rejected(|| {
        terminal_observation("TTY_STDIN_OK\nTIOCSTI_REFUSED 1", b"\n");
    });
    rejected(|| {
        terminal_observation("TTY_STDIN_OK\nTIOCSTI_REFUSED 25", b"");
    });
}

#[test]
fn surviving_descendant_fails_cleanup_until_test_owned_stop() {
    let root = tempfile::tempdir().unwrap();
    let dir = root
        .path()
        .join("long-process-observer-".repeat(7))
        .join("nested-".repeat(20));
    std::fs::create_dir_all(&dir).unwrap();
    let stop = support::StopDescendant(dir.clone());
    let mut child = Command::new(probe())
        .arg("descendant")
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    support::until(
        || dir.join("heartbeat").exists(),
        Duration::from_secs(2),
        "descendant",
    );
    let rows = support::marked_rows(probe(), &dir);
    assert_eq!(rows.len(), 1, "{rows:?}");
    rejected(|| support::require_cleanup(probe(), &dir, Duration::from_millis(60), &rows));
    drop(stop);
    support::until(
        || child.try_wait().unwrap().is_some(),
        Duration::from_secs(2),
        "descendant stop",
    );
    support::require_cleanup(probe(), &dir, Duration::from_millis(60), &rows);
}

#[test]
fn waiting_for_descendant_expiry_cannot_satisfy_cleanup() {
    rejected(|| support::require_exit_deadline(Duration::from_secs(120), Duration::from_secs(10)));
    support::require_exit_deadline(Duration::from_millis(100), Duration::from_secs(10));
}
