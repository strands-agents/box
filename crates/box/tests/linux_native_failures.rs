//! Failure behavior through the actual Box launch path.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support"
))]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

struct Run {
    child: Child,
    lines: mpsc::Receiver<String>,
    stderr: Arc<Mutex<String>>,
    root: PathBuf,
    file: PathBuf,
}
impl Run {
    fn start(mode: &str, fault: Option<&str>, permit: bool) -> Self {
        Self::start_selected(mode, fault, permit, true, true)
    }
    fn start_selected(
        mode: &str,
        fault: Option<&str>,
        permit: bool,
        enabled: bool,
        retain_capabilities: bool,
    ) -> Self {
        let parent = std::env::var_os("NATIVE_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap());
        let root = tempfile::tempdir_in(parent).unwrap().keep();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let file = workspace.join("protected.txt");
        std::fs::write(&file, "original\n").unwrap();
        let program = root.join("native-failure-workload");
        std::fs::copy(
            std::env::var_os("NATIVE_FAILURE_WORKLOAD")
                .unwrap_or_else(|| env!("NATIVE_FAILURE_WORKLOAD").into()),
            &program,
        )
        .unwrap();
        let q = |p: &std::path::Path| toml::Value::String(p.display().to_string()).to_string();
        let command = toml::Value::Array(
            vec![
                program.display().to_string(),
                mode.into(),
                if mode == "list" { &workspace } else { &file }
                    .display()
                    .to_string(),
            ]
            .into_iter()
            .map(toml::Value::String)
            .collect(),
        );
        let config = format!(
            "name = \"native-failure-test\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
            [experimental-features]\nnative-filesystem-policy = true\n\
            [agent]\ncommand = {command}\nworkspace = {}\nnative-filesystem-policy = {enabled}\n\
            [agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
            q(&root.join("state")),
            q(&workspace),
            q(&workspace),
            q(&workspace)
        );
        std::fs::write(root.join("box.toml"), config).unwrap();
        std::fs::write(
            root.join("policy.dw"),
            if permit && mode == "delete" {
                "permit(principal, action == Box::Action::\"fs:delete\", resource);\n"
            } else if permit && matches!(mode, "read" | "list") {
                "permit(principal, action == Box::Action::\"fs:read\", resource);\n"
            } else if permit {
                "permit(principal, action == Box::Action::\"fs:write\", resource);\n"
            } else {
                "forbid(principal, action, resource);\n"
            },
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
        command
            .args(["run", "--config"])
            .arg(root.join("box.toml"))
            .env("HOME", &root)
            .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
            .env_remove("BOX_NATIVE_TEST_FAULT")
            .current_dir(&workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(fault) = fault {
            command.env("BOX_NATIVE_TEST_FAULT", fault);
        }
        if !retain_capabilities {
            // Clear ambient capabilities before exec. The test binary has no file
            // capabilities, so Box starts without the loader's effective powers.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().unwrap();
        let (send, lines) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        let _ = send.send(line);
                    }
                    Err(error) => {
                        let _ = send.send(format!("STDOUT_ERROR={error}"));
                        return;
                    }
                }
            }
            let _ = send.send("EOF".into());
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let copied = Arc::clone(&stderr);
        let mut stream = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            while let Ok(count) = stream.read(&mut bytes) {
                if count == 0 {
                    break;
                }
                copied
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&bytes[..count]));
            }
        });
        Self {
            child,
            lines,
            stderr,
            root,
            file,
        }
    }
    fn line(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|error| panic!("{error}: {}", self.stderr.lock().unwrap()))
    }
    fn release(&mut self) {
        self.child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    }
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                std::thread::sleep(Duration::from_millis(30));
                let stderr = self.stderr.lock().unwrap().clone();
                std::fs::write(self.root.join("box.stderr.log"), &stderr).unwrap();
                println!("fixture={} status={status}\n{stderr}", self.root.display());
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Box did not stop: {}",
                self.stderr.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(box_native_test_faults)]
    fn marker(&self, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.stderr.lock().unwrap().contains(marker) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "missing {marker}: {}",
                self.stderr.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn signal(&self, signal: i32) {
        assert_eq!(unsafe { libc::kill(self.child.id() as i32, signal) }, 0);
    }
    fn unchanged(&self) {
        assert_eq!(std::fs::read_to_string(&self.file).unwrap(), "original\n");
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            let stderr = self.stderr.lock().unwrap();
            let _ = std::fs::write(self.root.join("box.stderr.log"), stderr.as_str());
            eprintln!("fixture={}\n{stderr}", self.root.display());
        }
    }
}

#[test]
fn selected_native_checks_refuse_without_loader_capabilities() {
    let mut run = Run::start_selected("wait", None, true, true, false);
    assert!(!run.wait().success());
    assert_eq!(run.line(), "EOF");
    run.unchanged();
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("requires CAP_BPF and CAP_PERFMON")
    );
}

#[test]
fn an_opted_out_workload_runs_without_loader_capabilities() {
    let mut run = Run::start_selected("wait", None, false, false, false);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    run.release();
    assert!(run.wait().success());
    assert_ne!(std::fs::read_to_string(&run.file).unwrap(), "original\n");
}

#[cfg(not(box_native_test_faults))]
#[test]
fn a_production_build_ignores_test_fault_environment() {
    let mut run = Run::start("wait", Some("registration"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    run.release();
    assert!(run.wait().success());
    assert!(!run.stderr.lock().unwrap().contains("NATIVE_TEST_FAULT"));
}

#[test]
fn a_policy_denial_preserves_the_file_without_stopping_box() {
    let mut run = Run::start("wait", None, false);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "DENIED");
    assert!(run.child.try_wait().unwrap().is_none());
    run.unchanged();
    run.release();
    assert!(run.wait().success());
}
#[cfg(box_native_test_faults)]
#[test]
fn a_request_storage_failure_stops_box_before_the_write() {
    let mut run = Run::start("wait", Some("request-storage"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    run.unchanged();
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("NATIVE_TEST_FAULT=request-storage")
    );
}
#[cfg(box_native_test_faults)]
#[test]
fn an_outcome_storage_failure_stops_box_after_descriptor_delivery() {
    let mut run = Run::start("wait", Some("outcome-storage"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("NATIVE_TEST_FAULT=outcome-storage")
    );
    assert!(
        std::fs::read(&run.file).unwrap().is_empty()
            || std::fs::read(&run.file).unwrap() == b"changed\n"
    );
}
#[test]
fn immediate_exit_preserves_a_completed_native_outcome() {
    let mut run = Run::start("exit", None, true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    assert!(run.wait().success());
    assert_eq!(std::fs::read(&run.file).unwrap(), b"changed\n");
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("\"outcome\":\"descriptor_issued\"")
    );
}

#[cfg(box_native_test_faults)]
#[test]
fn immediate_exit_cannot_hide_an_outcome_storage_failure() {
    let mut run = Run::start("exit", Some("outcome-storage"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    let stderr = run.stderr.lock().unwrap();
    assert!(stderr.contains("NATIVE_TEST_FAULT=outcome-storage"));
    assert!(stderr.contains("policy history failure: durable log"));
}

#[cfg(box_native_test_faults)]
#[test]
fn a_stalled_policy_worker_stops_box_within_the_deadline() {
    let mut run = Run::start("wait", Some("stall"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    run.unchanged();
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("native request deadline")
    );
}
#[cfg(box_native_test_faults)]
#[test]
fn a_worker_panic_stops_box_and_preserves_the_file() {
    let mut run = Run::start("wait", Some("panic"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    run.unchanged();
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("native worker panicked")
    );
}
#[cfg(box_native_test_faults)]
#[test]
fn registration_refusal_prevents_the_workload_from_starting() {
    let mut run = Run::start("wait", Some("registration"), true);
    assert!(!run.wait().success());
    run.unchanged();
    assert_eq!(run.line(), "EOF");
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("NATIVE_TEST_FAULT=registration")
    );
}
fn parent_death(signal: i32) {
    let mut run = Run::start("tree", None, true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    for _ in 0..4 {
        assert_eq!(run.line(), "TREE");
    }
    run.signal(signal);
    assert!(!run.wait().success());
    assert_eq!(
        run.lines.recv_timeout(Duration::from_secs(1)).unwrap(),
        "EOF"
    );
    let size = std::fs::metadata(&run.file).unwrap().len();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(std::fs::metadata(&run.file).unwrap().len(), size);
}
#[test]
fn sigkill_of_box_stops_descendants_in_separate_process_groups() {
    parent_death(libc::SIGKILL);
}
#[test]
fn sigterm_of_box_stops_descendants_in_separate_process_groups() {
    parent_death(libc::SIGTERM);
}

#[cfg(box_native_test_faults)]
#[test]
fn killing_box_with_a_pending_request_preserves_the_file() {
    let mut run = Run::start("wait", Some("stall"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    run.marker("NATIVE_TEST_FAULT=stall");
    run.signal(libc::SIGKILL);
    assert!(!run.wait().success());
    assert_eq!(
        run.lines.recv_timeout(Duration::from_secs(1)).unwrap(),
        "EOF"
    );
    run.unchanged();
}
#[test]
fn sixteen_children_complete_128_checked_writes() {
    let mut run = Run::start("concurrent", None, true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "COMPLETE");
    assert!(run.wait().success());
    let stderr = run.stderr.lock().unwrap();
    assert_eq!(stderr.matches("NATIVE_RESEARCH_EVENT=").count(), 128);
    assert_eq!(
        stderr.matches("\"outcome\":\"descriptor_issued\"").count(),
        128
    );
    assert_eq!(std::fs::read(&run.file).unwrap(), b"changed\n");
}
#[cfg(box_native_test_faults)]
#[test]
fn cancelling_a_request_keeps_box_available_for_the_next_request() {
    let mut run = Run::start("xcancel", Some("delay-once"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "PENDING");
    run.marker("NATIVE_TEST_FAULT=delay-once");
    run.release();
    assert_eq!(run.line(), "CANCELLED", "{}", run.stderr.lock().unwrap());
    std::thread::sleep(Duration::from_millis(650));
    run.unchanged();
    assert!(run.child.try_wait().unwrap().is_none());
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    run.release();
    assert!(run.wait().success());
}

#[cfg(box_native_test_faults)]
#[test]
fn a_stall_inside_the_dogwood_lock_stops_box_and_preserves_the_file() {
    let mut run = Run::start("wait", Some("policy-lock"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    run.marker("NATIVE_TEST_FAULT=policy-lock");
    assert!(!run.wait().success());
    run.unchanged();
    assert_eq!(
        run.lines.recv_timeout(Duration::from_secs(1)).unwrap(),
        "EOF"
    );
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("native request deadline")
    );
}

#[test]
fn box_threads_drop_loader_capabilities_before_launch() {
    check_capabilities_after_launch(true);
}

#[test]
fn opted_out_workloads_drop_unused_loader_capabilities() {
    check_capabilities_after_launch(false);
}

fn check_capabilities_after_launch(enabled: bool) {
    let mut run = Run::start_selected("wait", None, true, enabled, true);
    assert_eq!(run.line(), "READY");
    let mut processes = vec![run.child.id()];
    let mut checked = 0;
    while let Some(pid) = processes.pop() {
        for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
            let task = task.unwrap().path();
            let status = std::fs::read_to_string(task.join("status")).unwrap();
            let fields: &[&str] = if pid == run.child.id() {
                &["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            } else {
                let mapping = std::fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
                let ids: Vec<u32> = mapping
                    .split_whitespace()
                    .map(|id| id.parse().unwrap())
                    .collect();
                assert_eq!(
                    ids,
                    [0, unsafe { libc::getuid() }, 1],
                    "{task:?}: {mapping}"
                );
                std::fs::write(run.root.join(format!("process-{pid}-uid-map.txt")), mapping)
                    .unwrap();
                &["CapInh:", "CapAmb:"]
            };
            std::fs::write(
                run.root.join(format!(
                    "task-{}-status.txt",
                    task.file_name().unwrap().to_string_lossy()
                )),
                &status,
            )
            .unwrap();
            for name in fields {
                let value = status
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap();
                assert_eq!(
                    u64::from_str_radix(value.trim(), 16).unwrap(),
                    0,
                    "{task:?}: {name}"
                );
            }
            assert!(
                status.lines().any(|line| line == "NoNewPrivs:\t1"),
                "{task:?}"
            );
            let children = std::fs::read_to_string(task.join("children")).unwrap();
            processes.extend(
                children
                    .split_whitespace()
                    .map(|pid| pid.parse::<u32>().unwrap()),
            );
            checked += 1;
        }
    }
    assert!(
        checked > 2,
        "the inspection must include runtime threads and a workload"
    );
    run.release();
    assert_eq!(run.line(), "ALLOWED");
    run.release();
    assert!(run.wait().success());
}

#[cfg(box_native_test_faults)]
#[test]
fn a_guard_reset_failure_stops_box_after_the_approved_delete() {
    let mut run = Run::start("delete", Some("guard-reset"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert!(!run.wait().success());
    assert!(
        !run.file.exists(),
        "the authorized delete completed before reset failed"
    );
    let stderr = run.stderr.lock().unwrap();
    assert!(stderr.contains("NATIVE_TEST_FAULT=guard-reset"));
    assert!(stderr.contains("native entry guard could not clear its approval"));
}

#[cfg(box_native_test_faults)]
#[test]
fn worker_guard_registration_failure_prevents_the_workload_from_starting() {
    let mut run = Run::start("wait", Some("worker-registration"), true);
    assert!(!run.wait().success());
    run.unchanged();
    assert_eq!(run.line(), "EOF");
    assert!(
        run.stderr
            .lock()
            .unwrap()
            .contains("NATIVE_TEST_FAULT=worker-registration")
    );
}

fn complete_handle_operation(mode: &str, expected: &str) {
    let mut run = Run::start(mode, None, true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "OPENED");
    run.release();
    assert_eq!(run.line(), expected);
    run.release();
    assert!(run.wait().success());
    run.unchanged();
}

#[test]
fn an_approved_read_handle_returns_the_expected_bytes() {
    complete_handle_operation("read", "READ");
}

#[test]
fn an_approved_directory_handle_returns_the_expected_entry() {
    complete_handle_operation("list", "LISTED");
}

fn kill_with_open_handle(mode: &str) {
    let mut run = Run::start(mode, None, true);
    assert_eq!(run.line(), "READY");
    run.release();
    assert_eq!(run.line(), "OPENED");
    run.signal(libc::SIGKILL);
    assert!(!run.wait().success());
    assert_eq!(run.line(), "EOF");
    run.unchanged();
}

#[test]
fn killing_box_with_an_open_read_handle_stops_the_waiting_workload() {
    kill_with_open_handle("read");
}

#[test]
fn killing_box_with_an_open_directory_handle_stops_the_waiting_workload() {
    kill_with_open_handle("list");
}

#[cfg(box_native_test_faults)]
fn kill_with_pending_handle(mode: &str) {
    let mut run = Run::start(mode, Some("stall"), true);
    assert_eq!(run.line(), "READY");
    run.release();
    run.marker("NATIVE_TEST_FAULT=stall");
    run.signal(libc::SIGKILL);
    assert!(!run.wait().success());
    assert_eq!(run.line(), "EOF");
    run.unchanged();
}

#[cfg(box_native_test_faults)]
#[test]
fn killing_box_with_a_pending_read_open_returns_no_file_bytes() {
    kill_with_pending_handle("read");
}

#[cfg(box_native_test_faults)]
#[test]
fn killing_box_with_a_pending_directory_open_returns_no_entries() {
    kill_with_pending_handle("list");
}

#[test]
#[cfg(box_native_test_faults)]
fn an_unexpected_capability_probe_error_refuses_startup() {
    let mut run = Run::start("wait", Some("capability-probe"), true);
    assert!(!run.wait().success());
    assert_eq!(run.line(), "EOF");
    run.unchanged();
    let stderr = run.stderr.lock().unwrap();
    assert!(
        stderr.contains("injected path-only probe failure"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("this kernel cannot transfer O_PATH"),
        "{stderr}"
    );
    assert!(!run.root.join("state/private").exists());
}
