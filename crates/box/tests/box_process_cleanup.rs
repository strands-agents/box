//! Linux workload lifetime after the trusted process is killed.

#![cfg(all(target_os = "linux", feature = "test-support"))]

#[path = "support/fixture.rs"]
mod fixture;

use std::collections::BTreeSet;
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct RunningBox {
    child: Child,
    descendants: Vec<(u32, String)>,
}

impl Drop for RunningBox {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.descendants.extend(descendants(self.child.id()));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        for (pid, started) in &self.descendants {
            if process(*pid).is_some_and(|(_, current)| current == *started) {
                // SAFETY: the recorded creation time still identifies this test's child.
                unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
            }
        }
    }
}

impl RunningBox {
    fn observe(&mut self) {
        self.descendants = descendants(self.child.id());
        assert!(
            self.descendants.len() >= 6,
            "observe the complete process tree"
        );
    }

    fn finish(&mut self) -> ExitStatus {
        let mut status = None;
        assert!(
            eventually(|| {
                status = self.child.try_wait().expect("poll Box");
                status.is_some()
            }),
            "Box must exit within the cleanup deadline"
        );
        self.assert_stopped();
        status.unwrap()
    }

    fn assert_stopped(&self) {
        assert!(
            eventually(|| self.descendants.iter().all(|(pid, started)| {
                process(*pid).is_none_or(|(state, current)| {
                    current != *started || matches!(state, 'Z' | 'X')
                })
            })),
            "workload descendants survived: {:?}",
            self.descendants
        );
    }
}

fn process(pid: u32) -> Option<(char, String)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = text.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((fields.first()?.chars().next()?, fields.get(19)?.to_string()))
}

fn descendants(root: u32) -> Vec<(u32, String)> {
    let mut pending = vec![root];
    let mut seen = BTreeSet::from([root]);
    let mut found = Vec::new();
    while let Some(parent) = pending.pop() {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let children =
                std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
            for pid in children
                .split_whitespace()
                .filter_map(|pid| pid.parse().ok())
            {
                if seen.insert(pid) {
                    pending.push(pid);
                    if let Some((_, started)) = process(pid) {
                        found.push((pid, started));
                    }
                }
            }
        }
    }
    found
}

fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn tree_ready(directory: &std::path::Path) -> bool {
    ["leader", "child", "detached", "grandchild"]
        .iter()
        .all(|name| directory.join(name).is_file())
}

fn configured(kind: &str) -> fixture::Configured {
    let probe = env!("CARGO_BIN_EXE_box-exit-probe");
    let declaration = match kind {
        "tool" => "[tool.probe]\ncommand = [\"box-exit-probe\"]\n\
                   [tool.probe.filesystem]\nread = [\"{box_home}\"]\nwrite = [\"{box_home}\"]\n"
            .to_string(),
        "server" => "[mcp.probe]\ntype = \"stdio\"\n\
                     command = [\"box-exit-probe\", \"serve-tree\", \"{box_home}\"]\n\
                     [mcp.probe.filesystem]\nread = [\"{box_home}\"]\nwrite = [\"{box_home}\"]\n"
            .to_string(),
        _ => String::new(),
    };
    let path = format!(
        "{}:/usr/bin:/bin",
        std::path::Path::new(probe).parent().unwrap().display()
    );
    fixture::Request::with_config(
        "cleanup",
        "permit(principal, action, resource);",
        &declaration,
    )
    .env("PATH", &path)
    .expect()
}

fn cleanup_case(kind: &str, trigger: &str) {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let configured = configured(kind);
    let directory = configured.box_home();
    // Preparation can discover a server before the measured run.
    for entry in std::fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    let mut command = configured.command_for(env!("CARGO_BIN_EXE_box-exit-probe"));
    command
        .arg(match kind {
            "server" => "call-server",
            "tool" => "call-tool",
            _ => "hold-tree",
        })
        .arg(&directory);
    let output = tempfile::tempfile().unwrap();
    let child = command
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start actual Box");
    let mut running = RunningBox {
        child,
        descendants: Vec::new(),
    };
    assert!(
        eventually(
            || tree_ready(&directory) && (kind != "server" || directory.join("called").exists())
        ),
        "all processes and the server request must be ready"
    );
    running.observe();
    match trigger {
        "exit" | "failure" => {
            let code = if trigger == "failure" { "17" } else { "0" };
            std::fs::write(
                directory.join(if kind == "agent" {
                    "release"
                } else {
                    "agent-release"
                }),
                code,
            )
            .unwrap();
        }
        "cancel" => {
            // SAFETY: the handle still owns the live Box process.
            assert_eq!(
                unsafe { libc::kill(running.child.id() as i32, libc::SIGTERM) },
                0
            );
        }
        "kill" => running.child.kill().unwrap(),
        _ => unreachable!(),
    }
    let status = running.finish();
    if trigger == "exit" {
        assert!(status.success(), "{kind} normal exit: {status}");
    } else if trigger == "failure" {
        assert_eq!(status.code(), Some(17));
    } else {
        assert!(!status.success());
    }
}

#[test]
fn normal_agent_exit_stops_detached_descendants() {
    cleanup_case("agent", "exit");
}

#[test]
fn failed_agent_stops_detached_descendants() {
    cleanup_case("agent", "failure");
}

#[test]
fn cancellation_stops_children_that_ignore_termination() {
    cleanup_case("agent", "cancel");
}

#[test]
fn normal_exit_stops_separate_tool_descendants() {
    cleanup_case("tool", "exit");
}

#[test]
fn cancellation_stops_separate_tool_descendants() {
    cleanup_case("tool", "cancel");
}

#[test]
fn forced_box_death_stops_separate_tool_descendants() {
    cleanup_case("tool", "kill");
}

#[test]
fn normal_exit_stops_local_server_descendants() {
    cleanup_case("server", "exit");
}

#[test]
fn cancellation_stops_local_server_descendants() {
    cleanup_case("server", "cancel");
}

#[test]
fn forced_box_death_stops_local_server_descendants() {
    cleanup_case("server", "kill");
}

#[test]
fn command_timeout_stops_tool_descendants_and_box_keeps_serving() {
    captured_tool_case(None);
}

#[test]
fn successful_tool_exit_stops_descendants_that_hold_output_open() {
    captured_tool_case(Some(0));
}

#[test]
fn failed_tool_exit_stops_descendants_and_preserves_status() {
    captured_tool_case(Some(17));
}

fn captured_tool_case(release: Option<i32>) {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let configured = configured("tool");
    let directory = configured.box_home();
    let child = configured
        .command_for(env!("CARGO_BIN_EXE_box-exit-probe"))
        .arg("timeout-tool")
        .arg(&directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut running = RunningBox {
        child,
        descendants: Vec::new(),
    };
    assert!(eventually(|| tree_ready(&directory)));
    running.observe();
    let agent_tree = running.descendants.clone();
    if let Some(code) = release {
        std::fs::write(directory.join("release"), code.to_string()).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(40);
    while std::fs::read_to_string(directory.join("after"))
        .ok()
        .as_deref()
        != Some("STILL_SERVING")
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        std::fs::read_to_string(directory.join("after")).unwrap(),
        "STILL_SERVING"
    );
    let expected = release.unwrap_or(1).to_string();
    assert_eq!(
        std::fs::read_to_string(directory.join("status")).unwrap(),
        expected
    );
    // The agent and its launcher remain alive until the final release.
    assert!(
        eventually(|| {
            let active = descendants(running.child.id());
            agent_tree
                .iter()
                .filter(|entry| !active.contains(entry))
                .count()
                >= 6
        }),
        "the completed tool tree must stop"
    );
    let active = descendants(running.child.id());
    let stopped: Vec<_> = agent_tree
        .into_iter()
        .filter(|entry| !active.contains(entry))
        .collect();
    assert!(
        stopped.len() >= 6,
        "the timed-out tool tree must stop: {active:?}"
    );
    running.descendants = stopped;
    running.assert_stopped();
    running.descendants = active;
    std::fs::write(directory.join("agent-release"), b"0").unwrap();
    assert!(running.finish().success());
}

#[test]
fn killing_box_stops_children_and_descendants_in_a_separate_session() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let configured =
        fixture::Request::with_policy("process-death", "permit(principal, action, resource);")
            .expect();
    let markers = configured.box_home();
    let probe = env!("CARGO_BIN_EXE_box-exit-probe");
    let child = configured
        .command_for(probe)
        .arg("hold-tree")
        .arg(&markers)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Box");
    let mut running = RunningBox {
        child,
        descendants: Vec::new(),
    };
    assert!(
        eventually(|| ["leader", "child", "detached", "grandchild"]
            .iter()
            .all(|name| markers.join(name).is_file())),
        "every workload process must start before Box is killed"
    );
    running.descendants = descendants(running.child.id());
    assert!(
        running.descendants.len() >= 6,
        "observe the launcher, reaper, workload, and three descendants: {:?}",
        running.descendants
    );
    running.child.kill().expect("kill the trusted process");
    running.child.wait().expect("reap the trusted process");
    assert!(
        eventually(|| running.descendants.iter().all(|(pid, started)| {
            process(*pid)
                .is_none_or(|(state, current)| current != *started || matches!(state, 'Z' | 'X'))
        })),
        "all workload processes must stop after Box dies: {:?}",
        running.descendants
    );
}
