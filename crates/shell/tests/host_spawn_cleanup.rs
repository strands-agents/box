//! A pending host command stops at cancellation, at the deadline, or when its Shell drops.

#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use box_shell::HostSpawner;
use strands_shell::Shell;

/// Counts a spawn future that was dropped.
struct Pending(Arc<AtomicUsize>);

impl Drop for Pending {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A host folder at `/workspace` holding the host program `cleanup-probe`, and a Shell whose
/// spawner never finishes.
struct Probe {
    folder: tempfile::TempDir,
    program: String,
    stopped: Arc<AtomicUsize>,
    starts: tokio::sync::mpsc::UnboundedReceiver<()>,
    shell: Option<Shell>,
}

/// Run `body` on a current-thread runtime, and do not wait for the tasks it leaves.
fn on_runtime<F: std::future::Future>(body: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

fn probe(deadline: Duration) -> Probe {
    let folder = tempfile::tempdir().expect("host folder");
    let program = folder.path().join("cleanup-probe");
    std::fs::write(&program, "#!/bin/sh\n").expect("a program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let stopped = Arc::new(AtomicUsize::new(0));
    let (started, starts) = tokio::sync::mpsc::unbounded_channel();
    let observed = Arc::clone(&stopped);
    let spawner: HostSpawner = Arc::new(move |_| {
        let pending = Pending(Arc::clone(&observed));
        let started = started.clone();
        Box::pin(async move {
            let _pending = pending;
            started.send(()).expect("the test listens");
            std::future::pending().await
        })
    });
    let mut shell = support::builder()
        .bind_direct(folder.path().to_str().expect("UTF-8"), "/workspace")
        .host_spawner(spawner)
        .build()
        .expect("shell builds");
    shell.proc.deadline = Some(tokio::time::Instant::now() + deadline);
    Probe {
        program: program.to_str().expect("UTF-8").to_string(),
        folder,
        stopped,
        starts,
        shell: Some(shell),
    }
}

/// Wait until `count` spawns started, failing if `call` returns first.
async fn started<F: std::future::Future<Output = strands_shell::Output> + Unpin>(
    starts: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    call: &mut F,
    count: usize,
) {
    for _ in 0..count {
        tokio::select! {
            out = &mut *call => panic!("returned before every spawn started: {} {}", out.status, out.stderr),
            started = starts.recv() => assert!(started.is_some()),
            () = tokio::time::sleep(Duration::from_secs(2)) => panic!("the host command did not start"),
        }
    }
}

/// Wait until `count` spawn futures dropped while the runtime stays alive.
async fn stopped(stopped: &AtomicUsize, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while stopped.load(Ordering::SeqCst) != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} of {count} pending host commands stopped",
            stopped.load(Ordering::SeqCst)
        )
    });
}

fn cleanup(deadline: bool, stages: usize) {
    let limit = Duration::from_millis(if deadline { 100 } else { 5000 });
    let Probe {
        folder: _folder,
        program,
        stopped: count,
        mut starts,
        mut shell,
    } = probe(limit);
    let shell = shell.as_mut().expect("a shell");
    on_runtime(async {
        let command = vec![program.as_str(); stages].join(" | ");
        let mut call = Box::pin(shell.run(&command));
        started(&mut starts, &mut call, stages).await;
        if deadline {
            let out = tokio::time::timeout(Duration::from_secs(2), &mut call)
                .await
                .expect("the deadline ends the call");
            assert_eq!(out.status, 1, "{}", out.stderr);
            assert!(
                out.stderr.contains("execution timeout exceeded"),
                "{}",
                out.stderr
            );
        }
        drop(call);
        stopped(&count, stages).await;
        shell.proc.deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
        let next = shell.run("printf ready").await;
        assert_eq!((next.status, next.stdout.as_str()), (0, "ready"));
    });
}

#[test]
fn cancelling_a_host_command_drops_its_spawn_future() {
    cleanup(false, 1);
}

#[test]
fn cancelling_a_pipeline_drops_every_host_spawn_future() {
    cleanup(false, 2);
}

#[test]
fn the_command_deadline_stops_every_host_pipeline_stage() {
    cleanup(true, 2);
}

#[test]
fn dropping_a_shell_stops_its_background_host_command() {
    let mut probe = probe(Duration::from_secs(25));
    on_runtime(async {
        let shell = probe.shell.as_mut().expect("a shell");
        let out = shell.run(&format!("{} &", probe.program)).await;
        assert_eq!(out.status, 0, "{}", out.stderr);
        tokio::time::timeout(Duration::from_secs(2), probe.starts.recv())
            .await
            .expect("the background command starts")
            .expect("a start");
        let next = shell.run("printf ready").await;
        assert_eq!(next.stdout, "ready");
        assert_eq!(
            probe.stopped.load(Ordering::SeqCst),
            0,
            "an open shell still owns its background job"
        );
        drop(probe.shell.take());
        stopped(&probe.stopped, 1).await;
    });
}

#[test]
fn cancelling_wait_stops_every_background_host_command() {
    let mut probe = probe(Duration::from_secs(25));
    on_runtime(async {
        let shell = probe.shell.as_mut().expect("a shell");
        let command = format!("{0} & {0} & wait", probe.program);
        let mut call = Box::pin(shell.run(&command));
        started(&mut probe.starts, &mut call, 2).await;
        drop(call);
        stopped(&probe.stopped, 2).await;
        let next = shell.run("printf ready").await;
        assert_eq!((next.status, next.stdout.as_str()), (0, "ready"));
    });
}

/// A command substitution that outlasts the deadline starts no later command and no redirect.
#[test]
fn an_expired_substitution_cannot_start_following_commands_or_redirects() {
    for shape in [
        "{program}; printf LATE > /workspace/after",
        "printf '%s' \"$({program})\" > /workspace/after",
        "printf '%s' \"$({program}; printf LATE > /workspace/after)\"",
    ] {
        let mut probe = probe(Duration::from_millis(200));
        let command = shape.replace("{program}", &probe.program);
        let command = command.as_str();
        let after = probe.folder.path().join("after");
        let out = on_runtime(async { probe.shell.as_mut().expect("a shell").run(command).await });
        assert_eq!(out.status, 1, "{command}: {}", out.stderr);
        assert!(
            out.stderr.contains("execution timeout exceeded"),
            "{command}: {}",
            out.stderr
        );
        assert!(!after.exists(), "a late write ran: {command}");
    }
}
