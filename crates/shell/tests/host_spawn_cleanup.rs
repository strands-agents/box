//! A pending host command stops at cancellation or the shell deadline.

#![cfg(unix)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Pending(Arc<AtomicUsize>);

struct Directory(std::path::PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn cleanup(deadline: bool, stages: usize) {
    use std::os::unix::fs::PermissionsExt;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let directory = Directory(std::env::temp_dir().join(format!(
        "shell-cleanup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let program = directory.0.join("cleanup-probe");
    std::fs::write(&program, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let stopped = Arc::new(AtomicUsize::new(0));
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let observed = Arc::clone(&stopped);
    let hook: strands_shell::os::HostSpawner = Arc::new(move |_| {
        let stopped = Arc::clone(&observed);
        let started = started.clone();
        Box::pin(async move {
            let _pending = Pending(stopped);
            started.send(()).unwrap();
            std::future::pending().await
        })
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut shell = strands_shell::Shell::builder().host_spawner(hook)
            .timeout(Duration::from_millis(if deadline { 100 } else { 5000 })).build().unwrap();
        let command = vec![program.to_str().unwrap(); stages].join(" | ");
        let mut call = Box::pin(shell.run(&command));
        for _ in 0..stages {
            tokio::select! {
                result = &mut call => panic!("host command returned before readiness: {} {}", result.status, result.stderr),
                result = starts.recv() => assert!(result.is_some()),
                _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("host command did not start"),
            }
        }
        if deadline {
            let output = tokio::time::timeout(Duration::from_secs(2), &mut call).await.unwrap();
            assert_eq!(output.status, 1, "{}", output.stderr);
            assert!(output.stderr.contains("execution timeout exceeded"), "{}", output.stderr);
        }
        drop(call);
        tokio::time::timeout(Duration::from_secs(2), async {
            while stopped.load(Ordering::SeqCst) != stages {
                tokio::task::yield_now().await;
            }
        }).await.expect("each pending host command must drop while the runtime stays alive");
        let next = shell.run("printf ready").await;
        assert_eq!(next.status, 0);
        assert_eq!(next.stdout, "ready");
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
