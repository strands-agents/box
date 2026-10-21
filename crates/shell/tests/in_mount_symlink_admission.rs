//! An in-mount symlink is admitted under its target, and an escape out of the mount is refused.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use strands_shell::{EffectAttempt, EffectInterceptor, EffectPermit, Shell};

/// A fixture with one symlink inside the mount and one that points out of it.
fn fixture(name: &str) -> (std::path::PathBuf, String) {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    let workspace = base.join("ws");
    let outside = base.join("outside");
    std::fs::create_dir_all(workspace.join("sub")).expect("workspace");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(workspace.join("secret.txt"), "IN_MOUNT").expect("secret");
    std::fs::write(outside.join("host.txt"), "OUTSIDE").expect("host file");
    std::os::unix::fs::symlink(workspace.join("secret.txt"), workspace.join("sub/flink"))
        .expect("file symlink");
    std::os::unix::fs::symlink(&outside, workspace.join("escape")).expect("escape symlink");
    let mount = workspace.to_str().expect("UTF-8 workspace").to_string();
    (workspace, mount)
}

struct Pass;

#[async_trait]
impl EffectPermit for Pass {
    async fn record_outcome(
        self: Box<Self>,
        _outcome: strands_shell::EffectOutcome,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// Admits every attempt and records each filesystem path it judged.
struct Recorder {
    paths: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl EffectInterceptor for Recorder {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::Filesystem { path, .. } = effect {
            self.paths.lock().expect("record").push((*path).to_string());
        }
        Ok(Box::new(Pass))
    }
}

fn shell(mount: &str, paths: &Arc<Mutex<Vec<String>>>) -> Shell {
    let mut shell = Shell::builder()
        .bind_direct(mount, "/workspace")
        .disable_network()
        .effect_interceptor(Arc::new(Recorder {
            paths: Arc::clone(paths),
        }))
        .build()
        .expect("shell builds");
    shell.proc.cwd = std::path::PathBuf::from("/workspace");
    shell
}

#[tokio::test]
async fn an_in_mount_symlink_read_is_judged_on_the_target() {
    let (_workspace, mount) = fixture("symlink-read");
    let paths = Arc::new(Mutex::new(Vec::new()));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount, &paths);
            let output = shell.run("cat /workspace/sub/flink").await;
            assert_eq!(output.stdout.trim(), "IN_MOUNT", "{}", output.stderr);
        })
        .await;
    let paths = paths.lock().expect("record");
    assert!(
        paths.iter().any(|path| path == "/workspace/secret.txt"),
        "the read is judged on the target: {paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path == "/workspace/sub/flink"),
        "the read is not judged on the link: {paths:?}"
    );
}

#[tokio::test]
async fn an_in_mount_symlink_write_is_judged_on_the_target() {
    let (workspace, mount) = fixture("symlink-write");
    let paths = Arc::new(Mutex::new(Vec::new()));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount, &paths);
            let output = shell.run("printf PWNED > /workspace/sub/flink").await;
            assert_eq!(output.status, 0, "{}", output.stderr);
        })
        .await;
    // `run` can return before a redirect's bytes reach the host; awaiting the `LocalSet` drains them.
    local.await;

    assert_eq!(
        std::fs::read_to_string(workspace.join("secret.txt")).expect("target readable"),
        "PWNED"
    );
    let paths = paths.lock().expect("record");
    assert!(
        paths.iter().any(|path| path == "/workspace/secret.txt"),
        "the write is judged on the target: {paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path == "/workspace/sub/flink"),
        "the write is not judged on the link: {paths:?}"
    );
}

#[tokio::test]
async fn a_symlink_escaping_the_mount_is_refused() {
    let (_workspace, mount) = fixture("symlink-escape");
    let paths = Arc::new(Mutex::new(Vec::new()));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount, &paths);
            let output = shell.run("cat /workspace/escape/host.txt").await;
            assert_ne!(
                output.status, 0,
                "an escape out of the mount must be refused"
            );
            assert!(
                !output.stdout.contains("OUTSIDE"),
                "no byte from outside the mount may be returned"
            );
        })
        .await;
}
