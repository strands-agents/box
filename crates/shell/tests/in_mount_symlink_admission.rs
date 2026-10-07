//! An in-mount symlink is admitted under its own path, not its target.
//!
//! **This test pins a DEFECT, not a guarantee.** It asserts the behavior that exists
//! today so a fix has something to flip: when the mismatch is closed, the assertion
//! marked `THE DEFECT` below starts failing, and that failure is the good news.
//!
//! What is wrong: a host symlink *inside* a `bind_direct` mount is authorized under the
//! caller's spelling while the effect lands on the symlink's target. So a policy that
//! permits one subdirectory and refuses a sibling does not hold — for reads or writes.
//!
//! What is NOT wrong: an escape *out* of the mount is still refused, by
//! `resolve_host`'s canonicalize-and-prefix-check. This is an authorization defect,
//! not a containment escape.
//!
//! Cause: `VfsKernel::resolved_target` resolves symlinks through `Vfs::canonicalize_path`,
//! which follows only `InodeData::Symlink` — VFS inodes. A `bind_direct` mount is one
//! `HostDir` inode, so host symlinks beneath it are invisible to it.

use strands_shell::Shell;

/// A fixture whose layout exercises all three symlink shapes.
fn fixture(name: &str) -> (std::path::PathBuf, String) {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    let workspace = base.join("ws");
    let outside = base.join("outside");
    std::fs::create_dir_all(workspace.join("sub")).expect("workspace");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(workspace.join("secret.txt"), "IN_MOUNT").expect("secret");
    std::fs::write(outside.join("host.txt"), "OUTSIDE").expect("host file");
    // Inside the mount, pointing inside it — the defect.
    std::os::unix::fs::symlink(workspace.join("secret.txt"), workspace.join("sub/flink"))
        .expect("file symlink");
    // Inside the mount, pointing OUT — must stay refused.
    std::os::unix::fs::symlink(&outside, workspace.join("escape")).expect("escape symlink");
    let mount = workspace.to_str().expect("UTF-8 workspace").to_string();
    (workspace, mount)
}

async fn shell(mount: &str) -> Shell {
    let mut shell = Shell::builder()
        .bind_direct(mount, "/workspace")
        .disable_network()
        .build()
        .expect("shell builds");
    shell.proc.cwd = std::path::PathBuf::from("/workspace");
    shell
}

/// THE DEFECT: a read through an in-mount symlink returns the target's bytes.
///
/// When the admitted identity is fixed this still *reads* fine — what changes is which
/// path a policy sees. The companion assertion is in
/// `an_in_mount_symlink_write_lands_on_the_target`, which is the one with teeth.
#[tokio::test]
async fn an_in_mount_symlink_read_reaches_the_target() {
    let (_workspace, mount) = fixture("symlink-read");
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount).await;
            let output = shell.run("cat /workspace/sub/flink").await;
            assert_eq!(
                output.stdout.trim(),
                "IN_MOUNT",
                "a read through an in-mount symlink reaches its target: "
            );
        })
        .await;
}

/// THE DEFECT, in the form that matters: a WRITE through an in-mount symlink lands on
/// the target, so a rule scoped to the link's directory does not protect the target.
#[tokio::test]
async fn an_in_mount_symlink_write_lands_on_the_target() {
    let (workspace, mount) = fixture("symlink-write");
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount).await;
            let output = shell.run("printf PWNED > /workspace/sub/flink").await;
            assert_eq!(output.status, 0, "the write succeeds: ");
        })
        .await;
    // `run` reports status 0 before the redirect's bytes have necessarily reached the host,
    // so the host read below raced it: measured 2 failures in 15 runs, once seeing the
    // target *truncated and empty* rather than either expected value. `run_until` drives
    // only the future it is given; awaiting the `LocalSet` itself drains every task the
    // write spawned. Do not drop this await — and do not "fix" the flake with
    // `--test-threads=1`, which hides it on this test and leaves the next one exposed.
    local.await;

    // On the HOST, the target changed — the link's own directory was never written.
    assert_eq!(
        std::fs::read_to_string(workspace.join("secret.txt")).expect("target readable"),
        "PWNED",
        "a write through the symlink must land on the target — this is the defect being \
         pinned; if this assertion starts failing, the admitted identity was fixed"
    );
}

/// NOT a defect: a symlink escaping the mount is refused.
///
/// `resolve_host` canonicalizes and prefix-checks against the mount, so this is the
/// boundary holding. Kept beside the two above so the scope of the defect stays clear:
/// authorization identity is wrong, containment is not.
#[tokio::test]
async fn a_symlink_escaping_the_mount_is_refused() {
    let (_workspace, mount) = fixture("symlink-escape");
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut shell = shell(&mount).await;
            let output = shell.run("cat /workspace/escape/host.txt").await;
            assert_ne!(
                output.status, 0,
                "an escape out of the mount must be refused: "
            );
            assert!(
                !output.stdout.contains("OUTSIDE"),
                "no byte from outside the mount may be returned: "
            );
        })
        .await;
}
