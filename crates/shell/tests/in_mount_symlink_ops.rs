//! `ln -s`, `readlink`, and `chmod` act on the real host filesystem for a host-bound path.
//!
//! These three effects previously ran only against the in-memory VFS, so they failed with
//! `ENOTDIR` (or, for `chmod`, silently succeeded without changing the host mode) on any
//! `bind_direct` path. They now dispatch to the host like the sibling effects, refuse a
//! read-only bind, and — for `chmod` — refuse setuid/setgid/sticky on the host branch, because
//! the Shell runs outside the OS cage on inodes a writable bind shares with the operator's real
//! filesystem.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use strands_shell::Shell;

/// A writable bind at `/workspace` and a read-only bind at `/ro`, each seeded with one file.
fn fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    let workspace = base.join("ws");
    let readonly = base.join("ro");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&readonly).expect("readonly");
    std::fs::write(workspace.join("real.txt"), "REAL_BYTES").expect("real file");
    std::fs::write(workspace.join("mode.txt"), "MODE").expect("mode file");
    std::fs::write(readonly.join("ro.txt"), "RO").expect("ro file");
    (workspace, readonly)
}

fn build(workspace: &std::path::Path, readonly: &std::path::Path) -> Shell {
    let mut shell = Shell::builder()
        .bind_direct(workspace.to_str().expect("UTF-8"), "/workspace")
        .bind_direct_readonly(readonly.to_str().expect("UTF-8"), "/ro")
        .disable_network()
        .build()
        .expect("shell builds");
    shell.proc.cwd = std::path::PathBuf::from("/workspace");
    shell
}

fn host_mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("stat host file")
        .permissions()
        .mode()
        & 0o7777
}

#[tokio::test]
async fn ln_s_creates_a_real_symlink_on_the_host() {
    let (ws, ro) = fixture("ln_creates");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s real.txt link").await;
            assert_eq!(out.status, 0, "ln -s must succeed: {}", out.stderr);
            let link = ws.join("link");
            let meta = std::fs::symlink_metadata(&link).expect("link exists on host");
            assert!(
                meta.file_type().is_symlink(),
                "a real host symlink was created"
            );
            assert_eq!(
                std::fs::read_link(&link).expect("read the host link"),
                std::path::Path::new("real.txt")
            );
        })
        .await;
}

#[tokio::test]
async fn readlink_reads_a_host_symlinks_target() {
    let (ws, ro) = fixture("readlink");
    std::os::unix::fs::symlink("real.txt", ws.join("link")).expect("seed host symlink");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("readlink link").await;
            assert_eq!(out.status, 0, "readlink must succeed: {}", out.stderr);
            assert_eq!(out.stdout.trim(), "real.txt");
        })
        .await;
}

#[tokio::test]
async fn a_box_created_symlink_reads_through_to_the_target() {
    let (ws, ro) = fixture("read_through");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            assert_eq!(sh.run("ln -s real.txt link").await.status, 0);
            let out = sh.run("cat link").await;
            assert_eq!(
                out.status, 0,
                "cat through the link must succeed: {}",
                out.stderr
            );
            assert_eq!(out.stdout.trim(), "REAL_BYTES");
        })
        .await;
}

#[tokio::test]
async fn ln_on_a_readonly_bind_is_refused() {
    let (ws, ro) = fixture("ln_readonly");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s ro.txt /ro/link").await;
            assert_ne!(
                out.status, 0,
                "ln on a read-only bind must fail: {}",
                out.stderr
            );
            assert!(
                ro.join("link").symlink_metadata().is_err(),
                "no link may be created on the read-only bind"
            );
        })
        .await;
}

#[tokio::test]
async fn chmod_changes_the_host_file_mode() {
    let (ws, ro) = fixture("chmod_ok");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("chmod 700 mode.txt").await;
            assert_eq!(out.status, 0, "chmod must succeed: {}", out.stderr);
            assert_eq!(
                host_mode(&ws.join("mode.txt")),
                0o700,
                "the host mode changed"
            );
        })
        .await;
}

#[tokio::test]
async fn chmod_restores_a_host_file_with_no_permissions() {
    let (ws, ro) = fixture("chmod_mode_zero");
    let mode_file = ws.join("mode.txt");
    std::fs::set_permissions(&mode_file, std::fs::Permissions::from_mode(0o000))
        .expect("remove permissions");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("chmod 644 mode.txt").await;
            assert_eq!(out.status, 0, "chmod must succeed: {}", out.stderr);
        })
        .await;
    assert_eq!(host_mode(&mode_file), 0o644);
}

#[tokio::test]
async fn chmod_refuses_setuid_and_leaves_the_host_mode_unchanged() {
    let (ws, ro) = fixture("chmod_setuid");
    let before = host_mode(&ws.join("mode.txt"));
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("chmod 4755 mode.txt").await;
            assert_ne!(
                out.status, 0,
                "chmod with setuid must be refused: {}",
                out.stderr
            );
        })
        .await;
    let after = host_mode(&ws.join("mode.txt"));
    assert_eq!(
        after & 0o7000,
        0,
        "no setuid/setgid/sticky bit on the host inode"
    );
    assert_eq!(
        after, before,
        "a refused chmod must not change the host mode"
    );
}

#[tokio::test]
async fn ln_s_to_an_absolute_target_is_refused() {
    let (ws, ro) = fixture("ln_absolute");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s /etc/passwd escape").await;
            assert_ne!(
                out.status, 0,
                "ln -s to an absolute host target must be refused: {}",
                out.stderr
            );
            assert!(
                ws.join("escape").symlink_metadata().is_err(),
                "no escaping link may be planted on the host bind"
            );
        })
        .await;
}

#[tokio::test]
async fn ln_s_to_a_target_that_climbs_out_of_the_bind_is_refused() {
    let (ws, ro) = fixture("ln_climb");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s ../../../../etc/passwd escape").await;
            assert_ne!(
                out.status, 0,
                "ln -s to a target outside the bind must be refused: {}",
                out.stderr
            );
            assert!(
                ws.join("escape").symlink_metadata().is_err(),
                "no escaping link may be planted on the host bind"
            );
        })
        .await;
}

#[tokio::test]
async fn ln_s_through_a_non_directory_component_is_refused() {
    // `real.txt` is a regular file, so canonicalizing `real.txt/sub` fails with a non-NotFound
    // error (ENOTDIR). The target floor must fail closed on that rather than fold the failing
    // component as an ordinary directory.
    let (ws, ro) = fixture("ln_enotdir");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s real.txt/sub link").await;
            assert_ne!(
                out.status, 0,
                "ln -s through a non-directory component must be refused: {}",
                out.stderr
            );
            assert!(
                ws.join("link").symlink_metadata().is_err(),
                "no link may be planted when the target floor fails closed"
            );
        })
        .await;
}

#[tokio::test]
async fn ln_s_to_an_in_bind_target_with_missing_dirs_is_allowed() {
    let (ws, ro) = fixture("ln_dangling");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s newsub/file link").await;
            assert_eq!(
                out.status, 0,
                "ln -s to an in-bind target whose dirs do not exist yet must succeed: {}",
                out.stderr
            );
            let link = ws.join("link");
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link exists on host")
                    .file_type()
                    .is_symlink(),
                "a real host symlink was created"
            );
            assert_eq!(
                std::fs::read_link(&link).expect("read the host link"),
                std::path::Path::new("newsub/file")
            );
        })
        .await;
}

#[tokio::test]
async fn ln_s_through_a_dangling_symlink_prefix_is_refused() {
    let (ws, ro) = fixture("ln_dangling_prefix");
    std::os::unix::fs::symlink("../outside-missing", ws.join("dangling"))
        .expect("dangling host symlink");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("ln -s dangling/file link").await;
            assert_ne!(
                out.status, 0,
                "a dangling symlink prefix cannot prove an in-bind target: {}",
                out.stderr
            );
            assert!(
                ws.join("link").symlink_metadata().is_err(),
                "no link may be planted through a dangling prefix"
            );
        })
        .await;
}

#[tokio::test]
async fn symbolic_chmod_on_a_setgid_host_file_succeeds() {
    let (ws, ro) = fixture("chmod_symbolic_setgid");
    let mode_file = ws.join("mode.txt");
    std::fs::set_permissions(&mode_file, std::fs::Permissions::from_mode(0o2644))
        .expect("seed g+s");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("chmod +x mode.txt").await;
            assert_eq!(
                out.status, 0,
                "chmod +x on a file already carrying setgid must succeed: {}",
                out.stderr
            );
        })
        .await;
    assert_eq!(
        host_mode(&mode_file),
        0o755,
        "the ordinary bits changed and the special bits were dropped"
    );
}

#[tokio::test]
async fn chmod_on_a_readonly_bind_is_refused() {
    let (ws, ro) = fixture("chmod_readonly");
    let before = host_mode(&ro.join("ro.txt"));
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut sh = build(&ws, &ro);
            let out = sh.run("chmod 700 /ro/ro.txt").await;
            assert_ne!(
                out.status, 0,
                "chmod on a read-only bind must be refused: {}",
                out.stderr
            );
        })
        .await;
    assert_eq!(
        host_mode(&ro.join("ro.txt")),
        before,
        "a refused chmod must not change the host mode"
    );
}
