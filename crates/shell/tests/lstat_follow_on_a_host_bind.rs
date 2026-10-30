//! A no-follow metadata read on a `bind_direct` mount answers for the link, as on the in-memory VFS.

#![cfg(unix)]

use std::path::PathBuf;

use strands_shell::Shell;

/// `ws/` holds `secret.txt`, `dir/inner.txt`, `flink -> secret.txt`, and `dlink -> dir`.
fn fixture(name: &str) -> (PathBuf, String) {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    let workspace = base.join("ws");
    std::fs::create_dir_all(workspace.join("dir")).expect("workspace");
    std::fs::write(workspace.join("secret.txt"), "IN_MOUNT").expect("secret");
    std::fs::write(workspace.join("dir/inner.txt"), "INNER").expect("inner");
    std::os::unix::fs::symlink(workspace.join("secret.txt"), workspace.join("flink"))
        .expect("file symlink");
    std::os::unix::fs::symlink(workspace.join("dir"), workspace.join("dlink"))
        .expect("directory symlink");
    let mount = workspace.to_str().expect("UTF-8 workspace").to_string();
    (workspace, mount)
}

fn host_shell(mount: &str) -> Shell {
    let mut shell = Shell::builder()
        .bind_direct(mount, "/workspace")
        .disable_network()
        .build()
        .expect("shell builds");
    shell.proc.cwd = PathBuf::from("/workspace");
    shell
}

fn memory_shell() -> Shell {
    let mut shell = Shell::builder()
        .disable_network()
        .build()
        .expect("shell builds");
    shell.proc.cwd = PathBuf::from("/home/lash");
    shell
}

fn local_runtime() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    (runtime, tokio::task::LocalSet::new())
}

#[test]
fn test_minus_l_sees_a_host_symlink() {
    let (workspace, mount) = fixture("lstat-follow-test-l");
    let (runtime, local) = local_runtime();

    let (host_answer, host_readlink, memory_answer) = local.block_on(&runtime, async {
        let mut shell = host_shell(&mount);
        let host_answer = shell
            .run("if test -L /workspace/flink; then echo LINK; else echo NOTLINK; fi")
            .await;
        let host_readlink = shell.run("readlink /workspace/flink").await;

        let mut memory = memory_shell();
        let seeded = memory
            .run("printf IN_MEMORY > m.txt; ln -s m.txt mlink")
            .await;
        assert_eq!(
            seeded.status, 0,
            "seed the in-memory link: {}",
            seeded.stderr
        );
        let memory_answer = memory
            .run("if test -L /home/lash/mlink; then echo LINK; else echo NOTLINK; fi")
            .await;
        (host_answer, host_readlink, memory_answer)
    });
    runtime.block_on(local);

    assert_eq!(
        memory_answer.stdout.trim(),
        "LINK",
        "the in-memory VFS sees its link: {}",
        memory_answer.stderr
    );
    assert_eq!(
        host_readlink.stdout.trim(),
        workspace.join("secret.txt").to_string_lossy(),
        "readlink sees the host link: {}",
        host_readlink.stderr
    );
    assert_eq!(
        host_answer.stdout.trim(),
        "LINK",
        "`test -L` on a host symlink must answer for the link, not its target: {}",
        host_answer.stderr
    );
}

#[test]
fn test_minus_l_sees_a_dangling_host_symlink() {
    let (workspace, mount) = fixture("lstat-follow-dangling");
    std::os::unix::fs::symlink(workspace.join("absent"), workspace.join("gone"))
        .expect("dangling symlink");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        host_shell(&mount)
            .run("if test -L /workspace/gone; then echo LINK; else echo NOTLINK; fi")
            .await
    });
    runtime.block_on(local);

    assert_eq!(
        out.stdout.trim(),
        "LINK",
        "`test -L` on a dangling host symlink must answer for the link: {}",
        out.stderr
    );
}

#[test]
fn find_type_l_lists_a_host_symlink() {
    let (_workspace, mount) = fixture("lstat-follow-find");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        host_shell(&mount)
            .run("find /workspace -maxdepth 1 -type l -name 'flink'")
            .await
    });
    runtime.block_on(local);

    assert_eq!(
        out.stdout.trim(),
        "/workspace/flink",
        "`find -type l` must list a host symlink; stderr: {}",
        out.stderr
    );
}

#[test]
fn stat_still_follows_a_host_symlink() {
    let (_workspace, mount) = fixture("lstat-follow-stat");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        host_shell(&mount)
            .run("if test -d /workspace/dlink; then echo DIR; else echo NOTDIR; fi")
            .await
    });
    runtime.block_on(local);

    assert_eq!(
        out.stdout.trim(),
        "DIR",
        "`test -d` follows a host symlink to its directory: {}",
        out.stderr
    );
}

#[test]
fn rm_on_a_host_symlink_to_a_directory_removes_the_link() {
    let (workspace, mount) = fixture("lstat-follow-rm");
    let (runtime, local) = local_runtime();

    let (host, memory) = local.block_on(&runtime, async {
        let host = host_shell(&mount).run("rm /workspace/dlink").await;

        let mut memory = memory_shell();
        let seeded = memory
            .run("mkdir d; printf INNER > d/inner.txt; ln -s d dlink")
            .await;
        assert_eq!(seeded.status, 0, "seed the in-memory tree: {}", seeded.stderr);
        let removed = memory.run("rm dlink").await;
        assert_eq!(removed.status, 0, "in-memory `rm link`: {}", removed.stderr);
        let memory = memory
            .run("if test -e dlink; then echo LINK_LEFT; fi; if test -f d/inner.txt; then echo TARGET_KEPT; fi")
            .await;
        (host, memory)
    });
    runtime.block_on(local);

    assert_eq!(
        memory.stdout.trim(),
        "TARGET_KEPT",
        "in memory `rm link` removes the link and keeps the directory"
    );
    assert_eq!(
        host.status, 0,
        "`rm link` removes the link: {}",
        host.stderr
    );
    assert!(
        workspace.join("dlink").symlink_metadata().is_err(),
        "the link is gone after `rm /workspace/dlink`"
    );
    assert!(
        workspace.join("dir/inner.txt").exists(),
        "`rm link` keeps the directory the link points at and its contents"
    );
}

#[test]
fn rm_r_on_a_host_symlink_to_a_directory_removes_only_the_link() {
    let (workspace, mount) = fixture("lstat-follow-rm-r");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        host_shell(&mount).run("rm -r /workspace/dlink").await
    });
    runtime.block_on(local);

    assert_eq!(out.status, 0, "`rm -r link` succeeds: {}", out.stderr);
    assert!(
        workspace.join("dlink").symlink_metadata().is_err(),
        "`rm -r link` removes the link"
    );
    assert!(
        workspace.join("dir/inner.txt").exists(),
        "`rm -r link` keeps the directory the link points at and its contents"
    );
}

#[test]
fn ls_l_shows_a_host_symlink_as_a_link() {
    let (_workspace, mount) = fixture("lstat-follow-ls");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        host_shell(&mount).run("ls -l /workspace/flink").await
    });
    runtime.block_on(local);

    assert!(
        out.stdout.starts_with('l'),
        "`ls -l` shows a host symlink with type `l`: {:?} (stderr: {})",
        out.stdout,
        out.stderr
    );
}

#[test]
fn rm_r_on_a_host_symlink_out_of_the_mount_removes_only_the_link() {
    let (workspace, mount) = fixture("lstat-follow-escape");
    let outside = workspace.parent().expect("base").join("outside");
    std::fs::create_dir_all(&outside).expect("outside directory");
    std::fs::write(outside.join("kept.txt"), "OUTSIDE").expect("outside file");
    std::os::unix::fs::symlink(&outside, workspace.join("out")).expect("escaping symlink");
    let (runtime, local) = local_runtime();

    let (probe, removed) = local.block_on(&runtime, async {
        let mut shell = host_shell(&mount);
        let probe = shell
            .run("if test -L /workspace/out; then echo LINK; else echo NOTLINK; fi")
            .await;
        let removed = shell.run("rm -r /workspace/out").await;
        (probe, removed)
    });
    runtime.block_on(local);

    assert_eq!(
        probe.stdout.trim(),
        "LINK",
        "`test -L` sees a host symlink that points out of the mount: {}",
        probe.stderr
    );
    assert_eq!(
        removed.status, 0,
        "`rm -r link` succeeds: {}",
        removed.stderr
    );
    assert!(
        workspace.join("out").symlink_metadata().is_err(),
        "`rm -r link` removes the link"
    );
    assert!(
        outside.join("kept.txt").exists(),
        "`rm -r link` does not reach the directory out of the mount"
    );
}

#[test]
fn a_file_bind_whose_source_is_a_symlink_is_not_a_link() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lstat-follow-file-bind");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("base");
    std::fs::write(base.join("real.txt"), "REAL").expect("real file");
    std::os::unix::fs::symlink(base.join("real.txt"), base.join("alias.txt"))
        .expect("source symlink");
    let source = base.join("alias.txt");
    let (runtime, local) = local_runtime();

    let out = local.block_on(&runtime, async {
        let mut shell = Shell::builder()
            .bind_direct(source.to_str().expect("UTF-8 source"), "/home/lash/cfg.txt")
            .disable_network()
            .build()
            .expect("shell builds");
        shell
            .run("if test -L /home/lash/cfg.txt; then echo LINK; else echo NOTLINK; fi")
            .await
    });
    runtime.block_on(local);

    assert_eq!(
        out.stdout.trim(),
        "NOTLINK",
        "a file bind point is the file it binds, not its host source link: {}",
        out.stderr
    );
}
