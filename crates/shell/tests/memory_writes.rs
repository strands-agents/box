//! A write into the Shell's own filesystem keeps the semantics of its redirect.

mod support;

/// Two truncating writes to one file overwrite it, and two appends extend it.
#[test]
fn concurrent_truncating_writes_overwrite_and_appends_extend() {
    for (redirect, length) in [(">", 5), (">>", 10)] {
        for _ in 0..10 {
            let mut shell = support::builder().build().expect("shell builds");
            let out = support::run(shell.run(&format!(
                "printf FIRST {redirect}/tmp/shared & printf LAST! {redirect}/tmp/shared & wait; \
                 cat /tmp/shared"
            )));
            assert_eq!(out.status, 0, "{}", out.stderr);
            assert_eq!(out.stdout.len(), length, "{redirect}: {:?}", out.stdout);
        }
    }
}

/// `touch` on an existing memory file moves its modification time forward.
#[test]
fn touch_updates_an_existing_memory_file() {
    let mut shell = support::builder().build().expect("shell builds");
    let out = support::run(shell.run(
        "printf a >/tmp/touched; sleep 0.05; printf b >/tmp/reference; sleep 0.05; \
         touch /tmp/touched; if test /tmp/touched -nt /tmp/reference; then echo UPDATED; \
         else echo STALE; fi; cat /tmp/touched",
    ));
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "UPDATED\na");
}

/// A write the cap refuses entirely leaves a file that another writer truncated unchanged.
#[test]
fn a_refused_write_does_not_grow_a_truncated_file() {
    use strands_shell::os::{Kernel as _, OpenFlags};
    use tokio::io::AsyncWriteExt as _;

    let mut vfs = strands_shell::vfs_config::build_vfs(&Default::default()).expect("vfs");
    vfs.max_file_size = 2;
    let filesystem =
        std::sync::Arc::new(box_shell::Filesystem::serving(vfs, &[]).expect("a filesystem"));
    let kernel = box_shell::ShellKernel::over(filesystem, std::sync::Arc::new(support::PermitAll));
    let mut proc = kernel.new_process();
    let (refused, length) = support::run(async {
        let first = kernel
            .open(&mut proc, "/tmp/grown", OpenFlags::write())
            .await;
        let mut first = proc.take_writer(first.expect("opens")).expect("a writer");
        first.write_all(b"AB").await.expect("fits");
        let second = kernel
            .open(&mut proc, "/tmp/grown", OpenFlags::write())
            .await;
        drop(
            proc.take_writer(second.expect("truncates"))
                .expect("a writer"),
        );
        let refused = first.write_all(b"CD").await.is_err();
        drop(first);
        tokio::task::yield_now().await;
        (refused, kernel.stat(&proc, "/tmp/grown").await.len)
    });
    assert!(refused, "the cap refuses the second write");
    assert_eq!(length, 0);
}
