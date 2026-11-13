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
