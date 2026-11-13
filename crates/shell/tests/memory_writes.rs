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
