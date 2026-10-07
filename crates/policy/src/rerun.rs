//! Re-execution of one `#[ignore]`d test in a child process, so a test can read its stderr.
//!
//! The child half of each pair is `#[ignore]`d, so it runs only when its parent re-executes this
//! binary. `refuse_every_file_write` is Unix-only, because it sets `RLIMIT_FSIZE`.

/// Runs one `#[ignore]`d test of this binary in a child process and returns its stderr.
pub(crate) fn stderr_of(test: &str) -> String {
    let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            test,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("the child test runs");
    assert!(
        output.status.success(),
        "the child test must pass:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The libtest name of `function` in `module`, with the crate prefix of `module_path!()` removed.
pub(crate) fn test_name(module: &str, function: &str) -> String {
    let module = module.split_once("::").map_or(module, |(_, rest)| rest);
    format!("{module}::{function}")
}

/// Makes every later file write of this process fail with `EFBIG`, which models a full store.
#[cfg(unix)]
pub(crate) fn refuse_every_file_write() {
    #[repr(C)]
    struct Limit {
        current: u64,
        maximum: u64,
    }
    unsafe extern "C" {
        fn setrlimit(resource: i32, limit: *const Limit) -> i32;
        fn signal(number: i32, handler: usize) -> usize;
    }
    const RLIMIT_FSIZE: i32 = 1;
    const SIGXFSZ: i32 = 25;
    const SIG_IGN: usize = 1;
    let limit = Limit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: both calls take integers and a pointer to a live struct in the C layout they expect.
    let (ignored, limited) = unsafe { (signal(SIGXFSZ, SIG_IGN), setrlimit(RLIMIT_FSIZE, &limit)) };
    assert_ne!(
        ignored,
        usize::MAX,
        "SIGXFSZ must be ignored, or the write kills the process"
    );
    assert_eq!(limited, 0, "the file size limit must apply");
}
