//! A command's status is returned only after the bytes it wrote are visible.
//!
//! Bash is the reference: when a command exits, every byte it wrote is visible to the next
//! command on the same host. Durability may lag; visibility may not. The tests drive each writer
//! spelling the shell offers over both places a file can live: the in-memory VFS and a directly
//! bound host directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use strands_shell::Shell;

/// One byte under the in-memory cap, so the same size is valid in both places.
const LARGE: usize = 10 * 1024 * 1024 - 1;
const SMALL: usize = 1024;

/// Each writer spelling, with `src` the source file and `dst` the destination.
const WRITERS: &[(&str, &str)] = &[
    ("cp", "cp src dst"),
    ("cat >", "cat src > dst"),
    ("printf >", "printf '%s' \"$(cat src)\" > dst"),
    (">>", "cat src >> dst"),
    ("tee", "cat src | tee dst > /dev/null"),
    ("{ } >", "{ cat src; } > dst"),
    ("a | b >", "cat src | cat > dst"),
];

/// The largest payload a writer spelling can carry.
fn ceiling(name: &str) -> usize {
    match name {
        // A command substitution and a group's captured output are both bounded by the
        // shell's output limit.
        "printf >" | "{ } >" => 1024 * 1024 - 1,
        _ => LARGE,
    }
}

fn host_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("write_visibility")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("host directory");
    dir
}

fn host_shell(dir: &Path) -> Shell {
    let mut shell = Shell::builder()
        .bind_direct(dir.to_str().expect("UTF-8"), "/workspace")
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

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 26) as u8).collect()
}

fn host_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

async fn seen_len(shell: &mut Shell) -> usize {
    let out = shell.run("wc -c < dst").await;
    assert_eq!(out.status, 0, "wc reads the destination: {}", out.stderr);
    out.stdout.trim().parse().expect("a byte count")
}

async fn write_then_read(shell: &mut Shell, name: &str, command: &str, len: usize) {
    let _ = shell.run("rm -f dst").await;
    let out = shell.run(command).await;
    assert_eq!(out.status, 0, "{name} succeeds: {}", out.stderr);
    assert_eq!(
        seen_len(shell).await,
        len,
        "the next command sees every byte the previous command wrote ({name})"
    );
}

#[tokio::test]
async fn consecutive_commands_see_the_whole_write_on_the_host() {
    for len in [LARGE, SMALL] {
        for (name, command) in WRITERS {
            let dir = host_dir("consecutive_host");
            let len = len.min(ceiling(name));
            std::fs::write(dir.join("src"), payload(len)).expect("seed source");
            tokio::task::LocalSet::new()
                .run_until(async {
                    let mut shell = host_shell(&dir);
                    write_then_read(&mut shell, name, command, len).await;
                })
                .await;
        }
    }
}

#[tokio::test]
async fn consecutive_commands_see_the_whole_write_in_memory() {
    for len in [LARGE, SMALL] {
        for (name, command) in WRITERS {
            let len = len.min(ceiling(name));
            tokio::task::LocalSet::new()
                .run_until(async {
                    let mut shell = memory_shell();
                    shell
                        .write_file("/home/lash/src", &payload(len))
                        .await
                        .expect("seed source");
                    write_then_read(&mut shell, name, command, len).await;
                })
                .await;
        }
    }
}

#[tokio::test]
async fn a_new_shell_on_the_same_bind_sees_the_whole_write() {
    let dir = host_dir("new_shell");
    std::fs::write(dir.join("src"), payload(LARGE)).expect("seed source");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut first = host_shell(&dir);
            let out = first.run("cat src > dst").await;
            assert_eq!(out.status, 0, "the write succeeds: {}", out.stderr);
            let mut second = host_shell(&dir);
            assert_eq!(
                seen_len(&mut second).await,
                LARGE,
                "a new shell on the same bind sees every byte the first shell wrote"
            );
        })
        .await;
}

#[tokio::test]
async fn the_host_file_is_complete_when_the_command_returns() {
    let dir = host_dir("host_len");
    std::fs::write(dir.join("src"), payload(LARGE)).expect("seed source");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut shell = host_shell(&dir);
            let out = shell.run("cat src > dst").await;
            assert_eq!(out.status, 0, "the write succeeds: {}", out.stderr);
            assert_eq!(
                host_len(&dir.join("dst")),
                LARGE as u64,
                "the host file holds every byte when the command returns"
            );
        })
        .await;
}

#[test]
fn the_write_survives_dropping_the_runtime() {
    let dir = host_dir("runtime_drop");
    std::fs::write(dir.join("src"), payload(LARGE)).expect("seed source");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();
    let status = runtime.block_on(local.run_until(async {
        let mut shell = host_shell(&dir);
        shell.run("cat src > dst").await.status
    }));
    assert_eq!(status, 0, "the write succeeds");
    drop(local);
    drop(runtime);
    assert_eq!(
        host_len(&dir.join("dst")),
        LARGE as u64,
        "the host file holds every byte after the runtime is gone"
    );
}

#[tokio::test]
async fn a_small_write_returns_within_the_sanity_bound() {
    let dir = host_dir("latency");
    std::fs::write(dir.join("src"), payload(SMALL)).expect("seed source");
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut shell = host_shell(&dir);
            let started = Instant::now();
            for _ in 0..20 {
                let out = shell.run("cat src > dst").await;
                assert_eq!(out.status, 0, "the write succeeds: {}", out.stderr);
            }
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_secs(20),
                "twenty small writes return within the sanity bound: {elapsed:?}"
            );
        })
        .await;
}

/// Makes every later file write of this process fail past `bytes`, which models a full disk.
#[cfg(unix)]
fn limit_file_writes(bytes: u64) {
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
        current: bytes,
        maximum: bytes,
    };
    // SAFETY: both calls take integers and a pointer to a live struct in the C layout they expect.
    let (ignored, limited) = unsafe { (signal(SIGXFSZ, SIG_IGN), setrlimit(RLIMIT_FSIZE, &limit)) };
    assert_ne!(
        ignored,
        usize::MAX,
        "the file size signal is ignored, or the write kills the process"
    );
    assert_eq!(limited, 0, "the file size limit applies");
}

/// Runs the named ignored test of this binary in a child process, where a limit can be set.
#[cfg(unix)]
fn run_in_child(test: &str) {
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
        "the child test passes:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_failed_host_write_fails_the_command() {
    run_in_child("child_a_failed_host_write_fails_the_command");
}

#[cfg(unix)]
#[test]
#[ignore]
fn child_a_failed_host_write_fails_the_command() {
    let dir = host_dir("failed_host_write");
    std::fs::write(dir.join("src"), payload(SMALL)).expect("seed source");
    limit_file_writes(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let mut shell = host_shell(&dir);
        for (program, command, path) in [
            ("cat", "cat src > dst", "/workspace/dst"),
            ("cp", "cp src copy", "/workspace/copy"),
        ] {
            let out = shell.run(command).await;
            assert_ne!(out.status, 0, "{program} reports the write that failed");
            assert!(
                out.stderr
                    .contains(&format!("strands-shell: {program}: {path}: ")),
                "the message names the program and the file ({program}): {}",
                out.stderr
            );
            assert!(
                out.stderr.contains("File too large"),
                "the message names the operating system error ({program}): {}",
                out.stderr
            );
        }
        let out = shell
            .run("printf ok > /home/lash/note; cat /home/lash/note")
            .await;
        assert_eq!(
            out.status, 0,
            "a later write elsewhere succeeds: {}",
            out.stderr
        );
        assert_eq!(
            out.stdout, "ok",
            "the shell keeps settling writes after a failure"
        );
    });
}

/// The peak resident size of this process so far, in bytes.
#[cfg(unix)]
fn peak_resident_bytes() -> u64 {
    // SAFETY: the struct is zeroed and lives for the call, which only fills it in.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage
    };
    let scale = if cfg!(target_os = "macos") { 1 } else { 1024 };
    u64::try_from(usage.ru_maxrss).expect("a positive peak") * scale
}

/// One megabyte of pattern, the unit the large host write repeats.
const PIECE: usize = 1024 * 1024;
const PIECES: usize = 64;

#[cfg(unix)]
#[test]
fn a_large_host_write_streams_through_the_drain() {
    run_in_child("child_a_large_host_write_streams_through_the_drain");
}

#[cfg(unix)]
#[test]
#[ignore]
fn child_a_large_host_write_streams_through_the_drain() {
    let dir = host_dir("streaming");
    let piece = payload(PIECE);
    std::fs::write(dir.join("piece"), &piece).expect("seed piece");
    let command = format!("cat{} > dst", " piece".repeat(PIECES));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (before, after) = tokio::task::LocalSet::new().block_on(&runtime, async {
        let mut shell = host_shell(&dir);
        let out = shell.run("cat piece > warm").await;
        assert_eq!(out.status, 0, "the warm-up write succeeds: {}", out.stderr);
        let before = peak_resident_bytes();
        let out = shell.run(&command).await;
        assert_eq!(out.status, 0, "the large write succeeds: {}", out.stderr);
        (before, peak_resident_bytes())
    });
    eprintln!("peak resident bytes before {before} after {after}");
    assert!(
        after.saturating_sub(before) < 8 * 1024 * 1024,
        "the peak resident size grows by much less than the file written: before {before} after {after}"
    );
    let mut file = std::fs::File::open(dir.join("dst")).expect("the host file");
    assert_eq!(
        file.metadata().expect("host metadata").len(),
        (PIECE * PIECES) as u64,
        "the host file has the full length"
    );
    let mut chunk = vec![0u8; PIECE];
    for _ in 0..PIECES {
        std::io::Read::read_exact(&mut file, &mut chunk).expect("a full piece");
        assert!(chunk == piece, "every piece on the host matches its source");
    }
}

#[cfg(unix)]
#[test]
fn a_host_write_that_fails_midway_fails_the_command_and_keeps_the_partial_file() {
    run_in_child(
        "child_a_host_write_that_fails_midway_fails_the_command_and_keeps_the_partial_file",
    );
}

#[cfg(unix)]
#[test]
#[ignore]
fn child_a_host_write_that_fails_midway_fails_the_command_and_keeps_the_partial_file() {
    let dir = host_dir("midway");
    std::fs::write(dir.join("piece"), payload(PIECE)).expect("seed piece");
    limit_file_writes(PIECE as u64);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let mut shell = host_shell(&dir);
        let out = shell.run("cat piece piece piece piece > dst").await;
        assert_ne!(out.status, 0, "the command reports the write that failed");
        assert!(
            out.stderr.contains("strands-shell: cat: /workspace/dst: "),
            "the message names the program and the file: {}",
            out.stderr
        );
        assert!(
            out.stderr.contains("File too large"),
            "the message names the operating system error: {}",
            out.stderr
        );
    });
    let len = host_len(&dir.join("dst"));
    assert!(
        len > 0 && len < (4 * PIECE) as u64,
        "the bytes written before the failure stay on the host: {len}"
    );
}
