//! Production-path proof that `close_inherited_descriptors` and its fallbacks close every
//! descriptor above stderr, on Linux.
//!
//! Each phase runs in `box-close-range-probe`, a freshly spawned process: the function under
//! test wipes the caller's own descriptor table above stderr, which would tear this test
//! binary's own pipes out from under it if run in-process, and would be unsound to run in a
//! forked `cargo test` worker (fork in a multithreaded process only guarantees async-signal-safe
//! work in the child, and the probe's setup allocates). A real `exec` boundary has neither
//! problem.

#![cfg(target_os = "linux")]

use std::process::Command;

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_box-close-range-probe"))
}

fn run(phase: &str) -> std::process::Output {
    probe().arg(phase).output().expect("run the probe")
}

/// Assert a probe phase printed `PASS` and exited successfully, with both streams in the panic
/// message on failure.
fn assert_pass(phase: &str) {
    let output = run(phase);
    assert!(
        output.status.success(),
        "phase {phase}: stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "PASS\n",
        "phase {phase}: unexpected stdout; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_close_range_fast_path_closes_above_stdio_and_keeps_stdio() {
    // The probe asserts close_range specifically ran (not merely that some mechanism closed the
    // descriptors), and reports an explicit skip rather than passing vacuously if close_range is
    // genuinely unavailable on this host (an old kernel, or a seccomp profile that blocks it).
    let output = run("fast-path");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.starts_with("SKIP:") {
        // A CI runner that is known to have close_range (a stock Linux runner) sets
        // BOX_REQUIRE_CLOSE_RANGE=1 so a skip there is a real failure, not a quiet pass; it would
        // mean the fast path is no longer exercised where it was expected to be. Elsewhere a skip
        // is legitimate (old kernel or a seccomp block), so report the reason and pass.
        if std::env::var("BOX_REQUIRE_CLOSE_RANGE").as_deref() == Ok("1") {
            panic!(
                "close_range was required (BOX_REQUIRE_CLOSE_RANGE=1) but the probe skipped it.\n\
                 stdout: {stdout}\nstderr: {stderr}"
            );
        }
        eprintln!("fast-path skipped: {}", stdout.trim_end());
        return;
    }
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(stdout, "PASS\n", "unexpected stdout; stderr: {stderr}");
}

#[test]
fn the_proc_self_fd_fallback_closes_above_stdio_and_keeps_stdio() {
    assert_pass("proc-fallback");
}

/// The last-resort bounded loop, exercised directly rather than only as a fallback the fast two
/// paths might never reach on this host.
#[test]
fn the_bounded_loop_closes_above_stdio_and_keeps_stdio() {
    assert_pass("bounded");
}

/// A descriptor planted near the current soft `RLIMIT_NOFILE`, not just at the bottom of the
/// range, must still be closed. The scaling claim this module exists for is about descriptors
/// across the whole range, not only the low end a smaller test would happen to cover.
#[test]
fn a_descriptor_near_the_soft_limit_is_closed() {
    assert_pass("soft-limit");
}

/// The exact lower boundary (fd 3) must be closed, not just a descriptor placed well above it.
#[test]
fn the_exact_lower_boundary_descriptor_is_closed() {
    assert_pass("lower-boundary");
}
