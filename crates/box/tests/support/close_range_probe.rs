//! Test-only workload that exercises `close_inherited_descriptors` and its fallbacks directly.
//!
//! A real process boundary (this binary, spawned fresh by `std::process::Command`) is required
//! because the function under test wipes the caller's descriptor table above stderr: running it
//! in-process inside `cargo test` would tear out the harness's own pipes, and forking a
//! multithreaded test process would make the child's own setup (which allocates) unsound before
//! `_exit`. A freshly exec'd process has neither problem, and this probe needs no fork.

#[path = "../../src/bin/strands-box-sock-alias/close_descriptors.rs"]
#[allow(dead_code)]
mod close_descriptors;

#[cfg(not(target_os = "linux"))]
fn main() {
    // This probe drives the Linux-specific close paths; on every other target it is a no-op.
    // `box_close_range.rs`, which spawns it, is itself `#![cfg(target_os = "linux")]`, so this
    // branch is never reached from the test suite and exists only so the binary still builds.
    println!("skipping: box-close-range-probe is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use close_descriptors::ClosePath;
    use std::process::ExitCode;

    let phase = std::env::args().nth(1);
    let Some(phase) = phase else {
        eprintln!(
            "usage: box-close-range-probe <fast-path|proc-fallback|bounded|soft-limit|lower-boundary>"
        );
        return ExitCode::from(2);
    };
    let result = match phase.as_str() {
        // The fast-path phase requires close_range specifically to have closed the descriptors
        // (see ClosePath's doc). If it is genuinely unavailable here (old kernel or a seccomp
        // block), report an explicit skip rather than failing or passing through the fallback.
        "fast-path" => match close_range_available() {
            Ok(true) => run_phase(close_descriptors::close_inherited_descriptors_reporting)
                .and_then(|path| expect_path(path, ClosePath::CloseRange)),
            Ok(false) => {
                println!("SKIP: close_range is unavailable on this host");
                return ExitCode::SUCCESS;
            }
            Err(reason) => Err(reason),
        },
        "proc-fallback" => {
            run_phase(close_descriptors::close_inherited_descriptors_fallback_reporting)
                .and_then(|path| expect_path(path, ClosePath::Proc))
        }
        // Exercises the last-resort bounded loop directly, independent of whether close_range or
        // /proc are available on this host (the production code only reaches it when both of
        // those have already failed, which this test harness cannot force from the outside).
        "bounded" => cap_soft_limit(4096).and_then(|_| {
            run_phase(close_descriptors::close_inherited_descriptors_bounded_reporting)
                .and_then(|path| expect_path(path, ClosePath::Bounded))
        }),
        // Plants a descriptor near the current soft RLIMIT_NOFILE rather than at the lowest free
        // number, so a regression that only closes descriptors near the bottom of the range would
        // be caught here, not only in a separate benchmark.
        "soft-limit" => soft_limit(),
        "lower-boundary" => lower_boundary(),
        other => {
            eprintln!("probe: unknown phase {other}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => {
            println!("PASS");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("probe: {reason}");
            ExitCode::from(1)
        }
    }
}

/// Lower the soft `RLIMIT_NOFILE` to at most `cap`, leaving the hard limit untouched, and return
/// the new soft limit. Capping keeps the `bounded` and `soft-limit` phases fast and identical on
/// every host; the probe is its own process, so capping affects nothing else.
#[cfg(target_os = "linux")]
fn cap_soft_limit(cap: libc::rlim_t) -> Result<libc::rlim_t, String> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `&mut limit` is a valid, uniquely-owned pointer to a correctly-sized `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        let error = std::io::Error::last_os_error();
        return Err(format!("getrlimit(RLIMIT_NOFILE) failed: {error}"));
    }
    limit.rlim_cur = limit.rlim_cur.min(cap);
    // SAFETY: `&limit` is a valid pointer to a correctly-sized `rlimit`; lowering the soft limit
    // and leaving the hard limit unchanged needs no privilege.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        let error = std::io::Error::last_os_error();
        return Err(format!("setrlimit(RLIMIT_NOFILE) failed: {error}"));
    }
    Ok(limit.rlim_cur)
}

/// Whether `close_range` itself is usable on this host, checked directly (not through
/// `close_inherited_descriptors`, which would silently fall back) so the fast-path phase can
/// distinguish "unavailable, skip" from "available but something is actually broken".
#[cfg(target_os = "linux")]
fn close_range_available() -> Result<bool, String> {
    // Probe with a descriptor number that cannot be open, not a real low fd: first == last is a
    // one-element inclusive range (see close_range(2)), so probing fd 3 would close it. A huge
    // number is never open, so a working syscall succeeds while closing nothing.
    const UNOPENABLE_PROBE_FD: libc::c_uint = libc::c_uint::MAX - 1;
    // SAFETY: a range entirely above any descriptor this process could hold open; the only
    // possible effect of a successful call is closing nothing, and a failed call closes nothing
    // by definition.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            UNOPENABLE_PROBE_FD,
            UNOPENABLE_PROBE_FD,
            0,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EINVAL) => Ok(false),
        _ => Err(format!(
            "probing close_range availability failed unexpectedly: {error}"
        )),
    }
}

/// Confirm `close_fn` reported it used `expected`, after `run_phase` has already confirmed the
/// descriptor invariant held.
#[cfg(target_os = "linux")]
fn expect_path(
    actual: close_descriptors::ClosePath,
    expected: close_descriptors::ClosePath,
) -> Result<(), String> {
    if actual != expected {
        return Err(format!("expected path {expected:?}, but {actual:?} ran"));
    }
    Ok(())
}

/// Plant a descriptor above stderr (via `F_DUPFD`, never a fixed number), call `close_fn`, then
/// assert the planted descriptor is gone and the three standard streams survive. Returns the
/// `ClosePath` `close_fn` reports, for the caller to check against the phase.
#[cfg(target_os = "linux")]
fn run_phase(
    close_fn: fn() -> std::io::Result<close_descriptors::ClosePath>,
) -> Result<close_descriptors::ClosePath, String> {
    for standard in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if !is_open(standard) {
            return Err(format!(
                "standard descriptor {standard} was not open before the call; the probe's own \
                 setup is broken"
            ));
        }
    }

    let planted = plant_descriptor(libc::STDERR_FILENO + 1)?;
    let path = close_fn().map_err(|error| format!("close_fn returned an error: {error}"))?;

    if is_open(planted) {
        return Err(format!("planted descriptor {planted} survived the call"));
    }
    for standard in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if !is_open(standard) {
            return Err(format!(
                "standard descriptor {standard} was closed by the call"
            ));
        }
    }
    Ok(path)
}

/// Plant a descriptor one below the current soft `RLIMIT_NOFILE`, run the full
/// `close_inherited_descriptors`, and confirm it is gone. Proves closure is not limited to the
/// bottom of the range; the asymptotic timing is measured separately, not here.
#[cfg(target_os = "linux")]
fn soft_limit() -> Result<(), String> {
    // Cap the soft limit at 4096 first (see cap_soft_limit) so this phase plants near a bounded,
    // host-independent limit rather than near a limit that may be ~1e9 on some hosts.
    let soft = cap_soft_limit(4096)?;
    let near_soft_limit = libc::c_int::try_from(soft.saturating_sub(1))
        .map_err(|_| format!("soft RLIMIT_NOFILE {soft} does not fit c_int"))?;
    // Require a real margin above fd 3: on a host with a tiny soft limit, near_soft_limit could
    // land on the descriptor `lower-boundary` already covers, a vacuous pass. A host that cannot
    // spare 16 is far too small to be a realistic target, so refuse outright.
    const MINIMUM_MARGIN_ABOVE_FLOOR: libc::c_int = 16;
    if near_soft_limit < close_descriptors::FIRST_INHERITED_DESCRIPTOR + MINIMUM_MARGIN_ABOVE_FLOOR
    {
        return Err(format!(
            "soft RLIMIT_NOFILE {soft} leaves no real margin above the floor (fd {}); this phase \
             cannot distinguish a descriptor near the limit from one at the bottom of the range",
            close_descriptors::FIRST_INHERITED_DESCRIPTOR
        ));
    }

    let planted = plant_descriptor(near_soft_limit)?;
    close_descriptors::close_inherited_descriptors()
        .map_err(|error| format!("close_inherited_descriptors returned an error: {error}"))?;
    if is_open(planted) {
        return Err(format!(
            "descriptor {planted}, planted near the soft limit {soft}, survived the call"
        ));
    }
    Ok(())
}

/// The exact lower boundary: fd 3 (`STDERR_FILENO + 1`) itself must be closed, and nothing above
/// stderr may remain. Plants fd 3 explicitly first, so the "before" census contains it and the
/// test cannot pass vacuously on a process that started with a clean table above stderr.
#[cfg(target_os = "linux")]
fn lower_boundary() -> Result<(), String> {
    // Take fd 3 specifically: open `/dev/null`, then `dup2` it onto `STDERR_FILENO + 1`, which
    // closes anything already there and makes fd 3 definitively open and ours.
    // SAFETY: opening a real file for reading only.
    let source = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if source < 0 {
        return Err(format!(
            "open /dev/null failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `dup2` duplicates an open descriptor onto `STDERR_FILENO + 1`.
    let boundary = unsafe { libc::dup2(source, libc::STDERR_FILENO + 1) };
    // The error, if any, must be read before `close(source)` below: a successful `close` is
    // itself permitted to alter `errno`, so capturing it here (rather than after the cleanup
    // close) is what makes a reported failure describe `dup2`'s own error, not whatever `close`
    // left behind.
    let dup2_error = std::io::Error::last_os_error();
    if source != libc::STDERR_FILENO + 1 {
        // SAFETY: closing the now-redundant source descriptor.
        unsafe { libc::close(source) };
    }
    if boundary != libc::STDERR_FILENO + 1 {
        return Err(format!(
            "dup2 onto the lower boundary returned {boundary}: {dup2_error}"
        ));
    }

    let before = open_descriptors_above_stderr()?;
    if !before.contains(&(libc::STDERR_FILENO + 1)) {
        return Err(format!(
            "the exact lower boundary (fd {}) was not open before the call even after planting \
             it; the census is broken: {before:?}",
            libc::STDERR_FILENO + 1
        ));
    }

    close_descriptors::close_inherited_descriptors()
        .map_err(|error| format!("close_inherited_descriptors returned an error: {error}"))?;

    if is_open(libc::STDERR_FILENO + 1) {
        return Err(format!(
            "the descriptor at the exact lower boundary (fd {}) survived the call",
            libc::STDERR_FILENO + 1
        ));
    }
    let after = open_descriptors_above_stderr()?;
    if !after.is_empty() {
        return Err(format!(
            "descriptors above stderr survived the call: {after:?} (were open before: {before:?})"
        ));
    }
    Ok(())
}

/// Every open descriptor above `STDERR_FILENO`, read from `/proc/self/fd` directly. Entry errors
/// are propagated, not skipped (a dropped entry could hide a survivor). Numbers are collected
/// first so the directory handle's own descriptor drops before the open-check and is not misread.
#[cfg(target_os = "linux")]
fn open_descriptors_above_stderr() -> Result<Vec<libc::c_int>, String> {
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("read /proc/self/fd failed: {error}"))?;
    let mut descriptors = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read a /proc/self/fd entry failed: {error}"))?;
        if let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
        {
            descriptors.push(number);
        }
    }
    // Dropped at the end of the loop above, before the filter below runs -- see the doc comment.
    Ok(descriptors
        .into_iter()
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO && is_open(*descriptor))
        .collect())
}

/// Duplicate an open descriptor onto the lowest number at or above `minimum` that is not already
/// taken, so the test never collides with whatever the harness already has open and never assumes
/// a fixed descriptor number is available on every host.
#[cfg(target_os = "linux")]
fn plant_descriptor(minimum: libc::c_int) -> Result<libc::c_int, String> {
    // SAFETY: opening a real file for reading only.
    let source = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if source < 0 {
        return Err(format!(
            "open /dev/null failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `F_DUPFD` returns the lowest free descriptor at or above `minimum`, duplicating
    // `source`; `source` is closed right after since only the duplicate is needed.
    let planted = unsafe { libc::fcntl(source, libc::F_DUPFD, minimum) };
    // Capture the error, if any, before `close(source)` below can alter `errno` with its own
    // (successful) result.
    let fcntl_error = std::io::Error::last_os_error();
    if source != planted {
        // SAFETY: closing the now-redundant source descriptor (only when it is a different fd).
        unsafe { libc::close(source) };
    }
    if planted < 0 {
        return Err(format!("F_DUPFD failed: {fcntl_error}"));
    }
    Ok(planted)
}

/// Whether one descriptor number is open.
#[cfg(target_os = "linux")]
fn is_open(descriptor: libc::c_int) -> bool {
    // SAFETY: `F_GETFD` only inspects a descriptor number.
    unsafe { libc::fcntl(descriptor, libc::F_GETFD) != -1 }
}
