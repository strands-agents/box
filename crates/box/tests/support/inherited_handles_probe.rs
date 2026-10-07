//! Test-only workload that verifies the final descriptor table before and after re-exec.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::ExitCode;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> ExitCode {
    let phase = std::env::args().nth(1);
    if phase.as_deref() == Some("stdio-metadata") {
        return stdio_metadata();
    }
    if !matches!(phase.as_deref(), Some("initial" | "reexec")) {
        eprintln!("usage: box-inherited-handles-probe <initial|reexec|stdio-metadata>");
        return ExitCode::from(2);
    }
    let phase = phase.unwrap_or_default();

    let open = match open_descriptors() {
        Ok(open) => open,
        Err(reason) => {
            eprintln!("probe: {reason}");
            return ExitCode::from(2);
        }
    };
    // The census must enumerate before its emptiness means anything: stderr is open, so it appears.
    // Without this an unavailable census would report no leak and read as a pass.
    if !open.contains(&libc::STDERR_FILENO) {
        eprintln!("probe: the census found no stderr during {phase}, so it enumerated nothing");
        return ExitCode::from(2);
    }
    let unexpected: Vec<i32> = open
        .into_iter()
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        .collect();
    if !unexpected.is_empty() {
        eprintln!("probe: unexpected descriptors survived during {phase}: {unexpected:?}");
        return ExitCode::from(1);
    }

    if phase == "reexec" {
        println!("only standard streams survived launch and re-exec");
        return ExitCode::SUCCESS;
    }

    let program = std::env::args().next().expect("argv[0]");
    let error = std::process::Command::new(program).arg("reexec").exec();
    eprintln!("probe: re-exec failed: {error}");
    ExitCode::from(2)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stdio_metadata() -> ExitCode {
    for descriptor in 0..=2 {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `metadata` holds enough writable bytes for `fstat`.
        let result = unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) };
        let error = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        };
        println!("fstat({descriptor})={result},errno={error}");
    }
    ExitCode::SUCCESS
}

/// Every descriptor this process holds, standard streams included.
#[cfg(target_os = "linux")]
fn open_descriptors() -> Result<Vec<i32>, String> {
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("cannot enumerate /proc/self/fd: {error}"))?;
    let candidates: Vec<i32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    // The directory descriptor appears in its own listing and closes after collection.
    Ok(candidates.into_iter().filter(|d| is_open(*d)).collect())
}

/// Every descriptor this process holds, standard streams included.
///
/// The box grants no read on `/dev/fd`, so this asks the kernel about this process rather than
/// reading a directory. The profile permits `process-info*` on `(target self)`.
#[cfg(target_os = "macos")]
fn open_descriptors() -> Result<Vec<i32>, String> {
    match listed_descriptors() {
        Some(listed) => Ok(listed.into_iter().filter(|d| is_open(*d)).collect()),
        // The list is unavailable, so sweep the table rather than report an empty census.
        None => swept_descriptors(),
    }
}

/// The descriptor list the kernel reports for this process, or `None` when it refuses.
#[cfg(target_os = "macos")]
fn listed_descriptors() -> Option<Vec<i32>> {
    let pid = libc::c_int::try_from(std::process::id()).ok()?;
    // SAFETY: a null buffer of size zero asks only how many bytes the list needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }
    // Headroom, because the table can grow between the two calls.
    let capacity = usize::try_from(needed / libc::PROC_PIDLISTFD_SIZE).ok()? + 16;
    let mut buffer = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        capacity
    ];
    let size = libc::c_int::try_from(capacity * std::mem::size_of::<libc::proc_fdinfo>()).ok()?;
    // SAFETY: `buffer` owns `size` writable bytes for the duration of the call.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    // A full buffer means the list may be truncated, and a census that under-reports is the one
    // failure this whole test rests on not having. Fall back to the sweep rather than trust it.
    if written <= 0 || written >= size {
        return None;
    }
    let reported = usize::try_from(written / libc::PROC_PIDLISTFD_SIZE).ok()?;
    Some(
        buffer[..reported.min(capacity)]
            .iter()
            .map(|entry| entry.proc_fd)
            .collect(),
    )
}

/// Every open descriptor, found by probing each number in the table.
#[cfg(target_os = "macos")]
fn swept_descriptors() -> Result<Vec<i32>, String> {
    // SAFETY: `getdtablesize` takes no argument and only reports a limit.
    let maximum = unsafe { libc::getdtablesize() };
    if maximum < 0 {
        return Err(format!(
            "cannot read the descriptor table size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((0..maximum).filter(|d| is_open(*d)).collect())
}

/// Whether one descriptor number is open.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_open(descriptor: i32) -> bool {
    // SAFETY: `F_GETFD` only inspects a descriptor number.
    unsafe { libc::fcntl(descriptor, libc::F_GETFD) != -1 }
}
