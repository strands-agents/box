use std::os::fd::AsRawFd as _;
use std::process::ExitCode;

pub fn run() -> ExitCode {
    match check_routes() {
        Ok(()) => {
            println!("EXECUTABLE_MEMORY_DENIED");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("probe FAILED: {error}");
            ExitCode::from(1)
        }
    }
}

fn check_routes() -> Result<(), String> {
    use std::os::unix::fs::FileExt as _;

    let mut direct = std::hint::black_box(7_u8);
    // A successful self-read proves that missing memory access cannot satisfy the denial tests.
    let mem = std::fs::File::open("/proc/self/mem").map_err(|e| format!("self-read open: {e}"))?;
    let mut control = [0_u8; 1];
    mem.read_exact_at(&mut control, (&direct as *const u8) as u64)
        .map_err(|e| format!("self-read: {e}"))?;
    if control != [7] {
        return Err("self-read returned the wrong byte".into());
    }
    direct = std::hint::black_box(42);
    if std::hint::black_box(direct) != 42 {
        return Err("direct memory write failed".into());
    }
    // SAFETY: anonymous private mappings; no mapped code is executed.
    let writable = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if writable == libc::MAP_FAILED {
        return Err("writable mapping failed".into());
    }
    // SAFETY: writable points at the private page above.
    unsafe {
        writable.cast::<u8>().write_volatile(42);
        let observed = writable.cast::<u8>().read_volatile();
        libc::munmap(writable, 4096);
        if observed != 42 {
            return Err("writable mapping did not retain a byte".into());
        }
    }
    let pid = std::process::id();
    // SAFETY: gettid has no arguments.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    for route in [
        "/proc/self/mem".into(),
        "/proc/thread-self/mem".into(),
        "/proc/self/root/proc/self/mem".into(),
        format!("/proc/{pid}/mem"),
        format!("/proc/self/task/{tid}/mem"),
        format!("/proc/self/fd/{}", mem.as_raw_fd()),
    ] {
        deny_executable_write(&route)?;
    }
    // SAFETY: this probe is single-threaded; the child checks its own memory and exits.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err("fork failed".into());
    }
    if child == 0 {
        let status = i32::from(deny_executable_write("/proc/self/mem").is_err());
        // SAFETY: terminate the child without returning into the probe.
        unsafe { libc::_exit(status) };
    }
    let mut status = 0;
    // SAFETY: wait only for the child just created.
    if unsafe { libc::waitpid(child, &mut status, 0) } != child
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err("child memory route failed".into());
    }
    Ok(())
}

fn deny_executable_write(route: &str) -> Result<(), String> {
    use std::os::unix::fs::FileExt as _;

    // SAFETY: one anonymous, private read-execute page; never executed.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Err(format!("{route}: read-execute mapping failed"));
    }
    let result = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(route)
    {
        Err(error) if error.raw_os_error() == Some(libc::EROFS) => Ok(()),
        Err(error) => Err(format!("{route}: unexpected open error: {error}")),
        Ok(file) => match file.write_at(&[0x7f], page as u64) {
            Ok(1) => Err(format!("{route}: wrote an executable page")),
            result => Err(format!(
                "{route}: writable memory handle; write result {result:?}"
            )),
        },
    };
    // SAFETY: page is the mapping made above, and no references survive.
    unsafe { libc::munmap(page, 4096) };
    result
}
