//! User-namespace and inherited-filter probes for the Linux integration tests.

use std::ffi::{CStr, CString};
use std::process::ExitCode;

use serde::Serialize;

#[derive(Clone, Copy, Default, Serialize)]
#[repr(C)]
struct State {
    user_namespace: u64,
    inheritable: u64,
    permitted: u64,
    effective: u64,
    bounding: u64,
    ambient: u64,
    no_new_privs: u64,
    seccomp: u64,
}

#[derive(Clone, Copy, Default, Serialize)]
#[repr(C)]
struct Report {
    before: State,
    after: State,
    state_error: u64,
    operation_error: u64,
    private_mount_error: u64,
    mount_error: u64,
    fsopen_error: u64,
    child_error: u64,
    target_namespace: u64,
    fork_error: u64,
    thread_error: u64,
    spawn_error: u64,
}

fn errno() -> u64 {
    // SAFETY: libc provides this thread's errno address.
    unsafe { *libc::__errno_location() as u64 }
}

fn state() -> Result<State, u64> {
    // SAFETY: open receives a static path and returns an owned descriptor.
    let descriptor = unsafe {
        libc::open(
            c"/proc/self/status".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(errno());
    }
    let mut bytes = [0_u8; 8192];
    let mut used = 0;
    while used < bytes.len() {
        // SAFETY: the unused buffer suffix is writable for the requested length.
        let count = unsafe {
            libc::read(
                descriptor,
                bytes[used..].as_mut_ptr().cast(),
                bytes.len() - used,
            )
        };
        if count < 0 && errno() == libc::EINTR as u64 {
            continue;
        }
        if count < 0 {
            let error = errno();
            // SAFETY: this process owns the open descriptor.
            unsafe { libc::close(descriptor) };
            return Err(error);
        }
        if count == 0 {
            break;
        }
        used += count as usize;
    }
    // SAFETY: this process owns the open descriptor.
    unsafe { libc::close(descriptor) };
    if used == bytes.len() {
        return Err(libc::EOVERFLOW as u64);
    }
    let text = std::str::from_utf8(&bytes[..used]).map_err(|_| libc::EILSEQ as u64)?;
    let mut result = State::default();
    let mut fields = 0;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (field, radix) = match name {
            "CapInh" => (&mut result.inheritable, 16),
            "CapPrm" => (&mut result.permitted, 16),
            "CapEff" => (&mut result.effective, 16),
            "CapBnd" => (&mut result.bounding, 16),
            "CapAmb" => (&mut result.ambient, 16),
            "NoNewPrivs" => (&mut result.no_new_privs, 10),
            "Seccomp" => (&mut result.seccomp, 10),
            _ => continue,
        };
        *field = u64::from_str_radix(value.trim(), radix).map_err(|_| libc::EINVAL as u64)?;
        fields += 1;
    }
    if fields != 7 {
        return Err(libc::ENODATA as u64);
    }
    // SAFETY: zero is a valid initial representation for this output record.
    let mut namespace: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat receives a static path and a writable record.
    if unsafe { libc::stat(c"/proc/self/ns/user".as_ptr(), &mut namespace) } != 0 {
        return Err(errno());
    }
    result.user_namespace = namespace.st_ino;
    Ok(result)
}

fn mounts(report: &mut Report, target: &CStr, needs_namespace: bool) {
    // SAFETY: unshare creates a private mount namespace before any mount attempt.
    if needs_namespace && unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        report.private_mount_error = errno();
        return;
    }
    // SAFETY: mount and umount use the owned fixture directory inside this private namespace.
    if unsafe {
        libc::mount(
            c"none".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"size=4096".as_ptr().cast(),
        )
    } != 0
    {
        report.mount_error = errno();
    } else if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
        report.child_error = errno();
    }
    // SAFETY: fsopen receives a static filesystem name and no mount target.
    let descriptor = unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 1) };
    if descriptor < 0 {
        report.fsopen_error = errno();
    } else {
        // SAFETY: this process owns the returned descriptor.
        unsafe { libc::close(descriptor as i32) };
    }
}

fn after(report: &mut Report, target: &CStr, needs_namespace: bool) {
    match state() {
        Ok(value) => report.after = value,
        Err(error) => {
            report.state_error = error;
            return;
        }
    }
    mounts(report, target, needs_namespace);
}

fn transfer(descriptor: i32, record: &mut Report, writing: bool) -> bool {
    let size = std::mem::size_of::<Report>();
    let mut offset = 0;
    while offset < size {
        // SAFETY: Report consists solely of initialized u64 fields, with no padding.
        let pointer = unsafe { (record as *mut Report).cast::<u8>().add(offset) };
        // SAFETY: the descriptor transfers only the remaining bytes of this live record.
        let count = unsafe {
            if writing {
                libc::write(descriptor, pointer.cast(), size - offset)
            } else {
                libc::read(descriptor, pointer.cast(), size - offset)
            }
        };
        if count < 0 && errno() == libc::EINTR as u64 {
            continue;
        }
        if count <= 0 {
            return false;
        }
        offset += count as usize;
    }
    true
}

fn wait(pid: libc::pid_t, expected: i32) -> u64 {
    let mut status = 0;
    // SAFETY: the caller owns this child process.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if errno() != libc::EINTR as u64 {
            return errno();
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == expected {
        0
    } else {
        libc::ECHILD as u64
    }
}

fn clone_namespace(report: &mut Report, target: &CStr, clone3: bool, view_control: bool) {
    let mut pipe = [0; 2];
    // SAFETY: pipe is writable for two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        report.child_error = errno();
        return;
    }
    #[repr(C)]
    #[derive(Default)]
    struct CloneArguments {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }
    let arguments = CloneArguments {
        flags: libc::CLONE_NEWUSER as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArguments::default()
    };
    // SAFETY: neither form shares memory or supplies a new stack; the child performs only syscalls.
    let pid = unsafe {
        if clone3 {
            libc::syscall(
                libc::SYS_clone3,
                &arguments,
                std::mem::size_of_val(&arguments),
            )
        } else {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWUSER
                    | libc::SIGCHLD
                    | if view_control {
                        libc::CLONE_NEWNS | libc::CLONE_NEWPID
                    } else {
                        0
                    },
                0,
                0,
                0,
                0,
            )
        }
    };
    if pid == 0 {
        // SAFETY: the child uses only syscall-backed helpers and exits without destructors.
        unsafe {
            libc::close(pipe[0]);
            libc::alarm(10);
        }
        if view_control {
            // SAFETY: target is an owned fixture in this new user, mount, and PID namespace.
            if unsafe {
                libc::mount(
                    c"proc".as_ptr(),
                    target.as_ptr(),
                    c"proc".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } != 0
            {
                report.mount_error = errno();
            }
        } else {
            after(report, target, true);
        }
        let sent = transfer(pipe[1], report, true);
        // SAFETY: the child terminates without inherited Rust destructors.
        unsafe { libc::_exit(if sent { 0 } else { 1 }) };
    }
    if pid < 0 {
        report.operation_error = errno();
    }
    // SAFETY: the parent owns this pipe endpoint.
    unsafe { libc::close(pipe[1]) };
    if pid > 0 {
        if !transfer(pipe[0], report, false) {
            report.child_error = libc::EIO as u64;
        }
        let error = wait(pid as i32, 0);
        if error != 0 {
            report.child_error = error;
        }
    }
    // SAFETY: the parent owns this pipe endpoint.
    unsafe { libc::close(pipe[0]) };
}

fn enter_namespace(report: &mut Report, target: &CStr, kind: &str) {
    let pidfd = kind == "setns-pidfd";
    let mut ready = [0; 2];
    let mut done = [0; 2];
    // SAFETY: ready is writable for two descriptors.
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        report.child_error = errno();
        return;
    }
    // SAFETY: done is writable for two descriptors.
    if unsafe { libc::pipe2(done.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        report.child_error = errno();
        // SAFETY: this process owns both ready-pipe endpoints.
        unsafe {
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        return;
    }
    // SAFETY: the single-threaded child uses only syscall-backed helpers and _exit.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: the child owns these endpoints and sets its own finite lifetime.
        unsafe {
            libc::close(ready[0]);
            libc::close(done[1]);
            libc::alarm(10);
        }
        let flags = libc::CLONE_NEWUSER | if pidfd { libc::CLONE_NEWNS } else { 0 };
        // SAFETY: the single-threaded child requests only new private namespaces.
        if unsafe { libc::unshare(flags) } != 0 {
            report.operation_error = errno();
        } else {
            match state() {
                Ok(value) => report.target_namespace = value.user_namespace,
                Err(error) => report.state_error = error,
            }
        }
        let sent = transfer(ready[1], report, true);
        let mut byte = 0_u8;
        // SAFETY: the byte is writable, and the child then exits without destructors.
        unsafe {
            libc::read(done[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(if sent { 0 } else { 1 });
        }
    }
    if pid < 0 {
        report.child_error = errno();
    }
    // SAFETY: the parent owns its copies of these pipe endpoints.
    unsafe {
        libc::close(ready[1]);
        libc::close(done[0]);
    }
    if pid > 0 {
        if !transfer(ready[0], report, false) {
            report.child_error = libc::EIO as u64;
        }
        if report.operation_error == 0 && report.state_error == 0 && report.child_error == 0 {
            let path = CString::new(format!("/proc/{pid}/ns/user")).expect("namespace path");
            // SAFETY: the child remains alive and path is a valid namespace path.
            let descriptor = unsafe {
                if pidfd {
                    libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32
                } else {
                    libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
                }
            };
            if descriptor < 0 {
                report.operation_error = errno();
            } else {
                let flags = match kind {
                    "setns-zero" => 0,
                    "setns-pidfd" => libc::CLONE_NEWUSER | libc::CLONE_NEWNS,
                    _ => libc::CLONE_NEWUSER,
                };
                // SAFETY: descriptor identifies the owned fixture namespace or its live process.
                if unsafe { libc::setns(descriptor, flags) } != 0 {
                    report.operation_error = errno();
                } else {
                    after(report, target, !pidfd);
                }
                // SAFETY: this process owns the open descriptor.
                unsafe { libc::close(descriptor) };
            }
        }
        let byte = 0_u8;
        // SAFETY: the byte is readable and the parent owns the pipe endpoint.
        unsafe {
            libc::write(done[1], (&byte as *const u8).cast(), 1);
        }
    }
    // SAFETY: the parent owns these final pipe endpoints.
    unsafe {
        libc::close(ready[0]);
        libc::close(done[1]);
    }
    if pid > 0 {
        let error = wait(pid, 0);
        if error != 0 {
            report.child_error = error;
        }
    }
}

extern "C" fn thread_target(_: *mut libc::c_void) -> *mut libc::c_void {
    42_usize as *mut libc::c_void
}

fn ordinary(report: &mut Report, executable: &CStr) {
    // SAFETY: the child immediately exits without Rust cleanup.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: this child immediately exits without inherited Rust destructors.
        unsafe { libc::_exit(42) }
    }
    report.fork_error = if pid < 0 { errno() } else { wait(pid, 42) };
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    // SAFETY: the entry point touches no shared data and returns one sentinel value.
    let created = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            std::ptr::null(),
            thread_target,
            std::ptr::null_mut(),
        )
    };
    if created != 0 {
        report.thread_error = created as u64;
    } else {
        let mut value = std::ptr::null_mut();
        // SAFETY: pthread_create initialized this joinable thread, and value is writable.
        let joined = unsafe { libc::pthread_join(thread.assume_init(), &mut value) };
        if joined != 0 {
            report.thread_error = joined as u64;
        } else if value != 42_usize as *mut libc::c_void {
            report.thread_error = libc::EINVAL as u64;
        }
    }
    let mut pid = 0;
    let arguments = [
        executable.as_ptr().cast_mut(),
        c"--user-namespace".as_ptr().cast_mut(),
        c"exec-child".as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    let environment = [std::ptr::null_mut()];
    // SAFETY: argument and environment arrays are null-terminated and live across posix_spawn.
    let spawned = unsafe {
        libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            arguments.as_ptr(),
            environment.as_ptr(),
        )
    };
    report.spawn_error = if spawned == 0 {
        wait(pid, 73)
    } else {
        spawned as u64
    };
    match state() {
        Ok(value) => report.after = value,
        Err(error) => report.state_error = error,
    }
}

pub(super) fn run(arguments: &[String]) -> ExitCode {
    if arguments.get(2).is_some_and(|value| value == "exec-child") {
        return ExitCode::from(73);
    }
    if arguments.len() != 4 {
        eprintln!("usage: containment-test-probe --user-namespace <route> <mount-directory>");
        return ExitCode::from(2);
    }
    let target = CString::new(arguments[3].as_bytes()).expect("mount path");
    let executable = CString::new(arguments[0].as_bytes()).expect("probe path");
    let mut report = Report::default();
    // SAFETY: the probe runs as an owned subprocess with a finite lifetime.
    unsafe { libc::alarm(15) };
    match state() {
        Ok(value) => report.before = value,
        Err(error) => report.state_error = error,
    }
    if report.state_error == 0 {
        match arguments[2].as_str() {
            "unshare-user" | "unshare-user-mount" => {
                let mount_namespace = arguments[2] == "unshare-user-mount";
                let flags = libc::CLONE_NEWUSER
                    | if mount_namespace {
                        libc::CLONE_NEWNS
                    } else {
                        0
                    };
                // SAFETY: this single-threaded probe requests only new private namespaces.
                if unsafe { libc::unshare(flags) } != 0 {
                    report.operation_error = errno();
                } else {
                    after(&mut report, &target, !mount_namespace);
                }
            }
            "clone-user" => clone_namespace(&mut report, &target, false, false),
            "clone3-user" => clone_namespace(&mut report, &target, true, false),
            "setns-explicit" | "setns-zero" | "setns-pidfd" => {
                enter_namespace(&mut report, &target, &arguments[2])
            }
            "view-control" => clone_namespace(&mut report, &target, false, true),
            "ordinary" => ordinary(&mut report, &executable),
            _ => return ExitCode::from(2),
        }
    }
    println!("{}", serde_json::to_string(&report).expect("probe report"));
    ExitCode::SUCCESS
}
