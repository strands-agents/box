//! Disposable-terminal checks for both installed workload filters.

use super::{Network, SyscallPolicy};
use crate::backend::linux::namespace::install_syscall_filters;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn terminal() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty initializes both descriptors and creates no controlling terminal.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: these are distinct descriptors returned by openpty.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

fn child(filtered: bool, probe: impl FnOnce() -> i32) -> i32 {
    let filters = SyscallPolicy::for_config(&Network::Blocked)
        .compile()
        .unwrap();
    // SAFETY: the child uses bounded syscall probes and exits without unwinding.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: terminate a stuck disposable probe instead of hanging the test runner.
        unsafe { libc::alarm(5) };
        let result = if filtered && install_syscall_filters(&filters).is_err() {
            90
        } else {
            probe()
        };
        // SAFETY: do not return into the test runner.
        unsafe { libc::_exit(result) };
    }
    let mut status = 0;
    // SAFETY: pid is this test's child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "probe was signalled: {status}");
    libc::WEXITSTATUS(status)
}

fn discipline(fd: i32) -> i32 {
    let mut value = -1;
    // SAFETY: value is an initialized integer output and fd stays open.
    assert_eq!(unsafe { libc::ioctl(fd, libc::TIOCGETD, &mut value) }, 0);
    value
}

#[test]
fn terminal_requests_are_denied_with_kernel_argument_truncation() {
    for request in [libc::TIOCSTI, libc::TIOCLINUX, libc::TIOCSETD] {
        for high in [0, 1_u64 << 32, 0xffff_ffff_0000_0000] {
            let request = high | u64::from(request as u32);
            for filtered in [false, true] {
                let expected = if filtered { libc::EPERM } else { libc::EBADF };
                assert_eq!(
                    child(filtered, || {
                        // SAFETY: an invalid descriptor prevents all terminal side effects.
                        let result = unsafe { libc::syscall(libc::SYS_ioctl, -1, request, 0) };
                        i32::from(result != -1 || unsafe { *libc::__errno_location() } != expected)
                    }),
                    0,
                    "request {request:#x}, filtered {filtered}"
                );
            }
        }
    }
}

#[test]
fn terminal_discipline_cannot_change_or_break_input() {
    for high in [0, 1_u64 << 32, 0xffff_ffff_0000_0000] {
        for filtered in [false, true] {
            let (master, slave) = terminal();
            let fd = slave.as_raw_fd();
            assert_eq!(discipline(fd), 0);
            let outcome = child(filtered, || {
                let null_discipline: libc::c_int = 27;
                // SAFETY: only this disposable terminal can change its line discipline.
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_ioctl,
                        fd,
                        high | u64::from(libc::TIOCSETD as u32),
                        &null_discipline,
                    )
                };
                if filtered {
                    i32::from(result != -1 || unsafe { *libc::__errno_location() } != libc::EPERM)
                } else {
                    i32::from(result != 0)
                }
            });
            // Observe the shared terminal from outside the filtered process.
            let observed = discipline(fd);
            // SAFETY: inspect input processing without blocking on an empty terminal.
            let (read_result, read_error) = unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                assert!(flags >= 0);
                assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
                let mut byte = 0u8;
                let result = libc::read(fd, (&mut byte as *mut u8).cast(), 1);
                let error = *libc::__errno_location();
                assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags), 0);
                (result, error)
            };
            let normal: libc::c_int = 0;
            // SAFETY: restore only the terminal created in this iteration, even after failure.
            assert_eq!(unsafe { libc::ioctl(fd, libc::TIOCSETD, &normal) }, 0);
            eprintln!(
                "line discipline: high={high:#x}, filtered={filtered}, observed={observed}, outcome={outcome}"
            );
            assert_eq!(
                outcome, 0,
                "line discipline operation: filtered={filtered}, observed={observed}"
            );
            assert_eq!(observed, if filtered { 0 } else { 27 });
            assert_eq!(read_result, -1);
            assert_eq!(
                read_error,
                if filtered {
                    libc::EAGAIN
                } else {
                    libc::EOPNOTSUPP
                }
            );
            let bytes = b"input still works\n";
            // SAFETY: both buffers and terminal descriptors are valid.
            assert_eq!(
                unsafe { libc::write(master.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
                bytes.len() as isize
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll names one live descriptor and has a bounded timeout.
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
            let mut buffer = [0u8; 64];
            // SAFETY: buffer has the advertised size.
            let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            assert_eq!(n, bytes.len() as isize);
            assert_eq!(&buffer[..n as usize], bytes);
        }
    }
}

#[test]
fn terminal_injection_requests_leave_the_input_queue_empty() {
    for request in [libc::TIOCSTI, libc::TIOCLINUX] {
        for high in [0, 1_u64 << 32, 0xffff_ffff_0000_0000] {
            let (_master, slave) = terminal();
            let fd = slave.as_raw_fd();
            let mut raw = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: initialize terminal settings, then disable canonical buffering on this PTY.
            unsafe {
                assert_eq!(libc::tcgetattr(fd, raw.as_mut_ptr()), 0);
                let mut raw = raw.assume_init();
                libc::cfmakeraw(&mut raw);
                assert_eq!(libc::tcsetattr(fd, libc::TCSANOW, &raw), 0);
            }
            // Subcode 3 is console paste. A PTY cannot exercise console selection/paste.
            let byte = if request == libc::TIOCLINUX {
                3u8
            } else {
                b'X'
            };
            assert_eq!(
                child(true, || {
                    // SAFETY: the kernel receives one initialized input byte on a private PTY.
                    let result = unsafe {
                        libc::syscall(libc::SYS_ioctl, fd, high | u64::from(request as u32), &byte)
                    };
                    i32::from(result != -1 || unsafe { *libc::__errno_location() } != libc::EPERM)
                }),
                0
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: allow queued input to arrive without an unbounded read.
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 100) }, 0);
            let mut count: libc::c_int = -1;
            // SAFETY: count is a valid output integer.
            assert_eq!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut count) }, 0);
            assert_eq!(count, 0);
        }
    }
}

#[test]
fn terminal_modes_size_input_output_and_restoration_remain_available() {
    let (master, slave) = terminal();
    let fd = slave.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: original points to sufficient output storage.
    assert_eq!(unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) }, 0);
    // SAFETY: tcgetattr initialized original.
    let original = unsafe { original.assume_init() };
    let input = b"hello\n";
    // SAFETY: input and master are live for the write.
    assert_eq!(
        unsafe { libc::write(master.as_raw_fd(), input.as_ptr().cast(), input.len()) },
        input.len() as isize
    );
    assert_eq!(
        child(true, || {
            let mut buffer = [0u8; 6];
            // SAFETY: bounded buffer and live slave descriptor.
            if unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) } != 6
                || &buffer != input
            {
                return 1;
            }
            let size = libc::winsize {
                ws_row: 39,
                ws_col: 107,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let mut observed = libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: both window-size objects have the required layout.
            if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) } != 0 {
                return 2;
            }
            if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut observed) } != 0 {
                return 3;
            }
            if observed.ws_row != 39 || observed.ws_col != 107 {
                return 4;
            }
            let mut raw = original;
            // SAFETY: raw is initialized, and both termios calls target the private slave.
            unsafe { libc::cfmakeraw(&mut raw) };
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
                return 5;
            }
            if unsafe { libc::write(fd, b"output".as_ptr().cast(), 6) } != 6 {
                return 6;
            }
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) } != 0 {
                return 7;
            }
            0
        }),
        0
    );
    let mut restored = original;
    // SAFETY: restored is valid output storage for the private slave.
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut restored) }, 0);
    assert_eq!(restored.c_iflag, original.c_iflag);
    assert_eq!(restored.c_oflag, original.c_oflag);
    assert_eq!(restored.c_cflag, original.c_cflag);
    assert_eq!(restored.c_lflag, original.c_lflag);
    assert_eq!(restored.c_cc, original.c_cc);
    let mut buffer = [0u8; 128];
    let mut poll = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded poll and read on the private master.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
    let n = unsafe { libc::read(master.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    assert!(n > 0);
    assert!(
        buffer[..n as usize]
            .windows(6)
            .any(|part| part == b"output")
    );
}

#[test]
fn terminal_interrupt_reaches_the_filtered_foreground_process() {
    let (master, slave) = terminal();
    let filters = SyscallPolicy::for_config(&Network::Blocked)
        .compile()
        .unwrap();
    let mut ready = [-1; 2];
    // SAFETY: ready holds storage for both returned descriptors.
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
    // SAFETY: pipe returned two distinct descriptors.
    let (reader, writer) = unsafe {
        (
            OwnedFd::from_raw_fd(ready[0]),
            OwnedFd::from_raw_fd(ready[1]),
        )
    };
    // SAFETY: child uses only syscalls and exits without unwinding.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: establish a new session with only the disposable terminal attached.
        unsafe {
            libc::alarm(5);
            if libc::setsid() < 0 || libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0) != 0 {
                libc::_exit(91);
            }
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            let mut mask = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) != 0 {
                libc::_exit(92);
            }
        }
        if install_syscall_filters(&filters).is_err() {
            // SAFETY: leave the probe process on filter installation failure.
            unsafe { libc::_exit(90) };
        }
        // SAFETY: notify the parent only after the terminal and filters are ready.
        unsafe {
            libc::write(writer.as_raw_fd(), b"R".as_ptr().cast(), 1);
            let mut buffer = [0u8; 8];
            libc::read(slave.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len());
            libc::_exit(93);
        }
    }
    let mut poll = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: bounded readiness wait on the pipe owned by this test.
    let ready_result = unsafe { libc::poll(&mut poll, 1, 2000) };
    if ready_result == 1 {
        // SAFETY: only the new session's foreground process can receive this interrupt.
        assert_eq!(
            unsafe { libc::write(master.as_raw_fd(), b"\x03".as_ptr().cast(), 1) },
            1
        );
    }
    let mut status = 0;
    // SAFETY: reap the child even when readiness fails; its alarm bounds the wait.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(
        ready_result, 1,
        "foreground probe never became ready: {status}"
    );
    assert!(
        libc::WIFSIGNALED(status),
        "interrupt did not terminate the child: {status}"
    );
    assert_eq!(libc::WTERMSIG(status), libc::SIGINT);
}
