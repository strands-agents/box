//! Signal controls for isolated Linux unit-test processes.

use std::sync::atomic::{AtomicUsize, Ordering};

static DELIVERED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn record_signal(_: libc::c_int) {
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}

pub(super) struct SignalGuard(libc::sigaction);

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: restore the action saved before the test installed its handler.
        unsafe { libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut()) };
    }
}

pub(super) fn arm() -> SignalGuard {
    // These tests run in separate processes. The handler changes no shared test state.
    let mut old = unsafe { std::mem::zeroed() };
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = record_signal as *const () as libc::sighandler_t;
    // No SA_RESTART: the blocked syscall must report EINTR.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut old) },
        0
    );
    DELIVERED.store(0, Ordering::Relaxed);
    SignalGuard(old)
}

pub(super) fn interrupt_blocked(
    tid: libc::pid_t,
    thread: libc::pthread_t,
    syscall: libc::c_long,
    descriptor: libc::c_int,
) {
    let path = format!("/proc/self/task/{tid}/syscall");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let state = std::fs::read_to_string(&path).expect("read the worker's syscall");
        let fields: Vec<_> = state.split_whitespace().collect();
        let number = fields
            .first()
            .and_then(|value| value.parse::<libc::c_long>().ok());
        let argument = fields
            .get(1)
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok());
        if number == Some(syscall) && argument == Some(descriptor as u64) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker did not block: {state}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let before = DELIVERED.load(Ordering::Relaxed);
    assert_eq!(unsafe { libc::pthread_kill(thread, libc::SIGUSR1) }, 0);
    while DELIVERED.load(Ordering::Relaxed) == before {
        assert!(
            std::time::Instant::now() < deadline,
            "worker did not receive SIGUSR1"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub(super) fn interrupted_write(
    operation: impl FnOnce(libc::c_int) + Send + 'static,
    expected: u8,
) {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    let _signal = arm();
    let mut ends = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let mut reader = unsafe { std::fs::File::from_raw_fd(ends[0]) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(ends[1]) };
    let capacity = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ) };
    assert!(capacity > 0);
    writer.write_all(&vec![0; capacity as usize]).unwrap();
    let descriptor = writer.as_raw_fd();
    let (ready, started) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        ready
            .send(unsafe {
                (
                    libc::syscall(libc::SYS_gettid) as libc::pid_t,
                    libc::pthread_self(),
                )
            })
            .unwrap();
        operation(writer.as_raw_fd());
    });
    let (tid, thread) = started.recv().unwrap();
    interrupt_blocked(tid, thread, libc::SYS_write, descriptor);
    let mut received = Vec::new();
    reader.read_to_end(&mut received).unwrap();
    worker.join().unwrap();
    assert_eq!(received.len(), capacity as usize + 1);
    assert!(received[..capacity as usize].iter().all(|byte| *byte == 0));
    assert_eq!(received[capacity as usize], expected);
}
