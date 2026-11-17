use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};

static REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request(_signal: i32) {
    REQUESTED.store(true, Ordering::Relaxed);
}

unsafe extern "C" {
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
}

pub(super) fn install() -> io::Result<()> {
    for number in [2, 15] {
        // SAFETY: POSIX SIGINT/SIGTERM use a permanent handler that only stores a lock-free atomic.
        if unsafe { signal(number, request) } == usize::MAX {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn check() -> io::Result<()> {
    if REQUESTED.load(Ordering::Relaxed) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "harness shutdown requested",
        ))
    } else {
        Ok(())
    }
}
