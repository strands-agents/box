#![cfg(all(target_os = "macos", feature = "tls-intercept"))]

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::thread::{JoinHandleExt, RawPthread};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use egress_gateway::{
    CapabilitySet, EffectAttempt, EffectInterceptor, EffectPermit, MitmConfig, MitmInterceptor,
};

const SIGUSR1: i32 = 30;
const CHILD: &str = "STRANDS_BOX_INTERRUPTED_SHUTDOWN_CHILD";
static SIGNALS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
    fn pthread_kill(thread: RawPthread, number: i32) -> i32;
}

extern "C" fn handle_signal(_: i32) {
    SIGNALS.fetch_add(1, Ordering::Relaxed);
}

struct RefuseEffects;

impl EffectInterceptor for RefuseEffects {
    fn intercept(&self, _: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[test]
fn shutdown_completes_when_a_signal_interrupts_the_wakeup() {
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: The handler only changes a lock-free atomic in this isolated process.
        assert_ne!(unsafe { signal(SIGUSR1, handle_signal) }, usize::MAX);
        for attempt in 0..10 {
            interrupt_shutdown(attempt);
        }
        let handled = SIGNALS.load(Ordering::Relaxed);
        assert!(handled > 0, "no signal was handled");
        eprintln!("10 gateway shutdowns completed; {handled} signals handled");
        return;
    }

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "shutdown_completes_when_a_signal_interrupts_the_wakeup",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "shutdown regression child failed: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("shutdown regression child exceeded 15 seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn interrupt_shutdown(attempt: usize) {
    let handle = MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        Arc::new(RefuseEffects),
    )
    .unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], handle.port().unwrap()));
    let returned = Arc::new(AtomicBool::new(false));
    let (begin, started) = mpsc::channel();
    let (finished, completion) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let stopping = {
        let returned = Arc::clone(&returned);
        thread::spawn(move || {
            started.recv().unwrap();
            handle.shutdown();
            returned.store(true, Ordering::SeqCst);
            drop(handle);
            finished.send(()).unwrap();
            let _ = released.recv();
        })
    };
    let target = stopping.as_pthread_t();
    let handled = SIGNALS.load(Ordering::Relaxed);
    // SAFETY: The target thread is waiting for the start message.
    assert_eq!(unsafe { pthread_kill(target, SIGUSR1) }, 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while SIGNALS.load(Ordering::Relaxed) == handled && Instant::now() < deadline {
        thread::yield_now();
    }
    assert!(
        SIGNALS.load(Ordering::Relaxed) > handled,
        "the shutdown thread did not receive the signal"
    );
    begin.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut sent = 0;
    while !returned.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_micros(10));
        if !returned.load(Ordering::SeqCst) {
            // SAFETY: The thread waits for release after it completes shutdown.
            assert_eq!(unsafe { pthread_kill(target, SIGUSR1) }, 0);
            sent += 1;
        }
    }
    let completed = completion.recv_timeout(Duration::from_secs(1)).is_ok();
    if !completed {
        let _rescue = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        completion
            .recv_timeout(Duration::from_secs(1))
            .expect("a rescue connection must release the real listener");
    }
    release.send(()).unwrap();
    stopping.join().unwrap();
    assert!(
        completed,
        "attempt {attempt}: shutdown returned {}, but Drop needed a rescue connection after {sent} signals",
        returned.load(Ordering::SeqCst)
    );
}
