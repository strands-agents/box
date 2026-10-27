//! Fault controls compiled only into dedicated test builds.
use std::io;
#[cfg(box_native_test_faults)]
pub(super) fn at(stage: &str) -> io::Result<()> {
    let fault = std::env::var("BOX_NATIVE_TEST_FAULT").unwrap_or_default();
    let release = match stage {
        "entry-checked" => fault.strip_prefix("entry-race:"),
        "entry-verified" => fault.strip_prefix("entry-final-race:"),
        _ => None,
    };
    if let Some(release) = release {
        eprintln!("NATIVE_RACE_ENTRY_CHECKED");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !std::path::Path::new(release).exists() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "race test release absent",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    if stage == "worker-registration" && fault == "worker-registration" {
        std::thread::sleep(std::time::Duration::from_millis(250));
        eprintln!("NATIVE_TEST_FAULT=worker-registration");
        return Err(io::Error::other(
            "injected worker guard registration refusal",
        ));
    }
    if stage == "capability-probe" && fault == "capability-probe" {
        return Err(io::Error::other("injected path-only probe failure"));
    }
    if stage == "guard-reset" && fault == "guard-reset" {
        eprintln!("NATIVE_TEST_FAULT=guard-reset");
        return Err(io::Error::other("injected guard reset failure"));
    }
    if stage == "registration" && fault == "registration" {
        eprintln!("NATIVE_TEST_FAULT=registration");
        return Err(io::Error::other("injected native registration refusal"));
    }
    if stage == "request" && fault == "stall" {
        eprintln!("NATIVE_TEST_FAULT=stall");
        loop {
            std::thread::park();
        }
    }
    if stage == "request" && fault == "delay-once" {
        static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
        if FIRST.swap(false, std::sync::atomic::Ordering::AcqRel) {
            eprintln!("NATIVE_TEST_FAULT=delay-once");
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    if stage == "request" && fault == "panic" {
        eprintln!("NATIVE_TEST_FAULT=panic");
        panic!("injected native worker panic");
    }
    if (stage == "request" && fault == "request-storage")
        || (stage == "outcome" && fault == "outcome-storage")
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: limit is initialized and live through both calls; SIG_IGN is a valid signal disposition.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            limit.rlim_cur = 0;
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        eprintln!("NATIVE_TEST_FAULT={fault}");
    }
    Ok(())
}

#[cfg(not(box_native_test_faults))]
pub(super) fn at(_stage: &str) -> io::Result<()> {
    Ok(())
}
