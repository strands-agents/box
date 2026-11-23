use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::Panel;
use nix::libc;
use nix::sys::termios::{self, LocalFlags, SetArg};

#[test]
fn panel_child() {
    let Ok(mode) = std::env::var("BOX_PANEL_TEST_MODE") else {
        return;
    };
    let signal: i32 = std::env::var("BOX_PANEL_TEST_SIGNAL")
        .unwrap()
        .parse()
        .unwrap();
    let received = Arc::new(AtomicBool::new(false));
    if mode == "previous-handler" {
        signal_hook::flag::register(signal, received.clone()).unwrap();
    }
    let panel = Panel::enter().unwrap();
    assert!(
        Panel::enter().is_err(),
        "two panels cannot own the terminal"
    );
    if mode == "active" {
        let mut raw = termios::tcgetattr(io::stdin()).unwrap();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &raw).unwrap();
    } else {
        drop(panel);
    }
    if mode == "next-handler" {
        signal_hook::flag::register(signal, received.clone()).unwrap();
    }
    eprintln!("READY");
    io::stderr().flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !received.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        received.load(Ordering::Relaxed),
        "{mode}: termination signal was ignored"
    );
}

#[test]
fn panels_restore_the_terminal_and_leave_signal_handlers_intact() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        for mode in ["closed", "active", "previous-handler", "next-handler"] {
            let pair = nix::pty::openpty(None, None).unwrap();
            let mut master = File::from(pair.master);
            let slave = File::from(pair.slave);
            let original = termios::tcgetattr(&slave).unwrap();
            // SAFETY: this file descriptor remains owned by master.
            assert_eq!(
                unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
                0
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "panel::tests::panel_child", "--nocapture"])
                .env("BOX_PANEL_TEST_MODE", mode)
                .env("BOX_PANEL_TEST_SIGNAL", signal.to_string())
                .env("TERM", "xterm-256color")
                .stdin(slave.try_clone().unwrap())
                .stdout(slave.try_clone().unwrap())
                .stderr(slave.try_clone().unwrap())
                .spawn()
                .unwrap();
            let mut output = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut sent = false;
            let status = loop {
                let mut bytes = [0; 4096];
                match master.read(&mut bytes) {
                    Ok(count) => output.extend_from_slice(&bytes[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("{mode}: {error}"),
                }
                if !sent && output.windows(5).any(|text| text == b"READY") {
                    // SAFETY: child is the process created above.
                    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
                    sent = true;
                }
                if let Some(status) = child.try_wait().unwrap() {
                    let _ = master.read_to_end(&mut output);
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("{mode}: timed out: {}", String::from_utf8_lossy(&output));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(sent, "{mode}: {}", String::from_utf8_lossy(&output));
            if mode == "active" || mode == "closed" {
                assert_eq!(
                    status.signal(),
                    Some(signal),
                    "{mode}: {}",
                    String::from_utf8_lossy(&output)
                );
            } else {
                assert!(
                    status.success(),
                    "{mode}: {}",
                    String::from_utf8_lossy(&output)
                );
            }
            let restored = termios::tcgetattr(&slave).unwrap();
            assert_eq!(restored.input_flags, original.input_flags, "{mode}");
            assert_eq!(restored.output_flags, original.output_flags, "{mode}");
            assert_eq!(restored.control_flags, original.control_flags, "{mode}");
            assert_eq!(restored.control_chars, original.control_chars, "{mode}");
            // PENDIN reports queued input, not a setting restored by tcsetattr.
            assert_eq!(
                restored.local_flags & !LocalFlags::PENDIN,
                original.local_flags & !LocalFlags::PENDIN,
                "{mode}"
            );
            assert!(
                output.windows(8).any(|text| text == b"\x1b[?1049l"),
                "{mode}: the alternate screen was not restored"
            );
        }
    }
}
