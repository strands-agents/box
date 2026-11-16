//! Core diagnostics leave an active native terminal to the workload.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::json;

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};

const STARTUP: Duration = Duration::from_secs(45);
const SHUTDOWN: Duration = Duration::from_secs(10);
const REPORT: &str = "[mcp.alpha] runtime minimum, added by Core:";

fn fixture(exit: i32, terminal: bool) -> RuntimeMcpBox {
    let box_ = RuntimeMcpBox::new("terminal-diagnostics");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let input = if terminal {
        r#"
[ -t 0 ] && [ -t 1 ] && [ -t 2 ] || exit 71
printf '\033[?1049h\033[2J\033[HNATIVE_STDOUT\n'
printf '\033[3;4HNATIVE_STDERR\n' >&2
IFS= read -r response
[ "$response" = native-input ] || exit 72
"#
    } else {
        ""
    };
    box_.write_workspace(
        r#"permit (principal, action == Box::Action::"mcp:call", resource);"#,
        &[alpha],
        &format!(
            r#"set -eu
{input}
printf 'NATIVE_READY\n'
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
printf '\033[?1049lNATIVE_EXIT\n'
exit {exit}
"#
        ),
    );
    box_
}

struct Run {
    child: Child,
    input: Option<File>,
    output: Receiver<Vec<u8>>,
    bytes: Vec<u8>,
}

impl Run {
    fn start(mut command: Command, terminal: bool) -> Self {
        let (mut child, input, mut stream): (_, _, Box<dyn Read + Send>) = if terminal {
            let mut master = -1;
            let mut slave = -1;
            let mut size = libc::winsize {
                ws_row: 40,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: openpty initializes the two descriptors and only reads size.
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &raw mut size,
                    )
                },
                0
            );
            // SAFETY: each successful openpty descriptor is owned once.
            let master = unsafe { File::from_raw_fd(master) };
            let slave = unsafe { File::from_raw_fd(slave) };
            for file in [&master, &slave] {
                // SAFETY: the descriptor remains open through this call.
                assert_eq!(
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
            command
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::from(slave.try_clone().unwrap()))
                .stderr(Stdio::from(slave));
            // SAFETY: the child calls only session and terminal syscalls before exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn().expect("start Core in the terminal");
            let reader = Box::new(master.try_clone().unwrap());
            (child, Some(master), reader)
        } else {
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start Core with piped stderr");
            let reader = Box::new(child.stderr.take().unwrap());
            (child, None, reader)
        };
        drop(child.stdin.take());
        let (send, output) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0; 8192];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        if send.send(buffer[..length].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("read Core output: {error}"),
                }
            }
        });
        Self {
            child,
            input,
            output,
            bytes: Vec::new(),
        }
    }

    fn read_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.output.recv_timeout(remaining) {
                Ok(bytes) => self.bytes.extend(bytes),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    fn wait_for(&mut self, ready: impl Fn(&Self) -> bool, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !ready(self) {
            assert!(Instant::now() < deadline, "timed out:\n{}", self.text());
            self.read_for(Duration::from_millis(20));
            assert!(
                self.child.try_wait().unwrap().is_none() || ready(self),
                "Core exited before the expected output:\n{}",
                self.text()
            );
        }
    }

    fn wait_text(&mut self, text: &str) {
        self.wait_for(|run| run.text().contains(text), STARTUP);
    }

    fn wait_file(&mut self, path: &Path) {
        self.wait_for(|_| path.exists(), STARTUP);
    }

    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + SHUTDOWN;
        loop {
            self.read_for(Duration::from_millis(20));
            if let Some(status) = self.child.try_wait().unwrap() {
                self.read_for(Duration::from_millis(100));
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Core did not exit:\n{}",
                self.text()
            );
        }
    }

    fn signal(&self) {
        // SAFETY: the pid belongs to the child this test owns.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as _, libc::SIGTERM) },
            0
        );
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // SAFETY: the pid belongs to the child this test owns.
            let _ = unsafe { libc::kill(self.child.id() as _, libc::SIGTERM) };
            let deadline = Instant::now() + SHUTDOWN;
            while Instant::now() < deadline && self.child.try_wait().ok().flatten().is_none() {
                self.read_for(Duration::from_millis(20));
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn start_server(box_: &RuntimeMcpBox) -> runtime_mcp::RunningMcpClient {
    let mut client = box_.open_client("alpha-mcp");
    client.initialize_and_activate(json!("terminal"), STARTUP);
    client.assert_running();
    client
}

fn terminal_run(exit: i32, terminate: bool) {
    let box_ = fixture(exit, true);
    let mut run = Run::start(box_.command_for_run(), true);
    run.wait_text("NATIVE_STDERR");
    run.input
        .as_mut()
        .unwrap()
        .write_all(b"native-input\n")
        .unwrap();
    run.wait_text("NATIVE_READY\r\n");
    let startup = "[mcp.alpha] starts on demand; approved direct filesystem grants:";
    assert!(
        run.text().find(startup).unwrap() < run.text().find("NATIVE_STDOUT").unwrap(),
        "initial permissions precede the native screen:\n{}",
        run.text()
    );
    for expected in [
        b"\x1b[?1049h\x1b[2J\x1b[HNATIVE_STDOUT".as_slice(),
        b"\x1b[3;4HNATIVE_STDERR".as_slice(),
    ] {
        assert!(
            run.bytes
                .windows(expected.len())
                .any(|part| part == expected),
            "the agent's native control bytes remain intact"
        );
    }
    let before = run.bytes.len();
    let client = start_server(&box_);
    run.read_for(Duration::from_millis(250));
    assert_eq!(
        run.bytes.len(),
        before,
        "Core wrote into the active native screen:\n{}",
        String::from_utf8_lossy(&run.bytes[before..])
    );
    drop(client);
    if terminate {
        run.signal();
    } else {
        box_.release_workload();
    }
    let status = run.finish();
    if terminate {
        assert_eq!(status.code(), Some(143), "Core forwards termination");
    } else {
        assert_eq!(
            status.code(),
            Some(exit),
            "Core preserves the agent exit code"
        );
        assert!(
            run.text().find("NATIVE_EXIT").unwrap() < run.text().find(REPORT).unwrap(),
            "Core's report follows agent exit:\n{}",
            run.text()
        );
    }
    for line in [REPORT, "[mcp.alpha] broad exec:", "[mcp.alpha] HOME="] {
        assert!(
            run.text().contains(line),
            "the full report is retained: {line}"
        );
    }
}

#[test]
fn terminal_diagnostics_follow_successful_and_failed_agent_exits() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for exit in [0, 7] {
        terminal_run(exit, false);
    }
}

#[test]
fn terminal_diagnostics_survive_core_termination() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    terminal_run(0, true);
}

#[test]
fn piped_core_diagnostics_remain_live() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = fixture(0, false);
    let mut run = Run::start(box_.command_for_run(), false);
    run.wait_file(&box_.workload_path("workload.started"));
    let client = start_server(&box_);
    run.wait_text(REPORT);
    assert!(run.child.try_wait().unwrap().is_none());
    drop(client);
    box_.release_workload();
    assert!(run.finish().success());
}
