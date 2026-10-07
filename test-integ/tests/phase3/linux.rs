use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use strands_det_harness::{BoxFixture, Route, RunResult, find_box};

unsafe extern "C" {
    fn posix_openpt(flags: i32) -> i32;
    fn grantpt(fd: i32) -> i32;
    fn unlockpt(fd: i32) -> i32;
    fn ptsname_r(fd: i32, name: *mut u8, length: usize) -> i32;
    fn fcntl(fd: i32, op: i32, ...) -> i32;
    fn setsid() -> i32;
    fn ioctl(fd: i32, request: usize, ...) -> i32;
    fn shmget(key: i32, size: usize, flags: i32) -> i32;
    fn shmat(id: i32, address: *const u8, flags: i32) -> *mut u8;
    fn shmdt(address: *const u8) -> i32;
    fn shmctl(id: i32, command: i32, buffer: *mut u8) -> i32;
}

pub struct SharedMemory {
    pub id: i32,
    address: *mut u8,
}

impl SharedMemory {
    pub fn new() -> Self {
        let id = unsafe { shmget(0, 4096, 0o600) };
        assert!(
            id >= 0,
            "DET_ERROR: host shmget: {}",
            std::io::Error::last_os_error()
        );
        let address = unsafe { shmat(id, std::ptr::null(), 0) };
        if address as isize == -1 {
            unsafe {
                shmctl(id, 0, std::ptr::null_mut());
            }
            panic!("DET_ERROR: host shmat: {}", std::io::Error::last_os_error());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(b"PHASE3_SHM_OWNED".as_ptr(), address, 16);
        }
        Self { id, address }
    }

    pub fn unchanged(&self) {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(self.address, 16) },
            b"PHASE3_SHM_OWNED"
        );
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            shmdt(self.address);
            shmctl(self.id, 0, std::ptr::null_mut());
        }
    }
}

pub struct Terminal {
    controller: File,
    secondary: File,
}

impl Terminal {
    pub fn new() -> Self {
        let fd = unsafe { posix_openpt(2 | 0x100 | 0x80000) };
        assert!(
            fd >= 0,
            "DET_ERROR: open test PTY: {}",
            std::io::Error::last_os_error()
        );
        let controller = unsafe { File::from_raw_fd(fd) };
        assert_eq!(unsafe { grantpt(fd) }, 0, "DET_ERROR: grant PTY");
        assert_eq!(unsafe { unlockpt(fd) }, 0, "DET_ERROR: unlock PTY");
        let mut path = [0u8; 256];
        assert_eq!(
            unsafe { ptsname_r(fd, path.as_mut_ptr(), path.len()) },
            0,
            "DET_ERROR: PTY name"
        );
        let len = path
            .iter()
            .position(|b| *b == 0)
            .expect("DET_ERROR: PTY path terminator");
        let secondary = File::options()
            .read(true)
            .write(true)
            .custom_flags(0x100)
            .open(std::str::from_utf8(&path[..len]).unwrap())
            .expect("DET_ERROR: open PTY secondary");
        let flags = unsafe { fcntl(secondary.as_raw_fd(), 3) };
        assert!(flags >= 0, "DET_ERROR: PTY flags");
        assert_eq!(
            unsafe { fcntl(secondary.as_raw_fd(), 4, flags | 0x800) },
            0,
            "DET_ERROR: nonblocking PTY"
        );
        Self {
            controller,
            secondary,
        }
    }

    pub fn input(&mut self, duration: Duration) -> Vec<u8> {
        let end = Instant::now() + duration;
        let mut bytes = Vec::new();
        loop {
            let mut buf = [0; 128];
            match self.secondary.read(&mut buf) {
                Ok(0) => panic!("DET_ERROR: PTY observer EOF"),
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => panic!("DET_ERROR: PTY observer read: {e}"),
            }
            if Instant::now() >= end {
                return bytes;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn control(&mut self, message: &[u8]) {
        self.controller
            .write_all(message)
            .expect("DET_ERROR: PTY controller input");
        assert_eq!(
            self.input(Duration::from_millis(100)),
            message,
            "DET_ERROR: PTY input observer"
        );
    }

    pub fn launch(&self, command: &mut Command) -> std::process::Output {
        command
            .stdin(Stdio::from(
                self.secondary.try_clone().expect("DET_ERROR: clone PTY"),
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if setsid() < 0 || ioctl(0, 0x540e, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .expect("DET_ERROR: launch in test PTY session");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let drain = |mut pipe: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                pipe.read_to_end(&mut bytes)
                    .expect("DET_ERROR: drain PTY run");
                bytes
            })
        };
        let out = drain(Box::new(stdout));
        let err = drain(Box::new(stderr));
        let end = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("DET_ERROR: poll PTY run") {
                break status;
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                panic!("DET_ERROR: PTY run exceeded 30 seconds");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        std::process::Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    }

    pub fn run_box(&self, b: &BoxFixture, cmd: &str) -> RunResult {
        let config = b.workspace().join(".strands-box/box.toml");
        let original = std::fs::read_to_string(&config).expect("DET_ERROR: read fixture config");
        let text = b.with_exec_tree()(original.clone());
        assert!(
            text.contains("command = [\"bash\"]"),
            "DET_ERROR: native bash control must run first"
        );
        let restore = RestoreConfig {
            path: config.clone(),
            original,
        };
        std::fs::write(&config, text).expect("DET_ERROR: PTY run config");
        let before = b.decisions().len();
        let output = self.launch(
            Command::new(find_box().expect("DET_ERROR: find box"))
                .arg("run")
                .arg("--config")
                .arg(&config)
                .arg("--")
                .arg("-c")
                .arg(format!("printf 'DET_ENTERED\\n'; {cmd}"))
                .current_dir(b.workspace()),
        );
        drop(restore);
        RunResult {
            out: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            rc: output.status.code().unwrap_or(-1),
            route: Route::Native,
            decisions: b.decisions().into_iter().skip(before).collect(),
        }
    }
}

struct RestoreConfig {
    path: std::path::PathBuf,
    original: String,
}

impl Drop for RestoreConfig {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, &self.original);
    }
}

pub fn terminal_observation(out: &str, bytes: &[u8]) -> &'static str {
    assert!(
        out.lines().any(|l| l == "TTY_STDIN_OK"),
        "DET_ERROR: terminal probe did not enter"
    );
    let reached = out.lines().filter(|l| *l == "TIOCSTI_REACHED").count();
    let refused = out
        .lines()
        .filter(|l| l.starts_with("TIOCSTI_REFUSED "))
        .count();
    assert_eq!(
        reached + refused,
        1,
        "missing or ambiguous TIOCSTI outcome: {out}"
    );
    if reached == 1 {
        assert_eq!(
            bytes, b"\n",
            "TIOCSTI success lacked observed terminal input: {out}"
        );
        "input-injected"
    } else {
        super::require_refusal(out, "TIOCSTI", &[1, 5, 13]);
        assert!(
            bytes.is_empty(),
            "TIOCSTI refusal nevertheless changed terminal input: {bytes:?}"
        );
        "input-refused"
    }
}
