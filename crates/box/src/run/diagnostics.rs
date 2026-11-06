//! Core's stderr while a workload owns the terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::thread::{self, JoinHandle};

const CAPACITY: usize = 32 * 1024;

struct Report {
    bytes: Vec<u8>,
    truncated: bool,
}

pub(crate) struct Diagnostics {
    original: File,
    flags: libc::c_int,
    writer: UnixStream,
    reader: Option<JoinHandle<io::Result<Report>>>,
}

impl Diagnostics {
    pub(crate) fn capture() -> io::Result<Self> {
        // SAFETY: fcntl duplicates stderr without transferring its ownership.
        let saved = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if saved == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: saved is a new, owned descriptor.
        let original = unsafe { File::from_raw_fd(saved) };
        // SAFETY: stderr remains open.
        let flags = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFD) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let (reader, writer) = UnixStream::pair()?;
        let reader = thread::Builder::new()
            .name("box-diagnostics".into())
            .spawn(move || drain(reader))?;
        let mut diagnostics = Self {
            original,
            flags,
            writer,
            reader: Some(reader),
        };
        if let Err(error) = replace_stderr(diagnostics.writer.as_raw_fd(), flags) {
            let _ = diagnostics.finish();
            return Err(error);
        }
        Ok(diagnostics)
    }

    pub(crate) fn stderr(&self) -> io::Result<File> {
        self.original.try_clone()
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.reader.is_none() {
            return Ok(());
        }
        replace_stderr(self.original.as_raw_fd(), self.flags)?;
        // A descendant that retained fd 2 must not keep the reader alive after shutdown.
        self.writer.shutdown(Shutdown::Write)?;
        let reader = self.reader.take().expect("reader is present");
        let report = reader
            .join()
            .map_err(|_| io::Error::other("diagnostic reader panicked"))??;
        self.original.write_all(&report.bytes)?;
        if report.truncated {
            self.original
                .write_all(b"\nstrands-box: further runtime diagnostics were discarded\n")?;
        }
        Ok(())
    }
}

impl Drop for Diagnostics {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn replace_stderr(fd: libc::c_int, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: fd is open, and fd 2 is reserved for this run's stderr.
    if unsafe { libc::dup2(fd, libc::STDERR_FILENO) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: dup2 installed fd 2; restore its original descriptor flags.
    if unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_SETFD, flags) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(mut reader: impl Read) -> io::Result<Report> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0; 8192];
    loop {
        let length = match reader.read(&mut buffer) {
            Ok(0) => return Ok(Report { bytes, truncated }),
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let keep = length.min(CAPACITY - bytes.len());
        bytes.extend_from_slice(&buffer[..keep]);
        truncated |= keep < length;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_is_drained_with_bounded_retention() {
        let mut input = io::Cursor::new(vec![b'x'; CAPACITY * 4]);
        let report = drain(&mut input).unwrap();
        assert_eq!(report.bytes, vec![b'x'; CAPACITY]);
        assert!(report.truncated);
        assert_eq!(input.position(), (CAPACITY * 4) as u64);
        let small = drain(&b"small report"[..]).unwrap();
        assert_eq!(small.bytes, b"small report");
        assert!(!small.truncated);
    }

    #[test]
    fn stderr_is_restored_and_inherited_writers_do_not_block_replay() {
        const CHILD: &str = "BOX_DIAGNOSTICS_TEST_CHILD";
        if let Ok(scenario) = std::env::var(CHILD) {
            // SAFETY: stderr is owned by this isolated test process.
            assert_eq!(
                unsafe { libc::fcntl(2, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
            let mut diagnostics = Diagnostics::capture().unwrap();
            let mut native = diagnostics.stderr().unwrap();
            native.write_all(b"NATIVE\n").unwrap();
            let bytes = if scenario == "overflow" {
                vec![b'x'; CAPACITY * 4]
            } else {
                b"CORE\n".to_vec()
            };
            io::stderr().write_all(&bytes).unwrap();
            let retained_writer = diagnostics.writer.try_clone().unwrap();
            if scenario == "drop" {
                drop(diagnostics);
            } else {
                diagnostics.finish().unwrap();
            }
            // SAFETY: this queries the restored descriptor in this isolated process.
            assert_eq!(unsafe { libc::fcntl(2, libc::F_GETFD) }, libc::FD_CLOEXEC);
            io::stderr().write_all(b"RESTORED\n").unwrap();
            drop(retained_writer);
            return;
        }
        for scenario in ["restore", "overflow", "drop"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "run::diagnostics::tests::stderr_is_restored_and_inherited_writers_do_not_block_replay", "--nocapture"])
            .env(CHILD, scenario)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let output = thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).unwrap();
                bytes
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("diagnostic replay did not finish");
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(child.wait().unwrap().success(), "{scenario}");
            let bytes = output.join().unwrap();
            let expected = if scenario == "overflow" {
                let mut expected = b"NATIVE\n".to_vec();
                expected.extend(vec![b'x'; CAPACITY]);
                expected.extend(
                    b"\nstrands-box: further runtime diagnostics were discarded\nRESTORED\n",
                );
                expected
            } else {
                b"NATIVE\nCORE\nRESTORED\n".to_vec()
            };
            assert_eq!(bytes, expected, "{scenario}");
        }
    }
}
