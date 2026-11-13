//! Linux optimized copies move bytes between permitted descriptors and reach nothing else.
#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "OPTIMIZED_COPY_RESULT=";
const TEXT: &[u8] = b"synthetic Linux copy probe";
const PLANTED: RawFd = 900;

/// One raw call, so neither glibc nor Rust's standard library can substitute a fallback.
fn copy_file_range(source: RawFd, target: RawFd) -> io::Result<usize> {
    let (mut source_offset, mut target_offset) = (0_i64, 0_i64);
    // SAFETY: both offsets outlive the call, and the kernel validates the descriptors.
    let copied = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            source,
            &raw mut source_offset,
            target,
            &raw mut target_offset,
            TEXT.len(),
            0,
        )
    };
    usize::try_from(copied).map_err(|_| io::Error::last_os_error())
}

fn sendfile(target: RawFd, source: RawFd) -> io::Result<usize> {
    let mut offset = 0_i64;
    // SAFETY: the offset outlives the call, and the kernel validates the descriptors.
    let sent = unsafe {
        libc::syscall(
            libc::SYS_sendfile,
            target,
            source,
            &raw mut offset,
            TEXT.len(),
        )
    };
    usize::try_from(sent).map_err(|_| io::Error::last_os_error())
}

fn errno(result: io::Result<impl Sized>) -> Option<i32> {
    result.err().and_then(|error| error.raw_os_error())
}

fn fresh(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap()
}

fn copied_into_file(copy: fn(RawFd, RawFd) -> io::Result<usize>, swap: bool) -> bool {
    let source = Path::new("copy-source.txt");
    std::fs::write(source, TEXT).unwrap();
    let source = File::open(source).unwrap();
    let target = fresh(Path::new("copy-target.txt"));
    let (first, second) = if swap {
        (target.as_raw_fd(), source.as_raw_fd())
    } else {
        (source.as_raw_fd(), target.as_raw_fd())
    };
    copy(first, second).ok() == Some(TEXT.len())
        && std::fs::read("copy-target.txt").unwrap() == TEXT
}

fn sent_into_stream(target: &mut impl io::Read, target_fd: RawFd) -> bool {
    let source = File::open("copy-source.txt").unwrap();
    if sendfile(target_fd, source.as_raw_fd()).ok() != Some(TEXT.len()) {
        return false;
    }
    let mut received = vec![0; TEXT.len()];
    target.read_exact(&mut received).is_ok() && received == TEXT
}

#[test]
fn optimized_copy_probe() {
    let Some(root) = std::env::var_os("BOX_OPTIMIZED_COPY_PROBE") else {
        return;
    };
    let root = Path::new(&root);
    std::env::set_current_dir(root.join("work")).unwrap();
    let file_range = copied_into_file(copy_file_range, false);
    let file_send = copied_into_file(sendfile, true);

    let mut descriptors = [0; 2];
    // SAFETY: the array has room for the two descriptors pipe2 returns.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe2 returned two new descriptors that these values now own.
    let (reader, writer) = unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    };
    let pipe_send = sent_into_stream(&mut File::from(reader), writer.as_raw_fd());
    let (mut receiver, sender) = UnixStream::pair().unwrap();
    let socket_send = sent_into_stream(&mut receiver, sender.as_raw_fd());

    let source = File::open("copy-source.txt").unwrap();
    let published = root.join("published").join("published.txt");
    let published_write = OpenOptions::new().write(true).open(&published);
    let published = File::open(&published).unwrap();
    let denied = File::open(root.join("operator-note"));
    println!(
        "{MARKER}{}",
        serde_json::json!({
            "copy_file_range_file": file_range,
            "sendfile_file": file_send,
            "sendfile_pipe": pipe_send,
            "sendfile_socket": socket_send,
            "read_only_open_errno": errno(published_write),
            "read_only_copy_file_range_errno":
                errno(copy_file_range(source.as_raw_fd(), published.as_raw_fd())),
            "read_only_sendfile_errno": errno(sendfile(published.as_raw_fd(), source.as_raw_fd())),
            "denied_open_errno": errno(denied),
            "inherited_copy_file_range_errno":
                errno(copy_file_range(PLANTED, fresh(Path::new("leak.txt")).as_raw_fd())),
            "inherited_sendfile_errno":
                errno(sendfile(fresh(Path::new("leak.txt")).as_raw_fd(), PLANTED)),
        })
    );
    io::stdout().flush().unwrap();
}

#[test]
fn optimized_copies_reach_only_permitted_descriptors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let work = root.join("work");
    let published = root.join("published");
    std::fs::create_dir(&work).unwrap();
    std::fs::create_dir(&published).unwrap();
    std::fs::write(published.join("published.txt"), b"published bytes").unwrap();
    std::fs::write(root.join("operator-note"), b"operator bytes").unwrap();

    let operator_note = File::open(root.join("operator-note")).unwrap();
    // SAFETY: duplicate an open descriptor this test owns to a fixed number without close-on-exec.
    let planted = unsafe { libc::dup2(operator_note.as_raw_fd(), PLANTED) };
    assert_eq!(planted, PLANTED);
    // SAFETY: dup2 returned a new descriptor that this value now owns.
    let _planted = unsafe { OwnedFd::from_raw_fd(planted) };

    let executable = std::env::current_exe().unwrap();
    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Read, Scope::File)
        .unwrap()
        .allow(&executable, Operation::Exec, Scope::File)
        .unwrap()
        .allow(&work, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&work, Operation::Write, Scope::Root)
        .unwrap()
        .allow(&published, Operation::Read, Scope::Root)
        .unwrap();
    let json = config.to_json().unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config_file.path(), &json).unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg(serde_json::json!({ "BOX_OPTIMIZED_COPY_PROBE": root }).to_string())
        .arg("--")
        .arg(&executable)
        .args([
            "--exact",
            "optimized_copy_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(&work)
        .output()
        .expect("launch the real containment trampoline");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "contained probe failed: {stdout}\n{stderr}"
    );
    let report = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, report)| report))
        .expect("the contained copy probe completed");
    let report: serde_json::Value = serde_json::from_str(report).unwrap();
    assert_eq!(
        report,
        serde_json::json!({
            "copy_file_range_file": true,
            "sendfile_file": true,
            "sendfile_pipe": true,
            "sendfile_socket": true,
            "read_only_open_errno": libc::EROFS,
            "read_only_copy_file_range_errno": libc::EBADF,
            "read_only_sendfile_errno": libc::EBADF,
            "denied_open_errno": libc::ENOENT,
            "inherited_copy_file_range_errno": libc::EBADF,
            "inherited_sendfile_errno": libc::EBADF,
        }),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(published.join("published.txt")).unwrap(),
        b"published bytes"
    );
    assert_eq!(
        std::fs::read(root.join("operator-note")).unwrap(),
        b"operator bytes"
    );
}
