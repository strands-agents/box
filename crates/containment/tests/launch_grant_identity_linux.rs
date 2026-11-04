//! Filesystem grant identity across the production Linux launch handoff.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    approved: PathBuf,
    replacement: PathBuf,
    original: PathBuf,
    note: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("launch-grant-identity-")
            .tempdir_in("/var/tmp")
            .expect("create fixture outside the private tmp mount");
        let root = directory.path().canonicalize().expect("canonical fixture");
        let approved = root.join("approved");
        let replacement = root.join("replacement");
        let original = root.join("original");
        for path in [&approved, &replacement] {
            std::fs::create_dir(path).expect("create executable directory");
        }
        for (name, directory, marker) in [
            ("original", &approved, "ORIGINAL_TARGET_RAN"),
            ("replacement", &replacement, "REPLACEMENT_TARGET_RAN"),
        ] {
            let source = root.join(format!("{name}.c"));
            std::fs::write(
                &source,
                format!(
                    r#"#include <errno.h>
#include <stdio.h>
int main(int argc, char **argv) {{
    if (argc != 2) return 70;
    FILE *file = fopen(argv[1], "r");
    if (file) {{ fclose(file); puts("UNGRANTED_READ_SUCCEEDED"); return 71; }}
    if (errno != ENOENT && errno != EACCES) return 72;
    puts("{marker}");
    puts("UNGRANTED_READ_REFUSED");
    return 0;
}}
"#,
                ),
            )
            .expect("write harmless native fixture source");
            let output = Command::new("/usr/bin/cc")
                .arg(&source)
                .arg("-o")
                .arg(directory.join("helper"))
                .output()
                .expect("the native fixture requires /usr/bin/cc");
            assert!(
                output.status.success(),
                "compile native fixture: {output:?}"
            );
        }
        let note = root.join("ungranted-note");
        std::fs::write(&note, "synthetic ungranted bytes\n").expect("write ungranted fixture");
        Self {
            _directory: directory,
            root,
            approved,
            replacement,
            original,
            note,
        }
    }

    fn approve(&self) -> ContainmentConfig {
        let prepared = ContainmentConfig::prepare_filesystem_path(&self.approved)
            .expect("prepare this launch directory");
        ContainmentConfig::new()
            .allow_prepared(prepared, Operation::Exec, Scope::Root)
            .expect("approve the prepared directory")
            // This unchanged native executable supplies the loader and libc used by both helpers.
            .allow("/bin/true", Operation::Exec, Scope::File)
            .expect("approve the unchanged runtime dependency source")
    }

    fn replace_directory(&self) {
        std::fs::rename(&self.approved, &self.original).expect("move the approved directory aside");
        std::fs::rename(&self.replacement, &self.approved)
            .expect("put the replacement at the approved spelling");
    }
}

struct Launch {
    child: Child,
    gate: UnixStream,
    setup_status: UnixStream,
    config_file: tempfile::NamedTempFile,
    config_bytes: Vec<u8>,
    config_digest: String,
    _config: ContainmentConfig,
}

#[derive(Debug)]
struct Outcome {
    exit: ExitStatus,
    setup_status: Vec<u8>,
    stdout: String,
    stderr: String,
}

impl Launch {
    fn start(fixture: &Fixture, config: ContainmentConfig) -> Self {
        let config_bytes = config
            .to_json()
            .expect("serialize approved config")
            .into_bytes();
        let config_digest = sha256_hex(&config_bytes);
        let config_file =
            tempfile::NamedTempFile::new_in(&fixture.root).expect("create the launch config");
        std::fs::write(config_file.path(), &config_bytes).expect("write the launch config once");
        let (gate, gate_child) = UnixStream::pair().expect("create production launch gate");
        let (setup_status, status_child) = UnixStream::pair().expect("create setup status channel");
        for stream in [&gate, &setup_status] {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("bound channel reads");
        }
        gate.set_write_timeout(Some(Duration::from_secs(10)))
            .expect("bound launch acknowledgement");
        let gate_fd = gate_child.as_raw_fd();
        let status_fd = status_child.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
        command
            .env_clear()
            .current_dir(&fixture.root)
            .arg("--config")
            .arg(config_file.path())
            .args(["--config-sha256", &config_digest, "--target-env-json", "{}"])
            .arg("--launch-gate-fd")
            .arg(gate_fd.to_string())
            .arg("--setup-status-fd")
            .arg(status_fd.to_string())
            .arg("--")
            .arg(fixture.approved.join("helper"))
            .arg(&fixture.note)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the child only changes descriptor flags before the production trampoline exec.
        unsafe {
            command.pre_exec(move || {
                inherit(gate_fd)?;
                inherit(status_fd)
            });
        }
        let child = command.spawn().expect("start the production trampoline");
        drop(gate_child);
        drop(status_child);
        Self {
            child,
            gate,
            setup_status,
            config_file,
            config_bytes,
            config_digest,
            _config: config,
        }
    }

    fn ready(&mut self) -> [u8; 1] {
        let mut ready = [0];
        self.gate
            .read_exact(&mut ready)
            .expect("receive launch gate readiness");
        ready
    }

    fn finish(&mut self) -> Outcome {
        self.gate.write_all(b"G").expect("acknowledge the launch");
        let mut setup_status = Vec::new();
        self.setup_status
            .read_to_end(&mut setup_status)
            .expect("read setup status through EOF");
        let deadline = Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Some(exit) = self.child.try_wait().expect("wait for trampoline") {
                break exit;
            }
            assert!(Instant::now() < deadline, "the native fixture did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = String::new();
        let mut stderr = String::new();
        self.child
            .stdout
            .take()
            .expect("captured stdout")
            .read_to_string(&mut stdout)
            .expect("read native fixture output");
        self.child
            .stderr
            .take()
            .expect("captured stderr")
            .read_to_string(&mut stderr)
            .expect("read launch diagnostics");
        Outcome {
            exit,
            setup_status,
            stdout,
            stderr,
        }
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn inherit(descriptor: RawFd) -> std::io::Result<()> {
    // SAFETY: both calls inspect or update this inherited descriptor only.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags == -1
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = std::fs::metadata(path).expect("read fixture identity");
    (metadata.dev(), metadata.ino())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn an_unchanged_approved_directory_runs_contained() {
    let fixture = Fixture::new();
    let approved = identity(&fixture.approved);
    let mut launch = Launch::start(&fixture, fixture.approve());
    assert_eq!(launch.ready(), *b"R");
    assert_eq!(identity(&fixture.approved), approved);
    let bytes = std::fs::read(launch.config_file.path()).expect("read unchanged config");
    assert_eq!(bytes, launch.config_bytes);
    assert_eq!(sha256_hex(&bytes), launch.config_digest);
    assert_eq!(
        std::fs::read_to_string(&fixture.note).unwrap(),
        "synthetic ungranted bytes\n"
    );

    let outcome = launch.finish();
    eprintln!("unchanged approved directory: {outcome:?}");
    assert_eq!(outcome.exit.code(), Some(0), "{outcome:?}");
    assert!(
        matches!(outcome.setup_status.as_slice(), [6, 128] | [128, 6]),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.stdout, "ORIGINAL_TARGET_RAN\nUNGRANTED_READ_REFUSED\n",
        "{outcome:?}"
    );
}

#[test]
fn a_directory_replaced_after_approval_is_refused_before_execution() {
    let fixture = Fixture::new();
    let approved = identity(&fixture.approved);
    let replacement = identity(&fixture.replacement);
    assert_ne!(approved, replacement);
    let mut launch = Launch::start(&fixture, fixture.approve());
    assert_eq!(launch.ready(), *b"R");
    fixture.replace_directory();
    assert_eq!(identity(&fixture.original), approved);
    assert_eq!(identity(&fixture.approved), replacement);
    let bytes = std::fs::read(launch.config_file.path()).expect("read unchanged config");
    assert_eq!(bytes, launch.config_bytes);
    assert_eq!(sha256_hex(&bytes), launch.config_digest);

    let outcome = launch.finish();
    eprintln!("directory replaced after approval: {outcome:?}");
    assert_eq!(outcome.exit.code(), Some(2), "{outcome:?}");
    assert_eq!(outcome.setup_status, [2], "{outcome:?}");
    assert!(
        outcome
            .stderr
            .contains("filesystem grant object changed while loading config"),
        "{outcome:?}"
    );
    assert!(
        outcome.stderr.contains(fixture.approved.to_str().unwrap()),
        "{outcome:?}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "replacement code ran: {outcome:?}"
    );
}

#[test]
fn a_replacement_approved_for_a_new_launch_runs_contained() {
    let fixture = Fixture::new();
    let approved = identity(&fixture.approved);
    let replacement = identity(&fixture.replacement);
    assert_ne!(approved, replacement);
    fixture.replace_directory();
    assert_eq!(identity(&fixture.original), approved);
    assert_eq!(identity(&fixture.approved), replacement);
    let mut launch = Launch::start(&fixture, fixture.approve());
    assert_eq!(launch.ready(), *b"R");
    let bytes = std::fs::read(launch.config_file.path()).expect("read unchanged config");
    assert_eq!(bytes, launch.config_bytes);
    assert_eq!(sha256_hex(&bytes), launch.config_digest);
    assert_eq!(
        std::fs::read_to_string(&fixture.note).unwrap(),
        "synthetic ungranted bytes\n"
    );

    let outcome = launch.finish();
    eprintln!("replacement approved for a new launch: {outcome:?}");
    assert_eq!(outcome.exit.code(), Some(0), "{outcome:?}");
    assert!(
        matches!(outcome.setup_status.as_slice(), [6, 128] | [128, 6]),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.stdout, "REPLACEMENT_TARGET_RAN\nUNGRANTED_READ_REFUSED\n",
        "{outcome:?}"
    );
}
