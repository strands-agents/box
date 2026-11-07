//! Linux filesystem queries expose only the approved fields and preserve file access restrictions.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::ffi::{CStr, CString};
use std::io::{self, Write as _};
use std::mem::{offset_of, size_of, size_of_val};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "FILESYSTEM_TYPE_RESULT=";
const RESULT_SIZE: usize = size_of::<libc::statfs64>();
const DEADLINE: Duration = Duration::from_secs(20);

struct FilesystemInformation([u8; RESULT_SIZE]);

impl FilesystemInformation {
    fn fields(&self) -> libc::statfs64 {
        // SAFETY: every byte is initialized, and read_unaligned accepts this byte array's alignment.
        unsafe { std::ptr::read_unaligned(self.0.as_ptr().cast()) }
    }

    fn has_only_approved_fields(&self) -> bool {
        let fields = self.fields();
        let mut private = self.0;
        for (start, length) in [
            (
                offset_of!(libc::statfs64, f_type),
                size_of_val(&fields.f_type),
            ),
            (
                offset_of!(libc::statfs64, f_bsize),
                size_of_val(&fields.f_bsize),
            ),
            (
                offset_of!(libc::statfs64, f_frsize),
                size_of_val(&fields.f_frsize),
            ),
            (
                offset_of!(libc::statfs64, f_namelen),
                size_of_val(&fields.f_namelen),
            ),
            (
                offset_of!(libc::statfs64, f_flags),
                size_of_val(&fields.f_flags),
            ),
        ] {
            private[start..start + length].fill(0);
        }
        private.iter().all(|byte| *byte == 0)
    }
}

fn raw_query(path: &CStr, output: *mut libc::c_void) -> io::Result<()> {
    // SAFETY: the terminated path remains live; the syscall validates the supplied output address.
    if unsafe { libc::syscall(libc::SYS_statfs, path.as_ptr(), output) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn filesystem_information(path: &Path) -> io::Result<FilesystemInformation> {
    assert_eq!(RESULT_SIZE, size_of::<libc::statfs>());
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut information = FilesystemInformation([0xa5; RESULT_SIZE]);
    raw_query(&path, information.0.as_mut_ptr().cast())?;
    Ok(information)
}

fn assert_private_information(information: &FilesystemInformation, expected: &serde_json::Value) {
    let fields = information.fields();
    assert_eq!(fields.f_type, expected["filesystem_type"].as_i64().unwrap());
    assert_eq!(fields.f_bsize, expected["block_size"].as_i64().unwrap());
    assert_eq!(fields.f_frsize, expected["fragment_size"].as_i64().unwrap());
    assert_eq!(fields.f_namelen, expected["name_length"].as_i64().unwrap());
    let restrictions = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    assert_eq!(fields.f_flags as u64 & restrictions, restrictions);
    assert!(
        information.has_only_approved_fields(),
        "capacity, inode counts, filesystem identifiers, reserved bytes, and padding must be zero"
    );
}

fn mapped_output(directory: &Path, shared: bool, writable: bool) -> FilesystemInformation {
    let file = directory.join(if shared { "shared.bin" } else { "private.bin" });
    let original = std::fs::read(&file).unwrap();
    let handle = std::fs::File::open(&file).unwrap();
    let protection = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
    let sharing = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    // SAFETY: the file contains the full mapping length, and mmap validates the requested protections.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            original.len(),
            protection,
            sharing,
            handle.as_raw_fd(),
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED, "create the output mapping");
    let path = CString::new(directory.as_os_str().as_encoded_bytes()).unwrap();
    let result = raw_query(&path, address);
    // SAFETY: this mapping remains readable and spans the complete original file.
    let mapped = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), original.len()) };
    let mut information = FilesystemInformation([0; RESULT_SIZE]);
    information.0.copy_from_slice(&mapped[..RESULT_SIZE]);
    if writable {
        result.expect("a writable private mapping accepts the result");
    } else {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EFAULT));
        assert_eq!(
            mapped, original,
            "a refused write must leave the mapping unchanged"
        );
    }
    // SAFETY: release the mapping created in this function.
    assert_eq!(unsafe { libc::munmap(address, original.len()) }, 0);
    assert_eq!(
        std::fs::read(&file).unwrap(),
        original,
        "the backing file stays unchanged"
    );
    information
}

fn descendant_query(path: &Path, expected_type: libc::c_long) {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the child issues syscalls, checks stack storage, and exits without Rust cleanup.
    let child = unsafe { libc::fork() };
    assert!(child > -1, "fork the query child");
    if child == 0 {
        let mut information = FilesystemInformation([0xa5; RESULT_SIZE]);
        // SAFETY: the copied path and writable result storage remain live in this child.
        let result =
            unsafe { libc::syscall(libc::SYS_statfs, path.as_ptr(), information.0.as_mut_ptr()) };
        let passed = result == 0
            && information.fields().f_type == expected_type
            && information.has_only_approved_fields();
        // SAFETY: avoid running the inherited test harness or destructors after fork.
        unsafe { libc::_exit(i32::from(!passed)) };
    }
    let mut status = 0;
    // SAFETY: wait for the child created above and store its status.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the descendant receives sanitized results"
    );
}

fn busy_orphan(directory: &Path) -> ! {
    let path = CString::new(directory.as_os_str().as_encoded_bytes()).unwrap();
    let mut channel = [0; 2];
    // SAFETY: pipe2 initializes two descriptors in this process's storage.
    assert_eq!(
        unsafe { libc::pipe2(channel.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: the child only uses syscalls and stack storage after this fork.
    let child = unsafe { libc::fork() };
    assert!(child > -1);
    if child == 0 {
        // SAFETY: the child owns these inherited descriptors and retains stdout until namespace death.
        unsafe {
            libc::close(channel[0]);
            let mut information = [0_u8; RESULT_SIZE];
            for _ in 0..32 {
                if libc::syscall(libc::SYS_statfs, path.as_ptr(), information.as_mut_ptr()) != 0 {
                    libc::_exit(91);
                }
            }
            if libc::write(channel[1], b"1".as_ptr().cast(), 1) != 1 {
                libc::_exit(92);
            }
            libc::close(channel[1]);
            loop {
                // Keep stdout open even if a canceled notification returns an error.
                libc::syscall(libc::SYS_statfs, path.as_ptr(), information.as_mut_ptr());
            }
        }
    }
    // SAFETY: the parent receives proof that its child completed real filesystem requests.
    unsafe {
        libc::close(channel[1]);
        let mut byte = 0_u8;
        assert_eq!(libc::read(channel[0], (&mut byte as *mut u8).cast(), 1), 1);
        libc::close(channel[0]);
        assert_eq!(byte, b'1');
    }
    println!("{MARKER}{{\"busy_child_completed_queries\":32}}");
    std::io::stdout().flush().unwrap();
    // SAFETY: a distinctive main-workload exit must win over the orphan's lifetime.
    unsafe { libc::_exit(23) }
}

#[test]
fn filesystem_type_probe() {
    let Some(directory) = std::env::var_os("BOX_FILESYSTEM_TYPE_PROBE") else {
        return;
    };
    let directory = Path::new(&directory);
    let granted = directory.join("granted");
    // SAFETY: this helper is a separate workload process, and prctl takes scalar arguments here.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    // SAFETY: PR_GET_DUMPABLE has no pointer arguments.
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    match std::env::var("BOX_FILESYSTEM_TYPE_MODE").unwrap().as_str() {
        "busy-orphan" => busy_orphan(&granted),
        // SAFETY: exercise the real supervisor's idle completion path with a distinctive status.
        "idle-exit" => unsafe { libc::_exit(37) },
        "inspect" => {}
        other => panic!("unexpected probe mode {other}"),
    }
    let expected: serde_json::Value =
        serde_json::from_str(&std::env::var("BOX_FILESYSTEM_TYPE_EXPECTED").unwrap()).unwrap();
    let information = filesystem_information(&granted).expect("query from a nondumpable workload");
    assert_private_information(&information, &expected);
    let path = CString::new(granted.as_os_str().as_encoded_bytes()).unwrap();
    let invalid = raw_query(&path, std::ptr::without_provenance_mut(1));
    assert_eq!(invalid.unwrap_err().raw_os_error(), Some(libc::EFAULT));
    mapped_output(&granted, true, false);
    mapped_output(&granted, false, false);
    let private = mapped_output(&granted, false, true);
    assert_private_information(&private, &expected);

    let ungranted = directory.join("operator-note");
    let hidden_type = filesystem_information(&ungranted)
        .err()
        .expect("the path stays hidden");
    let hidden_read = std::fs::read(&ungranted).expect_err("ungranted content stays unreadable");
    let relative = filesystem_information(Path::new("."))
        .err()
        .expect("relative queries are unsupported");
    let file = granted.join("read-only.txt");
    assert_eq!(std::fs::read(&file).unwrap(), b"original bytes");
    let write = std::fs::write(&file, b"unexpected replacement")
        .expect_err("a filesystem query must not make a read grant writable");
    descendant_query(&granted, information.fields().f_type);
    let thread_path = granted.clone();
    let thread_information =
        std::thread::spawn(move || filesystem_information(&thread_path).unwrap())
            .join()
            .expect("the query thread completes");
    assert_private_information(&thread_information, &expected);
    println!(
        "{MARKER}{}",
        serde_json::json!({
            "filesystem_type": information.fields().f_type,
            "ungranted_statfs_errno": hidden_type.raw_os_error(),
            "ungranted_read_errno": hidden_read.raw_os_error(),
            "read_only_write_errno": write.raw_os_error(),
            "relative_statfs_errno": relative.raw_os_error(),
            "private_result_bytes": true,
            "nondumpable_queries": true,
            "descendant_and_thread_queries": true,
            "read_only_outputs_refused": true,
        })
    );
}

fn bounded_output(command: &mut Command) -> Output {
    let child = command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch the real containment trampoline");
    let process_group = child.id() as libc::pid_t;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(DEADLINE) {
        Ok(output) => output.expect("collect the launcher's status and closed output pipes"),
        Err(error) => {
            // SAFETY: this command created its own process group, containing only the test workload.
            unsafe { libc::kill(-process_group, libc::SIGKILL) };
            let cleanup = receiver.recv_timeout(Duration::from_secs(5));
            panic!("contained probe exceeded {DEADLINE:?}: {error}; cleanup: {cleanup:?}");
        }
    }
}

fn run_probe(root: &Path, mode: &str, expected: &serde_json::Value) -> Output {
    let granted = root.join("granted");
    let executable = std::env::current_exe().unwrap();
    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Read, Scope::File)
        .unwrap()
        .allow(&executable, Operation::Exec, Scope::File)
        .unwrap()
        .allow(&granted, Operation::Read, Scope::Root)
        .unwrap();
    let json = config.to_json().unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config_file.path(), &json).unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg(
            serde_json::json!({
                "BOX_FILESYSTEM_TYPE_PROBE": root,
                "BOX_FILESYSTEM_TYPE_MODE": mode,
                "BOX_FILESYSTEM_TYPE_EXPECTED": expected.to_string(),
            })
            .to_string(),
        )
        .arg("--")
        .arg(&executable)
        .args([
            "--exact",
            "filesystem_type_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(&granted);
    bounded_output(&mut command)
}

#[test]
fn filesystem_type_queries_preserve_file_access_restrictions() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let granted = root.join("granted");
    std::fs::create_dir(&granted).unwrap();
    let file = granted.join("read-only.txt");
    let ungranted = root.join("operator-note");
    std::fs::write(&file, b"original bytes").unwrap();
    std::fs::write(&ungranted, b"operator bytes").unwrap();
    std::fs::write(granted.join("shared.bin"), [0x53; 4096]).unwrap();
    std::fs::write(granted.join("private.bin"), [0x71; 4096]).unwrap();
    let host = filesystem_information(&granted).expect("host filesystem query must work");
    let fields = host.fields();
    assert!(
        fields.f_blocks > 0,
        "the host control contains real capacity information"
    );
    assert!(
        !host.has_only_approved_fields(),
        "the privacy check must reject the native result"
    );
    assert_eq!(
        filesystem_information(&ungranted).unwrap().fields().f_type,
        fields.f_type
    );
    assert_eq!(std::fs::read(&ungranted).unwrap(), b"operator bytes");
    assert!(
        filesystem_information(Path::new("."))
            .unwrap()
            .fields()
            .f_type
            > 0
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .expect("the host file must be writable before containment");
    mapped_output(&granted, true, false);
    mapped_output(&granted, false, false);
    assert!(mapped_output(&granted, false, true).fields().f_blocks > 0);
    let expected = serde_json::json!({
        "filesystem_type": fields.f_type,
        "block_size": fields.f_bsize,
        "fragment_size": fields.f_frsize,
        "name_length": fields.f_namelen,
    });
    let files = [
        file,
        ungranted,
        granted.join("shared.bin"),
        granted.join("private.bin"),
    ];
    let before = files
        .each_ref()
        .map(|path| Sha256::digest(std::fs::read(path).unwrap()));
    let output = run_probe(&root, "inspect", &expected);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "contained probe failed: {stdout}\n{stderr}"
    );
    let report = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, report)| report))
        .expect("the contained filesystem probe completed");
    let report: serde_json::Value = serde_json::from_str(report).unwrap();
    assert_eq!(report["filesystem_type"].as_i64(), Some(fields.f_type));
    assert_eq!(report["ungranted_statfs_errno"], libc::ENOENT);
    assert_eq!(report["ungranted_read_errno"], libc::ENOENT);
    assert_eq!(report["read_only_write_errno"], libc::EROFS);
    assert_eq!(report["relative_statfs_errno"], libc::EOPNOTSUPP);
    let after = files
        .each_ref()
        .map(|path| Sha256::digest(std::fs::read(path).unwrap()));
    assert_eq!(after, before, "all synthetic host files remain unchanged");
}

#[test]
fn filesystem_query_supervision_finishes_with_idle_and_busy_workloads() {
    for (mode, expected_status) in [("idle-exit", 37), ("busy-orphan", 23)] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("granted")).unwrap();
        let output = run_probe(&root, mode, &serde_json::json!({}));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "{mode}: {stdout}\n{stderr}"
        );
        if mode == "busy-orphan" {
            assert!(
                stdout.contains("\"busy_child_completed_queries\":32"),
                "the child issued real requests"
            );
            // Collecting stdout reached EOF although the orphan retained its writer in an endless loop.
        }
    }
}
