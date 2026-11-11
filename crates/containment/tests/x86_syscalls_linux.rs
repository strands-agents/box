//! Legacy x86 syscall effects and filesystem grants through the production trampoline.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use containment::{ContainmentConfig, Operation, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MARKER: &str = "X86_SYSCALL_RESULTS=";
const CONTENT: &[u8] = b"owned syscall fixture\n";
const VFORK_CHILD_ALLOWED: i32 = 37;
const VFORK_CHILD_DENIED: i32 = 38;
const VFORK_CHILD_UNEXPECTED: i32 = 39;
const SCOPES: [&str; 3] = ["writable", "readonly", "ungranted"];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Metadata {
    inode: u64,
    size: i64,
    mode: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct VforkChild {
    pid: i32,
    waited_pid: i32,
    wait_error: i32,
    status: i32,
    second_wait: i32,
    second_wait_error: i32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Report {
    calls: BTreeMap<String, i32>,
    metadata: BTreeMap<String, Metadata>,
    pipe_bytes: Vec<u8>,
    escaped_read: Option<Vec<u8>>,
    opened_bytes: BTreeMap<String, Vec<u8>>,
    vfork_child: Option<VforkChild>,
}

fn name(path: &Path) -> CString {
    CString::new(path.as_os_str().as_encoded_bytes()).unwrap()
}

fn error(result: libc::c_long) -> i32 {
    if result == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    } else {
        assert_eq!(result, 0);
        0
    }
}

fn two_paths(number: libc::c_long, first: &CStr, second: &CStr) -> i32 {
    // SAFETY: both names remain live; callers select a syscall taking two path pointers.
    error(unsafe { libc::syscall(number, first.as_ptr(), second.as_ptr()) })
}

fn stat(report: &mut Report, label: &str, path: &Path, number: libc::c_long) {
    let path = name(path);
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat and lstat use the same x86 result structure; path remains terminated.
    let result = unsafe { libc::syscall(number, path.as_ptr(), metadata.as_mut_ptr()) };
    report.calls.insert(label.into(), error(result));
    if result == 0 {
        // SAFETY: a successful stat initialized the structure.
        let metadata = unsafe { metadata.assume_init() };
        report.metadata.insert(
            label.into(),
            Metadata {
                inode: metadata.st_ino,
                size: metadata.st_size,
                mode: metadata.st_mode,
            },
        );
    }
}

fn open(report: &mut Report, label: &str, path: &Path, create: bool) {
    let path = name(path);
    let flags = libc::O_CLOEXEC
        | if create {
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_RDONLY
        };
    // SAFETY: path remains terminated; flags and the mode use open's x86 argument positions.
    let descriptor = unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), flags, 0o600_u32) };
    report.calls.insert(
        label.into(),
        error(if descriptor >= 0 { 0 } else { descriptor }),
    );
    if descriptor >= 0 {
        // SAFETY: successful open returned an owned descriptor.
        let mut file = unsafe { File::from_raw_fd(descriptor as i32) };
        if create {
            file.write_all(CONTENT).unwrap();
        } else {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            report.opened_bytes.insert(label.into(), bytes);
        }
        let metadata = file.metadata().unwrap();
        report.metadata.insert(
            label.into(),
            Metadata {
                inode: metadata.ino(),
                size: metadata.len() as i64,
                mode: metadata.mode(),
            },
        );
    }
}

fn vfork(report: &mut Report) {
    let result: libc::c_long;
    // SAFETY: vfork shares the caller's stack. The child stays in this single assembly block:
    // it queries its UID, calls setuid with that same UID, then encodes the result in raw exit.
    // It writes only registers and never returns to Rust or a C wrapper. The outside fixture
    // verifies equal real, effective, saved and filesystem UIDs before making this probe.
    // If exit is unexpectedly refused, the child spins without touching the shared stack until
    // the existing process-group deadline kills the probe. Only the parent or an error reaches
    // Rust. syscall clobbers rcx/r11; the child also changes rdi and the condition flags.
    unsafe {
        std::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 9f",
            "mov eax, {getuid}",
            "syscall",
            "test rax, rax",
            "js 6f",
            "mov edi, eax",
            "mov eax, {setuid}",
            "syscall",
            "test rax, rax",
            "jz 4f",
            "cmp rax, {denied_errno}",
            "je 5f",
            "6:",
            "mov edi, {unexpected}",
            "jmp 7f",
            "4:",
            "mov edi, {allowed}",
            "jmp 7f",
            "5:",
            "mov edi, {denied}",
            "7:",
            "mov eax, {exit}",
            "syscall",
            "8:",
            "jmp 8b",
            "9:",
            inlateout("rax") libc::SYS_vfork => result,
            getuid = const libc::SYS_getuid,
            setuid = const libc::SYS_setuid,
            exit = const libc::SYS_exit,
            denied_errno = const -libc::EPERM,
            allowed = const VFORK_CHILD_ALLOWED,
            denied = const VFORK_CHILD_DENIED,
            unexpected = const VFORK_CHILD_UNEXPECTED,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rdi") _,
            options(nostack),
        );
    }
    // Unlike libc::syscall, raw assembly returns a negative errno without setting thread errno.
    report.calls.insert(
        "vfork".into(),
        if result < 0 {
            i32::try_from(-result).unwrap()
        } else {
            0
        },
    );
    if result < 0 {
        return;
    }
    let pid = libc::pid_t::try_from(result).unwrap();
    assert!(pid > 0, "the child must never return to Rust");
    let mut status = 0;
    let (waited_pid, wait_error) = loop {
        // SAFETY: pid is this probe's child, and status is writable for waitpid's result.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        let error = if waited == -1 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        };
        if error != libc::EINTR {
            break (waited, error);
        }
    };
    let mut second_status = 0;
    // SAFETY: a nonblocking second wait checks that the same owned child has already been reaped.
    let second_wait = unsafe { libc::waitpid(pid, &mut second_status, libc::WNOHANG) };
    let second_wait_error = if second_wait == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    } else {
        0
    };
    report.vfork_child = Some(VforkChild {
        pid,
        waited_pid,
        wait_error,
        status,
        second_wait,
        second_wait_error,
    });
}

#[test]
fn legacy_syscall_probe() {
    let Some(root) = std::env::var_os("BOX_X86_SYSCALL_PROBE") else {
        return;
    };
    let root = Path::new(&root);
    let mut report = Report::default();
    for scope in SCOPES {
        let directory = root.join(scope);
        stat(
            &mut report,
            &format!("{scope}/stat"),
            &directory.join("stat-file"),
            libc::SYS_stat,
        );
        stat(
            &mut report,
            &format!("{scope}/missing"),
            &directory.join("missing-file"),
            libc::SYS_stat,
        );
        stat(
            &mut report,
            &format!("{scope}/lstat"),
            &directory.join("stat-file"),
            libc::SYS_lstat,
        );
        stat(
            &mut report,
            &format!("{scope}/lstat-link"),
            &directory.join("existing-link"),
            libc::SYS_lstat,
        );
        open(
            &mut report,
            &format!("{scope}/open-read"),
            &directory.join("stat-file"),
            false,
        );
        open(
            &mut report,
            &format!("{scope}/open-create"),
            &directory.join("created-file"),
            true,
        );
        report.calls.insert(
            format!("{scope}/rename"),
            two_paths(
                libc::SYS_rename,
                &name(&directory.join("rename-source")),
                &name(&directory.join("renamed")),
            ),
        );
        let removed = name(&directory.join("unlink-source"));
        // SAFETY: removed is a live, terminated path to an owned fixture.
        let result = unsafe { libc::syscall(libc::SYS_unlink, removed.as_ptr()) };
        report
            .calls
            .insert(format!("{scope}/unlink"), error(result));
        report.calls.insert(
            format!("{scope}/symlink"),
            two_paths(
                libc::SYS_symlink,
                c"stat-file",
                &name(&directory.join("symbolic-link")),
            ),
        );
        for (operation, number, filename) in [
            ("mkdir", libc::SYS_mkdir, "created-directory"),
            ("chmod", libc::SYS_chmod, "chmod-file"),
        ] {
            let target = name(&directory.join(filename));
            // SAFETY: target is terminated; mode is argument 1. The unused argument 2 is zero.
            let result = unsafe { libc::syscall(number, target.as_ptr(), 0o755_u32, 0_u64) };
            report
                .calls
                .insert(format!("{scope}/{operation}"), error(result));
        }
    }
    let mut descriptors = [-1; 2];
    // SAFETY: the array has space for both descriptors returned by pipe.
    let result = unsafe { libc::syscall(libc::SYS_pipe, descriptors.as_mut_ptr()) };
    report.calls.insert("pipe".into(), error(result));
    if result == 0 {
        // SAFETY: pipe returned two distinct owned descriptors.
        let (mut reader, mut writer) = unsafe {
            (
                File::from_raw_fd(descriptors[0]),
                File::from_raw_fd(descriptors[1]),
            )
        };
        writer.write_all(b"pipe round trip").unwrap();
        drop(writer);
        reader.read_to_end(&mut report.pipe_bytes).unwrap();
    }
    let escaped_link = root.join("writable/escape-link");
    report.calls.insert(
        "escape/symlink".into(),
        two_paths(
            libc::SYS_symlink,
            &name(&root.join("ungranted/stat-file")),
            &name(&escaped_link),
        ),
    );
    stat(&mut report, "escape/stat", &escaped_link, libc::SYS_stat);
    stat(&mut report, "escape/lstat", &escaped_link, libc::SYS_lstat);
    let read_error = match fs::read(&escaped_link) {
        Ok(bytes) => {
            report.escaped_read = Some(bytes);
            0
        }
        Err(error) => error.raw_os_error().unwrap(),
    };
    report.calls.insert("escape/read".into(), read_error);
    vfork(&mut report);
    println!("{MARKER}{}", serde_json::to_string(&report).unwrap());
}

fn bounded_output(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            // SAFETY: the child started a new process group; terminate only that owned group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            let output = child.wait_with_output().unwrap();
            panic!("syscall probe timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run_probe(root: &Path, contained: bool) -> Report {
    let executable = std::env::current_exe().unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    let mut command;
    if contained {
        let config = ContainmentConfig::new()
            .allow(&executable, Operation::Read, Scope::File)
            .unwrap()
            .allow(&executable, Operation::Exec, Scope::File)
            .unwrap()
            .allow(root.join("writable"), Operation::Read, Scope::Root)
            .unwrap()
            .allow(root.join("writable"), Operation::Write, Scope::Root)
            .unwrap()
            .allow(root.join("readonly"), Operation::Read, Scope::Root)
            .unwrap();
        let json = config.to_json().unwrap();
        fs::write(config_file.path(), &json).unwrap();
        command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
        command
            .arg("--config")
            .arg(config_file.path())
            .arg("--config-sha256")
            .arg(
                Sha256::digest(json.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .arg("--target-env-json")
            .arg(serde_json::json!({"BOX_X86_SYSCALL_PROBE": root}).to_string())
            .arg("--")
            .arg(&executable);
    } else {
        command = Command::new(&executable);
        command.env("BOX_X86_SYSCALL_PROBE", root);
    }
    command.current_dir(root.join("writable")).args([
        "--exact",
        "legacy_syscall_probe",
        "--nocapture",
        "--test-threads=1",
    ]);
    let output = bounded_output(&mut command);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probe failed: {stdout}\n{stderr}");
    let json = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, json)| json))
        .expect("the probe must execute every operation and publish its results");
    println!("contained={contained} {json}");
    serde_json::from_str(json).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct StoredObject {
    inode: u64,
    mode: u32,
    bytes: Option<Vec<u8>>,
    link_target: Option<PathBuf>,
}

fn stored_files(directory: &Path) -> BTreeMap<String, StoredObject> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            let object = StoredObject {
                inode: metadata.ino(),
                mode: metadata.mode(),
                bytes: metadata.is_file().then(|| fs::read(entry.path()).unwrap()),
                link_target: metadata
                    .file_type()
                    .is_symlink()
                    .then(|| fs::read_link(entry.path()).unwrap()),
            };
            (entry.file_name().into_string().unwrap(), object)
        })
        .collect()
}

fn user_ids() -> [u32; 4] {
    let status = fs::read_to_string("/proc/thread-self/status").unwrap();
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .expect("the kernel must report real, effective, saved and filesystem UIDs")
        .split_whitespace()
        .skip(1)
        .map(|value| value.parse().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[test]
fn legacy_syscalls_preserve_effects_and_filesystem_grants() {
    let identity = user_ids();
    assert!(
        identity.iter().all(|uid| *uid == identity[0]),
        "same-UID setuid needs an unchanged-identity outside control: {identity:?}"
    );
    for contained in [false, true] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let mut protected_before = BTreeMap::new();
        let mut expected_metadata = BTreeMap::new();
        let mut expected_link_metadata = BTreeMap::new();
        for scope in SCOPES {
            let directory = root.join(scope);
            fs::create_dir(&directory).unwrap();
            for filename in ["stat-file", "rename-source", "unlink-source", "chmod-file"] {
                fs::write(directory.join(filename), CONTENT).unwrap();
            }
            fs::set_permissions(
                directory.join("chmod-file"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert_eq!(
                fs::metadata(directory.join("chmod-file")).unwrap().mode() & 0o7777,
                0o600
            );
            std::os::unix::fs::symlink("stat-file", directory.join("existing-link")).unwrap();
            let link_metadata = fs::symlink_metadata(directory.join("existing-link")).unwrap();
            expected_link_metadata.insert(
                scope,
                Metadata {
                    inode: link_metadata.ino(),
                    size: link_metadata.len() as i64,
                    mode: link_metadata.mode(),
                },
            );
            protected_before.insert(scope, stored_files(&directory));
            let metadata = fs::metadata(directory.join("stat-file")).unwrap();
            expected_metadata.insert(
                scope,
                Metadata {
                    inode: metadata.ino(),
                    size: metadata.len() as i64,
                    mode: metadata.mode(),
                },
            );
        }
        let report = run_probe(root, contained);
        assert_eq!(
            report.calls.len(),
            39,
            "every probe must report: {report:?}"
        );
        for scope in SCOPES {
            let directory = root.join(scope);
            let visible = !contained || scope != "ungranted";
            let writable = !contained || scope == "writable";
            let stat_label = format!("{scope}/stat");
            assert_eq!(
                report.calls[&stat_label],
                if visible { 0 } else { libc::ENOENT },
                "{report:?}"
            );
            if visible {
                assert_eq!(report.metadata[&stat_label], expected_metadata[scope]);
            } else {
                assert!(!report.metadata.contains_key(&stat_label));
            }
            for (operation, expected) in [
                ("lstat", &expected_metadata[scope]),
                ("lstat-link", &expected_link_metadata[scope]),
                ("open-read", &expected_metadata[scope]),
            ] {
                let label = format!("{scope}/{operation}");
                assert_eq!(
                    report.calls[&label],
                    if visible { 0 } else { libc::ENOENT },
                    "{report:?}"
                );
                if visible {
                    assert_eq!(&report.metadata[&label], expected);
                } else {
                    assert!(!report.metadata.contains_key(&label));
                }
            }
            let read_label = format!("{scope}/open-read");
            if visible {
                assert_eq!(report.opened_bytes[&read_label], CONTENT);
            } else {
                assert!(
                    !report.opened_bytes.contains_key(&read_label),
                    "ungranted host bytes exposed"
                );
            }
            assert_eq!(
                report.calls[&format!("{scope}/missing")],
                libc::ENOENT,
                "{report:?}"
            );
            let expected_error = if writable {
                0
            } else if visible {
                libc::EROFS
            } else {
                libc::ENOENT
            };
            for operation in [
                "rename",
                "unlink",
                "symlink",
                "mkdir",
                "chmod",
                "open-create",
            ] {
                assert_eq!(
                    report.calls[&format!("{scope}/{operation}")],
                    expected_error,
                    "{report:?}"
                );
            }
            if writable {
                let created = directory.join("created-file");
                assert_eq!(fs::read(&created).unwrap(), CONTENT);
                let metadata = fs::metadata(created).unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                assert_eq!(
                    report.metadata[&format!("{scope}/open-create")],
                    Metadata {
                        inode: metadata.ino(),
                        size: CONTENT.len() as i64,
                        mode: metadata.mode(),
                    }
                );
                assert!(!directory.join("rename-source").exists());
                assert_eq!(fs::read(directory.join("renamed")).unwrap(), CONTENT);
                assert!(!directory.join("unlink-source").exists());
                assert_eq!(
                    fs::read_link(directory.join("symbolic-link")).unwrap(),
                    Path::new("stat-file")
                );
                assert_eq!(fs::read(directory.join("symbolic-link")).unwrap(), CONTENT);
                assert!(directory.join("created-directory").is_dir());
                assert_eq!(
                    fs::metadata(directory.join("chmod-file")).unwrap().mode() & 0o7777,
                    0o755
                );
            } else {
                assert_eq!(
                    stored_files(&directory),
                    protected_before[scope],
                    "protected host files changed"
                );
            }
        }
        assert_eq!(report.calls["vfork"], 0, "{report:?}");
        let child = report
            .vfork_child
            .as_ref()
            .expect("vfork must create a child");
        assert!(child.pid > 0);
        assert_eq!(child.waited_pid, child.pid, "{child:?}");
        assert_eq!(child.wait_error, 0, "{child:?}");
        assert!(libc::WIFEXITED(child.status), "{child:?}");
        assert_eq!(
            libc::WEXITSTATUS(child.status),
            if contained {
                VFORK_CHILD_DENIED
            } else {
                VFORK_CHILD_ALLOWED
            },
            "the child must retain the inherited setuid restriction: {child:?}"
        );
        assert_eq!(child.second_wait, -1, "{child:?}");
        assert_eq!(child.second_wait_error, libc::ECHILD, "{child:?}");
        assert_eq!(report.calls["pipe"], 0, "{report:?}");
        assert_eq!(report.pipe_bytes, b"pipe round trip");
        assert_eq!(
            report.calls["escape/symlink"], 0,
            "creating a link must not grant its target"
        );
        assert_eq!(
            fs::read_link(root.join("writable/escape-link")).unwrap(),
            root.join("ungranted/stat-file")
        );
        assert_eq!(
            report.calls["escape/lstat"], 0,
            "lstat inspects the permitted link without following it"
        );
        let metadata = fs::symlink_metadata(root.join("writable/escape-link")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_eq!(
            report.metadata["escape/lstat"],
            Metadata {
                inode: metadata.ino(),
                size: metadata.len() as i64,
                mode: metadata.mode(),
            }
        );
        let expected_error = if contained { libc::ENOENT } else { 0 };
        assert_eq!(report.calls["escape/stat"], expected_error, "{report:?}");
        assert_eq!(report.calls["escape/read"], expected_error, "{report:?}");
        if contained {
            assert!(
                report.escaped_read.is_none(),
                "ungranted host bytes were exposed"
            );
            assert!(!report.metadata.contains_key("escape/stat"));
        } else {
            assert_eq!(report.escaped_read.as_deref(), Some(CONTENT));
            assert_eq!(
                report.metadata["escape/stat"],
                expected_metadata["ungranted"]
            );
        }
    }
    assert_eq!(
        user_ids(),
        identity,
        "the parent identity must remain unchanged"
    );
}
