//! Native hard links stay within the Linux mount view's writable targets.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use containment::{ContainmentConfig, Operation, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MARKER: &str = "HARD_LINK_RESULTS=";
const COMMAND: &[u8] = b"#!/bin/sh\nprintf command\n";

#[derive(Debug, Serialize, Deserialize)]
struct Object {
    device: u64,
    inode: u64,
    mount: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Report {
    objects: BTreeMap<String, Object>,
    errors: BTreeMap<String, i32>,
}

fn name(path: &Path) -> CString {
    CString::new(path.as_os_str().as_encoded_bytes()).unwrap()
}

fn error(result: libc::c_long) -> i32 {
    if result < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    } else {
        0
    }
}

fn link(source_fd: i32, source: &CStr, target_fd: i32, target: &CStr, flags: u64) -> i32 {
    // SAFETY: both strings remain live and each descriptor is borrowed for this call.
    error(unsafe {
        libc::syscall(
            libc::SYS_linkat,
            source_fd,
            source.as_ptr(),
            target_fd,
            target.as_ptr(),
            flags,
        )
    })
}

fn link_paths(source: &Path, target: &Path, flags: u64) -> i32 {
    link(
        libc::AT_FDCWD,
        &name(source),
        libc::AT_FDCWD,
        &name(target),
        flags,
    )
}

fn object(path: &Path) -> Object {
    let metadata = std::fs::metadata(path).unwrap();
    let path = name(path);
    // SAFETY: statx receives a live path and writable output storage.
    let mut status: libc::statx = unsafe { std::mem::zeroed() };
    assert_eq!(
        // SAFETY: statx receives a live path and writable output storage.
        unsafe {
            libc::statx(
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
                libc::STATX_MNT_ID,
                &mut status,
            )
        },
        0,
        "statx: {}",
        std::io::Error::last_os_error()
    );
    assert_ne!(
        status.stx_mask & libc::STATX_MNT_ID,
        0,
        "kernel did not report the mount identity"
    );
    Object {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: status.stx_mnt_id,
    }
}

fn write_error(path: &Path) -> i32 {
    std::fs::write(path, b"changed")
        .err()
        .and_then(|error| error.raw_os_error())
        .unwrap_or(0)
}

fn rename(source: &Path, target: &Path, exchange: bool) -> i32 {
    let source = name(source);
    let target = name(target);
    // SAFETY: the syscall receives live paths and a defined rename flag.
    error(unsafe {
        if exchange {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        } else {
            libc::syscall(
                libc::SYS_renameat,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
            )
        }
    })
}

fn nested_namespace(root: &Path, relative: &str, label: &str) -> [i32; 6] {
    let command = name(&root.join(relative));
    let protected_target = name(&root.join(format!("a/nested-{label}-link")));
    let cache = name(&root.join("a/cache"));
    let cache_target = name(&root.join(format!("a/nested-{label}-cache-link")));
    let mut pipe = [0; 2];
    // SAFETY: pipe supplies two writable descriptor slots.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: the child uses only raw syscalls and exits without running Rust destructors.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut results = [-1_i32; 6];
        // SAFETY: these operations affect only this disposable child and its copied mount namespace.
        unsafe {
            libc::close(pipe[0]);
            results[0] = if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) == 0 {
                0
            } else {
                *libc::__errno_location()
            };
            if results[0] == 0 {
                results[5] = if libc::umount2(command.as_ptr(), 0) == 0 {
                    0
                } else {
                    *libc::__errno_location()
                };
                results[1] = if libc::umount2(command.as_ptr(), libc::MNT_DETACH) == 0 {
                    0
                } else {
                    *libc::__errno_location()
                };
                results[2] = if libc::linkat(
                    libc::AT_FDCWD,
                    command.as_ptr(),
                    libc::AT_FDCWD,
                    protected_target.as_ptr(),
                    0,
                ) == 0
                {
                    0
                } else {
                    *libc::__errno_location()
                };
                results[3] = if libc::linkat(
                    libc::AT_FDCWD,
                    cache.as_ptr(),
                    libc::AT_FDCWD,
                    cache_target.as_ptr(),
                    0,
                ) == 0
                {
                    0
                } else {
                    *libc::__errno_location()
                };
                let fd = libc::open(command.as_ptr(), libc::O_WRONLY | libc::O_TRUNC);
                results[4] = if fd >= 0 {
                    libc::close(fd);
                    0
                } else {
                    *libc::__errno_location()
                };
            }
            let written = libc::write(
                pipe[1],
                results.as_ptr().cast(),
                std::mem::size_of_val(&results),
            );
            libc::_exit(if written == std::mem::size_of_val(&results) as isize {
                0
            } else {
                1
            });
        }
    }
    // SAFETY: the parent owns these pipe ends, and waits for its one known child.
    let mut reader = unsafe {
        libc::close(pipe[1]);
        File::from_raw_fd(pipe[0])
    };
    let mut bytes = [0; 24];
    reader.read_exact(&mut bytes).unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "nested probe: {status}"
    );
    std::array::from_fn(|index| {
        i32::from_ne_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

#[test]
fn hard_link_probe() {
    let Some(root) = std::env::var_os("BOX_HARD_LINK_PROBE") else {
        return;
    };
    let root = Path::new(&root);
    // SAFETY: this disposable probe must not leave the test runner waiting indefinitely.
    unsafe { libc::alarm(20) };
    let mut report = Report::default();
    for (label, relative) in [
        ("a", "a"),
        ("cache", "a/cache"),
        ("nested", "a/nested"),
        ("nested-cache", "a/nested/cache"),
        ("b", "b"),
        ("read", "read"),
        ("command", "read/command"),
        ("alias", "read/command-alias"),
        ("exact", "exact"),
        ("protected", "a/protected"),
    ] {
        report
            .objects
            .insert(label.to_owned(), object(&root.join(relative)));
    }
    let command = root.join("read/command");
    let cache = root.join("a/cache");
    let command_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(&command)
        .unwrap();
    let cache_fd = File::open(&cache).unwrap();
    let a = File::open(root.join("a")).unwrap();
    let read = File::open(root.join("read")).unwrap();
    for (label, source, target, flags) in [
        ("protected-file", "a/protected", "a/protected-link", 0),
        ("same-grant", "a/cache", "a/cache-link", 0),
        ("ordinary-subdirectory", "a/cache", "a/nested/cache-link", 0),
        ("separate-write-grants", "a/cache", "b/cache-link", 0),
        ("read-only-command", "read/command", "a/command-link", 0),
        ("read-only-alias", "read/command-alias", "a/alias-link", 0),
        ("exact-write-file", "exact", "a/exact-link", 0),
        ("ungranted-source", "outside", "a/outside-link", 0),
        ("high-word-zero", "a/cache", "a/high-zero", 1 << 32),
        (
            "invalid-flags",
            "a/cache",
            "a/invalid-flags",
            libc::AT_REMOVEDIR as u64,
        ),
    ] {
        report.errors.insert(
            label.to_owned(),
            link_paths(&root.join(source), &root.join(target), flags),
        );
    }
    std::os::unix::fs::symlink(&cache, root.join("a/cache-symlink")).unwrap();
    std::os::unix::fs::symlink(&command, root.join("a/command-symlink")).unwrap();
    for (label, source, target, flags) in [
        (
            "follow-cache-symlink",
            "a/cache-symlink",
            "a/followed-cache",
            libc::AT_SYMLINK_FOLLOW as u64,
        ),
        (
            "high-word-follow",
            "a/cache-symlink",
            "a/high-follow",
            (1 << 32) | libc::AT_SYMLINK_FOLLOW as u64,
        ),
        (
            "follow-command-symlink",
            "a/command-symlink",
            "a/followed-command",
            libc::AT_SYMLINK_FOLLOW as u64,
        ),
        (
            "link-symlink-itself",
            "a/command-symlink",
            "a/linked-symlink",
            0,
        ),
    ] {
        report.errors.insert(
            label.to_owned(),
            link_paths(&root.join(source), &root.join(target), flags),
        );
    }
    report.errors.insert(
        "directory-fds".to_owned(),
        link(a.as_raw_fd(), c"cache", a.as_raw_fd(), c"directory-link", 0),
    );
    report.errors.insert(
        "read-directory-fd".to_owned(),
        link(
            read.as_raw_fd(),
            c"command-alias",
            a.as_raw_fd(),
            c"read-directory-link",
            0,
        ),
    );
    for (label, descriptor, target, flags) in [
        (
            "empty-cache-fd",
            cache_fd.as_raw_fd(),
            "empty-cache",
            libc::AT_EMPTY_PATH,
        ),
        (
            "empty-command-fd",
            command_fd.as_raw_fd(),
            "empty-command",
            libc::AT_EMPTY_PATH,
        ),
        (
            "empty-follow-cache-fd",
            cache_fd.as_raw_fd(),
            "empty-follow-cache",
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_FOLLOW,
        ),
        (
            "empty-follow-command-fd",
            command_fd.as_raw_fd(),
            "empty-follow-command",
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_FOLLOW,
        ),
    ] {
        report.errors.insert(
            label.to_owned(),
            link(
                descriptor,
                c"",
                a.as_raw_fd(),
                &CString::new(target).unwrap(),
                flags as u64,
            ),
        );
    }
    for (label, descriptor, target) in [
        ("proc-cache-fd", cache_fd.as_raw_fd(), "proc-cache"),
        ("proc-command-fd", command_fd.as_raw_fd(), "proc-command"),
    ] {
        let source = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
        report.errors.insert(
            label.to_owned(),
            link_paths(
                &source,
                &root.join("a").join(target),
                libc::AT_SYMLINK_FOLLOW as u64,
            ),
        );
    }
    for (label, directory, target) in [
        ("tmpfile", root.join("a"), root.join("a/published-tmpfile")),
        (
            "private-tmpfile",
            PathBuf::from("/tmp"),
            root.join("a/imported-tmpfile"),
        ),
    ] {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_TMPFILE)
            .mode(0o600)
            .open(&directory)
        {
            Ok(file) => {
                report.errors.insert(format!("{label}-open"), 0);
                report.errors.insert(
                    format!("{label}-empty"),
                    link(
                        file.as_raw_fd(),
                        c"",
                        libc::AT_FDCWD,
                        &name(&target),
                        libc::AT_EMPTY_PATH as u64,
                    ),
                );
                let source = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
                report.errors.insert(
                    format!("{label}-proc"),
                    link_paths(
                        &source,
                        &target.with_extension("proc"),
                        libc::AT_SYMLINK_FOLLOW as u64,
                    ),
                );
            }
            Err(error) => {
                report
                    .errors
                    .insert(format!("{label}-open"), error.raw_os_error().unwrap());
            }
        }
    }
    let nested = nested_namespace(root, "read/command", "command");
    for (label, result) in [
        "nested-unshare",
        "nested-unmount-command",
        "nested-command-link",
        "nested-cache-link",
        "nested-command-write",
        "nested-unmount-command-normal",
    ]
    .into_iter()
    .zip(nested)
    {
        report.errors.insert(label.to_owned(), result);
    }
    let nested = nested_namespace(root, "a/protected", "protected");
    for (label, result) in [
        "protected-unshare",
        "protected-unmount",
        "protected-link",
        "protected-cache-link",
        "protected-write",
        "protected-unmount-normal",
    ]
    .into_iter()
    .zip(nested)
    {
        report.errors.insert(label.to_owned(), result);
    }
    let private = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(private.path().join("cache"), b"private cache").unwrap();
    report.errors.insert(
        "private-cache-link".to_owned(),
        link_paths(
            &private.path().join("cache"),
            &private.path().join("linked"),
            0,
        ),
    );
    report.errors.insert(
        "command-into-private".to_owned(),
        link_paths(&command, &private.path().join("command"), 0),
    );
    for (label, path) in [
        ("direct-command-write", command.clone()),
        ("symlink-command-write", root.join("a/command-symlink")),
        (
            "proc-command-write",
            PathBuf::from(format!("/proc/self/fd/{}", command_fd.as_raw_fd())),
        ),
    ] {
        report.errors.insert(label.to_owned(), write_error(&path));
    }
    report.errors.insert(
        "rename-same-grant".to_owned(),
        rename(&root.join("a/rename"), &root.join("a/renamed"), false),
    );
    report.errors.insert(
        "rename-across-grants".to_owned(),
        rename(&root.join("a/cross-rename"), &root.join("b/renamed"), false),
    );
    report.errors.insert(
        "rename-command-alias".to_owned(),
        rename(
            &root.join("read/command-alias"),
            &root.join("a/moved-command"),
            false,
        ),
    );
    report.errors.insert(
        "rename-alias-directory".to_owned(),
        rename(
            &root.join("read/stash"),
            &root.join("a/imported-stash"),
            false,
        ),
    );
    report.errors.insert(
        "exchange-across-grants".to_owned(),
        rename(&root.join("a/exchange"), &root.join("b/exchange"), true),
    );
    if report.errors["same-grant"] == 0 {
        std::fs::write(
            root.join("a/cache-link"),
            b"cache changed through its hard link",
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&cache).unwrap(),
            b"cache changed through its hard link"
        );
        assert_eq!(
            std::fs::metadata(&cache).unwrap().ino(),
            std::fs::metadata(root.join("a/cache-link")).unwrap().ino()
        );
    }
    if report.errors["link-symlink-itself"] == 0 {
        assert!(
            std::fs::symlink_metadata(root.join("a/linked-symlink"))
                .unwrap()
                .is_symlink()
        );
        report.errors.insert(
            "linked-symlink-command-write".to_owned(),
            write_error(&root.join("a/linked-symlink")),
        );
    }
    println!("{MARKER}{}", serde_json::to_string(&report).unwrap());
}

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("box-hard-links-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let root = directory.path();
        for path in ["a/nested", "b", "read/stash"] {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
        for path in [
            "a/cache",
            "a/protected",
            "a/nested/cache",
            "a/rename",
            "a/cross-rename",
            "a/exchange",
            "b/exchange",
            "exact",
            "outside",
        ] {
            std::fs::write(root.join(path), path.as_bytes()).unwrap();
        }
        let command = root.join("read/command");
        std::fs::write(&command, COMMAND).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&command, root.join("read/command-alias")).unwrap();
        std::fs::hard_link(&command, root.join("read/stash/alias")).unwrap();
        Self { directory }
    }

    fn launch(&self, contained: bool, nested_grant: bool) -> Output {
        let root = self.directory.path();
        let executable = std::env::current_exe().unwrap();
        let mut command;
        if contained {
            let mut config = ContainmentConfig::new()
                .allow(&executable, Operation::Read, Scope::File)
                .unwrap()
                .allow(&executable, Operation::Exec, Scope::File)
                .unwrap()
                .allow(root.join("a"), Operation::Read, Scope::Root)
                .unwrap()
                .allow(root.join("a"), Operation::Write, Scope::Root)
                .unwrap()
                .allow(root.join("b"), Operation::Read, Scope::Root)
                .unwrap()
                .allow(root.join("b"), Operation::Write, Scope::Root)
                .unwrap()
                .allow(root.join("read"), Operation::Read, Scope::Root)
                .unwrap()
                .allow(root.join("read/command"), Operation::Read, Scope::File)
                .unwrap()
                .allow(root.join("exact"), Operation::Read, Scope::File)
                .unwrap()
                .allow(root.join("exact"), Operation::Write, Scope::File)
                .unwrap();
            let protected = root.join("a/protected");
            config = config
                .protect_write(&protected, &File::open(&protected).unwrap())
                .unwrap();
            if nested_grant {
                config = config
                    .allow(root.join("a/nested"), Operation::Write, Scope::Root)
                    .unwrap();
            }
            let json = config.to_json().unwrap();
            let digest = Sha256::digest(json.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let config_path = root.join("containment.json");
            std::fs::write(&config_path, json).unwrap();
            command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
            command
                .arg("--config")
                .arg(config_path)
                .args(["--config-sha256", &digest, "--target-env-json"])
                .arg(serde_json::json!({"BOX_HARD_LINK_PROBE": root}).to_string())
                .arg("--")
                .arg(&executable);
        } else {
            command = Command::new(&executable);
            command.env("BOX_HARD_LINK_PROBE", root);
        }
        command
            .current_dir(root.join("a"))
            .args([
                "--exact",
                "hard_link_probe",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap()
    }

    fn run(&self, contained: bool, nested_grant: bool) -> Report {
        let output = self.launch(contained, nested_grant);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "contained={contained}: {}: {stdout}\n{stderr}",
            output.status
        );
        let json = stdout
            .lines()
            .find_map(|line| line.split_once(MARKER).map(|(_, value)| value))
            .expect("probe result");
        println!("contained={contained}, nested_grant={nested_grant}: {json}");
        serde_json::from_str(json).unwrap()
    }
}

fn succeeds(report: &Report, names: &[&str]) {
    for name in names {
        assert_eq!(report.errors[*name], 0, "{name}: {report:?}");
    }
}

fn refused(report: &Report, names: &[&str], errors: &[i32]) {
    for name in names {
        assert!(errors.contains(&report.errors[*name]), "{name}: {report:?}");
    }
}

#[test]
fn native_hard_links_stay_inside_effective_write_mounts() {
    let control_fixture = Fixture::new();
    let control = control_fixture.run(false, false);
    let fixture = Fixture::new();
    let contained = fixture.run(true, false);
    for report in [&control, &contained] {
        let device = report.objects["a"].device;
        assert!(
            report
                .objects
                .values()
                .all(|object| object.device == device),
            "fixture paths must share one filesystem: {report:?}"
        );
    }
    let host_mount = control.objects["a"].mount;
    assert!(
        control
            .objects
            .values()
            .all(|object| object.mount == host_mount),
        "host controls must not begin across mounts"
    );
    let a = contained.objects["a"].mount;
    assert_eq!(contained.objects["cache"].mount, a);
    assert_eq!(contained.objects["nested"].mount, a);
    assert_eq!(contained.objects["nested-cache"].mount, a);
    let separate =
        ["a", "b", "read", "exact", "protected"].map(|name| contained.objects[name].mount);
    for (index, mount) in separate.iter().enumerate() {
        assert!(
            !separate[..index].contains(mount),
            "effective targets must retain separate mounts: {contained:?}"
        );
    }
    for writable in ["a", "b", "exact"] {
        assert_ne!(
            contained.objects["command"].mount, contained.objects[writable].mount,
            "the command must remain separate from writable mounts"
        );
    }
    assert_eq!(
        contained.objects["command"].inode,
        contained.objects["alias"].inode
    );
    for report in [&control, &contained] {
        succeeds(
            report,
            &[
                "same-grant",
                "ordinary-subdirectory",
                "directory-fds",
                "follow-cache-symlink",
                "high-word-zero",
                "high-word-follow",
                "link-symlink-itself",
                "proc-cache-fd",
                "rename-same-grant",
                "private-cache-link",
            ],
        );
        refused(report, &["invalid-flags"], &[libc::EINVAL]);
    }
    let crossings = [
        "protected-file",
        "separate-write-grants",
        "read-only-command",
        "read-only-alias",
        "exact-write-file",
        "follow-command-symlink",
        "read-directory-fd",
        "proc-command-fd",
        "rename-across-grants",
        "rename-command-alias",
        "rename-alias-directory",
    ];
    succeeds(&control, &crossings);
    refused(&contained, &crossings, &[libc::EXDEV]);
    succeeds(&control, &["ungranted-source"]);
    refused(&contained, &["ungranted-source"], &[libc::ENOENT]);
    for (positive, negative) in [
        ("empty-cache-fd", "empty-command-fd"),
        ("empty-follow-cache-fd", "empty-follow-command-fd"),
    ] {
        if control.errors[positive] == 0 {
            succeeds(&contained, &[positive]);
            succeeds(&control, &[negative]);
            refused(&contained, &[negative], &[libc::EXDEV]);
        } else {
            refused(&control, &[positive, negative], &[libc::ENOENT]);
            refused(&contained, &[positive, negative], &[libc::ENOENT]);
            eprintln!(
                "skipping: {positive}: this kernel requires a capability for AT_EMPTY_PATH; proc-fd routes remain tested"
            );
        }
    }
    for report in [&control, &contained] {
        if report.errors["tmpfile-open"] == 0 {
            succeeds(report, &["tmpfile-proc"]);
            if report.errors["empty-cache-fd"] == 0 {
                succeeds(report, &["tmpfile-empty"]);
            } else {
                refused(report, &["tmpfile-empty"], &[libc::ENOENT]);
            }
        } else {
            refused(report, &["tmpfile-open"], &[libc::EOPNOTSUPP]);
            eprintln!("skipping: O_TMPFILE: fixture filesystem does not support anonymous files");
        }
    }
    if contained.errors["private-tmpfile-open"] == 0 {
        refused(&contained, &["private-tmpfile-proc"], &[libc::EXDEV]);
        refused(
            &contained,
            &["private-tmpfile-empty"],
            &[libc::EXDEV, libc::ENOENT],
        );
    }
    succeeds(&contained, &["private-cache-link"]);
    refused(&contained, &["command-into-private"], &[libc::EXDEV]);
    let writes = [
        "direct-command-write",
        "symlink-command-write",
        "linked-symlink-command-write",
        "proc-command-write",
    ];
    succeeds(&control, &writes);
    refused(&contained, &writes, &[libc::EROFS]);
    succeeds(&control, &["exchange-across-grants"]);
    refused(
        &contained,
        &["exchange-across-grants"],
        &[libc::EPERM, libc::EXDEV],
    );
    assert_eq!(
        std::fs::read(fixture.directory.path().join("read/command")).unwrap(),
        COMMAND
    );
    assert_eq!(
        std::fs::metadata(fixture.directory.path().join("read/command"))
            .unwrap()
            .nlink(),
        3
    );
    assert!(fixture.directory.path().join("read/stash/alias").is_file());
    assert!(!fixture.directory.path().join("a/imported-stash").exists());
    if control.errors["nested-unshare"] == 0 {
        succeeds(&contained, &["nested-unshare", "nested-cache-link"]);
        succeeds(
            &control,
            &[
                "nested-command-link",
                "nested-cache-link",
                "nested-command-write",
            ],
        );
        refused(
            &contained,
            &["nested-unmount-command", "nested-unmount-command-normal"],
            &[libc::EINVAL],
        );
        refused(&contained, &["nested-command-link"], &[libc::EXDEV]);
        refused(&contained, &["nested-command-write"], &[libc::EROFS]);
        succeeds(
            &control,
            &[
                "protected-unshare",
                "protected-link",
                "protected-cache-link",
                "protected-write",
            ],
        );
        succeeds(&contained, &["protected-unshare", "protected-cache-link"]);
        refused(
            &contained,
            &["protected-unmount", "protected-unmount-normal"],
            &[libc::EINVAL],
        );
        refused(&contained, &["protected-link"], &[libc::EXDEV]);
        refused(&contained, &["protected-write"], &[libc::EROFS]);
        assert_eq!(
            std::fs::read(fixture.directory.path().join("a/protected")).unwrap(),
            b"a/protected"
        );
    } else {
        refused(
            &control,
            &["nested-unshare"],
            &[
                libc::EPERM,
                libc::EACCES,
                libc::ENOSYS,
                libc::ENOSPC,
                libc::EUSERS,
            ],
        );
        eprintln!(
            "skipping: nested user namespace: uncontained control errno={}",
            control.errors["nested-unshare"]
        );
    }
}

#[test]
fn overlapping_write_roots_refuse_before_the_probe_starts() {
    let fixture = Fixture::new();
    let output = fixture.launch(true, true);
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lies inside the write root"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(MARKER));
    assert_eq!(
        std::fs::read(fixture.directory.path().join("read/command")).unwrap(),
        COMMAND
    );
}
