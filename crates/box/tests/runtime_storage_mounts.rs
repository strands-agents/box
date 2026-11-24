//! Real Box command tests for asynchronous, protected admission of two FUSE roots.

#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ROOTS: [&str; 2] = ["/mnt/storage-first", "/mnt/storage-second"];
const CONTENTS: [&[u8]; 2] = [b"captured-first", b"captured-second"];
const OUTPUT: &str = "/mnt/storage-output";
const WAIT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_protects_two_fuse_roots_mounted_before_startup() {
    isolated(|| normal_box("before"));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_admits_first_root_while_second_stays_pending() {
    isolated(|| normal_box("after-first"));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_admits_second_root_while_first_stays_pending() {
    isolated(|| normal_box("after-second"));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_stops_all_processes_when_captured_rules_cannot_compile() {
    isolated(|| normal_box("compile-failure"));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_preserves_distinct_agent_tool_and_local_mcp_storage_permissions() {
    isolated(|| normal_box_roles(false));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn normal_box_stops_agent_tool_and_local_mcp_when_storage_compilation_fails() {
    isolated(|| normal_box_roles(true));
}

fn isolated(body: impl FnOnce()) {
    const CHILD: &str = "BOX_NORMAL_STORAGE_TEST_CHILD";
    let thread = std::thread::current();
    let name = thread.name().expect("a named test");
    if std::env::var(CHILD).as_deref() == Ok(name) {
        bring_up_loopback();
        body();
        return;
    }
    let fixture = std::env::var_os("BOX_STORAGE_TEST_FUSE")
        .expect("set BOX_STORAGE_TEST_FUSE to the compiled foreground FUSE fixture");
    assert!(Path::new(&fixture).is_file(), "FUSE fixture must exist");
    let temporary = tempfile::tempdir().unwrap();
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    let mut child = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "--ipc",
            "--uts",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--nocapture",
            "--test-threads=1",
            "--include-ignored",
        ])
        .env(CHILD, name)
        .env("TMPDIR", temporary.path())
        .process_group(0)
        .stdout(Stdio::from(stdout.try_clone().unwrap()))
        .stderr(Stdio::from(stderr.try_clone().unwrap()))
        .spawn()
        .expect("start isolated normal Box test");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let out = tail(&mut stdout);
            let err = tail(&mut stderr);
            assert!(status.success(), "{status}; stdout: {out}; stderr: {err}");
            assert!(
                out.contains("1 passed; 0 failed; 0 ignored"),
                "the selected integration test must execute: {out}; {err}"
            );
            eprintln!("{err}");
            break;
        }
        if Instant::now() >= deadline {
            // SAFETY: this test created and owns the isolated child's process group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            let status = child.wait().unwrap();
            panic!(
                "normal Box storage test timed out: {status}; stdout: {}; stderr: {}",
                tail(&mut stdout),
                tail(&mut stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The outer Box gateway must be able to connect to its listener during shutdown.
/// Only this fixture's newly created network namespace is changed.
fn bring_up_loopback() {
    // SAFETY: socket uses constant arguments and returns a new descriptor.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        descriptor >= 0,
        "loopback control socket: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful socket call returned one owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: an all-zero ifreq is valid before setting its interface name.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: ioctl receives the correctly sized, live ifreq for loopback.
    assert_eq!(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) },
        0
    );
    // SAFETY: SIOCGIFFLAGS initialized the flags member of this ifreq union.
    unsafe {
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    // SAFETY: the same live ifreq now requests loopback's existing flags plus IFF_UP.
    assert_eq!(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) },
        0
    );
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let _accepted = listener.accept().unwrap();
    drop(client);
}

fn tail(file: &mut std::fs::File) -> String {
    const LIMIT: u64 = 64 * 1024;
    let size = file.metadata().unwrap().len();
    file.seek(SeekFrom::Start(size.saturating_sub(LIMIT)))
        .unwrap();
    let mut bytes = Vec::new();
    file.take(LIMIT).read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

struct PrivateMount;
impl Drop for PrivateMount {
    fn drop(&mut self) {
        // SAFETY: /mnt belongs solely to this test's private namespace.
        unsafe { libc::umount2(c"/mnt".as_ptr(), libc::MNT_DETACH) };
    }
}

fn mount_tmpfs(path: &Path) {
    let target = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: each target is a fixture-owned directory in the private namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755,size=16m".as_ptr().cast(),
            )
        },
        0,
        "mount tmpfs: {}",
        std::io::Error::last_os_error()
    );
}

struct Process {
    child: Child,
    stdout: std::fs::File,
    stderr: std::fs::File,
    finished: bool,
}

impl Process {
    fn start(command: &mut Command) -> Self {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
            finished: false,
        }
    }

    fn require_running(&mut self, action: &str) {
        if let Some(status) = self.child.try_wait().unwrap() {
            self.finished = true;
            panic!(
                "process exited {action}: {status}; stdout: {}; stderr: {}",
                tail(&mut self.stdout),
                tail(&mut self.stderr)
            );
        }
    }

    fn expect_failure(&mut self) -> ExitStatus {
        // The failure probe runs for 60 seconds; this bound proves Box stopped it first.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                assert!(
                    !status.success(),
                    "Box accepted a source whose required denial cannot compile"
                );
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Box did not stop after source compilation failed; stdout: {}; stderr: {}",
                tail(&mut self.stdout),
                tail(&mut self.stderr)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                assert!(
                    status.success(),
                    "process failed: {status}; stdout: {}; stderr: {}",
                    tail(&mut self.stdout),
                    tail(&mut self.stderr)
                );
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "process {} did not finish; stdout: {}; stderr: {}",
                self.child.id(),
                tail(&mut self.stdout),
                tail(&mut self.stderr)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn populate(root: &Path, contents: &[u8]) {
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::create_dir_all(root.join("writable/frozen")).unwrap();
    std::fs::write(root.join("public"), contents).unwrap();
    std::fs::write(root.join("secret/token"), b"DENIED SOURCE BYTES").unwrap();
    std::fs::write(
        root.join("writable/frozen/existing"),
        b"readable but immutable",
    )
    .unwrap();
    std::fs::copy("/bin/true", root.join("run-true")).unwrap();
    std::fs::set_permissions(
        root.join("run-true"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

fn start_fuse(backing: &Path, root: &Path, contents: &[u8]) -> Process {
    let binary = std::env::var_os("BOX_STORAGE_TEST_FUSE").unwrap();
    let mut process = Process::start(Command::new(binary).arg(backing).arg(root));
    let deadline = Instant::now() + WAIT;
    loop {
        if std::fs::read(root.join("public")).is_ok_and(|bytes| bytes == contents) {
            break;
        }
        process.require_running("before FUSE attachment");
        assert!(
            Instant::now() < deadline,
            "FUSE source did not appear at {}",
            root.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| {
                line.split_whitespace().nth(4) == root.to_str()
                    && line
                        .split_once(" - ")
                        .is_some_and(|(_, fields)| fields.starts_with("fuse.boxfixture "))
            }),
        "the fixture must attach a real FUSE filesystem"
    );
    process
}

fn wait_marker(path: &Path, process: &mut Process) {
    let started = Instant::now();
    let deadline = started + WAIT;
    let mut sampled = false;
    while !path.exists() {
        if process.child.try_wait().unwrap().is_some() {
            storage_diagnostics("process-exited", path, process.child.id());
        }
        process.require_running("while waiting for workload marker");
        if !sampled && started.elapsed() >= Duration::from_secs(5) {
            storage_diagnostics("waiting-five-seconds", path, process.child.id());
            sampled = true;
        }
        if Instant::now() >= deadline {
            storage_diagnostics("marker-timeout", path, process.child.id());
            panic!(
                "waiting for {}; stdout: {}; stderr: {}",
                path.display(),
                tail(&mut process.stdout),
                tail(&mut process.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// Optional evidence for these ignored tests. Read only fixed receipt names and bounded proc files;
// never walk or probe provider contents while diagnosing a possibly blocked filesystem.
fn diagnostic_text(path: &Path, limit: usize) -> serde_json::Value {
    let result = (|| -> std::io::Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    match result {
        Ok(bytes) => serde_json::json!({
            "text":String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]),
            "truncated":bytes.len() > limit,
        }),
        Err(error) => serde_json::json!({"error":error.to_string(), "errno":error.raw_os_error()}),
    }
}

fn diagnostic_process(pid: u32) -> serde_json::Value {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let mut record = serde_json::Map::new();
    record.insert("pid".into(), serde_json::json!(pid));
    for name in ["status", "wchan", "syscall", "cmdline"] {
        record.insert(name.into(), diagnostic_text(&root.join(name), 8192));
    }
    for name in ["ns/user", "ns/mnt", "ns/pid"] {
        record.insert(
            name.into(),
            match std::fs::read_link(root.join(name)) {
                Ok(target) => serde_json::json!(target.to_string_lossy()),
                Err(error) => serde_json::json!({"error":error.to_string()}),
            },
        );
    }
    let mounts = diagnostic_text(&root.join("mountinfo"), 256 * 1024);
    let selected: Vec<_> = mounts["text"]
        .as_str()
        .unwrap_or("")
        .lines()
        .filter(|line| {
            line.split_whitespace().nth(4).is_some_and(|target| {
                target == "/"
                    || target == "/proc"
                    || target == "/mnt"
                    || target.starts_with("/mnt/")
            })
        })
        .take(48)
        .map(|line| line.chars().take(1024).collect::<String>())
        .collect();
    record.insert("mountinfo".into(), serde_json::json!({
        "selected":selected, "read_error":mounts["error"], "input_truncated":mounts["truncated"],
        "selection_limit":48,
    }));
    let mut threads = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join("task")) {
        for entry in entries.flatten().take(32) {
            threads.push(serde_json::json!({
                "tid":entry.file_name().to_string_lossy(),
                "comm":diagnostic_text(&entry.path().join("comm"), 128),
                "wchan":diagnostic_text(&entry.path().join("wchan"), 128),
                "syscall":diagnostic_text(&entry.path().join("syscall"), 512),
            }));
        }
    }
    record.insert("threads".into(), serde_json::json!(threads));
    serde_json::Value::Object(record)
}

fn storage_diagnostics(label: &str, waiting_for: &Path, box_pid: u32) {
    let Some(directory) = std::env::var_os("BOX_STORAGE_TEST_DIAGNOSTICS").map(PathBuf::from)
    else {
        return;
    };
    let result = (|| -> Result<PathBuf, String> {
        if !directory.is_absolute() {
            return Err(
                "BOX_STORAGE_TEST_DIAGNOSTICS must be an absolute evidence directory".into(),
            );
        }
        let mut roles = serde_json::Map::new();
        for role in ["agent", "tool", "server"] {
            let mut receipts = serde_json::Map::new();
            for name in [
                "pending",
                "active",
                "passed",
                "state",
                "error",
                "all-live",
                "all-passed",
                "monitoring",
                "monitor-state",
                "monitor-joined",
                "unexpected-publication",
            ] {
                receipts.insert(
                    name.into(),
                    diagnostic_text(&Path::new(OUTPUT).join(role).join(name), 8192),
                );
            }
            roles.insert(role.into(), serde_json::Value::Object(receipts));
        }
        // The harness already runs inside its own PID namespace, so this bounded list contains
        // only the fixture and its children, including source daemons beside the Box process.
        let mut pids: Vec<u32> = std::fs::read_dir("/proc")
            .map_err(|error| error.to_string())?
            .flatten()
            .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
            .collect();
        pids.sort_unstable();
        let seen = pids.len();
        pids.truncate(64);
        let processes: Vec<_> = pids.into_iter().map(diagnostic_process).collect();
        let timestamp = fixture_unix_millis();
        let thread = std::thread::current();
        let test = thread.name().unwrap_or("storage-test");
        let name: String = test
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let marker = waiting_for
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let report = serde_json::json!({
            "label":label, "test":test, "timestamp_unix_ms":timestamp, "box_pid":box_pid,
            "waiting_for":waiting_for, "roles":roles, "processes":processes,
            "processes_seen":seen, "process_limit":64, "thread_limit_per_process":32,
        });
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let path = directory.join(format!("{name}-{label}-{marker}-{timestamp}.json"));
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(path)
    })();
    match result {
        Ok(path) => eprintln!("storage fixture diagnostic: {}", path.display()),
        Err(error) => eprintln!("storage fixture diagnostic failed: {error}"),
    }
}

fn descendant_exited_after_scan(pid: u32, error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        Some(libc::ESRCH) => true,
        Some(libc::EINVAL) => {
            // Linux can retain the PID reference after its task has been reaped. Require an
            // independent absence check so an invalid call never hides a live descendant.
            // SAFETY: signal zero checks existence without delivering a signal.
            let absent = unsafe { libc::kill(pid as libc::pid_t, 0) } == -1;
            absent && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        }
        _ => false,
    }
}

#[test]
fn descendant_exit_race_accepts_a_reaped_child_but_never_a_live_child() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("start a child that remains alive until killed");
    let pid = child.id();
    let invalid = std::io::Error::from_raw_os_error(libc::EINVAL);
    let accepted_live_child = descendant_exited_after_scan(pid, &invalid);
    child.kill().expect("stop the test-owned child");
    child.wait().expect("reap the test-owned child");
    assert!(
        !accepted_live_child,
        "an invalid call must not hide a live child"
    );
    assert!(
        descendant_exited_after_scan(pid, &invalid),
        "the kernel can return EINVAL when its referenced PID has lost its task"
    );
    assert!(descendant_exited_after_scan(
        pid,
        &std::io::Error::from_raw_os_error(libc::ESRCH)
    ));
    assert!(!descendant_exited_after_scan(
        pid,
        &std::io::Error::from_raw_os_error(libc::EPERM)
    ));
}

fn descendants(parent: u32) -> Vec<OwnedFd> {
    let mut known = BTreeSet::from([parent]);
    loop {
        let before = known.len();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let ancestor = status.lines().find_map(|line| {
                line.strip_prefix("PPid:")
                    .and_then(|value| value.trim().parse::<u32>().ok())
            });
            if ancestor.is_some_and(|pid| known.contains(&pid)) {
                known.insert(pid);
            }
        }
        if known.len() == before {
            break;
        }
    }
    assert!(
        known.len() > 1,
        "the running Box must own a workload process"
    );
    known
        .into_iter()
        .filter_map(|pid| {
            // SAFETY: pidfd_open pins only a process observed in this test-owned Box tree.
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                assert!(
                    descendant_exited_after_scan(pid, &error),
                    "pin Box descendant {pid}: {error}"
                );
                // A completed staging child can be reaped between the process scan and pidfd_open.
                assert_ne!(
                    pid, parent,
                    "the Box owner must remain alive until the finish marker"
                );
                return None;
            }
            // SAFETY: pidfd_open returned a new owned descriptor.
            Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
        })
        .collect()
}

fn require_exited(processes: &[OwnedFd]) {
    let deadline = Instant::now() + WAIT;
    for process in processes {
        let mut event = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "a Box-owned process survived normal completion"
            );
            // SAFETY: the pidfd and one-element poll array remain live during the call.
            let ready = unsafe { libc::poll(&mut event, 1, left.as_millis() as i32) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert!(
                ready > 0 && event.revents & libc::POLLIN != 0,
                "Box descendant exit was not observed"
            );
            break;
        }
    }
}

fn normal_box(mode: &str) {
    mount_tmpfs(Path::new("/mnt"));
    let _mount = PrivateMount;
    // SAFETY: only this new private tmpfs participates in fixture mount propagation.
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/mnt".as_ptr(),
                std::ptr::null(),
                libc::MS_SHARED,
                std::ptr::null(),
            )
        },
        0
    );
    let roots = ROOTS.map(PathBuf::from);
    let output = Path::new(OUTPUT);
    std::fs::create_dir(output).unwrap();
    for root in &roots {
        std::fs::create_dir(root).unwrap();
        mount_tmpfs(root);
        populate(root, b"WRONG UNDERLAY BYTES");
        std::fs::write(
            root.join("underlay-marker"),
            b"never expose this placeholder",
        )
        .unwrap();
    }
    let positive = Path::new("/mnt/positive-true");
    std::fs::copy("/bin/true", positive).unwrap();
    std::fs::set_permissions(positive, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        Command::new(positive).status().unwrap().success(),
        "outside positive executable control"
    );
    let home = tempfile::Builder::new()
        .prefix("bs")
        .tempdir_in("/var/tmp")
        .unwrap();
    let state = home.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let backing = [
        home.path().join("backing-first"),
        home.path().join("backing-second"),
    ];
    for (index, path) in backing.iter().enumerate() {
        populate(path, CONTENTS[index]);
        assert!(
            Command::new(path.join("run-true"))
                .status()
                .unwrap()
                .success(),
            "each denied-exec candidate must be a working executable outside Box"
        );
    }
    if mode == "compile-failure" {
        // Only the arriving provider lacks the required literal; the pending underlay still has it.
        std::fs::rename(
            backing[0].join("secret"),
            backing[0].join("withheld-secret"),
        )
        .unwrap();
    }
    let probe = std::fs::canonicalize(env!("CARGO_BIN_EXE_box-storage-probe")).unwrap();
    let config = home.path().join("box.toml");
    let command = [
        probe.display().to_string(),
        mode.into(),
        OUTPUT.into(),
        ROOTS[0].into(),
        ROOTS[1].into(),
        positive.display().to_string(),
    ];
    let quoted = |value: &str| toml::Value::String(value.into()).to_string();
    let args = command
        .iter()
        .map(|value| quoted(value))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        home.path().join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "name = \"normal-storage\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\n\
         [experimental-features]\nlinux-storage-mounts = true\n\n\
         [agent]\ncommand = [{args}]\nworkspace = {}\n\n\
         [agent.filesystem]\nmounts = [{mount_one}, {mount_two}]\nread = [\"/mnt\"]\nwrite = [{}, {}, {}]\n\
         deny = [{}, {}]\ndeny_write = [{}, {}]\nexec = [{}]\n",
            quoted(&state.display().to_string()),
            quoted(OUTPUT),
            quoted(&roots[0].join("writable").display().to_string()),
            quoted(&roots[1].join("writable").display().to_string()),
            quoted(OUTPUT),
            quoted(&roots[0].join("secret").display().to_string()),
            quoted(&roots[1].join("secret").display().to_string()),
            quoted(&roots[0].join("writable/frozen").display().to_string()),
            quoted(&roots[1].join("writable/frozen").display().to_string()),
            quoted(&positive.display().to_string()),
            mount_one = quoted(ROOTS[0]),
            mount_two = quoted(ROOTS[1]),
        ),
    )
    .unwrap();
    let mut sources = Vec::new();
    if mode == "before" {
        for index in 0..2 {
            sources.push(start_fuse(&backing[index], &roots[index], CONTENTS[index]));
        }
    }
    let mut workload = Process::start(
        Command::new(env!("CARGO_BIN_EXE_strands-box"))
            .args(["run", "--config"])
            .arg(&config)
            .env("HOME", home.path())
            .current_dir(output),
    );
    wait_marker(&output.join("started"), &mut workload);
    if mode == "compile-failure" {
        wait_marker(&output.join("probe-active"), &mut workload);
        let active: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("probe-active")).unwrap()).unwrap();
        assert!(active["checks"].as_u64().unwrap() >= 3);
        assert!(active["background_checks"].as_u64().unwrap() > 0);
        let owned_processes = descendants(workload.child.id());
        let mut source = start_fuse(&backing[0], &roots[0], CONTENTS[0]);
        let status = workload.expect_failure();
        require_exited(&owned_processes);
        let stderr = tail(&mut workload.stderr);
        let missing = roots[0].join("secret");
        let policy_error = format!(
            "`[agent]` filesystem entry {:?} is refused: {} does not exist yet, and the Linux namespace backend cannot refuse a path that is not there; create it first, or deny an existing directory above it",
            missing.display().to_string(),
            missing.display()
        );
        assert!(
            stderr.contains("storage admission:")
                && stderr.contains("captured filesystem compilation failed:")
                && stderr.contains(&policy_error),
            "Box must report the actual retained-rule failure: {stderr}"
        );
        for marker in [
            "unexpected-publication",
            "admitted-first",
            "admitted-second",
            "independent-first",
            "independent-second",
            "passed",
            "finish",
        ] {
            assert!(
                !output.join(marker).exists(),
                "failed admission produced {marker}"
            );
        }
        for (index, path) in backing.iter().enumerate() {
            assert_eq!(std::fs::read(path.join("public")).unwrap(), CONTENTS[index]);
            assert!(
                !path.join("writable/created").exists(),
                "unadmitted storage received a workload write"
            );
            assert!(!path.join("writable/frozen/new").exists());
            assert_eq!(
                std::fs::read(path.join("writable/frozen/existing")).unwrap(),
                b"readable but immutable"
            );
        }
        let first = CString::new(roots[0].as_os_str().as_bytes()).unwrap();
        // SAFETY: every observed Box process exited; detach only this fixture's arriving FUSE mount.
        assert_eq!(
            unsafe { libc::umount2(first.as_ptr(), libc::MNT_DETACH) },
            0
        );
        source.finish();
        for root in &roots {
            assert_eq!(
                std::fs::read(root.join("underlay-marker")).unwrap(),
                b"never expose this placeholder"
            );
            assert_eq!(
                std::fs::read(root.join("public")).unwrap(),
                b"WRONG UNDERLAY BYTES"
            );
            assert!(!root.join("writable/created").exists());
        }
        eprintln!(
            "normal Box source compilation failure: {status}; owned_processes_exited={}; probe={active}; exact_policy_error={policy_error}",
            owned_processes.len()
        );
        return;
    }
    if mode != "before" {
        let first = usize::from(mode == "after-second");
        sources.push(start_fuse(&backing[first], &roots[first], CONTENTS[first]));
        let label = if first == 0 { "first" } else { "second" };
        wait_marker(&output.join(format!("independent-{label}")), &mut workload);
        let second = 1 - first;
        sources.push(start_fuse(
            &backing[second],
            &roots[second],
            CONTENTS[second],
        ));
    }
    wait_marker(&output.join("passed"), &mut workload);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("passed")).unwrap()).unwrap();
    assert_eq!(receipt["status"], "passed");
    assert_eq!(receipt["mode"], mode);
    assert!(receipt["background_checks"].as_u64().unwrap() > 0);
    for key in [
        "positive_exec",
        "no_new_privs",
        "secret_denied",
        "underlay_denied",
    ] {
        assert_eq!(
            receipt[key], true,
            "missing successful probe evidence: {key}"
        );
    }
    for key in ["noexec", "read_only_public", "allowed_write", "deny_write"] {
        assert_eq!(
            receipt[key],
            serde_json::json!([true, true]),
            "both roots must pass {key}"
        );
    }
    assert_eq!(receipt["independent"], mode != "before");
    let owned_processes = descendants(workload.child.id());
    let finish = output.join("finish.pending");
    std::fs::write(&finish, b"all provider assertions passed").unwrap();
    std::fs::rename(finish, output.join("finish")).unwrap();
    workload.finish();
    require_exited(&owned_processes);
    for (index, path) in backing.iter().enumerate() {
        assert_eq!(std::fs::read(path.join("public")).unwrap(), CONTENTS[index]);
        assert_eq!(
            std::fs::read(path.join("writable/created")).unwrap(),
            b"allowed storage write"
        );
        assert_eq!(
            std::fs::read(path.join("writable/frozen/existing")).unwrap(),
            b"readable but immutable"
        );
        assert!(!path.join("writable/frozen/new").exists());
    }
    for root in &roots {
        let root_c = CString::new(root.as_os_str().as_bytes()).unwrap();
        // SAFETY: the live Box has exited; detach only its fixture's original FUSE mount.
        assert_eq!(
            unsafe { libc::umount2(root_c.as_ptr(), libc::MNT_DETACH) },
            0
        );
        assert_eq!(
            std::fs::read(root.join("underlay-marker")).unwrap(),
            b"never expose this placeholder"
        );
        assert_eq!(
            std::fs::read(root.join("public")).unwrap(),
            b"WRONG UNDERLAY BYTES"
        );
        assert!(!root.join("writable/created").exists());
    }
    for mut source in sources {
        source.finish();
    }
    eprintln!(
        "normal Box storage mode={mode}: {receipt}; owned_processes_exited={}",
        owned_processes.len()
    );
}

fn populate_role_storage(root: &Path, mounted: bool, required_secret: bool) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("public"),
        if mounted {
            b"captured-roles".as_slice()
        } else {
            b"WRONG UNDERLAY BYTES".as_slice()
        },
    )
    .unwrap();
    if required_secret {
        std::fs::create_dir(root.join("required-secret")).unwrap();
        std::fs::write(root.join("required-secret/token"), b"always denied").unwrap();
    }
    for role in ["agent", "tool", "server"] {
        std::fs::create_dir(root.join(role)).unwrap();
        let value = if mounted {
            format!("captured-{role}")
        } else {
            format!("WRONG UNDERLAY {role}")
        };
        std::fs::write(root.join(role).join("value"), value).unwrap();
    }
}

fn normal_box_roles(expect_failure: bool) {
    mount_tmpfs(Path::new("/mnt"));
    let _mount = PrivateMount;
    // SAFETY: propagation is confined to this test's private tmpfs and mount namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/mnt".as_ptr(),
                std::ptr::null(),
                libc::MS_SHARED,
                std::ptr::null(),
            )
        },
        0
    );
    let root = Path::new(ROOTS[0]);
    let output = Path::new(OUTPUT);
    std::fs::create_dir(root).unwrap();
    mount_tmpfs(root);
    populate_role_storage(root, false, true);
    std::fs::write(
        root.join("underlay-marker"),
        b"never expose role placeholders",
    )
    .unwrap();
    std::fs::create_dir(output).unwrap();
    for role in ["agent", "tool", "server"] {
        std::fs::create_dir(output.join(role)).unwrap();
    }
    let home = tempfile::Builder::new()
        .prefix("br")
        .tempdir_in("/var/tmp")
        .unwrap();
    let state = home.path().join("state");
    let bin = home.path().join("bin");
    let backing = home.path().join("backing");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&bin).unwrap();
    populate_role_storage(&backing, true, !expect_failure);
    for role in ["agent", "tool", "server"] {
        let executable = bin.join(format!("storage-{role}"));
        std::fs::copy(env!("CARGO_BIN_EXE_box-storage-probe"), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let quoted = |value: &Path| toml::Value::String(value.display().to_string()).to_string();
    let filesystem = |role: &str| {
        let others: Vec<_> = ["agent", "tool", "server"]
            .into_iter()
            .filter(|other| *other != role)
            .map(|other| quoted(&root.join(other)))
            .chain(std::iter::once(quoted(&root.join("required-secret"))))
            .collect();
        format!(
            "mounts = [{}]\nread = [\"/mnt\"]\nwrite = [{}, {}]\ndeny = [{}]\n",
            quoted(root),
            quoted(&root.join(role)),
            quoted(&output.join(role)),
            others.join(", ")
        )
    };
    let config = home.path().join("box.toml");
    std::fs::write(
        home.path().join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "name = \"storage-roles\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\n\
         [experimental-features]\nlinux-storage-mounts = true\n\n\
         [agent]\ncommand = [{}, \"{}\", {}, {}]\nworkspace = {}\n\
         [agent.filesystem]\n{}\n\
         [tool.storage_probe]\ncommand = [\"storage-tool\"]\n\
         [tool.storage_probe.filesystem]\n{}\n\
         [mcp.storage_probe]\ntype = \"stdio\"\ncommand = [\"storage-server\", \"{}\", {}, {}]\n\
         [mcp.storage_probe.filesystem]\n{}",
            quoted(&state),
            quoted(&bin.join("storage-agent")),
            if expect_failure {
                "role-agent-failure"
            } else {
                "role-agent"
            },
            quoted(output),
            quoted(root),
            quoted(output),
            filesystem("agent"),
            filesystem("tool"),
            if expect_failure {
                "role-server-failure"
            } else {
                "role-server"
            },
            quoted(output),
            quoted(root),
            filesystem("server"),
        ),
    )
    .unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let mut workload = Process::start(
        Command::new(env!("CARGO_BIN_EXE_strands-box"))
            .args(["run", "--config"])
            .arg(&config)
            .env("HOME", home.path())
            .env("PATH", path)
            .current_dir(output),
    );
    let mut pending = std::collections::BTreeMap::new();
    let mut incarnations = BTreeSet::new();
    for role in ["agent", "tool", "server"] {
        let marker = output.join(role).join("pending");
        wait_marker(&marker, &mut workload);
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
        assert_eq!(receipt["role"], role);
        assert!(receipt["pending_checks"].as_u64().unwrap() >= 3);
        assert_role_caps(&receipt);
        assert!(
            incarnations.insert(receipt["incarnation"].as_str().unwrap().to_string()),
            "each role must retain a distinct process incarnation"
        );
        pending.insert(role, receipt);
    }
    wait_marker(&output.join("agent/all-live"), &mut workload);
    let live: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("agent/all-live")).unwrap()).unwrap();
    assert_eq!(live["mcp_initialized"], true);
    assert_eq!(live["mcp_listed"], true);
    assert_eq!(live["tool_running"], true);
    for role in ["agent", "tool", "server"] {
        assert_eq!(live[role], pending[role]["incarnation"]);
        if expect_failure {
            wait_marker(&output.join(role).join("active"), &mut workload);
            let active: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output.join(role).join("active")).unwrap())
                    .unwrap();
            assert_eq!(active["incarnation"], pending[role]["incarnation"]);
            assert!(active["checks"].as_u64().unwrap() >= 3);
            assert_role_caps(&active);
        }
    }
    wait_marker(&output.join("server/monitoring"), &mut workload);
    let monitoring: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("server/monitoring")).unwrap()).unwrap();
    assert_eq!(monitoring["incarnation"], pending["server"]["incarnation"]);
    assert!(monitoring["checks"].as_u64().unwrap() >= 3);
    workload.require_running("after every actual role proved pending storage inaccessible");
    assert_shared_source_workers(1);
    let before_mount_processes = descendants(workload.child.id());
    let mut source = start_fuse(&backing, root, b"captured-roles");
    // Each denied operation has a direct, positive provider control outside Box.
    for role in ["agent", "tool", "server"] {
        assert_eq!(
            std::fs::read(root.join(role).join("value")).unwrap(),
            format!("captured-{role}").as_bytes()
        );
        std::fs::write(
            root.join(role).join("outside-positive"),
            b"provider permits writes",
        )
        .unwrap();
        assert_eq!(
            std::fs::read(root.join(role).join("outside-positive")).unwrap(),
            b"provider permits writes"
        );
    }
    if expect_failure {
        let before_failure_wait = fixture_unix_millis();
        for receipt in pending.values() {
            assert!(
                receipt["fixture_deadline_unix_ms"].as_u64().unwrap()
                    > before_failure_wait + 15_000,
                "fixture startup consumed the deadline needed to distinguish Box shutdown from probe expiry"
            );
        }
        let during_failure_processes = descendants(workload.child.id());
        let status = workload.expect_failure();
        require_exited(&before_mount_processes);
        require_exited(&during_failure_processes);
        let stopped_at = fixture_unix_millis();
        for receipt in pending.values() {
            assert!(
                stopped_at < receipt["fixture_deadline_unix_ms"].as_u64().unwrap(),
                "Box must stop every role before its own fixture deadline"
            );
        }
        let stderr = tail(&mut workload.stderr);
        let missing = root.join("required-secret");
        let reason = format!(
            "filesystem entry {:?} is refused: {} does not exist yet, and the Linux namespace backend cannot refuse a path that is not there; create it first, or deny an existing directory above it",
            missing.display().to_string(),
            missing.display(),
        );
        assert!(
            stderr.contains("storage admission:")
                && stderr.contains("captured filesystem compilation failed:")
                && ["agent", "tool.storage_probe", "mcp.storage_probe"]
                    .iter()
                    .any(|table| stderr.contains(&format!("`[{table}]` {reason}"))),
            "a retained original role rule must cause the whole-Box failure: {stderr}"
        );
        assert!(!output.join("agent/all-passed").exists());
        assert!(!output.join("finish").exists());
        for role in ["agent", "tool", "server"] {
            assert!(
                !output.join(role).join("unexpected-publication").exists(),
                "{role} sampled readable storage during failed admission"
            );
            assert!(!output.join(role).join("passed").exists());
            assert!(
                !backing.join(role).join("created").exists(),
                "{role} wrote through a failed admission"
            );
            assert_eq!(
                std::fs::read(backing.join(role).join("value")).unwrap(),
                format!("captured-{role}").as_bytes()
            );
            for other in ["agent", "tool", "server"] {
                assert!(
                    !backing
                        .join(role)
                        .join(format!("pending-by-{other}"))
                        .exists()
                );
                assert!(
                    !backing
                        .join(role)
                        .join(format!("denied-from-{other}"))
                        .exists()
                );
            }
        }
        let root_c = CString::new(root.as_os_str().as_bytes()).unwrap();
        // SAFETY: all observed Box processes exited; detach only this fixture's FUSE source.
        assert_eq!(
            unsafe { libc::umount2(root_c.as_ptr(), libc::MNT_DETACH) },
            0
        );
        source.finish();
        assert_role_underlay(root);
        eprintln!(
            "normal Box all-role storage compilation failure: {status}; before_mount_processes_exited={}; during_failure_processes_exited={}; live={live}; exact_rule_error={reason}",
            before_mount_processes.len(),
            during_failure_processes.len()
        );
        return;
    }
    storage_diagnostics(
        "source-attached",
        &output.join("agent/all-passed"),
        workload.child.id(),
    );
    wait_marker(&output.join("agent/all-passed"), &mut workload);
    let combined: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("agent/all-passed")).unwrap()).unwrap();
    assert_eq!(combined["status"], "passed");
    for role in ["agent", "tool", "server"] {
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join(role).join("passed")).unwrap())
                .unwrap();
        assert_eq!(
            receipt, combined[role],
            "the actual {role} receipt must match the agent's aggregate"
        );
        assert_eq!(receipt["role"], role);
        assert_eq!(
            receipt["incarnation"], pending[role]["incarnation"],
            "{role} must stay alive across attachment"
        );
        assert_eq!(receipt["read"], true);
        assert_eq!(receipt["write"], true);
        assert_role_caps(&receipt);
        if role == "server" {
            assert!(
                receipt["background_checks"].as_u64().unwrap()
                    > monitoring["checks"].as_u64().unwrap()
            );
        }
        assert_eq!(
            std::fs::read(backing.join(role).join("created")).unwrap(),
            format!("written-by-{role}").as_bytes()
        );
        assert_eq!(
            std::fs::read(backing.join(role).join("value")).unwrap(),
            format!("captured-{role}").as_bytes()
        );
        for other in ["agent", "tool", "server"] {
            assert!(
                !backing
                    .join(role)
                    .join(format!("pending-by-{other}"))
                    .exists()
            );
            if other != role {
                assert_eq!(receipt["denied"][other]["read"], true);
                assert_eq!(receipt["denied"][other]["write"], true);
                assert!(
                    !backing
                        .join(other)
                        .join(format!("denied-from-{role}"))
                        .exists()
                );
            }
        }
    }
    let final_processes = descendants(workload.child.id());
    std::fs::write(
        output.join("finish.pending"),
        b"all three role policies passed",
    )
    .unwrap();
    std::fs::rename(output.join("finish.pending"), output.join("finish")).unwrap();
    workload.finish();
    require_exited(&before_mount_processes);
    require_exited(&final_processes);
    let joined: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("server/monitor-joined")).unwrap())
            .unwrap();
    assert_eq!(joined["joined"], true);
    assert_eq!(joined["incarnation"], pending["server"]["incarnation"]);
    assert!(
        joined["checks"].as_u64().unwrap()
            >= combined["server"]["background_checks"].as_u64().unwrap()
    );
    let root_c = CString::new(root.as_os_str().as_bytes()).unwrap();
    // SAFETY: Box exited; only this test's original FUSE mount is detached.
    assert_eq!(
        unsafe { libc::umount2(root_c.as_ptr(), libc::MNT_DETACH) },
        0
    );
    source.finish();
    assert_role_underlay(root);
    eprintln!(
        "normal Box distinct storage roles: {combined}; before_mount_processes_exited={}; final_processes_exited={}",
        before_mount_processes.len(),
        final_processes.len()
    );
}

fn assert_role_caps(receipt: &serde_json::Value) {
    assert_eq!(
        receipt["caps"]["checked"], true,
        "role capability evidence must be available: {receipt}"
    );
    assert_eq!(receipt["caps"]["zero"], true);
    assert_eq!(receipt["caps"]["no_new_privs"], true);
}

fn assert_role_underlay(root: &Path) {
    assert_eq!(
        std::fs::read(root.join("underlay-marker")).unwrap(),
        b"never expose role placeholders"
    );
    for role in ["agent", "tool", "server"] {
        assert_eq!(
            std::fs::read(root.join(role).join("value")).unwrap(),
            format!("WRONG UNDERLAY {role}").as_bytes()
        );
        assert!(!root.join(role).join("created").exists());
        for other in ["agent", "tool", "server"] {
            assert!(!root.join(role).join(format!("pending-by-{other}")).exists());
            assert!(
                !root
                    .join(role)
                    .join(format!("denied-from-{other}"))
                    .exists()
            );
        }
    }
    assert_eq!(
        std::fs::read(root.join("required-secret/token")).unwrap(),
        b"always denied"
    );
}

fn fixture_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn already_mounted_storage_is_ready_for_the_agents_first_read_with_an_absent_second_root() {
    isolated(|| first_read_box(false, FirstReadSource::Before));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn already_mounted_storage_is_ready_for_repeated_tools_and_local_server_first_reads() {
    isolated(|| first_read_box(true, FirstReadSource::Before));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn metadata_only_storage_starts_without_exposing_contents() {
    isolated(|| {
        mount_tmpfs(Path::new("/mnt"));
        let _mount = PrivateMount;
        for root in ROOTS {
            std::fs::create_dir(root).unwrap();
            mount_tmpfs(Path::new(root));
            populate(Path::new(root), b"WRONG UNDERLAY BYTES");
        }
        std::fs::create_dir(OUTPUT).unwrap();
        let home = tempfile::Builder::new()
            .prefix("bmd")
            .tempdir_in("/var/tmp")
            .unwrap();
        let backing = home.path().join("backing");
        populate(&backing, CONTENTS[0]);
        let mut source = start_fuse(&backing, Path::new(ROOTS[0]), CONTENTS[0]);
        let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        let root = Path::new(ROOTS[0]);
        std::fs::write(root.join("public"), CONTENTS[0]).unwrap();
        assert_eq!(std::fs::read(root.join("public")).unwrap(), CONTENTS[0]);
        let created = root.join("writable/created");
        std::fs::write(&created, b"source write control").unwrap();
        assert_eq!(std::fs::read(&created).unwrap(), b"source write control");
        std::fs::rename(&created, root.join("writable/source-write-control")).unwrap();
        assert!(!created.exists());
        let metadata_root = format!("metadata = [{}]\n", quote(root));
        let metadata_child = format!("metadata = [{}]\n", quote(&root.join("secret")));
        let read = format!(
            "read = [{}]\ndeny = [{}]\n",
            quote(root),
            quote(&root.join("secret"))
        );
        for (name, grants, readable) in [
            ("none", String::new(), false),
            ("metadata-root", metadata_root.clone(), false),
            ("metadata-child", metadata_child, false),
            ("read", read.clone(), true),
            ("metadata-and-read", format!("{metadata_root}{read}"), true),
        ] {
            let state = tempfile::Builder::new()
                .prefix(name)
                .tempdir_in(home.path())
                .unwrap();
            std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let mode = if readable {
                "first-read-native"
            } else {
                "first-read-pending"
            };
            let config = home.path().join("box.toml");
            std::fs::write(
                &config,
                format!(
                    "name = \"metadata-storage\"\nbox_dir = {}\n\
                     [experimental-features]\nlinux-storage-mounts = true\n\
                     [agent]\ncommand = [{}, \"{mode}\", {}, {}]\nworkspace = {}\n\
                     [agent.filesystem]\nmounts = [{}, {}]\n{grants}",
                    quote(state.path()),
                    quote(Path::new(env!("CARGO_BIN_EXE_box-storage-probe"))),
                    quote(root),
                    quote(Path::new(ROOTS[1])),
                    quote(Path::new(OUTPUT)),
                    quote(root),
                    quote(Path::new(ROOTS[1])),
                ),
            )
            .unwrap();
            let mut workload = Process::start(
                Command::new(env!("CARGO_BIN_EXE_strands-box"))
                    .args(["run", "--config"])
                    .arg(&config)
                    .env("HOME", home.path())
                    .current_dir(OUTPUT),
            );
            workload.finish();
            let receipt = tail(&mut workload.stdout);
            assert!(
                receipt.contains(if readable {
                    "native-first-read-passed"
                } else {
                    "pending-first-read-passed"
                }),
                "{name}: {receipt}"
            );
            source.require_running("after metadata storage checks");
            assert_eq!(std::fs::read(root.join("public")).unwrap(), CONTENTS[0]);
            assert_eq!(
                std::fs::read(root.join("secret/token")).unwrap(),
                b"DENIED SOURCE BYTES"
            );
            assert!(!root.join("writable/created").exists());
        }
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirstReadSource {
    Before,
    After,
    Covered,
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn storage_hidden_before_startup_does_not_delay_launch_or_expose_underlay() {
    isolated(|| first_read_box(false, FirstReadSource::Covered));
}

fn first_read_box(leaves: bool, timing: FirstReadSource) {
    let after_start = timing == FirstReadSource::After;
    mount_tmpfs(Path::new("/mnt"));
    let _mount = PrivateMount;
    // SAFETY: only the fixture's private mount participates in propagation.
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/mnt".as_ptr(),
                std::ptr::null(),
                libc::MS_SHARED,
                std::ptr::null(),
            )
        },
        0
    );
    for root in ROOTS {
        std::fs::create_dir(root).unwrap();
        mount_tmpfs(Path::new(root));
        populate(Path::new(root), b"WRONG UNDERLAY BYTES");
    }
    std::fs::create_dir(OUTPUT).unwrap();
    let home = tempfile::Builder::new()
        .prefix("bfr")
        .tempdir_in("/var/tmp")
        .unwrap();
    let state = home.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let backing = home.path().join("backing");
    populate(&backing, CONTENTS[0]);
    let mut source = if after_start {
        None
    } else {
        Some(start_fuse(&backing, Path::new(ROOTS[0]), CONTENTS[0]))
    };
    if timing == FirstReadSource::Covered {
        mount_tmpfs(Path::new(ROOTS[0]));
        populate(Path::new(ROOTS[0]), b"WRONG COVER BYTES");
    }
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    for name in ["storage-agent", "storage-tool", "storage-server"] {
        std::fs::copy(env!("CARGO_BIN_EXE_box-storage-probe"), bin.join(name)).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let roots = format!(
        "{}, {}",
        quote(Path::new(ROOTS[0])),
        quote(Path::new(ROOTS[1]))
    );
    let filesystem = format!(
        "mounts = [{roots}]\nread = [{roots}]\ndeny = [{}]\n",
        quote(&Path::new(ROOTS[0]).join("secret"))
    );
    let mode = if timing == FirstReadSource::Covered {
        "first-read-pending"
    } else if after_start {
        "first-read-wait"
    } else if leaves {
        "first-read-client"
    } else {
        "first-read-native"
    };
    let mut config = format!(
        "name = \"storage-first-read\"\nbox_dir = {}\npolicy = \"policy.dw\"\n[experimental-features]\nlinux-storage-mounts = true\n[agent]\ncommand = [{}, \"{mode}\", {roots}]\nworkspace = {}\n",
        quote(&state),
        quote(&bin.join("storage-agent")),
        quote(Path::new(OUTPUT))
    );
    if after_start {
        config.push_str(&format!(
            "[agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
            quote(Path::new(OUTPUT)),
            quote(Path::new(OUTPUT))
        ));
    }
    if leaves {
        config.push_str(&format!("[tool.first_read]\ncommand = [\"storage-tool\"]\n[tool.first_read.filesystem]\n{filesystem}\n[mcp.first_read]\ntype = \"stdio\"\ncommand = [\"storage-server\", \"first-read-server\", {roots}]\n[mcp.first_read.filesystem]\n{filesystem}"));
    } else {
        config.push_str(&format!("[agent.filesystem]\n{filesystem}"));
    }
    std::fs::write(home.path().join("box.toml"), config).unwrap();
    std::fs::write(
        home.path().join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let mut workload = Process::start(
        Command::new(env!("CARGO_BIN_EXE_strands-box"))
            .args(["run", "--config"])
            .arg(home.path().join("box.toml"))
            .env("HOME", home.path())
            .env("PATH", path)
            .current_dir(OUTPUT),
    );
    if after_start {
        wait_marker(&Path::new(OUTPUT).join("waiting-to-launch"), &mut workload);
        source = Some(start_fuse(&backing, Path::new(ROOTS[0]), CONTENTS[0]));
        assert_shared_source_workers(2);
        std::fs::write(Path::new(OUTPUT).join("launch-now"), b"source attached").unwrap();
    }
    workload.finish();
    let receipt = tail(&mut workload.stdout);
    assert!(
        receipt.contains(if timing == FirstReadSource::Covered {
            "pending-first-read-passed"
        } else if leaves {
            "three-tool-and-server-first-reads-passed"
        } else {
            "native-first-read-passed"
        }),
        "{receipt}"
    );
    source
        .as_mut()
        .unwrap()
        .require_running("after first-read checks");
    assert_eq!(
        std::fs::read(Path::new(ROOTS[0]).join("public")).unwrap(),
        if timing == FirstReadSource::Covered {
            b"WRONG COVER BYTES"
        } else {
            CONTENTS[0]
        }
    );
    assert_eq!(
        std::fs::read(Path::new(ROOTS[1]).join("public")).unwrap(),
        b"WRONG UNDERLAY BYTES"
    );
}

fn assert_shared_source_workers(expected_roots: usize) {
    let mut source_processes = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if !command
            .split(|byte| *byte == 0)
            .any(|argument| argument == b"--source-control-fd")
        {
            continue;
        }
        let status = std::fs::read_to_string(entry.path().join("status")).unwrap();
        let parent = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        source_processes.insert(pid, parent);
    }
    let owners: Vec<_> = source_processes
        .iter()
        .filter(|(_, parent)| !source_processes.contains_key(parent))
        .map(|(pid, _)| *pid)
        .collect();
    assert_eq!(
        owners.len(),
        1,
        "all three recipients must share one source helper: {source_processes:?}"
    );
    assert_eq!(
        source_processes.len(),
        1 + expected_roots,
        "source acquisition count must depend on distinct roots, not recipient count"
    );
    assert!(
        source_processes
            .iter()
            .filter(|(pid, _)| **pid != owners[0])
            .all(|(_, parent)| *parent == owners[0])
    );
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE and native Linux user/mount/FUSE support"]
fn storage_arriving_before_later_tool_launches_is_ready_without_retries() {
    isolated(|| first_read_box(true, FirstReadSource::After));
}

/// The root-mapped FUSE fixture does not reproduce proc ownership during an ordinary user's setup.
#[test]
fn nonroot_host_starts_storage_with_pending_sources_without_an_outer_user_namespace() {
    // SAFETY: geteuid only reads this test process's effective user identity.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: ordinary non-root host startup requires a nonzero effective UID");
        return;
    }
    let home = tempfile::Builder::new()
        .prefix("bsu")
        .tempdir_in("/var/tmp")
        .unwrap();
    let state = home.path().join("state");
    let workspace = home.path().join("workspace");
    let roots = [home.path().join("first"), home.path().join("second")];
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&workspace).unwrap();
    for root in &roots {
        populate(root, b"visible to the uncontained caller");
        assert_eq!(
            std::fs::read(root.join("public")).unwrap(),
            b"visible to the uncontained caller"
        );
    }
    let program = home.path().join("storage-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_box-storage-probe"), &program).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let config = format!(
        "name = \"storage-nonroot\"\nbox_dir = {}\npolicy = \"policy.dw\"\n[experimental-features]\nlinux-storage-mounts = true\n[agent]\ncommand = [{}, \"first-read-pending\", {}, {}]\nworkspace = {}\n[agent.filesystem]\nmounts = [{}, {}]\nread = [{}, {}]\n",
        quote(&state),
        quote(&program),
        quote(&roots[0]),
        quote(&roots[1]),
        quote(&workspace),
        quote(&roots[0]),
        quote(&roots[1]),
        quote(&roots[0]),
        quote(&roots[1])
    );
    std::fs::write(home.path().join("box.toml"), config).unwrap();
    std::fs::write(
        home.path().join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    let mut workload = Process::start(
        Command::new(env!("CARGO_BIN_EXE_strands-box"))
            .args(["run", "--config"])
            .arg(home.path().join("box.toml"))
            .env("HOME", home.path())
            .current_dir(&workspace),
    );
    workload.finish();
    assert!(tail(&mut workload.stdout).contains("pending-first-read-passed"));
}
