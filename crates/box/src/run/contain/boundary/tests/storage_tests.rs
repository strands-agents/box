//! Authored Box rules compiled against captured storage and published through the real helper.

use super::*;
use containment::test_support::storage;
use std::ffi::CString;
use std::io::SeekFrom;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ROOT: &str = "/mnt/box-storage";
const OUTPUT: &str = "/mnt/box-output";
const FUSE_BINARY: &str = "BOX_STORAGE_TEST_FUSE";
const CAPTURED: &[u8] = b"captured source";

#[derive(Clone, Copy)]
enum Arrival {
    BeforeLauncher,
    AfterLauncher,
    UnsupportedTmpfs,
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE pointing to the foreground FUSE fixture"]
fn authored_rules_protect_storage_mounted_before_the_launcher() {
    isolated(|| combined(Arrival::BeforeLauncher));
}

#[test]
#[ignore = "requires BOX_STORAGE_TEST_FUSE pointing to the foreground FUSE fixture"]
fn authored_rules_protect_storage_mounted_after_workload_startup() {
    isolated(|| combined(Arrival::AfterLauncher));
}

#[test]
fn authored_rules_keep_unclassified_tmpfs_storage_pending() {
    isolated(|| combined(Arrival::UnsupportedTmpfs));
}

fn namespace_command() -> Command {
    let mut command = Command::new("unshare");
    command.env("LC_ALL", "C").args([
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
    ]);
    command
}

fn isolated(body: impl FnOnce()) {
    const CHILD: &str = "BOX_COMBINED_STORAGE_CHILD";
    let thread = std::thread::current();
    let name = thread.name().expect("a named unit test");
    if std::env::var(CHILD).as_deref() == Ok(name) {
        body();
        return;
    }
    let prerequisite = namespace_command().arg("/bin/true").output().unwrap();
    if !prerequisite.status.success() {
        let stderr = String::from_utf8_lossy(&prerequisite.stderr);
        assert!(
            prerequisite.status.code() == Some(1)
                && prerequisite.stdout.is_empty()
                && matches!(
                    stderr.trim(),
                    "unshare: unshare failed: Operation not permitted"
                        | "unshare: write failed /proc/self/uid_map: Operation not permitted"
                        | "unshare: write failed /proc/self/gid_map: Operation not permitted"
                ),
            "unexpected namespace prerequisite failure: {prerequisite:?}"
        );
        eprintln!(
            "skipping: combined storage namespace prerequisite denied: {}",
            stderr.trim()
        );
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    let mut child = namespace_command()
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
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            // SAFETY: this test owns the isolated command's process group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            let status = child.wait().unwrap();
            panic!(
                "combined storage test timed out: {status}; stdout: {}; stderr: {}",
                captured_tail(&mut stdout),
                captured_tail(&mut stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().unwrap();
    let stdout = captured_tail(&mut stdout);
    let stderr = captured_tail(&mut stderr);
    assert!(
        status.success(),
        "{status}; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stdout.contains("1 passed; 0 failed; 0 ignored"),
        "the selected combined test must actually run: stdout: {stdout}; stderr: {stderr}"
    );
    eprintln!("{stderr}");
}

fn captured_tail(file: &mut std::fs::File) -> String {
    const LIMIT: u64 = 128 * 1024;
    let length = file.metadata().unwrap().len();
    file.seek(SeekFrom::Start(length.saturating_sub(LIMIT)))
        .unwrap();
    let mut bytes = Vec::new();
    file.take(LIMIT).read_to_end(&mut bytes).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    if length > LIMIT {
        format!("[last {LIMIT} bytes]\n{text}")
    } else {
        text.into_owned()
    }
}

struct MountFixture;
impl Drop for MountFixture {
    fn drop(&mut self) {
        // SAFETY: /mnt is replaced only inside this test's fresh mount namespace.
        unsafe { libc::umount2(c"/mnt".as_ptr(), libc::MNT_DETACH) };
    }
}

struct FuseProcess(Child);
impl FuseProcess {
    fn finish(mut self) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "FUSE fixture exit after unmount: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "FUSE fixture did not exit after unmount"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for FuseProcess {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Launcher(libc::pid_t);
impl Launcher {
    fn wait(mut self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut status = 0;
            // SAFETY: this guard owns this child and waits for it exactly once.
            let result = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
            assert!(
                result >= 0,
                "wait launcher: {}",
                std::io::Error::last_os_error()
            );
            if result == self.0 {
                self.0 = 0;
                assert!(libc::WIFEXITED(status), "launcher status {status}");
                assert_eq!(libc::WEXITSTATUS(status), 0, "launcher status {status}");
                break;
            }
            assert!(Instant::now() < deadline, "launcher did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Launcher {
    fn drop(&mut self) {
        if self.0 > 0 {
            // SAFETY: killing the owned supervisor triggers its existing child lifetime chain.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn mount_tmpfs(path: &Path) {
    let target = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: each target belongs to the fresh test mount namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755,size=8m".as_ptr().cast(),
            )
        },
        0,
        "mount tmpfs: {}",
        std::io::Error::last_os_error()
    );
}

fn populate(root: &Path, public: &[u8]) {
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::create_dir_all(root.join("writable/frozen")).unwrap();
    std::fs::write(root.join("public"), public).unwrap();
    std::fs::set_permissions(root.join("public"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(root.join("secret/token"), b"DENIED SOURCE BYTES").unwrap();
    std::fs::write(
        root.join("writable/frozen/existing"),
        b"readable but immutable",
    )
    .unwrap();
}

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !path.exists() {
        assert!(Instant::now() < deadline, "waiting for {}", path.display());
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn start_fuse(backing: &Path, root: &Path) -> FuseProcess {
    let binary = std::env::var_os(FUSE_BINARY).expect(
        "set BOX_STORAGE_TEST_FUSE to the foreground FUSE fixture before running this ignored test",
    );
    let mut process = FuseProcess(
        Command::new(binary)
            .arg(backing)
            .arg(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the real FUSE fixture"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::read(root.join("public")).is_ok_and(|bytes| bytes == CAPTURED) {
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "FUSE fixture exited before mounting"
        );
        assert!(Instant::now() < deadline, "real FUSE source did not appear");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| {
                line.split_whitespace().nth(4) == root.to_str()
                    && line.split_once(" - ").is_some_and(|(_, fields)| {
                        fields
                            .split_whitespace()
                            .next()
                            .is_some_and(|kind| kind.starts_with("fuse."))
                    })
            }),
        "the external fixture must actually mount FUSE"
    );
    process
}

fn compile(fixture: &Fixture, spec: &ProcessSpec, approved: &DirectReach) -> Boundary {
    let commands = crate::run::commands::ConfiguredCommands::load(&fixture.record).unwrap();
    commands.validate_reach("[agent]", approved).unwrap();
    crate::test_support::with_operator_home(&fixture.home, || {
        Boundary::translate(
            spec,
            Launch {
                table: "[agent]",
                trailing: &[],
                fallback_workspace: &fixture.path("project"),
                shebang_interpreters: ShebangInterpreters::Granted,
                runtime_reach: RuntimeReach::Agent,
                argument_zero: None,
                egress: EgressMode::Native,
                approved: Some(approved),
            },
            &Site {
                attachment: &fixture.attachment,
                layout: &fixture.root,
                stored: &fixture.record,
                protected_sources: &[],
            },
        )
    })
    .unwrap()
}

fn inspect_at_original_root(observed: OwnedFd, root: &Path) -> std::fs::File {
    let original_namespace = std::fs::File::open("/proc/self/ns/mnt").unwrap();
    // SAFETY: this controller is an isolated test process, separate from the live workload and helper.
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    let target = CString::new(root.as_os_str().as_bytes()).unwrap();
    // SAFETY: observation is an independent detached clone; the helper retains its own tree.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                observed.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::MOVE_MOUNT_F_EMPTY_PATH,
            )
        },
        0,
        "attach inspection clone: {}",
        std::io::Error::last_os_error()
    );
    original_namespace
}

fn release_source(original_namespace: std::fs::File, root: &Path) {
    let target = CString::new(root.as_os_str().as_bytes()).unwrap();
    // SAFETY: remove this controller's inspection clone before leaving its private mount view.
    assert_eq!(
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) },
        0
    );
    // SAFETY: the saved namespace belongs to this controller's user namespace.
    assert_eq!(
        unsafe { libc::setns(original_namespace.as_raw_fd(), libc::CLONE_NEWNS) },
        0
    );
    // SAFETY: remove the deliberate ambient tmpfs replacement, then the test's original FUSE mount.
    assert_eq!(
        unsafe { libc::umount2(target.as_ptr(), 0) },
        0,
        "unmount ambient replacement: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        unsafe { libc::umount2(target.as_ptr(), 0) },
        0,
        "unmount FUSE source: {}",
        std::io::Error::last_os_error()
    );
}

fn exec_errno(path: &Path) -> i32 {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let arguments = [path.as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null()];
    // SAFETY: this fixture contains text without a shebang and cannot replace the calling process.
    assert_eq!(
        unsafe { libc::execve(path.as_ptr(), arguments.as_ptr(), environment.as_ptr()) },
        -1
    );
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn workload(expect_admission: bool) {
    let root = Path::new(ROOT);
    let output = Path::new(OUTPUT);
    assert!(
        std::fs::read(root.join("public")).is_err(),
        "pending public bytes were exposed"
    );
    assert!(
        std::fs::read_dir(root).unwrap().next().is_none(),
        "pending names were exposed"
    );
    std::fs::write(output.join("started"), b"contained workload started").unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut checks = 0;
    loop {
        assert!(Instant::now() < deadline, "workload waited too long");
        assert!(
            std::fs::read(root.join("secret/token")).is_err(),
            "denied bytes reached workload"
        );
        assert!(
            std::fs::read(root.join("underlay-marker")).is_err(),
            "underlay bytes reached workload"
        );
        checks += 1;
        if checks == 3 {
            std::fs::write(output.join("probing"), b"background deny checks running").unwrap();
        }
        if let Ok(bytes) = std::fs::read(root.join("public")) {
            assert!(expect_admission, "unsupported storage was published");
            assert_eq!(bytes, CAPTURED, "ambient replacement was published");
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(root.join("public"))
                    .is_err()
            );
            std::fs::write(root.join("writable/created"), b"allowed write").unwrap();
            assert_eq!(
                std::fs::read(root.join("writable/created")).unwrap(),
                b"allowed write"
            );
            assert_eq!(
                std::fs::read(root.join("writable/frozen/existing")).unwrap(),
                b"readable but immutable"
            );
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(root.join("writable/frozen/existing"))
                    .is_err()
            );
            assert!(std::fs::write(root.join("writable/frozen/new"), b"blocked").is_err());
            assert_eq!(exec_errno(&root.join("public")), libc::EACCES);
            std::fs::write(output.join("passed"), checks.to_string()).unwrap();
            wait_file(&output.join("controller-finished"));
            break;
        }
        if !expect_admission && output.join("controller-finished").exists() {
            std::fs::write(output.join("passed"), checks.to_string()).unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn combined(arrival: Arrival) {
    mount_tmpfs(Path::new("/mnt"));
    let _mount = MountFixture;
    // SAFETY: sharing is confined to the newly mounted test tmpfs.
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
    let root = PathBuf::from(ROOT);
    let output = PathBuf::from(OUTPUT);
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&output).unwrap();
    populate(&root, b"UNDERLAY MUST STAY HIDDEN");
    std::fs::write(root.join("underlay-marker"), b"private placeholder bytes").unwrap();
    let mut fixture = Fixture::new();
    fixture.record.mcp.clear();
    for alias in fixture.root.all_aliases(&fixture.record.mcp) {
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::copy("/bin/true", alias).unwrap();
    }
    let mut spec = fixture.spec();
    spec.command = vec!["/bin/sh".into()];
    spec.env.clear();
    spec.filesystem = Filesystem {
        read: vec![PathBuf::from("/mnt")],
        write: vec![root.join("writable"), output.clone()],
        deny: vec![root.join("secret")],
        deny_write: vec![root.join("writable/frozen")],
        ..Filesystem::default()
    };
    fixture.record.agent = Some(spec.clone());
    let original = spec.filesystem.clone();
    let context = FilesystemContext {
        upstream_trust: Vec::new(),
        table: "[agent]",
        operator_home: &fixture.home,
        policy: None,
        authority_directories: Vec::new(),
        program_search_directories: Vec::new(),
        source_paths: &[],
    };
    let pending =
        match filesystem::FilesystemPlan::new(&original, std::slice::from_ref(&root), &context)
            .unwrap()
            .judge_current_view(&[], &context)
            .unwrap()
        {
            filesystem::FilesystemCompilation::Pending(pending) => pending,
            filesystem::FilesystemCompilation::Complete(_) => {
                panic!("placeholder incorrectly admitted storage")
            }
        };
    assert_eq!(pending.original(), &original);
    assert_eq!(pending.roots(), std::slice::from_ref(&root));
    let initial = compile(&fixture, &spec, pending.available_for_test());
    let backing = tempfile::tempdir().unwrap();
    populate(backing.path(), CAPTURED);
    let mut fuse = if matches!(arrival, Arrival::BeforeLauncher) {
        Some(start_fuse(backing.path(), &root))
    } else {
        None
    };
    let (controller, helper) = UnixStream::pair().unwrap();
    controller
        .set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    controller
        .set_write_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    // SAFETY: only the fresh isolated test process forks; this child exits after the real backend returns.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        drop(controller);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if matches!(arrival, Arrival::BeforeLauncher) {
                storage::apply(&initial._containment, root.clone(), helper).unwrap();
            } else {
                storage::apply_observing_pending(&initial._containment, root.clone(), helper)
                    .unwrap();
            }
            workload(!matches!(arrival, Arrival::UnsupportedTmpfs));
        }));
        // SAFETY: a contained workload must never return into the test harness or drop host fixtures.
        unsafe { libc::_exit(if outcome.is_ok() { 0 } else { 91 }) };
    }
    let launcher = Launcher(child);
    drop(helper);
    wait_file(&output.join("started"));
    wait_file(&output.join("probing"));
    if !matches!(arrival, Arrival::BeforeLauncher) {
        let pending_receipt: serde_json::Value =
            serde_json::from_str(&storage::receive_receipt(&controller).unwrap()).unwrap();
        assert_eq!(pending_receipt["status"], "pending", "{pending_receipt}");
    }
    if matches!(arrival, Arrival::UnsupportedTmpfs) {
        mount_tmpfs(&root);
        populate(&root, b"UNCLASSIFIED TMPFS");
        controller
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut byte = [0];
        let error = (&controller)
            .read(&mut byte)
            .expect_err("unclassified tmpfs produced a helper frame");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        std::fs::write(output.join("controller-finished"), b"still pending").unwrap();
        wait_file(&output.join("passed"));
        launcher.wait();
        return;
    }
    if matches!(arrival, Arrival::AfterLauncher) {
        fuse = Some(start_fuse(backing.path(), &root));
    }
    let observed = storage::receive_observation(&controller).unwrap();
    mount_tmpfs(&root);
    populate(&root, b"WRONG AMBIENT REPLACEMENT");
    assert_eq!(
        std::fs::read(root.join("public")).unwrap(),
        b"WRONG AMBIENT REPLACEMENT"
    );
    let original_namespace = inspect_at_original_root(observed, &root);
    assert_eq!(std::fs::read(root.join("public")).unwrap(), CAPTURED);
    assert_eq!(
        std::fs::read(root.join("secret/token")).unwrap(),
        b"DENIED SOURCE BYTES"
    );
    assert_eq!(
        exec_errno(&root.join("public")),
        libc::ENOEXEC,
        "source must allow direct execution before Box adds noexec"
    );
    let admitted = match pending
        .judge_current_view(std::slice::from_ref(&root), &context)
        .unwrap()
    {
        filesystem::FilesystemCompilation::Complete(reach) => reach,
        filesystem::FilesystemCompilation::Pending(_) => {
            panic!("observed declared source remained pending")
        }
    };
    assert_eq!(
        spec.filesystem, original,
        "authored rules changed during admission"
    );
    let compiled = compile(&fixture, &spec, &admitted);
    storage::send_config(&controller, &compiled.containment_config_text()).unwrap();
    let receipt: serde_json::Value =
        serde_json::from_str(&storage::receive_receipt(&controller).unwrap()).unwrap();
    assert_eq!(receipt["status"], "published", "{receipt}");
    assert_eq!(receipt["capture_mode"], "automatic", "{receipt}");
    assert_eq!(receipt["source_filesystem"], "fuse.boxfixture", "{receipt}");
    if matches!(arrival, Arrival::AfterLauncher) {
        assert!(
            receipt["pending_observations"].as_u64().unwrap() >= 1,
            "{receipt}"
        );
        assert!(
            receipt["notification_wakeups"].as_u64().unwrap() >= 1,
            "{receipt}"
        );
    }
    wait_file(&output.join("passed"));
    assert!(
        std::fs::read_to_string(output.join("passed"))
            .unwrap()
            .parse::<usize>()
            .unwrap()
            >= 3
    );
    assert_eq!(
        std::fs::read(backing.path().join("writable/created")).unwrap(),
        b"allowed write"
    );
    assert_eq!(
        std::fs::read(root.join("writable/frozen/existing")).unwrap(),
        b"readable but immutable"
    );
    std::fs::write(output.join("controller-finished"), b"publication verified").unwrap();
    launcher.wait();
    eprintln!("combined authored-rule storage receipt: {receipt}");
    drop(compiled);
    drop(initial);
    release_source(original_namespace, &root);
    fuse.take().unwrap().finish();
}
