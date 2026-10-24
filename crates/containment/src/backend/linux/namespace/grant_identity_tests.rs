//! Mounted grant identity regressions.

use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use super::{NamespaceBackend, enter_namespaces, view};
use crate::backend::ContainmentBackend as _;
use crate::{ContainmentConfig, Operation, Scope};

const GRANTED: &[u8] = b"synthetic granted bytes";
const UNGRANTED: &[u8] = b"synthetic replacement bytes";
const LEAKED: i32 = 7;
const STARTED: i32 = 0;
const REFUSED: i32 = 21;
const OTHER: i32 = 22;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Directory,
    File,
    Socket,
}

struct Fixture {
    _root: tempfile::TempDir,
    grant: PathBuf,
    replacement: PathBuf,
    held: PathBuf,
    _listeners: Vec<UnixListener>,
    kind: Kind,
    socket_identity: Option<crate::model::ObjectIdentity>,
    replacement_identity: Option<crate::model::ObjectIdentity>,
}

impl Fixture {
    fn new(kind: Kind) -> Self {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("project");
        std::fs::create_dir(&parent).unwrap();
        let grant = parent.join("vendor");
        let replacement = root.path().join("replacement");
        let mut listeners = Vec::new();
        for (path, bytes) in [(&grant, GRANTED), (&replacement, UNGRANTED)] {
            match kind {
                Kind::Directory => {
                    std::fs::create_dir(path).unwrap();
                    std::fs::write(path.join("value"), bytes).unwrap();
                }
                Kind::File => std::fs::write(path, bytes).unwrap(),
                Kind::Socket => listeners.push(UnixListener::bind(path).unwrap()),
            }
        }
        let identity = |path: &PathBuf| {
            matches!(kind, Kind::Socket)
                .then(|| crate::model::ObjectIdentity::from_metadata(&path.metadata().unwrap()))
        };
        Self {
            socket_identity: identity(&grant),
            replacement_identity: identity(&replacement),
            held: parent.join("held"),
            _root: root,
            grant,
            replacement,
            _listeners: listeners,
            kind,
        }
    }

    fn config(&self, enclosed: bool) -> ContainmentConfig {
        let (operation, scope) = match self.kind {
            Kind::Directory => (Operation::Read, Scope::Root),
            Kind::File => (Operation::Read, Scope::File),
            Kind::Socket => (Operation::Connect, Scope::File),
        };
        let config = ContainmentConfig::new()
            .allow(&self.grant, operation, scope)
            .unwrap();
        if enclosed {
            config
                .allow(self.grant.parent().unwrap(), Operation::Read, Scope::Root)
                .unwrap()
        } else {
            config
        }
    }

    fn swap(&self) {
        std::fs::rename(&self.grant, &self.held).unwrap();
        std::os::unix::fs::symlink(&self.replacement, &self.grant).unwrap();
    }

    fn inspect(&self) -> i32 {
        let (grant, replacement) = match self.kind {
            Kind::Directory => (self.grant.join("value"), self.replacement.join("value")),
            Kind::File => (self.grant.clone(), self.replacement.clone()),
            Kind::Socket => {
                let identity = std::fs::metadata(&self.grant)
                    .ok()
                    .map(|metadata| crate::model::ObjectIdentity::from_metadata(&metadata));
                return if identity == self.replacement_identity {
                    LEAKED
                } else if identity == self.socket_identity
                    && UnixStream::connect(&self.grant).is_ok()
                    && UnixStream::connect(&self.replacement).is_err()
                {
                    STARTED
                } else {
                    OTHER
                };
            }
        };
        match std::fs::read(grant) {
            Ok(bytes) if bytes == UNGRANTED => LEAKED,
            Ok(bytes) if bytes == GRANTED && std::fs::read(replacement).is_err() => STARTED,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 23,
            _ => OTHER,
        }
    }
}

fn supported() -> bool {
    let (code, report) = in_child(|| {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let prerequisites = || -> std::io::Result<()> {
            // Probe host permissions independently of the production setup path.
            // SAFETY: this isolated child exits without returning to the harness.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            std::fs::write("/proc/self/setgroups", "deny")?;
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
            // SAFETY: only this short-lived child changes namespaces.
            if unsafe {
                libc::unshare(
                    libc::CLONE_NEWNS
                        | libc::CLONE_NEWNET
                        | libc::CLONE_NEWIPC
                        | libc::CLONE_NEWUTS
                        | libc::CLONE_NEWPID,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        match prerequisites() {
            Ok(()) => STARTED,
            Err(error) => {
                eprintln!("namespace prerequisite: {error}");
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    77
                } else {
                    OTHER
                }
            }
        }
    });
    match code {
        STARTED => true,
        77 => {
            assert!(
                std::env::var_os("SBOX58_REQUIRE_RUNTIME").is_none(),
                "required Linux namespace support is unavailable: {report}"
            );
            eprintln!("skipping: Linux namespace prerequisites denied: {report}");
            false
        }
        _ => panic!("unexpected namespace prerequisite failure: {code}: {report}"),
    }
}

fn wait(child: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: the child belongs to this process and status is writable.
    assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -status
    }
}

fn in_child(action: impl FnOnce() -> i32) -> (i32, String) {
    let thread = std::thread::current();
    assert!(
        std::env::var("BOX_UNIT_SYSCALL_FAILURE_CHILD")
            .ok()
            .as_deref()
            == thread.name()
            || std::env::var_os("SBOX58_RACE_CHILD").is_some(),
        "forking grant tests must first re-execute with --test-threads=1"
    );
    let (mut reader, writer) = UnixStream::pair().unwrap();
    // SAFETY: the isolated harness runs no sibling tests; the child exits with _exit.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        drop(reader);
        // SAFETY: writer is open, and only the child replaces its stderr or exits.
        unsafe {
            if libc::dup2(writer.as_raw_fd(), 2) != 2 {
                libc::_exit(OTHER);
            }
        }
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)).unwrap_or(OTHER);
        // SAFETY: the parent owns the fixture and its cleanup.
        unsafe { libc::_exit(code) };
    }
    drop(writer);
    let mut report = String::new();
    reader.read_to_string(&mut report).unwrap();
    (wait(child), report)
}

#[test]
fn a_child_panic_is_an_error() {
    super::failure_tests::in_fresh_process(|| {
        let result = in_child(|| panic!("synthetic child failure"));
        assert_eq!(result.0, OTHER, "{result:?}");
    });
}

#[test]
fn a_child_setup_failure_is_an_error() {
    super::failure_tests::in_fresh_process(|| {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

        let filter = SeccompFilter::new(
            std::collections::BTreeMap::from([
                #[cfg(target_arch = "x86_64")]
                (libc::SYS_dup2, Vec::new()),
                (libc::SYS_dup3, Vec::new()),
            ]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EBADF as u32),
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .unwrap();
        let program: BpfProgram = filter.try_into().unwrap();
        seccompiler::apply_filter(&program).unwrap();

        let result = in_child(|| STARTED);
        assert_eq!(result.0, OTHER, "{result:?}");
    });
}

fn materialize(fixture: &Fixture, swap: bool, enclosed: bool) -> (i32, String) {
    materialize_after(fixture, enclosed, || {
        if swap {
            fixture.swap();
        }
    })
}

fn materialize_after(
    fixture: &Fixture,
    enclosed: bool,
    after_plan: impl FnOnce(),
) -> (i32, String) {
    let config = fixture.config(enclosed);
    config.require_live_path_identities().unwrap();
    let plan = view::MountView::plan(&config).unwrap();
    in_child(|| {
        after_plan();
        if let Err(error) = enter_namespaces(false) {
            let _ = writeln!(std::io::stderr(), "namespace setup: {error}");
            return OTHER;
        }
        // SAFETY: a PID namespace applies to the next child.
        if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
            return OTHER;
        }
        // SAFETY: both children terminate without returning to the harness.
        let reaper = unsafe { libc::fork() };
        if reaper < 0 {
            return OTHER;
        }
        if reaper > 0 {
            return wait(reaper);
        }
        if let Err(error) = plan.materialize() {
            let _ = writeln!(std::io::stderr(), "materialize: {error}");
            return REFUSED;
        }
        fixture.inspect()
    })
}

#[test]
fn unchanged_files_directories_and_sockets_start() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        for kind in [Kind::Directory, Kind::File, Kind::Socket] {
            let result = materialize(&Fixture::new(kind), false, false);
            assert_eq!(result.0, STARTED, "{kind:?}: {result:?}");
            let fixture = Fixture::new(kind);
            let result = apply(&fixture, &fixture.config(false));
            assert_eq!(result.0, STARTED, "real apply {kind:?}: {result:?}");
        }
    });
}

#[test]
fn swapped_files_directories_and_sockets_refuse_before_startup() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        for kind in [Kind::Directory, Kind::File, Kind::Socket] {
            let result = materialize(&Fixture::new(kind), true, false);
            println!("{kind:?}: {result:?}");
            assert_eq!(result.0, REFUSED, "{kind:?}: {result:?}");
            assert!(
                result.1.contains("mounted grant identity changed"),
                "unrelated refusal: {result:?}"
            );
        }
    });
}

#[test]
fn same_path_object_replacements_refuse_before_startup() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        for kind in [Kind::Directory, Kind::File, Kind::Socket] {
            let fixture = Fixture::new(kind);
            let result = materialize_after(&fixture, false, || {
                std::fs::rename(&fixture.grant, &fixture.held).unwrap();
                std::fs::rename(&fixture.replacement, &fixture.grant).unwrap();
            });
            assert_eq!(result.0, REFUSED, "{kind:?}: {result:?}");
            assert!(
                result.1.contains("mounted grant identity changed"),
                "{result:?}"
            );
        }
    });
}

#[test]
fn a_replacement_between_grant_creation_and_planning_is_refused() {
    for kind in [Kind::Directory, Kind::File, Kind::Socket] {
        let fixture = Fixture::new(kind);
        let config = fixture.config(false);
        std::fs::rename(&fixture.grant, &fixture.held).unwrap();
        std::fs::rename(&fixture.replacement, &fixture.grant).unwrap();
        let error = config.require_live_path_identities().unwrap_err();
        assert!(
            error.to_string().contains("object changed before apply"),
            "{error}"
        );
    }
}

#[test]
fn an_unlinked_grant_keeps_its_inode_reserved_until_the_config_drops() {
    let fixture = Fixture::new(Kind::File);
    let config = fixture.config(false);
    let identity = crate::model::ObjectIdentity::from_metadata(&fixture.grant.metadata().unwrap());
    std::fs::remove_file(&fixture.grant).unwrap();
    for _ in 0..128 {
        std::fs::write(&fixture.grant, UNGRANTED).unwrap();
        assert_ne!(
            crate::model::ObjectIdentity::from_metadata(&fixture.grant.metadata().unwrap()),
            identity,
            "the open grant must prevent inode reuse"
        );
        assert!(config.require_live_path_identities().is_err());
        std::fs::remove_file(&fixture.grant).unwrap();
    }
}

#[test]
fn a_prepared_object_stays_pinned_until_its_grant_is_applied() {
    let fixture = Fixture::new(Kind::File);
    let prepared = ContainmentConfig::prepare_filesystem_path(&fixture.grant).unwrap();
    let identity = crate::model::ObjectIdentity::from_metadata(&fixture.grant.metadata().unwrap());
    std::fs::remove_file(&fixture.grant).unwrap();
    std::fs::write(&fixture.grant, UNGRANTED).unwrap();
    assert_ne!(
        crate::model::ObjectIdentity::from_metadata(&fixture.grant.metadata().unwrap()),
        identity
    );
    let config = ContainmentConfig::new()
        .allow_prepared(prepared, Operation::Read, Scope::File)
        .unwrap();
    let error = config.require_live_path_identities().unwrap_err();
    assert!(
        error.to_string().contains("object changed before apply"),
        "{error}"
    );
}

#[test]
fn read_only_and_writable_grants_keep_their_access_modes() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        for kind in [Kind::Directory, Kind::File] {
            for writable in [false, true] {
                let fixture = Fixture::new(kind);
                let mut config = fixture.config(false);
                let scope = match kind {
                    Kind::Directory => Scope::Root,
                    _ => Scope::File,
                };
                if writable {
                    config = config
                        .allow(&fixture.grant, Operation::Write, scope)
                        .unwrap();
                }
                let path = match kind {
                    Kind::Directory => fixture.grant.join("value"),
                    _ => fixture.grant.clone(),
                };
                let result = in_child(|| {
                    if let Err(error) =
                        NamespaceBackend::with_probe_result(true).apply(&config, None, None)
                    {
                        let _ = writeln!(std::io::stderr(), "apply: {error}");
                        return REFUSED;
                    }
                    if fixture.inspect() != STARTED {
                        return OTHER;
                    }
                    if std::fs::write(&path, b"permitted write").is_ok() == writable {
                        STARTED
                    } else {
                        OTHER
                    }
                });
                assert_eq!(
                    result.0, STARTED,
                    "{kind:?} writable={writable}: {result:?}"
                );
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    if writable {
                        b"permitted write".as_slice()
                    } else {
                        GRANTED
                    }
                );
            }
        }
    });
}

#[test]
fn unchanged_symlinks_and_hardlinks_preserve_permitted_reads() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        for symbolic in [false, true] {
            let fixture = Fixture::new(Kind::File);
            let alias = fixture._root.path().join("alias");
            if symbolic {
                std::os::unix::fs::symlink(&fixture.grant, &alias).unwrap();
            } else {
                std::fs::hard_link(&fixture.grant, &alias).unwrap();
            }
            let config = ContainmentConfig::new()
                .allow(&alias, Operation::Read, Scope::File)
                .unwrap();
            let result = in_child(|| {
                if let Err(error) =
                    NamespaceBackend::with_probe_result(true).apply(&config, None, None)
                {
                    let _ = writeln!(std::io::stderr(), "apply: {error}");
                    return REFUSED;
                }
                if std::fs::read(&alias).is_ok_and(|bytes| bytes == GRANTED)
                    && std::fs::read(&fixture.replacement).is_err()
                {
                    STARTED
                } else {
                    OTHER
                }
            });
            assert_eq!(result.0, STARTED, "symbolic={symbolic}: {result:?}");
        }
    });
}

#[test]
fn enclosing_bind_does_not_expose_the_symlink_target() {
    super::failure_tests::in_fresh_process(|| {
        if !supported() {
            return;
        }
        let result = materialize(&Fixture::new(Kind::Directory), true, true);
        println!("enclosing bind: {result:?}");
        assert!(
            result.0 == 23
                || (result.0 == REFUSED && result.1.contains("mounted grant identity changed")),
            "the control must show an absent target or an identity refusal: {result:?}"
        );
    });
}

fn apply(fixture: &Fixture, config: &ContainmentConfig) -> (i32, String) {
    in_child(
        || match NamespaceBackend::with_probe_result(true).apply(config, None, None) {
            Ok(()) => fixture.inspect(),
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "apply: {error}");
                REFUSED
            }
        },
    )
}

#[test]
fn concurrent_source_swaps_never_expose_replacement_bytes() {
    const CHILD: &str = "SBOX58_RACE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let thread = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                thread.name().unwrap(),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.status.success(), "{output:?}");
        return;
    }
    if !supported() {
        return;
    }
    for kind in [Kind::Directory, Kind::File] {
        for link in [true, false] {
            race(kind, link);
        }
    }
}

fn race(kind: Kind, link: bool) {
    let fixture = Fixture::new(kind);
    let config = fixture.config(false);
    let control = apply(&fixture, &config);
    assert_eq!(control.0, STARTED, "real apply control: {control:?}");
    let cpath = |path: &std::path::Path| {
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap()
    };
    let grant = cpath(&fixture.grant);
    let alternate = fixture._root.path().join("alternate");
    if link {
        std::os::unix::fs::symlink(&fixture.replacement, &alternate).unwrap();
    } else {
        match kind {
            Kind::Directory => {
                std::fs::create_dir(&alternate).unwrap();
                std::fs::write(alternate.join("value"), UNGRANTED).unwrap();
            }
            Kind::File => std::fs::write(&alternate, UNGRANTED).unwrap(),
            Kind::Socket => unreachable!(),
        }
    }
    let alternate = cpath(&alternate);
    // SAFETY: the writer uses only path syscalls and the parent reaps it.
    let writer = unsafe { libc::fork() };
    assert!(writer >= 0);
    if writer == 0 {
        loop {
            // SAFETY: each path is NUL-terminated and remains allocated.
            unsafe {
                if libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    grant.as_ptr(),
                    libc::AT_FDCWD,
                    alternate.as_ptr(),
                    libc::RENAME_EXCHANGE,
                ) != 0
                {
                    libc::_exit(OTHER);
                }
            }
        }
    }
    let mut outcomes = std::collections::BTreeMap::new();
    let mut leak = None;
    for attempt in 1..=3_000 {
        let (status, report) = apply(&fixture, &config);
        let outcome = match status {
            LEAKED => "leaked",
            STARTED => "started_with_granted_bytes",
            23 => "started_with_absent_target",
            REFUSED | 127 if report.contains("mounted grant identity changed") => {
                "mount_identity_refusal"
            }
            REFUSED if report.contains("changed before apply") => "validation_refusal",
            REFUSED
                if report.contains("No such file or directory")
                    || report.contains("path does not exist") =>
            {
                "path_lookup_refusal"
            }
            _ => "other",
        };
        *outcomes.entry(outcome).or_insert(0) += 1;
        println!(
            "kind={kind:?} link={link} attempt={attempt} outcome={outcome} status={status} report={report:?}"
        );
        if status == LEAKED {
            leak = Some(attempt);
            break;
        }
    }
    // SAFETY: writer belongs to this process and has not been reaped.
    unsafe { libc::kill(writer, libc::SIGKILL) };
    assert_eq!(
        wait(writer),
        -libc::SIGKILL,
        "the writer must run until stopped"
    );
    println!("race outcomes kind={kind:?} link={link}: {outcomes:?}");
    assert!(
        leak.is_none(),
        "replacement bytes reached a workload: {leak:?}"
    );
    assert_eq!(
        outcomes.get("other"),
        None,
        "unclassified outcomes: {outcomes:?}"
    );
    assert_eq!(outcomes.get("started_with_absent_target"), None);
    assert_eq!(outcomes.values().sum::<i32>(), 3_000);
}
