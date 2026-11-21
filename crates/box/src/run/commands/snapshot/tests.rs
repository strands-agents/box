use super::*;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::fs::{PermissionsExt as _, symlink};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    commands: Arc<ConfiguredCommands>,
}

fn program(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("program");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
}

impl Fixture {
    fn new(hard_link: bool) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical fixture home");
        let root = home.join("programs");
        std::fs::create_dir(&root).expect("program directory");
        let tool = root.join("reader");
        let source = root.join("source");
        program(&tool);
        program(&source);
        if hard_link {
            std::fs::hard_link(&tool, root.join("reader-link")).expect("hard link");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o555)).expect("mode");
        }
        let alias = root.join("source-alias");
        symlink(&source, &alias).expect("source alias");
        let tool = ConfiguredCommand::load(
            "[tool.reader]".into(),
            tool.to_str().expect("path"),
            OsStr::new(""),
        )
        .expect("tool");
        let mut source = ConfiguredCommand::load(
            "[secret-source.token]".into(),
            alias.to_str().expect("path"),
            OsStr::new(""),
        )
        .expect("source");
        source.links = resolved_through_links(&alias).expect("source route").1;
        let commands = Arc::new(ConfiguredCommands {
            tools: BTreeMap::from([("reader".into(), Arc::new(tool))]),
            sources: BTreeMap::from([("token".into(), Arc::new(source))]),
        });
        Self {
            _directory: directory,
            root,
            commands,
        }
    }
}

fn files(export: &Export) -> Vec<File> {
    export
        .descriptors
        .iter()
        .map(|file| file.try_clone().expect("duplicate original pin"))
        .collect()
}

fn import(export: &Export) -> Result<ConfiguredCommands, BoxError> {
    export
        .manifest
        .clone()
        .import(files(export), export.owner.clone())
}

fn reach(root: &Path, write: bool) -> crate::record::config::filesystem::DirectReach {
    use crate::record::config::filesystem::{FilesystemContext, direct_grants};
    use crate::record::config::process::Filesystem;
    direct_grants(
        &Filesystem {
            read: vec![root.to_path_buf()],
            write: if write {
                vec![root.to_path_buf()]
            } else {
                Vec::new()
            },
            ..Default::default()
        },
        &FilesystemContext {
            upstream_trust: Vec::new(),
            table: "[agent]",
            operator_home: root.parent().expect("fixture home"),
            policy: None,
            authority_directories: Vec::new(),
            program_search_directories: Vec::new(),
            source_paths: &[],
        },
    )
    .expect("reach")
}

#[test]
fn snapshot_round_trip_preserves_roles_routes_and_reach_guards() {
    let fixture = Fixture::new(true);
    let export = fixture.commands.export_snapshot().expect("export");
    assert_eq!(export.manifest.descriptor_count(), 2);
    let encoded = serde_json::to_vec(&export.manifest).expect("encode");
    let manifest: Manifest = serde_json::from_slice(&encoded).expect("decode");
    let replica = manifest
        .import(files(&export), export.owner.clone())
        .expect("import");
    for (original, imported) in fixture
        .commands
        .tools
        .values()
        .chain(fixture.commands.sources.values())
        .zip(replica.tools.values().chain(replica.sources.values()))
    {
        assert_eq!(original.table, imported.table);
        assert_eq!(original.path, imported.path);
        assert_eq!(original.invoked, imported.invoked);
        assert_eq!(original.routes, imported.routes);
        assert_eq!(original.links, imported.links);
        assert_eq!(original.loaded, imported.loaded);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(original.needs_alias_scan, imported.needs_alias_scan);
        imported
            .verify()
            .expect("original owner verifies imported command");
    }
    for write in [false, true] {
        let reach = reach(&fixture.root, write);
        let original = fixture.commands.validate_reach("[agent]", &reach);
        let imported = replica.validate_reach("[agent]", &reach);
        assert_eq!(original.is_ok(), !write);
        assert_eq!(original.is_ok(), imported.is_ok());
    }
    assert!(
        Arc::new(replica).export_snapshot().is_err(),
        "replicas cannot manufacture original authority"
    );
}

#[test]
fn snapshot_requires_exact_descriptors_and_access_modes() {
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    let mut missing = files(&export);
    missing.pop();
    assert!(
        export
            .manifest
            .clone()
            .import(missing, export.owner.clone())
            .is_err()
    );
    let mut extra = files(&export);
    extra.push(extra[0].try_clone().expect("duplicate"));
    assert!(
        export
            .manifest
            .clone()
            .import(extra, export.owner.clone())
            .is_err()
    );
    let mut duplicate = files(&export);
    duplicate[1] = duplicate[0].try_clone().expect("wrong duplicate");
    assert!(
        export
            .manifest
            .clone()
            .import(duplicate, export.owner.clone())
            .is_err()
    );
    let mut directory = files(&export);
    directory[0] = File::open(&fixture.root).expect("directory");
    assert!(
        export
            .manifest
            .clone()
            .import(directory, export.owner.clone())
            .is_err()
    );
    let mut writable = files(&export);
    writable[0] = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join("reader"))
        .expect("writable descriptor");
    assert!(
        export
            .manifest
            .clone()
            .import(writable, export.owner.clone())
            .is_err()
    );
    let inheritable = files(&export);
    // SAFETY: change only this test's owned duplicate.
    assert_eq!(
        unsafe { libc::fcntl(inheritable[0].as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    assert!(
        export
            .manifest
            .clone()
            .import(inheritable, export.owner.clone())
            .is_err()
    );
    import(&export).expect("unchanged original pins remain valid");
}

#[test]
fn snapshot_binds_roles_metadata_and_indices_to_original_owner() {
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    let mut duplicated_index = export.manifest.clone();
    duplicated_index.commands[1].descriptor.index = 0;
    assert!(
        duplicated_index
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut duplicated_role = export.manifest.clone();
    duplicated_role.commands[1].role = Role::Tool;
    duplicated_role.commands[1].label = "reader".into();
    duplicated_role.commands[1].table = "[tool.reader]".into();
    assert!(
        duplicated_role
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut renamed = export.manifest.clone();
    renamed.commands[0].label = "other".into();
    renamed.commands[0].table = "[tool.other]".into();
    assert!(
        renamed
            .import(files(&export), export.owner.clone())
            .is_err(),
        "even internally valid role substitution changes the bound digest"
    );
    let mut changed_guard = export.manifest.clone();
    changed_guard.commands[0].needs_alias_scan = !changed_guard.commands[0].needs_alias_scan;
    assert!(
        changed_guard
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut changed_loaded = export.manifest.clone();
    changed_loaded.commands[0].loaded.owner ^= 1;
    assert!(
        changed_loaded
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    assert!(
        export
            .owner
            .verify(42, digest(&export.manifest).expect("digest"))
            .is_err()
    );
    assert!(export.owner.verify(0, [0; 32]).is_err());
}

#[test]
fn snapshot_rejects_original_metadata_changes_without_reloading_paths() {
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    std::fs::set_permissions(
        fixture.root.join("reader"),
        std::fs::Permissions::from_mode(0o555),
    )
    .expect("changed mode");
    assert!(
        export
            .owner
            .verify(0, digest(&export.manifest).expect("digest"))
            .is_err()
    );
    assert!(import(&export).is_err());
}

#[test]
fn snapshot_rejects_retargeted_source_even_to_same_inode() {
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    let source = fixture.root.join("source");
    let new_name = fixture.root.join("source-second-name");
    // Make a replacement symbolic link that resolves through a new link but reaches the same file.
    let intermediate = fixture.root.join("source-indirect");
    symlink(&source, &intermediate).expect("intermediate");
    let alias = fixture.root.join("source-alias");
    std::fs::rename(&alias, &new_name).expect("retain original alias");
    symlink(&intermediate, &alias).expect("retargeted alias");
    assert_eq!(
        super::super::disk_identity(&alias),
        super::super::disk_identity(&source)
    );
    assert!(
        import(&export).is_err(),
        "same final inode does not permit changing original symbolic-link route"
    );
}

#[test]
fn snapshot_rejects_replaced_names_and_new_hard_links() {
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    let path = fixture.root.join("reader");
    std::fs::rename(&path, fixture.root.join("old-reader")).expect("retain pinned original");
    program(&path);
    export
        .owner
        .verify(0, digest(&export.manifest).expect("digest"))
        .expect("owner only verifies original descriptor");
    assert!(
        import(&export).is_err(),
        "replica checks captured-view names separately"
    );

    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    std::fs::hard_link(fixture.root.join("reader"), fixture.root.join("new-link"))
        .expect("new hard link");
    assert!(import(&export).is_err());
}

#[test]
fn snapshot_preserves_legitimate_same_inode_across_roles() {
    let fixture = Fixture::new(false);
    let tool = fixture.commands.tools["reader"].clone();
    let source = ConfiguredCommand::load(
        "[secret-source.same]".into(),
        tool.path.to_str().expect("path"),
        OsStr::new(""),
    )
    .expect("source");
    let commands = Arc::new(ConfiguredCommands {
        tools: BTreeMap::from([("reader".into(), tool)]),
        sources: BTreeMap::from([("same".into(), Arc::new(source))]),
    });
    let export = commands.export_snapshot().expect("export");
    import(&export).expect("role indices may legitimately pin the same inode");
}

#[test]
fn snapshot_propagates_original_owner_verification_failure() {
    struct LostOwner;
    impl OwnerVerifier for LostOwner {
        fn verify(&self, _: u32, _: [u8; 32]) -> Result<(), BoxError> {
            Err(invalid("owner connection closed"))
        }
    }
    let fixture = Fixture::new(false);
    let export = fixture.commands.export_snapshot().expect("export");
    assert!(
        export
            .manifest
            .clone()
            .import(files(&export), Arc::new(LostOwner))
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_owner_snapshot_verifies_inside_child_user_namespace() {
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd as _;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;
    use std::sync::Mutex;
    use std::time::Duration;
    const REQUEST: &str = "BOX_SNAPSHOT_TEST_REQUEST";
    const DESCRIPTORS: &str = "BOX_SNAPSHOT_TEST_DESCRIPTORS";
    const SOCKET: &str = "BOX_SNAPSHOT_TEST_SOCKET";
    struct RemoteOwner(Mutex<UnixStream>);
    impl OwnerVerifier for RemoteOwner {
        fn verify(&self, descriptor: u32, digest: [u8; 32]) -> Result<(), BoxError> {
            let mut stream = self.0.lock().expect("stream lock");
            stream
                .write_all(&descriptor.to_le_bytes())
                .map_err(|e| invalid(e.to_string()))?;
            stream
                .write_all(&digest)
                .map_err(|e| invalid(e.to_string()))?;
            let mut reply = [0];
            stream
                .read_exact(&mut reply)
                .map_err(|e| invalid(e.to_string()))?;
            if reply == [1] {
                Ok(())
            } else {
                Err(invalid("original owner rejected request"))
            }
        }
    }
    if let Ok(request) = std::env::var(REQUEST) {
        // SAFETY: this branch only consumes dedicated descriptors inherited by this test's exec.
        assert_eq!(
            unsafe { libc::getuid() },
            0,
            "child is UID 0 only in its new user namespace"
        );
        let manifest: Manifest = serde_json::from_str(&request).expect("manifest");
        assert_ne!(
            manifest.commands[0].loaded.owner, 0,
            "manifest retains original owner's UID"
        );
        let files = std::env::var(DESCRIPTORS)
            .expect("descriptors")
            .split(',')
            .map(|number| {
                let fd: i32 = number.parse().expect("descriptor number");
                // SAFETY: each raw descriptor appears once and was dedicated to this exec.
                let file = unsafe { File::from_raw_fd(fd) };
                // SAFETY: set flags on the descriptor this File now owns.
                assert_eq!(
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
                file
            })
            .collect::<Vec<_>>();
        assert_eq!(files[0].metadata().expect("mapped metadata").uid(), 0);
        let fd = std::env::var(SOCKET)
            .expect("socket")
            .parse()
            .expect("socket descriptor");
        // SAFETY: the inherited test-only socket is uniquely owned here.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        let replica = manifest
            .import(files, Arc::new(RemoteOwner(Mutex::new(stream))))
            .expect("owner-backed import in child user namespace");
        replica.tools["reader"]
            .verify()
            .expect("owner-backed recheck");
        assert!(
            replica.tools["reader"].needs_alias_scan,
            "original hard-link defense survives mapping"
        );
        return;
    }
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        eprintln!(
            "ordinary-owner control requires a non-root operator; run explicitly as that operator"
        );
        return;
    }
    let fixture = Fixture::new(true);
    let export = fixture.commands.export_snapshot().expect("export");
    let (mut owner_stream, child_stream) = UnixStream::pair().expect("callback channel");
    owner_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("owner timeout");
    owner_stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("owner timeout");
    let descriptors = files(&export);
    let inherited = descriptors
        .iter()
        .map(|file| file.as_raw_fd())
        .chain(std::iter::once(child_stream.as_raw_fd()))
        .collect::<Vec<_>>();
    let mut child = Command::new("unshare");
    child.args(["--user", "--map-root-user", "--"])
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--exact", "run::commands::snapshot::tests::ordinary_owner_snapshot_verifies_inside_child_user_namespace", "--nocapture", "--test-threads=1"])
        .env(REQUEST, serde_json::to_string(&export.manifest).expect("manifest"))
        .env(DESCRIPTORS, descriptors.iter().map(|file| file.as_raw_fd().to_string()).collect::<Vec<_>>().join(","))
        .env(SOCKET, child_stream.as_raw_fd().to_string());
    // SAFETY: after fork this closure only calls fcntl on dedicated descriptors; it allocates nothing.
    unsafe {
        child.pre_exec(move || {
            for fd in &inherited {
                if libc::fcntl(*fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = child.spawn().expect("spawn fresh child user namespace");
    drop(child_stream);
    drop(descriptors);
    let owner = export.owner;
    let server = std::thread::spawn(move || {
        let mut served = 0;
        loop {
            let mut request = [0; 36];
            match owner_stream.read_exact(&mut request) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("bounded owner callback failed: {error}"),
            }
            assert!(served < 32, "bounded callback count");
            let index = u32::from_le_bytes(request[..4].try_into().expect("index"));
            let digest = request[4..].try_into().expect("digest");
            let accepted = owner.verify(index, digest).is_ok();
            owner_stream
                .write_all(&[u8::from(accepted)])
                .expect("reply");
            served += 1;
        }
        served
    });
    let status = child.wait().expect("child exit");
    let served = server.join().expect("owner callbacks");
    assert!(
        status.success(),
        "fresh child user namespace control failed: {status}"
    );
    assert!(served >= 3, "both roles and recheck reached original owner");
}
