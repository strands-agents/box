use super::*;

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    installed: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let installed = root.join("storage/install/launcher");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::write(&installed, "plain fixture bytes; never executed\n").unwrap();
        Self {
            _temporary: temporary,
            root,
            installed,
        }
    }

    fn alias(&self, relative: &str) -> PathBuf {
        let alias = self.root.join(relative);
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::fs::hard_link(&self.installed, &alias).unwrap();
        alias
    }

    fn identity(&self) -> (u64, u64) {
        let metadata = std::fs::metadata(&self.installed).unwrap();
        (
            std::os::unix::fs::MetadataExt::dev(&metadata),
            std::os::unix::fs::MetadataExt::ino(&metadata),
        )
    }

    fn mount(&self, root: &str, point: &Path) -> Mount {
        Mount {
            device: b"7:19".to_vec(),
            root: PathBuf::from(root),
            point: point.to_path_buf(),
        }
    }

    fn filesystem(&self) -> Mount {
        self.mount("/", &self.root)
    }
}

#[test]
fn a_name_through_a_directory_mount_finds_its_underlying_installation() {
    let fixture = Fixture::new();
    let visible = fixture.alias("visible/bin/launcher");
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install", &fixture.root.join("visible/bin")),
    ];
    let names =
        names_at_mounts(std::slice::from_ref(&visible), fixture.identity(), &mounts).unwrap();
    assert!(names.contains(&fixture.installed), "{names:?}");
    assert!(
        names.iter().any(|name| {
            crate::record::layout::lies_within(name, &fixture.root.join("storage"))
        })
    );
}

#[test]
fn a_file_mount_exposes_a_name_below_an_unrelated_writable_directory() {
    let fixture = Fixture::new();
    let alias = fixture.alias("workspace/nested/mounted-file");
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/launcher", &alias),
    ];
    let names = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert!(names.contains(&alias), "{names:?}");
    assert!(
        names.iter().any(|name| {
            crate::record::layout::lies_within(name, &fixture.root.join("workspace"))
        })
    );
    assert!(!crate::record::layout::lies_within(
        &fixture.installed,
        &fixture.root.join("workspace"),
    ));
}

#[test]
fn a_directory_mount_exposes_a_name_below_an_unrelated_writable_directory() {
    let fixture = Fixture::new();
    let alias = fixture.alias("workspace/nested/mounted-install/launcher");
    let mounts = [
        fixture.filesystem(),
        fixture.mount(
            "/storage/install",
            &fixture.root.join("workspace/nested/mounted-install"),
        ),
    ];
    let names = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert!(names.contains(&alias), "{names:?}");
    assert!(
        names.iter().any(|name| {
            crate::record::layout::lies_within(name, &fixture.root.join("workspace"))
        })
    );
    assert!(!crate::record::layout::lies_within(
        &fixture.installed,
        &fixture.root.join("workspace"),
    ));
}

#[test]
fn every_accounted_hard_link_contributes_its_mounted_aliases() {
    let fixture = Fixture::new();
    let cargo_name = fixture.alias("storage/install/deps/cargo-launcher");
    let mounted = fixture.alias("workspace/mounted-cargo-name");
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/deps/cargo-launcher", &mounted),
    ];
    let primary_only = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert!(!primary_only.contains(&mounted), "{primary_only:?}");
    let names = names_at_mounts(
        &[fixture.installed.clone(), cargo_name],
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert!(names.contains(&mounted), "{names:?}");
}

#[test]
fn duplicate_mount_records_do_not_duplicate_a_visible_name() {
    let fixture = Fixture::new();
    let alias = fixture.alias("workspace/mounted-file");
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/launcher", &alias),
        fixture.mount("/storage/install/launcher", &alias),
    ];
    let names = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert_eq!(names.iter().filter(|name| **name == alias).count(), 1);
}

#[test]
fn a_same_content_file_at_a_derived_path_is_not_an_identity_alias() {
    let fixture = Fixture::new();
    let alias = fixture.alias("workspace/same-identity");
    let lookalike = fixture.root.join("workspace/lookalike");
    std::fs::create_dir_all(lookalike.parent().unwrap()).unwrap();
    std::fs::copy(&fixture.installed, &lookalike).unwrap();
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/launcher", &alias),
        fixture.mount("/storage/install/launcher", &lookalike),
    ];
    let names = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    assert!(names.contains(&alias), "{names:?}");
    assert!(!names.contains(&lookalike), "{names:?}");
}

#[test]
fn mount_roots_and_filesystem_devices_bound_the_mapping() {
    let fixture = Fixture::new();
    let valid = fixture.alias("workspace/same-filesystem");
    let wrong_device = fixture.alias("workspace/different-device");
    let wrong_root = fixture.alias("workspace/unrelated-root");
    let prefix_only = fixture.alias("workspace/component-prefix");
    let mut other_device = fixture.mount("/storage/install/launcher", &wrong_device);
    other_device.device = b"7:20".to_vec();
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/launcher", &valid),
        other_device,
        fixture.mount("/storage/other/launcher", &wrong_root),
        fixture.mount("/storage/inst", &prefix_only),
    ];
    let names = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .unwrap();
    for outside in [wrong_device, wrong_root, prefix_only] {
        assert!(!names.contains(&outside), "{outside:?}: {names:?}");
    }
    assert!(names.contains(&valid), "{names:?}");
}

#[test]
fn mountinfo_decodes_escaped_paths_and_accepts_optional_fields() {
    let table = b"17 1 8:1 /source\\040dir\\011tab\\012line\\134slash /target\\040dir rw,relatime shared:3 master:1 - ext4 /dev/example rw\n";
    let mounts = parse(table).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].device, b"8:1");
    assert_eq!(
        mounts[0].root,
        PathBuf::from("/source dir\ttab\nline\\slash")
    );
    assert_eq!(mounts[0].point, PathBuf::from("/target dir"));
}

#[test]
fn mountinfo_preserves_non_utf8_path_bytes() {
    let table = b"17 1 8:1 /source/\xff /target/\xfe rw - ext4 /dev/example rw\n";
    let mounts = parse(table).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(
        std::os::unix::ffi::OsStrExt::as_bytes(mounts[0].root.as_os_str()),
        b"/source/\xff",
    );
    assert_eq!(
        std::os::unix::ffi::OsStrExt::as_bytes(mounts[0].point.as_os_str()),
        b"/target/\xfe",
    );
}

#[test]
fn an_empty_or_malformed_mount_table_is_refused() {
    let malformed: &[&[u8]] = &[
        b"",
        b"17 1 8:1 / /target rw ext4 /dev/example rw\n",
        b"17 1 8:1 / /target rw - ext4\n",
        b"17 1 8:1 relative /target rw - ext4 /dev/example rw\n",
        b"17 1 8:1 / relative rw - ext4 /dev/example rw\n",
        b"17 1 8 / /target rw - ext4 /dev/example rw\n",
        b"17 1 8: / /target rw - ext4 /dev/example rw\n",
        b"17 1 :1 / /target rw - ext4 /dev/example rw\n",
        b"17 1 x:1 / /target rw - ext4 /dev/example rw\n",
        b"17 1 8:1 /source\\04 /target rw - ext4 /dev/example rw\n",
        b"17 1 8:1 /source\\777 /target rw - ext4 /dev/example rw\n",
        b"17 1 8:1 /source\\xyz /target rw - ext4 /dev/example rw\n",
    ];
    for table in malformed {
        assert!(parse(table).is_err(), "accepted {table:?}");
    }
}

#[test]
fn an_unreadable_mapped_alias_is_protected_as_an_alias() {
    struct RestoreAccess {
        path: PathBuf,
        permissions: std::fs::Permissions,
    }
    impl Drop for RestoreAccess {
        fn drop(&mut self) {
            std::fs::set_permissions(&self.path, self.permissions.clone())
                .expect("restore the disposable directory's permissions");
        }
    }

    let fixture = Fixture::new();
    let hidden = fixture.alias("workspace/hidden/mounted-file");
    let parent = hidden.parent().unwrap();
    let _restore = RestoreAccess {
        path: parent.to_path_buf(),
        permissions: std::fs::metadata(parent).unwrap().permissions(),
    };
    std::fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    if std::fs::metadata(&hidden).is_ok() {
        println!(
            "skipping: this process can bypass directory access permissions; \
             the unreadable-alias control needs an unprivileged host user"
        );
        return;
    }
    let mounts = [
        fixture.filesystem(),
        fixture.mount("/storage/install/launcher", &hidden),
    ];
    let aliases = names_at_mounts(
        std::slice::from_ref(&fixture.installed),
        fixture.identity(),
        &mounts,
    )
    .expect("an uninspectable name does not refuse the inventory");
    assert!(
        aliases.contains(&hidden),
        "the uninspectable name is protected as an alias: {aliases:?}"
    );
}

#[test]
fn a_continuously_changing_mount_table_refuses_after_three_attempts() {
    let mut reads = 0;
    let error = aliases_with_reader(&[], || {
        reads += 1;
        Ok(if reads % 2 == 1 {
            b"17 1 8:1 / / rw - ext4 /dev/example rw\n".to_vec()
        } else {
            b"18 1 8:1 / / rw - ext4 /dev/example rw\n".to_vec()
        })
    })
    .unwrap_err();
    assert_eq!(reads, 6);
    assert!(error.to_string().contains("mount table changed"), "{error}");
}

#[test]
fn a_mount_table_that_stabilizes_is_retried_and_accepted() {
    let mut reads = 0;
    let names = aliases_with_reader(&[], || {
        reads += 1;
        Ok(if reads == 2 {
            b"18 1 8:1 / / rw - ext4 /dev/example rw\n".to_vec()
        } else {
            b"17 1 8:1 / / rw - ext4 /dev/example rw\n".to_vec()
        })
    })
    .unwrap();
    assert!(names.is_empty());
    assert_eq!(reads, 4);
}

#[test]
fn mount_table_read_and_parse_errors_refuse_the_inventory() {
    let mut reads = 0;
    let error = aliases_with_reader(&[], || {
        reads += 1;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected unreadable mount table",
        ))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(reads, 1);

    reads = 0;
    let error = aliases_with_reader(&[], || {
        reads += 1;
        Ok(b"malformed mount table\n".to_vec())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(reads, 1);

    reads = 0;
    let error = aliases_with_reader(&[], || {
        reads += 1;
        if reads == 1 {
            Ok(b"17 1 8:1 / / rw - ext4 /dev/example rw\n".to_vec())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected unreadable second mount table",
            ))
        }
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(reads, 2);
}

fn namespace_prerequisite_is_denied(output: &std::process::Output) -> bool {
    output.status.code() == Some(1)
        && output.stdout.is_empty()
        && matches!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "unshare: unshare failed: Operation not permitted"
                | "unshare: unshare failed: Permission denied"
                | "unshare: unshare failed: Function not implemented"
                | "unshare: write failed /proc/self/uid_map: Operation not permitted"
                | "unshare: write failed /proc/self/gid_map: Operation not permitted"
        )
}

#[test]
fn namespace_prerequisites_recognize_creation_and_id_mapping_refusals() {
    use std::os::unix::process::ExitStatusExt as _;

    for message in [
        "unshare: unshare failed: Operation not permitted",
        "unshare: unshare failed: Permission denied",
        "unshare: unshare failed: Function not implemented",
        "unshare: write failed /proc/self/uid_map: Operation not permitted",
        "unshare: write failed /proc/self/gid_map: Operation not permitted",
    ] {
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: format!("{message}\n").into_bytes(),
        };
        assert!(namespace_prerequisite_is_denied(&output), "{message}");
    }
}

#[test]
fn namespace_test_failures_cannot_be_reported_as_prerequisite_skips() {
    use std::os::unix::process::ExitStatusExt as _;

    let denied = b"unshare: write failed /proc/self/uid_map: Operation not permitted";
    for (status, stdout, stderr) in [
        (0, &b""[..], &denied[..]),
        (101, &b""[..], &denied[..]),
        (1, &b"INSTALLATION_MOUNT_NAMESPACE_ENTERED"[..], &denied[..]),
        (1, &b"running 1 test"[..], &denied[..]),
        (1, &b""[..], &b"unexpected namespace error"[..]),
        (
            1,
            &b""[..],
            &b"unshare: unshare failed: Invalid argument"[..],
        ),
        (
            1,
            &b""[..],
            &b"inner failure: unshare: unshare failed: Operation not permitted"[..],
        ),
    ] {
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        };
        assert!(!namespace_prerequisite_is_denied(&output), "{output:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn real_mount_aliases_preserve_link_counts_and_refuse_overlapping_write_grants() {
    const INNER: &str = "STRANDS_BOX_INSTALLATION_MOUNT_TEST_INNER";
    const ROOT: &str = "STRANDS_BOX_INSTALLATION_MOUNT_TEST_ROOT";
    const PARENT_MOUNT: &str = "STRANDS_BOX_INSTALLATION_PARENT_MOUNT_NAMESPACE";
    const PARENT_USER: &str = "STRANDS_BOX_INSTALLATION_PARENT_USER_NAMESPACE";
    const ENTERED: &str = "INSTALLATION_MOUNT_NAMESPACE_ENTERED";
    const COMPLETE: &str = "INSTALLATION_MOUNT_NAMESPACE_CHECKS_PASSED";

    fn namespace(path: &str) -> PathBuf {
        std::fs::read_link(path).expect("the process namespace identity is available")
    }

    if std::env::var_os(INNER).is_none() {
        let Some(unshare) = ["/usr/bin/unshare", "/bin/unshare"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
        else {
            println!(
                "skipping: installed unshare is unavailable; \
                 the real installation mount-alias test needs a private user and mount namespace"
            );
            return;
        };
        let fixture = Fixture::new();
        let test = format!(
            "{}::real_mount_aliases_preserve_link_counts_and_refuse_overlapping_write_grants",
            module_path!().split_once("::").unwrap().1,
        );
        let output = std::process::Command::new(unshare)
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--fork",
                "--propagation",
                "private",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env(INNER, "1")
            .env(ROOT, &fixture.root)
            .env(PARENT_MOUNT, namespace("/proc/self/ns/mnt"))
            .env(PARENT_USER, namespace("/proc/self/ns/user"))
            .env("LC_ALL", "C")
            .output()
            .expect("the installed unshare command starts");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if namespace_prerequisite_is_denied(&output) {
            println!(
                "skipping: this host refuses the private user and mount namespace \
                 for the real installation mount-alias test: {}",
                stderr.trim(),
            );
            return;
        }
        assert!(
            output.status.success(),
            "mount namespace test failed: {}\n{stdout}\n{stderr}",
            output.status,
        );
        assert!(
            stdout.contains(ENTERED),
            "the inner test never ran: {stdout}"
        );
        assert!(
            stdout.contains(COMPLETE),
            "the mount assertions never completed: {stdout}"
        );
        println!("{COMPLETE}");
        return;
    }

    assert_eq!(std::env::var(INNER).unwrap(), "1");
    assert_ne!(
        namespace("/proc/self/ns/mnt"),
        PathBuf::from(std::env::var_os(PARENT_MOUNT).unwrap()),
        "mounts must run in a different namespace from the parent test process",
    );
    assert_ne!(
        namespace("/proc/self/ns/user"),
        PathBuf::from(std::env::var_os(PARENT_USER).unwrap()),
        "mount capability must belong to the disposable user namespace",
    );
    // SAFETY: this subprocess has its own user and mount namespaces; no other tests share them.
    let private = unsafe {
        libc::alarm(30);
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    assert_eq!(
        private,
        0,
        "make mounts private: {}",
        io::Error::last_os_error()
    );
    println!("{ENTERED}");

    fn bind(source: &Path, target: &Path) {
        let source =
            std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(source.as_os_str()))
                .unwrap();
        let target =
            std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(target.as_os_str()))
                .unwrap();
        // SAFETY: both paths name disposable fixtures, and mount propagation is private.
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(
            result,
            0,
            "bind plain fixture: {}",
            io::Error::last_os_error()
        );
    }

    fn write_reach(
        path: &Path,
        operator_home: &Path,
        file: bool,
    ) -> crate::record::config::filesystem::DirectReach {
        use crate::record::config::filesystem::{FilesystemContext, direct_grants};
        use crate::record::config::process::Filesystem;
        let filesystem = if file {
            Filesystem {
                read_file: vec![path.to_path_buf()],
                write_file: vec![path.to_path_buf()],
                ..Default::default()
            }
        } else {
            Filesystem {
                read: vec![path.to_path_buf()],
                write: vec![path.to_path_buf()],
                ..Default::default()
            }
        };
        direct_grants(
            &filesystem,
            &FilesystemContext {
                table: "[agent]",
                operator_home,
                policy: None,
                authority_directories: Vec::new(),
                program_search_directories: Vec::new(),
            },
        )
        .unwrap()
    }

    let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
    let directory = root.join("storage/install");
    let current = directory.join("box");
    let helper = directory.join("launcher");
    let alias_image = directory.join("strands-box-sock-alias");
    std::fs::write(&current, "plain current-binary fixture; never executed\n").unwrap();
    std::fs::write(&alias_image, "plain alias-image fixture; never executed\n").unwrap();
    for binary in [&current, &helper, &alias_image] {
        std::fs::set_permissions(binary, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
    }
    let installation = super::super::TrustedInstallation::open(current.clone(), helper.clone())
        .expect("plain executable-mode files satisfy the identity fixture");
    let links_before = std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(&helper).unwrap());
    assert_eq!(links_before, 1);

    let file_alias = root.join("workspace/file-alias/nested/launcher");
    let directory_alias = root.join("workspace/directory-alias/nested/install");
    std::fs::create_dir_all(file_alias.parent().unwrap()).unwrap();
    std::fs::write(&file_alias, "plain mountpoint fixture\n").unwrap();
    std::fs::create_dir_all(&directory_alias).unwrap();
    bind(&helper, &file_alias);
    bind(&directory, &directory_alias);
    let directory_helper = directory_alias.join("launcher");
    let source_identity = crate::record::layout::disk_identity(&helper).unwrap();
    for alias in [&file_alias, &directory_helper] {
        assert_eq!(
            crate::record::layout::disk_identity(alias),
            Some(source_identity)
        );
        assert_eq!(
            std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(alias).unwrap()),
            links_before,
        );
    }
    assert_eq!(
        std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(&helper).unwrap()),
        links_before,
    );
    installation.verify().unwrap();
    assert!(
        installation
            .binaries
            .iter()
            .all(|binary| binary.names.len() == 1)
    );
    let mounted_names = installation.aliases().unwrap();
    assert!(mounted_names.contains(&file_alias), "{mounted_names:?}");
    assert!(
        mounted_names.contains(&directory_helper),
        "{mounted_names:?}"
    );

    for (target, file) in [
        (file_alias.clone(), true),
        (directory_helper, true),
        (root.join("workspace/file-alias"), false),
        (root.join("workspace/directory-alias"), false),
        (root.join("workspace"), false),
    ] {
        let error = installation
            .validate_reach("[agent]", &write_reach(&target, &root, file))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("trusted Box executable"),
            "{target:?}: {error}"
        );
        assert!(installation.refuses_mutation(&target), "{target:?}");
    }

    let reached_through_mount = super::super::TrustedInstallation::open(
        directory_alias.join("box"),
        directory_alias.join("launcher"),
    )
    .unwrap();
    let reverse_names = reached_through_mount.aliases().unwrap();
    assert!(reverse_names.contains(&current), "{reverse_names:?}");
    assert!(reverse_names.contains(&helper), "{reverse_names:?}");
    let source_ancestor = root.join("storage");
    let error = reached_through_mount
        .validate_reach("[agent]", &write_reach(&source_ancestor, &root, false))
        .unwrap_err()
        .to_string();
    assert!(error.contains("trusted Box executable"), "{error}");
    assert!(reached_through_mount.refuses_mutation(&source_ancestor));

    let sibling = root.join("ordinary-output");
    std::fs::create_dir(&sibling).unwrap();
    for installation in [&installation, &reached_through_mount] {
        installation
            .validate_reach("[agent]", &write_reach(&sibling, &root, false))
            .unwrap();
        assert!(!installation.refuses_mutation(&sibling));
    }
    std::fs::write(
        sibling.join("control"),
        "ordinary output remains writable\n",
    )
    .unwrap();
    let hidden_parent = root.join("workspace/unreadable");
    std::fs::create_dir(&hidden_parent).unwrap();
    let hidden_alias = hidden_parent.join("launcher");
    std::fs::write(&hidden_alias, "plain mountpoint fixture\n").unwrap();
    bind(&helper, &hidden_alias);

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut capabilities = [CapabilityData::default(); 2];
    // SAFETY: these buffers match Linux capability ABI version 3 for this private subprocess.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capget, &mut header, capabilities.as_mut_ptr()) },
        0
    );
    capabilities[0].effective &= !((1 << 1) | (1 << 2));
    // SAFETY: only this private subprocess loses its directory access override capabilities.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capset, &header, capabilities.as_ptr()) },
        0
    );

    struct RestoreDirectory(PathBuf);
    impl Drop for RestoreDirectory {
        fn drop(&mut self) {
            std::fs::set_permissions(&self.0, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .expect("restore the disposable directory");
        }
    }
    let _restore = RestoreDirectory(hidden_parent.clone());
    std::fs::set_permissions(
        &hidden_parent,
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(&hidden_alias).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(installation.aliases().unwrap().contains(&hidden_alias));
    for table in ["[agent]", "[tool.writer]", "[mcp.writer]"] {
        installation
            .validate_reach(table, &write_reach(&sibling, &root, false))
            .unwrap();
        for target in [&hidden_parent, &root.join("workspace")] {
            let error = installation
                .validate_reach(table, &write_reach(target, &root, false))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("this write grant can change trusted Box executable"),
                "{error}"
            );
            assert!(installation.refuses_mutation(target));
        }
    }
    assert!(!installation.refuses_mutation(&sibling));
    std::fs::set_permissions(
        &hidden_parent,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(
        crate::record::layout::disk_identity(&hidden_alias),
        Some(source_identity)
    );
    let error = installation
        .validate_reach("[agent]", &write_reach(&hidden_alias, &root, true))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("this write grant can change trusted Box executable"),
        "{error}"
    );
    assert!(installation.refuses_mutation(&hidden_alias));
    println!("UNREADABLE_MOUNT_ALIASES_REMAIN_PROTECTED");
    println!("{COMPLETE}");
}
