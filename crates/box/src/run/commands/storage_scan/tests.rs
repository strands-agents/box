use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use crate::record::config::filesystem::{FilesystemContext, direct_grants};
use crate::record::config::process::Filesystem;
use crate::run::commands::ConfiguredCommand;

fn commands(folder: &Path) -> ConfiguredCommands {
    let path = folder.join("command");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::hard_link(&path, folder.join("second-name")).unwrap();
    let command = ConfiguredCommand::load(
        "[tool.reader]".to_string(),
        path.to_str().unwrap(),
        "".as_ref(),
    )
    .unwrap();
    assert!(
        command.needs_alias_scan,
        "the original command must require alias protection"
    );
    ConfiguredCommands {
        tools: BTreeMap::from([("reader".to_string(), Arc::new(command))]),
        sources: BTreeMap::new(),
    }
}

fn reach(home: &Path, writable: &Path) -> DirectReach {
    direct_grants(
        &Filesystem {
            read: vec![writable.to_path_buf()],
            write: vec![writable.to_path_buf()],
            ..Default::default()
        },
        &FilesystemContext {
            upstream_trust: Vec::new(),
            table: "[agent]",
            operator_home: home,
            policy: None,
            authority_directories: Vec::new(),
            program_search_directories: Vec::new(),
            source_paths: &[],
        },
    )
    .unwrap()
}

#[test]
fn pending_roots_are_pruned_before_any_directory_read() {
    let home = tempfile::tempdir().unwrap();
    let pending = home.path().join("absent-provider");
    let (result, reads) = aliases::with_readdir_count(|| {
        aliases::contains_excluding(&pending, &[(1, 2)], std::slice::from_ref(&pending))
    });
    assert!(!result.unwrap(), "pending roots need not exist");
    assert_eq!(reads, 0, "pending roots must not call readdir");
    assert_eq!(
        aliases::contains(&pending, &[(1, 2)]).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn an_ancestor_scan_skips_only_pending_data_and_keeps_outside_alias_checks() {
    let home = tempfile::tempdir().unwrap();
    let commands = commands(home.path());
    let tree = home.path().join("writable");
    let pending = tree.join("storage");
    std::fs::create_dir_all(pending.join("nested")).unwrap();
    std::fs::hard_link(
        home.path().join("command"),
        pending.join("nested/hidden-alias"),
    )
    .unwrap();
    let policy = reach(home.path(), &tree);
    let (result, reads) = aliases::with_readdir_count(|| {
        commands.validate_storage_reach("[agent]", &policy, std::slice::from_ref(&pending), &[])
    });
    result.unwrap();
    assert!(reads > 0, "the ordinary ancestor was still enumerated");
    assert!(
        commands
            .validate_storage_reach("[agent]", &policy, &[], &[])
            .is_err(),
        "the unchanged ordinary path must find the alias in the same fixture"
    );
    std::fs::hard_link(home.path().join("command"), tree.join("outside-alias")).unwrap();
    assert!(
        commands
            .validate_storage_reach("[agent]", &policy, std::slice::from_ref(&pending), &[])
            .is_err(),
        "pruning storage must not hide an alias outside it"
    );
}

#[test]
fn storage_mode_keeps_direct_command_and_ancestor_refusals() {
    let home = tempfile::tempdir().unwrap();
    let command_directory = tempfile::tempdir().unwrap();
    let commands = commands(command_directory.path());
    let policy = reach(home.path(), command_directory.path());
    let roots = [home.path().join("unrelated-pending")];
    let (result, reads) = aliases::with_readdir_count(|| {
        commands.validate_storage_reach("[agent]", &policy, &roots, &[])
    });
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("command") && error.contains("or its path"),
        "{error}"
    );
    assert_eq!(reads, 0, "the direct overlap must refuse before any scan");
}

#[test]
fn a_real_disjoint_mount_requires_no_provider_readdir() {
    let home = tempfile::tempdir().unwrap();
    let provider = PathBuf::from("/dev/shm");
    let Ok(metadata) = std::fs::metadata(&provider) else {
        eprintln!("skipping: /dev/shm is unavailable for the real-mount control");
        return;
    };
    if metadata.dev() == std::fs::metadata(home.path()).unwrap().dev() {
        eprintln!("skipping: the real-mount control needs two filesystem devices");
        return;
    }
    let commands = commands(home.path());
    let policy = reach(home.path(), &provider);
    let (result, reads) = aliases::with_readdir_count(|| {
        commands.validate_storage_reach(
            "[agent]",
            &policy,
            std::slice::from_ref(&provider),
            std::slice::from_ref(&provider),
        )
    });
    result.unwrap();
    assert_eq!(reads, 0, "the real admitted mount must not call readdir");
}

#[test]
fn a_real_same_device_mount_refuses_without_enumeration() {
    let provider = PathBuf::from("/dev/shm");
    let Ok(metadata) = std::fs::metadata(&provider) else {
        eprintln!("skipping: /dev/shm is unavailable for the real-mount control");
        return;
    };
    let (result, reads) = aliases::with_readdir_count(|| {
        Proof::capture(
            std::slice::from_ref(&provider),
            std::slice::from_ref(&provider),
            &HashSet::from([metadata.dev()]),
        )
    });
    let error = result
        .err()
        .expect("same-device proof must refuse")
        .to_string();
    assert!(
        error.contains("shares a protected command device"),
        "{error}"
    );
    assert_eq!(reads, 0);
}

fn table(extra: &str) -> MountTable {
    let text = format!(
        "1 0 8:1 / / rw - ext4 root rw\n\
         2 1 0:99 / /mnt/data rw - fuse.test provider rw\n{extra}"
    );
    MountTable::parse(text.as_bytes(), Instant::now() + PROOF_TIMEOUT).unwrap()
}

fn closure(table: &MountTable) -> io::Result<HashSet<u64>> {
    table.disjoint_closure(
        &[PathBuf::from("/mnt/data")],
        HashSet::from([libc::makedev(0, 99)]),
        &HashSet::from([libc::makedev(8, 1)]),
        Instant::now() + PROOF_TIMEOUT,
    )
}

#[test]
fn descendant_mounts_and_external_bind_aliases_must_be_disjoint() {
    let ordinary_child = table("3 2 0:100 / /mnt/data/child rw - tmpfs child rw\n");
    assert!(
        closure(&ordinary_child)
            .unwrap()
            .contains(&libc::makedev(0, 100))
    );
    let protected_child = table("3 2 8:1 /tools /mnt/data/command-alias rw - ext4 root rw\n");
    assert!(closure(&protected_child).is_err());
    let external_alias = table(
        "3 1 0:99 / /elsewhere rw - fuse.test provider rw\n\
         4 3 8:1 /tools /elsewhere/command-alias rw - ext4 root rw\n",
    );
    assert!(
        closure(&external_alias).is_err(),
        "a child under another provider spelling is still relevant"
    );
    let stacked = table("3 1 8:1 /tools /mnt/data rw - ext4 root rw\n");
    assert!(
        closure(&stacked).is_err(),
        "ambiguous stacked records cannot prove separation"
    );
}

#[test]
fn mount_paths_decode_escapes_and_use_component_prefixes() {
    let mounts = table("3 1 8:1 /tools /mnt/database rw - ext4 root rw\n");
    assert!(
        closure(&mounts).is_ok(),
        "a textual prefix is not a child path"
    );
    let parsed = MountTable::parse(
        b"1 0 0:99 / /mnt/a\\040master:7\\134b rw shared:3 - fuse.test provider rw\n",
        Instant::now() + PROOF_TIMEOUT,
    )
    .unwrap();
    assert_eq!(parsed.entries[0].point, PathBuf::from("/mnt/a master:7\\b"));
    assert!(
        MountTable::parse(
            b"1 0 bad / /mnt/data rw - fuse.test provider rw\n",
            Instant::now() + PROOF_TIMEOUT
        )
        .is_err()
    );
    assert!(
        MountTable::parse(
            b"1 0 0:99 / /mnt/a\\000b rw - fuse.test provider rw\n",
            Instant::now() + PROOF_TIMEOUT
        )
        .is_err()
    );
}

#[test]
fn changed_mount_table_or_anchor_refuses() {
    let proof = Proof {
        before: Some(b"before".to_vec()),
        anchors: Vec::new(),
        excluded: Vec::new(),
        deadline: Instant::now() + PROOF_TIMEOUT,
    };
    assert!(proof.verify_with(|| Ok(b"after".to_vec())).is_err());
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("view");
    std::fs::create_dir(&path).unwrap();
    let anchor = Anchor::open(&path).unwrap();
    std::fs::rename(&path, home.path().join("old-view")).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(
        anchor.verify().is_err(),
        "a reopened pathname must retain the pinned directory identity"
    );
}

#[test]
fn incomplete_and_expired_proofs_refuse() {
    let home = tempfile::tempdir().unwrap();
    let anchor = Anchor::open(home.path()).unwrap();
    let mounts = MountTable {
        entries: Vec::new(),
    };
    assert!(mounts.active(&anchor).is_err());
    let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(
        MountTable::parse(b"1 0 8:1 / / rw - ext4 root rw\n", expired)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(declarations(&[PathBuf::from("/mnt/a")], &[PathBuf::from("/mnt/b")]).is_err());
    assert!(
        declarations(
            &[PathBuf::from("/mnt/a"), PathBuf::from("/mnt/a/child")],
            &[]
        )
        .is_err()
    );
}
