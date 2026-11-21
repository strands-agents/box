use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    current: PathBuf,
    helper: PathBuf,
}

fn program(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("program");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
}

impl Fixture {
    fn new(compiler: bool) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical fixture home");
        let root = home.join("programs");
        std::fs::create_dir(&root).expect("program directory");
        let current = root.join("box");
        let helper = root.join("strands-box-contain-trampoline");
        for path in [&current, &helper, &root.join("strands-box-sock-alias")] {
            program(path);
        }
        if compiler {
            program(&root.join("strands-box-storage-compiler"));
        }
        Self {
            _directory: directory,
            root,
            current,
            helper,
        }
    }

    fn ordinary(&self) -> Arc<TrustedInstallation> {
        Arc::new(
            TrustedInstallation::open(self.current.clone(), self.helper.clone())
                .expect("ordinary installation"),
        )
    }

    fn storage(&self) -> Arc<TrustedInstallation> {
        Arc::new(
            TrustedInstallation::open_for_storage(self.current.clone(), self.helper.clone())
                .expect("storage installation"),
        )
    }
}

fn files(export: &Export) -> Vec<File> {
    export
        .descriptors
        .iter()
        .map(|file| file.try_clone().expect("duplicate original pin"))
        .collect()
}

fn import(export: &Export) -> Result<TrustedInstallation, BoxError> {
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
fn ordinary_snapshot_requires_no_storage_compiler() {
    let fixture = Fixture::new(false);
    let original = fixture.ordinary();
    assert!(original.storage_compiler().is_none());
    assert!(original.export_snapshot_for_storage().is_err());
    let export = original.export_snapshot().expect("ordinary export");
    assert_eq!(export.manifest.descriptor_count(), 3);
    let encoded = serde_json::to_vec(&export.manifest).expect("encode");
    let manifest: Manifest = serde_json::from_slice(&encoded).expect("decode");
    let replica = manifest
        .import(files(&export), export.owner.clone())
        .expect("import");
    replica.verify().expect("unchanged originals");
    assert!(replica.storage_compiler().is_none());
    for (before, after) in original.binaries.iter().zip(&replica.binaries) {
        assert_eq!(before.path, after.path);
        assert_eq!(before.names, after.names);
        assert_eq!(before.identity, after.identity);
    }
    for write in [false, true] {
        let reach = reach(&fixture.root, write);
        let before = original.validate_reach("[agent]", &reach);
        let after = replica.validate_reach("[agent]", &reach);
        assert_eq!(before.is_ok(), !write);
        assert_eq!(before.is_ok(), after.is_ok());
    }
    assert!(Arc::new(replica).export_snapshot().is_err());
    assert!(TrustedInstallation::open_for_storage(fixture.current, fixture.helper).is_err());
}

#[test]
fn storage_snapshot_pins_compiler_as_an_additional_original_role() {
    let fixture = Fixture::new(true);
    let original = fixture.storage();
    let export = original
        .export_snapshot_for_storage()
        .expect("storage export");
    assert_eq!(export.manifest.descriptor_count(), 4);
    assert_eq!(export.manifest.binaries[3].role, Role::StorageCompiler);
    let replica = import(&export).expect("import");
    let (path, _) = replica.storage_compiler().expect("compiler pin");
    assert_eq!(path, fixture.root.join("strands-box-storage-compiler"));
    assert!(
        replica
            .validate_reach("[agent]", &reach(&fixture.root, true))
            .is_err()
    );
    assert_eq!(
        fixture.ordinary().binaries.len(),
        3,
        "ordinary load does not add an available compiler implicitly"
    );
}

#[test]
fn installation_snapshot_preserves_bundle_wrapper_role() {
    let fixture = Fixture::new(true);
    let application = fixture.root.join("Box.app/Contents/MacOS");
    std::fs::create_dir_all(&application).expect("bundle");
    let current = application.join("box");
    program(&current);
    let original = Arc::new(
        TrustedInstallation::open_for_storage(current, fixture.helper.clone())
            .expect("bundle installation"),
    );
    let export = original
        .export_snapshot_for_storage()
        .expect("bundle export");
    assert_eq!(export.manifest.descriptor_count(), 5);
    assert_eq!(export.manifest.binaries[3].role, Role::ApplicationWrapper);
    assert_eq!(export.manifest.binaries[4].role, Role::StorageCompiler);
    import(&export).expect("bundle import");
}

#[test]
fn installation_snapshot_requires_exact_descriptors_and_roles() {
    let fixture = Fixture::new(true);
    let export = fixture
        .storage()
        .export_snapshot_for_storage()
        .expect("export");
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
    extra.push(extra[0].try_clone().expect("extra pin"));
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
    directory[0] = File::open(&fixture.root).expect("directory descriptor");
    assert!(
        export
            .manifest
            .clone()
            .import(directory, export.owner.clone())
            .is_err()
    );
    let mut wrong_role = export.manifest.clone();
    wrong_role.binaries[2].role = Role::Trampoline;
    assert!(
        wrong_role
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut wrong_index = export.manifest.clone();
    wrong_index.binaries[2].descriptor.index = 1;
    assert!(
        wrong_index
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut omitted_name = export.manifest.clone();
    omitted_name.binaries[0].names.clear();
    assert!(
        omitted_name
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    let mut duplicate_name = export.manifest.clone();
    let duplicated_path = duplicate_name.binaries[0].path.clone();
    duplicate_name.binaries[0].names.push(duplicated_path);
    assert!(
        duplicate_name
            .import(files(&export), export.owner.clone())
            .is_err()
    );
    assert!(
        export
            .owner
            .verify(99, digest(&export.manifest).expect("digest"))
            .is_err()
    );
    import(&export).expect("unchanged original inventory remains usable");
}

#[test]
fn installation_snapshot_keeps_all_inventoried_hard_links() {
    let fixture = Fixture::new(false);
    let alias = fixture.root.join("box-alias");
    std::fs::hard_link(&fixture.current, &alias).expect("inventoried alias");
    let export = fixture.ordinary().export_snapshot().expect("export");
    assert_eq!(export.manifest.binaries[0].names.len(), 2);
    import(&export).expect("all inventoried names retained");
    let mut changed = export.manifest.clone();
    changed.binaries[0].names.reverse();
    assert!(
        changed
            .import(files(&export), export.owner.clone())
            .is_err(),
        "even equivalent reordered metadata must match owner's original digest"
    );
    std::fs::rename(&alias, fixture.root.join("changed-alias")).expect("change inventoried name");
    assert!(import(&export).is_err());
}

#[test]
fn installation_snapshot_rejects_original_metadata_and_name_changes() {
    let fixture = Fixture::new(false);
    let export = fixture.ordinary().export_snapshot().expect("export");
    std::fs::set_permissions(&fixture.current, std::fs::Permissions::from_mode(0o555))
        .expect("mode change");
    assert!(
        export
            .owner
            .verify(0, digest(&export.manifest).expect("digest"))
            .is_err()
    );
    assert!(import(&export).is_err());

    let fixture = Fixture::new(false);
    let export = fixture.ordinary().export_snapshot().expect("export");
    std::fs::rename(&fixture.current, fixture.root.join("old-box"))
        .expect("retain original executable");
    program(&fixture.current);
    export
        .owner
        .verify(0, digest(&export.manifest).expect("digest"))
        .expect("original descriptor remains pinned");
    assert!(
        import(&export).is_err(),
        "import checks captured-view names instead of reopening authority"
    );
}
