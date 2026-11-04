use super::*;
use std::os::unix::fs::PermissionsExt as _;

use crate::record::config::filesystem::{FilesystemContext, direct_grants};
use crate::record::config::process::Filesystem;

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    directory: PathBuf,
    current: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let directory = root.join("target/debug");
        std::fs::create_dir_all(directory.join("deps")).unwrap();
        let current = directory.join("strands-box");
        let helper = directory.join("strands-box-contain-trampoline");
        executable_fixture(&current);
        executable_fixture(&helper);
        Self {
            _temporary: temporary,
            root,
            directory,
            current,
            helper,
        }
    }

    fn open(&self) -> TrustedInstallation {
        TrustedInstallation::open(self.current.clone(), self.helper.clone()).unwrap()
    }

    fn cargo_aliases(&self) -> [PathBuf; 2] {
        let aliases = [
            self.directory.join("deps/strands_box-artifact"),
            self.directory
                .join("deps/strands_box_contain_trampoline-artifact"),
        ];
        for (installed, alias) in [&self.current, &self.helper].into_iter().zip(&aliases) {
            std::fs::hard_link(installed, alias).unwrap();
        }
        aliases
    }

    fn writable(&self, path: &Path) -> DirectReach {
        direct_grants(
            &Filesystem {
                read: vec![path.to_path_buf()],
                write: vec![path.to_path_buf()],
                ..Default::default()
            },
            &FilesystemContext {
                table: "[agent]",
                operator_home: &self.root,
                policy: None,
                authority_directories: Vec::new(),
                program_search_directories: Vec::new(),
            },
        )
        .unwrap()
    }
}

fn executable_fixture(path: &Path) {
    std::fs::write(path, "plain fixture bytes that this test never executes\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_single_name_per_installed_binary_retains_the_launcher_identity() {
    let fixture = Fixture::new();
    let installation = fixture.open();
    installation.verify().unwrap();
    for binary in &installation.binaries {
        assert_eq!(binary.names.as_slice(), std::slice::from_ref(&binary.path));
    }
    let (path, opened) = installation.launcher();
    assert_eq!(path, fixture.helper);
    let metadata = opened.metadata().unwrap();
    assert_eq!(disk_identity(path), Some((metadata.dev(), metadata.ino())));
}

#[test]
fn cargo_hard_links_and_all_their_ancestors_remain_protected() {
    let fixture = Fixture::new();
    let aliases = fixture.cargo_aliases();
    let installation = fixture.open();
    installation.verify().unwrap();
    for binary in &installation.binaries {
        assert_eq!(binary.names.len(), 2);
        for name in &binary.names {
            assert!(installation.refuses_mutation(name));
            assert!(installation.refuses_mutation(name.parent().unwrap()));
        }
    }
    for alias in &aliases {
        assert!(installation.refuses_mutation(alias));
    }
    assert!(installation.refuses_mutation(&fixture.root));
    assert!(installation.refuses_mutation(&fixture.root.join("target")));
    assert!(!installation.refuses_mutation(&fixture.directory.join("ordinary-output")));
}

#[test]
fn a_running_cargo_alias_still_inventories_the_installed_name() {
    let fixture = Fixture::new();
    let aliases = fixture.cargo_aliases();
    let installation =
        TrustedInstallation::open(aliases[0].clone(), fixture.helper.clone()).unwrap();
    assert!(installation.binaries[0].names.contains(&fixture.current));
    assert!(installation.binaries[0].names.contains(&aliases[0]));
    installation.verify().unwrap();
}

#[test]
fn a_hard_link_outside_the_installation_inventory_refuses_startup() {
    let fixture = Fixture::new();
    fixture.cargo_aliases();
    std::fs::hard_link(&fixture.helper, fixture.root.join("unexplained-link")).unwrap();
    let error = TrustedInstallation::open(fixture.current.clone(), fixture.helper.clone())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("hard links outside the installation inventory"),
        "{error}"
    );
    assert!(
        error.contains(&fixture.helper.display().to_string()),
        "{error}"
    );
}

#[test]
fn a_symbolic_link_does_not_complete_the_hard_link_inventory() {
    let fixture = Fixture::new();
    std::fs::hard_link(&fixture.helper, fixture.root.join("unexplained-link")).unwrap();
    std::os::unix::fs::symlink(
        &fixture.helper,
        fixture.directory.join("deps/symbolic-helper"),
    )
    .unwrap();
    let error = TrustedInstallation::open(fixture.current.clone(), fixture.helper.clone())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("hard links outside the installation inventory"),
        "{error}"
    );
}

#[test]
fn a_new_hard_link_invalidates_the_loaded_installation() {
    let fixture = Fixture::new();
    let installation = fixture.open();
    let alias = fixture.directory.join("deps/new-helper-link");
    std::fs::hard_link(&fixture.helper, &alias).unwrap();
    assert!(installation.refuses_mutation(&alias));
    assert!(installation.verify().is_err());
}

#[test]
fn removing_an_inventoried_name_invalidates_the_loaded_installation() {
    let fixture = Fixture::new();
    let aliases = fixture.cargo_aliases();
    let installation = fixture.open();
    std::fs::remove_file(&aliases[1]).unwrap();
    assert!(installation.verify().is_err());
}

#[test]
fn a_replaced_original_refuses_until_a_new_run_loads_it() {
    let fixture = Fixture::new();
    let installation = fixture.open();
    let original = disk_identity(&fixture.helper).unwrap();
    let replacement = fixture.directory.join("operator-update");
    executable_fixture(&replacement);
    std::fs::rename(&replacement, &fixture.helper).unwrap();
    assert_ne!(disk_identity(&fixture.helper), Some(original));
    assert!(installation.verify().is_err());
    fixture.open().verify().unwrap();
}

#[test]
fn a_symbolic_replacement_of_an_inventoried_name_is_refused() {
    let fixture = Fixture::new();
    let aliases = fixture.cargo_aliases();
    let installation = fixture.open();
    std::fs::remove_file(&aliases[1]).unwrap();
    std::os::unix::fs::symlink(&fixture.helper, &aliases[1]).unwrap();
    std::fs::hard_link(&fixture.helper, fixture.directory.join("new-helper-name")).unwrap();
    assert_eq!(std::fs::metadata(&fixture.helper).unwrap().nlink(), 2);
    assert!(installation.verify().is_err());
}

#[test]
fn every_write_grant_to_an_installed_alias_is_refused_and_sibling_output_is_allowed() {
    let fixture = Fixture::new();
    let aliases = fixture.cargo_aliases();
    let installation = fixture.open();
    let targets = [
        fixture.current.clone(),
        fixture.helper.clone(),
        aliases[0].clone(),
        aliases[1].clone(),
        fixture.directory.clone(),
        fixture.directory.join("deps"),
        fixture.root.join("target"),
    ];
    for table in ["[agent]", "[tool.writer]", "[mcp.writer]"] {
        for target in &targets {
            let error = installation
                .validate_reach(table, &fixture.writable(target))
                .unwrap_err()
                .to_string();
            assert!(error.contains("trusted Box executable"), "{error}");
            assert!(error.contains(table), "{error}");
        }
    }
    let sibling = fixture.directory.join("ordinary-output");
    std::fs::write(&sibling, "ordinary bytes").unwrap();
    installation
        .validate_reach("[agent]", &fixture.writable(&sibling))
        .unwrap();
}

#[test]
fn a_second_spelling_of_an_installation_ancestor_is_protected() {
    let fixture = Fixture::new();
    fixture.cargo_aliases();
    let installation = fixture.open();
    let alias = fixture.root.join("visible");
    std::os::unix::fs::symlink(&fixture.directory, &alias).unwrap();
    assert!(installation.refuses_mutation(&alias));
    assert!(installation.refuses_mutation(&alias.join("deps")));
    assert!(installation.refuses_mutation(&alias.join("strands-box")));
}

#[test]
fn repeated_directory_identities_cannot_hide_an_unaccounted_hard_link() {
    let fixture = Fixture::new();
    std::fs::hard_link(&fixture.helper, fixture.root.join("outside-helper")).unwrap();
    let directories = [fixture.directory.clone(), fixture.directory.join("deps/..")];
    let error = InstalledBinary::open_with_inventory(fixture.helper.clone(), &directories)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("hard links outside the installation inventory"),
        "{error}"
    );
}

#[test]
fn a_second_primary_path_spelling_does_not_count_as_another_hard_link() {
    let fixture = Fixture::new();
    std::fs::hard_link(&fixture.helper, fixture.root.join("outside-helper")).unwrap();
    let primary = fixture
        .directory
        .join("deps/../strands-box-contain-trampoline");
    let error = InstalledBinary::open(primary, &fixture.directory)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("hard links outside the installation inventory"),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn data_volume_spellings_protect_ancestors_without_adding_hard_links() {
    let fixture = Fixture::new();
    fixture.cargo_aliases();
    let installation = fixture.open();
    let aliases = installation.aliases().unwrap();
    for binary in &installation.binaries {
        assert_eq!(binary.names.len(), 2);
        assert_eq!(binary.opened.metadata().unwrap().nlink(), 2);
        for name in &binary.names {
            let data_name = Path::new("/System/Volumes/Data").join(name.strip_prefix("/").unwrap());
            assert_eq!(disk_identity(&data_name), Some(binary.identity));
            assert!(aliases.contains(&data_name));
            for ancestor in data_name.ancestors() {
                assert!(
                    installation.refuses_mutation(ancestor),
                    "the Data-volume ancestor {} must remain protected",
                    ancestor.display()
                );
            }
            let parent = data_name.parent().unwrap();
            assert!(
                installation
                    .validate_reach("[agent]", &fixture.writable(parent))
                    .is_err()
            );
        }
    }
    installation.verify().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn loading_data_volume_names_also_protects_the_original_ancestors() {
    let fixture = Fixture::new();
    let cargo_aliases = fixture.cargo_aliases();
    let data = Path::new("/System/Volumes/Data");
    let data_current = data.join(fixture.current.strip_prefix("/").unwrap());
    let data_helper = data.join(fixture.helper.strip_prefix("/").unwrap());
    assert_eq!(
        disk_identity(&data_current),
        disk_identity(&fixture.current)
    );
    assert_eq!(disk_identity(&data_helper), disk_identity(&fixture.helper));
    let installation = TrustedInstallation::open(data_current, data_helper).unwrap();
    let aliases = installation.aliases().unwrap();
    for name in [&fixture.current, &fixture.helper]
        .into_iter()
        .chain(&cargo_aliases)
    {
        assert!(aliases.contains(name));
        for ancestor in name.ancestors() {
            assert!(
                installation.refuses_mutation(ancestor),
                "the original ancestor {} must remain protected",
                ancestor.display()
            );
        }
    }
    for binary in &installation.binaries {
        assert_eq!(binary.names.len(), 2);
        assert_eq!(binary.opened.metadata().unwrap().nlink(), 2);
    }
    installation.verify().unwrap();
}

#[test]
fn the_main_binary_needs_execution_permission_but_no_read_permission() {
    let fixture = Fixture::new();
    std::fs::set_permissions(&fixture.current, std::fs::Permissions::from_mode(0o111)).unwrap();
    fixture.open().verify().unwrap();
}

#[test]
fn a_symbolic_main_name_is_refused_by_the_metadata_only_open() {
    let fixture = Fixture::new();
    let alias = fixture.directory.join("symbolic-main");
    std::os::unix::fs::symlink(&fixture.current, &alias).unwrap();
    assert!(TrustedInstallation::open(alias, fixture.helper.clone()).is_err());
}
