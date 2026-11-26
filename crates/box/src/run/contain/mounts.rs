//! Startup compatibility of incoming mounts with one process's judged filesystem reach.

use std::path::{Path, PathBuf};

use containment::{ContainmentConfig, Operation, Scope};

use super::boundary::RuntimeReach;

use crate::error::ConfigError;
use crate::record::config::filesystem::DirectReach;
use crate::record::config::process::ProcessSpec;
use crate::record::config::{AuthoritySource, Record};

mod pinned;
use pinned::DirectoryPin;

/// A directory approved for one process and retained without reopening its selected pathname.
#[derive(Debug)]
pub(super) struct ApprovedMount {
    resolved: PathBuf,
    directory: DirectoryPin,
}

impl ApprovedMount {
    pub(super) fn resolved_path(&self) -> &Path {
        &self.resolved
    }

    /// Hand the checked object to containment without authorizing any additional access.
    pub(super) fn forward_into(
        &self,
        config: ContainmentConfig,
    ) -> Result<ContainmentConfig, containment::ContainmentError> {
        config.receive_mounts_from(&self.resolved, self.directory.file())
    }

    fn intersects(&self, authored: &Path, protected: &Path) -> std::io::Result<bool> {
        let resolved = crate::record::layout::resolved_to_its_deepest_existing_ancestor(protected);
        // Path restrictions also describe absent descendants that a future mount could introduce.
        if [authored, self.resolved_path()].into_iter().any(|source| {
            source.starts_with(protected)
                || protected.starts_with(source)
                || source.starts_with(&resolved)
                || resolved.starts_with(source)
        }) {
            return Ok(true);
        }
        self.directory.intersects(&resolved)
    }
}

/// Approve whole-directory permissions and retain each selected source for the mount backend.
pub(super) fn prepare(
    spec: &ProcessSpec,
    table: &str,
    runtime_reach: RuntimeReach,
    stored: &Record,
    reach: &DirectReach,
    protected_sources: &[AuthoritySource],
) -> Result<Vec<ApprovedMount>, ConfigError> {
    let paths = &spec.filesystem.receive_mounts;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    crate::record::config::mounts::validate_paths(paths, table)?;
    crate::record::config::mounts::validate_selection(spec, table, &stored.experimental_features)?;
    if cfg!(target_os = "macos") {
        return Err(ConfigError::Process {
            table: table.into(),
            reason: "`filesystem.receive_mounts` is not supported on macOS".into(),
        });
    }
    let mut prepared: Vec<ApprovedMount> = Vec::new();
    for path in paths {
        let refuse = |reason: String| ConfigError::Filesystem {
            table: table.into(),
            entry: format!("receive_mounts: {}", path.display()),
            reason,
        };
        let inspect = |error: std::io::Error| {
            refuse(format!(
                "cannot inspect the receiving directory or its permission boundaries: {error}"
            ))
        };
        let resolved = path.canonicalize().map_err(inspect)?;
        if resolved == Path::new("/") {
            return Err(refuse(
                "the receiving source must be an existing directory other than `/`".into(),
            ));
        }
        let source = ApprovedMount {
            directory: DirectoryPin::open(&resolved).map_err(inspect)?,
            resolved,
        };
        for other in &prepared {
            if source
                .directory
                .overlaps(&other.directory)
                .map_err(inspect)?
            {
                return Err(refuse(format!(
                    "the receiving directory overlaps {} by filesystem identity in the same process table",
                    other.resolved_path().display()
                )));
            }
        }
        for name in [path.as_path(), source.resolved_path()] {
            super::boundary::require_box_directory_absent(
                name,
                Operation::Write,
                Scope::Root,
                &stored.box_dir,
            )
            .map_err(|error| refuse(error.to_string()))?;
        }
        if source.intersects(path, &stored.box_dir).map_err(inspect)? {
            return Err(refuse(
                "the receiving directory intersects Box's own directory".into(),
            ));
        }
        for authority in protected_sources {
            authority.verify("authority")?;
            if source.intersects(path, authority.path()).map_err(inspect)? {
                return Err(refuse(format!(
                    "the receiving directory intersects protected authority source {}",
                    authority.path().display()
                )));
            }
        }
        for refusal in &reach.refusals {
            if source.intersects(path, &refusal.path).map_err(inspect)? {
                return Err(refuse(format!(
                    "the receiving directory intersects denied or protected path {}; incoming mounts cannot preserve this restriction",
                    refusal.path.display()
                )));
            }
        }
        for protection in &reach.write_protections {
            if source.intersects(path, protection).map_err(inspect)? {
                return Err(refuse(format!(
                    "the receiving directory intersects deny_write path {}; incoming mounts cannot preserve this restriction",
                    protection.display()
                )));
            }
        }
        let required: &[Operation] = match runtime_reach {
            RuntimeReach::Agent => &[Operation::Read, Operation::Write, Operation::Exec],
            RuntimeReach::Leaf => &[Operation::Read, Operation::Write],
        };
        for operation in required {
            let mut covered = false;
            for grant in &reach.grants {
                if grant.operation == *operation && grant.scope == Scope::Root {
                    let root = DirectoryPin::open(&grant.resolved).map_err(inspect)?;
                    if source.directory.within(&root).map_err(inspect)? {
                        covered = true;
                        break;
                    }
                }
            }
            if !covered {
                let key = match operation {
                    Operation::Read => "read",
                    Operation::Write => "write",
                    Operation::Exec => "exec",
                    _ => unreachable!("only whole-directory read, write, and exec are required"),
                };
                return Err(refuse(format!(
                    "the receiving directory requires a `{key}` grant covering the whole directory; child and exact-file grants are insufficient"
                )));
            }
        }
        prepared.push(source);
    }
    Ok(prepared)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::record::config::filesystem::{self, FilesystemContext};
    use crate::record::config::process::Filesystem;
    use crate::run::contain::boundary::ApprovedReach;
    use std::path::PathBuf;

    struct Fixture {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        data: PathBuf,
        record: Record,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let data = root.join("data");
            for path in [
                &data,
                &data.join("child"),
                &root.join("state"),
                &root.join("home"),
            ] {
                std::fs::create_dir(path).unwrap();
            }
            std::fs::write(data.join("file"), "ordinary data").unwrap();
            let record: Record = toml::from_str(&format!(
                "version = 42\nbox_id = 'box-0123456789abcdef'\nbox_dir = {:?}\nname = 'mounts'\n",
                root.join("state").display().to_string()
            ))
            .unwrap();
            Self {
                _temporary: temporary,
                root,
                data,
                record,
            }
        }

        fn spec(&self, agent: bool) -> ProcessSpec {
            let mut spec: ProcessSpec = toml::from_str("command = ['/bin/true']").unwrap();
            spec.filesystem = Filesystem {
                receive_mounts: vec![self.data.clone()],
                read: vec![self.data.clone()],
                write: vec![self.data.clone()],
                exec: if agent {
                    vec![self.data.clone()]
                } else {
                    vec![]
                },
                ..Filesystem::default()
            };
            spec
        }

        fn reach(&self, spec: &ProcessSpec, table: &str) -> Result<DirectReach, ConfigError> {
            filesystem::direct_grants(
                &spec.filesystem,
                &FilesystemContext {
                    table,
                    operator_home: &self.root.join("home"),
                    policy: None,
                    authority_directories: vec![],
                    upstream_trust: vec![],
                    program_search_directories: vec![],
                    source_paths: &[],
                },
            )
        }

        fn prepare(
            &self,
            spec: &ProcessSpec,
            table: &str,
        ) -> Result<Vec<ApprovedMount>, ConfigError> {
            let reach = self.reach(spec, table)?;
            let role = if table == "[agent]" {
                RuntimeReach::Agent
            } else {
                RuntimeReach::Leaf
            };
            prepare(spec, table, role, &self.record, &reach, &[])
        }
    }

    /// Whole-directory coverage belongs to the selected process; a child grant cannot replace it.
    #[test]
    fn each_process_requires_its_whole_directory_grants() {
        let fixture = Fixture::new();
        for (table, agent) in [
            ("[agent]", true),
            ("[tool.reader]", false),
            ("[mcp.local]", false),
        ] {
            let valid = fixture.spec(agent);
            assert_eq!(fixture.prepare(&valid, table).unwrap().len(), 1);
            let mut read_only = valid.clone();
            read_only.filesystem.write.clear();
            let error = fixture.prepare(&read_only, table).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("`write` grant covering the whole directory"),
                "{error}"
            );
            let mut child_write = valid.clone();
            child_write.filesystem.write = vec![fixture.data.join("child")];
            assert!(
                fixture
                    .prepare(&child_write, table)
                    .unwrap_err()
                    .to_string()
                    .contains("`write` grant covering the whole directory")
            );
            let mut files_only = valid.clone();
            files_only.filesystem.read.clear();
            files_only.filesystem.write.clear();
            files_only.filesystem.read_file = vec![fixture.data.join("file")];
            files_only.filesystem.write_file = vec![fixture.data.join("file")];
            assert!(
                fixture
                    .prepare(&files_only, table)
                    .unwrap_err()
                    .to_string()
                    .contains("`read` grant covering the whole directory")
            );
            if agent {
                let mut no_exec = valid.clone();
                no_exec.filesystem.exec.clear();
                assert!(
                    fixture
                        .prepare(&no_exec, table)
                        .unwrap_err()
                        .to_string()
                        .contains("`exec` grant covering the whole directory")
                );
            }
            let mut parent = valid.clone();
            parent.filesystem.receive_mounts = vec![fixture.data.join("child")];
            assert_eq!(fixture.prepare(&parent, table).unwrap().len(), 1);
            let mut redundant = valid;
            redundant
                .filesystem
                .read_file
                .push(fixture.data.join("file"));
            assert!(
                fixture
                    .prepare(&redundant, table)
                    .unwrap_err()
                    .to_string()
                    .contains("narrower one enforces nothing")
            );
        }
    }

    /// Intersecting denials stay incompatible even through aliases or before their target exists.
    #[test]
    fn denials_and_write_restrictions_cannot_intersect_receiving_directories() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("alias");
        std::os::unix::fs::symlink(&fixture.data, &alias).unwrap();
        for denied in [
            fixture.data.clone(),
            fixture.data.join("child"),
            fixture.data.join("absent"),
            alias.join("child"),
            alias.join("absent"),
        ] {
            let mut spec = fixture.spec(true);
            spec.filesystem.deny.push(denied.clone());
            assert!(
                fixture.prepare(&spec, "[agent]").is_err(),
                "deny {}",
                denied.display()
            );
        }
        for protected in [
            fixture.data.clone(),
            fixture.data.join("child"),
            alias.join("child"),
        ] {
            let mut spec = fixture.spec(true);
            spec.filesystem.deny_write.push(protected);
            assert!(fixture.prepare(&spec, "[agent]").is_err());
        }
        let outside = fixture.root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        let mut ordinary_denial = fixture.spec(true);
        ordinary_denial.filesystem.deny.push(outside);
        assert_eq!(
            fixture.prepare(&ordinary_denial, "[agent]").unwrap().len(),
            1
        );
        let mut child = fixture.spec(true);
        child.filesystem.receive_mounts = vec![fixture.data.join("child")];
        child.filesystem.deny_write = vec![fixture.data.clone()];
        assert!(
            fixture
                .prepare(&child, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("deny_write")
        );
    }

    /// The process override decides native-policy compatibility without changing the inherited flag.
    #[test]
    fn native_overrides_are_checked_without_a_mount_feature_flag() {
        let mut fixture = Fixture::new();
        for table in ["[agent]", "[tool.reader]", "[mcp.local]"] {
            let mut spec = fixture.spec(table == "[agent]");
            for (default, local, allowed) in [
                (false, None, true),
                (true, None, false),
                (true, Some(false), true),
                (false, Some(true), false),
            ] {
                fixture
                    .record
                    .experimental_features
                    .native_filesystem_policy = default;
                spec.native_filesystem_policy = local;
                assert_eq!(
                    fixture.prepare(&spec, table).is_ok(),
                    allowed,
                    "{table}: {default} {local:?}"
                );
                assert_eq!(
                    fixture
                        .record
                        .experimental_features
                        .native_filesystem_policy,
                    default
                );
            }
            fixture
                .record
                .experimental_features
                .native_filesystem_policy = false;
            spec.native_filesystem_policy = None;
        }
    }

    /// Existing path resolution and identity comparisons catch overlapping names of one directory.
    #[test]
    fn aliases_and_normalized_paths_use_the_existing_filesystem_identity() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("alias");
        std::os::unix::fs::symlink(&fixture.data, &alias).unwrap();
        let mut spec = fixture.spec(true);
        spec.filesystem.receive_mounts = vec![alias.clone()];
        assert_eq!(
            fixture.prepare(&spec, "[agent]").unwrap()[0].resolved_path(),
            fixture.data
        );
        spec.filesystem.receive_mounts.push(fixture.data.clone());
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("filesystem identity")
        );
        spec.filesystem.receive_mounts = vec![alias, fixture.data.join("child")];
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("filesystem identity")
        );
        spec.filesystem.receive_mounts = vec![fixture.data.join("."), fixture.data.clone()];
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
        spec.filesystem.receive_mounts = vec![fixture.data.join("child")];
        spec.filesystem.read = vec![fixture.root.join("alias")];
        spec.filesystem.write = spec.filesystem.read.clone();
        spec.filesystem.exec = spec.filesystem.read.clone();
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
    }

    /// The selected object must be an existing directory; declaring a missing source creates nothing.
    #[test]
    fn selected_sources_are_existing_directories_without_implicit_creation() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec(true);
        for invalid in [fixture.data.join("file"), fixture.data.join("absent")] {
            spec.filesystem.receive_mounts = vec![invalid.clone()];
            assert!(fixture.prepare(&spec, "[agent]").is_err());
        }
        assert!(!fixture.data.join("absent").exists());
        let root_alias = fixture.root.join("root-alias");
        std::os::unix::fs::symlink("/", &root_alias).unwrap();
        spec.filesystem.receive_mounts = vec![root_alias];
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("other than `/`")
        );
        spec.filesystem.receive_mounts = vec![fixture.data.clone()];
        assert_eq!(fixture.prepare(&spec, "[agent]").unwrap().len(), 1);
    }

    /// Private state and loaded authority files cannot be overlaid through a selected directory.
    #[test]
    fn box_state_and_authority_paths_keep_their_identity_guards() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec(true);
        let reach = fixture.reach(&spec, "[agent]").unwrap();
        let alias = fixture.root.join("state-alias");
        std::os::unix::fs::symlink(&fixture.record.box_dir, &alias).unwrap();
        let outward_link = fixture.record.box_dir.join("outside");
        std::os::unix::fs::symlink(&fixture.data, &outward_link).unwrap();
        for selected in [
            &fixture.record.box_dir,
            &alias,
            &fixture.root,
            &outward_link,
        ] {
            spec.filesystem.receive_mounts = vec![selected.clone()];
            assert!(
                prepare(
                    &spec,
                    "[agent]",
                    RuntimeReach::Agent,
                    &fixture.record,
                    &reach,
                    &[]
                )
                .unwrap_err()
                .to_string()
                .contains("Box's own directory")
            );
        }
        spec.filesystem.receive_mounts = vec![fixture.data.clone()];
        let policy = fixture.data.join("policy.dw");
        std::fs::write(&policy, "permit(principal, action, resource);").unwrap();
        let (source, _) = AuthoritySource::read(&policy, "policy").unwrap();
        assert!(
            prepare(
                &spec,
                "[agent]",
                RuntimeReach::Agent,
                &fixture.record,
                &reach,
                &[source]
            )
            .unwrap_err()
            .to_string()
            .contains("protected authority source")
        );
        assert_eq!(
            prepare(
                &spec,
                "[agent]",
                RuntimeReach::Agent,
                &fixture.record,
                &reach,
                &[]
            )
            .unwrap()
            .len(),
            1
        );
    }

    /// Startup judges every table independently before any process can borrow another one's grants.
    #[test]
    fn startup_checks_each_agent_tool_and_local_mcp_selection() {
        let mut fixture = Fixture::new();
        fixture.record.agent = Some(fixture.spec(true));
        fixture
            .record
            .tool
            .insert("reader".into(), fixture.spec(false));
        let local = toml::from_str::<crate::record::config::process::ContainedMcp>(
            "[spec]\ncommand = ['/bin/true']\n",
        )
        .unwrap();
        fixture.record.contained_mcp.insert("local".into(), local);
        fixture.record.contained_mcp.get_mut("local").unwrap().spec = fixture.spec(false);
        ApprovedReach::judge(&fixture.record, &[]).unwrap();
        for table in ["[agent]", "[tool.reader]", "[mcp.local]"] {
            let mut record = fixture.record.clone();
            let spec = match table {
                "[agent]" => record.agent.as_mut().unwrap(),
                "[tool.reader]" => record.tool.get_mut("reader").unwrap(),
                _ => &mut record.contained_mcp.get_mut("local").unwrap().spec,
            };
            spec.filesystem.write.clear();
            let error = ApprovedReach::judge(&record, &[]).unwrap_err();
            assert!(
                error.to_string().contains(table)
                    && error
                        .to_string()
                        .contains("`write` grant covering the whole directory"),
                "{error}"
            );
        }
    }

    /// Permission requirements follow the launch role, independently of diagnostic table text.
    #[test]
    fn launch_role_determines_required_permissions() {
        let fixture = Fixture::new();
        let spec = fixture.spec(false);
        let reach = fixture.reach(&spec, "[tool.reader]").unwrap();
        assert!(
            prepare(
                &spec,
                "[agent]",
                RuntimeReach::Leaf,
                &fixture.record,
                &reach,
                &[]
            )
            .is_ok()
        );
        let error = prepare(
            &spec,
            "[tool.reader]",
            RuntimeReach::Agent,
            &fixture.record,
            &reach,
            &[],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("`exec` grant covering the whole directory"),
            "{error}"
        );
    }

    /// Only the object approved by Core can cross the configuration handoff.
    #[test]
    fn handoff_refuses_a_replaced_approved_directory() {
        let fixture = Fixture::new();
        let spec = fixture.spec(true);
        let approved = fixture.prepare(&spec, "[agent]").unwrap();
        approved[0].forward_into(ContainmentConfig::new()).unwrap();
        std::fs::rename(&fixture.data, fixture.root.join("original-data")).unwrap();
        std::fs::create_dir(&fixture.data).unwrap();
        assert!(approved[0].forward_into(ContainmentConfig::new()).is_err());
    }

    /// With no selected directories, the ordinary grant compiler and compatibility check are unchanged.
    #[test]
    fn empty_selection_preserves_ordinary_grants_and_native_policy() {
        let mut fixture = Fixture::new();
        let mut spec = fixture.spec(true);
        spec.filesystem.receive_mounts.clear();
        spec.filesystem.write.clear();
        spec.filesystem.deny.push(fixture.data.join("child"));
        fixture
            .record
            .experimental_features
            .native_filesystem_policy = true;
        let before = fixture.reach(&spec, "[agent]").unwrap();
        assert!(
            prepare(
                &spec,
                "[agent]",
                RuntimeReach::Agent,
                &fixture.record,
                &before,
                &[]
            )
            .unwrap()
            .is_empty()
        );
        let after = fixture.reach(&spec, "[agent]").unwrap();
        assert_eq!(before.grants, after.grants);
        assert_eq!(before.refusals, after.refusals);
        assert!(
            fixture
                .record
                .experimental_features
                .native_filesystem_policy
        );
    }

    /// Retargeting a selected alias requires new grants for the object it now names.
    #[test]
    fn rechecking_a_source_alias_does_not_reuse_the_old_path_decision() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("selected");
        let other = fixture.root.join("other");
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&fixture.data, &alias).unwrap();
        let mut spec = fixture.spec(true);
        spec.filesystem.receive_mounts = vec![alias.clone()];
        let held = fixture.prepare(&spec, "[agent]").unwrap();
        std::fs::rename(&alias, fixture.root.join("original-alias")).unwrap();
        std::os::unix::fs::symlink(&other, &alias).unwrap();
        assert_eq!(held[0].resolved_path(), fixture.data);
        assert!(
            fixture
                .prepare(&spec, "[agent]")
                .unwrap_err()
                .to_string()
                .contains("`read` grant covering the whole directory")
        );
        spec.filesystem.read = vec![other.clone()];
        spec.filesystem.write = vec![other.clone()];
        spec.filesystem.exec = vec![other.clone()];
        assert_eq!(
            fixture.prepare(&spec, "[agent]").unwrap()[0].resolved_path(),
            other
        );
    }

    /// Receiving grants retain the ordinary protection for configured commands and credential paths.
    #[test]
    fn receiving_grants_do_not_bypass_program_or_credential_source_protection() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut fixture = Fixture::new();
        fixture.record.agent = Some(fixture.spec(true));
        let program = fixture.data.join("program");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut tool: ProcessSpec = toml::from_str("command = ['/bin/true']").unwrap();
        tool.command = vec![program.display().to_string()];
        fixture.record.tool.insert("protected".into(), tool);
        let error = ApprovedReach::judge(&fixture.record, &[])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("[agent]") && error.contains("command"),
            "{error}"
        );
        fixture.record.tool.get_mut("protected").unwrap().command = vec!["/bin/true".into()];
        ApprovedReach::judge(&fixture.record, &[]).unwrap();
        fixture.record.secret_source.insert(
            "vault".into(),
            crate::record::config::secret_source::SecretSourceEntry {
                command: vec!["/bin/cat".into()],
                reads: vec![fixture.data.join("file").display().to_string()],
                ..Default::default()
            },
        );
        let error = ApprovedReach::judge(&fixture.record, &[])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("[agent]") && error.contains("secret source `vault`"),
            "{error}"
        );
        fixture.record.secret_source.clear();
        ApprovedReach::judge(&fixture.record, &[]).unwrap();
    }
}
