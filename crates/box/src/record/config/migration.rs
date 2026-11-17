//! Existing configuration and original policy inputs for offline history conversion.

use std::path::{Path, PathBuf};

use policy::{Policy, ToolGrammars};

use super::{AuthoritySource, ConfigFile, grammar, mcp};
use crate::error::{BoxError, ConfigError, HistoryMigrationError};
use crate::record::layout::BoxRoot;

pub(crate) struct HistoryMigrationConfig {
    source: AuthoritySource,
    text: String,
    file: ConfigFile,
}

pub(crate) struct HistoryMigrationSources {
    pub(crate) policies: Vec<Policy>,
    pub(crate) grammars: ToolGrammars,
    captured: Vec<(AuthoritySource, String)>,
}

impl HistoryMigrationConfig {
    pub(crate) fn read(path: &Path) -> Result<Self, BoxError> {
        let (source, text) = AuthoritySource::read(path, "configuration")?;
        let file = ConfigFile::parse(&text, source.path())?;
        if !file.box_dir.is_absolute() {
            return Err(ConfigError::Contract {
                reason: format!("`box_dir` must be absolute: {}", file.box_dir.display()),
            }
            .into());
        }
        Ok(Self { source, text, file })
    }

    pub(crate) fn box_directory(&self) -> &Path {
        &self.file.box_dir
    }

    pub(crate) fn capture(self, root: &BoxRoot) -> Result<HistoryMigrationSources, BoxError> {
        let record = root.read_record()?;
        if record.box_dir != self.file.box_dir || record.name != self.file.name {
            return Err(HistoryMigrationError::ConfigurationChanged {
                field: "box identity",
            }
            .into());
        }
        let (local, remote) = mcp::partition(&self.file.mcp)?;
        let remote: std::collections::BTreeMap<_, _> = remote
            .into_iter()
            .map(|server| {
                (
                    server.name,
                    super::egress::EgressEntry {
                        destinations: server.destinations,
                        protocol: super::egress::Protocol::Mcp,
                        secret: server.secret,
                        backends: Vec::new(),
                    },
                )
            })
            .collect();
        if local != record.mcp
            || remote != record.remote_mcp
            || mcp::contained_specs(&self.file.mcp) != record.contained_mcp
        {
            return Err(HistoryMigrationError::ConfigurationChanged {
                field: "MCP server declarations",
            }
            .into());
        }
        let grammars = grammar::tool_grammars(&self.file.tool)?;
        let original_grammars = grammar::tool_grammars(&record.tool)?;
        if grammars
            .compose_action_schema(&[])
            .map_err(|source| HistoryMigrationError::Schema { source })?
            != original_grammars
                .compose_action_schema(&[])
                .map_err(|source| HistoryMigrationError::Schema { source })?
        {
            return Err(HistoryMigrationError::ConfigurationChanged {
                field: "tool grammar schemas",
            }
            .into());
        }
        let mut captured = vec![(self.source.clone(), self.text)];
        let policy = self
            .file
            .policy_path(self.source.path())
            .map(|path| {
                let (source, text) = AuthoritySource::read(&path, "policy")?;
                let policy = Policy {
                    origin: source.path().to_path_buf(),
                    text: text.clone(),
                };
                captured.push((source, text));
                Ok::<_, BoxError>(policy)
            })
            .transpose()?;
        if policy.as_ref().map(|p| &p.origin) != record.policy.as_ref()
            || policy.as_ref().map(|p| p.text.as_str()) != root.read_policy()?.as_deref()
        {
            return Err(HistoryMigrationError::ConfigurationChanged {
                field: "original policy",
            }
            .into());
        }
        let sources = HistoryMigrationSources {
            policies: policy.into_iter().collect(),
            grammars,
            captured,
        };
        sources.verify()?;
        Ok(sources)
    }
}

impl HistoryMigrationSources {
    pub(crate) fn verify(&self) -> Result<(), BoxError> {
        for (source, text) in &self.captured {
            source.verify("history migration source")?;
            let current =
                std::fs::read(source.path()).map_err(|source_error| ConfigError::Read {
                    path: source.path().to_path_buf(),
                    source: source_error,
                })?;
            source.verify("history migration source")?;
            if current != text.as_bytes() {
                return Err(HistoryMigrationError::SourceChanged {
                    path: PathBuf::from(source.path()),
                }
                .into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::record::config::{RECORD_VERSION, Record};

    const ORIGINAL: &str =
        r#"permit(principal, action, resource) when { context has "input".host };"#;

    struct Fixture {
        _temporary: tempfile::TempDir,
        config: PathBuf,
        policy: PathBuf,
        directory: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let parent = temporary.path().canonicalize().unwrap();
            let directory = parent.join("state");
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let policy = parent.join("policy.dw");
            std::fs::write(&policy, ORIGINAL).unwrap();
            let config = parent.join("box.toml");
            std::fs::write(
                &config,
                format!(
                    "name = \"migration\"\nbox_dir = {:?}\npolicy = \"policy.dw\"\n",
                    directory.display().to_string()
                ),
            )
            .unwrap();
            let (mut root, _operation) = BoxRoot::lock_directory(&directory).unwrap();
            root.settle_identity(None).unwrap();
            let record = Record::parse(
                &format!(
                    "version = {RECORD_VERSION}\nbox_id = {:?}\nbox_dir = {:?}\nname = \"migration\"\npolicy = {:?}\n",
                    root.box_id(), directory.display().to_string(), policy.display().to_string()
                ),
                &root.record(),
            )
            .unwrap();
            root.initialize_first_use(&record).unwrap();
            root.write_private_file(&root.policy(), ORIGINAL, 0o600)
                .unwrap();
            Self {
                _temporary: temporary,
                config,
                policy,
                directory,
            }
        }

        fn capture(&self) -> Result<HistoryMigrationSources, BoxError> {
            let selected = HistoryMigrationConfig::read(&self.config)?;
            let (root, _operation) = BoxRoot::lock_directory(&self.directory)?;
            selected.capture(&root)
        }
    }

    #[test]
    fn original_policy_capture_does_not_parse_or_rewrite_legacy_syntax() {
        let fixture = Fixture::new();
        let sources = fixture.capture().unwrap();
        assert_eq!(sources.policies.len(), 1);
        assert_eq!(sources.policies[0].text, ORIGINAL);
        assert_eq!(sources.policies[0].origin, fixture.policy);
        sources.verify().unwrap();
    }

    #[test]
    fn selector_does_not_create_workspace_or_execute_a_configured_command() {
        let fixture = Fixture::new();
        let workspace = fixture
            .directory
            .parent()
            .unwrap()
            .join("missing-workspace");
        let sentinel = fixture.directory.parent().unwrap().join("command-ran");
        let mut text = std::fs::read_to_string(&fixture.config).unwrap();
        text.push_str(&format!(
            "\n[agent]\ncommand = [\"/usr/bin/touch\", {:?}]\nworkspace = {:?}\n",
            sentinel.display().to_string(),
            workspace.display().to_string()
        ));
        std::fs::write(&fixture.config, text).unwrap();
        fixture.capture().unwrap();
        assert!(!workspace.exists());
        assert!(!sentinel.exists());
    }

    #[test]
    fn changed_original_policy_is_refused_before_history_is_opened() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.policy, format!("{ORIGINAL}\n")).unwrap();
        let error = fixture
            .capture()
            .err()
            .expect("changed source must refuse")
            .to_string();
        assert!(error.contains("original policy"), "{error}");
    }

    #[test]
    fn in_place_changes_to_either_captured_source_are_refused() {
        for config in [false, true] {
            let fixture = Fixture::new();
            let sources = fixture.capture().unwrap();
            let path = if config {
                &fixture.config
            } else {
                &fixture.policy
            };
            let mut bytes = std::fs::read(path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
            let error = sources.verify().unwrap_err().to_string();
            assert!(error.contains("changed after it was read"), "{error}");
        }
    }

    #[test]
    fn replaced_original_policy_is_refused_even_with_identical_bytes() {
        let fixture = Fixture::new();
        let sources = fixture.capture().unwrap();
        let replacement = fixture.policy.with_extension("replacement");
        std::fs::write(&replacement, ORIGINAL).unwrap();
        std::fs::rename(replacement, &fixture.policy).unwrap();
        assert!(sources.verify().is_err());
    }

    #[test]
    fn changed_mcp_declarations_are_refused_without_discovery() {
        let fixture = Fixture::new();
        let mut text = std::fs::read_to_string(&fixture.config).unwrap();
        text.push_str(
            "\n[mcp.offline]\ntype = \"stdio\"\ncommand = [\"missing-migration-test-server\"]\n",
        );
        std::fs::write(&fixture.config, text).unwrap();
        let error = fixture
            .capture()
            .err()
            .expect("changed MCP must refuse")
            .to_string();
        assert!(error.contains("MCP server declarations"), "{error}");
    }
}
