//! Reuse of the normal filesystem compiler in a private captured-source view.
//!
//! The caller owns that view and supplies the run's frozen filesystem context and original
//! command and installation pins.
//! Compiler requests preserve the original rules and receive captured mounts by descriptor.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use containment::ContainmentConfig;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::with_filesystem_context;
use super::{GuardedBoxState, apply_command_identity, apply_filesystem_reach};
use crate::error::{BoxError, ConfigError};
use crate::record::config::filesystem::{
    FilesystemCheckpoint, FilesystemContext, FilesystemGeneration, FilesystemPlan, PendingMask,
    PublicationTarget,
};
use crate::record::config::process::ProcessSpec;
use crate::record::config::secret_source::ProtectedPath;
#[cfg(test)]
use crate::record::config::{AuthoritySource, ProcessTables};
use crate::run::commands::ConfiguredCommands;
use crate::run::installation::TrustedInstallation;

/// The original filesystem guards, captured before entering a later compiler's source view.
///
/// This value travels only on the private trusted channel. Deserialization performs no environment
/// lookup or path resolution; it does not authenticate the sender or replace descriptor handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenFilesystemContext {
    table: String,
    operator_home: PathBuf,
    #[serde(deserialize_with = "required_policy")]
    policy: Option<PathBuf>,
    authority_directories: Vec<PathBuf>,
    program_search_directories: Vec<PathBuf>,
    source_paths: Vec<FrozenSourcePath>,
    upstream_trust: Vec<PathBuf>,
}

// A missing policy field is malformed; only an explicit null preserves an originally absent policy.
fn required_policy<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error> {
    Option::<PathBuf>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenSourcePath {
    scheme: String,
    list: SourceList,
    entry: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceList {
    Reads,
    Deny,
}

impl SourceList {
    fn key(self) -> &'static str {
        match self {
            Self::Reads => "reads",
            Self::Deny => "deny",
        }
    }
}

impl FrozenFilesystemContext {
    /// Capture exactly the context used by the ordinary startup compiler, in the owner's view.
    #[cfg(test)]
    pub(crate) fn capture(
        table: &str,
        tables: &ProcessTables,
        protected_sources: &[AuthoritySource],
    ) -> Result<Self, BoxError> {
        with_filesystem_context(table, tables, protected_sources, |context| {
            let source_paths = context
                .source_paths
                .iter()
                .map(|path| {
                    let list = match path.list {
                        "reads" => SourceList::Reads,
                        "deny" => SourceList::Deny,
                        _ => {
                            return Err(ConfigError::SecretSource {
                                scheme: path.scheme.clone(),
                                reason: "a retained source path has an unknown list".to_string(),
                            });
                        }
                    };
                    Ok(FrozenSourcePath {
                        scheme: path.scheme.clone(),
                        list,
                        entry: path.entry.clone(),
                    })
                })
                .collect::<Result<_, ConfigError>>()?;
            Ok(Self {
                table: context.table.to_string(),
                operator_home: context.operator_home.to_path_buf(),
                policy: context.policy.map(Path::to_path_buf),
                authority_directories: context.authority_directories.clone(),
                program_search_directories: context.program_search_directories.clone(),
                source_paths,
                upstream_trust: context.upstream_trust.clone(),
            })
        })
    }

    /// Borrow the captured guards without consulting the compiler worker's environment.
    fn with_context<T>(
        &self,
        table: &str,
        judge: impl FnOnce(&FilesystemContext<'_>) -> Result<T, BoxError>,
    ) -> Result<T, BoxError> {
        if self.table != table {
            return Err(ConfigError::Filesystem {
                table: table.to_string(),
                entry: "filesystem".to_string(),
                reason: "the retained filesystem context belongs to a different process table"
                    .to_string(),
            }
            .into());
        }
        let source_paths: Vec<_> = self
            .source_paths
            .iter()
            .map(|path| ProtectedPath {
                scheme: path.scheme.clone(),
                list: path.list.key(),
                entry: path.entry.clone(),
            })
            .collect();
        judge(&FilesystemContext {
            table: &self.table,
            operator_home: &self.operator_home,
            policy: self.policy.as_deref(),
            authority_directories: self.authority_directories.clone(),
            program_search_directories: self.program_search_directories.clone(),
            source_paths: &source_paths,
            upstream_trust: self.upstream_trust.clone(),
        })
    }
}

/// The same process scope and immutable runtime objects that startup already judged.
pub(crate) struct GenerationSite<'a> {
    pub(crate) spec: &'a ProcessSpec,
    pub(crate) table: &'a str,
    pub(crate) context: &'a FrozenFilesystemContext,
    pub(crate) roots: &'a [PathBuf],
    pub(crate) commands: &'a Arc<ConfiguredCommands>,
    pub(crate) installation: &'a Arc<TrustedInstallation>,
}

/// Compile original authored rules with every currently admitted capture at its logical path.
/// The caller must not substitute ambient source paths for missing captured descriptors.
pub(crate) fn compile_generation(
    site: &GenerationSite<'_>,
    admitted: &[PathBuf],
    previous: Option<FilesystemCheckpoint>,
) -> Result<FilesystemGeneration, BoxError> {
    site.context.with_context(site.table, |context| {
        let generation = if let Some(previous) = previous {
            if !previous.matches(&site.spec.filesystem, site.roots) {
                return Err(ConfigError::Filesystem {
                    table: site.table.to_string(),
                    entry: "filesystem".to_string(),
                    reason:
                        "retained storage rules do not match this process's authored configuration"
                            .to_string(),
                }
                .into());
            }
            previous.compile(admitted, context)?
        } else {
            FilesystemPlan::new(&site.spec.filesystem, site.roots, context)?
                .compile_generation(admitted, context)?
        };
        generation.with_policy(|reach, _, _| -> Result<(), BoxError> {
            site.commands
                .validate_storage_reach(site.table, reach, site.roots, admitted)?;
            site.installation.validate_reach(site.table, reach)?;
            Ok(())
        })?;
        Ok(generation.with_runtime_bindings(
            site.commands.get(site.table).cloned(),
            Arc::clone(site.installation),
        ))
    })
}

/// Logical masks and projections are part of the compiled configuration, never optional hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageLayout {
    pub(crate) pending_masks: Vec<PendingMask>,
    pub(crate) publication_targets: Vec<PublicationTarget>,
}

/// A partial containment configuration cannot be taken without its mandatory logical masks.
#[derive(Debug)]
pub(crate) struct StorageContainment {
    containment: ContainmentConfig,
    layout: StorageLayout,
}

impl StorageContainment {
    /// The receiver must install all masks before exposing any target from this configuration.
    pub(crate) fn into_parts(self) -> (ContainmentConfig, StorageLayout) {
        (self.containment, self.layout)
    }
}

/// Apply the original permission lowering to the caller's ordinary launch configuration.
///
/// Runtime minimum, authority-source protection, and process attributes remain the ordinary
/// launcher's responsibility. Command identity uses the same guard as an ordinary launch. Pending masks use logical names: calling `refuse` on
/// a missing-target alias would resolve the provider and cannot safely represent this barrier.
pub(crate) fn apply_generation(
    containment: ContainmentConfig,
    generation: &FilesystemGeneration,
    table: &str,
    guard: &GuardedBoxState<'_>,
    program_identity: &Path,
    interpreter_exec_files: &[PathBuf],
) -> Result<StorageContainment, BoxError> {
    generation.with_policy(|reach, masks, targets| {
        let containment = apply_filesystem_reach(
            containment,
            reach,
            table,
            guard,
            program_identity,
            interpreter_exec_files,
        )?;
        let containment = apply_command_identity(containment, reach, table, program_identity)?;
        Ok(StorageContainment {
            containment,
            layout: StorageLayout {
                pending_masks: masks.to_vec(),
                publication_targets: targets.to_vec(),
            },
        })
    })
}

/// The immutable part of each fresh compiler request. It contains no environment lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilationInput {
    pub(crate) spec: ProcessSpec,
    pub(crate) table: String,
    pub(crate) context: FrozenFilesystemContext,
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) previous: FilesystemCheckpoint,
    pub(crate) admitted: Vec<PathBuf>,
    pub(crate) base_config_json: String,
    pub(crate) private: PathBuf,
    pub(crate) box_directory: PathBuf,
    pub(crate) program_identity: PathBuf,
    pub(crate) interpreter_exec_files: Vec<PathBuf>,
}

/// A fully compiled captured view and its retained next-generation policy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilationOutput {
    pub(crate) checkpoint: FilesystemCheckpoint,
    pub(crate) layout: StorageLayout,
    pub(crate) config_json: String,
}

/// Run in a fresh worker after every named capture occupies its original logical path.
pub(crate) fn compile(
    input: CompilationInput,
    commands: &Arc<ConfiguredCommands>,
    installation: &Arc<TrustedInstallation>,
) -> Result<CompilationOutput, BoxError> {
    let site = GenerationSite {
        spec: &input.spec,
        table: &input.table,
        context: &input.context,
        roots: &input.roots,
        commands,
        installation,
    };
    let generation = compile_generation(&site, &input.admitted, Some(input.previous))?;
    let base = ContainmentConfig::from_json(&input.base_config_json)?;
    let guard = GuardedBoxState {
        private: &input.private,
        box_directory: &input.box_directory,
    };
    let (config, layout) = apply_generation(
        base,
        &generation,
        &input.table,
        &guard,
        &input.program_identity,
        &input.interpreter_exec_files,
    )?
    .into_parts();
    Ok(CompilationOutput {
        checkpoint: generation.checkpoint(),
        layout,
        config_json: config.to_json()?,
    })
}

#[cfg(target_os = "linux")]
pub(crate) mod compiler;

#[cfg(test)]
mod tests;
