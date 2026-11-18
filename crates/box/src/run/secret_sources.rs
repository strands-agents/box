//! The declared secret sources of one run: each checked program, and the one backend that reads
//! through them.
//!
//! | Step | Owner |
//! |---|---|
//! | Check each program file before a secret is read | [`SecretSources::open`] |
//! | Refuse a table that lets a workload go around a source, before a program first starts | [`SecretSources::refuse_exposure`] |
//! | Name each source and its program on stderr | [`SecretSources::disclose`] |
//! | Find each entry whose secret a source reads | [`SecretSources::telemetry_uses`], [`SecretSources::route_uses`] |
//! | Read each of those secrets, and state each outcome | [`SecretSources::fetch`] |
//! | Drop each held secret after the vaults open | [`SecretSources::close`] |

use std::collections::BTreeMap;

use credentials::{Backend, Locator};

use crate::error::{BoxError, ConfigError};
use crate::record::config::egress::EgressEntry;
use crate::record::config::secret_source::{DeclaredSources, SecretSourceEntry, VaultCredential};
use crate::record::config::{AuthoritySource, ProcessTables, Record};
use crate::run::commands::ConfiguredCommands;
use crate::run::contain::boundary::judge_lists;
use crate::run::telemetry::{ControlOperation, ControlRecord};

/// Why a read that failed is a refusal in its record, with no word of the program in it.
const NO_SECRET: &str = "the secret source returned no secret; the standard error of the box \
                         holds the reason";

/// The declared secret sources of one run.
#[derive(Debug)]
pub(crate) struct SecretSources {
    backend: Backend,
    /// The program path of each declared scheme, as `box.toml` spells it, with each control
    /// character escaped.
    programs: BTreeMap<String, String>,
    /// The checked program of each declared scheme, and each file that its arguments name.
    commands: ConfiguredCommands,
    /// The checked declarations, which name the owner of each credential of a vault and hold no
    /// value of the operator.
    declared: DeclaredSources,
}

/// One configuration entry that names a secret in a declared scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretUse {
    /// The table and the key, such as `[egress.github] secret.ref`.
    entry: String,
    reference: String,
}

/// One read of a secret through a declared source, as the collector records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fetched {
    /// The table and the key of the entry that names the secret.
    entry: String,
    /// The source, its program, and the redacted reference.
    detail: String,
    /// Whether the source returned the secret.
    returned: bool,
}

impl Fetched {
    /// This read as one control-plane record.
    pub(crate) fn record(&self) -> ControlRecord {
        let record = if self.returned {
            ControlRecord::completed(ControlOperation::SecretFetched, &self.entry)
        } else {
            ControlRecord::refused(ControlOperation::SecretFetched, &self.entry, NO_SECRET)
        };
        record.detailed(&self.detail)
    }
}

impl SecretSources {
    /// Check the program file of each `[secret-source.<scheme>]` table of a configuration whose
    /// `[experimental-features] secret-sources` is `enabled`, and build the one backend.
    pub(crate) fn open(
        entries: &BTreeMap<String, SecretSourceEntry>,
        enabled: bool,
    ) -> Result<Self, BoxError> {
        Self::over(entries, || DeclaredSources::check(entries, enabled))
    }

    /// [`open`](Self::open) on a protected operating system, with the feature on.
    #[cfg(test)]
    pub(crate) fn for_tests(
        entries: &BTreeMap<String, SecretSourceEntry>,
    ) -> Result<Self, BoxError> {
        Self::over(entries, || Ok(DeclaredSources::for_tests(entries)))
    }

    /// The sources of `entries`, whose checked declarations `check` gives.
    fn over(
        entries: &BTreeMap<String, SecretSourceEntry>,
        check: impl Fn() -> Result<DeclaredSources, ConfigError>,
    ) -> Result<Self, BoxError> {
        let declared = check()?;
        // A configuration that declares no source keeps the local sources as they are.
        if entries.is_empty() {
            return Ok(Self {
                backend: Backend::local(),
                programs: BTreeMap::new(),
                commands: ConfiguredCommands::default(),
                declared,
            });
        }
        let commands = ConfiguredCommands::of_secret_sources(entries)?;
        let mut programs = BTreeMap::new();
        let mut checked = Vec::with_capacity(entries.len());
        // The backend takes each declaration, so it gets the declarations of a second check.
        for (scheme, declaration) in check()?.into_declarations() {
            let refuse = |reason: String| ConfigError::SecretSource {
                scheme: scheme.clone(),
                reason,
            };
            let opened = commands
                .source(&scheme)
                .ok_or_else(|| refuse("its program was not checked".to_string()))?
                .opened()
                .try_clone()
                .map_err(|error| {
                    refuse(format!("its program file cannot be held open: {error}"))
                })?;
            programs.insert(scheme.clone(), escaped(&entries[&scheme].command[0]));
            checked.push((declaration, opened));
        }
        let backend = Backend::declared(checked).map_err(|source| ConfigError::Contract {
            reason: format!("the declared secret sources do not open: {source}"),
        })?;
        Ok(Self {
            backend,
            programs,
            commands,
            declared,
        })
    }

    /// Refuse each process table in `tables` that lets a workload go around a source, so that
    /// no source program starts in that configuration: a grant that reaches a path that a
    /// source protects, a write grant that can change a file that a source runs, and a value
    /// that holds a credential of a source's own vault, as the operator's environment holds it
    /// now.
    pub(crate) fn refuse_exposure(
        &self,
        tables: &ProcessTables,
        protected_sources: &[AuthoritySource],
    ) -> Result<(), BoxError> {
        self.refuse_exposure_in(tables, protected_sources, std::env::vars_os)
    }

    /// [`refuse_exposure`](Self::refuse_exposure) for an operator whose variables `environment`
    /// reads.
    fn refuse_exposure_in<Environment>(
        &self,
        tables: &ProcessTables,
        protected_sources: &[AuthoritySource],
        environment: impl FnOnce() -> Environment,
    ) -> Result<(), BoxError>
    where
        Environment: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        // A configuration that declares no source has nothing to judge a table against.
        if !self.commands.has_sources() {
            return Ok(());
        }
        // The copy of each value lasts for this check alone, and is wiped as the check returns.
        let credentials = self.declared.vault_credentials(environment());
        for (table, spec) in &tables.tables {
            let reach = judge_lists(spec, table, tables, protected_sources)?;
            self.commands.validate_reach(table, &reach)?;
            VaultCredential::refuse_held(&credentials, table, spec)?;
        }
        Ok(())
    }

    /// The sources of a record that declares none.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self::open(&BTreeMap::new(), false).expect("no declaration, no refusal")
    }

    /// The sources of `record`.
    pub(crate) fn of(record: &Record) -> Result<Self, BoxError> {
        Self::open(
            &record.secret_source,
            record.experimental_features.secret_sources,
        )
    }

    /// The one backend that reads each secret of this run.
    pub(crate) fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Whether a source of this run reads the secret that `reference` names.
    pub(crate) fn reads(&self, reference: &str) -> bool {
        scheme_of(reference).is_some_and(|scheme| self.programs.contains_key(scheme))
    }

    /// One line for each declared source, with the program that reads its secrets.
    pub(crate) fn disclose(&self, mut output: impl std::io::Write) -> std::io::Result<()> {
        for (scheme, program) in &self.programs {
            writeln!(
                output,
                "strands-box: [secret-source.{scheme}]: reads each {scheme}:// secret with \
                 {program}, which runs outside every sandbox"
            )?;
        }
        Ok(())
    }

    /// Each telemetry target of `record` whose secret a declared source reads.
    pub(crate) fn telemetry_uses(&self, record: &Record) -> Vec<SecretUse> {
        record
            .telemetry
            .iter()
            .filter_map(|(name, target)| {
                let reference = target.secret.as_ref()?.reference.trim();
                self.reads(reference).then(|| SecretUse {
                    entry: format!("[telemetry.{name}] secret.ref"),
                    reference: reference.to_string(),
                })
            })
            .collect()
    }

    /// Each egress route, remote MCP server, and backend of `record` whose secret a declared
    /// source reads.
    pub(crate) fn route_uses(&self, record: &Record) -> Vec<SecretUse> {
        let entries = |table: &'static str, entries: &BTreeMap<String, EgressEntry>| {
            entries
                .iter()
                .flat_map(move |(name, entry)| {
                    let own = entry.secret.iter().map(|secret| ("secret.ref", secret));
                    let backends = entry
                        .backends
                        .iter()
                        .filter_map(|backend| backend.auth.as_ref())
                        .map(|auth| ("backends.auth.ref", auth));
                    own.chain(backends).map(move |(key, secret)| SecretUse {
                        entry: format!("[{table}.{name}] {key}"),
                        reference: secret.reference.clone(),
                    })
                })
                .collect::<Vec<_>>()
        };
        entries("egress", &record.egress)
            .into_iter()
            .chain(entries("mcp", &record.remote_mcp))
            .filter(|secret| self.reads(&secret.reference))
            .collect()
    }

    /// Read the secret of each entry in `uses` until one read fails, and send the words of the
    /// program to `diagnostics` alone.
    pub(crate) fn fetch(
        &self,
        uses: &[SecretUse],
        mut diagnostics: impl std::io::Write,
    ) -> (Vec<Fetched>, Result<(), BoxError>) {
        let mut fetched = Vec::with_capacity(uses.len());
        for secret in uses {
            let scheme = scheme_of(&secret.reference).unwrap_or_default();
            let program = self
                .programs
                .get(scheme)
                .map(String::as_str)
                .unwrap_or_default();
            // The value is wiped as it drops; each vault reads it again from the backend.
            let read = Locator::parse_uri(&secret.reference)
                .and_then(|locator| self.backend.resolve(&locator).map(drop));
            fetched.push(Fetched {
                entry: secret.entry.clone(),
                detail: format!(
                    "source `{scheme}`, program {program}, reference {scheme}://[REDACTED]"
                ),
                returned: read.is_ok(),
            });
            if let Err(error) = read {
                let refusal = match writeln!(diagnostics, "strands-box: {}: {error}", secret.entry)
                {
                    Ok(()) => ConfigError::SecretFetch {
                        entry: secret.entry.clone(),
                        scheme: scheme.to_string(),
                        program: program.to_string(),
                    },
                    Err(source) => ConfigError::Disclosure { source },
                };
                return (fetched, Err(refusal.into()));
            }
        }
        (fetched, Ok(()))
    }

    /// Drop each secret that the backend holds, so no later step reads through a declared source.
    pub(crate) fn close(&self) {
        self.backend.close_declared();
    }
}

/// The text before `://` in `reference`.
fn scheme_of(reference: &str) -> Option<&str> {
    reference.split_once("://").map(|(scheme, _)| scheme)
}

/// `text` with each control character escaped, as each startup line spells a path.
fn escaped(text: &str) -> String {
    text.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
pub(crate) mod tests;
