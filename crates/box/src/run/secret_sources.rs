//! The declared secret sources of one run, as three types that fix the order of startup: the one
//! check, the two reads, and the end of the reads, and one type for a command that starts no box.
//!
//! | Step | Owner |
//! |---|---|
//! | Resolve each `reads` and `deny` path, check each program file, refuse a table that lets a workload go around a source, and name each source and each path that no sandbox denies on stderr | [`SecretSources::check`] |
//! | Read the secret of each telemetry target, and state each outcome | [`SecretSources::fetch_telemetry`] |
//! | Read each other secret, and state each outcome | [`TelemetrySecrets::fetch_routes`] |
//! | Drop each held secret after the vaults open | [`RouteSecrets`], which the vaults consume |
//! | Read the secret of a remote MCP server for `policy generate-schema` | [`SchemaSecrets`] |

use std::collections::BTreeMap;

use credentials::{Backend, Locator};

use crate::error::{BoxError, ConfigError};
use crate::record::config::egress::EgressEntry;
use crate::record::config::secret_source::{
    DeclaredSources, SecretSourceEntry, protected_paths, routed_scheme,
};
use crate::record::config::{AuthoritySource, ProcessTables, Record};
use crate::record::layout::{canonical, operator_home_directory};
use crate::run::commands::ConfiguredCommands;
use crate::run::contain::boundary::judge_lists;
use crate::run::telemetry::{ControlOperation, ControlRecord};

/// Why a read that failed is a refusal in its record, with no word of the program in it.
const NO_SECRET: &str = "the secret source returned no secret; the standard error of the box \
                         holds the reason";

/// The checked secret sources of one run, which no read has used yet.
#[derive(Debug)]
pub(crate) struct SecretSources {
    backend: Backend,
    /// The program path of each declared scheme, as `box.toml` spells it, with each control
    /// character escaped.
    programs: BTreeMap<String, String>,
    /// The checked program of each declared scheme.
    commands: ConfiguredCommands,
    /// Each telemetry target whose secret a source reads.
    telemetry: Vec<SecretUse>,
    /// Each egress route, remote MCP server, and backend whose secret a source reads.
    routes: Vec<SecretUse>,
    /// The scheme and the line of each `reads` or `deny` entry that no sandbox of this run denies.
    skipped: Vec<(String, String)>,
}

/// The secret sources of one run after the read of each telemetry secret, with which the
/// collector opens.
#[derive(Debug)]
pub(crate) struct TelemetrySecrets(SecretSources);

/// The secret sources of one run after the read of each secret, which the vaults consume.
#[derive(Debug)]
pub(crate) struct RouteSecrets(SecretSources);

/// The checked secret sources of `policy generate-schema`, which starts no box and has no read
/// step.
#[derive(Debug)]
pub(crate) struct SchemaSecrets(SecretSources);

/// One configuration entry that names a secret in a declared scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretUse {
    /// The table and the key, such as `[egress.github] secret.ref`.
    entry: String,
    /// The reference as `credentials` parses it, which the backend routes by its scheme.
    locator: Locator,
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
    /// Resolve each `reads` and `deny` path, check the program file of each
    /// `[secret-source.<scheme>]` table of `record`, refuse each process table that lets a
    /// workload go around a source, and write one line to `disclosure` for each source and for
    /// each path that no sandbox of this run denies.
    pub(crate) fn check(
        record: &Record,
        protected_sources: &[AuthoritySource],
        disclosure: impl std::io::Write,
    ) -> Result<Self, BoxError> {
        let enabled = record.experimental_features.secret_sources;
        let declared = DeclaredSources::check(&record.secret_source, enabled)?;
        Self::checked_for_record(record, declared, protected_sources, disclosure)
    }

    /// [`check`](Self::check) of `record`, whose checked declarations are `declared`.
    fn checked_for_record(
        record: &Record,
        declared: DeclaredSources,
        protected_sources: &[AuthoritySource],
        disclosure: impl std::io::Write,
    ) -> Result<Self, BoxError> {
        let entries = &record.secret_source;
        let tables = record.process_tables();
        Self::checked(entries, declared, &tables, protected_sources, disclosure)
            .map(|sources| sources.reading(record))
    }

    /// [`check`](Self::check) for a caller that reads `references` alone and holds no record:
    /// when no reference names a scheme of `entries`, no program runs, so no table is checked.
    pub(crate) fn check_for_references<'a>(
        entries: &BTreeMap<String, SecretSourceEntry>,
        enabled: bool,
        tables: &ProcessTables,
        references: impl IntoIterator<Item = &'a str>,
        disclosure: impl std::io::Write,
    ) -> Result<SchemaSecrets, BoxError> {
        let read = references.into_iter().any(|reference| {
            routed_scheme(reference).is_ok_and(|scheme| entries.contains_key(&scheme))
        });
        let none = BTreeMap::new();
        let entries = if read { entries } else { &none };
        let declared = DeclaredSources::check(entries, enabled)?;
        Self::checked(entries, declared, tables, &[], disclosure).map(SchemaSecrets)
    }

    /// The one order of the check, which each constructor follows: the protected paths, the
    /// program files, the process tables, then the lines.
    fn checked(
        entries: &BTreeMap<String, SecretSourceEntry>,
        declared: DeclaredSources,
        tables: &ProcessTables,
        protected_sources: &[AuthoritySource],
        disclosure: impl std::io::Write,
    ) -> Result<Self, BoxError> {
        // Also for a configuration with no process table, whose lists nothing judges.
        let mut skipped = Vec::new();
        if !entries.is_empty() {
            let home = canonical(&operator_home_directory()?);
            for path in protected_paths(entries) {
                let spelled = path.spellings(&home)?;
                if let (false, Some(resolved)) = (spelled.covered, spelled.spellings.last()) {
                    let line = format!(
                        "`{}` entry {:?} names {}, which does not exist when the box starts, \
                         so no sandbox denies it in this run",
                        path.list,
                        path.entry,
                        escaped(&resolved.display().to_string())
                    );
                    skipped.push((path.scheme, line));
                }
            }
        }
        let mut sources = Self::open(entries, declared)?;
        sources.skipped = skipped;
        sources.refuse_exposure(tables, protected_sources)?;
        sources
            .disclose(disclosure)
            .map_err(|source| ConfigError::Disclosure { source })?;
        Ok(sources)
    }

    /// These sources with each entry of `record` whose secret they read.
    fn reading(mut self, record: &Record) -> Self {
        self.telemetry = self.telemetry_uses(record);
        self.routes = self.route_uses(record);
        self
    }

    /// The sources of `entries`, whose checked declarations are `declared`, with the program
    /// file of each one checked and held open.
    fn open(
        entries: &BTreeMap<String, SecretSourceEntry>,
        declared: DeclaredSources,
    ) -> Result<Self, BoxError> {
        // A configuration that declares no source keeps the local sources as they are.
        if entries.is_empty() {
            return Ok(Self {
                backend: Backend::local(),
                programs: BTreeMap::new(),
                commands: ConfiguredCommands::default(),
                telemetry: Vec::new(),
                routes: Vec::new(),
                skipped: Vec::new(),
            });
        }
        let commands = ConfiguredCommands::of_secret_sources(entries)?;
        let mut programs = BTreeMap::new();
        let mut checked = Vec::with_capacity(entries.len());
        for (scheme, declaration) in declared.into_declarations() {
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
            telemetry: Vec::new(),
            routes: Vec::new(),
            skipped: Vec::new(),
        })
    }

    /// Refuse each process table in `tables` that lets a workload go around a source, so that
    /// no source program starts in that configuration: a grant that reaches a path that a
    /// source protects, and a write grant that can change the program of a source.
    fn refuse_exposure(
        &self,
        tables: &ProcessTables,
        protected_sources: &[AuthoritySource],
    ) -> Result<(), BoxError> {
        // A configuration that declares no source has nothing to judge a table against.
        if !self.commands.has_sources() {
            return Ok(());
        }
        for (table, spec) in &tables.tables {
            let reach = judge_lists(spec, table, tables, protected_sources)?;
            self.commands.validate_reach(table, &reach)?;
        }
        Ok(())
    }

    /// Whether a source of this run reads the secret that `reference` names.
    fn reads(&self, reference: &str) -> bool {
        self.locator(reference).is_some()
    }

    /// `reference` as `credentials` parses it, when a source of this run reads its secret.
    fn locator(&self, reference: &str) -> Option<Locator> {
        Locator::parse_uri(reference)
            .ok()
            .filter(|locator| self.programs.contains_key(locator.scheme()))
    }

    /// One line for each declared source, with the program that reads its secrets, then one line
    /// for each entry of that source that no sandbox of this run denies.
    fn disclose(&self, mut output: impl std::io::Write) -> std::io::Result<()> {
        for (scheme, program) in &self.programs {
            writeln!(
                output,
                "strands-box: [secret-source.{scheme}]: reads each {scheme}:// secret with \
                 {program}, which runs outside every sandbox"
            )?;
            for (_, entry) in self.skipped.iter().filter(|(of, _)| of == scheme) {
                writeln!(output, "strands-box: [secret-source.{scheme}]: {entry}")?;
            }
        }
        Ok(())
    }

    /// Each telemetry target of `record` whose secret a declared source reads.
    fn telemetry_uses(&self, record: &Record) -> Vec<SecretUse> {
        record
            .telemetry
            .iter()
            .filter_map(|(name, target)| {
                let locator = self.locator(target.secret.as_ref()?.reference.trim())?;
                Some(SecretUse {
                    entry: format!("[telemetry.{name}] secret.ref"),
                    locator,
                })
            })
            .collect()
    }

    /// Each egress route, remote MCP server, and backend of `record` whose secret a declared
    /// source reads.
    fn route_uses(&self, record: &Record) -> Vec<SecretUse> {
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
                    own.chain(backends).filter_map(move |(key, secret)| {
                        Some(SecretUse {
                            entry: format!("[{table}.{name}] {key}"),
                            locator: self.locator(&secret.reference)?,
                        })
                    })
                })
                .collect::<Vec<_>>()
        };
        entries("egress", &record.egress)
            .into_iter()
            .chain(entries("mcp", &record.remote_mcp))
            .collect()
    }

    /// Read the secret of each telemetry target until one read fails, and send the words of the
    /// program to `diagnostics` alone.
    pub(crate) fn fetch_telemetry(
        self,
        diagnostics: impl std::io::Write,
    ) -> (Vec<Fetched>, Result<TelemetrySecrets, BoxError>) {
        let (fetched, read) = self.fetch(&self.telemetry, diagnostics);
        (fetched, read.map(|()| TelemetrySecrets(self)))
    }

    /// Read the secret of each entry in `uses` until one read fails, and send the words of the
    /// program to `diagnostics` alone.
    fn fetch(
        &self,
        uses: &[SecretUse],
        mut diagnostics: impl std::io::Write,
    ) -> (Vec<Fetched>, Result<(), BoxError>) {
        let mut fetched = Vec::with_capacity(uses.len());
        for secret in uses {
            let scheme = secret.locator.scheme();
            let program = self
                .programs
                .get(scheme)
                .map(String::as_str)
                .unwrap_or_default();
            // The value is wiped as it drops; each vault reads it again from the backend.
            let read = self.backend.resolve(&secret.locator).map(drop);
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
}

/// The end of the sources drops each secret that the backend holds, so no later step reads
/// through a declared source.
impl Drop for SecretSources {
    fn drop(&mut self) {
        self.backend.close_declared();
    }
}

impl TelemetrySecrets {
    /// The one backend that reads each secret of this run, for the collector.
    pub(in crate::run) fn backend(&self) -> &Backend {
        &self.0.backend
    }

    /// Read the secret of each egress route, remote MCP server, and backend until one read
    /// fails, and send the words of the program to `diagnostics` alone.
    pub(crate) fn fetch_routes(
        self,
        diagnostics: impl std::io::Write,
    ) -> (Vec<Fetched>, Result<RouteSecrets, BoxError>) {
        let (fetched, read) = self.0.fetch(&self.0.routes, diagnostics);
        (fetched, read.map(|()| RouteSecrets(self.0)))
    }
}

impl RouteSecrets {
    /// The one backend that reads each secret of this run, for the vaults.
    pub(in crate::run) fn backend(&self) -> &Backend {
        &self.0.backend
    }
}

impl SchemaSecrets {
    /// Whether a declared source reads the secret that `reference` names.
    pub(crate) fn reads(&self, reference: &str) -> bool {
        self.0.reads(reference)
    }

    /// The one backend that reads each secret of this command.
    pub(crate) fn backend(&self) -> &Backend {
        &self.0.backend
    }
}

/// `text` with each control character escaped, as each startup line spells a path.
fn escaped(text: &str) -> String {
    text.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
pub(crate) mod tests;
