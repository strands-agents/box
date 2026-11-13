//! The reachable set: what the interpreters may name, and the one resolver over it.
//!
//! One directory has one name for every participant. The agent's home keeps its host path,
//! because an environment variable must be true for the process that reads it: the workload's
//! own syscalls resolve these strings directly, so the Shell must report the same one or the agent
//! reads two names for one directory.
//!
//! **`HOME` and the working directory are two questions.** `HOME` is the agent's home, which is the
//! operator's own unless `[agent] env.HOME` names another directory, and every participant reads the
//! same string for it. `PWD` is the workspace, because that is where the operator's policy names
//! paths — so [`Reach::working_directory`] answers `PWD` and relative-path rooting, and
//! [`Reach::home_variable`] answers `HOME`.
//!
//! The accessors stay separate because the agent's home and the operator home answer different
//! questions. The interpreters report paths under the operator home relative to that home, so
//! checked-in policy remains portable.
//!
//! [`Reach`] holds that set once and both interpreters share it, so the two cannot
//! drift. It also holds the one [`PathResolver`], which is the floor **beneath** policy:
//! it translates the visible home prefix into its canonical host identity, refuses
//! other non-canonical spellings, and refuses an identity outside every
//! declared root. Policy decides first; this cannot widen what policy allowed,
//! and no `permit` can open it.

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use policy::{PathRefusal, PathResolver};

use crate::record::config::AuthoritySource;
use crate::record::config::process::Grant;
use crate::record::layout::{disk_identity, has_ancestor_among, lies_within};
use crate::run::broker::invalid_input;
use crate::run::commands::CommandMutationRefusal;

/// The set of paths the interpreters may name, and the resolver that admits one.
#[derive(Debug)]
pub(super) struct Reach {
    /// The agent's home, at its host path. One string for the workload, the Shell, and Monty.
    home: String,

    /// The canonical host identity that backs the home's visible spelling.
    home_source: String,

    /// The one resolver over the agent's home, the operator home, and the workspace.
    resolver: PathResolver,

    /// The deny floor: roots no path may resolve into, whatever policy says.
    forbidden: Vec<PathBuf>,

    /// The on-disk identities of the deny floor's roots that existed when the set was declared.
    forbidden_identities: Vec<(u64, u64)>,

    /// The exact authority-source identities that this run loaded.
    forbidden_exactly: Vec<AuthoritySource>,

    /// Every spelling of each credential store under the operator home and the agent's home.
    credential_store_paths: Vec<PathBuf>,

    /// The same spellings, folded the way a case-insensitive volume compares names.
    credential_stores: Vec<PathBuf>,

    /// The credential store paths that the agent's own `read` and `write` lists name.
    credential_store_grants: Vec<CredentialStoreGrant>,

    /// The agent's `deny` entries inside a credential store, case-folded.
    credential_store_denials: Vec<PathBuf>,

    /// The stores under a declared `[agent] env.HOME` that are not also operator-home stores, folded.
    declared_home_stores: Vec<PathBuf>,

    commands: std::sync::Arc<crate::run::commands::ConfiguredCommands>,
    installation: Option<std::sync::Arc<crate::run::installation::TrustedInstallation>>,

    /// The operator home both interpreters may name under policy.
    shared: Option<String>,

    /// The directory a relative path means: the workspace, when the box has one.
    working: Option<String>,
}

impl Reach {
    /// Declare the reachable set from the agent's home, the operator home, and the workspace.
    #[cfg(test)]
    pub(super) fn over(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
    ) -> io::Result<Self> {
        Self::over_with_floor(home, operator_home, working, None, &[])
    }

    pub(super) fn over_box(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
        box_root: &Path,
        protected_sources: &[AuthoritySource],
    ) -> io::Result<Self> {
        Self::over_with_floor(
            home,
            operator_home,
            working,
            Some(box_root),
            protected_sources,
        )
    }

    fn over_with_floor(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
        box_root: Option<&Path>,
        protected_sources: &[AuthoritySource],
    ) -> io::Result<Self> {
        let home_text = utf8(home, "the agent's home")?;

        let canonical_home = home.canonicalize().map_err(|source| {
            invalid_input(format!(
                "the agent's home {home_text} could not be resolved: {source}"
            ))
        })?;
        let home_source = utf8(&canonical_home, "the resolved home")?;

        let mut forbidden = forbidden_roots();
        if let Some(box_root) = box_root {
            let canonical = box_root.canonicalize().map_err(|source| {
                invalid_input(format!(
                    "the box directory {} could not be resolved: {source}",
                    box_root.display()
                ))
            })?;
            if !forbidden.contains(&canonical) {
                forbidden.push(canonical);
            }
        }
        // The operator home first, so the resolver's own roots read widest-first. The order does
        // not decide anything: `PathResolver` admits a path under any root.
        let shared = match operator_home {
            Some(shared) => {
                let canonical = shared.canonicalize().map_err(|source| {
                    invalid_input(format!(
                        "the operator home {} could not be resolved: {source}",
                        shared.display()
                    ))
                })?;
                Some(canonical)
            }
            None => None,
        };
        let mut roots = Vec::new();
        if let Some(shared) = &shared {
            roots.push(shared.clone());
        }
        if !roots.iter().any(|root| canonical_home.starts_with(root)) {
            roots.push(canonical_home.clone());
        }
        if let Some(working) = working {
            let canonical = working.canonicalize().map_err(|source| {
                invalid_input(format!(
                    "the workspace directory {} could not be resolved: {source}",
                    working.display()
                ))
            })?;
            if !roots.iter().any(|root| canonical.starts_with(root)) {
                roots.push(canonical);
            }
        }
        let mut credential_stores: Vec<PathBuf> = Vec::new();
        for home in shared.iter().chain(std::iter::once(&canonical_home)) {
            for store in containment::credential_store_anchors(home) {
                if !credential_stores.contains(&store) {
                    credential_stores.push(store);
                }
            }
        }
        // The sandbox anchors its floor at the operator home, so a list entry that encloses one of
        // these is a sandbox grant, and the interpreters lift their floor for it the same way.
        let operator_stores = shared
            .as_deref()
            .map(containment::credential_store_anchors)
            .unwrap_or_default();
        let declared_home_stores: Vec<PathBuf> =
            containment::credential_store_anchors(&canonical_home)
                .into_iter()
                .filter(|store| !operator_stores.contains(store))
                .map(|store| folded(&store))
                .collect();
        let mut resolver = PathResolver::over(roots).map_err(|refusal| {
            invalid_input(format!("the reachable set is unusable: {refusal}"))
        })?;
        // **A rule reads `~/<relative>`, so a checked-in policy holds in every clone.**
        //
        if let Some(shared) = &shared {
            resolver = resolver.reporting_under(shared.clone());
        }

        // **Refused rather than corrected, on two counts.**
        //
        let working_text = match working {
            Some(workspace) => {
                let text = utf8(workspace, "the workspace directory")?;
                let canonical = workspace.canonicalize().map_err(|source| {
                    invalid_input(format!(
                        "the workspace directory {text} could not be resolved: {source}"
                    ))
                })?;
                if canonical != workspace {
                    return Err(invalid_input(format!(
                        "the workspace directory is {text} but resolves to {}; the interpreters \
                         would name one directory with two strings",
                        canonical.display()
                    )));
                }
                if resolver.approve_host(&canonical).is_err() {
                    return Err(invalid_input(format!(
                        "the workspace directory {text} is outside this box's reachable set, so \
                         every relative path through an interpreter would be refused"
                    )));
                }
                Some(text)
            }
            None => None,
        };

        Ok(Self {
            home: home_text,
            home_source,
            resolver,
            forbidden_identities: forbidden
                .iter()
                .filter_map(|root| disk_identity(root))
                .collect(),
            forbidden,
            forbidden_exactly: protected_sources.to_vec(),
            credential_stores: credential_stores
                .iter()
                .map(|store| folded(store))
                .collect(),
            credential_store_paths: credential_stores,
            credential_store_grants: Vec::new(),
            credential_store_denials: Vec::new(),
            declared_home_stores,
            commands: std::sync::Arc::default(),
            installation: None,
            shared: shared
                .map(|home| utf8(&home, "the operator home"))
                .transpose()?,
            working: working_text,
        })
    }

    pub(super) fn with_commands(
        mut self,
        commands: std::sync::Arc<crate::run::commands::ConfiguredCommands>,
    ) -> Self {
        self.commands = commands;
        self
    }

    pub(super) fn with_installation(
        mut self,
        installation: std::sync::Arc<crate::run::installation::TrustedInstallation>,
    ) -> Self {
        self.installation = Some(installation);
        self
    }

    /// Exempt the credential stores that the agent's `read` and `write` entries name, from every
    /// entry of the agent's filesystem lists.
    pub(super) fn with_credential_store_grants(
        mut self,
        entries: impl IntoIterator<Item = (Grant, String)>,
    ) -> Self {
        for (kind, spelling) in entries {
            let named = match spelling.strip_prefix("~/") {
                Some(relative) => match &self.shared {
                    Some(home) => Path::new(home).join(relative),
                    None => continue,
                },
                None => PathBuf::from(&spelling),
            };
            if kind == Grant::Deny {
                // A `deny` entry may name a path that does not exist yet, so resolve its parent.
                let resolved = named.canonicalize().ok().or_else(|| {
                    let parent = named.parent()?.canonicalize().ok()?;
                    Some(parent.join(named.file_name()?))
                });
                let denied = folded(resolved.as_deref().unwrap_or(&named));
                if self.is_in_a_credential_store(&denied) {
                    self.credential_store_denials.push(denied);
                }
                continue;
            }
            let (mutates, subtree) = match kind {
                Grant::Read => (false, true),
                Grant::ReadFile => (false, false),
                Grant::Write => (true, true),
                Grant::WriteFile => (true, false),
                Grant::List | Grant::Metadata | Grant::Exec | Grant::Deny => continue,
            };
            // An entry that does not resolve exempts nothing, so the floor stays closed.
            let Ok(path) = named.canonicalize() else {
                continue;
            };
            // Configuration admits an entry that names a store or a path inside it, never one above
            // an operator-home store. Above a declared home's store, the sandbox grants it too.
            if !self.is_in_a_credential_store(&path) {
                if subtree {
                    let enclosing = folded(&path);
                    let lifted: Vec<PathBuf> = self
                        .declared_home_stores
                        .iter()
                        .filter(|store| store.starts_with(&enclosing))
                        .cloned()
                        .collect();
                    for store in lifted {
                        self.credential_store_grants.push(CredentialStoreGrant {
                            path: store,
                            mutates,
                            subtree: true,
                        });
                    }
                }
                continue;
            }
            self.credential_store_grants.push(CredentialStoreGrant {
                path: folded(&path),
                mutates,
                subtree,
            });
        }
        self
    }

    /// The directory a relative path means, and what the interpreters report as `PWD`.
    pub(super) fn working_directory(&self) -> &str {
        self.working.as_deref().unwrap_or(&self.home)
    }

    /// The agent's home, at its host path.
    #[cfg(test)]
    pub(super) fn home(&self) -> &str {
        &self.home
    }

    /// The home a reported path is abbreviated against, when this box shares one.
    pub(super) fn reported_home(&self) -> Option<&str> {
        self.shared.as_deref()
    }

    /// The string every participant must read from `HOME`.
    pub(super) fn home_variable(&self) -> &str {
        &self.home
    }

    /// The absolute name a relative spelling means, resolved against the working
    /// directory.
    pub(super) fn absolute(&self, spelled: &str) -> PathBuf {
        let named = Path::new(spelled);
        if named.is_absolute() {
            named.to_path_buf()
        } else {
            // The working directory, not the home, so a relative path means the same file for
            // the script interpreter as it does for the Shell.
            Path::new(self.working_directory()).join(named)
        }
    }

    /// Every root the hosted Shell must bind to the same host path.
    pub(super) fn shell_binds(&self) -> Vec<(&str, &str)> {
        let mut roots = Vec::new();
        for candidate in [
            self.shared.as_deref().map(|path| (path, path)),
            Some((self.home_source.as_str(), self.home.as_str())),
            self.working.as_deref().map(|path| (path, path)),
        ]
        .into_iter()
        .flatten()
        {
            if roots
                .iter()
                .any(|(_, destination)| Path::new(candidate.1).starts_with(destination))
            {
                continue;
            }
            roots.push(candidate);
        }
        roots
    }

    /// Whether this name is backed by a host object at all.
    pub(super) fn names_a_host_path(&self, named: &Path) -> bool {
        self.is_inside_the_set(named)
    }

    /// Approve one interpreter path, returning the host path an effect may act on.
    pub(super) fn approve(&self, named: &Path, reported_as: &str) -> Result<PathBuf, Refused> {
        self.approve_with_source_access(named, reported_as, false)
    }

    /// Approve a path for an operation that can change its bytes or identity.
    pub(super) fn approve_mutation(
        &self,
        named: &Path,
        reported_as: &str,
    ) -> Result<PathBuf, Refused> {
        self.approve_with_source_access(named, reported_as, true)
    }

    fn approve_with_source_access(
        &self,
        named: &Path,
        reported_as: &str,
        mutates: bool,
    ) -> Result<PathBuf, Refused> {
        if mutates
            && self
                .installation
                .as_ref()
                .is_some_and(|installation| installation.refuses_mutation(named))
        {
            return Err(Refused::new(reported_as, TRUSTED_EXECUTABLE));
        }
        if mutates && let Some(refusal) = self.commands.mutation_refusal(named) {
            return Err(Refused::new(reported_as, command_mutation_reason(refusal)));
        }
        if !self.is_inside_the_set(named) {
            return Err(Refused::new(reported_as, OUTSIDE_THE_SET));
        }
        let identity = named
            .strip_prefix(&self.home)
            .map(|relative| Path::new(&self.home_source).join(relative))
            .unwrap_or_else(|_| named.to_path_buf());
        let approved = self
            .resolver
            .approve_host(&identity)
            .map(|approved| approved.as_path().to_path_buf())
            .map_err(|refusal| {
                // A store answers the same whether or not the named path inside it exists.
                if let Err(refused) = self.refuse_credential_store(&identity, reported_as, mutates)
                {
                    return refused;
                }
                let mut refused = Refused::new(reported_as, reason(&refusal));
                refused.unresolved = matches!(refusal, PathRefusal::Unresolvable { .. })
                    && self.is_an_unresolved_answer(&identity);
                refused
            })?;
        // **The deny floor, applied last and on the canonical identity.**
        //
        self.refuse_forbidden(&approved, reported_as, mutates)?;
        Ok(approved)
    }

    /// Refuse a canonical path that resolves into a root no policy may open.
    fn refuse_forbidden(
        &self,
        approved: &Path,
        reported_as: &str,
        mutates: bool,
    ) -> Result<(), Refused> {
        if mutates
            && self
                .installation
                .as_ref()
                .is_some_and(|installation| installation.refuses_mutation(approved))
        {
            return Err(Refused::new(reported_as, TRUSTED_EXECUTABLE));
        }
        if mutates && let Some(refusal) = self.commands.mutation_refusal(approved) {
            return Err(Refused::new(reported_as, command_mutation_reason(refusal)));
        }
        // The authority this run loaded is trusted Box state wherever it sits, so no operation
        // reaches it; changing its enclosing directory is refused too. It keeps its own reason, so
        // the operator learns which file the run loaded rather than which root refused it.
        if self
            .forbidden_exactly
            .iter()
            .any(|forbidden| forbidden.path() == approved || forbidden.matches(approved))
        {
            return Err(Refused::new(reported_as, AUTHORITY_SOURCE));
        }
        if mutates
            && self
                .forbidden_exactly
                .iter()
                .any(|forbidden| lies_within(forbidden.path(), approved))
        {
            return Err(Refused::new(reported_as, AUTHORITY_SOURCE));
        }

        // No exception for a home: `layout::refuse_home_in_box_state` refuses one here first.
        if self.forbidden.iter().any(|root| approved.starts_with(root))
            || has_ancestor_among(approved, &self.forbidden_identities)
        {
            return Err(Refused::new(reported_as, BENEATH_THE_FLOOR));
        }
        if mutates
            && self
                .forbidden
                .iter()
                .any(|root| lies_within(root, approved))
        {
            return Err(Refused::new(reported_as, ENCLOSES_BOX_STATE));
        }

        self.refuse_credential_store(approved, reported_as, mutates)
    }

    /// Refuse a path in a credential store that no `[agent.filesystem]` entry lifts the floor for,
    /// and a change to a directory that holds a store.
    fn refuse_credential_store(
        &self,
        approved: &Path,
        reported_as: &str,
        mutates: bool,
    ) -> Result<(), Refused> {
        let in_store = self.is_in_a_credential_store(approved);
        if in_store && self.store_grant(approved, mutates).is_none() {
            return Err(Refused::new(reported_as, CREDENTIAL_STORE));
        }
        if mutates && !in_store {
            let spelled = folded(approved);
            // A store that exists now is found where it resolves, whatever spelling made it. Only a
            // directory can hold one, so a change to anything else skips those lookups.
            let encloses = self.credential_stores.iter().any(|store| {
                store.starts_with(&spelled) && self.store_grant(store, true).is_none()
            }) || std::fs::symlink_metadata(approved)
                .is_ok_and(|metadata| metadata.is_dir())
                && self.credential_store_paths.iter().any(|store| {
                    store.canonicalize().is_ok_and(|resolved| {
                        resolved != approved
                            && resolved.starts_with(approved)
                            && self.store_grant(&resolved, true).is_none()
                    })
                });
            if encloses {
                return Err(Refused::new(reported_as, ENCLOSES_CREDENTIAL_STORE));
            }
        }
        Ok(())
    }

    /// Refuse a rename that carries credential-store content out of the `write` entry that opened it.
    ///
    /// `destination` is `None` when the Shell names a path the host does not back.
    pub(super) fn refuse_store_relocation(
        &self,
        source: &Path,
        destination: Option<&Path>,
        reported_as: &str,
    ) -> Result<(), Refused> {
        if !self.is_in_a_credential_store(source) {
            return Ok(());
        }
        let same_grant = match (self.store_grant(source, true), destination) {
            (Some(grant), Some(destination)) => self
                .store_grant(destination, true)
                .is_some_and(|other| std::ptr::eq(grant, other)),
            _ => false,
        };
        if same_grant {
            Ok(())
        } else {
            Err(Refused::new(reported_as, CREDENTIAL_STORE_RELOCATION))
        }
    }

    /// The entry that opens `approved` for this kind of operation, unless a `deny` entry covers it.
    fn store_grant(&self, approved: &Path, mutates: bool) -> Option<&CredentialStoreGrant> {
        let spelled = folded(approved);
        if self
            .credential_store_denials
            .iter()
            .any(|denied| spelled.starts_with(denied))
        {
            return None;
        }
        self.credential_store_grants.iter().find(|grant| {
            grant.mutates == mutates
                && (grant.path == spelled || (grant.subtree && spelled.starts_with(&grant.path)))
        })
    }

    /// Whether `approved` is a credential store or lies inside one, by folded spelling or by the
    /// on-disk identity each store has now.
    fn is_in_a_credential_store(&self, approved: &Path) -> bool {
        let spelled = folded(approved);
        if self
            .credential_stores
            .iter()
            .any(|store| spelled.starts_with(store))
        {
            return true;
        }
        // Read at decision time, so a store made later, or under another spelling, still counts.
        let identities: Vec<(u64, u64)> = self
            .credential_store_paths
            .iter()
            .filter_map(|store| disk_identity(store))
            .collect();
        has_ancestor_among(approved, &identities)
    }

    /// Whether a path the resolver could not resolve crosses no symbolic link and lies beneath no deny floor.
    fn is_an_unresolved_answer(&self, identity: &Path) -> bool {
        if identity
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return false;
        }
        let mut prefix = PathBuf::new();
        for component in identity.components() {
            prefix.push(component);
            match std::fs::symlink_metadata(&prefix) {
                Ok(metadata) if metadata.file_type().is_symlink() => return false,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        self.refuse_forbidden(identity, "", false).is_ok()
    }

    /// Whether `named` lies under a root of this box's reachable set.
    fn is_inside_the_set(&self, named: &Path) -> bool {
        [
            Some(self.home.as_str()),
            self.shared.as_deref(),
            self.working.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|root| named.starts_with(root))
    }
}

/// The one refusal every path outside the set gets, spelled once.
const OUTSIDE_THE_SET: &str = "outside this box's home and every declared bind";

const CREDENTIAL_STORE: &str = "resolves into a credential store, which no policy may open \
     unless an `[agent.filesystem]` `read` or `write` entry names that store";

const ENCLOSES_CREDENTIAL_STORE: &str =
    "contains a credential store, so no policy may change this directory";

const CREDENTIAL_STORE_RELOCATION: &str = "would move credential-store content outside the \
     `[agent.filesystem]` `write` entry that names it";

/// `path` case-folded, with each letter that Unicode case folding maps to ASCII replaced by that
/// ASCII, so a store matches every spelling a case-insensitive volume treats as the same name.
fn folded(path: &Path) -> PathBuf {
    let mut text = String::new();
    for character in path.to_string_lossy().chars() {
        match character {
            '\u{17F}' => text.push('s'),
            '\u{212A}' => text.push('k'),
            '\u{130}' => text.push('i'),
            '\u{DF}' | '\u{1E9E}' => text.push_str("ss"),
            '\u{FB00}' => text.push_str("ff"),
            '\u{FB01}' => text.push_str("fi"),
            '\u{FB02}' => text.push_str("fl"),
            '\u{FB03}' => text.push_str("ffi"),
            '\u{FB04}' => text.push_str("ffl"),
            '\u{FB05}' | '\u{FB06}' => text.push_str("st"),
            other => text.extend(other.to_lowercase()),
        }
    }
    PathBuf::from(text)
}

/// A credential store path that the agent's own filesystem lists name.
#[derive(Debug)]
struct CredentialStoreGrant {
    /// The canonical path the entry names.
    path: PathBuf,

    /// Whether the entry is a `write` entry rather than a `read` entry.
    mutates: bool,

    /// Whether the entry covers the paths beneath it.
    subtree: bool,
}

/// The one refusal a path beneath the deny floor gets.
const BENEATH_THE_FLOOR: &str = "resolves into trusted Box state, which no policy may open";

const ENCLOSES_BOX_STATE: &str =
    "contains trusted Box state, so no policy may change this directory";

const TRUSTED_EXECUTABLE: &str = "cannot change a trusted Box executable or its path";

const CONFIGURED_COMMAND: &str =
    "is a configured tool command or its ancestor, which this run does not allow to change";

#[cfg(any(target_os = "macos", target_os = "linux"))]
const CONFIGURED_COMMAND_ALIAS: &str =
    "contains a hard link to a configured tool command, so this mutation is not allowed";

#[cfg(any(target_os = "macos", target_os = "linux"))]
const COMMAND_SCAN_INCOMPLETE: &str =
    "cannot finish checking for configured tool command hard links";

fn command_mutation_reason(refusal: CommandMutationRefusal) -> Cow<'static, str> {
    match refusal {
        CommandMutationRefusal::CommandOrAncestor => CONFIGURED_COMMAND.into(),
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        CommandMutationRefusal::HardLinkAlias => CONFIGURED_COMMAND_ALIAS.into(),
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        CommandMutationRefusal::IncompleteScan(error) => {
            format!("{COMMAND_SCAN_INCOMPLETE}: {error}").into()
        }
    }
}

const AUTHORITY_SOURCE: &str =
    "resolves to an authority source that this run loaded, which no policy may open or change";

/// The roots no interpreter path may resolve into, whatever policy permits.
fn forbidden_roots() -> Vec<PathBuf> {
    crate::record::layout::reserved_host_roots()
}

/// Why the reachable set refused a path, named in the caller's own spelling.
#[derive(Debug)]
pub(super) struct Refused {
    /// The spelling the caller used.
    requested: String,

    /// What is wrong with it, in the operator's and the agent's terms.
    reason: Cow<'static, str>,

    /// Whether the host could not resolve the path, beneath no deny floor and through no symbolic link.
    unresolved: bool,
}

impl Refused {
    fn new(requested: &str, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            requested: requested.to_string(),
            reason: reason.into(),
            unresolved: false,
        }
    }

    /// Whether the refusal only reports that the host could not resolve the path.
    pub(super) fn is_unresolved(&self) -> bool {
        self.unresolved
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.requested, self.reason)
    }
}

/// Carry a resolver refusal into the words a caller reads.
fn reason(refusal: &PathRefusal) -> &'static str {
    match refusal {
        PathRefusal::NotAbsolute(_) => "is not an absolute path",
        PathRefusal::NotCanonical { .. } => {
            "resolves to a different path, so it is not the identity policy judged"
        }
        PathRefusal::Unreachable(_) => OUTSIDE_THE_SET,
        PathRefusal::Unresolvable { .. } => "cannot be resolved to a path this box acts on",
        // Neither can arise once `Reach::over` has built the resolver, and both are
        // reported there instead. Answered rather than ignored, because a silent
        PathRefusal::NoRoot | PathRefusal::RootNotAbsolute(_) => {
            "cannot be judged, because this box declares no reachable root"
        }
    }
}

fn utf8(path: &Path, description: &str) -> io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        invalid_input(format!(
            "{description} is not valid UTF-8: {}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent home, the whole reachable set for a box with no workspace.
    fn fixture() -> (tempfile::TempDir, Reach) {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        let home = resolved.join("home");
        std::fs::create_dir(&home).expect("the agent's home");

        let reach = Reach::over(&home, None, None).expect("the reachable set is usable");
        (root, reach)
    }

    /// **The home is named by its own host path, and it is the only entry.** The second half of
    /// this asserted a bind at `/workspace`.
    #[test]
    fn the_home_keeps_its_host_path_and_is_the_only_bind() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");

        assert_eq!(
            reach.home(),
            resolved.join("home").to_str().expect("UTF-8"),
            "the home must be named by its host path for every participant"
        );
        assert_eq!(
            reach.shell_binds(),
            [(reach.home(), reach.home())],
            "one entry, the home at its own path: a renamed mount point cannot exist"
        );
    }

    #[test]
    fn a_path_outside_the_reachable_set_is_refused_in_the_callers_spelling() {
        let (_root, reach) = fixture();

        let refused = reach
            .approve(Path::new("/etc/passwd"), "/etc/passwd")
            .expect_err("outside the set");
        assert_eq!(
            refused.to_string(),
            format!("/etc/passwd: {OUTSIDE_THE_SET}")
        );
        assert!(
            !reach.names_a_host_path(Path::new("/etc/passwd")),
            "a path outside the set is backed by no host object"
        );
    }

    /// The refusal must name what the caller wrote, not a path derived from it.
    #[test]
    fn a_refusal_names_the_spelling_the_caller_used() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");

        let refused = reach
            .approve(&reach.absolute("absent/f.txt"), "absent/f.txt")
            .expect_err("a missing parent cannot be resolved");
        assert!(
            refused.to_string().starts_with("absent/f.txt: "),
            "the caller's spelling must lead the refusal: {refused}"
        );
        assert!(
            !refused
                .to_string()
                .contains(resolved.to_str().expect("UTF-8")),
            "the resolved host path must not leak into the refusal: {refused}"
        );
    }

    /// A symlink is refused, because the path policy judged is not the path the effect would
    /// touch.
    #[cfg(unix)]
    #[test]
    fn a_symlink_whose_spelling_is_not_its_identity_is_refused() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/secret"), "s").expect("a secret in the home");
        std::os::unix::fs::symlink(resolved.join("home/secret"), resolved.join("home/link"))
            .expect("a link beside the secret it names");

        let named = resolved.join("home/link");
        let refused = reach
            .approve(&named, named.to_str().expect("UTF-8"))
            .expect_err("a link is not its own identity, however reachable both ends are");
        assert!(
            refused
                .to_string()
                .contains("not the identity policy judged"),
            "the refusal must say the spelling is not the identity: {refused}"
        );
    }

    /// A relative spelling means the same file it means in the Shell, because both
    /// resolve it against the working directory.
    #[test]
    fn a_relative_spelling_resolves_against_the_working_directory() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/notes.txt"), "n").expect("a file in the home");

        assert_eq!(
            reach.absolute("notes.txt"),
            resolved.join("home/notes.txt"),
            "a relative path must resolve against the working directory, not the root"
        );
        let approved = reach
            .approve(&reach.absolute("notes.txt"), "notes.txt")
            .expect("a relative path inside the home is reachable");
        assert_eq!(approved, resolved.join("home/notes.txt"));
        let already_absolute = resolved.join("home/notes.txt");
        assert_eq!(
            reach.absolute(already_absolute.to_str().expect("UTF-8")),
            already_absolute,
            "an absolute spelling is already what it means"
        );
    }

    /// A new leaf is approved, because a create names a path that does not exist yet.
    #[test]
    fn a_new_leaf_inside_the_home_is_approved() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        let requested = resolved.join("home/new.txt");

        let approved = reach
            .approve(&requested, requested.to_str().expect("UTF-8"))
            .expect("a create inside the home is reachable");
        assert_eq!(approved, requested);
    }

    /// An ancestor symlink may spell the visible home, while effects use its canonical identity.
    #[cfg(unix)]
    #[test]
    fn an_ancestor_symlink_spelling_binds_to_the_canonical_home_identity() {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::create_dir(resolved.join("real")).expect("real parent");
        std::fs::create_dir(resolved.join("real/home")).expect("the agent's home");
        std::os::unix::fs::symlink(resolved.join("real"), resolved.join("visible"))
            .expect("visible parent");
        let visible = resolved.join("visible/home");
        let canonical = resolved.join("real/home");

        let reach = Reach::over(&visible, None, None).expect("the visible home is reachable");
        assert_eq!(reach.home(), visible.to_str().expect("UTF-8"));
        assert_eq!(
            reach.shell_binds(),
            [(
                canonical.to_str().expect("UTF-8"),
                visible.to_str().expect("UTF-8")
            )]
        );
        assert_eq!(
            reach
                .approve(
                    &visible.join("new.txt"),
                    visible.join("new.txt").to_str().expect("UTF-8"),
                )
                .expect("the visible spelling resolves"),
            canonical.join("new.txt")
        );
    }

    /// A non-canonical spelling of the box home, offered as the workspace, is
    /// refused rather than silently corrected, so the interpreters cannot name one directory two
    /// ways.
    #[cfg(unix)]
    #[test]
    fn a_non_canonical_workspace_spelling_of_the_home_is_refused() {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        let home = resolved.join("home");
        std::fs::create_dir(&home).expect("the box home");
        // A second spelling of the home, through a symlink beside it.
        std::os::unix::fs::symlink(&home, resolved.join("visible")).expect("a link to the home");
        let visible = resolved.join("visible");

        let refusal = Reach::over(&home, None, Some(&visible))
            .expect_err("a workspace that resolves to a different string is refused");
        let message = refusal.to_string();
        assert!(
            message.contains("resolves to") && message.contains("two strings"),
            "the refusal must say the spelling resolves to another, not silently accept it: \
             {message}"
        );
    }

    // ── The deny floor ─────────────────────────────────────────────────────────

    /// A `Reach` whose home is the operator home itself, over a caller-selected box directory that
    /// holds this box's stored policy.
    fn operator_home_fixture() -> (tempfile::TempDir, Reach) {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let private = resolved.join("boxes/codex/private");
        std::fs::create_dir_all(&private).expect("this box's private tree");
        std::fs::write(private.join("policy.dw"), "// the stored rules\n").expect("its policy");
        std::fs::create_dir_all(resolved.join("workspace/service")).expect("a workspace");

        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                None,
                &resolved.join("boxes/codex"),
                &[],
            )
            .expect("the reachable set is usable")
        });
        (operator, reach)
    }

    /// **A path inside the box directory is refused, and no policy is consulted.**
    ///
    /// This is the sharpest hazard of interpreter reach: the interpreters see the whole
    #[test]
    fn a_path_inside_the_box_directory_is_beneath_the_floor() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("boxes/codex/private/policy.dw");

        let refusal = crate::test_support::with_operator_home(&resolved, || {
            reach
                .approve(&target, target.to_str().expect("UTF-8"))
                .expect_err("this box's stored policy must be unreachable")
        })
        .to_string();
        assert!(
            refusal.contains(BENEATH_THE_FLOOR),
            "the refusal must say the floor refused it, not that policy did: {refusal}"
        );
    }

    /// The box directory itself is refused, not merely its contents, whether the caller reads it
    /// or changes it.
    #[test]
    fn the_box_directory_itself_is_beneath_the_floor_for_every_operation() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("boxes/codex");
        let spelled = target.to_str().expect("UTF-8");

        crate::test_support::with_operator_home(&resolved, || {
            assert!(
                reach.approve(&target, spelled).is_err(),
                "the box directory holds this box's state, so reading it must be refused"
            );
            assert!(
                reach.approve_mutation(&target, spelled).is_err(),
                "the box directory holds this box's state, so changing it must be refused"
            );
        });
    }

    /// **The floor makes no exception for a home**: a home declared inside the box directory
    /// reaches nothing there.
    #[test]
    fn a_home_inside_trusted_box_state_reaches_nothing_there() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let box_root = resolved.join("boxes/codex");
        let home = box_root.join("home");
        std::fs::create_dir_all(&home).expect("a home inside the box directory");

        for target in [home.clone(), home.join("note.txt")] {
            let reach = crate::test_support::with_operator_home(&resolved, || {
                Reach::over_box(&home, Some(&resolved), None, &box_root, &[])
                    .expect("the reachable set is declarable")
            });
            let spelled = target.to_str().expect("UTF-8");
            let refusal = crate::test_support::with_operator_home(&resolved, || {
                reach.approve(&target, spelled)
            })
            .err()
            .unwrap_or_else(|| panic!("{spelled} must be beneath the floor"))
            .to_string();
            assert!(refusal.contains(BENEATH_THE_FLOOR), "{spelled}: {refusal}");
        }
    }

    /// Only a path under a missing folder, through no link and beneath no deny floor, is unresolved.
    #[test]
    fn only_a_plain_path_under_a_missing_folder_is_unresolved() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let private = resolved.join("boxes/codex/private");
        std::fs::create_dir(resolved.join("real")).expect("a real folder");
        std::os::unix::fs::symlink(resolved.join("real"), resolved.join("link"))
            .expect("a link in the home");
        std::os::unix::fs::symlink(private.join("nodir"), resolved.join("dangle"))
            .expect("a dangling link into box state");
        let unresolved = |target: PathBuf| {
            let spelled = target.to_str().expect("UTF-8").to_string();
            crate::test_support::with_operator_home(&resolved, || reach.approve(&target, &spelled))
                .err()
                .unwrap_or_else(|| panic!("{spelled} must be refused"))
                .is_unresolved()
        };

        assert!(unresolved(resolved.join("absent-dir/x")));
        assert!(unresolved(resolved.join("absent-dir/deeper/x")));
        for target in [
            private.join("nodir/x"),
            resolved.join("link/nodir/x"),
            resolved.join("link/x"),
            resolved.join("dangle"),
            resolved.join("dangle/x"),
            resolved.join("boxes/codex/private/policy.dw"),
            resolved.join("absent-dir/../boxes/codex/private/policy.dw"),
        ] {
            let spelled = target.display().to_string();
            assert!(!unresolved(target), "{spelled} must not be unresolved");
        }
    }

    /// **A box directory in the macOS data-volume spelling is still beneath the floor** for a path
    /// that names its private state in the ordinary spelling.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_data_volume_box_directory_is_still_beneath_the_floor() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let box_directory = resolved.join("boxes/codex");
        std::fs::create_dir_all(box_directory.join("private")).expect("the box's private state");
        let target = box_directory.join("private/record.json");
        std::fs::write(&target, "{}").expect("a record");
        let data_volume =
            Path::new("/System/Volumes/Data").join(box_directory.strip_prefix("/").unwrap());

        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(&resolved, Some(&resolved), None, &data_volume, &[])
                .expect("the reachable set is declarable")
        });
        let spelled = target.to_str().expect("UTF-8");
        let refusal =
            crate::test_support::with_operator_home(&resolved, || reach.approve(&target, spelled))
                .err()
                .unwrap_or_else(|| panic!("{spelled} must be beneath the floor"))
                .to_string();
        assert!(refusal.contains(BENEATH_THE_FLOOR), "{spelled}: {refusal}");
    }

    /// A symlink into the box directory is refused — **by the resolver, not by the floor.**
    ///
    /// Measured 2026-08-18 by deleting the floor: this test still passed, because
    #[test]
    fn a_symlink_into_the_box_directory_is_refused() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let link = resolved.join("workspace/service/shortcut");
        std::os::unix::fs::symlink(resolved.join("boxes/codex/private"), &link)
            .expect("plant the link");

        let target = link.join("policy.dw");
        assert!(
            crate::test_support::with_operator_home(&resolved, || reach
                .approve(&target, target.to_str().expect("UTF-8"),))
            .is_err(),
            "a link into the box directory must be refused on its canonical identity"
        );
    }

    /// **A sibling box's authority under the reachable set passes the floor**, so policy decides:
    /// only this run's own sources and trusted Box state sit beneath it, whatever a directory is
    /// called.
    #[test]
    fn a_sibling_boxs_authority_passes_the_floor_and_policy_decides() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let sibling = resolved.join("workspace/service/.strands-box");
        std::fs::create_dir_all(&sibling).expect("a sibling box's directory");
        std::fs::write(sibling.join("policy.dw"), "permit(...)").expect("its policy");

        for target in [sibling.clone(), sibling.join("policy.dw")] {
            let spelled = target.to_str().expect("UTF-8");
            reach
                .approve(&target, spelled)
                .unwrap_or_else(|error| panic!("{spelled} is policy's to decide: {error}"));
            reach
                .approve_mutation(&target, spelled)
                .unwrap_or_else(|error| panic!("{spelled} is policy's to decide: {error}"));
        }
    }

    /// **A loaded authority source is beneath the floor wherever it sits**, so a policy read from
    /// beside the project is no more readable than one under it.
    #[test]
    fn a_loaded_authority_source_is_beneath_the_floor_wherever_it_sits() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let policy = resolved.join("workspace/policy.dw");
        std::fs::create_dir_all(resolved.join("workspace")).expect("a workspace");
        std::fs::write(&policy, "permit(...)").expect("a policy beside the project");
        let (source, _text) =
            AuthoritySource::read(&policy, "policy").expect("the authority loads");
        std::fs::create_dir(resolved.join("box")).expect("a box directory");
        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                None,
                &resolved.join("box"),
                &[source],
            )
            .expect("the reachable set is usable")
        });

        let refusal = reach
            .approve(&policy, policy.to_str().expect("UTF-8"))
            .expect_err("the loaded policy must be unreadable through the interpreters")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
        assert!(
            !refusal.contains(BENEATH_THE_FLOOR),
            "a source outside any product directory does not borrow that reason: {refusal}"
        );
        // The enclosing directory keeps its own refusal, and keeps its own reason: a read is fine,
        // and only an operation that could change the source's identity is refused.
        let enclosing = resolved.join("workspace");
        reach
            .approve(&enclosing, enclosing.to_str().expect("UTF-8"))
            .expect("the directory beside the policy stays reachable");
        let refusal = reach
            .approve_mutation(&enclosing, enclosing.to_str().expect("UTF-8"))
            .expect_err("the directory holding a loaded source may not be changed")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
    }

    /// **A policy loaded in the macOS data-volume spelling still guards its directory** against a
    /// change named in the ordinary spelling.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_data_volume_authority_source_still_guards_its_directory() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let enclosing = resolved.join("workspace");
        std::fs::create_dir_all(&enclosing).expect("a workspace");
        std::fs::write(enclosing.join("policy.dw"), "permit(...)").expect("a policy");
        let policy = Path::new("/System/Volumes/Data")
            .join(enclosing.join("policy.dw").strip_prefix("/").unwrap());
        let (source, _text) =
            AuthoritySource::read(&policy, "policy").expect("the authority loads");
        std::fs::create_dir(resolved.join("box")).expect("a box directory");
        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                None,
                &resolved.join("box"),
                &[source],
            )
            .expect("the reachable set is usable")
        });

        let refusal = reach
            .approve_mutation(&enclosing, enclosing.to_str().expect("UTF-8"))
            .expect_err("the directory holding a loaded source may not be changed")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
    }

    /// **A configuration `--config` named outside the workspace is protected identically**: the
    /// source is refused for every operation, and the directory holding it may not be changed.
    #[test]
    fn a_config_loaded_from_outside_the_workspace_is_beneath_the_floor() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let authority = resolved.join("elsewhere/authority");
        std::fs::create_dir_all(&authority).expect("the authority directory");
        std::fs::create_dir_all(resolved.join("workspace")).expect("a workspace");
        let config = authority.join("control.toml");
        std::fs::write(&config, "name = \"elsewhere\"\n").expect("a configuration");
        let (source, _text) = AuthoritySource::read(&config, "config").expect("the config loads");
        std::fs::create_dir(resolved.join("box")).expect("a box directory");
        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                Some(&resolved.join("workspace")),
                &resolved.join("box"),
                &[source],
            )
            .expect("the reachable set is usable")
        });

        let spelled = config.to_str().expect("UTF-8");
        for outcome in [
            reach.approve(&config, spelled),
            reach.approve_mutation(&config, spelled),
        ] {
            let refusal = outcome
                .expect_err("the loaded configuration is beneath the floor")
                .to_string();
            assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
        }
        let spelled = authority.to_str().expect("UTF-8");
        reach
            .approve(&authority, spelled)
            .expect("the directory holding the configuration stays readable");
        let refusal = reach
            .approve_mutation(&authority, spelled)
            .expect_err("the directory holding the configuration may not be changed")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
    }

    /// An ordinary workspace path is still reachable, so the floor is a floor and not a wall.
    #[test]
    fn an_ordinary_project_path_is_still_reachable() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("workspace/service");

        assert!(
            crate::test_support::with_operator_home(&resolved, || reach
                .approve(&target, target.to_str().expect("UTF-8"),))
            .is_ok(),
            "the floor must refuse only trusted Box state and the sources this run loaded"
        );
    }
}

#[cfg(test)]
mod private_tree_mutation_tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Reach, PathBuf) {
        let temporary = tempfile::tempdir().expect("fixture directory");
        let home = temporary.path().canonicalize().expect("canonical fixture");
        let box_root = home.join("grandparent/parent/dummy-box");
        std::fs::create_dir_all(box_root.join("private/child")).expect("dummy directories");
        std::fs::create_dir_all(home.join("sibling")).expect("sibling directory");
        let reach = Reach::over_box(&home, None, None, &box_root, &[]).expect("reachable fixture");
        (temporary, reach, box_root)
    }

    fn refused_by_floor(reach: &Reach, named: &Path, reason: &str) {
        let direct = reach.refuse_forbidden(named, "dummy", true);
        let resolved = reach.approve_mutation(named, "dummy");
        assert!(
            direct.is_err(),
            "direct mutation validation accepted {named:?}"
        );
        assert!(
            resolved.is_err(),
            "resolved mutation validation accepted {named:?}"
        );
        assert_eq!(direct.unwrap_err().to_string(), format!("dummy: {reason}"));
        assert_eq!(
            resolved.unwrap_err().to_string(),
            format!("dummy: {reason}")
        );
    }

    #[test]
    fn parent_mutation_is_refused() {
        let (_temporary, reach, box_root) = fixture();
        refused_by_floor(&reach, box_root.parent().unwrap(), ENCLOSES_BOX_STATE);
    }

    #[test]
    fn grandparent_mutation_is_refused() {
        let (_temporary, reach, box_root) = fixture();
        refused_by_floor(
            &reach,
            box_root.parent().unwrap().parent().unwrap(),
            ENCLOSES_BOX_STATE,
        );
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_mutation_through_a_second_spelling_is_refused() {
        let (temporary, reach, box_root) = fixture();
        let home = temporary.path().canonicalize().unwrap();
        for (name, ancestor) in [
            ("parent-alias", box_root.parent().unwrap()),
            (
                "grandparent-alias",
                box_root.parent().unwrap().parent().unwrap(),
            ),
        ] {
            let alias = home.join(name);
            std::os::unix::fs::symlink(ancestor, &alias).expect("ancestor alias");
            assert!(!box_root.starts_with(&alias));
            assert_eq!(disk_identity(&alias), disk_identity(ancestor));
            let refusal = reach
                .refuse_forbidden(&alias, "dummy", true)
                .expect_err("the ancestor identity must remain protected");
            assert_eq!(refusal.to_string(), format!("dummy: {ENCLOSES_BOX_STATE}"));
            assert!(reach.refuse_forbidden(&alias, "dummy", false).is_ok());
        }
    }

    #[test]
    fn protected_root_mutation_is_refused() {
        let (_temporary, reach, box_root) = fixture();
        refused_by_floor(&reach, &box_root, BENEATH_THE_FLOOR);
    }

    #[test]
    fn protected_descendant_mutation_is_refused() {
        let (_temporary, reach, box_root) = fixture();
        refused_by_floor(&reach, &box_root.join("private/child"), BENEATH_THE_FLOOR);
    }

    #[test]
    fn ancestor_non_mutating_access_is_accepted() {
        let (_temporary, reach, box_root) = fixture();
        for ancestor in [
            box_root.parent().unwrap(),
            box_root.parent().unwrap().parent().unwrap(),
        ] {
            assert!(reach.refuse_forbidden(ancestor, "dummy", false).is_ok());
            assert_eq!(reach.approve(ancestor, "dummy").unwrap(), ancestor);
        }
    }

    #[test]
    fn unaffected_sibling_mutation_is_accepted() {
        let (temporary, reach, _box_root) = fixture();
        let sibling = temporary.path().canonicalize().unwrap().join("sibling");
        assert!(reach.refuse_forbidden(&sibling, "dummy", true).is_ok());
        assert_eq!(reach.approve_mutation(&sibling, "dummy").unwrap(), sibling);
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod linked_command_mutation_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    use crate::record::config::Record;
    use crate::record::config::process::ProcessSpec;
    use crate::run::commands::ConfiguredCommands;

    fn fixture() -> (tempfile::TempDir, Reach, PathBuf) {
        let temporary = tempfile::tempdir().expect("fixture directory");
        let home = temporary.path().canonicalize().expect("canonical fixture");
        let tools = home.join("tools");
        let staging = home.join("staging/nested");
        std::fs::create_dir(&tools).expect("tool directory");
        std::fs::create_dir_all(&staging).expect("alias directory");
        std::fs::create_dir(home.join("output")).expect("unrelated directory");
        let command = tools.join("reader");
        std::fs::write(&command, "#!/bin/sh\nexit 0\n").expect("fixture command");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755))
            .expect("executable command");
        std::fs::hard_link(&command, staging.join("alias")).expect("preexisting hard link");
        let record = Record {
            version: crate::record::config::RECORD_VERSION,
            experimental_features: Default::default(),
            file_attributes: false,
            gateway: Default::default(),
            limits: Default::default(),
            box_id: "linked-command-reach".to_string(),
            box_dir: home.join("box-state"),
            name: "linked-command-reach".to_string(),
            policy: None,
            agent: None,
            tool: BTreeMap::from([(
                "reader".to_string(),
                ProcessSpec {
                    native_filesystem_policy: None,
                    command: vec![command.display().to_string()],
                    workspace: None,
                    env: Default::default(),
                    filesystem: Default::default(),
                    network: None,
                    grammar: None,
                    ingress: Vec::new(),
                },
            )]),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp: Default::default(),
            contained_mcp: Default::default(),
            telemetry: Default::default(),
        };
        let commands = ConfiguredCommands::load(&record).expect("linked command is admitted");
        let reach = Reach::over(&home, None, None)
            .expect("reachable fixture")
            .with_commands(Arc::new(commands));
        (temporary, reach, home)
    }

    fn mutation_refused_for(reach: &Reach, named: &Path, reported_as: &str, reason: &str) {
        for result in [
            reach.approve_mutation(named, reported_as).map(|_| ()),
            reach.refuse_forbidden(named, reported_as, true),
        ] {
            assert_eq!(
                result.expect_err("mutation is refused").to_string(),
                format!("{reported_as}: {reason}")
            );
        }
    }

    #[test]
    fn known_command_paths_keep_the_precise_mutation_refusal() {
        let (_temporary, reach, home) = fixture();
        for (relative, reported_as) in [
            ("tools/reader", "tools/reader"),
            ("tools", "tools"),
            ("", "home"),
        ] {
            mutation_refused_for(
                &reach,
                &home.join(relative),
                reported_as,
                "is a configured tool command or its ancestor, which this run does not allow to change",
            );
        }
    }

    #[test]
    fn a_preexisting_command_alias_and_its_ancestors_refuse_mutation() {
        let (_temporary, reach, home) = fixture();
        for (relative, reason) in [
            ("staging", CONFIGURED_COMMAND_ALIAS),
            ("staging/nested", CONFIGURED_COMMAND_ALIAS),
            ("staging/nested/alias", CONFIGURED_COMMAND),
        ] {
            let named = home.join(relative);
            assert_eq!(
                reach
                    .approve(&named, relative)
                    .expect("reading remains reachable"),
                named
            );
            mutation_refused_for(&reach, &named, relative, reason);
        }
    }

    #[test]
    fn unrelated_directory_and_new_destination_mutations_remain_reachable() {
        let (_temporary, reach, home) = fixture();
        for relative in ["output", "output/new"] {
            let named = home.join(relative);
            assert_eq!(
                reach
                    .approve_mutation(&named, relative)
                    .expect("an unrelated mutation remains reachable"),
                named
            );
            assert!(reach.refuse_forbidden(&named, relative, true).is_ok());
        }
    }

    #[test]
    fn an_unreadable_directory_cannot_be_cleared_for_mutation() {
        let (_temporary, reach, home) = fixture();
        let named = home.join("output");
        std::fs::write(named.join("ordinary"), "ordinary contents").expect("directory entry");
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o000))
            .expect("remove directory access");
        let inaccessible = std::fs::read_dir(&named).is_err();
        let results = [
            reach.approve_mutation(&named, "output").map(|_| ()),
            reach.refuse_forbidden(&named, "output", true),
        ];
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o755))
            .expect("restore fixture access");
        if !inaccessible {
            eprintln!(
                "skipping: this identity can enumerate the mode-000 directory, so the refusal is unmeasured"
            );
            return;
        }
        for result in results {
            let refusal = result
                .expect_err("an incomplete alias scan must refuse the mutation")
                .to_string();
            assert!(
                refusal.starts_with(&format!(
                    "output: {COMMAND_SCAN_INCOMPLETE}: directory inspection failed: "
                )),
                "{refusal}"
            );
        }
    }

    #[test]
    fn an_incomplete_scan_reports_its_cause_without_claiming_to_find_a_command() {
        let (_temporary, reach, home) = fixture();
        let named = home.join("output");
        let mut nested = named.clone();
        for _ in 0..128 {
            nested.push("d");
            std::fs::create_dir(&nested).expect("directory beyond the inspection depth");
        }
        assert_eq!(
            reach
                .approve(&named, "output")
                .expect("reading remains reachable"),
            named
        );
        mutation_refused_for(
            &reach,
            &named,
            "output",
            &format!(
                "{COMMAND_SCAN_INCOMPLETE}: directory inspection failed: directory depth exceeds 128"
            ),
        );
        mutation_refused_for(&reach, &home.join("tools"), "tools", CONFIGURED_COMMAND);
    }
}

#[cfg(test)]
mod credential_store_tests {
    use super::*;

    /// An operator home holding two credential stores and an ordinary file, with a box beside them.
    struct Fixture {
        _operator: tempfile::TempDir,
        home: PathBuf,
        box_root: PathBuf,
    }

    fn fixture() -> Fixture {
        let operator = tempfile::tempdir().expect("an operator home");
        let home = operator.path().canonicalize().expect("the home resolves");
        let box_root = home.join("boxes/codex");
        std::fs::create_dir_all(&box_root).expect("a box directory");
        for store in [".ssh", ".aws", ".config"] {
            std::fs::create_dir_all(home.join(store)).expect("a store");
        }
        std::fs::write(home.join(".ssh/id_rsa"), "key").expect("a key");
        std::fs::write(home.join(".aws/config"), "[default]\n").expect("a config");
        std::fs::write(home.join(".aws/credentials"), "secret").expect("a credential");
        std::fs::write(home.join("notes.txt"), "notes").expect("an ordinary file");
        Fixture {
            _operator: operator,
            home,
            box_root,
        }
    }

    impl Fixture {
        fn reach(&self, grants: &[(Grant, &str)]) -> Reach {
            crate::test_support::with_operator_home(&self.home, || {
                Reach::over_box(&self.home, Some(&self.home), None, &self.box_root, &[])
                    .expect("the reachable set is declarable")
                    .with_credential_store_grants(
                        grants
                            .iter()
                            .map(|(kind, spelling)| (*kind, (*spelling).to_string())),
                    )
            })
        }

        fn read(&self, reach: &Reach, relative: &str) -> Result<PathBuf, String> {
            let target = self.home.join(relative);
            crate::test_support::with_operator_home(&self.home, || reach.approve(&target, relative))
                .map_err(|refused| refused.to_string())
        }

        fn change(&self, reach: &Reach, relative: &str) -> Result<PathBuf, String> {
            let target = self.home.join(relative);
            crate::test_support::with_operator_home(&self.home, || {
                reach.approve_mutation(&target, relative)
            })
            .map_err(|refused| refused.to_string())
        }
    }

    fn refused_as(outcome: Result<PathBuf, String>, reason: &str, what: &str) {
        let refusal = outcome.expect_err(what);
        assert!(refusal.contains(reason), "{what}: {refusal}");
    }

    #[test]
    fn a_credential_store_is_refused_when_the_reachable_set_holds_the_home() {
        let fixture = fixture();
        let reach = fixture.reach(&[]);
        refused_as(
            fixture.read(&reach, ".ssh/id_rsa"),
            CREDENTIAL_STORE,
            "a key read",
        );
        refused_as(
            fixture.read(&reach, ".ssh"),
            CREDENTIAL_STORE,
            "the store itself",
        );
        refused_as(
            fixture.change(&reach, ".aws/config"),
            CREDENTIAL_STORE,
            "a config write",
        );
        refused_as(
            fixture.read(&reach, ".netrc"),
            CREDENTIAL_STORE,
            "an absent store",
        );
        fixture
            .read(&reach, "notes.txt")
            .expect("an ordinary file reads");
        fixture
            .change(&reach, "notes.txt")
            .expect("an ordinary file changes");
        fixture.read(&reach, "").expect("the home itself lists");
    }

    #[test]
    fn a_store_named_by_a_read_entry_reads_and_nothing_else_opens() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::Read, "~/.aws")]);
        fixture
            .read(&reach, ".aws/config")
            .expect("the named store reads");
        fixture
            .read(&reach, ".aws/credentials")
            .expect("the named store reads");
        refused_as(
            fixture.change(&reach, ".aws/config"),
            CREDENTIAL_STORE,
            "a read entry writes",
        );
        refused_as(
            fixture.read(&reach, ".ssh/id_rsa"),
            CREDENTIAL_STORE,
            "another store reads",
        );
    }

    #[test]
    fn a_store_named_by_a_write_entry_changes_and_does_not_read() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::Write, "~/.aws")]);
        fixture
            .change(&reach, ".aws/config")
            .expect("the named store changes");
        refused_as(
            fixture.read(&reach, ".aws/config"),
            CREDENTIAL_STORE,
            "write implies read",
        );
    }

    #[test]
    fn a_file_entry_exempts_that_file_alone() {
        let fixture = fixture();
        let absolute = fixture.home.join(".aws/config");
        let reach = fixture.reach(&[(Grant::ReadFile, absolute.to_str().expect("UTF-8"))]);
        fixture
            .read(&reach, ".aws/config")
            .expect("the named file reads");
        refused_as(
            fixture.read(&reach, ".aws/credentials"),
            CREDENTIAL_STORE,
            "a sibling",
        );
        refused_as(
            fixture.read(&reach, ".aws"),
            CREDENTIAL_STORE,
            "the store directory",
        );
    }

    #[test]
    fn a_list_or_metadata_entry_exempts_no_interpreter_read() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::List, "~/.aws"), (Grant::Metadata, "~/.ssh")]);
        refused_as(
            fixture.read(&reach, ".aws/config"),
            CREDENTIAL_STORE,
            "a list entry",
        );
        refused_as(
            fixture.read(&reach, ".ssh/id_rsa"),
            CREDENTIAL_STORE,
            "a metadata entry",
        );
    }

    #[test]
    fn a_linked_store_is_refused_at_the_directory_it_names() {
        let fixture = fixture();
        let target = fixture.home.join("dotfiles/kube");
        std::fs::create_dir_all(&target).expect("a link target");
        std::fs::write(target.join("config"), "token").expect("a kube config");
        std::os::unix::fs::symlink(&target, fixture.home.join(".kube")).expect("a linked store");
        let reach = fixture.reach(&[]);
        refused_as(
            fixture.read(&reach, "dotfiles/kube/config"),
            CREDENTIAL_STORE,
            "the store's target",
        );
        refused_as(
            fixture.change(&reach, "dotfiles"),
            ENCLOSES_CREDENTIAL_STORE,
            "its parent",
        );
        fixture
            .read(&reach, ".kube/config")
            .expect_err("the link spelling is refused too");
    }

    #[test]
    fn a_link_planted_into_a_store_reaches_nothing() {
        let fixture = fixture();
        std::os::unix::fs::symlink(fixture.home.join(".ssh/id_rsa"), fixture.home.join("key"))
            .expect("a planted link");
        let reach = fixture.reach(&[]);
        fixture
            .read(&reach, "key")
            .expect_err("a link into a store is refused");
    }

    #[test]
    fn a_directory_that_holds_a_store_cannot_be_changed() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::Write, "~/.aws")]);
        refused_as(
            fixture.change(&reach, ".config"),
            ENCLOSES_CREDENTIAL_STORE,
            "~/.config",
        );
        fixture
            .read(&reach, ".config")
            .expect("the directory still lists");
        fixture
            .change(&reach, ".config/settings.json")
            .expect("a file beside the store changes");
        fixture
            .change(&reach, ".aws")
            .expect("a store named by a write entry changes itself");
    }

    #[test]
    fn a_store_is_refused_in_every_letter_case_whether_or_not_it_exists() {
        let fixture = fixture();
        let reach = fixture.reach(&[]);
        refused_as(
            fixture.change(&reach, ".KUBE"),
            CREDENTIAL_STORE,
            "an absent store, upper case",
        );
        refused_as(
            fixture.change(&reach, ".KUBE/config"),
            CREDENTIAL_STORE,
            "a file in an absent store, upper case",
        );
        refused_as(
            fixture.change(&reach, ".Aws/config"),
            CREDENTIAL_STORE,
            "mixed case",
        );
        refused_as(
            fixture.read(&reach, ".SSH/id_rsa"),
            CREDENTIAL_STORE,
            "a read in upper case",
        );
    }

    #[test]
    fn a_store_is_refused_under_each_unicode_spelling_that_folds_to_its_name() {
        let fixture = fixture();
        std::fs::remove_dir_all(fixture.home.join(".aws")).expect("an absent store");
        let reach = fixture.reach(&[]);
        for spelling in [
            ".aw\u{17F}",
            ".aw\u{17F}/config",
            ".\u{DF}h/authorized_keys",
            ".\u{212A}ube/config",
            "Library/Application Support/\u{FB01}refox/profiles.ini",
        ] {
            refused_as(fixture.change(&reach, spelling), CREDENTIAL_STORE, spelling);
        }
    }

    #[test]
    fn a_store_linked_after_startup_is_refused_where_it_resolves() {
        let fixture = fixture();
        let reach = fixture.reach(&[]);
        let target = fixture.home.join("dotfiles/kube");
        std::fs::create_dir_all(&target).expect("a link target");
        std::fs::write(target.join("config"), "token").expect("a kube config");
        std::os::unix::fs::symlink(&target, fixture.home.join(".kube")).expect("a late link");
        refused_as(
            fixture.read(&reach, "dotfiles/kube/config"),
            CREDENTIAL_STORE,
            "the late store's target",
        );
        refused_as(
            fixture.change(&reach, "dotfiles"),
            ENCLOSES_CREDENTIAL_STORE,
            "the directory that now holds it",
        );
    }

    #[test]
    fn a_missing_path_in_a_store_answers_like_a_present_one() {
        let fixture = fixture();
        let reach = fixture.reach(&[]);
        refused_as(
            fixture.read(&reach, ".gnupg/x"),
            CREDENTIAL_STORE,
            "an absent store",
        );
        refused_as(
            fixture.read(&reach, ".aws/missing"),
            CREDENTIAL_STORE,
            "a missing file",
        );
    }

    #[test]
    fn a_deny_entry_inside_a_named_store_stays_refused() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::Read, "~/.aws"), (Grant::Deny, "~/.aws/credentials")]);
        fixture
            .read(&reach, ".aws/config")
            .expect("the rest of the store reads");
        refused_as(
            fixture.read(&reach, ".aws/credentials"),
            CREDENTIAL_STORE,
            "the denied file",
        );
        refused_as(
            fixture.read(&reach, ".AWS/credentials"),
            CREDENTIAL_STORE,
            "the denied file, upper case",
        );
    }

    #[test]
    fn a_write_entry_cannot_move_its_contents_out() {
        let fixture = fixture();
        let cache = fixture.home.join(".aws/sso/cache");
        std::fs::create_dir_all(&cache).expect("a cache");
        std::fs::write(cache.join("token.json"), "token").expect("a token");
        let reach = fixture.reach(&[(Grant::Write, "~/.aws/sso/cache")]);
        let source = fixture
            .change(&reach, ".aws/sso/cache/token.json")
            .expect("the source");
        let outside = fixture
            .change(&reach, "stolen.json")
            .expect("the destination");
        let inside = fixture
            .change(&reach, ".aws/sso/cache/renamed.json")
            .expect("inside");
        reach
            .refuse_store_relocation(&source, Some(&outside), "stolen.json")
            .expect_err("a file leaves the store");
        reach
            .refuse_store_relocation(&source, None, "/tmp/stolen.json")
            .expect_err("a file leaves for a path the host does not back");
        let directory = fixture
            .change(&reach, ".aws/sso/cache")
            .expect("the directory");
        let copy = fixture.change(&reach, "cache-copy").expect("a destination");
        reach
            .refuse_store_relocation(&directory, Some(&copy), "cache-copy")
            .expect_err("the whole directory leaves the store");
        reach
            .refuse_store_relocation(&source, Some(&inside), "renamed.json")
            .expect("a rename inside the entry stays allowed");
        let notes = fixture
            .change(&reach, "notes.txt")
            .expect("an ordinary file");
        reach
            .refuse_store_relocation(&notes, Some(&outside), "stolen.json")
            .expect("an ordinary rename is not judged");
    }

    #[test]
    fn an_entry_outside_every_store_exempts_nothing() {
        let fixture = fixture();
        let reach = fixture.reach(&[(Grant::Read, "~/.config"), (Grant::Read, "~")]);
        assert!(
            reach.credential_store_grants.is_empty(),
            "{:?}",
            reach.credential_store_grants
        );
    }

    #[test]
    fn a_declared_home_carries_its_own_stores() {
        let fixture = fixture();
        let agent_home = fixture.home.join("agent-home");
        std::fs::create_dir_all(agent_home.join(".ssh")).expect("a store in the declared home");
        std::fs::write(agent_home.join(".ssh/id_rsa"), "key").expect("a key");
        let reach = crate::test_support::with_operator_home(&fixture.home, || {
            Reach::over_box(
                &agent_home,
                Some(&fixture.home),
                None,
                &fixture.box_root,
                &[],
            )
            .expect("the reachable set is declarable")
        });
        refused_as(
            fixture.read(&reach, "agent-home/.ssh/id_rsa"),
            CREDENTIAL_STORE,
            "a key under the declared home",
        );
        let granted =
            reach.with_credential_store_grants([(Grant::Read, "~/agent-home/.ssh".to_string())]);
        fixture
            .read(&granted, "agent-home/.ssh/id_rsa")
            .expect("a store under the declared home reads when an entry names it");
    }

    #[test]
    fn an_entry_enclosing_a_declared_home_lifts_the_floor_for_its_stores_only() {
        let fixture = fixture();
        let agent_home = fixture.home.join("agent-home");
        for store in [".aws", ".config/gcloud"] {
            std::fs::create_dir_all(agent_home.join(store)).expect("a declared-home store");
        }
        std::fs::write(agent_home.join(".aws/config"), "[default]\n").expect("a config");
        let reach = crate::test_support::with_operator_home(&fixture.home, || {
            Reach::over_box(
                &agent_home,
                Some(&fixture.home),
                None,
                &fixture.box_root,
                &[],
            )
            .expect("the reachable set is declarable")
            .with_credential_store_grants([
                (Grant::Read, "~/agent-home".to_string()),
                (Grant::Write, "~/agent-home".to_string()),
            ])
        });
        fixture
            .read(&reach, "agent-home/.aws/config")
            .expect("the sandbox reaches this store, so the interpreters do too");
        fixture
            .change(&reach, "agent-home/.aws/config")
            .expect("a write entry on the declared home lifts the floor for changes");
        fixture
            .change(&reach, "agent-home/.config/settings.json")
            .expect("a file beside a lifted store changes");
        fixture
            .change(&reach, "agent-home/.config")
            .expect("a directory holding only lifted stores changes");
        refused_as(
            fixture.read(&reach, ".ssh/id_rsa"),
            CREDENTIAL_STORE,
            "an operator-home store",
        );
        refused_as(
            fixture.change(&reach, ".aws/config"),
            CREDENTIAL_STORE,
            "an operator-home store",
        );
        refused_as(
            fixture.change(&reach, ".config"),
            ENCLOSES_CREDENTIAL_STORE,
            "a directory holding an operator-home store",
        );
    }
}
