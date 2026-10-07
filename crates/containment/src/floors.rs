//! The deny-only floors every request clears, beneath every backend, and the one warning it carries.
//!
//! A floor is not part of what a [`ContainmentConfig`] *is*, so none of this sits on that public
//! type: a config refuses a malformed grant when it is built, and these refuse a grant *set* that
//! combines into more than any one member states. [`crate::facade::apply_backend`] is the only caller
//! of the floors; [`ContainmentConfig::warnings`] is the one caller of [`warnings`].

use crate::config::ContainmentConfig;
use crate::error::ContainmentError;
use crate::model::{Operation, PathGrant, Scope};
use crate::os_paths::{Forbidden, ForbiddenClass, Match, forbidden_paths};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, ContainmentError>;

/// Apply every floor this request must clear, in the order their cost demands.
///
/// **The two pure checks run before the two that touch the filesystem.** A grant naming `/` is
/// refused without a single `canonicalize`, which matters because a grant's path may be
/// workload-influenced: refusing it should not require acting on it first.
///
/// One method rather than a list at the call site, so a fifth floor arrives here beside the
/// reason for its position.
pub(crate) fn require_all(config: &ContainmentConfig) -> Result<()> {
    config.validate_platform_credential_grants()?;
    require_bounded_grants(config)?;
    require_no_conflicting_grants(config)?;
    config.require_live_path_identities()?;
    require_no_identity_changing_executables(config)
}

/// Refuse every grant that hands over a system tree or the whole filesystem.
///
/// A deny-only floor, so it runs beneath each backend rather than inside one.
fn require_bounded_grants(config: &ContainmentConfig) -> Result<()> {
    // **A denial is exempt, and that is the whole point of the exemption.** This floor refuses a
    // grant that hands over too much; a `Deny` hands over nothing, so the broader it is the safer it
    // is. Judging one here would refuse `deny /`, which is the strongest entry a caller can write.
    for granted in config.authorizations() {
        require_bounded_grant(
            granted,
            config.operator_home(),
            config.credential_store_exempts(granted),
        )?;
    }
    Ok(())
}

/// A grant set that renders, and that its caller discloses rather than refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainmentWarning {
    /// One path is both writable and executable, so the workload may replace a program it runs.
    WritableAndExecutable {
        /// The exec grant, by the spelling that reaches the writable path.
        executable: PathBuf,
        /// The write grant that reaches it.
        writable: PathBuf,
    },
}

impl std::fmt::Display for ContainmentWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WritableAndExecutable {
                executable,
                writable,
            } => write!(
                formatter,
                "{} is both writable and executable: the write grant {} reaches it, so the workload \
                 can replace a program it is authorized to run",
                executable.display(),
                writable.display()
            ),
        }
    }
}

/// Every pair of grants that renders and that the caller should disclose.
///
/// **Write-plus-exec on one path is a warning and no longer a refusal.** Pairwise over (exec grant,
/// write grant) is complete for the *grant set*, because "writable" is exactly "inside some write
/// grant" and `starts_with` over the union covers it. The caller spelling counts as well, because
/// an execute grant renders `file-read-metadata` on it when the two differ, and both spellings of a
/// write root are rendered. What this does not cover is a reachable interpreter that is universal
/// over authored data — a separate residual this crate records.
pub(crate) fn warnings(config: &ContainmentConfig) -> Vec<ContainmentWarning> {
    let executables: Vec<&PathGrant> = [Scope::File, Scope::Root]
        .into_iter()
        .flat_map(|scope| config.grants_in(Operation::Exec, scope))
        .collect();
    let writables: Vec<&PathGrant> = [Scope::File, Scope::Root]
        .into_iter()
        .flat_map(|scope| config.grants_in(Operation::Write, scope))
        .collect();
    let mut warnings = Vec::new();
    for executable in &executables {
        for writable in &writables {
            let reaches = |path: &Path, spelling: &Path| match writable.scope {
                Scope::Root => path.starts_with(spelling),
                _ => path == spelling,
            };
            let spelling = if reaches(&executable.resolved, &writable.resolved) {
                Some((&executable.resolved, &writable.resolved))
            } else if executable.original != executable.resolved
                && (reaches(&executable.original, &writable.original)
                    || reaches(&executable.original, &writable.resolved))
            {
                Some((&executable.original, &writable.original))
            } else if executable.scope == Scope::Root
                && writable.resolved.starts_with(&executable.resolved)
            {
                Some((&executable.resolved, &writable.resolved))
            } else {
                None
            };
            if let Some((executable, writable)) = spelling {
                warnings.push(ContainmentWarning::WritableAndExecutable {
                    executable: executable.clone(),
                    writable: writable.clone(),
                });
            }
        }
    }
    warnings
}

/// Refuse a grant set whose members, taken together, permit more than any one states.
///
/// A deny-only floor, so it runs beneath every backend. Two `allow` rules cannot narrow each
/// other, so a profile rendered from grants that disagree about a path enforces their union.
fn require_no_conflicting_grants(config: &ContainmentConfig) -> Result<()> {
    let write_roots = config.grants_in(Operation::Write, Scope::Root);

    for writable in &write_roots {
        // **A write FILE may not sit inside a write root.** The file cell denies its own literal's
        // mode, owner, and identity, and a specific deny beats the enclosing root's `file-write*`,
        // so the nested path silently loses authority every sibling in the tree keeps. This is the
        // mirror of the rule below, and it became reachable when the file cell gained those denies.
        for nested in &config.grants_in(Operation::Write, Scope::File) {
            if nested.resolved.starts_with(&writable.resolved) {
                return Err(ContainmentError::ConflictingGrants {
                    reason: format!(
                        "write grant {} lies inside the write root {}; the file cell's denies would \
                     override the root's grant, so the nested path loses authority its siblings keep",
                        nested.resolved.display(),
                        writable.resolved.display(),
                    ),
                });
            }
        }
        // **Two write roots may not nest.** The union is the outer one, so the inner grant states a
        // narrowing the profile does not enforce, and a reader of the config would predict a
        // boundary that is not there.
        for other in &write_roots {
            if !std::ptr::eq::<PathGrant>(*writable, *other)
                && writable.resolved.starts_with(&other.resolved)
            {
                return Err(ContainmentError::ConflictingGrants {
                    reason: format!(
                        "write root {} lies inside the write root {}; the union is the outer root, \
                     so the inner grant enforces nothing it appears to",
                        writable.resolved.display(),
                        other.resolved.display(),
                    ),
                });
            }
        }
    }
    Ok(())
}

const SET_USER_ID: u32 = 0o4000;
const SET_GROUP_ID: u32 = 0o2000;

/// Refuse an execute grant on a file that changes the identity of the process that runs it.
///
/// A deny-only floor, so it runs beneath each backend rather than inside one. An exec tree is
/// walked, because every regular file under it is a program the grant authorizes.
fn require_no_identity_changing_executables(config: &ContainmentConfig) -> Result<()> {
    for granted in config.grants_in(Operation::Exec, Scope::File) {
        require_no_identity_change(&granted.resolved, &granted.resolved)?;
    }
    for granted in config.grants_in(Operation::Exec, Scope::Root) {
        let mut pending = vec![granted.resolved.clone()];
        while let Some(directory) = pending.pop() {
            let entries = std::fs::read_dir(&directory).map_err(|source| {
                ContainmentError::ConfigValidation(format!(
                    "cannot enumerate {} under the execute grant {}: {source}",
                    directory.display(),
                    granted.resolved.display()
                ))
            })?;
            for entry in entries {
                let path = entry
                    .map_err(|source| {
                        ContainmentError::ConfigValidation(format!(
                            "cannot enumerate {} under the execute grant {}: {source}",
                            directory.display(),
                            granted.resolved.display()
                        ))
                    })?
                    .path();
                // Links are not followed: a link's target is judged where it lies, or is absent
                // from the grant altogether.
                let kind = std::fs::symlink_metadata(&path)
                    .map_err(|source| {
                        ContainmentError::ConfigValidation(format!(
                            "cannot read the mode of {} under the execute grant {}: {source}",
                            path.display(),
                            granted.resolved.display()
                        ))
                    })?
                    .file_type();
                if kind.is_dir() {
                    pending.push(path);
                } else if kind.is_file() {
                    require_no_identity_change(&path, &granted.resolved)?;
                }
            }
        }
    }
    Ok(())
}

/// Refuse one regular file that carries set-user-ID or set-group-ID.
fn require_no_identity_change(path: &Path, granted: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let mode = std::fs::metadata(path)
        .map_err(|source| {
            ContainmentError::ConfigValidation(format!(
                "cannot read the mode of the execute grant {}: {source}",
                path.display()
            ))
        })?
        .mode();
    if mode & (SET_USER_ID | SET_GROUP_ID) != 0 {
        return Err(ContainmentError::ConfigValidation(format!(
            "the execute grant {} carries set-user-ID or set-group-ID at {}, so running it would \
             change the identity the workload runs under; an execute grant authorizes programs \
             and never a second identity",
            granted.display(),
            path.display()
        )));
    }
    Ok(())
}

impl Forbidden {
    /// This entry's path, joined lexically so an absent directory is still refused.
    fn lexical(&self, operator_home: &Path) -> PathBuf {
        match self.anchor.strip_prefix("~/") {
            Some(relative) => operator_home.join(relative),
            None => PathBuf::from(&self.anchor),
        }
    }

    /// This entry's path under the identity a grant carries.
    fn resolve(&self, operator_home: &Path) -> PathBuf {
        let lexical = self.lexical(operator_home);
        // A grant carries its canonical identity, so the anchor must too. A dotfile manager makes
        // `~/.ssh` a symlink, and a lexical anchor then matched nothing the grant resolved to.
        lexical.canonicalize().unwrap_or(lexical)
    }

    /// Whether this entry and a grant share a path, as this entry's `rule` defines sharing.
    fn covers(&self, protected: &Path, granted: &Path, operation: Operation, scope: Scope) -> bool {
        if self.permits.contains(&(operation, scope)) {
            return false;
        }
        let granted_reaches_down = scope == Scope::Root;
        match self.rule {
            Match::ExactPath => protected == granted,
            Match::AnyOverlap => {
                granted.starts_with(protected)
                    || (granted_reaches_down && protected.starts_with(granted))
            }
        }
    }
}

/// Every row beside the anchor it was resolved against, one pair per row per anchor.
type ResolvedAnchors = Vec<(&'static Forbidden, PathBuf)>;

/// Every row beside its resolved anchor, once per home. Cached for the homes a box has, and
/// recomputed for any others, because a test passes a fixture home and a stale anchor would judge
/// the wrong tree.
fn resolved_anchors(homes: &[PathBuf]) -> ResolvedAnchors {
    static ANCHORS: std::sync::OnceLock<(Vec<PathBuf>, ResolvedAnchors)> =
        std::sync::OnceLock::new();
    let resolve = |homes: &[PathBuf]| -> ResolvedAnchors {
        homes
            .iter()
            .flat_map(|home| {
                forbidden_paths().iter().flat_map(move |entry| {
                    let anchor = entry.resolve(home);
                    // Every row twice, because the data volume reaches the same file by a second
                    // name and `canonicalize` does not collapse a firmlink. Without this, `/private`
                    // is refused and `/System/Volumes/Data/private` is not.
                    let through_the_data_volume = data_volume_spelling(&anchor);
                    [
                        Some((entry, anchor)),
                        through_the_data_volume.map(|path| (entry, path)),
                    ]
                })
            })
            .flatten()
            .collect()
    };
    let (cached_homes, cached) = ANCHORS.get_or_init(|| (homes.to_vec(), resolve(homes)));
    if cached_homes == homes {
        return cached.clone();
    }
    resolve(homes)
}

/// The mount point of the data volume, which reaches the same files by a second name.
const DATA_VOLUME_ROOT: &str = "/System/Volumes/Data";

/// This path as the data volume also spells it, or nothing when it is already that spelling.
pub(crate) fn data_volume_spelling(path: &Path) -> Option<PathBuf> {
    if path.starts_with(DATA_VOLUME_ROOT) {
        return None;
    }
    Some(Path::new(DATA_VOLUME_ROOT).join(path.strip_prefix("/").ok()?))
}

/// Every spelling for every active home anchor.
pub(crate) fn operator_home_spellings(declared_home: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut spellings = Vec::new();
    for home in anchor_homes(declared_home)? {
        if home.starts_with(DATA_VOLUME_ROOT) {
            return Err(ContainmentError::ConfigValidation(format!(
                "the operator's home is already spelled through {DATA_VOLUME_ROOT}: {}. A second \
                 name is what refuses the existence test at the firmlink spelling, so one name \
                 would leave it answering",
                home.display()
            )));
        }
        for spelling in [Some(home.clone()), data_volume_spelling(&home)] {
            if let Some(spelling) = spelling
                && !spellings.contains(&spelling)
            {
                spellings.push(spelling);
            }
        }
    }
    Ok(spellings)
}

/// Every credential store under every active home anchor.
pub(crate) fn credential_store_paths(declared_home: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for home in operator_home_spellings(declared_home)? {
        for path in credential_store_paths_under(&home) {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        return Err(ContainmentError::ConfigValidation(
            "the floor names no credential store, so nothing would refuse an existence test there"
                .to_string(),
        ));
    }
    Ok(paths)
}

/// The same set anchored at a caller-supplied home, so a test can spell one it controls.
fn credential_store_paths_under(operator_home: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in forbidden_paths()
        .iter()
        .filter(|entry| entry.rule == Match::AnyOverlap)
    {
        for spelling in [entry.lexical(operator_home), entry.resolve(operator_home)] {
            if !paths.contains(&spelling) {
                paths.push(spelling);
            }
        }
    }
    paths
}

/// Why the floor refuses this grant, if it does.
pub(crate) fn forbidden_path_refusal(
    homes: &[PathBuf],
    granted: &Path,
    operation: Operation,
    scope: Scope,
) -> Option<ForbiddenClass> {
    resolved_anchors(homes)
        .iter()
        .find(|(entry, anchor)| entry.covers(anchor, granted, operation, scope))
        .map(|(entry, _)| entry.class)
}

/// Why the floor refuses a `~/`-relative spelling, if it does.
///
/// Judges the spelling rather than a resolved path, so an authoring-time caller needs no home.
pub fn home_relative_path_refusal(spelling: &str) -> Option<&'static str> {
    let relative = spelling.strip_prefix("~/").unwrap_or(spelling);
    forbidden_paths().iter().find_map(|entry| {
        let forbidden = entry.anchor.strip_prefix("~/")?;
        (relative == forbidden
            || relative
                .strip_prefix(forbidden)
                .is_some_and(|rest| rest.starts_with('/')))
        .then_some(entry.reason())
    })
}

/// Validate one grant against the floors before it is composed, and report whether it names a
/// credential store exactly.
pub fn validate_grant(
    path: &Path,
    operator_home: &Path,
    operation: Operation,
    scope: Scope,
) -> Result<bool> {
    if matches!(operation, Operation::Deny) {
        return Err(ContainmentError::ConfigValidation(format!(
            "a grant never carries Deny: {}",
            path.display()
        )));
    }
    let credential_store = credential_store_path(path, operator_home)?;
    if path.exists() {
        let grant = PathGrant::new(path, operation, scope)?;
        if credential_store {
            if !credential_store_path(&grant.resolved, operator_home)? {
                return Err(ContainmentError::ConfigValidation(format!(
                    "{} resolves outside every credential store: {}",
                    path.display(),
                    grant.resolved.display()
                )));
            }
            if !credential_store_grant_stays_in_store(&grant, Some(operator_home))? {
                return Err(ContainmentError::ConfigValidation(format!(
                    "{} resolves into a different credential store: {}",
                    path.display(),
                    grant.resolved.display()
                )));
            }
        }
        require_bounded_grant(
            &grant,
            Some(operator_home),
            credential_store && matches!(operation, Operation::Read | Operation::Write),
        )?;
    }
    Ok(credential_store)
}

fn credential_store_path(path: &Path, operator_home: &Path) -> Result<bool> {
    if !path.is_absolute() || !operator_home.is_absolute() {
        return Err(ContainmentError::ConfigValidation(format!(
            "a grant path and the operator home must be absolute: path {}, home {}",
            path.display(),
            operator_home.display()
        )));
    }

    let mut anchors = Vec::new();
    for entry in forbidden_paths()
        .iter()
        .filter(|entry| entry.class == ForbiddenClass::CredentialStore)
    {
        for anchor in [entry.lexical(operator_home), entry.resolve(operator_home)] {
            if !anchors.contains(&anchor) {
                anchors.push(anchor.clone());
            }
            if let Some(other) = data_volume_spelling(&anchor)
                && !anchors.contains(&other)
            {
                anchors.push(other);
            }
        }
    }

    let classify = |candidate: &Path| {
        let inside = anchors.iter().any(|anchor| candidate.starts_with(anchor));
        let contains = anchors
            .iter()
            .any(|anchor| anchor != candidate && anchor.starts_with(candidate));
        (inside, contains)
    };
    let (inside, contains) = classify(path);
    if contains && !inside {
        return Err(ContainmentError::ConfigValidation(format!(
            "{} contains a credential store but does not name its exact anchor or a path under it",
            path.display()
        )));
    }
    if inside {
        return Ok(true);
    }

    if let Ok(resolved) = path.canonicalize() {
        let (resolved_inside, resolved_contains) = classify(&resolved);
        if resolved_inside || resolved_contains {
            return Err(ContainmentError::ConfigValidation(format!(
                "{} reaches a credential store through another spelling; name the exact store path",
                path.display()
            )));
        }
    }
    Ok(false)
}

#[cfg(test)]
pub(crate) fn same_credential_store(
    original: &Path,
    resolved: &Path,
    declared_home: Option<&Path>,
) -> Result<bool> {
    let original = credential_store_identities(original, declared_home)?;
    let resolved = credential_store_identities(resolved, declared_home)?;
    Ok(original.len() == 1 && original == resolved)
}

/// Whether one grant stays in its original credential store at every traversal node.
pub(crate) fn credential_store_grant_stays_in_store(
    granted: &PathGrant,
    declared_home: Option<&Path>,
) -> Result<bool> {
    let original = credential_store_identities(&granted.original, declared_home)?;
    if original.len() != 1
        || credential_store_identities(&granted.resolved, declared_home)? != original
    {
        return Ok(false);
    }
    for path in granted.traversal_paths() {
        let identities = credential_store_identities(&path, declared_home)?;
        if !identities.is_empty() && identities != original {
            return Ok(false);
        }
    }
    Ok(true)
}

fn credential_store_identities(
    path: &Path,
    declared_home: Option<&Path>,
) -> Result<BTreeSet<(PathBuf, &'static str)>> {
    let mut identities = BTreeSet::new();
    for home in anchor_homes(declared_home)? {
        for entry in forbidden_paths()
            .iter()
            .filter(|entry| entry.class == ForbiddenClass::CredentialStore)
        {
            for anchor in [entry.lexical(&home), entry.resolve(&home)] {
                if path.starts_with(&anchor) {
                    identities.insert((home.clone(), entry.anchor.as_str()));
                }
                if let Some(other) = data_volume_spelling(&anchor)
                    && path.starts_with(other)
                {
                    identities.insert((home.clone(), entry.anchor.as_str()));
                }
            }
        }
    }
    Ok(identities)
}

/// Whether a serialized exception names a credential store under any active home anchor.
pub(crate) fn credential_store_exception_path(
    path: &Path,
    declared_home: Option<&Path>,
) -> Result<bool> {
    for home in anchor_homes(declared_home)? {
        match credential_store_path(path, &home) {
            Ok(true) => return Ok(true),
            Ok(false) | Err(ContainmentError::ConfigValidation(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// Every home a `~/`-relative row is anchored at: the passwd database's, plus the caller's when it
/// differs.
///
/// Additive, so a caller naming a home widens the refusal set and can never narrow it.
fn anchor_homes(declared: Option<&Path>) -> Result<Vec<PathBuf>> {
    let passwd = operator_home()?;
    let mut homes = vec![passwd.to_path_buf()];
    if let Some(declared) = declared {
        // Refused rather than skipped, on both routes into this function: a relative anchor resolves
        // against the applying process's working directory, and skipping one would weaken the floor
        // in silence. The wire refuses it at load too, so this covers the in-process builder.
        if declared.as_os_str().is_empty() || !declared.is_absolute() {
            return Err(ContainmentError::ConfigValidation(format!(
                "the stated operator home must be an absolute path: {}",
                declared.display()
            )));
        }
        if declared != passwd {
            homes.push(declared.to_path_buf());
        }
    }
    Ok(homes)
}

/// The operator's home, from the passwd database, looked up once per process.
///
/// Not `$HOME`: the trampoline applies a config whose workload home is the box's own.
pub(crate) fn operator_home() -> Result<&'static Path> {
    static HOME: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    HOME.get_or_init(passwd_home).as_deref().ok_or_else(|| {
        ContainmentError::ConfigValidation(
            "cannot read the operator's home from the passwd database, so a home-anchored floor \
             cannot be evaluated"
                .to_string(),
        )
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn passwd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    // SAFETY: `getpwuid` returns a pointer to a libc-owned static, and `pw_dir` is copied here
    // before any other libc call can overwrite it.
    let directory = unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() {
            return None;
        }
        let directory = (*entry).pw_dir;
        if directory.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr(directory).to_bytes().to_vec()
    };
    let path = PathBuf::from(std::ffi::OsString::from_vec(directory));
    // Canonical, because a grant carries its canonical identity.
    Some(path.canonicalize().unwrap_or(path))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn passwd_home() -> Option<PathBuf> {
    None
}

/// Refuse a grant that reaches a forbidden path, judged at every anchor.
pub(crate) fn require_bounded_grant(
    granted: &PathGrant,
    declared_home: Option<&Path>,
    credential_store_exempt: bool,
) -> Result<()> {
    // Every node the lookup traverses, not just the resolved one: the exec and metadata cells render
    // a rule on each, so a row that never saw one would leave the rendered set wider than the
    // approved set. The row set carries the data volume's second name for each anchor, so a caller
    // naming that spelling is judged here as well.
    let homes = anchor_homes(declared_home)?;
    for path in granted.traversal_paths() {
        if let Some(class) = forbidden_path_refusal(&homes, &path, granted.operation, granted.scope)
        {
            // **Only the operator's own store is exemptible.** A class states that; the message text
            // used to carry it, which is why the machine's stores needed text of their own.
            if class.is_exemptible() && credential_store_exempt {
                continue;
            }
            return Err(ContainmentError::GrantTooBroad {
                path,
                reason: class.reason(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DATA_VOLUME_ROOT, Forbidden, ForbiddenClass, Match, credential_store_paths_under,
        forbidden_path_refusal, forbidden_paths, home_relative_path_refusal, require_bounded_grant,
    };
    use crate::model::{Operation, Scope};
    use std::path::{Path, PathBuf};

    const HOME: &str = "/Users/operator";

    fn resolve(spelling: &str) -> PathBuf {
        match spelling.strip_prefix('~') {
            Some("") => PathBuf::from(HOME),
            Some(rest) => PathBuf::from(format!("{HOME}{rest}")),
            None => PathBuf::from(spelling),
        }
    }

    /// Every case below reads a path, which is the operation a grant on one of these carries.
    fn refused(spelling: &str, scope: Scope) -> bool {
        forbidden_path_refusal(
            &[PathBuf::from(HOME)],
            &resolve(spelling),
            Operation::Read,
            scope,
        )
        .is_some()
    }

    /// The absolute entries, which is what the old list held.
    fn absolute_entries() -> Vec<&'static str> {
        forbidden_paths()
            .iter()
            .map(|entry| entry.anchor.as_str())
            .filter(|anchor| !anchor.starts_with("~/"))
            .collect()
    }

    /// **The two match rules are what they say**, tested once on paths that mean nothing.
    ///
    /// Every entry states its rule and nothing else, so this is the only place the semantics are
    /// pinned. The last two cases are the pair that no single rule can express.
    #[test]
    fn the_match_rules_are_what_they_say() {
        let exact = Forbidden::exact("/a", ForbiddenClass::SystemTree);
        let overlap = Forbidden::overlap("/a", ForbiddenClass::CredentialStore);
        let a = Path::new("/a");
        let read = Operation::Read;

        assert!(exact.covers(a, Path::new("/a"), read, Scope::Root));
        assert!(
            !exact.covers(a, Path::new("/a/b"), read, Scope::Root),
            "a descendant"
        );
        assert!(
            !exact.covers(a, Path::new("/"), read, Scope::Root),
            "an ancestor"
        );

        assert!(overlap.covers(a, Path::new("/a"), read, Scope::Root));
        assert!(
            overlap.covers(a, Path::new("/a/b"), read, Scope::Dir),
            "a descendant"
        );
        assert!(
            overlap.covers(a, Path::new("/"), read, Scope::Root),
            "an ancestor"
        );
        assert!(
            !overlap.covers(a, Path::new("/"), read, Scope::Dir),
            "an ancestor naming itself alone holds nothing"
        );
        assert!(
            !overlap.covers(a, Path::new("/c"), read, Scope::Root),
            "unrelated"
        );

        // A stat is refused unless the row opts in, so a new entry is strict by omission.
        let stat = Operation::Metadata;
        assert!(exact.covers(a, Path::new("/a"), stat, Scope::Root));
        assert!(overlap.covers(a, Path::new("/a"), stat, Scope::Root));
        const STAT: &[(Operation, Scope)] = &[(Operation::Metadata, Scope::Root)];
        let statable = Forbidden::exact("/a", ForbiddenClass::SystemTree).permitting(STAT);
        assert!(!statable.covers(a, Path::new("/a"), stat, Scope::Root));
        assert!(
            statable.covers(a, Path::new("/a"), read, Scope::Root),
            "opting a stat in must not let a read through"
        );
    }

    #[test]
    fn an_exact_credential_exception_clears_only_its_operation() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");

        let ordinary = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow(&store, Operation::Read, Scope::Root)
            .expect("the vocabulary accepts the grant");
        super::require_all(&ordinary)
            .expect_err("the ordinary route to a credential store stays refused");

        let exempt = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("the exact exception is accepted");
        super::require_all(&exempt).expect("the matching read exception clears the floor");

        let mismatched = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("the read exception is accepted")
            .allow(&store, Operation::Write, Scope::Root)
            .expect("the separate write grant is accepted");
        super::require_all(&mismatched)
            .expect_err("a read exception must not clear a write refusal");
    }

    #[test]
    fn an_exact_descendant_inherits_a_root_exception_but_an_alias_does_not() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let credentials = store.join("credentials");
        std::fs::write(&credentials, "secret").expect("a credential file");
        let exact = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("the exact exception is accepted")
            .allow(&credentials, Operation::Read, Scope::File)
            .expect("the exact descendant is accepted");
        super::require_all(&exact).expect("the root exception covers its exact descendant");

        let alias = home_path.join("alias");
        std::os::unix::fs::symlink(&store, &alias).expect("an alias to the credential store");
        let config = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("the exact exception is accepted")
            .allow(&alias, Operation::Read, Scope::Root)
            .expect("an ordinary grant can name the alias");

        super::require_all(&config)
            .expect_err("the alias must not inherit the exact grant's exception");
    }

    #[test]
    fn the_same_store_kind_under_two_homes_is_not_the_same_store() {
        let declared = tempfile::tempdir().expect("a declared home");
        let declared = declared.path().canonicalize().expect("the home resolves");
        let passwd = super::operator_home().expect("the passwd home");
        let original = declared.join(".aws/credentials");
        let resolved = passwd.join(".aws/credentials");

        assert!(
            !super::same_credential_store(&original, &resolved, Some(&declared))
                .expect("the store identities classify"),
            "a store identity includes its home anchor"
        );
    }

    #[test]
    fn a_direct_exception_cannot_cover_a_symlink_from_another_store() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let aws = home_path.join(".aws");
        let ssh = home_path.join(".ssh");
        std::fs::create_dir(&aws).expect("an AWS store");
        std::fs::create_dir(&ssh).expect("an SSH store");
        let credential = aws.join("credentials");
        std::fs::write(&credential, "secret").expect("an AWS credential");
        let route = ssh.join("id_rsa");
        std::os::unix::fs::symlink(&credential, &route).expect("a cross-store route");
        let config = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&aws, Operation::Read, Scope::Root)
            .expect("the AWS exception is accepted")
            .allow(&route, Operation::Read, Scope::File)
            .expect("the ordinary grant records the SSH spelling");

        super::require_all(&config)
            .expect_err("the SSH spelling must not inherit the AWS exception");
    }

    #[test]
    fn a_system_tree_cannot_receive_a_credential_exception() {
        let error = crate::config::ContainmentConfig::new()
            .allow_credential_store("/etc", Operation::Read, Scope::Root)
            .expect_err("a system tree is not a credential store");
        assert!(
            error.to_string().contains("exact credential-store path"),
            "the system row remains outside the exception: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_credential_write_requires_the_same_read_grant_on_linux() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let cache = home_path.join(".aws/sso/cache");
        std::fs::create_dir_all(&cache).expect("a credential cache");
        let config = crate::config::ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&cache, Operation::Write, Scope::Root)
            .expect("the builder can receive grants in either order");

        let error = super::require_all(&config)
            .expect_err("the complete Linux request must state its read authority");
        assert!(
            error
                .to_string()
                .contains("must have a read grant on Linux"),
            "the refusal names the missing operation: {error}"
        );
    }

    /// **Execute and write on one path clears every floor and yields one warning**, in each of the
    /// shapes that carry the pair.
    ///
    /// The floor once refused the pair; a build that writes its output and runs it needs it, so the
    /// caller is told rather than stopped. Every other floor is unchanged, and the pair is counted
    /// once however many spellings reach it.
    #[test]
    fn execute_and_write_on_one_path_warn_and_clear_every_floor() {
        use super::ContainmentWarning::WritableAndExecutable;

        let directory = tempfile::tempdir().expect("a directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("a canonical directory");
        let program = root.join("agent");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("a program");
        let output = root.join("target");
        std::fs::create_dir_all(output.join("debug")).expect("build output");
        let tree = root.join("tools");
        let cache = tree.join("cache");
        std::fs::create_dir_all(&cache).expect("an exec tree with a writable corner");
        let one_file = crate::config::ContainmentConfig::new()
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an exec grant")
            .allow(&program, Operation::Write, Scope::File)
            .expect("the vocabulary accepts the cell");
        let literal_in_root = crate::config::ContainmentConfig::new()
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an exec grant")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("a write root enclosing it");
        let tree_in_root = crate::config::ContainmentConfig::new()
            .allow(&output, Operation::Exec, Scope::Root)
            .expect("an exec tree")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("a write root enclosing it");
        let root_in_tree = crate::config::ContainmentConfig::new()
            .allow(&tree, Operation::Exec, Scope::Root)
            .expect("an exec tree")
            .allow(&cache, Operation::Write, Scope::Root)
            .expect("a write root inside it");

        for (label, config, expected) in [
            (
                "one file granted both",
                one_file,
                WritableAndExecutable {
                    executable: program.clone(),
                    writable: program.clone(),
                },
            ),
            (
                "an exec literal inside a write root",
                literal_in_root,
                WritableAndExecutable {
                    executable: program.clone(),
                    writable: root.clone(),
                },
            ),
            (
                "an exec tree inside a write root",
                tree_in_root,
                WritableAndExecutable {
                    executable: output.clone(),
                    writable: root.clone(),
                },
            ),
            (
                "a write root inside an exec tree",
                root_in_tree,
                WritableAndExecutable {
                    executable: tree.clone(),
                    writable: cache.clone(),
                },
            ),
        ] {
            super::require_all(&config)
                .unwrap_or_else(|error| panic!("{label}: the pair clears every floor: {error}"));
            assert_eq!(
                super::warnings(&config),
                vec![expected],
                "{label}: one pair, one warning"
            );
        }

        // The control: a program beside a write root is neither refused nor warned about.
        let disjoint = crate::config::ContainmentConfig::new()
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an exec grant")
            .allow(&output, Operation::Write, Scope::Root)
            .expect("a write root beside it");
        super::require_all(&disjoint).expect("a disjoint pair clears every floor");
        assert!(super::warnings(&disjoint).is_empty());
    }

    /// **A write root inside a read root clears every floor.** The inner grant states the one
    /// writable corner of a read-only tree.
    #[test]
    fn a_write_root_inside_a_read_root_clears_every_floor() {
        let directory = tempfile::tempdir().expect("a directory");
        let project = directory
            .path()
            .canonicalize()
            .expect("a canonical directory");
        let workspace = project.join("workspace");
        std::fs::create_dir_all(&workspace).expect("a writable corner");
        let config = crate::config::ContainmentConfig::new()
            .allow(&project, Operation::Read, Scope::Root)
            .expect("a read root")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("a write root inside it");

        super::require_all(&config).expect("the nested pair clears every floor");
    }

    /// **One grant clears the floors on its own**, and the caller learns whether it named a
    /// credential store exactly.
    #[test]
    fn one_grant_clears_the_floors_and_reports_a_credential_store() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let project = home_path.join("project");
        std::fs::create_dir_all(&project).expect("an ordinary directory");
        let store = home_path.join(".aws");
        std::fs::create_dir_all(&store).expect("a credential store");

        assert!(
            !super::validate_grant(&project, &home_path, Operation::List, Scope::Root)
                .expect("an ordinary directory clears every row"),
            "an ordinary directory is no credential store"
        );
        assert!(
            super::validate_grant(&store, &home_path, Operation::Read, Scope::Root)
                .expect("a read punches through the store"),
            "the store is reported to the caller"
        );

        // Only a read or a write punches through a store, so the exec cell meets the row.
        let refusal = super::validate_grant(&store, &home_path, Operation::Exec, Scope::Root)
            .expect_err("an exec grant on a credential store is refused");
        assert!(
            refusal.to_string().contains("credential"),
            "the refusal names the store: {refusal}"
        );

        let refusal =
            super::validate_grant(Path::new("/usr"), &home_path, Operation::Read, Scope::Root)
                .expect_err("a system root is never a grantable tree");
        assert!(
            refusal.to_string().contains("system root"),
            "the refusal names the row: {refusal}"
        );

        let refusal = super::validate_grant(&project, &home_path, Operation::Deny, Scope::Root)
            .expect_err("a denial is not a grant");
        assert!(
            refusal.to_string().contains("never carries Deny"),
            "the refusal says a grant carries no denial: {refusal}"
        );
    }

    /// **A grant on a path that does not exist yet still reports a credential store.**
    #[test]
    fn an_absent_grant_path_reports_its_store_without_a_live_identity() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");

        assert!(
            super::validate_grant(
                &home_path.join(".aws"),
                &home_path,
                Operation::Read,
                Scope::Root,
            )
            .expect("an absent store clears the floors"),
            "the store is reported before it exists"
        );
        assert!(
            !super::validate_grant(
                &home_path.join("project"),
                &home_path,
                Operation::Read,
                Scope::Root,
            )
            .expect("an absent directory clears the floors"),
            "an absent ordinary directory is no credential store"
        );
    }

    /// **The system-tree row permits a metadata cell on the `/etc` entry and nothing at root
    /// scope**: the privilege configuration beneath it is never reachable through a root grant, so
    /// a root permit on the row would promise reach that does not exist.
    #[test]
    fn a_metadata_grant_on_etc_clears_one_row_at_a_time() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");

        assert!(
            !super::validate_grant(
                Path::new("/etc"),
                &home_path,
                Operation::Metadata,
                Scope::Dir,
            )
            .expect("the system-tree row permits the metadata dir cell"),
            "/etc is no credential store"
        );

        // A root grant reaches down into `/etc/sudoers.d`, which permits no cell at all.
        let refusal = super::validate_grant(
            Path::new("/etc"),
            &home_path,
            Operation::Metadata,
            Scope::Root,
        )
        .expect_err("a root grant on /etc is refused");
        assert!(
            refusal.to_string().contains("never a grantable tree"),
            "the refusal names the row that fired: {refusal}"
        );
    }

    /// **An exec tree holding a program that changes identity is refused**, and the refusal names
    /// the file. The control is the same tree before the bit is set.
    #[test]
    fn an_execute_tree_holding_an_identity_changing_program_is_refused() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempfile::tempdir().expect("a directory");
        let tree = directory.path().join("tools");
        std::fs::create_dir_all(tree.join("bin")).expect("an exec tree");
        let program = tree.join("bin/su");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("a program");
        let grant = || {
            crate::config::ContainmentConfig::new()
                .allow(&tree, Operation::Exec, Scope::Root)
                .expect("an exec tree")
        };

        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("a mode");
        super::require_all(&grant()).expect("an ordinary tree clears every floor");

        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o4755))
            .expect("a mode");
        assert_ne!(
            std::fs::metadata(&program).expect("metadata").mode() & super::SET_USER_ID,
            0,
            "the fixture must carry the bit, or the refusal below proves nothing"
        );
        let error = super::require_all(&grant()).expect_err("a set-user-ID program under the tree");
        let text = error.to_string();
        assert!(
            text.contains("set-user-ID") && text.contains(&program.display().to_string()),
            "the refusal must name the file: {text}"
        );
    }

    /// **An execute grant on a file that changes identity is refused**, on either bit and on both.
    ///
    /// The control runs first on the same path, and each case asserts the bit survived the `chmod`.
    #[test]
    fn an_execute_grant_that_changes_identity_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a directory");
        let program = directory.path().join("agent");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("a program");

        let grant = || {
            crate::config::ContainmentConfig::new()
                .allow(&program, Operation::Exec, Scope::File)
                .expect("an exec grant")
        };
        let set_mode = |bits: u32| {
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(bits))
                .expect("a mode");
        };

        set_mode(0o755);
        super::require_all(&grant()).expect("an ordinary program clears every floor");

        for bits in [0o4755, 0o2755, 0o6755] {
            set_mode(bits);
            let live = std::fs::metadata(&program)
                .expect("a mode")
                .permissions()
                .mode();
            assert_eq!(
                live & 0o7000,
                bits & 0o7000,
                "this host dropped the mode bit, so the case below would prove nothing"
            );

            let error = super::require_all(&grant())
                .expect_err("an execute grant on an identity-changing file must be refused");
            assert!(
                error.to_string().contains("set-user-ID or set-group-ID"),
                "the refusal must name what it refuses: {error}"
            );
        }
    }

    /// **What the list does to a path.** One table, so the entries are read together.
    #[test]
    fn the_list_refuses_what_it_claims_and_renders_what_it_must() {
        let must_refuse = [
            ("/usr", Scope::Root),
            ("/usr", Scope::Dir),
            ("/", Scope::Root),
            ("/Users", Scope::Root),
            // The whole-home grant. No absolute entry catches it, because `/Users` is one path
            // and `/Users/operator` is another.
            ("~", Scope::Root),
            ("~/.ssh", Scope::Root),
            // A file grant, which the earlier floor never judged at all.
            ("~/.ssh/id_rsa", Scope::File),
            ("~/.aws/credentials", Scope::File),
            ("~/Library/Keychains/login.keychain-db", Scope::File),
        ];
        let must_render = [
            // Each is a path the box's floor or an `[agent] read` grant names.
            ("/usr/share/icu", Scope::Root),
            ("/usr/lib/libSystem.dylib", Scope::File),
            ("/System/Library/OpenSSL", Scope::Root),
            ("~/.pyenv/versions", Scope::Root),
            ("~/.strands-box/b/probe/home", Scope::Root),
            // The home named alone reaches nothing inside it.
            ("~", Scope::Dir),
            // A sibling whose name merely starts the same way.
            ("~/.awsome", Scope::Root),
        ];

        for (path, scope) in must_refuse {
            assert!(refused(path, scope), "{path} at {scope:?} must be refused");
        }
        for (path, scope) in must_render {
            assert!(!refused(path, scope), "{path} at {scope:?} must render");
        }
        // Each `/etc` spelling permits the metadata cell on its own entry and refuses read at either
        // scope. The row permits no root cell, because a root grant would reach down into the
        // privilege configuration beneath it, which permits nothing.
        // A grant carries its canonical identity, so judge the canonical spelling: on macOS `/etc`
        // is a symlink to `/private/etc`, and the row anchors resolve there too, so the bare literal
        // `/etc` matches no row.
        for path in ["/etc", "/private/etc"] {
            let granted = Path::new(path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(path));
            let refusal = |operation, scope| {
                forbidden_path_refusal(&[PathBuf::from(HOME)], &granted, operation, scope)
            };
            assert!(
                refusal(Operation::Metadata, Scope::Dir).is_none(),
                "{path} at Metadata/Dir must render"
            );
            assert_eq!(
                refusal(Operation::Metadata, Scope::Root),
                Some(ForbiddenClass::SystemTree),
                "{path} must refuse the metadata root cell on itself"
            );
            for scope in [Scope::Dir, Scope::Root] {
                assert!(
                    refusal(Operation::Read, scope).is_some(),
                    "{path} at Read/{scope:?} must be refused"
                );
            }
        }
    }

    /// An anchor's spelling matches its kind, so no entry means the wrong path.
    #[test]
    fn every_anchor_is_spelled_for_its_kind() {
        for entry in forbidden_paths() {
            let anchor = entry.anchor.as_str();
            assert!(!anchor.contains(".."), "{anchor} traverses upward");
            assert!(
                anchor.starts_with('/') || anchor.starts_with("~/"),
                "{anchor} is neither absolute nor home-relative"
            );
            assert!(
                !anchor.trim_start_matches("~/").contains('~'),
                "{anchor} spells a home twice"
            );
        }
    }

    /// **Every credential path the box's own loader once refused is still refused here.**
    ///
    /// The box held this list, so a path present there and absent here is a floor lost in the
    /// merge. It is checked through the authoring-time predicate the box now calls.
    #[test]
    fn the_floor_covers_every_credential_path_the_pack_loader_held() {
        for relative in [
            ".aws",
            ".ssh",
            ".gnupg",
            ".netrc",
            ".docker",
            ".kube",
            ".config/gcloud",
            "Library/Keychains",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Firefox",
            ".mozilla",
            ".config/google-chrome",
        ] {
            assert!(
                refused(&format!("~/{relative}"), Scope::Root),
                "{relative} is no longer refused by the floor"
            );
            assert!(
                home_relative_path_refusal(&format!("~/{relative}/secret")).is_some(),
                "{relative} is no longer refused at authoring time"
            );
        }
        assert!(
            home_relative_path_refusal("~/.awsome/config").is_none(),
            "a sibling name is not a credential store"
        );
        assert!(
            home_relative_path_refusal("~/.pyenv/versions").is_none(),
            "a python install tree is not a credential store"
        );
    }

    /// Every root either backend refused on its own is still refused by the shared list.
    ///
    /// The two backends held separate lists, so a root present in one was a floor the other
    /// lacked. The three groups below are what each list carried, and dropping any entry is a
    /// silent widening on at least one platform.
    #[test]
    fn the_shared_floor_covers_what_each_backend_refused_separately() {
        let shared = absolute_entries();

        let both = [
            "/",
            "/etc",
            "/opt",
            "/tmp",
            "/usr",
            "/usr/lib",
            "/usr/local",
            "/usr/share",
            "/var",
        ];
        let macos_only = [
            "/Library",
            "/System",
            "/Users",
            "/opt/homebrew",
            "/private",
            "/private/etc",
            "/private/tmp",
            "/private/var",
        ];
        let linux_only = [
            "/bin",
            "/boot",
            "/dev",
            "/home",
            "/lib",
            "/lib64",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/usr/bin",
            "/usr/lib64",
            "/usr/sbin",
        ];

        for (group, roots) in [
            ("both", &both[..]),
            ("macos", &macos_only[..]),
            ("linux", &linux_only[..]),
        ] {
            for root in roots {
                assert!(
                    shared.contains(root),
                    "{root} was refused by the {group} floor and is missing from the shared list"
                );
            }
        }
        // Rows this list gained after the merge, which neither backend ever held. Named here so the
        // count below still refuses an entry nobody decided on.
        let added_since_the_merge = [
            "/etc/master.passwd",
            "/private/etc/master.passwd",
            "/etc/shadow",
            "/etc/gshadow",
            "/var/db/dslocal",
            "/private/var/db/dslocal",
            "/Library/Keychains",
            "/var/db/SystemKey",
            "/private/var/db/SystemKey",
            "/etc/sudoers",
            "/private/etc/sudoers",
            "/etc/sudoers.d",
            "/private/etc/sudoers.d",
            "/Library/Application Support/com.apple.TCC",
        ];
        for path in added_since_the_merge {
            assert!(
                shared.contains(&path),
                "{path} was added deliberately and is missing from the shared list"
            );
        }
        assert_eq!(
            shared.len(),
            both.len() + macos_only.len() + linux_only.len() + added_since_the_merge.len(),
            "the shared list gained or lost an entry the groups above do not name"
        );
    }

    /// A file inside a system tree stays grantable, because that entry names one path.
    #[test]
    fn the_floor_names_roots_and_not_prefixes() {
        for root in absolute_entries() {
            assert!(
                !root.ends_with('/') || root == "/",
                "{root} carries a trailing separator, which reads as a prefix rather than a root"
            );
        }
    }

    /// `/var` permits metadata at `dir` scope and nothing wider, so a grant asking for more is
    /// refused whichever spelling names it.
    ///
    /// Judged through `require_bounded_grant`, because that is what a grant meets.
    /// `forbidden_path_refusal` on the bare literal `/var` answers nothing: the row's anchor
    /// resolves to `/private/var`, so only the resolved spelling matches a row.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_grant_on_the_var_system_root_is_refused_beyond_the_cell_it_permits() {
        let homes = [PathBuf::from("/Users/fixture")];
        for spelling in ["/var", "/private/var"] {
            for (operation, scope) in [
                (Operation::Read, Scope::Root),
                (Operation::Read, Scope::Dir),
                (Operation::Write, Scope::Root),
            ] {
                let granted = crate::model::PathGrant::new(Path::new(spelling), operation, scope)
                    .expect("the portable model accepts a system root");
                assert!(
                    require_bounded_grant(&granted, Some(&homes[0]), false).is_err(),
                    "{spelling} must stay refused at {operation:?}/{scope:?}"
                );
            }
            let permitted =
                crate::model::PathGrant::new(Path::new(spelling), Operation::Metadata, Scope::Dir)
                    .expect("the portable model accepts a system root");
            assert!(
                require_bounded_grant(&permitted, Some(&homes[0]), false).is_ok(),
                "{spelling} must pass at Metadata/Dir, which the time zone chain needs"
            );
        }
    }

    /// **A loader directory reads as a tree, and nothing wider.** Every process maps code from it,
    /// so the runtime minimum grants it; a write, an exec, or an entry-only read there stays refused.
    #[test]
    fn a_loader_directory_reads_as_a_tree_and_nothing_wider() {
        let homes = [PathBuf::from(HOME)];
        for spelling in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
            // A grant carries its canonical identity, and so does each row's anchor.
            let resolved = Path::new(spelling)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(spelling));
            let path = resolved.as_path();
            assert!(
                forbidden_path_refusal(&homes, path, Operation::Read, Scope::Root).is_none(),
                "{spelling} must read as a tree"
            );
            for (operation, scope) in [
                (Operation::Write, Scope::Root),
                (Operation::Exec, Scope::Root),
                (Operation::Read, Scope::Dir),
                (Operation::Metadata, Scope::Root),
            ] {
                let class =
                    forbidden_path_refusal(&homes, path, operation, scope).unwrap_or_else(|| {
                        panic!("{spelling} must stay refused at {operation:?}/{scope:?}")
                    });
                assert_eq!(
                    class,
                    ForbiddenClass::LoaderDirectory,
                    "the refusal names the row: {}",
                    class.reason()
                );
            }
        }
        assert!(
            forbidden_path_refusal(&homes, Path::new("/usr/bin"), Operation::Read, Scope::Root)
                .is_some(),
            "a program directory is not a loader directory"
        );
    }

    /// The second anchor name refuses no cell the box's floor or an `[agent] read` entry grants.
    #[test]
    fn the_second_anchor_name_refuses_no_cell_a_pack_grants() {
        for (path, operation, scope) in [
            ("/", Operation::Read, Scope::Dir),
            ("/etc", Operation::Metadata, Scope::Dir),
            ("/private/etc", Operation::Metadata, Scope::Dir),
            ("/tmp", Operation::Metadata, Scope::Root),
            ("/private/tmp", Operation::Metadata, Scope::Root),
            ("/dev/null", Operation::Read, Scope::File),
            ("/dev/null", Operation::Write, Scope::File),
            ("/System/Library/OpenSSL", Operation::Read, Scope::Root),
            (
                "/System/Library/OpenSSL/openssl.cnf",
                Operation::Read,
                Scope::File,
            ),
            ("/usr/share/icu", Operation::Read, Scope::Root),
            ("/usr/share/zoneinfo", Operation::Read, Scope::Root),
            ("/etc/localtime", Operation::Read, Scope::File),
            ("/var", Operation::Metadata, Scope::Dir),
            ("/private/var", Operation::Metadata, Scope::Dir),
        ] {
            if !Path::new(path).exists() {
                continue;
            }
            let granted = crate::model::PathGrant::new(path, operation, scope)
                .expect("the portable model accepts the path");
            assert!(
                require_bounded_grant(&granted, None, false).is_ok(),
                "{path} at {operation:?}/{scope:?} is a grant the box states and must pass"
            );
        }
    }

    /// A forbidden path named through the data volume matches a row, credential or system.
    ///
    /// Judged lexically against a fixture home, so it runs on every host: the data volume's names
    /// exist only on macOS, and `PathGrant::new` refuses a path that is not there.
    #[test]
    fn a_forbidden_path_named_through_the_data_volume_is_refused() {
        let homes = [PathBuf::from("/fixture-home")];
        let through_the_data_volume = |path: &str| -> PathBuf {
            Path::new(DATA_VOLUME_ROOT).join(path.strip_prefix('/').expect("absolute"))
        };
        for path in [
            through_the_data_volume("/fixture-home/Library/Keychains"),
            through_the_data_volume("/private"),
            through_the_data_volume("/usr"),
        ] {
            assert!(
                forbidden_path_refusal(&homes, &path, Operation::Read, Scope::Root).is_some(),
                "{} must match a row",
                path.display()
            );
        }
        // And the canonical name alone never saw them, which is why every row carries the second.
        for path in ["/fixture-home/Library/Keychains", "/private", "/usr"] {
            assert!(
                forbidden_path_refusal(&homes, Path::new(path), Operation::Read, Scope::Root)
                    .is_some(),
                "{path} must still match its own row"
            );
        }
    }

    /// `require_bounded_grant` refuses a real grant named through the data volume.
    ///
    /// The integration leg of the test above, and macOS-only because `PathGrant::new` canonicalizes
    /// and these names exist on no other platform.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_real_grant_named_through_the_data_volume_is_refused() {
        let spellings = super::operator_home_spellings(None).expect("home spellings");
        let canonical = spellings.first().expect("a canonical spelling");
        // Both present on every macOS install, so these pin the rule rather than the host.
        let credential_row = Path::new(DATA_VOLUME_ROOT)
            .join(canonical.strip_prefix("/").expect("an absolute home"))
            .join("Library/Keychains");
        let system_row = Path::new(DATA_VOLUME_ROOT).join("private");

        for path in [&credential_row, &system_row] {
            if !path.exists() {
                println!("skipping: {} is absent on this host", path.display());
                continue;
            }
            let granted = crate::model::PathGrant::new(path, Operation::Read, Scope::Root)
                .expect("the portable model accepts the path");
            assert!(
                require_bounded_grant(&granted, None, false).is_err(),
                "{} must be refused",
                path.display()
            );
        }
    }

    /// A grant whose chain passes through a credential store is refused, and named.
    ///
    /// The security half of the traversal walk. The renderer emits a `file-read-metadata` rule on
    /// every node, so a node this floor never judged would disclose a credential file's existence
    /// and mode. The grant's own two ends are outside every row; only a middle node is inside one.
    #[test]
    fn a_chain_node_inside_a_credential_store_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical tempdir");
        let home = root.join("home");
        let store = home.join(".ssh");
        std::fs::create_dir_all(&store).expect("the credential store");
        let target = root.join("agent");
        std::fs::write(&target, "agent").expect("the program");
        // The middle node sits inside the store; neither end does.
        let middle = store.join("hop-1");
        let route = root.join("agent-link");
        std::os::unix::fs::symlink(&target, &middle).expect("hop 1");
        std::os::unix::fs::symlink(&middle, &route).expect("hop 2");

        let granted = crate::model::PathGrant::new(&route, Operation::Exec, Scope::File)
            .expect("the portable model accepts the route");
        let refusal = require_bounded_grant(&granted, Some(&home), false)
            .expect_err("a chain through a credential store must be refused");
        let reported = refusal.to_string();
        assert!(
            reported.contains("hop-1") && reported.contains("credential"),
            "the refusal must name the offending node and why: {reported}"
        );

        // The control: the same chain with its middle outside the store renders.
        let elsewhere = root.join("hop-1");
        let plain_route = root.join("plain-link");
        std::os::unix::fs::symlink(&target, &elsewhere).expect("a middle outside the store");
        std::os::unix::fs::symlink(&elsewhere, &plain_route).expect("hop 2");
        let granted = crate::model::PathGrant::new(&plain_route, Operation::Exec, Scope::File)
            .expect("the portable model accepts the route");
        assert!(
            require_bounded_grant(&granted, Some(&home), false).is_ok(),
            "a chain outside every row must pass, or this test proves nothing"
        );
    }

    /// **The exemption clears the operator's own store and no other row, judged where a grant meets
    /// it.** `require_bounded_grant` reads `is_exemptible`, so a row retyped to `CredentialStore`
    /// becomes exemptible; `only_a_credential_store_row_is_exemptible` reads the table and this reads
    /// the refusal, because a green table says nothing about what the gate does with the flag set.
    #[test]
    fn the_exemption_clears_no_row_the_operator_does_not_own() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");

        let mut judged: Vec<(&str, ForbiddenClass)> = Vec::new();
        for row in forbidden_paths() {
            if !matches!(
                row.class,
                ForbiddenClass::MachineCredential
                    | ForbiddenClass::PasswordDatabase
                    | ForbiddenClass::PrivilegeConfiguration
            ) {
                continue;
            }
            let anchor = Path::new(&row.anchor);
            // A grant names a path that is there, so a row this host lacks is judged nowhere.
            let Ok(metadata) = std::fs::metadata(anchor) else {
                continue;
            };
            let scope = if metadata.is_dir() {
                Scope::Root
            } else {
                Scope::File
            };
            let granted = crate::model::PathGrant::new(anchor, Operation::Read, scope)
                .expect("the vocabulary accepts a read on a present path");
            let refusal = require_bounded_grant(&granted, Some(&home_path), true).expect_err(
                "a row the operator does not own stays refused with the exemption asked for",
            );
            let reported = refusal.to_string();
            assert!(
                reported.contains(row.reason()),
                "{} must refuse by its own class: {reported}",
                row.anchor
            );
            judged.push((row.anchor.as_str(), row.class));
        }
        assert!(
            !judged.is_empty(),
            "no machine credential, password database or privilege configuration is present, so \
             this host judged nothing"
        );

        // The control: the flag does clear the operator's own store, so the cases above are refused
        // by their class rather than by a gate that never opens.
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("the operator's own store");
        let granted = crate::model::PathGrant::new(&store, Operation::Read, Scope::Root)
            .expect("the vocabulary accepts the grant");
        assert!(
            require_bounded_grant(&granted, Some(&home_path), false).is_err(),
            "the operator's own store is refused without the exemption"
        );
        assert!(
            require_bounded_grant(&granted, Some(&home_path), true).is_ok(),
            "the exemption clears the operator's own store, or {judged:?} proves nothing"
        );
    }

    /// Two anchors protect two homes, so a caller whose home differs from the passwd database's
    /// still has its credential stores refused.
    ///
    /// This is the divergence the declared home closes: the box resolves `~/.aws` against `$HOME`,
    /// and under `sudo -E` that is the invoking user's home while `passwd(getuid())` is root's.
    #[test]
    fn every_anchor_protects_its_own_home() {
        const OTHER: &str = "/Users/elsewhere";
        let homes = [PathBuf::from(HOME), PathBuf::from(OTHER)];
        for home in [HOME, OTHER] {
            for relative in [".aws", ".ssh", "Library/Keychains"] {
                let granted = PathBuf::from(format!("{home}/{relative}"));
                assert!(
                    forbidden_path_refusal(&homes, &granted, Operation::Read, Scope::Root)
                        .is_some(),
                    "{} is a credential store and must be refused at every anchor",
                    granted.display()
                );
            }
            // The anchor protects what it names and not the whole home, or every box home under it
            // would be refused too.
            let ordinary = PathBuf::from(format!("{home}/projects/thing"));
            assert!(
                forbidden_path_refusal(&homes, &ordinary, Operation::Read, Scope::Root).is_none(),
                "{} holds no credential and must stay grantable",
                ordinary.display()
            );
        }
    }

    /// The system password database is refused by name, in every spelling and at every cell.
    ///
    /// The system-tree rows are `ExactPath`, so `/etc` being forbidden leaves each file inside it
    /// grantable. These hold a password hash, and DAC is the only thing refusing an authored grant
    /// on one — which is nothing at `euid` 0.
    #[test]
    fn the_system_password_database_is_never_grantable() {
        let homes = [PathBuf::from("/fixture-home")];
        // A real grant reaches the floor canonicalized, so judge the identity rather than the
        // spelling an operator typed. An absent path keeps its own name, which is the Linux rows.
        let as_granted = |path: &str| -> PathBuf {
            let lexical = PathBuf::from(path);
            lexical.canonicalize().unwrap_or(lexical)
        };
        for path in [
            as_granted("/etc/master.passwd"),
            as_granted("/private/etc/master.passwd"),
            as_granted("/etc/shadow"),
            as_granted("/etc/gshadow"),
        ] {
            for (operation, scope) in [
                (Operation::Read, Scope::File),
                (Operation::Read, Scope::Root),
                (Operation::Metadata, Scope::Dir),
                (Operation::Write, Scope::File),
            ] {
                assert!(
                    forbidden_path_refusal(&homes, &path, operation, scope).is_some(),
                    "{} holds a password hash and must be refused at {operation:?}/{scope:?}",
                    path.display()
                );
            }
        }
        // The floor the box itself states must survive the rows above, or every box refuses to start.
        for (path, operation, scope) in [
            ("/etc", Operation::Metadata, Scope::Dir),
            ("/etc/localtime", Operation::Read, Scope::File),
            ("/", Operation::Read, Scope::Dir),
        ] {
            assert!(
                forbidden_path_refusal(&homes, Path::new(path), operation, scope).is_none(),
                "{path} is a cell the baseline floor grants and must stay grantable"
            );
        }
    }

    /// A machine credential store refuses a grant on a path *inside* it, not only on its own name.
    ///
    /// The password-database rows are `ExactPath`, which is right for a file and useless for a tree:
    /// a hash under the local directory service sits several components down. These rows are
    /// `AnyOverlap` so the descendants go with them, and this test is what tells the two rules apart —
    /// switching any row here to `ExactPath` leaves every assertion below failing.
    #[test]
    fn a_machine_credential_store_refuses_a_grant_inside_it() {
        let homes = [PathBuf::from("/fixture-home")];
        // Each row's anchor is resolved before the comparison, so a descendant is spelled the way a
        // canonicalized grant arrives: under `/private` where the ancestor is a symlink, and as
        // authored where it is not. A lexical `/var/…` spelling matches no row and never reaches the
        // floor, because `PathGrant::new` canonicalizes first.
        for path in [
            "/private/var/db/dslocal/nodes/Default/users/operator.plist",
            "/private/var/db/dslocal/nodes/Default",
            "/Library/Keychains/System.keychain",
            "/private/etc/sudoers.d/operator",
            "/Library/Application Support/com.apple.TCC/TCC.db",
        ] {
            for (operation, scope) in [
                (Operation::Read, Scope::File),
                (Operation::Read, Scope::Root),
                (Operation::Metadata, Scope::Dir),
                (Operation::Write, Scope::Root),
            ] {
                assert!(
                    forbidden_path_refusal(&homes, Path::new(path), operation, scope).is_some(),
                    "{path} sits inside a machine credential store and must be refused at \
                     {operation:?}/{scope:?}"
                );
            }
        }
        // The cells the baseline floor grants must survive every row above, or no box starts. `/var`
        // is the one that matters: the time zone chain crosses it, and an `AnyOverlap` row beneath it
        // must not reach a grant on the tree above.
        for (path, operation, scope) in [
            ("/var", Operation::Metadata, Scope::Dir),
            ("/private/var", Operation::Metadata, Scope::Dir),
            ("/etc", Operation::Metadata, Scope::Dir),
            ("/", Operation::Read, Scope::Dir),
        ] {
            assert!(
                forbidden_path_refusal(&homes, Path::new(path), operation, scope).is_none(),
                "{path} is a cell the baseline floor grants and must stay grantable"
            );
        }
    }

    /// No `AnyOverlap` row lets a cell through, and the existence deny depends on it.
    #[test]
    fn no_credential_row_lets_a_cell_through() {
        for entry in forbidden_paths()
            .iter()
            .filter(|entry| entry.rule == Match::AnyOverlap)
        {
            assert!(
                entry.permits.is_empty(),
                "{} opts {:?} back in, which the rendered existence deny would silently void",
                entry.anchor,
                entry.permits
            );
        }
    }

    /// A credential anchor reached through a symbolic link renders both spellings.
    #[test]
    fn a_linked_credential_anchor_renders_both_spellings() {
        let fixtures = tempfile::tempdir().expect("fixtures");
        let home = fixtures.path().canonicalize().expect("canonical fixtures");
        let elsewhere = home.join("vault-aws");
        std::fs::create_dir(&elsewhere).expect("link target");
        std::os::unix::fs::symlink(&elsewhere, home.join(".aws")).expect("linked anchor");

        let paths = credential_store_paths_under(&home);
        assert!(
            paths.contains(&home.join(".aws")),
            "the spelling a caller names is missing: {paths:?}"
        );
        assert!(
            paths.contains(&elsewhere),
            "the identity the link resolves to is missing: {paths:?}"
        );
    }

    /// The set is exactly the credential rows, named here rather than derived from the list.
    #[test]
    fn the_existence_deny_covers_exactly_these_credential_stores() {
        let home = std::path::Path::new("/fixture-home");
        let mut rendered: Vec<String> = credential_store_paths_under(home)
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        rendered.sort();

        let mut expected: Vec<String> = [
            ".aws",
            ".ssh",
            ".gnupg",
            ".netrc",
            ".docker",
            ".kube",
            ".config/gcloud",
            ".config/google-chrome",
            ".mozilla",
            "Library/Keychains",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Firefox",
        ]
        .iter()
        .map(|relative| home.join(relative).display().to_string())
        .collect();
        // The machine's own stores, which are not home-relative and join this set the same way. Their
        // presence is denied as well as their contents; no grant names any of them, so the deny costs
        // nothing and closes the existence oracle on each.
        expected.extend(
            [
                "/var/db/dslocal",
                "/private/var/db/dslocal",
                "/Library/Keychains",
                "/etc/sudoers.d",
                "/private/etc/sudoers.d",
                "/Library/Application Support/com.apple.TCC",
            ]
            .iter()
            .map(|absolute| absolute.to_string()),
        );
        expected.sort();

        assert_eq!(
            rendered, expected,
            "the credential set changed. A row added here needs its deny; a row removed reopens \
             the existence oracle on that path"
        );
    }

    /// A declared home is **added** to the passwd anchor and never replaces it.
    ///
    /// **This is the test that makes the design safe rather than merely working.** Anchoring is
    /// monotone, so a caller naming a wrong or hostile home only widens the refusal set. Swap the
    /// union for an override and [`every_anchor_protects_its_own_home`] still passes while a caller
    /// gains the power to switch the floor off — so that test cannot carry this property.
    #[test]
    fn a_declared_home_never_replaces_the_passwd_anchor() {
        let passwd = super::operator_home().expect("this platform reports a passwd home");

        let declared = PathBuf::from("/Users/elsewhere");
        let homes = super::anchor_homes(Some(&declared)).expect("two anchors");
        assert!(
            homes.contains(&passwd.to_path_buf()),
            "the passwd anchor left the set, so a declared home can move the floor: {homes:?}"
        );
        assert!(
            homes.contains(&declared),
            "the declared home was not added: {homes:?}"
        );

        // Naming the passwd home itself adds nothing, so the anchor set holds no duplicate.
        assert_eq!(
            super::anchor_homes(Some(passwd)).expect("one anchor"),
            vec![passwd.to_path_buf()]
        );
        assert_eq!(
            super::anchor_homes(None).expect("one anchor"),
            vec![passwd.to_path_buf()]
        );
    }
}
