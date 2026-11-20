//! A `ProcessSpec`'s eight lists, translated into containment cells beneath Core's guards.
//!
//! | List | Entry kind | Cell |
//! |---|---|---|
//! | `read` | directory, file | `Read` at `Root`, `Read` at `File` |
//! | `write` | directory, file | `Write` at `Root`, `Write` at `File` |
//! | `read_file` | file | `Read` at `File` |
//! | `write_file` | existing file | `Write` at `File` |
//! | `list` | directory | `List` at `Root` |
//! | `metadata` | directory | `Metadata` at `Root` |
//! | `exec` | directory, executable file | `Exec` at `Root`, `Exec` at `File` |
//! | `deny` | file, directory, absent path | `Deny` at `File`, `Deny` at `Root` |

use std::path::{Path, PathBuf};

use containment::{ContainmentConfig, Operation, PreparedFilesystemPath, Scope};

use crate::GrantRefusal;
use crate::error::{BoxError, ConfigError};
use crate::record::config::process::{Filesystem, Grant};
use crate::record::config::secret_source::{ProtectedPath, Spelled};
use crate::record::layout::{lies_within, resolved_to_its_deepest_existing_ancestor};

/// One host path a process's own syscalls reach, with no policy decision in the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectGrant {
    /// Which list stated it.
    pub(crate) kind: Grant,
    /// The path as authored, which every refusal names.
    pub(crate) authored: String,
    /// The authored path with `~` expanded, which a credential-store exception is judged on.
    pub(crate) lexical: PathBuf,
    /// The path the kernel checks.
    pub(crate) resolved: PathBuf,
    pub(crate) operation: Operation,
    pub(crate) scope: Scope,
    /// Whether the entry names a credential store exactly, which is the one way through the floor.
    pub(crate) credential_store: bool,
    access: &'static str,
}

impl DirectGrant {
    /// How this grant reads in the startup disclosure.
    pub(crate) fn disclosure(&self) -> String {
        let store = if self.credential_store {
            "  (credential store)"
        } else {
            ""
        };
        let access = if self.access.is_empty() {
            String::new()
        } else {
            format!("  ({})", self.access)
        };
        let link = if self.is_link() {
            format!("{} -> ", self.lexical.display())
        } else {
            String::new()
        };
        format!(
            "  {:<10}  {link}{}{store}{access}",
            self.kind.key(),
            self.resolved.display()
        )
    }

    /// Whether the entry names a link to the file it grants.
    pub(crate) fn is_link(&self) -> bool {
        self.lexical != self.resolved
    }

    /// Each path the box shows this grant at: its file, and a link's own name.
    fn names(&self) -> Vec<&Path> {
        if self.is_link() {
            vec![self.resolved.as_path(), self.lexical.as_path()]
        } else {
            vec![self.resolved.as_path()]
        }
    }

    /// **Look the grant up once, as the identity the run approved.** A link entry is looked up by
    /// its own name, so the box shows the file there too. The containment grant is
    /// built from this one lookup, so a link hop swapped after the spawn check cannot move it to
    /// another file: the swap either lands before this lookup, which refuses it, or after, which
    /// the live-identity check at apply refuses.
    pub(crate) fn prepare(&self, table: &str) -> Result<PreparedFilesystemPath, ConfigError> {
        let changed = |reason: String| ConfigError::Filesystem {
            table: table.to_string(),
            entry: self.authored.clone(),
            reason: format!(
                "{reason} since the run judged it. A spawn acts on the identity the run approved, \
                 so it is refused"
            ),
        };
        let name = if self.is_link() {
            &self.lexical
        } else {
            &self.resolved
        };
        let prepared = ContainmentConfig::prepare_filesystem_path(name).map_err(|source| {
            changed(format!("{} cannot be resolved ({source})", name.display()))
        })?;
        if prepared.resolved_path() != self.resolved {
            return Err(changed(format!(
                "{} resolves to {}, not {},",
                name.display(),
                prepared.resolved_path().display(),
                self.resolved.display()
            )));
        }
        Ok(prepared)
    }
}

/// One path subtracted from every grant, whatever any grant says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The path as the caller must state it to containment.
    pub(crate) path: PathBuf,
    pub(crate) scope: Scope,
    /// The file the path named when the run judged it, or `None` for a `deny` entry not there yet.
    pub(crate) judged: Option<FileIdentity>,
}

/// The device and inode pair that identifies one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl FileIdentity {
    pub(crate) fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Every grant the eight lists state, and the paths subtracted beneath them.
///
/// One value, because a grant and the refusals that carve its interior are one decision: applying
/// the grant without them is the configuration these keys must never produce.
#[derive(Debug)]
pub(crate) struct DirectReach {
    pub(crate) command: Option<std::sync::Arc<crate::run::commands::ConfiguredCommand>>,
    pub(crate) installation: Option<std::sync::Arc<crate::run::installation::TrustedInstallation>>,
    /// What the process's own syscalls reach.
    pub(crate) grants: Vec<DirectGrant>,
    /// What stays unreachable inside those grants: `deny` entries, the directory holding each
    /// authority source this run loaded, and each path that a secret source protects.
    pub(crate) refusals: Vec<Refusal>,
    /// The `deny_write` directories, canonical, each inside a `write` tree.
    pub(crate) write_protections: Vec<PathBuf>,
    /// The directory each of `write_protections` named when the run judged it.
    pub(crate) write_protection_identities: Vec<FileIdentity>,
}

/// What the paths in one spec are judged against.
///
/// The Box's own state is not named here: `boundary` refuses a grant that reaches or encloses the
/// Box's own directory, on the same guards every operator-derived grant shares.
pub(crate) struct FilesystemContext<'a> {
    /// The table the lists came from, as a refusal names it.
    pub(crate) table: &'a str,
    /// The operator's own home, canonical, which a `~/` entry resolves against.
    pub(crate) operator_home: &'a Path,
    /// The policy file this box reads its authority from.
    pub(crate) policy: Option<&'a Path>,
    /// The directory holding each authority source this run loaded, canonical.
    pub(crate) authority_directories: Vec<PathBuf>,
    /// Every directory a declared MCP program is searched for in, which is the operator's own
    /// `PATH`. A declared program is always a bare name, so the box resolves it there, outside
    /// containment, and a writable directory on that path is a program the workload chose.
    pub(crate) program_search_directories: Vec<PathBuf>,
    /// Each `reads` and `deny` entry of a secret source of this configuration.
    pub(crate) source_paths: &'a [ProtectedPath],
}

/// Every grant the lists state, refusing each class these keys may not express.
///
/// One validation, so the grants a caller acts on are the grants that were judged.
pub(crate) fn direct_grants(
    lists: &Filesystem,
    context: &FilesystemContext<'_>,
) -> Result<DirectReach, ConfigError> {
    let mut grants: Vec<DirectGrant> = Vec::new();
    let mut refusals: Vec<Refusal> = Vec::new();
    let protected = source_path_spellings(context)?;
    let mut write_protections: Vec<PathBuf> = Vec::new();
    let mut write_protection_identities: Vec<FileIdentity> = Vec::new();
    for (kind, entry) in lists.entries() {
        match kind {
            Grant::Deny => refusals.push(denial(entry, context)?),
            // A `deny_write` entry authorizes nothing, so it is judged against no path of a
            // secret source, as a `deny` entry. The `write` tree that holds it is judged below.
            Grant::DenyWrite => {
                let (tree, identity) = write_protection(entry, context)?;
                write_protections.push(tree);
                write_protection_identities.push(identity);
            }
            _ => {
                // Before the floor, so the refusal names the source for a credential store too.
                require_outside_source_paths(kind, entry, &protected, context)?;
                grants.push(entry_grant(kind, entry, context).map_err(|(_, error)| error)?);
            }
        }
    }
    require_no_overlap(&grants, context)?;

    // Each path that a secret source protects is refused to the process, so no cell that Box
    // adds beneath the lists reaches it. macOS refuses a path that is not there too, and Linux
    // skips it, because a mount needs a path that is there.
    let covered = protected.iter().filter(|(_, spelled)| spelled.covered);
    for path in covered.flat_map(|(_, spelled)| &spelled.spellings) {
        if refusals.iter().any(|refusal| &refusal.path == path) {
            continue;
        }
        refusals.push(Refusal {
            path: path.clone(),
            // A tree, which covers the path as a file and as a directory.
            scope: Scope::Root,
            // No grant holds the path, so no identity is acted on.
            judged: None,
        });
    }

    // The directory holding a loaded authority source is subtracted from every tree that strictly
    // encloses it. A grant that is that directory, or lies inside it, keeps the sources' identity
    // protection in `boundary` and the policy file's own refusal below.
    for grant in &grants {
        if grant.scope != Scope::Root {
            continue;
        }
        for directory in &context.authority_directories {
            if directory == &grant.resolved || !directory.starts_with(&grant.resolved) {
                continue;
            }
            if refusals.iter().any(|refusal| &refusal.path == directory) {
                continue;
            }
            let judged = std::fs::symlink_metadata(directory)
                .map(|metadata| FileIdentity::of(&metadata))
                .map_err(|_| {
                    refuse(
                        context,
                        &grant.authored,
                        &format!(
                            "{} holds an authority source this run loaded and cannot be read, so \
                             it cannot be subtracted from {}",
                            directory.display(),
                            grant.resolved.display()
                        ),
                    )
                })?;
            refusals.push(Refusal {
                path: directory.clone(),
                scope: Scope::Root,
                judged: Some(judged),
            });
        }
    }
    require_no_grant_is_wholly_refused(&grants, &refusals, context)?;
    require_nothing_sensitive_stays_reachable(&grants, &refusals, context)?;
    require_supported_grants(&grants, context)?;
    let access: Vec<_> = grants
        .iter()
        .map(|grant| effective_access(grant, &grants))
        .collect();
    for (grant, access) in grants.iter_mut().zip(access) {
        grant.access = access;
    }
    for (entry, tree) in lists.deny_write.iter().zip(&write_protections) {
        if !grants.iter().any(|grant| {
            grant.operation == Operation::Write
                && grant.scope == Scope::Root
                && tree.starts_with(&grant.resolved)
        }) {
            return Err(refuse(
                context,
                &entry.display().to_string(),
                &format!(
                    "{} lies inside no `write` directory, so `deny_write` protects nothing there",
                    tree.display()
                ),
            ));
        }
    }
    Ok(DirectReach {
        grants,
        refusals,
        write_protections,
        write_protection_identities,
        command: None,
        installation: None,
    })
}

fn covers(outer: &DirectGrant, inner: &DirectGrant) -> bool {
    // Disclosure compares validated file/tree grants, which exclude directory-entry grants.
    outer.resolved == inner.resolved
        || outer.scope == Scope::Root && inner.resolved.starts_with(&outer.resolved)
}

fn require_supported_grants(
    grants: &[DirectGrant],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    containment::validate_grants(
        &grants
            .iter()
            .map(|grant| (grant.resolved.as_path(), grant.operation, grant.scope))
            .collect::<Vec<_>>(),
    )
    .map_err(|error| {
        if let containment::ContainmentError::WriteOnlyUnsupported { ref path, .. } = error
            && let Some(write) = grants
                .iter()
                .find(|grant| grant.operation == Operation::Write && grant.resolved == *path)
        {
            return refuse(
                context,
                &write.authored,
                &format!(
                    "Linux cannot enforce write-only access for `{}` at {}. \
                     Add an explicit `read` or `read_file` grant covering the entire write scope \
                     to request read-write access, or remove the write grant",
                    write.kind.key(),
                    write.resolved.display()
                ),
            );
        }
        refuse(context, "filesystem", &error.to_string())
    })
}

fn effective_access(grant: &DirectGrant, grants: &[DirectGrant]) -> &'static str {
    let (opposite, only, mixed) = match grant.operation {
        Operation::Read => (
            Operation::Write,
            "read-only",
            "read-only except read-write at overlapping write grants",
        ),
        Operation::Write => (
            Operation::Read,
            "write-only",
            "write-only except read-write at overlapping read grants",
        ),
        _ => return "",
    };
    if grants
        .iter()
        .any(|other| other.operation == opposite && covers(other, grant))
    {
        "read-write"
    } else if grants
        .iter()
        .any(|other| other.operation == opposite && covers(grant, other))
    {
        mixed
    } else {
        only
    }
}

/// Refuse a spawn when a granted path no longer has the identity the run judged.
pub(crate) fn require_judged_identities(
    reach: &DirectReach,
    table: &str,
) -> Result<(), ConfigError> {
    for grant in &reach.grants {
        let changed = |reason: &str| ConfigError::Filesystem {
            table: table.to_string(),
            entry: grant.authored.clone(),
            reason: format!(
                "{} {reason} since the run judged it. A spawn acts on the identity the run \
                 approved, so it is refused",
                grant.resolved.display()
            ),
        };
        let metadata = std::fs::symlink_metadata(&grant.resolved)
            .map_err(|source| changed(&format!("cannot be read ({source})")))?;
        if metadata.is_symlink() {
            return Err(changed("became a symbolic link"));
        }
        if metadata.is_dir() != (grant.scope != Scope::File) {
            return Err(changed("changed between a file and a directory"));
        }
        let now = grant
            .resolved
            .canonicalize()
            .map_err(|source| changed(&format!("cannot be resolved ({source})")))?;
        if now != grant.resolved {
            return Err(changed(&format!("resolves to {}", now.display())));
        }
        if grant.is_link() {
            let named = grant
                .lexical
                .canonicalize()
                .map_err(|source| changed(&format!("lost its link ({source})")))?;
            if named != grant.resolved {
                return Err(changed(&format!(
                    "is no longer what {} points at",
                    grant.lexical.display()
                )));
            }
        }
    }
    for (refusal, judged) in reach
        .refusals
        .iter()
        .filter_map(|refusal| refusal.judged.map(|judged| (refusal, judged)))
    {
        let changed = |reason: &str| ConfigError::Filesystem {
            table: table.to_string(),
            entry: refusal.path.display().to_string(),
            reason: format!(
                "{} {reason} since the run judged it. A path the run subtracted is no longer the \
                 file it was judged as, so the spawn is refused",
                refusal.path.display()
            ),
        };
        let metadata = std::fs::symlink_metadata(&refusal.path)
            .map_err(|source| changed(&format!("cannot be read ({source})")))?;
        if FileIdentity::of(&metadata) != judged {
            return Err(changed("was replaced"));
        }
    }
    for (tree, judged) in reach
        .write_protections
        .iter()
        .zip(&reach.write_protection_identities)
    {
        let changed = |reason: &str| ConfigError::Filesystem {
            table: table.to_string(),
            entry: tree.display().to_string(),
            reason: format!(
                "{} {reason} since the run judged it. A spawn protects the directory the run \
                 approved, so it is refused",
                tree.display()
            ),
        };
        let metadata = std::fs::symlink_metadata(tree)
            .map_err(|source| changed(&format!("cannot be read ({source})")))?;
        if metadata.is_symlink() {
            return Err(changed("became a symbolic link"));
        }
        let now = tree
            .canonicalize()
            .map_err(|source| changed(&format!("cannot be resolved ({source})")))?;
        if &now != tree {
            return Err(changed(&format!("resolves to {}", now.display())));
        }
        if FileIdentity::of(&metadata) != *judged {
            return Err(changed("was replaced"));
        }
    }
    Ok(())
}

/// One path that a secret source protects, with what it names.
type SourcePath<'a> = (&'a ProtectedPath, Spelled);

/// Each path that a secret source protects, with its spellings and the links on the way to it.
fn source_path_spellings<'a>(
    context: &FilesystemContext<'a>,
) -> Result<Vec<SourcePath<'a>>, ConfigError> {
    context
        .source_paths
        .iter()
        .map(|protected| Ok((protected, protected.spellings(context.operator_home)?)))
        .collect()
}

/// Refuse an authorizing entry that is a path of a secret source, lies inside one, or holds one,
/// and a writing entry that holds a symbolic link on the way to one.
fn require_outside_source_paths(
    kind: Grant,
    entry: &Path,
    protected: &[SourcePath<'_>],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    let authored = entry.display().to_string();
    // An entry that is not a host path is refused as one by `entry_grant`.
    let Ok(written) = expand_home(entry, &authored, context) else {
        return Ok(());
    };
    let granted = [resolved_to_its_deepest_existing_ancestor(&written), written];
    for (source, spelled) in protected {
        let (spellings, links) = (&spelled.spellings, &spelled.links);
        let reached = spellings.iter().find(|path| {
            granted
                .iter()
                .any(|granted| lies_within(granted, path) || lies_within(path, granted))
        });
        if let Some(path) = reached {
            return Err(refuse(
                context,
                &authored,
                &format!(
                    "this grant reaches {}, which the secret source `{}` keeps from each \
                     workload (its `{}` entry {:?}). Keep each grant outside the paths that a \
                     secret source names in `reads` and `deny`",
                    path.display(),
                    source.scheme,
                    source.list,
                    source.entry
                ),
            ));
        }
        // A change to a link needs a write to its folder, so the folder is what no write grant
        // may reach. A grant on the link itself reaches the path by identity, above.
        if !kind.writes() {
            continue;
        }
        let held = links.iter().find(|link| {
            link.parent()
                .is_some_and(|folder| granted.iter().any(|granted| lies_within(folder, granted)))
        });
        if let Some(link) = held {
            return Err(refuse(
                context,
                &authored,
                &format!(
                    "this write grant can change {}, a symbolic link on the way to {}, which the \
                     secret source `{}` keeps from each workload (its `{}` entry {:?}). Keep each \
                     write grant outside the folders that hold a link on the way to a path that \
                     a secret source names in `reads` and `deny`",
                    link.display(),
                    spellings.last().unwrap_or(link).display(),
                    source.scheme,
                    source.list,
                    source.entry
                ),
            ));
        }
    }
    Ok(())
}

/// One `deny` entry, which may name a path that does not exist yet.
fn denial(entry: &Path, context: &FilesystemContext<'_>) -> Result<Refusal, ConfigError> {
    let authored = entry.display().to_string();
    let lexical = expand_home(entry, &authored, context)?;
    let metadata = std::fs::symlink_metadata(&lexical).ok();
    let scope = match &metadata {
        Some(kind) if kind.is_file() => Scope::File,
        Some(_) => Scope::Root,
        None => {
            // A path that is not there yet: a tree refusal covers it whether it becomes a file or
            // a directory. The namespace backend has no lowering for it, so on Linux the entry is
            // refused here, by name, rather than at the trampoline.
            if cfg!(target_os = "linux") {
                return Err(refuse(
                    context,
                    &authored,
                    &format!(
                        "{} does not exist yet, and the Linux namespace backend cannot refuse a \
                         path that is not there; create it first, or deny an existing directory \
                         above it",
                        lexical.display()
                    ),
                ));
            }
            Scope::Root
        }
    };
    Ok(Refusal {
        path: lexical,
        scope,
        judged: metadata.as_ref().map(FileIdentity::of),
    })
}

/// A `deny_write` entry, which names an existing directory.
fn write_protection(
    entry: &Path,
    context: &FilesystemContext<'_>,
) -> Result<(PathBuf, FileIdentity), ConfigError> {
    let authored = entry.display().to_string();
    let lexical = expand_home(entry, &authored, context)?;
    match std::fs::symlink_metadata(&lexical) {
        Ok(metadata) if metadata.is_symlink() => Err(refuse(
            context,
            &authored,
            &match lexical.canonicalize() {
                Ok(target) => format!(
                    "{} is a symbolic link to {}. The link sits where the agent may be able to \
                     change it, so `deny_write` names the directory itself; name {} instead",
                    lexical.display(),
                    target.display(),
                    target.display()
                ),
                Err(error) => format!(
                    "{} is a symbolic link that cannot be resolved: {error}; name the directory \
                     itself",
                    lexical.display()
                ),
            },
        )),
        Ok(metadata) if metadata.is_dir() => {
            let resolved = lexical.canonicalize().map_err(|error| {
                refuse(
                    context,
                    &authored,
                    &format!("cannot resolve {}: {error}", lexical.display()),
                )
            })?;
            if resolved == lexical {
                Ok((resolved, FileIdentity::of(&metadata)))
            } else {
                Err(refuse(
                    context,
                    &authored,
                    &format!(
                        "{} is not the path the kernel checks, which is {}. A link or a `..` in the \
                         path can be changed under the protection, so name that path instead",
                        lexical.display(),
                        resolved.display()
                    ),
                ))
            }
        }
        Ok(_) => Err(refuse(
            context,
            &authored,
            &format!(
                "{} is not a directory; `deny_write` names a directory",
                lexical.display()
            ),
        )),
        Err(error) => Err(refuse(
            context,
            &authored,
            &format!(
                "{} cannot be read: {error}; create the directory before the box starts",
                lexical.display()
            ),
        )),
    }
}

/// Judge a read grant on `path` as a box judges a `read` entry, and return whether it lies in a
/// credential store.
pub(crate) fn judge_read_grant(path: &Path) -> Result<bool, (GrantRefusal, BoxError)> {
    let home = crate::record::layout::canonical(
        &crate::record::layout::operator_home_directory()
            .map_err(|error| (GrantRefusal::Other, error))?,
    );
    let context = FilesystemContext {
        table: "check_read_grant",
        operator_home: &home,
        policy: None,
        authority_directories: Vec::new(),
        program_search_directories: Vec::new(),
        source_paths: &[],
    };
    entry_grant(Grant::Read, path, &context)
        .map(|grant| grant.credential_store)
        .map_err(|(kind, error)| (kind, BoxError::from(error)))
}

/// One authorizing entry as a grant, refused by name for each class it falls in, with the kind of
/// each refusal.
fn entry_grant(
    kind: Grant,
    entry: &Path,
    context: &FilesystemContext<'_>,
) -> Result<DirectGrant, (GrantRefusal, ConfigError)> {
    let authored = entry.display().to_string();
    let refused = |kind, reason: &str| (kind, refuse(context, &authored, reason));
    let other = |reason: &str| refused(GrantRefusal::Other, reason);
    let lexical = expand_home(entry, &authored, context)
        .map_err(|error| (GrantRefusal::NotAbsolute, error))?;

    // **An authored grant on an absent path is refused, never skipped.** A grant that silently
    // does nothing is the defect class this repository has recorded twice.
    let metadata = std::fs::symlink_metadata(&lexical).map_err(|source| match source.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => refused(
            GrantRefusal::Absent,
            &format!(
                "{} is not there: {source}. A grant on a path that does not exist grants nothing \
                 and says so nowhere",
                lexical.display()
            ),
        ),
        _ => other(&format!("cannot read {}: {source}", lexical.display())),
    })?;
    // **A read-only entry may name a link to a file**, such as `/usr/bin/cc`, because a program
    // runs a helper by the name `PATH` finds. The grant is the file the link resolves to, and the
    // box shows that file under the link's own name as well. The link must sit in its real folder,
    // so the name is the one the program opens.
    let link = metadata.is_symlink()
        && matches!(kind, Grant::Read | Grant::ReadFile)
        && lexical
            .parent()
            .is_some_and(|folder| folder.canonicalize().is_ok_and(|real| real == folder))
        && lexical.canonicalize().is_ok_and(|target| target.is_file());
    let metadata = if link {
        std::fs::metadata(&lexical)
            .map_err(|source| other(&format!("cannot read {}: {source}", lexical.display())))?
    } else {
        metadata
    };
    if metadata.is_symlink() {
        // Name the target so the operator can paste it into the grant. A missing target and a
        // resolve failure (permission, link loop) are different problems; say which one it is.
        let named = |reason: &str| refuse(context, &authored, reason);
        return Err((
            GrantRefusal::Link,
            match lexical.canonicalize() {
                Ok(target) => named(&format!(
                    "{} is a symbolic link to {}. A grant carries the identity the kernel checks,                  so a link renders a rule that matches nothing; name {} instead",
                    lexical.display(),
                    target.display(),
                    target.display()
                )),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => named(&format!(
                    "{} is a symbolic link whose target is missing. A grant carries the identity                  the kernel checks, so a link renders a rule that matches nothing; repair the                  link or name a path that exists",
                    lexical.display()
                )),
                Err(source) => named(&format!(
                    "{} is a symbolic link that cannot be resolved: {source}. A grant carries the                  identity the kernel checks, so a link renders a rule that matches nothing;                  repair the link or name a path that exists",
                    lexical.display()
                )),
            },
        ));
    }
    let resolved = lexical
        .canonicalize()
        .map_err(|source| other(&format!("cannot resolve {}: {source}", lexical.display())))?;
    if resolved != lexical && !link {
        // Not necessarily a link: `canonicalize` also folds `.` and `..`, so the message names
        // what is actually wrong, which is that the authored spelling is not the identity the kernel
        // checks.
        return Err(refused(
            GrantRefusal::NotCanonical,
            &format!(
                "{} is not the path the kernel checks, which is {}. A grant carries the identity it \
                 acts on, so name that path instead",
                lexical.display(),
                resolved.display()
            ),
        ));
    }

    let is_directory = metadata.is_dir();
    let key = kind.key();
    let (operation, scope) = match (kind, is_directory) {
        (Grant::Read, true) => (Operation::Read, Scope::Root),
        (Grant::Read, false) => (Operation::Read, Scope::File),
        (Grant::Write, true) => (Operation::Write, Scope::Root),
        (Grant::Write, false) => (Operation::Write, Scope::File),
        (Grant::ReadFile, false) => (Operation::Read, Scope::File),
        (Grant::WriteFile, false) => (Operation::Write, Scope::File),
        (Grant::ReadFile | Grant::WriteFile, true) => {
            return Err(other(&format!(
                "{} is a directory; `{key}` names one file, and a tree belongs in `{}`",
                resolved.display(),
                if kind == Grant::ReadFile {
                    "read"
                } else {
                    "write"
                }
            )));
        }
        (Grant::List, true) => {
            if cfg!(target_os = "linux") {
                return Err(other(&format!(
                    "{} cannot be listed without its contents on Linux: the namespace backend \
                     has no lowering for `list`; grant `read` instead",
                    resolved.display()
                )));
            }
            (Operation::List, Scope::Root)
        }
        (Grant::List, false) => {
            return Err(other(&format!(
                "{} is a file, and `list` enumerates a directory tree",
                resolved.display()
            )));
        }
        (Grant::Metadata, true) => (Operation::Metadata, Scope::Root),
        (Grant::Metadata, false) => {
            return Err(other(&format!(
                "{} is a file, and a file's metadata comes with the `read_file` or `exec` grant \
                 that names it",
                resolved.display()
            )));
        }
        (Grant::Exec, true) => (Operation::Exec, Scope::Root),
        (Grant::Exec, false) => {
            if !crate::run::contain::executable::is_executable(&resolved) {
                return Err(other(&format!(
                    "{} is not an executable regular file",
                    resolved.display()
                )));
            }
            (Operation::Exec, Scope::File)
        }
        (Grant::Deny, _) => unreachable!("a denial is built by `denial`"),
        (Grant::DenyWrite, _) => unreachable!("a write protection is built by `write_protection`"),
    };

    // A writable search directory is the same defect one step earlier: the box execs a bare name
    // off the operator's `PATH`, so whoever writes that directory picks the program. Only a
    // WRITE entry reaches it, because reading a directory on the search path grants nothing.
    if kind.writes() {
        for directory in &context.program_search_directories {
            if directory.starts_with(&resolved) {
                return Err(other(&format!(
                    "{} is at or above {}, which is on the search path this box resolves a \
                     bare-name MCP program against. That program starts outside containment at \
                     the operator's identity, so a writable directory there is a program the \
                     workload chooses",
                    resolved.display(),
                    directory.display()
                )));
            }
        }
    }

    // The floor beneath every grant: a system tree, the whole filesystem, the machine's own stores.
    // A credential store named exactly is the one exception, and it is stated rather than silent.
    let credential_store =
        containment::validate_grant(&lexical, context.operator_home, operation, scope).map_err(
            |error| {
                let (_, refused) = other(&format!(
                    "{} is refused beneath every grant: {error}",
                    resolved.display()
                ));
                let kind = error
                    .forbidden_class()
                    .map_or(GrantRefusal::Other, GrantRefusal::Forbidden);
                (kind, refused)
            },
        )?;
    // **A link inside a credential store stays refused.** The store exception re-resolves the
    // entry at each spawn, so a link there could be pointed at another file of the store during a
    // run, such as `~/.ssh/config` at `~/.ssh/id_ed25519`.
    if link && credential_store {
        return Err(refused(
            GrantRefusal::Link,
            &format!(
                "{} is a symbolic link in a credential store. A store entry must name the file                  itself, so name {} instead",
                lexical.display(),
                resolved.display()
            ),
        ));
    }

    Ok(DirectGrant {
        kind,
        authored,
        lexical,
        resolved,
        operation,
        scope,
        credential_store,
        access: "",
    })
}

/// The authored path with `~` or `~/` replaced by the operator's home.
fn expand_home(
    entry: &Path,
    authored: &str,
    context: &FilesystemContext<'_>,
) -> Result<PathBuf, ConfigError> {
    // The entry itself, so a path that is not text keeps each byte.
    if entry.is_absolute() {
        return Ok(entry.to_path_buf());
    }
    under_home(authored, context.operator_home).ok_or_else(|| {
        refuse(
            context,
            authored,
            "a path is absolute or `~`-relative, so a checked-in configuration holds in every \
             clone; this one is neither",
        )
    })
}

/// `authored` with `~` or `~/` replaced by `home`, when it is `~`-relative or absolute.
pub(crate) fn under_home(authored: &str, home: &Path) -> Option<PathBuf> {
    match authored.strip_prefix("~/") {
        Some(relative) => Some(home.join(relative)),
        None if authored == "~" => Some(home.to_path_buf()),
        None if Path::new(authored).is_absolute() => Some(PathBuf::from(authored)),
        None => None,
    }
}

/// Refuse a configuration that leaves something sensitive reachable once the refusals are applied.
///
/// **This is what lets an entry name the project without handing over the box's authority.** Such
/// an entry grants a tree that holds the directory this box's authority was read from, so it is
/// judged against its EFFECTIVE reach, the grants minus the refusals. Checking the raw grant would
/// refuse every project entry outright.
fn require_nothing_sensitive_stays_reachable(
    grants: &[DirectGrant],
    refusals: &[Refusal],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    let refused = |path: &Path| {
        refusals.iter().any(|hidden| match hidden.scope {
            Scope::Root => path.starts_with(&hidden.path),
            _ => path == hidden.path,
        })
    };
    let reaching = |path: &Path| -> Option<&DirectGrant> {
        grants.iter().find(|grant| {
            grant.operation == Operation::Write
                && !refused(path)
                && match grant.scope {
                    Scope::Root => path.starts_with(&grant.resolved),
                    _ => path == grant.resolved,
                }
        })
    };

    // The policy file is checked against WRITABLE grants: writing it rewrites the box's
    // authority, and a read grant that encloses it is a stated disclosure rather than authority.
    // Private Box state is judged in `boundary`, on the guard every grant kind shares.
    if let Some(policy) = context.policy
        && let Some(grant) = reaching(policy)
    {
        return Err(refuse(
            context,
            &grant.authored,
            &format!(
                "`{}` reaches this box's policy file, {}. A grant may enclose it only when it is \
                 subtracted, and nothing subtracts it here",
                grant.kind.key(),
                policy.display()
            ),
        ));
    }
    Ok(())
}

/// Refuse a grant a refusal covers completely, because it would enforce nothing and say so nowhere.
///
/// A refusal strictly INSIDE a grant is the carve-out these keys are built on: the project stays
/// granted and the directory holding its authority does not. A refusal covering the whole grant is
/// different: the grant renders, the startup disclosure names it, and the workload reaches none of it.
fn require_no_grant_is_wholly_refused(
    grants: &[DirectGrant],
    refusals: &[Refusal],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    for grant in grants {
        for hidden in refusals {
            let covered = match hidden.scope {
                Scope::Root => grant.resolved.starts_with(&hidden.path),
                _ => grant.resolved == hidden.path,
            };
            if covered {
                return Err(refuse(
                    context,
                    &grant.authored,
                    &format!(
                        "{} is at or inside {}, which no grant reaches. The grant would render and \
                         reach nothing, so it is refused rather than left enforcing nothing",
                        grant.resolved.display(),
                        hidden.path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Refuse two grants of one operation that name one path, or nest, because the union enforces a
/// boundary no member states.
fn require_no_overlap(
    grants: &[DirectGrant],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    for (index, grant) in grants.iter().enumerate() {
        for other in grants.iter().skip(index + 1) {
            if grant.operation != other.operation {
                continue;
            }
            // A link adds its own name, so two names for one file are two grants. A grant whose
            // every name the other already has adds nothing, such as a link listed beside its file.
            let adds = |one: &DirectGrant, two: &DirectGrant| {
                one.names().iter().any(|name| !two.names().contains(name))
            };
            if grant.resolved == other.resolved && !(adds(grant, other) && adds(other, grant)) {
                return Err(refuse(
                    context,
                    &other.authored,
                    &format!(
                        "{} is granted {} twice, by `{}` and `{}`",
                        grant.resolved.display(),
                        grant.kind.key(),
                        grant.kind.key(),
                        other.kind.key()
                    ),
                ));
            }
            let (inner, outer) = if other.resolved.starts_with(&grant.resolved) {
                (other, grant)
            } else if grant.resolved.starts_with(&other.resolved) {
                (grant, other)
            } else {
                continue;
            };
            if outer.scope != Scope::Root {
                continue;
            }
            // A link whose own name lies outside the tree reaches the file at a name the tree
            // does not, such as `/usr/bin/java` beside the JDK folder it points into.
            if inner.is_link() && !inner.lexical.starts_with(&outer.resolved) {
                continue;
            }
            return Err(refuse(
                context,
                &inner.authored,
                &format!(
                    "{} lies inside {}, granted by `{}`. The union is the wider grant, so the \
                     narrower one enforces nothing it appears to",
                    inner.resolved.display(),
                    outer.resolved.display(),
                    outer.kind.key()
                ),
            ));
        }
    }
    Ok(())
}

/// Refuse an entry, naming its table, it, and why.
fn refuse(context: &FilesystemContext<'_>, authored: &str, reason: &str) -> ConfigError {
    ConfigError::Filesystem {
        table: context.table.to_string(),
        entry: authored.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(text: &str) -> Filesystem {
        toml::from_str(text).expect("the lists parse")
    }

    /// One home holding a project, a box root, and the paths the cases below name.
    struct Fixture {
        home: PathBuf,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a home");
            let home = directory.path().canonicalize().expect("a canonical home");
            for relative in [
                "project/src",
                "project/.strands-box",
                "vendor/sdk",
                "scratch",
                "notes",
                "tools",
                "bin",
            ] {
                std::fs::create_dir_all(home.join(relative)).expect("a directory");
            }
            std::fs::write(home.join("project/.strands-box/policy.dw"), "").expect("a policy");
            std::fs::write(home.join("notes/api.md"), "").expect("a file");
            for script in ["tools/run", "bin/run"] {
                std::fs::write(home.join(script), "#!/bin/sh\n").expect("a script");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(
                        home.join(script),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .expect("an executable script");
                }
            }
            Self {
                home,
                _directory: directory,
            }
        }

        fn context(&self) -> FilesystemContext<'_> {
            FilesystemContext {
                table: "[agent]",
                operator_home: &self.home,
                policy: None,
                authority_directories: Vec::new(),
                program_search_directories: Vec::new(),
                source_paths: &[],
            }
        }

        /// The context of a box whose `box.toml` and `policy.dw` were read from `directory`.
        fn context_with_authority_in(&self, directory: &Path) -> FilesystemContext<'_> {
            FilesystemContext {
                authority_directories: vec![directory.to_path_buf()],
                ..self.context()
            }
        }

        fn reach(&self, context: &FilesystemContext<'_>, body: &str) -> DirectReach {
            direct_grants(&lists(body), context)
                .unwrap_or_else(|error| panic!("{body:?} must be granted: {error}"))
        }

        /// The refusal one set of lists produces, or a panic when it was accepted.
        fn refusal(&self, context: &FilesystemContext<'_>, body: &str) -> String {
            match direct_grants(&lists(body), context) {
                Ok(grants) => panic!("{body:?} must be refused; it granted {grants:?}"),
                Err(error) => error.to_string(),
            }
        }
    }

    fn text(path: &Path) -> String {
        path.display().to_string()
    }

    /// **A `deny_write` entry names an existing directory inside a `write` tree**, and is carried
    /// canonical beside the grants rather than as one.
    #[test]
    fn a_deny_write_entry_is_a_directory_inside_a_write_tree() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let reach = fixture.reach(
            &context,
            "read = ['~/project']\nwrite = ['~/project']\ndeny_write = ['~/project/src']",
        );
        assert_eq!(reach.write_protections, [fixture.home.join("project/src")]);
        assert!(reach.refusals.is_empty());
        assert!(
            reach
                .grants
                .iter()
                .all(|grant| grant.kind != Grant::DenyWrite)
        );

        for (body, reason) in [
            (
                "read = ['~/scratch']\nwrite = ['~/scratch']\ndeny_write = ['~/project/src']",
                "lies inside no `write`",
            ),
            (
                "read = ['~/project']\ndeny_write = ['~/project/src']",
                "lies inside no `write`",
            ),
            (
                "read = ['~/notes']\nwrite = ['~/notes']\ndeny_write = ['~/notes/api.md']",
                "is not a directory",
            ),
            (
                "read = ['~/project']\nwrite = ['~/project']\ndeny_write = ['~/project/absent']",
                "cannot be read",
            ),
        ] {
            let refusal = fixture.refusal(&context, body);
            assert!(refusal.contains(reason), "{body:?}: {refusal}");
        }
    }

    #[test]
    fn a_deny_write_entry_refuses_a_link_and_a_non_canonical_spelling() {
        let fixture = Fixture::new();
        let context = fixture.context();
        let project = fixture.home.join("project");
        std::os::unix::fs::symlink(project.join("src"), project.join("venv-link"))
            .expect("a link to the directory");
        std::os::unix::fs::symlink(&project, fixture.home.join("project-link"))
            .expect("a link to an ancestor");
        for (body, reason) in [
            (
                "read = ['~/project']\nwrite = ['~/project']\ndeny_write = ['~/project/venv-link']",
                "is a symbolic link",
            ),
            (
                "read = ['~/project']\nwrite = ['~/project']\ndeny_write = ['~/project-link/src']",
                "is not the path the kernel checks",
            ),
            (
                "read = ['~/project']\nwrite = ['~/project']\ndeny_write = ['~/project/src/../src']",
                "is not the path the kernel checks",
            ),
        ] {
            let refusal = fixture.refusal(&context, body);
            assert!(refusal.contains(reason), "{body:?}: {refusal}");
        }
    }

    fn identity(path: &Path) -> FileIdentity {
        FileIdentity::of(&std::fs::symlink_metadata(path).expect("the path is there"))
    }

    #[test]
    fn absent_lists_state_no_grant() {
        let fixture = Fixture::new();
        let reach = direct_grants(&Filesystem::default(), &fixture.context()).expect("empty");
        assert!(reach.grants.is_empty());
        assert!(reach.refusals.is_empty());
    }

    #[test]
    fn linux_write_access_requires_explicit_read_coverage() {
        let fixture = Fixture::new();
        let context = fixture.context();
        for (body, accepted) in [
            ("write_file = ['~/notes/api.md']", false),
            ("write = ['~/notes/api.md']", false),
            ("write = ['~/project']", false),
            ("read = ['~/notes']\nwrite = ['~/project']", false),
            ("read = ['~/project/src']\nwrite = ['~/project']", false),
            ("read_file = ['~/notes/api.md']\nwrite = ['~/notes']", false),
            (
                "exec = ['~/tools/run']\nwrite_file = ['~/tools/run']",
                false,
            ),
            ("read = ['~/project']\nwrite = ['~/project']", true),
            ("read = ['~/project']\nwrite = ['~/project/src']", true),
            ("read = ['~/notes']\nwrite_file = ['~/notes/api.md']", true),
            (
                "read_file = ['~/notes/api.md']\nwrite_file = ['~/notes/api.md']",
                true,
            ),
            (
                "read = ['~/notes/api.md']\nwrite = ['~/notes/api.md']",
                true,
            ),
            ("read = ['~/project']", true),
        ] {
            let grants: Vec<_> = lists(body)
                .entries()
                .map(|(kind, path)| {
                    entry_grant(kind, path, &context)
                        .map_err(|(_, error)| error)
                        .unwrap()
                })
                .collect();
            let result = require_supported_grants(&grants, &context);
            assert_eq!(
                result.is_ok(),
                accepted || !cfg!(target_os = "linux"),
                "{body}: {result:?}"
            );
            if let Err(error) = result {
                let error = error.to_string();
                assert!(error.contains("Linux cannot enforce write-only"), "{error}");
                assert!(error.contains("[agent]"), "{error}");
                assert!(error.contains("explicit `read` or `read_file`"), "{error}");
            }
        }
    }

    #[test]
    fn disclosures_distinguish_complete_and_partial_access() {
        let fixture = Fixture::new();
        for (body, modes) in [
            ("read = ['~/notes']", vec!["read-only"]),
            (
                "read_file = ['~/notes/api.md']\nwrite_file = ['~/notes/api.md']",
                vec!["read-write", "read-write"],
            ),
            (
                "read = ['~/project']\nwrite = ['~/project/src']",
                vec![
                    "read-only except read-write at overlapping write grants",
                    "read-write",
                ],
            ),
            (
                "read = ['~/notes']\nwrite_file = ['~/notes/api.md']",
                vec![
                    "read-only except read-write at overlapping write grants",
                    "read-write",
                ],
            ),
        ] {
            let reach = fixture.reach(&fixture.context(), body);
            let actual: Vec<_> = reach.grants.iter().map(|grant| grant.access).collect();
            assert_eq!(actual, modes, "{body}");
            for grant in &reach.grants {
                assert!(grant.disclosure().contains(&format!("({})", grant.access)));
                assert!(!grant.disclosure().contains("readable too"));
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_preserves_write_only_and_partial_read_grants() {
        let fixture = Fixture::new();
        let reach = fixture.reach(&fixture.context(), "write_file = ['~/notes/api.md']");
        assert_eq!(reach.grants[0].access, "write-only");
        let reach = fixture.reach(
            &fixture.context(),
            "read_file = ['~/notes/api.md']\nwrite = ['~/notes']",
        );
        assert_eq!(
            reach.grants[0].access,
            "write-only except read-write at overlapping read grants"
        );
        assert_eq!(reach.grants[1].access, "read-write");
    }

    /// **Each list maps to its cell**, on a directory and on a file where both are legal.
    #[test]
    fn every_list_translates_to_its_cell() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let body = format!(
            "read = [{:?}, {:?}]\nwrite = [{:?}]\nread_file = [{:?}]\nwrite_file = [{:?}]\n\
             metadata = [{:?}]\nexec = [{:?}, {:?}]\ndeny = [{:?}]",
            text(&home.join("vendor")),
            text(&home.join("scratch")),
            text(&home.join("scratch")),
            text(&home.join("notes/api.md")),
            text(&home.join("notes/api.md")),
            text(&home.join("notes")),
            text(&home.join("tools")),
            text(&home.join("bin/run")),
            text(&home.join("vendor/sdk")),
        );
        let reach = fixture.reach(&fixture.context(), &body);
        let cells: Vec<(Grant, Operation, Scope)> = reach
            .grants
            .iter()
            .map(|grant| (grant.kind, grant.operation, grant.scope))
            .collect();
        assert_eq!(
            cells,
            [
                (Grant::Read, Operation::Read, Scope::Root),
                (Grant::Read, Operation::Read, Scope::Root),
                (Grant::Write, Operation::Write, Scope::Root),
                (Grant::ReadFile, Operation::Read, Scope::File),
                (Grant::WriteFile, Operation::Write, Scope::File),
                (Grant::Metadata, Operation::Metadata, Scope::Root),
                (Grant::Exec, Operation::Exec, Scope::Root),
                (Grant::Exec, Operation::Exec, Scope::File),
            ]
        );
        assert_eq!(
            reach.refusals,
            [Refusal {
                path: home.join("vendor/sdk"),
                scope: Scope::Root,
                judged: Some(identity(&home.join("vendor/sdk"))),
            }],
            "a denied directory inside a read tree is a tree refusal"
        );
        assert!(
            reach.grants.iter().all(|grant| !grant.credential_store),
            "an ordinary path is not a punch-through"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn list_and_a_future_deny_translate_where_the_backend_lowers_them() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let body = format!(
            "list = [{:?}]\ndeny = [{:?}, {:?}]",
            text(&home.join("vendor")),
            text(&home.join("notes/api.md")),
            text(&home.join("vendor/future.env")),
        );
        let reach = fixture.reach(&fixture.context(), &body);
        assert_eq!(reach.grants[0].operation, Operation::List);
        assert_eq!(reach.grants[0].scope, Scope::Root);
        assert_eq!(
            reach.refusals,
            [
                Refusal {
                    path: home.join("notes/api.md"),
                    scope: Scope::File,
                    judged: Some(identity(&home.join("notes/api.md"))),
                },
                Refusal {
                    path: home.join("vendor/future.env"),
                    scope: Scope::Root,
                    judged: None,
                },
            ],
            "an existing file is refused at file scope; a path not there yet as a tree"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn list_and_a_future_deny_are_refused_by_name_on_linux() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let context = fixture.context();
        let refusal = fixture.refusal(
            &context,
            &format!("list = [{:?}]", text(&home.join("vendor"))),
        );
        assert!(
            refusal.contains("no lowering for `list`") && refusal.contains("read"),
            "{refusal}"
        );
        let refusal = fixture.refusal(
            &context,
            &format!("deny = [{:?}]", text(&home.join("vendor/future.env"))),
        );
        assert!(
            refusal.contains("does not exist yet") && refusal.contains("Linux"),
            "{refusal}"
        );
    }

    /// **One case per refusal class, each asserting the message names the table and the entry.**
    #[test]
    fn every_refusal_class_fires_and_names_the_entry() {
        let fixture = Fixture::new();
        let home = fixture.home.clone();
        let context = fixture.context();

        // A path that does not exist is refused, never skipped.
        let absent = home.join("not-there");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&absent)));
        assert!(
            refusal.contains("not there")
                && refusal.contains(&text(&absent))
                && refusal.contains("[agent]"),
            "{refusal}"
        );

        // A symlinked entry, whose authored spelling and identity differ.
        let link = home.join("vendor-link");
        let target = home.join("vendor/sdk");
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&link)));
        assert!(
            refusal.contains("symbolic link")
                && refusal.contains(&text(&link))
                && refusal.contains(&text(&target))
                && refusal.contains("instead"),
            "{refusal}"
        );

        // A read-only entry may name a link to a file. It grants the file, and keeps the link's
        // own name so the box shows the file there too.
        let file_link = home.join("api-link.md");
        let file = home.join("notes/api.md");
        std::os::unix::fs::symlink(&file, &file_link).expect("a link to a file");
        for (list, kind) in [("read", Grant::Read), ("read_file", Grant::ReadFile)] {
            let reach = fixture.reach(&context, &format!("{list} = [{:?}]", text(&file_link)));
            let grant = &reach.grants[0];
            assert_eq!(
                grant,
                &DirectGrant {
                    kind,
                    authored: text(&file_link),
                    lexical: file_link.clone(),
                    resolved: file.clone(),
                    operation: Operation::Read,
                    scope: Scope::File,
                    credential_store: false,
                    access: "read-only",
                },
                "{list}"
            );
            assert!(grant.is_link(), "{list}");
            assert!(
                grant
                    .disclosure()
                    .contains(&format!("{} -> {}", text(&file_link), text(&file))),
                "{}",
                grant.disclosure()
            );
        }

        // Two links to one file are two names, and a link beside the tree its file is in reaches a
        // name the tree does not: both are granted.
        let second_link = home.join("api-other.md");
        std::os::unix::fs::symlink(&file, &second_link).expect("a second link");
        let reach = fixture.reach(
            &context,
            &format!(
                "read_file = [{:?}, {:?}]",
                text(&file_link),
                text(&second_link)
            ),
        );
        assert_eq!(reach.grants.len(), 2);
        let reach = fixture.reach(
            &context,
            &format!("read = ['~/notes']\nread_file = [{:?}]", text(&file_link)),
        );
        assert_eq!(reach.grants.len(), 2);
        // A link inside the tree it points into adds no name the tree lacks.
        let inner_link = home.join("notes/api-alias.md");
        std::os::unix::fs::symlink(&file, &inner_link).expect("a link inside the tree");
        let refusal = fixture.refusal(
            &context,
            &format!("read = ['~/notes']\nread_file = [{:?}]", text(&inner_link)),
        );
        assert!(refusal.contains("lies inside"), "{refusal}");

        // Only a read: a write, an exec or a metadata entry naming a link stays refused.
        for list in ["write_file", "metadata"] {
            let refusal = fixture.refusal(
                &context,
                &format!("read = ['~/notes']\n{list} = [{:?}]", text(&file_link)),
            );
            assert!(refusal.contains("symbolic link"), "{list}: {refusal}");
        }
        let run_link = home.join("run-link");
        std::os::unix::fs::symlink(home.join("tools/run"), &run_link).expect("a link to a script");
        let refusal = fixture.refusal(&context, &format!("exec = [{:?}]", text(&run_link)));
        assert!(refusal.contains("symbolic link"), "{refusal}");

        // A link reached through a linked folder is refused: the name must be the one opened.
        let linked_folder = home.join("notes-link");
        std::os::unix::fs::symlink(home.join("notes"), &linked_folder).expect("a linked folder");
        let through = linked_folder.join("api.md");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&through)));
        assert!(
            refusal.contains("not the path the kernel checks"),
            "{refusal}"
        );
        let inner_link = home.join("notes/api-link.md");
        std::os::unix::fs::symlink(&file, &inner_link).expect("a link beside its file");
        let refusal = fixture.refusal(
            &context,
            &format!("read = [{:?}]", text(&linked_folder.join("api-link.md"))),
        );
        assert!(refusal.contains("symbolic link"), "{refusal}");

        // A link inside a credential store is refused: the store exception would follow it again
        // at each spawn.
        std::fs::create_dir_all(home.join(".ssh")).expect("an SSH directory");
        std::fs::write(home.join(".ssh/config.real"), "").expect("a real config");
        std::os::unix::fs::symlink(home.join(".ssh/config.real"), home.join(".ssh/config"))
            .expect("a link in the store");
        let refusal = fixture.refusal(&context, "read_file = ['~/.ssh/config']");
        assert!(
            refusal.contains("symbolic link in a credential store"),
            "{refusal}"
        );
        let refused = entry_grant(Grant::ReadFile, Path::new("~/.ssh/config"), &context)
            .expect_err("a store link");
        assert_eq!(refused.0, GrantRefusal::Link);

        // A link into a credential store is judged by the store it reaches.
        std::fs::create_dir_all(home.join(".ssh")).expect("an SSH directory");
        std::fs::write(home.join(".ssh/id_ed25519"), "").expect("a key");
        let key_link = home.join("key-link");
        std::os::unix::fs::symlink(home.join(".ssh/id_ed25519"), &key_link).expect("a key link");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&key_link)));
        assert!(refusal.contains("refused"), "{refusal}");

        // A link and its file in one list grant one file twice.
        let refusal = fixture.refusal(
            &context,
            &format!("read_file = [{:?}, {:?}]", text(&file_link), text(&file)),
        );
        assert!(refusal.contains("twice"), "{refusal}");

        // A broken symlink has no canonical target; the refusal must still name the link.
        let broken = home.join("broken-link");
        std::os::unix::fs::symlink(home.join("no-such-target"), &broken).expect("a broken link");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&broken)));
        assert!(
            refusal.contains("symbolic link")
                && refusal.contains(&text(&broken))
                && refusal.contains("target is missing"),
            "{refusal}"
        );

        // A link that points at itself fails canonicalize with a loop, not NotFound.
        let looped = home.join("loop-link");
        std::os::unix::fs::symlink(&looped, &looped).expect("a self link");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&looped)));
        assert!(
            refusal.contains("symbolic link")
                && refusal.contains(&text(&looped))
                && refusal.contains("cannot be resolved"),
            "{refusal}"
        );

        // A spelling that is neither absolute nor `~`-relative.
        let refusal = fixture.refusal(&context, "read = [\"relative/path\"]");
        assert!(
            refusal.contains("absolute or `~`-relative") && refusal.contains("relative/path"),
            "{refusal}"
        );

        // A kind that disagrees with the filesystem.
        for (body, expected) in [
            (
                format!("read_file = [{:?}]", text(&home.join("notes"))),
                "names one file",
            ),
            (
                format!("write_file = [{:?}]", text(&home.join("notes"))),
                "names one file",
            ),
            (
                format!("list = [{:?}]", text(&home.join("notes/api.md"))),
                "is a file",
            ),
            (
                format!("metadata = [{:?}]", text(&home.join("notes/api.md"))),
                "comes with the `read_file` or `exec` grant",
            ),
            (
                format!("exec = [{:?}]", text(&home.join("notes/api.md"))),
                "not an executable regular file",
            ),
        ] {
            let refusal = fixture.refusal(&context, &body);
            assert!(refusal.contains(expected), "{body}: {refusal}");
        }

        // One path granted one operation twice, across two lists or within one.
        let notes = home.join("notes/api.md");
        let refusal = fixture.refusal(
            &context,
            &format!("read = [{0:?}]\nread_file = [{0:?}]", text(&notes)),
        );
        assert!(refusal.contains("twice"), "{refusal}");

        // A nested entry in one list.
        let refusal = fixture.refusal(
            &context,
            &format!(
                "read = [{:?}, {:?}]",
                text(&home.join("vendor")),
                text(&home.join("vendor/sdk"))
            ),
        );
        assert!(
            refusal.contains("lies inside") && refusal.contains(&text(&home.join("vendor/sdk"))),
            "{refusal}"
        );

        // A grant a denial covers completely.
        let refusal = fixture.refusal(
            &context,
            &format!(
                "read = [{0:?}]\ndeny = [{0:?}]",
                text(&home.join("vendor/sdk"))
            ),
        );
        assert!(refusal.contains("no grant reaches"), "{refusal}");

        // The whole filesystem, and a system tree, beneath every grant.
        for tree in ["/", "/usr"] {
            let refusal = fixture.refusal(&context, &format!("read = [{tree:?}]"));
            assert!(
                refusal.contains("refused beneath every grant"),
                "{tree}: {refusal}"
            );
        }
    }

    /// **`write` no longer implies `read`**, so naming one path in both is how read-write is stated,
    /// and a write root inside a read root is a narrowing rather than a conflict.
    #[test]
    fn read_and_write_compose_rather_than_conflict() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let reach = fixture.reach(
            &fixture.context(),
            &format!(
                "read = [{0:?}, {1:?}]\nwrite = [{0:?}, {1:?}]",
                text(&home.join("scratch")),
                text(&home.join("notes"))
            ),
        );
        assert_eq!(reach.grants.len(), 4);
        let reach = fixture.reach(
            &fixture.context(),
            &format!(
                "read = [{:?}]\nwrite = [{:?}]",
                text(&home.join("project")),
                text(&home.join("project/src"))
            ),
        );
        assert_eq!(
            reach
                .grants
                .iter()
                .map(|grant| grant.operation)
                .collect::<Vec<_>>(),
            [Operation::Read, Operation::Write]
        );
    }

    /// **A credential store named exactly is a disclosed punch-through; one beneath a grant is
    /// refused.**
    #[test]
    fn a_credential_store_is_granted_only_when_named_exactly() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::fs::create_dir_all(home.join(".aws")).expect("a credential store");
        std::fs::write(home.join(".aws/credentials"), "").expect("a credential");
        let context = fixture.context();

        let reach = fixture.reach(&context, "read = [\"~/.aws\"]");
        assert!(reach.grants[0].credential_store, "{:?}", reach.grants);
        assert_eq!(reach.grants[0].lexical, home.join(".aws"));

        let refusal = fixture.refusal(&context, "read = [\"~\"]");
        assert!(
            refusal.contains("refused beneath every grant"),
            "the home encloses a credential store: {refusal}"
        );
    }

    /// One `reads` or `deny` entry of the secret source `scheme`.
    fn protected(scheme: &str, list: &'static str, entry: &str) -> ProtectedPath {
        ProtectedPath {
            scheme: scheme.to_string(),
            list,
            entry: entry.to_string(),
        }
    }

    /// The refusal of `authored` in `[agent]`, which reaches `path` of the source entry.
    fn source_refusal(
        authored: &str,
        path: &Path,
        scheme: &str,
        list: &str,
        entry: &str,
    ) -> String {
        format!(
            "`[agent]` filesystem entry {authored:?} is refused: this grant reaches {}, which \
             the secret source `{scheme}` keeps from each workload (its `{list}` entry \
             {entry:?}). Keep each grant outside the paths that a secret source names in \
             `reads` and `deny`",
            path.display()
        )
    }

    /// **No grant reaches a path that a secret source protects**: the path itself, a path inside
    /// it, or a folder that holds it, in each list that authorizes.
    #[test]
    fn a_grant_that_reaches_a_path_of_a_secret_source_is_refused() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::fs::write(home.join("vendor/sdk/config"), "").expect("a file of the source");
        std::fs::write(home.join("tools/vault"), "").expect("a file of the source");
        let paths = [
            protected("op", "reads", "~/vendor/sdk"),
            protected(
                "aws-secretsmanager",
                "deny",
                &text(&home.join("tools/vault")),
            ),
        ];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        let sdk = home.join("vendor/sdk");
        let mut cases = vec![
            // The path, a file inside it, and a folder that holds it.
            ("read", "~/vendor/sdk"),
            ("write", "~/vendor/sdk"),
            ("read_file", "~/vendor/sdk/config"),
            ("write_file", "~/vendor/sdk/config"),
            ("metadata", "~/vendor"),
            ("exec", "~/vendor/sdk"),
            ("read", "~/vendor"),
        ];
        if !cfg!(target_os = "linux") {
            cases.push(("list", "~/vendor"));
        }
        for (list, authored) in cases {
            assert_eq!(
                fixture.refusal(&context, &format!("{list} = [{authored:?}]")),
                source_refusal(authored, &sdk, "op", "reads", "~/vendor/sdk"),
                "{list}"
            );
        }
        // An absolute spelling of the grant, and an entry that names one file.
        let absolute = text(&home.join("vendor/sdk/config"));
        assert_eq!(
            fixture.refusal(&context, &format!("read_file = [{absolute:?}]")),
            source_refusal(&absolute, &sdk, "op", "reads", "~/vendor/sdk")
        );
        let vault = home.join("tools/vault");
        for authored in ["~/tools/vault", "~/tools"] {
            assert_eq!(
                fixture.refusal(&context, &format!("read = [{authored:?}]")),
                source_refusal(
                    authored,
                    &vault,
                    "aws-secretsmanager",
                    "deny",
                    &text(&vault)
                )
            );
        }

        // A grant beside each path stays, and an operator's own `deny` of one is no grant.
        let reach = fixture.reach(
            &context,
            "read = ['~/project', '~/tools/run', '~/scratch']\nwrite = ['~/scratch']\n\
             deny = ['~/vendor/sdk']",
        );
        assert_eq!(reach.grants.len(), 4);
        assert_eq!(
            reach.refusals,
            [
                Refusal {
                    path: sdk.clone(),
                    scope: Scope::Root,
                    judged: Some(identity(&sdk)),
                },
                Refusal {
                    path: vault,
                    scope: Scope::Root,
                    judged: None,
                },
            ],
            "the operator's own `deny` keeps its identity, and the other path is refused once"
        );
    }

    /// **A `deny_write` entry authorizes nothing, so no path of a secret source refuses it**: the
    /// `write` tree that must hold it is what the source refuses, and an entry beside a source
    /// keeps its protection.
    #[test]
    fn a_deny_write_entry_is_judged_against_no_path_of_a_secret_source() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::fs::create_dir(home.join("scratch/deps")).expect("a protected directory");
        let paths = [protected("op", "reads", "~/vendor/sdk")];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        let sdk = home.join("vendor/sdk");
        // The entry is the path of the source, or holds it: the grant around it is refused.
        for (tree, entry) in [
            ("~/vendor/sdk", "~/vendor/sdk"),
            ("~/vendor", "~/vendor/sdk"),
            ("~/vendor", "~/vendor"),
        ] {
            assert_eq!(
                fixture.refusal(
                    &context,
                    &format!("read = [{tree:?}]\nwrite = [{tree:?}]\ndeny_write = [{entry:?}]")
                ),
                source_refusal(tree, &sdk, "op", "reads", "~/vendor/sdk"),
                "{tree} {entry}"
            );
        }
        // With no grant around it, the entry gets its own refusal, not the refusal of the source.
        let alone = fixture.refusal(
            &context,
            "read = ['~/project']\ndeny_write = ['~/vendor/sdk']",
        );
        assert!(
            alone.contains("lies inside no `write` directory") && !alone.contains("secret source"),
            "{alone}"
        );
        let reach = fixture.reach(
            &context,
            "read = ['~/scratch']\nwrite = ['~/scratch']\ndeny_write = ['~/scratch/deps']",
        );
        assert_eq!(reach.write_protections, [home.join("scratch/deps")]);
        assert_eq!(
            reach.refusals,
            [Refusal {
                path: sdk,
                scope: Scope::Root,
                judged: None,
            }]
        );
    }

    /// **Each process is refused each path of a secret source**, also a process with no list,
    /// and no source means no refusal.
    #[test]
    fn each_process_is_refused_each_path_of_a_secret_source() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        // On Linux no sandbox denies a path that is not there, so there each path is a folder.
        if cfg!(target_os = "linux") {
            for folder in [".op", "scratch/later/socket"] {
                std::fs::create_dir_all(home.join(folder)).expect("a path of the vault");
            }
        }
        let paths = [
            protected("op", "reads", "~/vendor/sdk"),
            protected("op", "reads", "~/.op"),
            protected("op", "deny", "~/scratch/later/socket"),
        ];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        let refused = |path: &str| Refusal {
            path: home.join(path),
            scope: Scope::Root,
            judged: None,
        };
        let expected = [
            refused("vendor/sdk"),
            refused(".op"),
            refused("scratch/later/socket"),
        ];
        let reach = direct_grants(&Filesystem::default(), &context).expect("no list, no grant");
        assert_eq!(reach.refusals, expected);
        let reach = fixture.reach(&context, "read = ['~/project']");
        assert_eq!(reach.refusals, expected);
        assert!(
            fixture
                .reach(&fixture.context(), "read = ['~/project']")
                .refusals
                .is_empty(),
            "a configuration with no source subtracts nothing"
        );
    }

    /// **No grant reaches an absent path of a secret source, by its spelling**, and on Linux no
    /// sandbox gets a refusal for it, because a mount needs a path that is there.
    #[test]
    fn a_grant_that_reaches_an_absent_path_of_a_secret_source_is_refused() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let paths = [
            protected("op", "reads", "~/.op"),
            protected("op", "deny", "~/scratch/later/socket"),
        ];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        assert_eq!(
            fixture.refusal(&context, "read = ['~/.op']"),
            source_refusal("~/.op", &home.join(".op"), "op", "reads", "~/.op"),
            "the refusal names the source, not the absent path"
        );
        assert_eq!(
            fixture.refusal(&context, "write = ['~/scratch']"),
            source_refusal(
                "~/scratch",
                &home.join("scratch/later/socket"),
                "op",
                "deny",
                "~/scratch/later/socket"
            )
        );
        let refused = |path: &str| Refusal {
            path: home.join(path),
            scope: Scope::Root,
            judged: None,
        };
        let both = [refused(".op"), refused("scratch/later/socket")];
        let reach = fixture.reach(&context, "read = ['~/notes']");
        if cfg!(target_os = "linux") {
            assert_eq!(
                reach.refusals,
                [],
                "no sandbox denies a path that is absent"
            );
            // A path that is there is denied beside one that is not.
            std::fs::create_dir(home.join(".op")).expect("the folder of the vault");
            let reach = fixture.reach(&context, "read = ['~/notes']");
            assert_eq!(reach.refusals, [refused(".op")]);
        } else {
            assert_eq!(reach.refusals, both);
        }
    }

    /// **A credential store that a secret source reads has no exact-name exception**, and the
    /// refusal names the source where the floor would refuse first.
    #[test]
    fn a_credential_store_of_a_secret_source_is_refused_when_named_exactly() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::fs::create_dir_all(home.join(".aws")).expect("a credential store");
        std::fs::write(home.join(".aws/credentials"), "").expect("a credential");
        let paths = [protected("aws-secretsmanager", "reads", "~/.aws")];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        let aws = home.join(".aws");
        for authored in ["~/.aws", "~/.aws/credentials", "~"] {
            assert_eq!(
                fixture.refusal(&context, &format!("read = [{authored:?}]")),
                source_refusal(authored, &aws, "aws-secretsmanager", "reads", "~/.aws")
            );
        }
        // Without the source, the store keeps its exception.
        assert!(
            fixture
                .reach(&fixture.context(), "read = ['~/.aws']")
                .grants[0]
                .credential_store
        );
    }

    /// **A path of a secret source is judged by the file that it names**: a grant that names the
    /// folder behind a link in the entry is refused, and the refusal spells the path as written.
    #[test]
    fn a_grant_that_reaches_a_path_of_a_secret_source_through_a_link_is_refused() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::os::unix::fs::symlink(home.join("vendor"), home.join("linked")).expect("a link");
        let paths = [protected("op", "reads", "~/linked/sdk")];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        for authored in ["~/vendor/sdk", "~/vendor"] {
            assert_eq!(
                fixture.refusal(&context, &format!("read = [{authored:?}]")),
                source_refusal(
                    authored,
                    &home.join("linked/sdk"),
                    "op",
                    "reads",
                    "~/linked/sdk"
                )
            );
        }
        // The process is refused the entry as written and the folder that it resolves to.
        let refused = |path: &str| Refusal {
            path: home.join(path),
            scope: Scope::Root,
            judged: None,
        };
        assert_eq!(
            fixture.reach(&context, "read = ['~/notes']").refusals,
            [refused("linked/sdk"), refused("vendor/sdk")]
        );

        // A link whose target is not there yet, as the last name and in the middle: the target
        // is protected, because a file that appears there is opened by the path of the target.
        std::fs::create_dir(home.join("group")).expect("the folder of the target");
        std::os::unix::fs::symlink(home.join("group/t/agent.sock"), home.join("dangling"))
            .expect("a link");
        std::os::unix::fs::symlink("group/absent", home.join("gone")).expect("a link");
        for (entry, written, target) in [
            ("~/dangling", "dangling", "group/t/agent.sock"),
            ("~/gone/socket", "gone/socket", "group/absent/socket"),
        ] {
            let paths = [protected("op", "deny", entry)];
            let context = FilesystemContext {
                source_paths: &paths,
                ..fixture.context()
            };
            assert_eq!(
                fixture.refusal(&context, "read = ['~/group']"),
                source_refusal("~/group", &home.join(target), "op", "deny", entry)
            );
            // On Linux no sandbox denies an entry whose link names a target that is not there.
            let refusals = fixture.reach(&context, "read = ['~/notes']").refusals;
            if cfg!(target_os = "linux") {
                assert_eq!(refusals, []);
            } else {
                assert_eq!(refusals, [refused(written), refused(target)]);
            }
        }

        // A chain of two links: a write grant over the folder that holds the middle link could
        // point it elsewhere, so it is refused; a read grant there reaches only the denied
        // target. The middle link of the second chain names a target that is not there yet.
        for folder in ["dotfiles", "keys/store"] {
            std::fs::create_dir_all(home.join(folder)).expect("a folder");
        }
        std::os::unix::fs::symlink(home.join("keys/store"), home.join("dotfiles/hop"))
            .expect("a link");
        std::os::unix::fs::symlink(home.join("dotfiles/hop"), home.join("chain")).expect("a link");
        std::os::unix::fs::symlink(home.join("keys/absent"), home.join("dotfiles/hop-absent"))
            .expect("a link");
        std::os::unix::fs::symlink(home.join("dotfiles/hop-absent"), home.join("chain-absent"))
            .expect("a link");
        for (entry, hop, target) in [
            ("~/chain", "dotfiles/hop", "keys/store"),
            ("~/chain-absent", "dotfiles/hop-absent", "keys/absent"),
        ] {
            let paths = [protected("op", "reads", entry)];
            let context = FilesystemContext {
                source_paths: &paths,
                ..fixture.context()
            };
            assert_eq!(
                fixture.refusal(&context, "read = ['~/dotfiles']\nwrite = ['~/dotfiles']"),
                format!(
                    "`[agent]` filesystem entry \"~/dotfiles\" is refused: this write grant can \
                     change {}, a symbolic link on the way to {}, which the secret source `op` \
                     keeps from each workload (its `reads` entry {entry:?}). Keep each write \
                     grant outside the folders that hold a link on the way to a path that a \
                     secret source names in `reads` and `deny`",
                    home.join(hop).display(),
                    home.join(target).display()
                )
            );
            fixture.reach(&context, "read = ['~/dotfiles']");
            assert_eq!(
                fixture.refusal(&context, "read = ['~/keys']\nwrite = ['~/keys']"),
                source_refusal("~/keys", &home.join(target), "op", "reads", entry)
            );
        }

        // An entry whose links do not end names no place, so the box does not start.
        std::os::unix::fs::symlink(home.join("loop-b"), home.join("loop-a")).expect("a link");
        std::os::unix::fs::symlink(home.join("loop-a"), home.join("loop-b")).expect("a link");
        let paths = [protected("op", "deny", "~/loop-a")];
        let context = FilesystemContext {
            source_paths: &paths,
            ..fixture.context()
        };
        assert_eq!(
            fixture.refusal(&context, "read = ['~/notes']"),
            "invalid `[secret-source.op]` table: `deny` entry \"~/loop-a\" cannot be inspected: \
             the path passes through too many symbolic links"
        );

        // Two paths that are absent have no file to compare, so each one is compared as it
        // resolves: a link in the entry, and a link in the grant.
        for (entry, authored) in [
            ("~/linked/later", "~/vendor/later"),
            ("~/vendor/later", "~/linked/later"),
        ] {
            let paths = [protected("op", "deny", entry)];
            let context = FilesystemContext {
                source_paths: &paths,
                ..fixture.context()
            };
            assert_eq!(
                fixture.refusal(&context, &format!("read = [{authored:?}]")),
                source_refusal(authored, &home.join("vendor/later"), "op", "deny", entry)
            );
        }
    }

    /// **A project entry is granted and the directory holding this box's authority is subtracted**,
    /// by path: a sibling box's directory beneath the same grant is not, and the disclosure names
    /// the grant that reaches it.
    #[test]
    fn a_project_entry_subtracts_the_directory_holding_this_boxs_authority() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let own = home.join("project/.strands-box");
        let sibling = home.join("project/vendor/inner/.strands-box");
        std::fs::create_dir_all(&sibling).expect("a sibling box's directory");
        std::fs::write(sibling.join("policy.dw"), "").expect("the sibling's policy");
        std::fs::write(sibling.join("box.toml"), "").expect("the sibling's configuration");
        let policy = own.join("policy.dw");
        let context = FilesystemContext {
            policy: Some(&policy),
            ..fixture.context_with_authority_in(&own)
        };
        let reach = fixture.reach(
            &context,
            &format!(
                "read = [{0:?}]\nwrite = [{0:?}]",
                text(&home.join("project"))
            ),
        );
        assert_eq!(
            reach
                .refusals
                .iter()
                .map(|refusal| (refusal.path.clone(), refusal.scope))
                .collect::<Vec<_>>(),
            [(own.clone(), Scope::Root)],
            "the one refusal is the directory the authority was read from"
        );
        assert_eq!(reach.refusals[0].judged, Some(identity(&own)));
        // The sibling box's directory is inside the granted tree and nothing subtracts it; the
        // grant that reaches it is what the startup disclosure names.
        let disclosure = reach.grants[0].disclosure();
        assert!(
            disclosure.contains("write") && disclosure.contains(&text(&home.join("project"))),
            "{disclosure}"
        );
    }

    /// **A configuration loaded from outside the workspace is protected the same way**: the
    /// directory `--config` named is subtracted from a wider grant by path, whatever it is called.
    #[test]
    fn an_authority_directory_outside_the_workspace_is_subtracted_by_path() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let authority = home.join("elsewhere/authority");
        std::fs::create_dir_all(authority.join("deeper")).expect("the authority directory");
        std::fs::write(authority.join("control.toml"), "").expect("the configuration");
        let context = fixture.context_with_authority_in(&authority);

        let reach = fixture.reach(
            &context,
            &format!(
                "read = [{0:?}]\nwrite = [{0:?}]",
                text(&home.join("elsewhere"))
            ),
        );
        assert_eq!(
            reach
                .refusals
                .iter()
                .map(|refusal| refusal.path.clone())
                .collect::<Vec<_>>(),
            std::slice::from_ref(&authority)
        );

        // A grant that IS the directory, or lies inside it, is not subtracted: the sources keep
        // their identity protection, and a grant may not be refused whole and enforce nothing.
        for granted in [authority.clone(), authority.join("deeper")] {
            let reach = fixture.reach(
                &context,
                &format!("read = [{0:?}]\nwrite = [{0:?}]", text(&granted)),
            );
            assert!(
                reach.refusals.is_empty(),
                "{granted:?}: {:?}",
                reach.refusals
            );
        }

        // A second grant inside the subtracted directory is covered by the refusal the first
        // produced, so it is refused rather than left enforcing nothing.
        let refusal = fixture.refusal(
            &context,
            &format!(
                "write = [{:?}]\nread = [{:?}]",
                text(&home.join("elsewhere")),
                text(&authority.join("deeper"))
            ),
        );
        assert!(refusal.contains("no grant reaches"), "{refusal}");

        // A file-scoped grant is never subtracted from: only a tree can hold the directory.
        std::fs::write(home.join("elsewhere/note.txt"), "").expect("a file beside it");
        let reach = fixture.reach(
            &context,
            &format!("read_file = [{:?}]", text(&home.join("elsewhere/note.txt"))),
        );
        assert!(reach.refusals.is_empty());
    }

    /// **A writable grant enclosing a policy that nothing subtracts is refused.**
    #[test]
    fn a_writable_grant_over_an_unsubtracted_policy_is_refused() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        std::fs::write(home.join("scratch/policy.dw"), "").expect("a policy outside a box");
        let policy = home.join("scratch/policy.dw");
        let context = FilesystemContext {
            policy: Some(&policy),
            ..fixture.context()
        };
        let refusal = fixture.refusal(
            &context,
            &format!("write = [{:?}]", text(&home.join("scratch"))),
        );
        assert!(refusal.contains("policy file"), "{refusal}");
        // A read grant over it is a disclosure, not authority.
        fixture.reach(
            &context,
            &format!("read = [{:?}]", text(&home.join("scratch"))),
        );
    }

    /// **A write entry enclosing a directory on the MCP program search path is refused.**
    #[test]
    fn a_writable_search_directory_is_refused() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let context = FilesystemContext {
            program_search_directories: vec![home.join("scratch/bin")],
            ..fixture.context()
        };
        let refusal = fixture.refusal(
            &context,
            &format!("write = [{:?}]", text(&home.join("scratch"))),
        );
        assert!(refusal.contains("search path"), "{refusal}");
        fixture.reach(
            &context,
            &format!("read = [{:?}]", text(&home.join("scratch"))),
        );
    }

    /// **A link hop swapped after the spawn check is refused, not granted.** The check and the
    /// grant each look the chain up, so the grant compares its own lookup with the approved file.
    #[test]
    fn a_link_hop_swapped_after_the_spawn_check_is_refused() {
        let fixture = Fixture::new();
        let home = fixture.home.clone();
        let context = fixture.context();
        std::fs::write(home.join("notes/approved.txt"), "approved").expect("approved");
        std::fs::write(home.join("notes/other.txt"), "other").expect("other");
        let selector = home.join("scratch/selector");
        std::os::unix::fs::symlink(home.join("notes/approved.txt"), &selector).expect("a hop");
        let helper = home.join("tools/helper");
        std::os::unix::fs::symlink(&selector, &helper).expect("the link");
        let reach = fixture.reach(&context, &format!("read_file = [{:?}]", text(&helper)));
        let grant = &reach.grants[0];
        assert_eq!(grant.resolved, home.join("notes/approved.txt"));

        // Unchanged, the lookup is the approved file.
        require_judged_identities(&reach, "[tool.t]").expect("the identity is unchanged");
        let prepared = grant.prepare("[tool.t]").expect("the approved file");
        assert_eq!(prepared.resolved_path(), grant.resolved);
        drop(prepared);

        // A process that can write `scratch` swaps the hop after the spawn check.
        let swap = home.join("scratch/selector.new");
        std::os::unix::fs::symlink(home.join("notes/other.txt"), &swap).expect("a new hop");
        std::fs::rename(&swap, &selector).expect("the swap");
        let refusal = grant
            .prepare("[tool.t]")
            .expect_err("a swapped hop is refused")
            .to_string();
        assert!(
            refusal.contains("other.txt") && refusal.contains("since the run judged it"),
            "{refusal}"
        );
    }
}
