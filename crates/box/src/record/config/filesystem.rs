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

use containment::{Operation, Scope};

use crate::error::ConfigError;
use crate::record::config::process::{Filesystem, Grant};

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
}

impl DirectGrant {
    /// How this grant reads in the startup disclosure.
    pub(crate) fn disclosure(&self) -> String {
        let store = if self.credential_store {
            "  (credential store)"
        } else {
            ""
        };
        // A writable bind reads on Linux, so a `write` tree is disclosed as the reach it is there.
        let reads_too = if cfg!(target_os = "linux")
            && self.operation == Operation::Write
            && self.scope == Scope::Root
        {
            "  (readable too: a writable bind reads)"
        } else {
            ""
        };
        format!(
            "  {:<10}  {}{store}{reads_too}",
            self.kind.key(),
            self.resolved.display()
        )
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
    /// What the process's own syscalls reach.
    pub(crate) grants: Vec<DirectGrant>,
    /// What stays unreachable inside those grants: `deny` entries, and the directory holding each
    /// authority source this run loaded.
    pub(crate) refusals: Vec<Refusal>,
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
    for (kind, entry) in lists.entries() {
        match kind {
            Grant::Deny => refusals.push(denial(entry, context)?),
            _ => grants.push(entry_grant(kind, entry, context)?),
        }
    }
    require_no_overlap(&grants, context)?;

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
    Ok(DirectReach { grants, refusals })
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

/// One authorizing entry as a grant, refused by name for each class it falls in.
fn entry_grant(
    kind: Grant,
    entry: &Path,
    context: &FilesystemContext<'_>,
) -> Result<DirectGrant, ConfigError> {
    let authored = entry.display().to_string();
    let named = |reason: &str| refuse(context, &authored, reason);
    let lexical = expand_home(entry, &authored, context)?;

    // **An authored grant on an absent path is refused, never skipped.** A grant that silently
    // does nothing is the defect class this repository has recorded twice.
    let metadata = std::fs::symlink_metadata(&lexical).map_err(|source| {
        named(&format!(
            "{} is not there: {source}. A grant on a path that does not exist grants nothing \
             and says so nowhere",
            lexical.display()
        ))
    })?;
    if metadata.is_symlink() {
        return Err(named(&format!(
            "{} is a symbolic link. A grant carries the identity the kernel checks, so a link \
             renders a rule that matches nothing; name what it points at",
            lexical.display()
        )));
    }
    let resolved = lexical
        .canonicalize()
        .map_err(|source| named(&format!("cannot resolve {}: {source}", lexical.display())))?;
    if resolved != lexical {
        // Not necessarily a link: `canonicalize` also folds `.` and `..`, so the message names
        // what is actually wrong, which is that the authored spelling is not the identity the kernel
        // checks.
        return Err(named(&format!(
            "{} is not the path the kernel checks, which is {}. A grant carries the identity it \
             acts on, so name that path instead",
            lexical.display(),
            resolved.display()
        )));
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
            return Err(named(&format!(
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
                return Err(named(&format!(
                    "{} cannot be listed without its contents on Linux: the namespace backend \
                     has no lowering for `list`; grant `read` instead",
                    resolved.display()
                )));
            }
            (Operation::List, Scope::Root)
        }
        (Grant::List, false) => {
            return Err(named(&format!(
                "{} is a file, and `list` enumerates a directory tree",
                resolved.display()
            )));
        }
        (Grant::Metadata, true) => (Operation::Metadata, Scope::Root),
        (Grant::Metadata, false) => {
            return Err(named(&format!(
                "{} is a file, and a file's metadata comes with the `read_file` or `exec` grant \
                 that names it",
                resolved.display()
            )));
        }
        (Grant::Exec, true) => (Operation::Exec, Scope::Root),
        (Grant::Exec, false) => {
            if !crate::run::contain::executable::is_executable(&resolved) {
                return Err(named(&format!(
                    "{} is not an executable regular file",
                    resolved.display()
                )));
            }
            (Operation::Exec, Scope::File)
        }
        (Grant::Deny, _) => unreachable!("a denial is built by `denial`"),
    };

    // A writable search directory is the same defect one step earlier: the box execs a bare name
    // off the operator's `PATH`, so whoever writes that directory picks the program. Only a
    // WRITE entry reaches it, because reading a directory on the search path grants nothing.
    if kind.writes() {
        for directory in &context.program_search_directories {
            if directory.starts_with(&resolved) {
                return Err(named(&format!(
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
                named(&format!(
                    "{} is refused beneath every grant: {error}",
                    resolved.display()
                ))
            },
        )?;

    Ok(DirectGrant {
        kind,
        authored,
        lexical,
        resolved,
        operation,
        scope,
        credential_store,
    })
}

/// The authored path with `~` or `~/` replaced by the operator's home.
fn expand_home(
    entry: &Path,
    authored: &str,
    context: &FilesystemContext<'_>,
) -> Result<PathBuf, ConfigError> {
    match authored.strip_prefix("~/") {
        Some(relative) => Ok(context.operator_home.join(relative)),
        None if authored == "~" => Ok(context.operator_home.to_path_buf()),
        None if entry.is_absolute() => Ok(entry.to_path_buf()),
        None => Err(refuse(
            context,
            authored,
            "a path is absolute or `~`-relative, so a checked-in configuration holds in every \
             clone; this one is neither",
        )),
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
            if grant.resolved == other.resolved {
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

    /// **Each list maps to its cell**, on a directory and on a file where both are legal.
    #[test]
    fn every_list_translates_to_its_cell() {
        let fixture = Fixture::new();
        let home = &fixture.home;
        let body = format!(
            "read = [{:?}]\nwrite = [{:?}]\nread_file = [{:?}]\nwrite_file = [{:?}]\n\
             metadata = [{:?}]\nexec = [{:?}, {:?}]\ndeny = [{:?}]",
            text(&home.join("vendor")),
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
        std::os::unix::fs::symlink(home.join("vendor/sdk"), &link).expect("a link");
        let refusal = fixture.refusal(&context, &format!("read = [{:?}]", text(&link)));
        assert!(
            refusal.contains("symbolic link") && refusal.contains(&text(&link)),
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
                "read = [{0:?}]\nwrite = [{0:?}, {1:?}]",
                text(&home.join("scratch")),
                text(&home.join("notes"))
            ),
        );
        assert_eq!(reach.grants.len(), 3);
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
            &format!("write = [{:?}]", text(&home.join("project"))),
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
            &format!("write = [{:?}]", text(&home.join("elsewhere"))),
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
            let reach = fixture.reach(&context, &format!("write = [{:?}]", text(&granted)));
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
}
