//! The operating system's own paths, stated as data: what every process reaches, and what none does.
//!
//! Named for the paths rather than for a floor, because `floors.rs` next door is deny-only and this
//! module states grants as well.
//!
//! | item | what it states |
//! |---|---|
//! | [`os_runtime_cells`] | what any process needs to load and run, which is the agent set |
//! | [`os_leaf_cells`] | what leaf containment needs in addition, which is the leaf set |
//! | [`os_minimum_cells`] | both, which is what leaf containment reaches
//! | [`forbidden_paths`] | every path no grant may reach, for every backend |

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{Operation, Scope};

/// One set's cells, one list per cell, so a set can state no exec grant and no write root.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    /// What the set is for, read by a person and by nothing else.
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    read_root: Vec<String>,
    #[serde(default)]
    read_dir: Vec<String>,
    #[serde(default)]
    read_file: Vec<String>,
    #[serde(default)]
    write_file: Vec<String>,
    #[serde(default)]
    metadata_root: Vec<String>,
    #[serde(default)]
    metadata_dir: Vec<String>,
}

impl Set {
    /// The cells this set states, each list in the order the file writes it.
    fn cells(&self) -> Vec<(PathBuf, Operation, Scope)> {
        [
            (&self.read_root, Operation::Read, Scope::Root),
            (&self.read_dir, Operation::Read, Scope::Dir),
            (&self.read_file, Operation::Read, Scope::File),
            (&self.write_file, Operation::Write, Scope::File),
            (&self.metadata_root, Operation::Metadata, Scope::Root),
            (&self.metadata_dir, Operation::Metadata, Scope::Dir),
        ]
        .into_iter()
        .flat_map(|(paths, operation, scope)| {
            paths
                .iter()
                .map(move |path| (PathBuf::from(path), operation, scope))
        })
        .collect()
    }
}

/// The two sets this operating system states, each named for the process that receives it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsPaths {
    /// What the file is for, read by a person and by nothing else.
    #[allow(dead_code)]
    description: String,
    agent: Set,
    /// What leaf containment receives in addition to agent containment, never instead of it.
    leaf: Set,
}

#[cfg(target_os = "macos")]
const OS_PATHS_JSON: &str = include_str!("containment-data/os-paths.macos.json");
#[cfg(not(target_os = "macos"))]
const OS_PATHS_JSON: &str = include_str!("containment-data/os-paths.linux.json");

/// Both sets, parsed once. A malformed file is a mistake in this repository rather than a condition a
/// box meets, so it panics here.
fn os_paths() -> &'static OsPaths {
    static PARSED: std::sync::OnceLock<OsPaths> = std::sync::OnceLock::new();
    PARSED.get_or_init(|| {
        serde_json::from_str(OS_PATHS_JSON)
            .unwrap_or_else(|error| panic!("the compiled-in os-paths JSON parses: {error}"))
    })
}

/// What any process on this operating system needs to load and run.
pub fn os_runtime_cells() -> Vec<(PathBuf, Operation, Scope)> {
    present(os_paths().agent.cells())
}

/// What leaf containment additionally needs.
pub(crate) fn os_leaf_cells() -> Vec<(PathBuf, Operation, Scope)> {
    present(os_paths().leaf.cells())
}

/// Both sets, which is what every process reaches.
pub fn os_minimum_cells() -> Vec<(PathBuf, Operation, Scope)> {
    let mut cells = os_runtime_cells();
    cells.extend(os_leaf_cells());
    one_per_identity(cells)
}

/// The cells this host actually has, one per identity.
fn present(cells: Vec<(PathBuf, Operation, Scope)>) -> Vec<(PathBuf, Operation, Scope)> {
    one_per_identity(
        cells
            .into_iter()
            .filter(|(path, _, scope)| kind_matches(path, *scope))
            .collect(),
    )
}

/// Whether the path is there, and is the kind its scope names.
fn kind_matches(path: &Path, scope: Scope) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => match scope {
            Scope::File => !metadata.is_dir(),
            Scope::Dir | Scope::Root => metadata.is_dir(),
        },
        Err(_) => false,
    }
}

/// One cell per identity: `/lib64` and `/usr/lib64` are one directory on a merged host, and the
/// first spelling carries both.
fn one_per_identity(cells: Vec<(PathBuf, Operation, Scope)>) -> Vec<(PathBuf, Operation, Scope)> {
    let mut identities: Vec<(PathBuf, Operation, Scope)> = Vec::new();
    let mut kept = Vec::new();
    for (path, operation, scope) in cells {
        let identity = path.canonicalize().unwrap_or_else(|_| path.clone());
        let key = (identity, operation, scope);
        if identities.contains(&key) {
            continue;
        }
        identities.push(key);
        kept.push((path, operation, scope));
    }
    kept
}

/// How far a forbidden path reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum Match {
    /// The grant names this exact path. A path inside it stays grantable.
    #[serde(rename = "exact")]
    ExactPath,
    /// The grant touches this path: at it, under it, or above it.
    #[serde(rename = "overlap")]
    AnyOverlap,
}

/// What a forbidden row protects, which decides its message and whether a caller may exempt it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ForbiddenClass {
    /// The whole filesystem.
    WholeFilesystem,
    /// The directory every home sits in.
    HomeNamespace,
    /// A system tree, which is never handed over as a unit.
    SystemTree,
    /// A loader directory, which every process maps code from and which reads as one tree.
    LoaderDirectory,
    /// The operator's own credential store, and the one class `allow_credential_store` may exempt.
    CredentialStore,
    /// The system password database, which a system-tree row leaves grantable file by file.
    PasswordDatabase,
    /// A machine credential store, which is not the operator's to hand over.
    MachineCredential,
    /// The privilege configuration, which decides who may become someone else.
    PrivilegeConfiguration,
}

impl ForbiddenClass {
    /// Whether `allow_credential_store` may punch a hole in a row of this class.
    pub(crate) const fn is_exemptible(self) -> bool {
        matches!(self, Self::CredentialStore)
    }

    /// Why this class refuses a grant. The text, not the class, is what a caller reads.
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::WholeFilesystem => "the whole filesystem is never a grantable tree",
            Self::HomeNamespace => "the home namespace is never a grantable tree",
            Self::SystemTree => "a system root is never a grantable tree",
            Self::LoaderDirectory => {
                "the loader's library directory reads as a tree, and nothing wider"
            }
            Self::CredentialStore => {
                "this path holds a credential; the box mints and injects a secret the agent never \
                 sees, so a read here does not weaken that design, it makes it pointless"
            }
            Self::PasswordDatabase => {
                "this path holds the system password hashes; only file permissions refuse a grant \
                 here, and a trusted process at euid 0 has none"
            }
            Self::MachineCredential => {
                "this path holds the machine's own credentials; only file permissions refuse a \
                 grant here, and a trusted process at euid 0 has none"
            }
            Self::PrivilegeConfiguration => {
                "this path decides which identities and programs hold privilege; only file \
                 permissions refuse a grant here, and a trusted process at euid 0 has none"
            }
        }
    }
}

/// One path no grant may reach.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Forbidden {
    /// `/absolute`, or `~/relative` to the operator's own home.
    pub(crate) anchor: String,
    pub(crate) rule: Match,
    /// The cells this row lets through. Empty where the path's own existence is protected.
    #[serde(default)]
    pub(crate) permits: Vec<(Operation, Scope)>,
    pub(crate) class: ForbiddenClass,
}

impl Forbidden {
    /// Why this entry refuses a grant.
    pub(crate) const fn reason(&self) -> &'static str {
        self.class.reason()
    }

    /// A grant naming this exact path is refused. A path inside it stays grantable.
    #[cfg(test)]
    pub(crate) fn exact(anchor: &str, class: ForbiddenClass) -> Self {
        Self {
            anchor: anchor.to_string(),
            rule: Match::ExactPath,
            permits: Vec::new(),
            class,
        }
    }

    /// A grant touching this path is refused: at it, under it, or above it.
    #[cfg(test)]
    pub(crate) fn overlap(anchor: &str, class: ForbiddenClass) -> Self {
        Self {
            anchor: anchor.to_string(),
            rule: Match::AnyOverlap,
            permits: Vec::new(),
            class,
        }
    }

    /// Let these cells through, because they expose nothing this entry protects.
    #[cfg(test)]
    pub(crate) fn permitting(mut self, permits: &[(Operation, Scope)]) -> Self {
        self.permits = permits.to_vec();
        self
    }
}

/// The forbidden rows, as `forbidden-paths.json` states them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForbiddenFile {
    /// What the file is for, read by a person and by nothing else.
    #[allow(dead_code)]
    description: String,
    rows: Vec<Forbidden>,
}

/// Every path no grant may reach, for every backend.
///
/// One cross-platform list: both platform spellings are present on every host, because a config
/// authored on one platform can be applied on another.
pub(crate) fn forbidden_paths() -> &'static [Forbidden] {
    static ROWS: std::sync::OnceLock<Vec<Forbidden>> = std::sync::OnceLock::new();
    &ROWS.get_or_init(|| {
        let parsed: ForbiddenFile =
            serde_json::from_str(include_str!("containment-data/forbidden-paths.json"))
                .unwrap_or_else(|error| {
                    panic!("the compiled-in forbidden-paths JSON parses: {error}")
                });
        parsed.rows
    })[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every cell each set states, in order.** The two files replaced one Rust table in the box,
    /// and this is the whole record of what that table held for this platform.
    #[test]
    fn each_set_states_exactly_these_cells() {
        #[cfg(target_os = "macos")]
        let (agent, leaf) = (
            vec![
                ("/usr/share/icu", Operation::Read, Scope::Root),
                ("/usr/share/zoneinfo", Operation::Read, Scope::Root),
                // Node reads `/System/Library/OpenSSL/openssl.cnf` before it runs a line, so this is
                // any process's rather than a leaf's. Measured: withholding it aborts Node 18.
                ("/System/Library", Operation::Read, Scope::Root),
                ("/", Operation::Read, Scope::Dir),
                ("/dev/null", Operation::Read, Scope::File),
                ("/etc/localtime", Operation::Read, Scope::File),
                // Apple's libffi loads it for its first callback, and aborts the process when the
                // load fails. Measured: withholding it aborts Homebrew Python 3.14 at `import ctypes`.
                (
                    "/usr/lib/libffi-trampolines.dylib",
                    Operation::Read,
                    Scope::File,
                ),
                ("/dev/null", Operation::Write, Scope::File),
                ("/private/tmp", Operation::Metadata, Scope::Root),
                ("/etc", Operation::Metadata, Scope::Dir),
                ("/var", Operation::Metadata, Scope::Dir),
            ],
            vec![
                ("/usr/share/locale", Operation::Read, Scope::Root),
                ("/usr/share/terminfo", Operation::Read, Scope::Root),
                ("/System/Cryptexes", Operation::Read, Scope::Root),
                ("/Library/Frameworks", Operation::Read, Scope::Root),
                ("/usr/lib", Operation::Read, Scope::Root),
                ("/var/db/dyld", Operation::Read, Scope::Root),
                ("/var/db/timezone", Operation::Read, Scope::Root),
                ("/var/select", Operation::Read, Scope::Root),
                ("/etc/ssl", Operation::Read, Scope::Root),
                ("/dev/urandom", Operation::Read, Scope::File),
                ("/dev/random", Operation::Read, Scope::File),
                ("/dev/zero", Operation::Read, Scope::File),
            ],
        );
        #[cfg(not(target_os = "macos"))]
        let (agent, leaf) = (
            vec![
                ("/usr/share/zoneinfo", Operation::Read, Scope::Root),
                ("/", Operation::Read, Scope::Dir),
                ("/dev/null", Operation::Read, Scope::File),
                ("/etc/localtime", Operation::Read, Scope::File),
                ("/dev/null", Operation::Write, Scope::File),
                ("/etc", Operation::Metadata, Scope::Dir),
                ("/var", Operation::Metadata, Scope::Dir),
            ],
            vec![
                ("/lib", Operation::Read, Scope::Root),
                ("/lib64", Operation::Read, Scope::Root),
                ("/usr/lib", Operation::Read, Scope::Root),
                ("/usr/lib64", Operation::Read, Scope::Root),
                ("/etc/ssl", Operation::Read, Scope::Root),
                ("/dev/urandom", Operation::Read, Scope::File),
                ("/dev/random", Operation::Read, Scope::File),
                ("/dev/zero", Operation::Read, Scope::File),
                ("/etc/ld.so.cache", Operation::Read, Scope::File),
            ],
        );

        // The stated rows, not the present ones: a host missing `/usr/share/terminfo` must not make
        // this test pass for the wrong reason.
        assert_eq!(
            os_paths().agent.cells(),
            agent
                .into_iter()
                .map(|(path, operation, scope)| (PathBuf::from(path), operation, scope))
                .collect::<Vec<_>>(),
            "the agent set changed"
        );
        assert_eq!(
            os_paths().leaf.cells(),
            leaf.into_iter()
                .map(|(path, operation, scope)| (PathBuf::from(path), operation, scope))
                .collect::<Vec<_>>(),
            "the leaf set changed"
        );
    }

    /// **The two sets are disjoint**, so the union is each stated once and no path is in both sets.
    #[test]
    fn no_path_is_in_both_sets() {
        for (path, operation, scope) in os_paths().agent.cells() {
            assert!(
                !os_paths()
                    .leaf
                    .cells()
                    .iter()
                    .any(|(other, other_operation, other_scope)| other == &path
                        && *other_operation == operation
                        && *other_scope == scope),
                "{} at {operation:?}/{scope:?} is in both sets",
                path.display()
            );
        }
    }

    /// **No set can state an exec grant, a denial, or a write root: the schema has no list for one.**
    /// Each list names one cell, so the vocabulary a set may reach is the six lists and nothing else.
    #[test]
    fn a_set_has_no_list_for_an_exec_grant_a_denial_or_a_write_tree() {
        for absent in [
            "exec",
            "exec_root",
            "exec_file",
            "deny",
            "list",
            "connect",
            "write_root",
            "write_dir",
            "cells",
        ] {
            let text = format!(
                r#"{{"description":"a","agent":{{"description":"b","{absent}":["/dev/null"]}},"leaf":{{"description":"c"}}}}"#
            );
            assert!(
                serde_json::from_str::<OsPaths>(&text).is_err(),
                "a set that states {absent} must not parse"
            );
        }
        // The control: the same shape with a list the schema does hold parses, so the cases above
        // fail on the name rather than on the surrounding text.
        let text = r#"{"description":"a","agent":{"description":"b","read_file":["/dev/null"]},"leaf":{"description":"c"}}"#;
        let parsed: OsPaths = serde_json::from_str(text).expect("a stated list parses");
        assert_eq!(
            parsed.agent.cells(),
            vec![(PathBuf::from("/dev/null"), Operation::Read, Scope::File)]
        );
    }

    /// Only the null device is written, which is the one claim the schema cannot carry by itself.
    #[test]
    fn only_the_null_device_is_written() {
        for (name, set) in [("agent", &os_paths().agent), ("leaf", &os_paths().leaf)] {
            assert!(
                set.write_file.iter().all(|path| path == "/dev/null"),
                "{name} writes more than the null device: {:?}",
                set.write_file
            );
        }
    }

    /// Every cell the host reports exists, in the kind its scope names, and once per identity.
    #[test]
    fn every_reported_cell_exists_in_the_kind_its_scope_names() {
        let reported = os_minimum_cells();
        assert!(
            reported
                .iter()
                .any(|(path, _, _)| path == Path::new("/dev/null")),
            "{reported:?}"
        );
        let mut seen = Vec::new();
        for (path, operation, scope) in &reported {
            assert!(kind_matches(path, *scope), "{}", path.display());
            let key = (
                path.canonicalize().unwrap_or_else(|_| path.clone()),
                *operation,
                *scope,
            );
            assert!(!seen.contains(&key), "one cell per identity: {reported:?}");
            seen.push(key);
        }
    }

    /// Neither runtime set reaches the active developer directory.
    #[cfg(target_os = "macos")]
    #[test]
    fn no_containment_reaches_the_developer_directory() {
        let Some(developer) = std::process::Command::new("/usr/bin/xcode-select")
            .arg("-p")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
                    .canonicalize()
                    .ok()
            })
        else {
            println!("skipping: this host has no developer directory");
            return;
        };
        let reaches = |cells: Vec<(PathBuf, Operation, Scope)>| {
            cells.iter().any(|(path, _, _)| {
                let identity = path.canonicalize().unwrap_or_else(|_| path.clone());
                (developer.starts_with(&identity) && identity != Path::new("/"))
                    || identity.starts_with(&developer)
            })
        };
        assert!(
            !reaches(os_leaf_cells()),
            "leaf containment reaches {}",
            developer.display()
        );
        assert!(
            !reaches(os_runtime_cells()),
            "agent containment reaches {}",
            developer.display()
        );
    }

    /// One `(operation, scope)` pair, which is what a row's `permits` holds.
    type Permit = (Operation, Scope);

    /// **Every forbidden row, in order: its anchor, its rule, its class, and the cells it permits.**
    ///
    /// The list moved from a Rust `const` into `forbidden-paths.json`, and this is the whole record of
    /// what it held. Three properties nothing else carries in full: the `permits` set, the **class** of
    /// each row — a row moved from `machine_credential` to `credential_store` becomes exemptible by
    /// `allow_credential_store`, and every other test stays green — and the order.
    #[test]
    fn the_forbidden_rows_are_exactly_these() {
        use ForbiddenClass::{
            CredentialStore, HomeNamespace, LoaderDirectory, MachineCredential, PasswordDatabase,
            PrivilegeConfiguration, SystemTree, WholeFilesystem,
        };
        use Match::{AnyOverlap, ExactPath};
        const READ_DIR: Permit = (Operation::Read, Scope::Dir);
        const READ_ROOT: Permit = (Operation::Read, Scope::Root);
        const STAT_DIR: Permit = (Operation::Metadata, Scope::Dir);
        const STAT_ROOT: Permit = (Operation::Metadata, Scope::Root);

        let expected: &[(&str, Match, ForbiddenClass, &[Permit])] = &[
            ("/", ExactPath, WholeFilesystem, &[READ_DIR, STAT_DIR]),
            ("/Users", ExactPath, HomeNamespace, &[]),
            ("/home", ExactPath, HomeNamespace, &[]),
            ("/Library", ExactPath, SystemTree, &[]),
            ("/System", ExactPath, SystemTree, &[]),
            ("/bin", ExactPath, SystemTree, &[]),
            ("/boot", ExactPath, SystemTree, &[]),
            ("/dev", ExactPath, SystemTree, &[]),
            ("/etc", ExactPath, SystemTree, &[STAT_DIR]),
            ("/lib", ExactPath, LoaderDirectory, &[READ_ROOT]),
            ("/lib64", ExactPath, LoaderDirectory, &[READ_ROOT]),
            ("/opt", ExactPath, SystemTree, &[]),
            ("/opt/homebrew", ExactPath, SystemTree, &[]),
            ("/private", ExactPath, SystemTree, &[]),
            ("/private/etc", ExactPath, SystemTree, &[STAT_DIR]),
            ("/etc/master.passwd", ExactPath, PasswordDatabase, &[]),
            (
                "/private/etc/master.passwd",
                ExactPath,
                PasswordDatabase,
                &[],
            ),
            ("/etc/shadow", ExactPath, PasswordDatabase, &[]),
            ("/etc/gshadow", ExactPath, PasswordDatabase, &[]),
            ("/var/db/dslocal", AnyOverlap, PasswordDatabase, &[]),
            ("/private/var/db/dslocal", AnyOverlap, PasswordDatabase, &[]),
            ("/Library/Keychains", AnyOverlap, MachineCredential, &[]),
            ("/var/db/SystemKey", ExactPath, MachineCredential, &[]),
            (
                "/private/var/db/SystemKey",
                ExactPath,
                MachineCredential,
                &[],
            ),
            ("/etc/sudoers", ExactPath, PrivilegeConfiguration, &[]),
            (
                "/private/etc/sudoers",
                ExactPath,
                PrivilegeConfiguration,
                &[],
            ),
            ("/etc/sudoers.d", AnyOverlap, PrivilegeConfiguration, &[]),
            (
                "/private/etc/sudoers.d",
                AnyOverlap,
                PrivilegeConfiguration,
                &[],
            ),
            (
                "/Library/Application Support/com.apple.TCC",
                AnyOverlap,
                PrivilegeConfiguration,
                &[],
            ),
            (
                "/private/tmp",
                ExactPath,
                SystemTree,
                &[READ_DIR, STAT_ROOT],
            ),
            ("/private/var", ExactPath, SystemTree, &[STAT_DIR]),
            ("/proc", ExactPath, SystemTree, &[]),
            ("/root", ExactPath, SystemTree, &[]),
            ("/run", ExactPath, SystemTree, &[]),
            ("/sbin", ExactPath, SystemTree, &[]),
            ("/srv", ExactPath, SystemTree, &[]),
            ("/sys", ExactPath, SystemTree, &[]),
            ("/tmp", ExactPath, SystemTree, &[READ_DIR, STAT_ROOT]),
            ("/usr", ExactPath, SystemTree, &[]),
            ("/usr/bin", ExactPath, SystemTree, &[]),
            ("/usr/lib", ExactPath, LoaderDirectory, &[READ_ROOT]),
            ("/usr/lib64", ExactPath, LoaderDirectory, &[READ_ROOT]),
            ("/usr/local", ExactPath, SystemTree, &[]),
            ("/usr/sbin", ExactPath, SystemTree, &[]),
            ("/usr/share", ExactPath, SystemTree, &[]),
            ("/var", ExactPath, SystemTree, &[STAT_DIR]),
            ("~/.aws", AnyOverlap, CredentialStore, &[]),
            ("~/.ssh", AnyOverlap, CredentialStore, &[]),
            ("~/.gnupg", AnyOverlap, CredentialStore, &[]),
            ("~/.netrc", AnyOverlap, CredentialStore, &[]),
            ("~/.docker", AnyOverlap, CredentialStore, &[]),
            ("~/.kube", AnyOverlap, CredentialStore, &[]),
            ("~/.config/gcloud", AnyOverlap, CredentialStore, &[]),
            ("~/.config/google-chrome", AnyOverlap, CredentialStore, &[]),
            ("~/.mozilla", AnyOverlap, CredentialStore, &[]),
            ("~/Library/Keychains", AnyOverlap, CredentialStore, &[]),
            (
                "~/Library/Application Support/Google/Chrome",
                AnyOverlap,
                CredentialStore,
                &[],
            ),
            (
                "~/Library/Application Support/Firefox",
                AnyOverlap,
                CredentialStore,
                &[],
            ),
        ];

        let loaded: Vec<(&str, Match, ForbiddenClass, Vec<Permit>)> = forbidden_paths()
            .iter()
            .map(|row| {
                (
                    row.anchor.as_str(),
                    row.rule,
                    row.class,
                    row.permits.clone(),
                )
            })
            .collect();
        let stated: Vec<(&str, Match, ForbiddenClass, Vec<Permit>)> = expected
            .iter()
            .map(|(anchor, rule, class, permits)| (*anchor, *rule, *class, permits.to_vec()))
            .collect();
        assert_eq!(
            loaded, stated,
            "forbidden-paths.json changed. A row added needs its class argued; a row removed, \
             reclassified, or given a new cell reopens what it was protecting"
        );
    }

    /// **Only the operator's own store is exemptible**, which is the gate a message string carried.
    #[test]
    fn only_a_credential_store_row_is_exemptible() {
        for row in forbidden_paths() {
            assert_eq!(
                row.class.is_exemptible(),
                row.class == ForbiddenClass::CredentialStore,
                "{} is {:?} and must not change who may exempt it",
                row.anchor,
                row.class
            );
        }
        // The machine's own stores sit beside the operator's and are never the operator's to hand
        // over. Without this, sharing one class would be invisible.
        assert!(!ForbiddenClass::MachineCredential.is_exemptible());
        assert!(!ForbiddenClass::PasswordDatabase.is_exemptible());
        assert!(!ForbiddenClass::PrivilegeConfiguration.is_exemptible());
    }

    /// Every class states a distinct reason, so a refusal names which row refused.
    #[test]
    fn every_class_states_its_own_reason() {
        let classes = [
            ForbiddenClass::WholeFilesystem,
            ForbiddenClass::HomeNamespace,
            ForbiddenClass::SystemTree,
            ForbiddenClass::LoaderDirectory,
            ForbiddenClass::CredentialStore,
            ForbiddenClass::PasswordDatabase,
            ForbiddenClass::MachineCredential,
            ForbiddenClass::PrivilegeConfiguration,
        ];
        let mut seen: Vec<&str> = Vec::new();
        for class in classes {
            let reason = class.reason();
            assert!(!reason.is_empty(), "{class:?} states no reason");
            assert!(
                !seen.contains(&reason),
                "{class:?} repeats another class's reason, so a refusal cannot name the row"
            );
            seen.push(reason);
        }
    }
}
