//! Fixed macOS Seatbelt profile and `sandbox_init` application.
//!
//! One block per cell, where a cell is one [`Operation`] at one [`Scope`]. The kernel takes the union
//! of every `allow`, so a path granted read and write reaches two blocks and needs no third.
//!
//! | cell               | rules |
//! |--------------------|-------|
//! | `Exec` + `File`    | `process-exec` on the literal, paired with `file-read-metadata` and never `file-read*` |
//! | `Exec` + `Root`    | ancestor metadata, `process-exec` over the subpath, and `file-read-metadata` over it — never `file-read*`; rendered in the exec block |
//! | `Read` + `File`    | `file-read*` on the literal |
//! | `Read` + `Dir`     | ancestor metadata, the literal's own metadata, and its entries — no descendant |
//! | `Read` + `Root`    | ancestor metadata, and `file-read*` over the subtree |
//! | `List` + `Root`    | ancestor metadata, `file-read-metadata` over the subtree, and `file-read-data` on its directory vnodes alone; rendered in the read-root block |
//! | `Write` + `File`   | `file-write*` on the literal, and denies leaving its contents alone: its flags, its identity, its ACL, its mode, its owner, and its executable mapping |
//! | `Write` + `Root`   | `file-write*` over the subtree, two denies fixing the root's own identity, and denies on the subtree's flags, ACL, owner, and executable mappings |
//! | `Connect` + `File` | `network-outbound` on the path |
//!
//! A write cell ends with one executable-mapping allow per exec grant it reaches, so the pair the
//! floor warns about renders as stated. A refusal renders as `subpath` for a tree and as `literal`
//! for one file. A write protection or a refusal strictly inside a write root fixes each directory
//! between the two with the root's own identity pair, after the root's leaf allows.
//!
//! Two blocks are not cells. One refuses the existence test across the operator's home, allows it
//! back on each granted path and its ancestor chain — over the subtree when the path is inside the
//! home — and denies it on every credential store last. The other names the regular files behind
//! the inherited standard streams, metadata only and judged by the same floor as a grant, so `fstat`
//! on a redirected stream answers.
//!
//! **A rule must name the path a load asks for, not the path it resolves to**: a
//! Homebrew dylib's `install_name` requests the symlink spelling, so a grant built from the resolved
//! one matches nothing and the workload dies in dyld. Probe a footprint with `DYLD_PRINT_SEARCHING`,
//! which reports the requested path, and never `DYLD_PRINT_LIBRARIES`, which reports only the
//! resolved one.

use std::collections::{BTreeMap, BTreeSet};

use crate::ContainmentConfig;
// Used by the apply path and its test, both gated below.
#[cfg(target_os = "macos")]
use crate::backend::{ContainmentBackend, SupportInfo};
use crate::error::ContainmentError;
use crate::floors::{
    credential_store_paths, data_volume_spelling, operator_home_spellings, require_bounded_grant,
};
use crate::model::{
    BackendOverride, IpcMode, Network, Operation, PathGrant, ProcessInfoMode, Scope, SignalMode,
};
#[cfg(target_os = "macos")]
use crate::platform::Platform;

type Result<T> = std::result::Result<T, ContainmentError>;

pub(crate) const MECHANISM: &str = "seatbelt";
const AGENT_PROFILE: &str = include_str!("seatbelt-agent.sb");

/// One placeholder per cell, named for the cell rather than for a role.
const EXEC_FILE: &str = "{{EXEC_FILE}}";
const READ_FILE: &str = "{{READ_FILE}}";
const READ_DIR: &str = "{{READ_DIR}}";
const READ_ROOT: &str = "{{READ_ROOT}}";
const WRITE_FILE: &str = "{{WRITE_FILE}}";
const WRITE_ROOT: &str = "{{WRITE_ROOT}}";
const WRITE_PROTECTION: &str = "{{WRITE_PROTECTION}}";
const CONNECT_FILE: &str = "{{CONNECT_FILE}}";
const METADATA_DIR: &str = "{{METADATA_DIR}}";
const METADATA_ROOT: &str = "{{METADATA_ROOT}}";
const CONNECT_PORTS: &str = "{{CONNECT_PORTS}}";
const STANDARD_STREAMS: &str = "{{STANDARD_STREAMS}}";
/// A leaf-only cell: the host services a bundled runtime touches at startup, empty for the agent box.
const RUNTIME_SERVICES: &str = "{{RUNTIME_SERVICES}}";
/// Not a cell: the existence block, whose parts come from the floor and from every grant.
const DENY_EXISTENCE: &str = "{{DENY_EXISTENCE}}";
const DENY_REFUSED: &str = "{{DENY_REFUSED}}";
const IDENTITY_LOOKUP: &str = "{{IDENTITY_LOOKUP}}";
/// Not a cell: the leaf-only additive overlay (broad exec). Empty for the agent box.
const LEAF_OVERLAY: &str = "{{LEAF_OVERLAY}}";

/// The `mDNSResponder` socket that `getaddrinfo` connects to.
const SYSTEM_RESOLVER: &str = "/private/var/run/mDNSResponder";

/// The `file-write*` leaves a write root grants, and the set every overriding deny must also name.
pub(crate) const WRITE_ROOT_LEAVES: [&str; 6] = [
    "file-write-data",
    "file-write-create",
    "file-write-unlink",
    "file-write-xattr",
    "file-write-mode",
    "file-write-times",
];

/// One `allow` per leaf in `WRITE_ROOT_LEAVES`, at `filter` scope.
fn write_leaf_allows(filter: &str, path: &str) -> String {
    WRITE_ROOT_LEAVES
        .iter()
        .map(|leaf| format!("(allow {leaf} ({filter} \"{path}\"))\n"))
        .collect()
}

/// One `deny` per leaf in `WRITE_ROOT_LEAVES`, at `filter` scope.
fn write_leaf_denies(filter: &str, path: &str) -> String {
    WRITE_ROOT_LEAVES
        .iter()
        .map(|leaf| format!("(deny {leaf} ({filter} \"{path}\"))\n"))
        .collect()
}

fn unsupported(capability: impl Into<String>) -> ContainmentError {
    ContainmentError::UnsupportedCapability {
        capability: capability.into(),
        backend: MECHANISM.to_string(),
    }
}

/// Whether a path lies strictly beneath one of the home's spellings.
fn inside_operator_home(path: &std::path::Path, homes: &[std::path::PathBuf]) -> bool {
    homes
        .iter()
        .any(|home| path != home.as_path() && path.starts_with(home))
}

/// Group grants by resolved path, so a duplicate operation and a scope disagreement are structural.
fn group_by_path(config: &ContainmentConfig) -> Result<Vec<(&PathGrant, BTreeSet<Operation>)>> {
    let mut groups: Vec<(&PathGrant, BTreeSet<Operation>)> = Vec::new();
    for granted in config.authorizations() {
        // Breadth first, and independent of the cell: the widest possible grant is also a
        // well-formed one, so recognizing the cell would accept it.
        require_bounded_grant(
            granted,
            config.operator_home(),
            config.credential_store_exempts(granted),
        )?;
        match groups
            .iter_mut()
            .find(|(first, _)| first.resolved == granted.resolved)
        {
            Some((first, operations)) => {
                if first.scope != granted.scope {
                    return Err(unsupported(format!(
                        "{} is granted at two scopes, {:?} and {:?}; one path has one scope",
                        granted.resolved.display(),
                        first.scope,
                        granted.scope,
                    )));
                }
                if !operations.insert(granted.operation) {
                    return Err(unsupported(format!(
                        "{} is granted {:?} twice",
                        granted.resolved.display(),
                        granted.operation,
                    )));
                }
            }
            None => groups.push((granted, BTreeSet::from([granted.operation]))),
        }
    }
    Ok(groups)
}

/// Refuse a configuration this fixed profile cannot express, before a rule is rendered.
fn require_expressible(config: &ContainmentConfig) -> Result<()> {
    if config.signal_mode() != SignalMode::Isolated
        || config.process_info_mode() != ProcessInfoMode::Isolated
        || config.ipc_mode() != IpcMode::SharedMemoryOnly
        || !matches!(config.backend_override(), BackendOverride::None)
    {
        return Err(unsupported(
            "configuration outside the fixed macOS Agent profile",
        ));
    }
    match config.network() {
        // Localhost with no inbound bind (the mediated default), or AllowAll (operator-declared
        // native egress, contain_egress = false). A `listen` port is still unsupported on macOS.
        Network::Localhost { listen, .. } if listen.is_empty() => {}
        Network::AllowAll => {}
        _ => {
            return Err(unsupported(
                "network access other than localhost ports or native (allow-all) egress",
            ));
        }
    }

    // Grouping is validation only. The renderer walks the grants themselves.
    let grouped = group_by_path(config)?;
    let with = |operation: Operation, scope: Scope| -> Vec<&PathGrant> {
        grouped
            .iter()
            .filter(|(granted, operations)| {
                granted.scope == scope && operations.contains(&operation)
            })
            .map(|(granted, _)| *granted)
            .collect()
    };

    let executables = with(Operation::Exec, Scope::File);
    if executables.is_empty() {
        return Err(unsupported(
            "missing Agent executable (at least one path granted exec at file scope)",
        ));
    }
    Ok(())
}

/// Escape a path for inclusion in an SBPL string literal, or refuse it.
fn escaped(path: &std::path::Path) -> Result<String> {
    let path = path.to_str().ok_or_else(|| ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason: format!("path contains non-UTF-8 bytes: {}", path.display()),
    })?;
    if path.contains("{{") {
        return Err(ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!(
                "path contains the profile placeholder opener \"{{{{\", which could \
                 inject a rule during substitution: {path}"
            ),
        });
    }
    let mut result = String::with_capacity(path.len());
    for character in path.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            value if value.is_control() => {
                return Err(ContainmentError::ApplyFailed {
                    backend: MECHANISM.to_string(),
                    reason: format!(
                        "path contains control character 0x{:02X}: {path}",
                        value as u32
                    ),
                });
            }
            value => result.push(value),
        }
    }
    Ok(result)
}

/// One `file-read-metadata` rule per node a lookup of this grant traverses.
fn reachable_metadata(granted: &PathGrant) -> Result<String> {
    let mut rules = String::new();
    for path in granted.traversal_paths() {
        let route = escaped(&path)?;
        rules.push_str(&format!(
            "(allow file-read-metadata (literal \"{route}\"))\n"
        ));
    }
    Ok(rules)
}

/// The same rule for every node except the resolved identity, which a `subpath` already covers.
fn other_spelling_metadata(granted: &PathGrant) -> Result<String> {
    let mut rules = String::new();
    for path in granted
        .traversal_paths()
        .iter()
        .filter(|candidate| *candidate != &granted.resolved)
    {
        let route = escaped(path)?;
        rules.push_str(&format!(
            "(allow file-read-metadata (literal \"{route}\"))\n"
        ));
    }
    Ok(rules)
}

/// One `file-read-metadata` rule per symbolic link among the directories a requested spelling
/// traverses, which a load through a linked directory needs beside the file's own spellings.
fn linked_directory_metadata(requested: &std::path::Path) -> Result<String> {
    let mut rules = String::new();
    for ancestor in requested.ancestors().skip(1) {
        if std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| metadata.is_symlink()) {
            let route = escaped(ancestor)?;
            rules.push_str(&format!(
                "(allow file-read-metadata (literal \"{route}\"))\n"
            ));
        }
    }
    Ok(rules)
}

/// One executable-mapping allow per exec grant this write grant reaches, after the cell's own deny.
///
/// Empty unless an exec grant overlaps this write grant, which is the pair `floors::warnings`
/// reports; the allow names the exec grant's own path and never the write grant's.
fn executable_carve_outs(config: &ContainmentConfig, writable: &PathGrant) -> Result<String> {
    let mut rules = String::new();
    for scope in [Scope::File, Scope::Root] {
        for executable in config.grants_in(Operation::Exec, scope) {
            let inside_writable = match writable.scope {
                Scope::Root => executable.resolved.starts_with(&writable.resolved),
                Scope::File | Scope::Dir => executable.resolved == writable.resolved,
            };
            let carved = if inside_writable {
                Some((executable.scope, &executable.resolved))
            } else if scope == Scope::Root && writable.resolved.starts_with(&executable.resolved) {
                Some((writable.scope, &writable.resolved))
            } else {
                None
            };
            if let Some((scope, path)) = carved {
                let filter = if scope == Scope::Root {
                    "subpath"
                } else {
                    "literal"
                };
                rules.push_str(&format!(
                    "(allow file-map-executable ({filter} \"{}\"))\n",
                    escaped(path)?
                ));
            }
        }
    }
    Ok(rules)
}

/// Every directory strictly between `path` and `root`, deepest first, and nothing when `path` is
/// not strictly inside `root`.
fn directories_between<'a>(
    path: &'a std::path::Path,
    root: &'a std::path::Path,
) -> impl Iterator<Item = &'a std::path::Path> {
    path.ancestors()
        .skip(1)
        .take_while(move |ancestor| *ancestor != root && ancestor.starts_with(root))
}

/// The ancestor-metadata rule a lookup needs, or nothing for the root, which has none.
fn ancestor_rule(path: &str) -> String {
    if path == "/" {
        String::new()
    } else {
        format!("(allow file-read-metadata (path-ancestors \"{path}\"))\n")
    }
}

/// The ancestor-existence rule a lookup needs, or nothing for the root, which has none.
fn ancestor_existence_rule(path: &str) -> String {
    if path == "/" {
        String::new()
    } else {
        format!("(allow file-test-existence (path-ancestors \"{path}\"))\n")
    }
}

fn grant_existence_rules(granted: &PathGrant, homes: &[std::path::PathBuf]) -> Result<Vec<String>> {
    let filter = if granted.scope == Scope::Root || inside_operator_home(&granted.resolved, homes) {
        "subpath"
    } else {
        "literal"
    };
    let resolved = escaped(&granted.resolved)?;
    let mut rules = vec![
        ancestor_existence_rule(&resolved),
        format!("(allow file-test-existence ({filter} \"{resolved}\"))\n"),
    ];
    for other in granted
        .traversal_paths()
        .iter()
        .filter(|candidate| *candidate != &granted.resolved)
    {
        let path = escaped(other)?;
        rules.push(format!(
            "(allow file-test-existence (literal \"{path}\"))\n"
        ));
    }
    Ok(rules)
}

/// The regular files behind the standard streams a process inherited.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct InheritedStreams {
    paths: Vec<std::path::PathBuf>,
}

impl InheritedStreams {
    /// The files behind this process's descriptors 0, 1, and 2.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn of_this_process() -> Self {
        Self::of_descriptors(&[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO])
    }

    /// The files behind the given descriptors, each once, in descriptor order.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn of_descriptors(descriptors: &[libc::c_int]) -> Self {
        let mut paths: Vec<std::path::PathBuf> = Vec::new();
        for path in descriptors
            .iter()
            .filter_map(|descriptor| vnode_path(*descriptor))
        {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        Self { paths }
    }

    /// The paths, in descriptor order.
    pub(crate) fn paths(&self) -> &[std::path::PathBuf] {
        &self.paths
    }
}

/// The path behind a descriptor when a regular file is behind it.
#[cfg(any(target_os = "macos", test))]
fn vnode_path(descriptor: libc::c_int) -> Option<std::path::PathBuf> {
    // SAFETY: `stat` is a plain C struct, and `fstat` writes only into it.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is a number, and `stat` is writable for the call.
    if unsafe { libc::fstat(descriptor, &raw mut stat) } != 0 {
        return None;
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    descriptor_path(descriptor)
}

#[cfg(target_os = "macos")]
fn descriptor_path(descriptor: libc::c_int) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `buffer` holds `PATH_MAX` bytes, the most `F_GETPATH` writes.
    if unsafe { libc::fcntl(descriptor, libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer[..end],
    )))
}

#[cfg(all(not(target_os = "macos"), test))]
fn descriptor_path(descriptor: libc::c_int) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{descriptor}")).ok()
}

/// The profile for one request, naming no inherited stream.
pub(crate) fn render_profile(config: &ContainmentConfig) -> Result<String> {
    render_profile_with_streams(config, &InheritedStreams::default())
}

/// Render the fixed profile by replacing its explicit placeholders, one per inherited stream too.
pub(crate) fn render_profile_with_streams(
    config: &ContainmentConfig,
    streams: &InheritedStreams,
) -> Result<String> {
    require_expressible(config)?;

    let mut cells: BTreeMap<&str, String> = BTreeMap::new();
    let mut loaded_images: BTreeSet<std::path::PathBuf> = BTreeSet::new();

    for granted in config.authorizations() {
        let path = escaped(&granted.resolved)?;
        match (granted.operation, granted.scope) {
            // The paired metadata read is what lets a `PATH` search stat the candidate, and a
            // second one covers the caller's spelling when it differs.
            (Operation::Exec, Scope::File) => {
                let rules = format!(
                    "(allow process-exec (literal \"{path}\"))\n{}",
                    reachable_metadata(granted)?
                );
                cells.entry(EXEC_FILE).or_default().push_str(&rules);
                // The images the program loads from outside the shared cache are read-file cells:
                // `file-read*` on each identity, and metadata on the spelling the load requests.
                for image in super::macho::dylib_closure(&granted.resolved)? {
                    let loaded = PathGrant::new(&image, Operation::Read, Scope::File)?;
                    require_bounded_grant(&loaded, config.operator_home(), false).map_err(
                        |error| ContainmentError::ApplyFailed {
                            backend: MECHANISM.to_string(),
                            reason: format!(
                                "'{}' loads '{}', which the floor refuses: {error}",
                                granted.resolved.display(),
                                image.display()
                            ),
                        },
                    )?;
                    if !loaded_images.insert(loaded.resolved.clone()) {
                        continue;
                    }
                    cells.entry(READ_FILE).or_default().push_str(&format!(
                        "(allow file-read* (literal \"{}\"))\n{}{}",
                        escaped(&loaded.resolved)?,
                        other_spelling_metadata(&loaded)?,
                        linked_directory_metadata(&image)?
                    ));
                }
            }
            (Operation::Read, Scope::File) => {
                cells.entry(READ_FILE).or_default().push_str(&format!(
                    "(allow file-read* (literal \"{path}\"))\n{}",
                    other_spelling_metadata(granted)?
                ));
            }
            // On a directory the data operation is enumeration, so no descendant is granted.
            (Operation::Read, Scope::Dir) => cells.entry(READ_DIR).or_default().push_str(&format!(
                "{}(allow file-read-metadata (literal \"{path}\"))\n\
                 (allow file-read-data (literal \"{path}\"))\n{}",
                ancestor_rule(&path),
                other_spelling_metadata(granted)?
            )),
            (Operation::Read, Scope::Root) => {
                cells.entry(READ_ROOT).or_default().push_str(&format!(
                    "{}(allow file-read* (subpath \"{path}\"))\n{}",
                    ancestor_rule(&path),
                    other_spelling_metadata(granted)?
                ))
            }
            // Every program under the tree runs, and a lookup stats its way to each; the bytes stay
            // unreadable, as for one file. The exec block holds it, so the template gains no slot.
            (Operation::Exec, Scope::Root) => {
                cells.entry(EXEC_FILE).or_default().push_str(&format!(
                    "{}(allow process-exec (subpath \"{path}\"))\n\
                     (allow file-read-metadata (subpath \"{path}\"))\n{}",
                    ancestor_rule(&path),
                    other_spelling_metadata(granted)?
                ))
            }
            // Enumeration over the subtree: metadata on every entry, and the data operation on
            // directory vnodes alone, so no regular file's bytes are readable.
            (Operation::List, Scope::Root) => {
                cells.entry(READ_ROOT).or_default().push_str(&format!(
                    "{}(allow file-read-metadata (subpath \"{path}\"))\n\
                     (allow file-read-data (require-all (subpath \"{path}\") (vnode-type DIRECTORY)))\n{}",
                    ancestor_rule(&path),
                    other_spelling_metadata(granted)?
                ))
            }
            // A write cell names the leaves it needs. The flags, the access-control list, the mode,
            // the owner, and the identity pair are absent rather than denied. The
            // executable-mapping deny is what makes the path writable-XOR-executable.
            (Operation::Write, Scope::File) => {
                cells.entry(WRITE_FILE).or_default().push_str(&format!(
                    "(allow file-write-data (literal \"{path}\"))\n\
                     (deny file-map-executable (literal \"{path}\"))\n{}",
                    executable_carve_outs(config, granted)?
                ));
            }
            // The identity pair is granted over the subtree and denied on the root's own literal, so
            // the entries may be replaced and the root may not. `(subpath X)` covers `X` itself, so
            // without both denies a `symlink` at that path would succeed. The mode is granted here
            // and not on the file cell, because a workload tightens a file it creates in its own
            // tree.
            (Operation::Write, Scope::Root) => {
                cells.entry(WRITE_ROOT).or_default().push_str(&format!(
                    "{}(deny file-write-unlink (literal \"{path}\"))\n\
                     (deny file-write-create (literal \"{path}\"))\n\
                     (deny file-map-executable (subpath \"{path}\"))\n{}",
                    write_leaf_allows("subpath", &path),
                    executable_carve_outs(config, granted)?
                ));
                cells.entry(CONNECT_FILE).or_default().push_str(&format!(
                    "(allow network-bind (subpath \"{path}\"))\n\
                     (allow network-inbound (subpath \"{path}\"))\n\
                     (allow network-outbound (subpath \"{path}\"))\n"
                ));
            }
            // No data rule, so a directory is not enumerable and a file's bytes stay unreadable.
            // The caller's spelling gets its own metadata rule when it differs, because a lookup
            // traverses the link node itself, as for an exec grant; `/etc` needs it.
            (Operation::Metadata, Scope::Dir) => cells.entry(METADATA_DIR).or_default().push_str(
                &format!("{}{}", ancestor_rule(&path), reachable_metadata(granted)?),
            ),
            (Operation::Metadata, Scope::Root) => {
                cells.entry(METADATA_ROOT).or_default().push_str(&format!(
                    "{}(allow file-read-metadata (subpath \"{path}\"))\n{}",
                    ancestor_rule(&path),
                    other_spelling_metadata(granted)?
                ))
            }
            (Operation::Connect, Scope::File) => {
                let routes = cells.entry(CONNECT_FILE).or_default();
                routes.push_str(&format!(
                    "(allow network-outbound\n    (path \"{path}\"))\n"
                ));
            }
            // Unreachable rather than permissive, and a refusal so a new cell cannot render nothing.
            (operation, scope) => {
                return Err(unsupported(format!(
                    "the fixed Agent profile has no block for {operation:?} at {scope:?} scope: {}",
                    granted.resolved.display()
                )));
            }
        }
    }

    let write_roots = config.grants_in(Operation::Write, Scope::Root);
    let mut fixed_ancestors = BTreeSet::new();
    for protected in config.write_protections() {
        let path = escaped(protected.path())?;
        cells
            .entry(WRITE_PROTECTION)
            .or_default()
            .push_str(&format!(
                "(deny file-write* (literal \"{path}\"))\n\
                 {}(deny file-link (literal \"{path}\"))\n",
                write_leaf_denies("literal", &path)
            ));
        for root in &write_roots {
            fixed_ancestors.extend(
                directories_between(protected.path(), &root.resolved)
                    .map(std::path::Path::to_path_buf),
            );
        }
    }
    for refused in config.refusals() {
        for root in &write_roots {
            fixed_ancestors.extend(
                directories_between(&refused.resolved, &root.resolved)
                    .map(std::path::Path::to_path_buf),
            );
        }
    }
    for ancestor in fixed_ancestors {
        let path = escaped(&ancestor)?;
        cells
            .entry(WRITE_PROTECTION)
            .or_default()
            .push_str(&format!(
                "(deny file-write-unlink (literal \"{path}\"))\n\
                 (deny file-write-create (literal \"{path}\"))\n"
            ));
    }

    // Three parts, in this order, because Seatbelt takes the last matching rule for an operation.
    // Every name the home answers to: the operation matches the pre-resolution path, so a rule on
    // one spelling leaves the others answering.
    let homes = operator_home_spellings(config.operator_home())?;
    let discovery = config.discovery_roots();
    // Home existence-deny per spelling, suppressed only where a discovery root is AT OR ABOVE that
    // spelling (only then does the root's own allow below cover it). A child discovery root does not
    // cover the home, so the home keeps its deny and is never opened wholesale.
    for home in &homes {
        if discovery.iter().any(|root| home.starts_with(root)) {
            continue;
        }
        let escaped_home = escaped(home)?;
        cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
            "(deny file-test-existence (subpath \"{escaped_home}\"))\n"
        ));
    }
    // Leaf discovery
    // (docs/design/decisions.md#a-leaf-discovers-existence-and-metadata-content-stays-gated):
    // render EACH discovery root as its own subtree — the root itself, not an overlapping home
    // spelling — plus its macOS data-volume twin, because Seatbelt matches the pre-resolution path
    // and one spelling leaves the other answering. A tool tests existence and reads metadata across
    // the root; content stays gated, and the box-state and credential denies below still win.
    for root in discovery {
        for spelling in [Some(root.clone()), data_volume_spelling(root)] {
            let Some(spelling) = spelling else { continue };
            let escaped_root = escaped(&spelling)?;
            cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
                "(allow file-test-existence (subpath \"{escaped_root}\"))\n\
                 (allow file-read-metadata (subpath \"{escaped_root}\"))\n"
            ));
        }
    }
    // Under discovery the box's own state tree lies under the home allow above, so exclude it here —
    // deny existence and metadata across it, then re-allow both for exactly the paths a grant already
    // names beneath it (the box home and the CA trust bundle). So a leaf still stats its own granted
    // state, while an ungranted sibling-box path or this box's private state stays refused. The
    // metadata re-allow is explicit because `grant_existence_rules` restores existence alone, and the
    // deny above would otherwise clobber a granted read's metadata. Gated on discovery being active.
    if !discovery.is_empty() {
        // Each spelling, like the discovery-root allow above: the home allow opened both the plain
        // path and its data-volume twin, so a plain-only deny would leave the twin answering and a
        // leaf could stat this box's private state or a sibling box's through it.
        for path in config.discovery_denies() {
            for spelling in [Some(path.clone()), data_volume_spelling(path)] {
                let Some(spelling) = spelling else { continue };
                let escaped_deny = escaped(&spelling)?;
                cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
                    "(deny file-test-existence (subpath \"{escaped_deny}\"))\n\
                     (deny file-read-metadata (subpath \"{escaped_deny}\"))\n"
                ));
            }
        }
        for granted in config.authorizations() {
            if config
                .discovery_denies()
                .iter()
                .any(|deny| granted.resolved.starts_with(deny))
            {
                let filter = if granted.scope == Scope::Root
                    || inside_operator_home(&granted.resolved, &homes)
                {
                    "subpath"
                } else {
                    "literal"
                };
                for spelling in [
                    Some(granted.resolved.clone()),
                    data_volume_spelling(&granted.resolved),
                ] {
                    let Some(spelling) = spelling else { continue };
                    let resolved = escaped(&spelling)?;
                    cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
                        "(allow file-test-existence ({filter} \"{resolved}\"))\n\
                         (allow file-read-metadata ({filter} \"{resolved}\"))\n"
                    ));
                }
            }
        }
    }
    // One rule per distinct path, in grant order: a path granted read and write is two grants and
    // needs one pairing, and a repeat would only inflate the profile.
    let mut paired: Vec<String> = Vec::new();
    for granted in config.authorizations() {
        for rule in grant_existence_rules(granted, &homes)? {
            if !rule.is_empty() && !paired.contains(&rule) {
                paired.push(rule);
            }
        }
    }
    cells
        .entry(DENY_EXISTENCE)
        .or_default()
        .push_str(&paired.concat());
    let discovering = !discovery.is_empty();
    for path in credential_store_paths(config.operator_home())? {
        let path = escaped(&path)?;
        cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
            "(deny file-test-existence (subpath \"{path}\"))\n"
        ));
        if discovering {
            // Discovery allowed metadata across the home, so a credential store needs its own
            // metadata deny too; it renders last, after the home allow, so it wins.
            cells
                .entry(DENY_EXISTENCE)
                .or_default()
                .push_str(&format!("(deny file-read-metadata (subpath \"{path}\"))\n"));
        }
    }
    for granted in config
        .authorizations()
        .into_iter()
        .filter(|granted| config.credential_store_exempts(granted))
    {
        for rule in grant_existence_rules(granted, &homes)? {
            cells.entry(DENY_EXISTENCE).or_default().push_str(&rule);
        }
        if discovering {
            // Discovery added a metadata deny on the store above, and `grant_existence_rules`
            // restores existence alone. An announced store the leaf may read needs its metadata
            // re-allowed after that deny too, or `stat` and `open` on the named credentials break.
            // Mirror the box-state re-allow, and render both spellings for the same reason.
            let filter = if granted.scope == Scope::Root
                || inside_operator_home(&granted.resolved, &homes)
            {
                "subpath"
            } else {
                "literal"
            };
            for spelling in [
                Some(granted.resolved.clone()),
                data_volume_spelling(&granted.resolved),
            ] {
                let Some(spelling) = spelling else { continue };
                let resolved = escaped(&spelling)?;
                cells.entry(DENY_EXISTENCE).or_default().push_str(&format!(
                    "(allow file-read-metadata ({filter} \"{resolved}\"))\n"
                ));
            }
        }
    }

    // Each refused tree or file keeps both spellings closed to content reads, writes, and
    // execution, whether or not the path exists.
    for refused in config.refusals() {
        let filter = if refused.scope == Scope::File {
            "literal"
        } else {
            "subpath"
        };
        for spelling in refused.reachable_paths() {
            let path = escaped(&spelling)?;
            cells.entry(DENY_REFUSED).or_default().push_str(&format!(
                "(deny file-read* ({filter} \"{path}\"))\n\
                 (deny file-write* ({filter} \"{path}\"))\n\
                 {}(deny file-read-data ({filter} \"{path}\"))\n\
                 (deny file-read-metadata ({filter} \"{path}\"))\n\
                 (deny file-test-existence ({filter} \"{path}\"))\n\
                 (deny process-exec ({filter} \"{path}\"))\n\
                 (deny file-map-executable ({filter} \"{path}\"))\n\
                 (deny network-bind ({filter} \"{path}\"))\n\
                 (deny network-inbound ({filter} \"{path}\"))\n\
                 (deny network-outbound ({filter} \"{path}\"))\n",
                write_leaf_denies(filter, &path)
            ));
        }
    }

    let identity_paths: BTreeSet<_> = config
        .identity_requirements()
        .iter()
        .chain(config.write_protections())
        .flat_map(|required| required.path().ancestors())
        .collect();
    for path in identity_paths {
        let path = escaped(path)?;
        cells.entry(IDENTITY_LOOKUP).or_default().push_str(&format!(
            "(allow file-read-metadata (literal \"{path}\"))\n\
             (allow file-test-existence (literal \"{path}\"))\n"
        ));
    }

    // Leaf-only: a bundled JS/Node runtime calls `getifaddrs` at startup. It reads the `net.*`
    // sysctls and opens a routing socket. This is host information, never egress: the `(deny
    // network*)` that follows still stands, and AF_INET/AF_UNIX are unaffected. Scope the socket
    // grant to AF_ROUTE so it cannot authorize another PF_SYSTEM domain.
    if config.runtime_services() {
        cells.entry(RUNTIME_SERVICES).or_default().push_str(
            "(allow sysctl-read (sysctl-name-prefix \"net.\"))\n\
             (allow system-socket (socket-domain AF_ROUTE))\n",
        );
    }
    if !config.broad_exec() || config.runtime_services() {
        // Agents and opted-in leaves call `getpwuid` through this service. Keep the identity lookup
        // separate so an agent does not inherit the leaf-only sysctl and routing-socket grants.
        cells.entry(RUNTIME_SERVICES).or_default().push_str(
            "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n",
        );
    }

    match config.network() {
        Network::Localhost { connect, .. } => {
            for port in connect {
                cells.entry(CONNECT_PORTS).or_default().push_str(&format!(
                    "(allow network-outbound\n    (remote tcp \"localhost:{port}\"))\n"
                ));
            }
        }
        // Native egress: any IP host and the system resolver, and no other pathname socket.
        Network::AllowAll => {
            cells.entry(CONNECT_PORTS).or_default().push_str(&format!(
                "(allow network-outbound\n    (remote ip \"*:*\"))\n\
                 (allow network-outbound\n    (literal \"{SYSTEM_RESOLVER}\"))\n"
            ));
        }
        Network::Blocked => {}
    }

    // A stream is judged as a read grant on its file would be, and one the floor refuses gets no rule.
    for path in streams.paths() {
        let Ok(judged) = PathGrant::new(path, Operation::Read, Scope::File) else {
            continue;
        };
        if require_bounded_grant(&judged, config.operator_home(), false).is_err() {
            continue;
        }
        cells
            .entry(STANDARD_STREAMS)
            .or_default()
            .push_str(&format!(
                "(allow file-read-metadata (require-all (literal \"{}\") (vnode-type REGULAR-FILE)))\n",
                escaped(path)?
            ));
    }

    // Leaf-only additive overlay (broad exec,
    // docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds), filled
    // into the `{{LEAF_OVERLAY}}` cell — the template places it AFTER the write cells so the
    // executable-mapping allow overrides their deny, and BEFORE the refused/existence denies so a
    // refused tree stays non-executable. Additive by design: the agent's cell rendering above
    // carries no broad-exec branch, so this is the one place broad exec lives and the agent profile
    // cannot change by an edit here. Empty for the agent box (`broad_exec` false).
    if config.broad_exec() {
        let mut overlay = String::from("(allow process-exec*)\n");
        // One executable-mapping allow per writable grant (workspace, box home), so a build loads
        // what it compiles; scoped to the writable grants.
        for granted in config.authorizations() {
            if granted.operation == Operation::Write {
                let path = escaped(&granted.resolved)?;
                let filter = if granted.scope == Scope::Root {
                    "subpath"
                } else {
                    "literal"
                };
                overlay.push_str(&format!(
                    "(allow file-map-executable ({filter} \"{path}\"))\n"
                ));
            }
        }
        cells.entry(LEAF_OVERLAY).or_default().push_str(&overlay);
    }

    let replacements: Vec<(&str, String)> = [
        EXEC_FILE,
        STANDARD_STREAMS,
        READ_FILE,
        READ_DIR,
        READ_ROOT,
        WRITE_FILE,
        WRITE_ROOT,
        WRITE_PROTECTION,
        METADATA_DIR,
        METADATA_ROOT,
        CONNECT_FILE,
        CONNECT_PORTS,
        RUNTIME_SERVICES,
        DENY_EXISTENCE,
        DENY_REFUSED,
        IDENTITY_LOOKUP,
        LEAF_OVERLAY,
    ]
    .into_iter()
    .map(|placeholder| {
        let rules = cells.remove(placeholder).unwrap_or_default();
        (placeholder, rules.trim_end().to_string())
    })
    .collect();

    // ONE pass, not one pass per placeholder.
    let mut profile = String::with_capacity(AGENT_PROFILE.len());
    let mut rest = AGENT_PROFILE;
    'outer: while !rest.is_empty() {
        if let Some(open) = rest.find("{{") {
            profile.push_str(&rest[..open]);
            let after = &rest[open..];
            for (placeholder, value) in &replacements {
                if let Some(tail) = after.strip_prefix(*placeholder) {
                    profile.push_str(value);
                    rest = tail;
                    continue 'outer;
                }
            }
            // An unrecognized `{{` in the checked-in profile is a authoring mistake,
            // not something to pass through: it would reach `sandbox_init` as text.
            return Err(ContainmentError::ApplyFailed {
                backend: MECHANISM.to_string(),
                reason: format!(
                    "the fixed profile carries an unknown placeholder: {}",
                    after.chars().take(40).collect::<String>()
                ),
            });
        }
        profile.push_str(rest);
        break;
    }
    // A real check, not a `debug_assert!`: this is the backstop for a profile that reached
    // `sandbox_init` with an unsubstituted placeholder, and an assertion compiled out of release
    // builds is no backstop at all.
    if let Some(index) = profile.find("{{") {
        return Err(ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!(
                "rendered profile still contains a placeholder at byte {index}: {:?}",
                &profile[index..profile.len().min(index + 40)]
            ),
        });
    }
    Ok(profile)
}

#[cfg(any(target_os = "macos", test))]
fn apply_validated_profile(
    config: &ContainmentConfig,
    apply: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    let profile = render_profile_with_streams(config, &InheritedStreams::of_this_process())?;
    config.require_live_path_identities()?;
    apply(&profile)?;
    config.require_live_file_identities()
}

/// macOS Seatbelt backend.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub(crate) struct SeatbeltBackend;

#[cfg(target_os = "macos")]
impl SeatbeltBackend {
    /// Construct a fresh backend.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl ContainmentBackend for SeatbeltBackend {
    fn validate_config(&self, config: &ContainmentConfig) -> Result<()> {
        require_expressible(config)
    }

    fn apply(
        &self,
        config: &ContainmentConfig,
        // This mechanism pins the workload to an endpoint that already
        // exists, so it creates nothing to hand back.
        _egress_handoff: Option<&std::os::unix::net::UnixStream>,
        // Seatbelt execs in place, so a successful `exec` closes the status pipe (EOF); there is no
        // reaper to write a byte, and none is needed.
        _confirm_fd: Option<std::os::fd::RawFd>,
    ) -> Result<()> {
        apply_validated_profile(config, apply_current_process)
    }

    fn support_info(&self) -> SupportInfo {
        // Off macOS there is no arm here, because this `impl` is gated and `facade::detect_backend`
        // answers `PlatformUnsupported` instead.
        SupportInfo {
            is_supported: true,
            platform: Platform::MacOS,
            mechanism: MECHANISM.to_string(),
            details: "fixed macOS Seatbelt Agent profile available".to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
fn apply_current_process(profile: &str) -> Result<()> {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;

    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    let profile = CString::new(profile).map_err(|error| ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason: format!("invalid profile string: {error}"),
    })?;
    let mut error_buffer = ptr::null_mut();

    // SAFETY: `profile` is NUL terminated and `error_buffer` is writable.
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_buffer) };
    if result == 0 {
        return Ok(());
    }

    let reason = if error_buffer.is_null() {
        format!("sandbox_init returned error code {result}")
    } else {
        // SAFETY: sandbox_init returned an owned C string in `error_buffer`.
        let reason = unsafe { CStr::from_ptr(error_buffer).to_string_lossy().into_owned() };
        // SAFETY: sandbox_free_error frees the buffer returned by sandbox_init.
        unsafe { sandbox_free_error(error_buffer) };
        reason
    };
    Err(ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason,
    })
}

// The `#[cfg(not(target_os = "macos"))]` twin of `apply_current_process` stood here.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_escaping_rejects_injection_and_escapes_quotes() {
        assert_eq!(
            escaped(std::path::Path::new("/tmp/a\\b\"c")).unwrap(),
            "/tmp/a\\\\b\\\"c"
        );
        assert!(escaped(std::path::Path::new("/tmp/a\n(allow default)")).is_err());
    }

    /// **One path is one group**, so a repeated path cannot fill two slots.
    ///
    /// Read and write on one tree is two grants, and they must arrive as one group carrying both
    /// operations. Two scopes on one path, or one operation twice, is refused.
    #[test]
    fn grouping_folds_one_path_into_one_rule_set() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical");

        let config = ContainmentConfig::new()
            .allow(&root, Operation::Read, Scope::Root)
            .expect("read tree")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("write tree");
        let groups = group_by_path(&config).expect("read and write on one tree is one group");
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].1,
            BTreeSet::from([Operation::Read, Operation::Write])
        );

        let two_scopes = ContainmentConfig::new()
            .allow(&root, Operation::Read, Scope::Root)
            .expect("read tree")
            .allow(&root, Operation::Read, Scope::Dir)
            .expect("read dir");
        assert!(matches!(
            group_by_path(&two_scopes),
            Err(ContainmentError::UnsupportedCapability { .. })
        ));

        let twice = ContainmentConfig::new()
            .allow(&root, Operation::Read, Scope::Root)
            .expect("read tree")
            .allow(&root, Operation::Read, Scope::Root)
            .expect("read tree again");
        assert!(matches!(
            group_by_path(&twice),
            Err(ContainmentError::UnsupportedCapability { .. })
        ));
    }

    /// **A write root with no read root beside it renders write rules and no read rule.**
    ///
    /// It used to be refused, because the one write block also read. Each cell renders alone now, so
    /// the two are independent and the kernel takes the union.
    #[test]
    fn a_write_root_renders_without_a_read_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        // The program sits OUTSIDE the write root, or the conflict guard refuses the pair: a path
        // that is both writable and executable is one the workload can replace.
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let root = base.join("state");
        std::fs::create_dir(&root).expect("write root fixture");

        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("write root");
        let profile = render_profile(&config).expect("a write root renders on its own");

        let path = root.display().to_string();
        assert!(profile.contains(&format!("(allow file-write-data (subpath \"{path}\"))")));
        assert!(
            !profile.contains(&format!("(allow file-write* (subpath \"{path}\"))")),
            "a write root names leaves and never the family wildcard: {profile}"
        );
        assert!(
            !profile.contains(&format!("(allow file-read* (subpath \"{path}\"))")),
            "a write root grants no read: {profile}"
        );
    }

    /// A program outside a write root, with the one proxy port every expressible profile carries.
    fn stream_fixture() -> (tempfile::TempDir, std::path::PathBuf, ContainmentConfig) {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec");
        (temp, base, config)
    }

    /// **A regular file behind an inherited stream renders one metadata rule, before every
    /// refusal, and the plain render carries none.**
    #[test]
    fn an_inherited_file_stream_renders_one_metadata_rule_before_the_refusals() {
        use std::os::fd::AsRawFd as _;
        let (_temp, base, config) = stream_fixture();
        let redirected = base.join("agent.out");
        let file = std::fs::File::create(&redirected).expect("redirect target");
        let streams = InheritedStreams::of_descriptors(&[file.as_raw_fd(), file.as_raw_fd()]);
        assert_eq!(streams.paths(), std::slice::from_ref(&redirected));

        let profile = render_profile_with_streams(&config, &streams).expect("renders");
        let rule = format!(
            "(allow file-read-metadata (require-all (literal \"{}\") (vnode-type REGULAR-FILE)))",
            redirected.display()
        );
        assert_eq!(profile.matches(&rule).count(), 1, "{profile}");
        let rule_at = profile.find(&rule).expect("the rule is present");
        let first_refusal = profile
            .find("(deny file-test-existence")
            .expect("the home refuses the existence test");
        assert!(
            rule_at < first_refusal,
            "a refusal below must win: {profile}"
        );
        assert!(
            !profile.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                redirected.display()
            )),
            "no data travels with the stream: {profile}"
        );
        assert!(!render_profile(&config).expect("renders").contains(&rule));
    }

    /// **A pipe behind a stream renders nothing, because Seatbelt never path-checks one.**
    #[test]
    fn a_pipe_behind_a_stream_renders_no_rule() {
        let (_temp, _base, config) = stream_fixture();
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: `ends` holds the two descriptors `pipe` writes.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let streams = InheritedStreams::of_descriptors(&ends);
        for end in ends {
            // SAFETY: closing this test's own descriptors.
            unsafe { libc::close(end) };
        }
        assert!(streams.paths().is_empty());
        assert_eq!(
            render_profile_with_streams(&config, &streams).expect("renders"),
            render_profile(&config).expect("renders")
        );
    }

    /// **A stream path the profile cannot spell is refused rather than rendered.**
    #[test]
    fn a_stream_path_the_profile_cannot_spell_is_refused() {
        use std::os::fd::AsRawFd as _;
        let (_temp, base, config) = stream_fixture();
        let redirected = base.join("agent\n(allow default).out");
        let file = std::fs::File::create(&redirected).expect("redirect target");
        let streams = InheritedStreams::of_descriptors(&[file.as_raw_fd()]);
        assert_eq!(streams.paths(), [redirected]);
        assert!(matches!(
            render_profile_with_streams(&config, &streams),
            Err(ContainmentError::ApplyFailed { .. })
        ));
    }

    /// The `(allow <operation>` names of a profile, sorted, over the comment-free view.
    fn granted_operations(profile: &str) -> Vec<String> {
        let mut operations: Vec<String> = profile
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with(';'))
            .filter_map(|line| line.strip_prefix("(allow "))
            .map(|rest| {
                rest.split([' ', '(', ')'])
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .filter(|operation| !operation.is_empty())
            .collect();
        operations.sort();
        operations
    }

    /// **A stream adds one `file-read-metadata` to the census and nothing else.**
    #[test]
    fn a_stream_adds_one_metadata_operation_and_nothing_else() {
        use std::os::fd::AsRawFd as _;
        let (_temp, base, config) = stream_fixture();
        let file = std::fs::File::create(base.join("agent.out")).expect("redirect target");
        let streams = InheritedStreams::of_descriptors(&[file.as_raw_fd()]);
        let mut expected = granted_operations(&render_profile(&config).expect("renders"));
        expected.push("file-read-metadata".to_string());
        expected.sort();
        assert_eq!(
            granted_operations(&render_profile_with_streams(&config, &streams).expect("renders")),
            expected
        );
    }

    /// **A stream inside a credential store renders no rule, because the floor judges it as it
    /// judges a grant.**
    #[test]
    fn a_stream_inside_a_credential_store_renders_no_rule() {
        use std::os::fd::AsRawFd as _;
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable");
        let redirected = store.join("agent.out");
        let file = std::fs::File::create(&redirected).expect("redirect target");
        let streams = InheritedStreams::of_descriptors(&[file.as_raw_fd()]);
        assert_eq!(streams.paths(), std::slice::from_ref(&redirected));
        let profile = render_profile_with_streams(&config, &streams).expect("renders");
        assert_eq!(profile, render_profile(&config).expect("renders"));
        assert!(!profile.contains(&format!("(literal \"{}\")", redirected.display())));
    }

    #[test]
    fn a_credential_exception_restores_existence_only_after_the_store_deny() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("an exact credential-store grant");
        let profile = render_profile(&config).expect("the exception renders");
        let escaped_store =
            escaped(&store.canonicalize().expect("the store resolves")).expect("the path escapes");
        let deny = format!("(deny file-test-existence (subpath \"{escaped_store}\"))");
        let allow = format!("(allow file-test-existence (subpath \"{escaped_store}\"))");

        assert!(
            profile.rfind(&allow).expect("the exception allow renders")
                > profile.rfind(&deny).expect("the credential deny renders"),
            "Seatbelt is last-match-wins, so the exact exception must follow the store deny"
        );
    }

    /// **An announced credential store keeps its metadata under discovery.** Discovery adds a
    /// metadata deny on every store; an explicitly granted store re-allows both existence and
    /// metadata after that deny, so a leaf the operator let read the named credentials can still
    /// `stat` and `open` them rather than losing metadata to last-match.
    #[test]
    fn a_granted_credential_store_keeps_metadata_under_discovery() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("an exact credential-store grant")
            .allow_discovery(&home_path);
        let profile = render_profile(&config).expect("the discovery profile renders");
        let escaped_store = escaped(&store).expect("the path escapes");
        let meta_deny = format!("(deny file-read-metadata (subpath \"{escaped_store}\"))");
        let meta_allow = format!("(allow file-read-metadata (subpath \"{escaped_store}\"))");

        assert!(
            profile.contains(&meta_deny),
            "discovery denies store metadata: {profile}"
        );
        assert!(
            profile
                .rfind(&meta_allow)
                .expect("the store metadata re-allow renders")
                > profile
                    .rfind(&meta_deny)
                    .expect("the store metadata deny renders"),
            "the announced store's metadata re-allow must follow the discovery metadata deny"
        );
    }

    /// **The operator home keeps its existence-deny and receives no broad metadata allow.**
    #[test]
    fn the_home_keeps_its_existence_deny_and_grants_no_broad_metadata() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root");
        let profile = render_profile(&config).expect("the agent profile renders");
        let escaped_home = escaped(&home_path).expect("the home escapes");
        assert!(
            profile.contains(&format!(
                "(deny file-test-existence (subpath \"{escaped_home}\"))"
            )),
            "the agent box keeps its home existence-deny: {profile}"
        );
        assert!(
            !profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{escaped_home}\"))"
            )),
            "the agent box grants no broad home metadata: {profile}"
        );
    }

    /// **An exec literal renders its out-of-cache dylibs as read-file cells**: `file-read*` on each
    /// image's identity, nothing for a shared-cache image, and no `process-exec` on any image.
    #[test]
    fn an_exec_literal_renders_its_out_of_cache_dylibs_as_read_files() {
        use crate::backend::macos::macho::tests::{planted_image, synthetic_macho};
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(
                &[
                    ("/usr/lib/libSystem.B.dylib", false),
                    ("@rpath/libapp.dylib", false),
                ],
                &["@loader_path/../lib"],
            ),
        );
        let libapp = planted_image(&root, "lib/libapp.dylib", &synthetic_macho(&[], &[]));
        let config = ContainmentConfig::new()
            .set_network(Network::Localhost {
                connect: vec![41080],
                listen: Vec::new(),
            })
            .expect("localhost")
            .allow(&app, Operation::Exec, Scope::File)
            .expect("exec grant");

        let profile = render_profile(&config).expect("the profile renders");

        let library_rule = format!("(allow file-read* (literal \"{}\"))", libapp.display());
        assert!(profile.contains(&library_rule), "{profile}");
        assert!(
            !profile.contains("libSystem.B.dylib"),
            "a shared-cache image renders nothing: {profile}"
        );
        assert_eq!(
            profile.matches("(allow process-exec ").count(),
            1,
            "an image is read, never exec'd: {profile}"
        );
    }

    /// **An exec literal whose image the floor refuses fails the render**, so a forbidden image
    /// never becomes a read rule.
    #[test]
    fn an_exec_literal_whose_image_the_floor_refuses_fails_the_render() {
        use crate::backend::macos::macho::tests::{planted_image, synthetic_macho};
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path().canonicalize().expect("canonical");
        planted_image(&home, ".aws/libapp.dylib", &synthetic_macho(&[], &[]));
        let app = planted_image(
            &home,
            "bin/app",
            &synthetic_macho(&[("@rpath/libapp.dylib", false)], &["@loader_path/../.aws"]),
        );
        let config = ContainmentConfig::new()
            .set_network(Network::Localhost {
                connect: vec![41080],
                listen: Vec::new(),
            })
            .expect("localhost")
            .allow(&app, Operation::Exec, Scope::File)
            .expect("exec grant")
            .anchored_at(&home);

        let error = render_profile(&config).expect_err("a credential store is never a library");

        let text = error.to_string();
        assert!(
            text.contains("floor refuses") && text.contains("libapp.dylib"),
            "the refusal names the library and the floor: {text}"
        );
    }

    /// **An image requested through a linked directory renders metadata on the link**, beside
    /// `file-read*` on its identity and metadata on the requested spelling, and no `file-read*` on
    /// the directory.
    #[test]
    fn an_image_requested_through_a_linked_directory_renders_metadata_on_the_link() {
        use crate::backend::macos::macho::tests::{planted_image, synthetic_macho};
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let libapp = planted_image(&root, "lib/libapp.dylib", &synthetic_macho(&[], &[]));
        std::os::unix::fs::symlink(root.join("lib"), root.join("opt")).expect("a linked directory");
        let requested = root.join("opt/libapp.dylib");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(&[(requested.to_str().expect("utf-8"), false)], &[]),
        );
        let config = ContainmentConfig::new()
            .set_network(Network::Localhost {
                connect: vec![41080],
                listen: Vec::new(),
            })
            .expect("localhost")
            .allow(&app, Operation::Exec, Scope::File)
            .expect("exec grant");

        let profile = render_profile(&config).expect("the profile renders");

        for rule in [
            format!("(allow file-read* (literal \"{}\"))", libapp.display()),
            format!(
                "(allow file-read-metadata (literal \"{}\"))",
                requested.display()
            ),
            format!(
                "(allow file-read-metadata (literal \"{}\"))",
                root.join("opt").display()
            ),
        ] {
            assert!(profile.contains(&rule), "{rule} is missing: {profile}");
        }
        assert!(
            !profile.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                root.join("opt").display()
            )),
            "the linked directory gets metadata, never its contents: {profile}"
        );
    }

    /// **The agent (non-broad) profile carries no `process-exec*`, enumerates one `process-exec` rule
    /// per exec grant, and keeps write-xor-execute.** A leaf may render broad exec
    /// (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds); this
    /// pins that the agent never does.
    #[test]
    fn the_agent_profile_never_carries_broad_exec() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let agent = home_path.join("agent");
        std::fs::write(&agent, "agent").expect("the first program");
        let shell = home_path.join("shell");
        std::fs::write(&shell, "shell").expect("the second program");
        let toolchain = home_path.join("toolchain");
        std::fs::create_dir(&toolchain).expect("an executable tree");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&agent, Operation::Exec, Scope::File)
            .expect("the first executable")
            .allow(&shell, Operation::Exec, Scope::File)
            .expect("the second executable")
            .allow(&toolchain, Operation::Exec, Scope::Root)
            .expect("the executable tree")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root");
        let profile = render_profile(&config).expect("three exec grants render");

        assert!(
            !profile.contains("process-exec*"),
            "the agent (non-broad) profile carries no broad exec: {profile}"
        );
        assert_eq!(
            profile.matches("(allow process-exec ").count(),
            3,
            "one process-exec rule per exec grant: {profile}"
        );
        for program in [&agent, &shell] {
            let escaped_program = escaped(program).expect("the program escapes");
            assert!(
                profile.contains(&format!(
                    "(allow process-exec (literal \"{escaped_program}\"))"
                )),
                "each exec file renders its own literal: {profile}"
            );
        }
        let escaped_toolchain = escaped(&toolchain).expect("the tree escapes");
        assert!(
            profile.contains(&format!(
                "(allow process-exec (subpath \"{escaped_toolchain}\"))"
            )),
            "the exec tree renders one subpath: {profile}"
        );
        let escaped_state = escaped(&state).expect("the write root escapes");
        assert!(
            profile.contains(&format!(
                "(deny file-map-executable (subpath \"{escaped_state}\"))"
            )),
            "the agent keeps write-xor-execute on its write root: {profile}"
        );
        assert!(
            !profile.contains("(allow file-map-executable"),
            "the agent emits no executable-mapping allow that could lift W^X: {profile}"
        );
    }

    /// **A leaf carries broad exec and the main (agent) box does not.** The same config, rendered with
    /// `allow_broad_exec`, adds `(allow process-exec*)`; without it, the agent keeps its enumerated
    /// literal. Broad exec is additive — the enumerated literal is present in both.
    #[test]
    fn a_leaf_carries_broad_exec_and_the_main_box_does_not() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let base = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root");
        let escaped_program = escaped(&program).expect("the program escapes");
        let literal = format!("(allow process-exec (literal \"{escaped_program}\"))");

        let agent = render_profile(&base.clone()).expect("the agent profile renders");
        assert!(
            agent.contains(&literal),
            "the agent enumerates exec: {agent}"
        );
        assert!(
            !agent.contains("(allow process-exec*)"),
            "the agent renders no broad exec: {agent}"
        );

        let leaf = render_profile(&base.allow_broad_exec()).expect("the leaf profile renders");
        assert!(
            leaf.contains("(allow process-exec*)"),
            "the leaf overlay adds broad exec: {leaf}"
        );
        assert!(
            leaf.contains(&literal),
            "the leaf keeps the enumerated literal (broad exec is additive): {leaf}"
        );
    }

    /// **The map-exec allow is additive and wins by last-match.** The write cell's
    /// `file-map-executable` deny still renders; the leaf overlay adds an allow AFTER it, so a build
    /// loads what it compiles. The agent carries the deny and no allow (write-xor-execute).
    #[test]
    fn broad_exec_adds_a_map_exec_allow_overriding_the_write_cell_deny() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let workspace = home_path.join("workspace");
        std::fs::create_dir(&workspace).expect("a writable workspace");
        let base = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("a write root");
        let escaped_workspace = escaped(&workspace).expect("the workspace escapes");
        let map_exec_deny = format!("(deny file-map-executable (subpath \"{escaped_workspace}\"))");
        let map_exec_allow =
            format!("(allow file-map-executable (subpath \"{escaped_workspace}\"))");

        let agent = render_profile(&base.clone()).expect("the agent profile renders");
        assert!(
            agent.contains(&map_exec_deny),
            "the agent keeps the write-cell map-exec deny: {agent}"
        );
        assert!(
            !agent.contains(&map_exec_allow),
            "the agent renders no map-exec allow: {agent}"
        );

        let leaf = render_profile(&base.allow_broad_exec()).expect("the leaf profile renders");
        assert!(
            leaf.rfind(&map_exec_allow)
                .expect("the leaf overlay allow renders")
                > leaf
                    .rfind(&map_exec_deny)
                    .expect("the write-cell deny still renders"),
            "the leaf's map-exec allow must follow the write-cell deny so it wins: {leaf}"
        );
    }

    /// **Broad exec maps executable only over writable grants.** One allow per write grant, a
    /// `subpath` for a root and a `literal` for a file, and none over a read root or the program.
    #[test]
    fn broad_exec_map_exec_allow_names_only_write_grants() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let workspace = home_path.join("workspace");
        std::fs::create_dir(&workspace).expect("a writable workspace");
        let log = home_path.join("tool.log");
        std::fs::write(&log, "").expect("a writable file");
        let sources = home_path.join("sources");
        std::fs::create_dir(&sources).expect("a read root");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow(&log, Operation::Write, Scope::File)
            .expect("a write file")
            .allow(&sources, Operation::Read, Scope::Root)
            .expect("a read root")
            .allow_broad_exec();
        let profile = render_profile(&config).expect("the leaf profile renders");

        let allows: Vec<&str> = profile
            .lines()
            .filter(|line| line.starts_with("(allow file-map-executable"))
            .collect();
        let expected = [
            format!(
                "(allow file-map-executable (subpath \"{}\"))",
                escaped(&workspace).expect("the workspace escapes")
            ),
            format!(
                "(allow file-map-executable (literal \"{}\"))",
                escaped(&log).expect("the file escapes")
            ),
        ];
        assert_eq!(
            allows.len(),
            expected.len(),
            "one map-exec allow per write grant and no other: {profile}"
        );
        for rule in &expected {
            assert!(allows.contains(&rule.as_str()), "{rule} renders: {profile}");
        }
    }

    /// **A refused tree inside a leaf's write root stays unexecutable.** The refusal's exec and
    /// map-exec denies render after the broad-exec overlay, so the overlay cannot re-open them.
    #[test]
    fn broad_exec_refused_tree_inside_a_write_root_stays_unexecutable() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let workspace = home_path.join("workspace");
        let refused = workspace.join("secret");
        std::fs::create_dir_all(&refused).expect("a refused tree inside the write root");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("a write root")
            .refuse(&refused, Scope::Root)
            .expect("the refusal")
            .allow_broad_exec();
        let profile = render_profile(&config).expect("the leaf profile renders");

        let escaped_workspace = escaped(&workspace).expect("the workspace escapes");
        let escaped_refused = escaped(&refused).expect("the refusal escapes");
        let exec_deny = format!("(deny process-exec (subpath \"{escaped_refused}\"))");
        let map_exec_deny = format!("(deny file-map-executable (subpath \"{escaped_refused}\"))");
        let map_exec_allow =
            format!("(allow file-map-executable (subpath \"{escaped_workspace}\"))");
        assert!(
            profile
                .rfind(&exec_deny)
                .expect("the refusal's exec deny renders")
                > profile
                    .find("(allow process-exec*)")
                    .expect("the broad exec allow renders"),
            "the refusal's exec deny must follow broad exec: {profile}"
        );
        assert!(
            profile
                .rfind(&map_exec_deny)
                .expect("the refusal's map-exec deny renders")
                > profile
                    .rfind(&map_exec_allow)
                    .expect("the write root's map-exec allow renders"),
            "the refusal's map-exec deny must follow the overlay allow: {profile}"
        );
    }

    /// **A write root inside a read root renders the read subpath on the outer root and the write
    /// leaves on the inner one.**
    #[test]
    fn a_write_root_inside_a_read_root_renders_both_roots() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let agent = home_path.join("agent");
        std::fs::write(&agent, "agent").expect("an executable fixture");
        let project = home_path.join("project");
        let output = project.join("build");
        std::fs::create_dir_all(&output).expect("a read tree with a writable corner");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&agent, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&project, Operation::Read, Scope::Root)
            .expect("the read root")
            .allow(&output, Operation::Write, Scope::Root)
            .expect("a write root inside the read root");
        let profile = render_profile(&config).expect("the pair renders");

        let escaped_project = escaped(&project).expect("the read root escapes");
        assert!(
            profile.contains(&format!(
                "(allow file-read* (subpath \"{escaped_project}\"))"
            )),
            "the outer root stays readable: {profile}"
        );
        let escaped_output = escaped(&output).expect("the write root escapes");
        for leaf in WRITE_ROOT_LEAVES {
            assert!(
                profile.contains(&format!("(allow {leaf} (subpath \"{escaped_output}\"))")),
                "the inner root names every write leaf: {profile}"
            );
        }
    }

    #[test]
    fn a_discovery_root_opens_home_existence_and_metadata_but_a_credential_store_stays_refused() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow_discovery(&home_path);
        let profile = render_profile(&config).expect("the discovery profile renders");

        let escaped_home = escaped(&home_path).expect("the home escapes");
        let escaped_store = escaped(&store).expect("the store escapes");
        let home_exist_allow = format!("(allow file-test-existence (subpath \"{escaped_home}\"))");
        let home_meta_allow = format!("(allow file-read-metadata (subpath \"{escaped_home}\"))");
        let store_exist_deny = format!("(deny file-test-existence (subpath \"{escaped_store}\"))");
        let store_meta_deny = format!("(deny file-read-metadata (subpath \"{escaped_store}\"))");

        assert!(
            profile.contains(&home_exist_allow),
            "discovery allows home existence: {profile}"
        );
        assert!(
            profile.contains(&home_meta_allow),
            "discovery allows home metadata: {profile}"
        );
        assert!(
            !profile.contains(&format!(
                "(deny file-test-existence (subpath \"{escaped_home}\"))"
            )),
            "the home existence-deny is suppressed under discovery: {profile}"
        );
        // The credential store stays refused for BOTH existence and metadata, and each deny renders
        // AFTER the home allow so Seatbelt's last-match rule keeps the store opaque.
        assert!(
            profile.contains(&store_exist_deny),
            "the store existence stays denied: {profile}"
        );
        assert!(
            profile.contains(&store_meta_deny),
            "the store metadata stays denied: {profile}"
        );
        assert!(
            profile
                .rfind(&store_exist_deny)
                .expect("store existence deny")
                > profile
                    .rfind(&home_exist_allow)
                    .expect("home existence allow"),
            "the store existence deny must follow the home existence allow"
        );
        assert!(
            profile
                .rfind(&store_meta_deny)
                .expect("store metadata deny")
                > profile
                    .rfind(&home_meta_allow)
                    .expect("home metadata allow"),
            "the store metadata deny must follow the home metadata allow"
        );
    }

    /// Under discovery the box's own `.strands-box` state tree is excluded (existence+metadata
    /// denied), but a path a grant already names beneath it — the CA trust bundle, the box home —
    /// keeps existence AND metadata, while an ungranted sibling-box path stays refused.
    #[test]
    fn discovery_excludes_the_box_state_tree_but_a_granted_path_beneath_it_survives() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let boxes = home_path.join(".strands-box/b");
        let trust = boxes.join("codex/trust");
        std::fs::create_dir_all(&trust).expect("the box trust dir");
        let cert = trust.join("cert.pem");
        std::fs::write(&cert, "cert").expect("a CA bundle fixture");
        std::fs::create_dir_all(boxes.join("other/private")).expect("a sibling box");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow(&cert, Operation::Read, Scope::File)
            .expect("the CA bundle read")
            .allow_discovery(&home_path)
            .deny_discovery(&boxes);
        let profile = render_profile(&config).expect("the discovery profile renders");

        let escaped_home = escaped(&home_path).expect("home escapes");
        let escaped_boxes = escaped(&boxes).expect("boxes escapes");
        let escaped_cert = escaped(&cert).expect("cert escapes");
        let home_meta_allow = format!("(allow file-read-metadata (subpath \"{escaped_home}\"))");
        let boxes_exist_deny = format!("(deny file-test-existence (subpath \"{escaped_boxes}\"))");
        let boxes_meta_deny = format!("(deny file-read-metadata (subpath \"{escaped_boxes}\"))");
        let cert_exist_allow = format!("(allow file-test-existence (subpath \"{escaped_cert}\"))");
        let cert_meta_allow = format!("(allow file-read-metadata (subpath \"{escaped_cert}\"))");

        // The box-state tree is denied existence AND metadata, each rendered AFTER the home allow.
        assert!(
            profile.contains(&boxes_exist_deny),
            "box-state existence denied: {profile}"
        );
        assert!(
            profile.contains(&boxes_meta_deny),
            "box-state metadata denied: {profile}"
        );
        assert!(
            profile
                .rfind(&boxes_meta_deny)
                .expect("box-state metadata deny")
                > profile
                    .rfind(&home_meta_allow)
                    .expect("home metadata allow"),
            "the box-state deny must follow the home allow so it wins"
        );
        // The granted CA bundle beneath the denied tree keeps existence AND metadata, each rendered
        // AFTER the box-state deny — the leaf's own trust read is not clobbered.
        assert!(
            profile.contains(&cert_exist_allow),
            "granted cert existence survives: {profile}"
        );
        assert!(
            profile.contains(&cert_meta_allow),
            "granted cert metadata survives: {profile}"
        );
        assert!(
            profile
                .rfind(&cert_meta_allow)
                .expect("cert metadata allow")
                > profile
                    .rfind(&boxes_meta_deny)
                    .expect("box-state metadata deny"),
            "the granted cert's metadata allow must follow the box-state deny (trust survives)"
        );
        // An ungranted sibling-box path gets no allow of its own, so the box-state deny keeps it
        // refused — a leaf cannot stat sibling-box state.
        let sibling = escaped(&boxes.join("other/private")).expect("sibling escapes");
        assert!(
            !profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{sibling}\"))"
            )) && !profile.contains(&format!(
                "(allow file-test-existence (subpath \"{sibling}\"))"
            )),
            "an ungranted sibling-box path gets no discovery allow: {profile}"
        );
        // The data-volume twin of the box-state tree is denied too, because the home allow opened
        // both spellings — a plain-only deny would leave the twin answering.
        let twin = std::path::Path::new("/System/Volumes/Data").join(
            boxes
                .strip_prefix("/")
                .expect("an absolute boxes namespace"),
        );
        let escaped_twin = escaped(&twin).expect("the twin escapes");
        assert!(
            profile.contains(&format!(
                "(deny file-read-metadata (subpath \"{escaped_twin}\"))"
            )) && profile.contains(&format!(
                "(deny file-test-existence (subpath \"{escaped_twin}\"))"
            )),
            "the box-state data-volume twin is denied too: {profile}"
        );
    }

    #[test]
    fn without_a_discovery_root_the_home_existence_deny_survives() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root");
        let profile = render_profile(&config).expect("the agent profile renders");
        let escaped_home = escaped(&home_path).expect("the home escapes");
        assert!(
            profile.contains(&format!(
                "(deny file-test-existence (subpath \"{escaped_home}\"))"
            )),
            "the agent box keeps its home existence-deny: {profile}"
        );
        assert!(
            !profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{escaped_home}\"))"
            )),
            "the agent box grants no broad home metadata: {profile}"
        );
    }

    #[test]
    fn a_child_discovery_root_does_not_open_the_whole_home() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let child = home_path.join("public");
        std::fs::create_dir(&child).expect("a child directory");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow_discovery(&child);
        let profile = render_profile(&config).expect("the discovery profile renders");
        let escaped_child = escaped(&child).expect("the child escapes");
        let escaped_home = escaped(&home_path).expect("the home escapes");
        assert!(
            profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{escaped_child}\"))"
            )),
            "the requested child root is opened for discovery: {profile}"
        );
        assert!(
            !profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{escaped_home}\"))"
            )),
            "a child discovery root must NOT open the whole operator home: {profile}"
        );
        assert!(
            profile.contains(&format!(
                "(deny file-test-existence (subpath \"{escaped_home}\"))"
            )),
            "the home keeps its existence-deny when only a child is discovered: {profile}"
        );
    }

    #[test]
    fn discovery_opens_the_data_volume_spelling_of_the_home() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let state = home_path.join("state");
        std::fs::create_dir(&state).expect("a writable state directory");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow_discovery(&home_path);
        let profile = render_profile(&config).expect("the discovery profile renders");
        let twin = std::path::Path::new("/System/Volumes/Data")
            .join(home_path.strip_prefix("/").expect("an absolute home"));
        let escaped_twin = escaped(&twin).expect("the twin escapes");
        assert!(
            profile.contains(&format!(
                "(allow file-read-metadata (subpath \"{escaped_twin}\"))"
            )),
            "discovery opens the /System/Volumes/Data spelling of the home too: {profile}"
        );
    }

    /// **Discovery keeps a credential store's metadata denied on the data-volume spelling too.**
    #[test]
    fn discovery_denies_credential_store_metadata_on_the_data_volume_twin() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .allow_discovery(&home_path);
        let profile = render_profile(&config).expect("the discovery profile renders");

        let twin = std::path::Path::new("/System/Volumes/Data")
            .join(home_path.strip_prefix("/").expect("an absolute home"));
        let escaped_twin = escaped(&twin).expect("the twin escapes");
        let escaped_store = escaped(&twin.join(".aws")).expect("the twin store escapes");
        let home_allow = format!("(allow file-read-metadata (subpath \"{escaped_twin}\"))");
        let store_deny = format!("(deny file-read-metadata (subpath \"{escaped_store}\"))");
        assert!(
            profile
                .rfind(&store_deny)
                .expect("the twin store deny renders")
                > profile
                    .rfind(&home_allow)
                    .expect("the twin home allow renders"),
            "the twin store deny must follow the twin home allow: {profile}"
        );
    }

    /// **A refused tree stays opaque under discovery.** Its existence and metadata denies render
    /// after the discovery allows over the home, so discovery cannot re-open them.
    #[test]
    fn a_refused_tree_stays_opaque_under_discovery() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let program = home_path.join("agent");
        std::fs::write(&program, "agent").expect("an executable fixture");
        let refused = home_path.join("private-notes");
        std::fs::create_dir(&refused).expect("a refused tree");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .anchored_at(&home_path)
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an executable")
            .refuse(&refused, Scope::Root)
            .expect("the refusal")
            .allow_discovery(&home_path);
        let profile = render_profile(&config).expect("the discovery profile renders");

        let escaped_home = escaped(&home_path).expect("the home escapes");
        let escaped_refused = escaped(&refused).expect("the refusal escapes");
        for operation in ["file-test-existence", "file-read-metadata"] {
            let allow = format!("(allow {operation} (subpath \"{escaped_home}\"))");
            let deny = format!("(deny {operation} (subpath \"{escaped_refused}\"))");
            assert!(
                profile.rfind(&deny).expect("the refusal deny renders")
                    > profile.rfind(&allow).expect("the discovery allow renders"),
                "the refused {operation} deny must follow the discovery allow: {profile}"
            );
        }
    }

    #[test]
    fn a_write_protection_subtracts_write_and_hard_link_after_the_write_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let root = base.join("state");
        std::fs::create_dir(&root).expect("write root fixture");
        let authority_directory = root.join(".strands-box/nested");
        std::fs::create_dir_all(&authority_directory).expect("authority directory");
        let authority = authority_directory.join("authority");
        std::fs::write(&authority, "authority").expect("authority fixture");
        let opened = std::fs::File::open(&authority).expect("open authority");

        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("write root")
            .protect_write(&authority, &opened)
            .expect("write protection");
        let profile = render_profile(&config).expect("profile");

        // The timestamps are the write-root cell's LAST leaf allow, so the protection deny following
        // it follows every one of them.
        let write_root = format!("(allow file-write-times (subpath \"{}\"))", root.display());
        let deny_write = format!("(deny file-write* (literal \"{}\"))", authority.display());
        let deny_link = format!("(deny file-link (literal \"{}\"))", authority.display());
        let parent_unlink = format!(
            "(deny file-write-unlink (literal \"{}\"))",
            authority_directory.display()
        );
        let parent_create = format!(
            "(deny file-write-create (literal \"{}\"))",
            authority_directory.display()
        );
        let container = root.join(".strands-box");
        let container_unlink = format!(
            "(deny file-write-unlink (literal \"{}\"))",
            container.display()
        );
        assert!(
            profile.find(&write_root).expect("write-root allow")
                < profile.find(&deny_write).expect("exact write deny"),
            "last-match-wins requires the exact protection after the writable root"
        );
        assert!(profile.contains(&deny_link), "{profile}");
        assert!(profile.contains(&parent_unlink), "{profile}");
        assert!(profile.contains(&parent_create), "{profile}");
        assert!(profile.contains(&container_unlink), "{profile}");
    }

    /// The identity pair rendered on one directory's literal, as the write-root cell and the
    /// ancestor block spell it.
    fn identity_pair(path: &std::path::Path) -> [String; 2] {
        [
            format!("(deny file-write-unlink (literal \"{}\"))", path.display()),
            format!("(deny file-write-create (literal \"{}\"))", path.display()),
        ]
    }

    /// How many times `profile` fixes `path`'s own directory entry, asserting both denies agree.
    fn identity_pairs_on(profile: &str, path: &std::path::Path) -> usize {
        let [unlink, create] = identity_pair(path);
        let count = profile.matches(&unlink).count();
        assert_eq!(
            count,
            profile.matches(&create).count(),
            "the unlink and create denies on {} must render as one pair: {profile}",
            path.display()
        );
        count
    }

    /// An executable, a write root holding a nested directory refusal and a nested file refusal,
    /// and a sibling directory with nothing refused inside.
    fn refusal_fixture() -> (tempfile::TempDir, std::path::PathBuf, ContainmentConfig) {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let root = base.join("state");
        let sibling_box = root.join("sub/deep/.strands-box");
        std::fs::create_dir_all(&sibling_box).expect("a sibling box's authority directory");
        std::fs::write(sibling_box.join("policy.dw"), "policy").expect("the sibling policy");
        let secret = root.join("files/nested/secret.txt");
        std::fs::create_dir_all(secret.parent().expect("parent")).expect("the file's directory");
        std::fs::write(&secret, "secret").expect("the refused file");
        std::fs::create_dir(root.join("plain")).expect("a directory with nothing refused");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&root, Operation::Read, Scope::Root)
            .expect("read root")
            .allow(&root, Operation::Write, Scope::Root)
            .expect("write root")
            .refuse(&sibling_box, Scope::Root)
            .expect("the directory refusal")
            .refuse(&secret, Scope::File)
            .expect("the file refusal");
        (temp, root, config)
    }

    /// **A refusal strictly inside a write root fixes every directory between the two**, with the
    /// same literal pair the root carries on itself, after the root's last leaf allow, and touches
    /// neither the root, nor anything above it, nor the refused path, nor a sibling directory.
    #[test]
    fn a_refusal_inside_a_write_root_fixes_its_ancestors() {
        let (_temp, root, config) = refusal_fixture();
        let profile = render_profile(&config).expect("profile");

        let last_leaf_allow = format!("(allow file-write-times (subpath \"{}\"))", root.display());
        let last_leaf_at = profile
            .find(&last_leaf_allow)
            .expect("the write root renders");
        for ancestor in [
            root.join("sub"),
            root.join("sub/deep"),
            root.join("files"),
            root.join("files/nested"),
        ] {
            assert_eq!(
                identity_pairs_on(&profile, &ancestor),
                1,
                "{} is fixed exactly once: {profile}",
                ancestor.display()
            );
            for rule in identity_pair(&ancestor) {
                assert!(
                    profile.find(&rule).expect("the pair renders") > last_leaf_at,
                    "last-match-wins requires the pair after the root's leaf allows: {profile}"
                );
            }
            // The directory entry is fixed and its contents are not.
            for frozen in [
                format!("(deny file-write* (literal \"{}\"))", ancestor.display()),
                format!(
                    "(deny file-write-data (literal \"{}\"))",
                    ancestor.display()
                ),
                format!(
                    "(deny file-write-unlink (subpath \"{}\"))",
                    ancestor.display()
                ),
                format!(
                    "(deny file-write-create (subpath \"{}\"))",
                    ancestor.display()
                ),
            ] {
                assert!(
                    !profile.contains(&frozen),
                    "an ancestor keeps its permitted contents writable: {frozen}\n{profile}"
                );
            }
        }
        assert_eq!(
            identity_pairs_on(&profile, &root),
            1,
            "the root carries its own pair and gains no second: {profile}"
        );
        let base = root.parent().expect("the fixture base");
        assert_eq!(
            identity_pairs_on(&profile, base),
            0,
            "no rule renders above a grant root: {profile}"
        );
        assert_eq!(
            identity_pairs_on(&profile, &root.join("plain")),
            0,
            "a directory with nothing refused inside is not fixed: {profile}"
        );
        // The refused tree renders its own `subpath` denies and no ancestor-style literal pair; the
        // refused file renders one literal pair, from the refusal's own leaf denies.
        assert_eq!(
            identity_pairs_on(&profile, &root.join("sub/deep/.strands-box")),
            0,
            "the refused tree is denied over its subpath, never fixed as an ancestor: {profile}"
        );
        assert!(profile.contains(&format!(
            "(deny file-write-unlink (subpath \"{}\"))",
            root.join("sub/deep/.strands-box").display()
        )));
        assert_eq!(
            identity_pairs_on(&profile, &root.join("files/nested/secret.txt")),
            1,
            "the refused file carries its refusal's leaf denies and no ancestor pair: {profile}"
        );
    }

    /// **A refusal directly under a write root adds no rule**, because its parent is the root, and
    /// **a refusal outside every write root adds none**, because no write cell reaches its parent.
    #[test]
    fn a_refusal_at_the_root_or_outside_every_write_root_fixes_nothing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let state = base.join("state");
        let own = state.join(".strands-box");
        std::fs::create_dir_all(&own).expect("the box's own authority under the root");
        let project = base.join("project");
        let read_only_refused = project.join("sub/deep/.strands-box");
        std::fs::create_dir_all(&read_only_refused).expect("a refusal under a read root");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("write root")
            .allow(&project, Operation::Read, Scope::Root)
            .expect("read root")
            .refuse(&own, Scope::Root)
            .expect("a refusal directly under the write root")
            .refuse(&read_only_refused, Scope::Root)
            .expect("a refusal outside every write root");
        let profile = render_profile(&config).expect("profile");

        assert_eq!(
            profile.matches("(deny file-write-unlink (literal ").count(),
            1,
            "the write root's own pair is the only literal identity deny: {profile}"
        );
        assert_eq!(identity_pairs_on(&profile, &state), 1, "{profile}");
        for untouched in [
            project.clone(),
            project.join("sub"),
            project.join("sub/deep"),
            base.clone(),
        ] {
            assert_eq!(
                identity_pairs_on(&profile, &untouched),
                0,
                "{} gains no rule: {profile}",
                untouched.display()
            );
        }
    }

    /// **Shared ancestors render one pair**, whether two refusals share them, a refusal and a write
    /// protection share them, or a second write root sits beside the first.
    #[test]
    fn shared_ancestors_of_refusals_and_protections_render_one_pair() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let alpha = base.join("alpha");
        let first = alpha.join("shared/one/.strands-box");
        let second = alpha.join("shared/two/.strands-box");
        std::fs::create_dir_all(&first).expect("the first sibling box");
        std::fs::create_dir_all(&second).expect("the second sibling box");
        let authority = first.join("policy.dw");
        std::fs::write(&authority, "authority").expect("the loaded authority");
        let opened = std::fs::File::open(&authority).expect("open authority");
        let beta = base.join("beta");
        let third = beta.join("x/.strands-box");
        std::fs::create_dir_all(&third).expect("a sibling box under the second root");
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&alpha, Operation::Read, Scope::Root)
            .expect("the first root, readable")
            .allow(&alpha, Operation::Write, Scope::Root)
            .expect("the first root, writable")
            .allow(&beta, Operation::Write, Scope::Root)
            .expect("the second root")
            .refuse(&first, Scope::Root)
            .expect("first refusal")
            .refuse(&second, Scope::Root)
            .expect("second refusal")
            .refuse(&third, Scope::Root)
            .expect("third refusal")
            .protect_write(&authority, &opened)
            .expect("a protection sharing the first refusal's ancestors");
        let profile = render_profile(&config).expect("profile");

        for (fixed, expected) in [
            (alpha.join("shared"), 1),
            (alpha.join("shared/one"), 1),
            (alpha.join("shared/two"), 1),
            (beta.join("x"), 1),
            (alpha.clone(), 1),
            (beta.clone(), 1),
            (base.clone(), 0),
        ] {
            assert_eq!(
                identity_pairs_on(&profile, &fixed),
                expected,
                "{} renders {expected} pair(s): {profile}",
                fixed.display()
            );
        }
        // The refused tree is also the protection's parent, so that walk fixes it once as a literal
        // beside the refusal's own `subpath` denies.
        assert_eq!(
            profile
                .matches(&format!(
                    "(deny file-write-create (literal \"{}\"))",
                    first.display()
                ))
                .count(),
            1,
            "the refused tree holding the protection is fixed once, as the protection's parent: \
             {profile}"
        );
    }

    /// **Two nested write roots: the floor refuses the pair, and the renderer alone still bounds
    /// and orders the fixed directories.** `ContainmentConfig::allow` appends, so the renderer can
    /// see the pair; `floors::require_all` is what refuses it before any apply. A refusal under the
    /// inner root fixes the directory between them once, and the inner root itself, which is an
    /// ancestor for the outer root, renders its identity pair again after the outer root's leaf
    /// allows, so its identity holds whatever order the grants were stated in.
    #[test]
    fn nested_write_roots_are_refused_by_the_floor_and_bounded_by_the_renderer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let outer = base.join("outer");
        let inner = outer.join("inner");
        let refused = inner.join("sub/.strands-box");
        std::fs::create_dir_all(&refused).expect("a sibling box under the inner root");
        // The inner root is stated first, so the outer root's leaf allows render after the inner
        // root's own identity pair in the write-root block: the order that would undo that pair.
        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&inner, Operation::Write, Scope::Root)
            .expect("the inner write root")
            .allow(&outer, Operation::Read, Scope::Root)
            .expect("the outer root, readable")
            .allow(&outer, Operation::Write, Scope::Root)
            .expect("the outer root, writable")
            .refuse(&refused, Scope::Root)
            .expect("the refusal");

        assert!(
            matches!(
                crate::floors::require_all(&config),
                Err(ContainmentError::ConflictingGrants { .. })
            ),
            "the floor refuses nested write roots before any backend renders them"
        );

        let profile = render_profile(&config).expect("the renderer alone still renders");
        let last_leaf_allow = profile
            .rfind("(allow file-write-times (subpath ")
            .expect("a write root renders");
        assert_eq!(
            identity_pairs_on(&profile, &inner.join("sub")),
            1,
            "{profile}"
        );
        for rule in identity_pair(&inner.join("sub")) {
            assert!(
                profile.rfind(&rule).expect("rendered") > last_leaf_allow,
                "the fixed directory renders after every leaf allow: {profile}"
            );
        }
        // Once as its own root, once as an ancestor for the outer root; the later copy is the one
        // that holds after the outer root's allows.
        assert_eq!(
            identity_pairs_on(&profile, &inner),
            2,
            "the inner root carries its own pair and gains one in the ancestor block: {profile}"
        );
        for rule in identity_pair(&inner) {
            assert!(
                profile.rfind(&rule).expect("rendered") > last_leaf_allow,
                "the inner root's identity must be re-fixed after the outer root's allows: {profile}"
            );
        }
        assert_eq!(identity_pairs_on(&profile, &outer), 1, "{profile}");
        assert_eq!(identity_pairs_on(&profile, &base), 0, "{profile}");
    }

    #[test]
    fn an_identity_requirement_remains_inspectable_after_profile_apply() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program fixture");
        let authority = base.join("authority");
        std::fs::write(&authority, "authority").expect("authority fixture");
        let opened = std::fs::File::open(&authority).expect("open authority");
        let state = base.join("state");
        std::fs::create_dir(&state).expect("state fixture");

        let config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(33085))
            .expect("localhost")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec")
            .allow(&state, Operation::Write, Scope::Root)
            .expect("write root")
            .require_file_identity(&authority, &opened)
            .expect("identity requirement");
        let profile = render_profile(&config).expect("profile");
        let path = authority.display();

        assert!(
            profile.contains(&format!("(allow file-read-metadata (literal \"{path}\"))")),
            "{profile}"
        );
        assert!(
            !profile.contains(&format!("(allow file-read-data (literal \"{path}\"))")),
            "{profile}"
        );
    }

    #[test]
    fn an_identity_lookup_remains_narrow_after_a_directory_refusal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().canonicalize().expect("canonical");
        let program = base.join("agent");
        std::fs::write(&program, "agent").expect("program");
        let root = base.join("state");
        let refused = root.join("authority");
        let parent = refused.join("nested");
        std::fs::create_dir_all(&parent).expect("authority directories");
        let source = parent.join("policy.dw");
        std::fs::write(&source, "authority").expect("authority file");
        let opened = std::fs::File::open(&source).expect("opened authority");

        for write_protected in [false, true] {
            let config = ContainmentConfig::new()
                .set_network(Network::localhost().connect(33085))
                .expect("network")
                .anchored_at(&base)
                .allow(&program, Operation::Exec, Scope::File)
                .expect("program grant")
                .allow(&root, Operation::Read, Scope::Root)
                .expect("read root")
                .allow(&root, Operation::Write, Scope::Root)
                .expect("write root")
                .refuse(&refused, Scope::Root)
                .expect("directory refusal");
            let config = if write_protected {
                config.protect_write(&source, &opened)
            } else {
                config.require_file_identity(&source, &opened)
            }
            .expect("identity check");
            let profile = render_profile(&config).expect("profile");
            let final_deny = format!(
                "(deny file-map-executable (subpath \"{}\"))",
                refused.display()
            );
            let after_denial = profile
                .rsplit_once(&final_deny)
                .expect("the directory keeps its denial")
                .1;
            let allows: BTreeSet<_> = after_denial
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("(allow "))
                .map(str::to_owned)
                .collect();
            let expected: BTreeSet<_> = source
                .ancestors()
                .flat_map(|path| {
                    ["file-read-metadata", "file-test-existence"].map(|operation| {
                        format!("(allow {operation} (literal \"{}\"))", path.display())
                    })
                })
                .collect();
            assert_eq!(
                allows, expected,
                "only exact-file and ancestor lookups may override the directory refusal"
            );
            for operation in [
                "file-read*",
                "file-write*",
                "file-read-metadata",
                "file-test-existence",
                "process-exec",
                "file-map-executable",
            ] {
                assert!(
                    profile.contains(&format!(
                        "(deny {operation} (subpath \"{}\"))",
                        refused.display()
                    )),
                    "the {operation} refusal must remain: {profile}"
                );
            }
        }
    }

    #[test]
    fn a_path_move_during_profile_apply_is_refused_before_exec() {
        for write_protected in [false, true] {
            let temp = tempfile::tempdir().expect("tempdir");
            let base = temp.path().canonicalize().expect("canonical");
            let program = base.join("agent");
            std::fs::write(&program, "agent").expect("program fixture");
            let root = base.join("state");
            let authority_directory = root.join(".strands-box");
            std::fs::create_dir_all(&authority_directory).expect("authority directory");
            let authority = authority_directory.join("authority");
            std::fs::write(&authority, "authority").expect("authority fixture");
            let opened = std::fs::File::open(&authority).expect("open authority");
            let moved = root.join("moved");
            let config = ContainmentConfig::new()
                .set_network(Network::localhost().connect(33085))
                .expect("localhost")
                .allow(&program, Operation::Exec, Scope::File)
                .expect("exec")
                .allow(&root, Operation::Write, Scope::Root)
                .expect("write root");
            let config = if write_protected {
                config.protect_write(&authority, &opened)
            } else {
                config.require_file_identity(&authority, &opened)
            }
            .expect("authority identity");

            let error = apply_validated_profile(&config, |_| {
                std::fs::rename(&authority_directory, &moved).expect("move authority directory");
                Ok(())
            })
            .expect_err("identity drift during apply must stop before exec")
            .to_string();
            assert!(
                error.contains("write-protected") || error.contains("path does not exist"),
                "{error}"
            );
        }
    }

    /// **Gated with the backend it names.** `SeatbeltBackend` exists only on macOS, so this runs
    /// there.
    #[cfg(target_os = "macos")]
    #[test]
    fn support_info_names_seatbelt() {
        let info = SeatbeltBackend::new().support_info();
        assert_eq!(info.platform, Platform::MacOS);
        assert_eq!(info.mechanism, MECHANISM);
    }
}
