//! Admission and startup diagnostics for automatically discovered native dependencies.

use crate::model::PathGrant;
use crate::{ContainmentConfig, ContainmentError, Operation, Scope};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn failure(backend: &str, reason: String) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: backend.to_owned(),
        reason,
    }
}

#[derive(Default)]
pub(super) struct MissingReads {
    paths: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
}

impl MissingReads {
    pub(super) fn add(&mut self, dependency: &Path, image: &Path) {
        self.paths
            .entry(dependency.to_owned())
            .or_default()
            .insert(image.to_owned());
    }

    pub(super) fn require_complete(&self, backend: &str) -> Result<(), ContainmentError> {
        // Box's supervise::trampoline_message allows 8192 characters, including error framing.
        const MAXIMUM_REASON_BYTES: usize = 6000;
        const TRUNCATED_REASON_BYTES: usize = 5500;

        if self.paths.is_empty() {
            return Ok(());
        }
        let mut reason = format!(
            "{} dependencies lack read access; no filesystem grant reaches them.\nA writable dependency chain cannot add these reads.\n",
            self.paths.len()
        );
        for (path, images) in self.paths.iter().take(32) {
            reason.push_str(&format!(
                "\nDependency: {path:?}\nRequested by: {images:?}\n"
            ));
        }
        reason.push_str("\nKeep existing filesystem entries. Append these paths to read_file in the affected process's filesystem table:\n");
        for path in self.paths.keys().take(32) {
            if let Some(text) = path.to_str() {
                reason.push_str(&format!(
                    "  {},\n",
                    serde_json::to_string(text)
                        .expect("a string serializes")
                        .replace('\u{007f}', "\\u007f")
                ));
            } else {
                reason.push_str("  # A path above is not UTF-8 and cannot be expressed in TOML.\n");
            }
        }
        reason.push_str("Each added entry permits reading the file's contents. Review it before granting access.\nDiscovery stopped at unreadable dependencies; more may appear after retry.\nNo configuration files changed.");
        if self.paths.len() > 32 {
            reason.push_str("\nOnly the first 32 missing files are shown.");
        }
        // Keep the setup-status pipe's diagnostic bounded, including hostile path lengths.
        if reason.len() > MAXIMUM_REASON_BYTES {
            let mut end = TRUNCATED_REASON_BYTES;
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason.truncate(end);
            reason
                .push_str("\nDiagnostic truncated; do not copy incomplete configuration guidance.");
        }
        Err(failure(backend, reason))
    }
}

pub(super) fn require_not_refused(
    config: &ContainmentConfig,
    path: &PathGrant,
    backend: &str,
) -> Result<(), ContainmentError> {
    for denied in config.refusals() {
        if path
            .traversal_paths()
            .iter()
            .any(|node| match denied.scope {
                Scope::Root => {
                    node.starts_with(&denied.resolved) || node.starts_with(&denied.original)
                }
                Scope::File | Scope::Dir => node == &denied.resolved || node == &denied.original,
            })
        {
            return Err(failure(
                backend,
                format!(
                    "dependency {:?} is explicitly denied by {:?}; remove the dependency or change the workload. A Read entry cannot override this denial.",
                    path.resolved, denied.original
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn workload_writable(
    config: &ContainmentConfig,
    image: &Path,
    backend: &str,
) -> Result<bool, ContainmentError> {
    if !config
        .authorizations()
        .iter()
        .any(|grant| grant.operation == Operation::Write)
    {
        return Ok(false);
    }
    let path = crate::model::PathGrant::new(image, Operation::Read, Scope::File)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = |name: &Path| {
            std::fs::metadata(name).map_err(|error| {
                failure(
                    backend,
                    format!("checking dependency identity {name:?}: {error}"),
                )
            })
        };
        let identity = metadata(&path.resolved)?;
        for grant in config.authorizations() {
            if grant.operation != Operation::Write {
                continue;
            }
            match grant.scope {
                // A directory scan cannot exclude an alias added during discovery.
                Scope::Root if identity.nlink() > 1 => return Ok(true),
                Scope::File => {
                    let writable = metadata(&grant.resolved)?;
                    if identity.dev() == writable.dev() && identity.ino() == writable.ino() {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
    }
    let mut nodes = path.traversal_paths();
    for grant in config
        .authorizations()
        .iter()
        .filter(|grant| grant.operation == Operation::Exec && grant.resolved == path.resolved)
    {
        nodes.extend(grant.traversal_paths());
    }
    let mut visited = BTreeSet::new();
    while let Some(node) = nodes.pop() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if visited.len() > 256 {
            return Err(failure(
                backend,
                format!(
                    "dependency '{}' has too many link paths to verify",
                    image.display()
                ),
            ));
        }
        if config.authorizations().iter().any(|grant| {
            grant.operation == Operation::Write
                && match grant.scope {
                    Scope::Root => {
                        node.starts_with(&grant.resolved) || node.starts_with(&grant.original)
                    }
                    Scope::File => node == grant.resolved || node == grant.original,
                    Scope::Dir => false,
                }
        }) {
            return Ok(true);
        }
        for ancestor in node.ancestors() {
            if let Ok(target) = std::fs::read_link(ancestor) {
                let target = if target.is_absolute() {
                    target
                } else {
                    ancestor.parent().unwrap_or(Path::new("/")).join(target)
                };
                let target = target.join(node.strip_prefix(ancestor).unwrap_or(Path::new("")));
                nodes.push(folded(&target));
                nodes.push(target);
            }
        }
    }
    Ok(false)
}

pub(super) fn folded(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_escapes_control_characters_and_never_changes_configuration() {
        let mut missing = MissingReads::default();
        missing.add(
            Path::new("/vendor/quote\"\n\u{007f}"),
            Path::new("/project/app\nFORGED"),
        );
        let text = missing.require_complete("test").unwrap_err().to_string();
        assert!(
            text.contains("\\u007f"),
            "TOML forbids a literal DEL: {text}"
        );
        assert!(
            !text.contains("app\nFORGED"),
            "a path must not inject a diagnostic line: {text}"
        );
        assert!(
            text.contains("Keep existing filesystem entries")
                && text.contains("No configuration files changed.")
        );
    }

    #[test]
    fn missing_read_diagnostics_bound_the_complete_reason() {
        let reason = |count: usize, padding: &str| {
            let mut missing = MissingReads::default();
            for index in 0..count {
                let image = if index == 0 {
                    format!("/project/app{padding}")
                } else {
                    "/project/app".to_owned()
                };
                missing.add(Path::new(&format!("/vendor/{index:02}")), Path::new(&image));
            }
            let ContainmentError::ApplyFailed { reason, .. } =
                missing.require_complete("test").unwrap_err()
            else {
                panic!("missing reads must fail application");
            };
            reason
        };
        for count in [2, 33] {
            let padding = "x".repeat(6000 - reason(count, "").len());
            let complete = reason(count, &padding);
            assert_eq!(complete.len(), 6000);
            assert!(complete.contains("No configuration files changed."));
            assert_eq!(complete.contains("Only the first 32"), count > 32);

            let oversized = reason(count, &format!("{padding}x"));
            assert!(oversized.len() <= 6000, "{} bytes", oversized.len());
            assert!(
                oversized.ends_with(
                    "Diagnostic truncated; do not copy incomplete configuration guidance."
                )
            );
        }
        let unicode = reason(2, &"界".repeat(3000));
        assert!(unicode.len() <= 6000);
        assert!(
            unicode
                .ends_with("Diagnostic truncated; do not copy incomplete configuration guidance.")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_has_no_lossy_configuration_suggestion() {
        use std::os::unix::ffi::OsStrExt as _;
        let mut missing = MissingReads::default();
        missing.add(
            Path::new(std::ffi::OsStr::from_bytes(b"/vendor/\xff")),
            Path::new("/project/app"),
        );
        let text = missing.require_complete("test").unwrap_err().to_string();
        assert!(text.contains("cannot be expressed in TOML"), "{text}");
        assert!(!text.contains('�'));
    }
    #[cfg(unix)]
    #[test]
    fn write_access_follows_file_identity_across_hard_links() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let image = root.join("installed-program");
        std::fs::write(&image, b"program bytes").unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        let alias = project.join("alias");
        std::fs::hard_link(&image, &alias).unwrap();
        for (path, scope) in [(&project, Scope::Root), (&alias, Scope::File)] {
            let config = ContainmentConfig::new()
                .allow(path, Operation::Write, scope)
                .unwrap();
            assert!(workload_writable(&config, &image, "test").unwrap());
        }
        let unrelated = root.join("unrelated");
        std::fs::write(&unrelated, b"other bytes").unwrap();
        let config = ContainmentConfig::new()
            .allow(&unrelated, Operation::Write, Scope::File)
            .unwrap();
        assert!(!workload_writable(&config, &image, "test").unwrap());
        assert!(!workload_writable(&ContainmentConfig::new(), &image, "test").unwrap());
    }
}
