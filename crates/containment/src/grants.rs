//! Set-level filesystem capability checks.

use std::path::Path;

use crate::{ContainmentError, Operation, Scope};

/// Check backend read/write coverage for already-resolved grants without probing the host.
pub fn validate_grants(grants: &[(&Path, Operation, Scope)]) -> crate::Result<()> {
    if cfg!(target_os = "linux") {
        require_read_for_writes(grants)?;
    }
    Ok(())
}

pub(crate) fn require_read_for_writes(grants: &[(&Path, Operation, Scope)]) -> crate::Result<()> {
    for &(path, operation, scope) in grants {
        if operation != Operation::Write {
            continue;
        }
        let covered = grants
            .iter()
            .any(|&(read_path, read_operation, read_scope)| {
                read_operation == Operation::Read
                    && match (read_scope, scope) {
                        (Scope::Root, Scope::Root | Scope::File) => path.starts_with(read_path),
                        (Scope::File, Scope::File) => path == read_path,
                        _ => false,
                    }
            });
        if !covered {
            return Err(ContainmentError::WriteOnlyUnsupported {
                path: path.to_path_buf(),
                backend: "namespace".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_require_content_reads_over_their_entire_scope() {
        for (write_path, write_scope, read_path, read_operation, read_scope, accepted) in [
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::Read,
                Scope::Root,
                true,
            ),
            (
                "/project/sub",
                Scope::Root,
                "/project",
                Operation::Read,
                Scope::Root,
                true,
            ),
            (
                "/project/file",
                Scope::File,
                "/project",
                Operation::Read,
                Scope::Root,
                true,
            ),
            (
                "/project/file",
                Scope::File,
                "/project/file",
                Operation::Read,
                Scope::File,
                true,
            ),
            (
                "/project",
                Scope::Root,
                "/project/sub",
                Operation::Read,
                Scope::Root,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project/file",
                Operation::Read,
                Scope::File,
                false,
            ),
            (
                "/project-other",
                Scope::Root,
                "/project",
                Operation::Read,
                Scope::Root,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::Read,
                Scope::Dir,
                false,
            ),
            (
                "/project/file",
                Scope::File,
                "/project",
                Operation::Read,
                Scope::Dir,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::List,
                Scope::Root,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::Metadata,
                Scope::Root,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::Exec,
                Scope::Root,
                false,
            ),
            (
                "/project",
                Scope::Root,
                "/project",
                Operation::Deny,
                Scope::Root,
                false,
            ),
        ] {
            let mut grants = [
                (Path::new(write_path), Operation::Write, write_scope),
                (Path::new(read_path), read_operation, read_scope),
            ];
            for _ in 0..2 {
                let result = require_read_for_writes(&grants);
                assert_eq!(result.is_ok(), accepted, "{grants:?}: {result:?}");
                if let Err(ContainmentError::WriteOnlyUnsupported { path, backend }) = result {
                    assert_eq!(path, Path::new(write_path));
                    assert_eq!(backend, "namespace");
                }
                grants.reverse();
            }
        }
    }

    #[test]
    fn every_write_needs_coverage_and_empty_sets_are_valid() {
        assert!(require_read_for_writes(&[]).is_ok());
        let grants = [
            (Path::new("/project"), Operation::Read, Scope::Root),
            (Path::new("/project/output"), Operation::Write, Scope::Root),
            (Path::new("/other"), Operation::Write, Scope::Root),
        ];
        assert!(matches!(
            require_read_for_writes(&grants),
            Err(ContainmentError::WriteOnlyUnsupported { path, .. }) if path == Path::new("/other")
        ));
        assert!(require_read_for_writes(&grants[2..]).is_err());
    }

    #[test]
    fn the_host_check_preserves_macos_write_only_access() {
        let grants = [(Path::new("/project"), Operation::Write, Scope::Root)];
        assert_eq!(validate_grants(&grants).is_err(), cfg!(target_os = "linux"));
    }
}
