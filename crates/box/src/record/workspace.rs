//! Refuse the operator's home as a workspace.

use std::path::{Path, PathBuf};

use crate::error::{BoxError, ConfigError};

/// Where a working directory stands relative to the operator's home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// The home itself, which is not a workspace.
    TheHomeItself,
    /// A directory under the home.
    Inside,
    /// Anywhere else.
    Outside,
}

/// Classify `path` against the operator's home.
fn standing(path: &Path) -> Result<Standing, BoxError> {
    let (resolved, home) = resolved_beside_home(path)?;
    if resolved == home || same_directory(&resolved, &home) {
        return Ok(Standing::TheHomeItself);
    }
    Ok(if resolved.starts_with(&home) {
        Standing::Inside
    } else {
        Standing::Outside
    })
}

/// Refuse `path` when it is the operator's home, with the one message every verb gives.
pub(crate) fn refuse_operator_home(path: &Path) -> Result<(), BoxError> {
    if standing(path)? == Standing::TheHomeItself {
        return Err(the_home_is_not_a_project(path));
    }
    Ok(())
}

/// Refuse the operator home as a workspace.
fn the_home_is_not_a_project(path: &Path) -> BoxError {
    ConfigError::Workspace {
        reason: format!(
            "{} is the operator's home, which is not a workspace: a policy scoped to it would permit \
             writes across every harness's stored credentials, and the box would not start. Make a \
             directory for the workspace and work there",
            path.display()
        ),
    }
    .into()
}

/// Whether two paths name one directory, by identity rather than by spelling.
fn same_directory(left: &Path, right: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(left), std::fs::metadata(right)) {
            (Ok(one), Ok(two)) => one.dev() == two.dev() && one.ino() == two.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

/// `path` resolved as far as the filesystem allows, beside the canonical operator home.
fn resolved_beside_home(path: &Path) -> Result<(PathBuf, PathBuf), BoxError> {
    let home = operator_home()?;
    let resolved = crate::record::layout::canonical(path);
    Ok((resolved, home))
}

/// The operator's home, which bounds the upward search and anchors a derived name.
fn operator_home() -> Result<PathBuf, BoxError> {
    let home = crate::record::layout::operator_home_directory()?;
    Ok(crate::record::layout::canonical(&home))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `same_directory` answers by identity, so two routes to one directory agree.
    #[test]
    fn one_directory_reached_two_ways_is_the_same_directory() {
        let root = std::env::temp_dir().join(format!("sb-ident-{}", std::process::id()));
        let real = root.join("real");
        let other = root.join("other");
        std::fs::create_dir_all(&real).expect("create the real directory");
        std::fs::create_dir_all(&other).expect("create a second, different directory");

        assert!(
            same_directory(&real, &real),
            "a directory must be itself, or the helper refuses nothing"
        );
        assert!(
            !same_directory(&real, &other),
            "two distinct directories must not be equated, or every workspace reads as the home"
        );

        #[cfg(unix)]
        {
            let link = root.join("link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&real, &link).expect("symlink the real directory");
            assert!(
                same_directory(&link, &real),
                "a second route to one directory must answer the same"
            );
        }

        // An absent path answers `false` rather than panicking, so a workspace directory that does
        // not exist yet gets no added refusal.
        assert!(!same_directory(&root.join("absent"), &real));

        let _ = std::fs::remove_dir_all(&root);
    }
}
