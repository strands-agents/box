//! The shell aliases: what the contained workload finds on its `PATH`.

use std::io;
use std::path::{Path, PathBuf};

use crate::error::{BoxError, ShellError};
use crate::record::layout::BoxRoot;

/// The installed image's filename, which must sit beside the box executable.
const ALIAS_IMAGE_NAME: &str = "strands-box-sock-alias";

/// Place one alias per conventional shell name in the box's `bin/`.
pub(crate) fn materialize(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
) -> Result<(), BoxError> {
    let installed = installed_image()?;

    // Shell and Python names alike: one image serves both, dispatching on its own filename, so
    // materializing is identical and the loop is shared.
    for alias in layout.all_aliases(servers) {
        layout
            .install_file(&installed, &alias, 0o500)
            .map_err(|error| ShellError::Materialize {
                path: alias,
                reason: format!("place the Shell alias: {error}"),
            })?;
    }

    // **An alias for a server the operator removed is unlinked, not left behind.**
    //
    let placed: std::collections::BTreeSet<_> = layout
        .all_aliases(servers)
        .into_iter()
        .filter_map(|path| path.file_name().map(std::ffi::OsStr::to_os_string))
        .collect();
    if let Ok(entries) = layout.directory_entry_names(&layout.bin_directory()) {
        for entry in entries {
            if !placed.contains(&entry) {
                // A failure here is not fatal: the box still serves, and the next `run` retries.
                let _ = layout.remove_file(&layout.bin_directory().join(entry));
            }
        }
    }

    // **The stamp is written LAST**, after every alias is in place. Written first, an interrupted
    // materialization would leave a stamp claiming aliases that are not there — and `is_stale` would
    let stamp = image_stamp(&installed).map_err(|error| ShellError::Materialize {
        path: installed.clone(),
        reason: format!("reading the installed image's identity for the stamp: {error}"),
    })?;
    layout.write_private_file(&layout.alias_stamp(), &stamp, 0o600)?;

    Ok(())
}

/// Whether the placed aliases came from a different installed image than the one on disk now.
pub(crate) fn is_stale(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
) -> bool {
    let Ok(installed) = installed_image() else {
        // No installed image is a failure `materialize` reports with a name and a reason, so it
        // is not this function's to guess at.
        return false;
    };
    let Ok(current) = image_stamp(&installed) else {
        return false;
    };
    if layout.read_text(&layout.alias_stamp()).ok().as_deref() != Some(current.as_str()) {
        return true;
    }
    // The stamp matches, so the aliases came from this image. They must still all be present: a
    // declared MCP server added since the last `materialize` has no alias yet, and the stamp alone
    layout
        .all_aliases(servers)
        .into_iter()
        .any(|alias| !layout.path_exists(&alias).unwrap_or(false))
}

/// The installed image's identity, as the stamp records it.
fn image_stamp(installed: &Path) -> io::Result<String> {
    let metadata = std::fs::metadata(installed)?;
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("the image predates the epoch: {error}")))?;
    Ok(format!(
        "{} {}.{:09}",
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

/// Find the shim beside the box's own executable, and nowhere else.
fn installed_image() -> Result<PathBuf, BoxError> {
    let current = std::env::current_exe().map_err(|source| ShellError::Missing {
        path: PathBuf::from(ALIAS_IMAGE_NAME),
        source,
    })?;
    let installed = current
        .parent()
        .map(|directory| directory.join(ALIAS_IMAGE_NAME))
        .ok_or_else(|| ShellError::NotExecutable {
            path: current.clone(),
        })?;

    let metadata = std::fs::symlink_metadata(&installed).map_err(|source| ShellError::Missing {
        path: installed.clone(),
        source,
    })?;
    // A symlink is refused rather than followed: what is executed must be the file the
    // install placed, not wherever a link now points.
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ShellError::NotExecutable { path: installed }.into());
    }
    #[cfg(unix)]
    if metadata.mode() & 0o111 == 0 {
        return Err(ShellError::NotExecutable { path: installed }.into());
    }
    Ok(installed)
}

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

#[cfg(test)]
mod tests {
    use super::*;

    /// **A box materialized from the current image is not stale; a rebuilt image makes it stale.**
    ///
    /// Two earlier shapes of this check were both wrong, and each cost something different:
    #[test]
    fn a_box_materialized_from_the_current_image_is_not_stale() {
        let operator_home = tempfile::tempdir().expect("an operator home");
        let layout = crate::record::layout::testing::box_root(operator_home.path(), "codex");

        // The image is installed only beside a built binary, so a unit-test run from `deps/` has
        // nothing to materialize from.
        if installed_image().is_err() {
            eprintln!("skipping: no {ALIAS_IMAGE_NAME} installed beside the test binary");
            return;
        }

        assert!(
            is_stale(&layout, &[]),
            "a box with no stamp must read as stale, which is what recovers one configured by an \
             earlier build"
        );

        materialize(&layout, &[]).expect("the aliases are placed");
        assert!(
            !is_stale(&layout, &[]),
            "a box just materialized from this image must not read as stale"
        );

        // A declared server with no alias yet is stale, which the stamp alone cannot see.
        let declared = [crate::record::config::mcp::McpServer {
            name: "issues-mcp".to_string(),
            command: vec!["issues-mcp".to_string()],
        }];
        assert!(
            is_stale(&layout, &declared),
            "a newly declared MCP server has no alias, so the box is stale even though the stamp \
             matches"
        );
        materialize(&layout, &declared).expect("the server's alias is placed");
        assert!(!is_stale(&layout, &declared), "and placing it settles it");

        // A rebuilt install moves the stamp, which is the case this exists for.
        std::fs::write(layout.alias_stamp(), "0 0.000000000").expect("stand in for an older image");
        assert!(
            is_stale(&layout, &declared),
            "a stamp naming a different image must read as stale"
        );

        // A missing alias is stale even when the stamp matches, which recovers an interrupted
        // `bin/`.
        materialize(&layout, &declared).expect("re-place everything");
        let alias = layout
            .shell_aliases()
            .into_iter()
            .next()
            .expect("at least one shell alias");
        std::fs::remove_file(&alias).expect("unlink one alias");
        assert!(
            is_stale(&layout, &declared),
            "a missing alias must read as stale"
        );
    }

    #[test]
    fn every_alias_is_materialized_and_executable() {
        let operator_home = tempfile::tempdir().unwrap();
        let layout = crate::record::layout::testing::box_root(operator_home.path(), "codex");

        // The shim image is only installed beside a built binary, so a source tree
        // without one has nothing to materialize from. Reported rather than skipped
        if installed_image().is_err() {
            eprintln!("skipping: no {ALIAS_IMAGE_NAME} installed beside the test binary");
            return;
        }
        let declared = [crate::record::config::mcp::McpServer {
            name: "issues-mcp".to_string(),
            command: vec!["issues-mcp".to_string()],
        }];
        materialize(&layout, &declared).expect("the aliases materialize");

        for alias in layout.all_aliases(&declared) {
            let metadata = std::fs::symlink_metadata(&alias)
                .unwrap_or_else(|error| panic!("{} must exist: {error}", alias.display()));
            assert!(
                !metadata.file_type().is_symlink(),
                "{} must be a real file: the profile matches the path spelling for exec, \
                 so a symlink to a granted target is denied",
                alias.display()
            );
            assert!(
                metadata.mode() & 0o111 != 0,
                "{} must be executable",
                alias.display()
            );
            assert!(
                metadata.len() > 0,
                "{} must not be a truncated copy",
                alias.display()
            );
        }
    }

    /// `configure` twice replaces the aliases rather than failing or skipping.
    #[test]
    fn reconfiguring_replaces_the_aliases() {
        let operator_home = tempfile::tempdir().unwrap();
        let layout = crate::record::layout::testing::box_root(operator_home.path(), "codex");
        if installed_image().is_err() {
            eprintln!("skipping: no {ALIAS_IMAGE_NAME} installed beside the test binary");
            return;
        }

        materialize(&layout, &[]).expect("first configure");
        // Stand in for a stale alias from an older install: a different size is what
        // proves the second pass replaced it rather than left it.
        let first = &layout.shell_aliases()[0];
        std::fs::remove_file(first).unwrap();
        std::fs::write(first, b"stale").unwrap();

        materialize(&layout, &[]).expect("a second configure must not fail");

        let replaced = std::fs::metadata(first).unwrap().len();
        assert_ne!(
            replaced, 5,
            "the stale alias must be replaced by the installed image"
        );
    }
}
