//! The shell aliases: what the contained workload finds on its `PATH`.
//!
//! | File | Holds |
//! |---|---|
//! | `bin/.alias-image` | this box's own copy of the installed alias image, one inode per box |
//! | `bin/<name>` | one hard link to that image per interpreter name and per MCP server |
//! | `private/alias-image.stamp` | the SHA-256 of the installed image the copy was taken from |

use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use crate::error::{BoxError, ShellError};
use crate::record::layout::{ALIAS_IMAGE_FILE, BoxRoot};
use crate::run::lock::Lock;

/// The installed image's filename, which must sit beside the box executable.
pub(crate) const ALIAS_IMAGE_NAME: &str = "strands-box-sock-alias";

/// Place one alias per conventional shell name in the box's `bin/`.
///
/// The run lock proves no workload of this box is executing an alias name while one is replaced.
pub(crate) fn materialize(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
    owner: &Lock,
) -> Result<(), BoxError> {
    materialize_from(layout, servers, &installed_image()?, owner)
}

/// `_owner` is the run lock as a token: `run` takes it before the first call and holds it until
/// the workload has exited.
fn materialize_from(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
    installed: &Path,
    _owner: &Lock,
) -> Result<(), BoxError> {
    let materialize_error = |path: &Path, reason: String| ShellError::Materialize {
        path: path.to_path_buf(),
        reason,
    };
    let digest = image_digest(installed).map_err(|error| {
        materialize_error(
            installed,
            format!("reading the installed image for its digest: {error}"),
        )
    })?;

    // The box's own image is cloned once and kept across runs; only an installed image with other
    // bytes replaces it.
    let image = layout.alias_image();
    let recorded = layout.read_text(&layout.alias_stamp()).ok();
    if recorded.as_deref() != Some(digest.as_str()) || layout.file_identity(&image)?.is_none() {
        layout
            .install_private_image(installed, &image, 0o500)
            .map_err(|error| {
                materialize_error(&image, format!("place the box's alias image: {error}"))
            })?;
    }
    let identity = layout
        .file_identity(&image)?
        .ok_or_else(|| materialize_error(&image, "the placed image is absent".to_string()))?;

    // Shell and Python names alike: one image serves both, dispatching on its own filename, so
    // materializing is identical and the loop is shared. A name already linked to this box's image
    // is left alone.
    for alias in layout.all_aliases(servers) {
        if layout.file_identity(&alias)? == Some(identity) {
            continue;
        }
        layout
            .link_file(&image, &alias)
            .map_err(|error| ShellError::Materialize {
                path: alias,
                reason: format!("place the Shell alias: {error}"),
            })?;
    }

    // **An alias for a server the operator removed is unlinked, not left behind.**
    let placed: std::collections::BTreeSet<_> = layout
        .all_aliases(servers)
        .into_iter()
        .filter_map(|path| path.file_name().map(std::ffi::OsStr::to_os_string))
        .chain(std::iter::once(std::ffi::OsString::from(ALIAS_IMAGE_FILE)))
        .collect();
    if let Ok(entries) = layout.directory_entry_names(&layout.bin_directory()) {
        for entry in entries {
            if !placed.contains(&entry) {
                // A failure here is not fatal: the box still serves, and the next `run` retries.
                let _ = layout.remove_file(&layout.bin_directory().join(entry));
            }
        }
    }

    // **The stamp is written LAST**, after every alias is in place, so an interrupted
    // materialization reads as stale.
    layout.write_private_file(&layout.alias_stamp(), &digest, 0o600)?;

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
    is_stale_against(layout, servers, &installed)
}

fn is_stale_against(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
    installed: &Path,
) -> bool {
    let Ok(current) = image_digest(installed) else {
        return false;
    };
    if layout.read_text(&layout.alias_stamp()).ok().as_deref() != Some(current.as_str()) {
        return true;
    }
    // The stamp matches, so the box's image came from this installed image. Every alias must
    // still be a link to it: a declared MCP server added since the last `materialize` has no
    // alias yet, and a name replaced by another file is not this box's image.
    let Ok(Some(identity)) = layout.file_identity(&layout.alias_image()) else {
        return true;
    };
    layout
        .all_aliases(servers)
        .into_iter()
        .any(|alias| layout.file_identity(&alias).ok().flatten() != Some(identity))
}

/// The SHA-256 of the installed image's bytes, as the stamp records it.
fn image_digest(installed: &Path) -> io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut file = crate::record::layout::open_without_following(installed)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>());
        }
        hasher.update(&buffer[..read]);
    }
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
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A box beside a fixture operator home, the run lock on it, and a stand-in installed image.
    fn fixture(image: &[u8]) -> (BoxRoot, Lock, PathBuf, tempfile::TempDir) {
        let operator_home = tempfile::tempdir().expect("an operator home");
        let layout = crate::record::layout::testing::box_root(operator_home.path(), "codex");
        let owner = Lock::try_acquire(&layout.lock())
            .expect("the lock file opens")
            .expect("nothing else holds a fresh box");
        let install = operator_home.path().join("install");
        std::fs::create_dir_all(&install).expect("an install directory");
        let installed = install.join(ALIAS_IMAGE_NAME);
        write_image(&installed, image);
        (layout, owner, installed, operator_home)
    }

    fn write_image(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("the stand-in image is written");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in image is executable");
    }

    fn identity(path: &Path) -> (u64, u64) {
        let metadata = std::fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));
        (metadata.dev(), metadata.ino())
    }

    fn change_time(path: &Path) -> (i64, i64) {
        let metadata = std::fs::symlink_metadata(path).expect("the path exists");
        (metadata.ctime(), metadata.ctime_nsec())
    }

    fn declared(name: &str) -> crate::record::config::mcp::McpServer {
        crate::record::config::mcp::McpServer {
            name: name.to_string(),
            alias: None,
            command: vec![name.to_string()],
        }
    }

    /// **Every alias name links to this box's own image, and none to the installed one.**
    #[test]
    fn every_alias_shares_the_boxs_own_image_inode_and_not_the_installed_one() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        let servers = [declared("issues-mcp")];

        materialize_from(&layout, &servers, &installed, &owner).expect("the aliases are placed");

        let image = layout.alias_image();
        let own = identity(&image);
        assert_ne!(
            own,
            identity(&installed),
            "the box's image must be its own inode, not a link to the installed image"
        );
        assert_eq!(
            std::fs::read(&image).expect("the image reads"),
            b"image one",
            "the box's image must carry the installed image's bytes"
        );
        assert_eq!(
            std::fs::symlink_metadata(&image)
                .expect("the image exists")
                .mode()
                & 0o777,
            0o500,
            "the box's image is execute-only for its owner"
        );
        for alias in layout.all_aliases(&servers) {
            assert_eq!(
                identity(&alias),
                own,
                "{} must be a hard link to the box's own image",
                alias.display()
            );
        }
        assert!(
            !is_stale_against(&layout, &servers, &installed),
            "a box just materialized from this image must not read as stale"
        );
    }

    /// **A second `materialize` on the same box reuses the clone and touches no alias name.**
    #[test]
    fn a_second_materialize_reuses_the_clone_and_unlinks_no_alias() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        materialize_from(&layout, &[], &installed, &owner).expect("the first materialize");
        let image = layout.alias_image();
        let before = identity(&image);
        let changed_before = change_time(&image);
        let names_before: Vec<_> = layout
            .shell_aliases()
            .into_iter()
            .map(|alias| identity(&alias))
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(20));

        materialize_from(&layout, &[], &installed, &owner).expect("the second materialize");

        assert_eq!(
            identity(&image),
            before,
            "the clone must be reused, not replaced"
        );
        assert_eq!(
            change_time(&image),
            changed_before,
            "no alias name was unlinked or relinked: the image's link count never moved"
        );
        let names_after: Vec<_> = layout
            .shell_aliases()
            .into_iter()
            .map(|alias| identity(&alias))
            .collect();
        assert_eq!(names_before, names_after);
    }

    /// **An installed image with other bytes replaces the clone, and every alias follows it.**
    #[test]
    fn a_changed_installed_image_replaces_the_clone() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        materialize_from(&layout, &[], &installed, &owner).expect("the first materialize");
        let image = layout.alias_image();
        let first = identity(&image);
        assert!(!is_stale_against(&layout, &[], &installed));

        write_image(&installed, b"image two");
        assert!(
            is_stale_against(&layout, &[], &installed),
            "an installed image with other bytes must read as stale"
        );
        materialize_from(&layout, &[], &installed, &owner).expect("the second materialize");

        let second = identity(&image);
        assert_ne!(first, second, "the clone must be replaced by a new inode");
        assert_eq!(
            std::fs::read(&image).expect("the image reads"),
            b"image two"
        );
        for alias in layout.shell_aliases() {
            assert_eq!(
                identity(&alias),
                second,
                "{} must follow the replaced image",
                alias.display()
            );
        }
        assert!(
            !layout.bin_directory().join(".alias-image.pending").exists(),
            "no pending image is left beside the placed one"
        );
        assert!(!is_stale_against(&layout, &[], &installed));
    }

    /// **A box materialized from the current image is not stale; a missing or foreign alias is.**
    #[test]
    fn a_box_materialized_from_the_current_image_is_not_stale() {
        let (layout, owner, installed, _home) = fixture(b"image one");

        assert!(
            is_stale_against(&layout, &[], &installed),
            "a box with no stamp must read as stale, which is what recovers one configured by an \
             earlier build"
        );
        materialize_from(&layout, &[], &installed, &owner).expect("the aliases are placed");
        assert!(!is_stale_against(&layout, &[], &installed));

        // A declared server with no alias yet is stale, which the stamp alone cannot see.
        let servers = [declared("issues-mcp")];
        assert!(
            is_stale_against(&layout, &servers, &installed),
            "a newly declared MCP server has no alias, so the box is stale even though the stamp \
             matches"
        );
        materialize_from(&layout, &servers, &installed, &owner).expect("the server's alias");
        assert!(!is_stale_against(&layout, &servers, &installed));

        // A stamp naming a different image is what a rebuilt install looks like.
        std::fs::write(layout.alias_stamp(), "0 0.000000000").expect("stand in for an older image");
        assert!(is_stale_against(&layout, &servers, &installed));
        materialize_from(&layout, &servers, &installed, &owner).expect("re-place everything");
        assert!(!is_stale_against(&layout, &servers, &installed));

        // A missing alias is stale even when the stamp matches, which recovers an interrupted
        // `bin/`.
        let alias = layout.shell_aliases().remove(0);
        std::fs::remove_file(&alias).expect("unlink one alias");
        assert!(
            is_stale_against(&layout, &servers, &installed),
            "a missing alias must read as stale"
        );

        // An alias that is another file is stale, and `materialize` puts the link back.
        std::fs::write(&alias, b"stale").expect("stand in for a foreign alias");
        assert!(is_stale_against(&layout, &servers, &installed));
        materialize_from(&layout, &servers, &installed, &owner).expect("re-place the alias");
        assert_eq!(
            identity(&alias),
            identity(&layout.alias_image()),
            "the foreign file must be replaced by a link to the box's image"
        );
    }

    /// **A dropped MCP server's alias is removed at the next `materialize`, under the run lock.**
    #[test]
    fn a_dropped_servers_alias_is_removed_at_the_next_materialize() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        let servers = [declared("issues-mcp")];
        materialize_from(&layout, &servers, &installed, &owner).expect("with the server");
        let alias = layout.mcp_aliases(&servers).remove(0);
        assert!(alias.exists(), "the declared server has an alias");

        materialize_from(&layout, &[], &installed, &owner).expect("without the server");

        assert!(!alias.exists(), "the dropped server's alias is unlinked");
        assert!(
            layout.alias_image().exists(),
            "the sweep of `bin/` must not remove the box's own image"
        );
        for alias in layout.shell_aliases() {
            assert!(alias.exists(), "{} stays", alias.display());
        }
    }

    /// **A server with `alias` is placed under that name, and its program gets no alias.**
    #[test]
    fn an_aliased_server_is_placed_under_its_alias_and_not_its_program() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        let servers = ["github", "filesystem"].map(|name| crate::record::config::mcp::McpServer {
            name: name.to_string(),
            alias: Some(format!("{name}-mcp")),
            command: vec!["npx".to_string(), "-y".to_string()],
        });
        materialize_from(&layout, &servers, &installed, &owner).expect("the aliases are placed");

        let bin = layout.bin_directory();
        assert!(bin.join("github-mcp").is_file());
        assert!(bin.join("filesystem-mcp").is_file());
        assert!(
            !bin.join("npx").exists(),
            "the agent's own `npx` must not be shadowed by a server alias"
        );
        assert_eq!(
            layout.mcp_aliases(&servers),
            [bin.join("github-mcp"), bin.join("filesystem-mcp")]
        );
    }

    #[test]
    fn every_alias_is_materialized_and_executable() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        let servers = [declared("issues-mcp")];
        materialize_from(&layout, &servers, &installed, &owner).expect("the aliases materialize");

        for alias in layout.all_aliases(&servers) {
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

    /// The installed image beside a built binary, when there is one, materializes as well.
    #[test]
    fn the_installed_image_materializes_when_present() {
        let operator_home = tempfile::tempdir().expect("an operator home");
        let layout = crate::record::layout::testing::box_root(operator_home.path(), "codex");
        if installed_image().is_err() {
            eprintln!("skipping: no {ALIAS_IMAGE_NAME} installed beside the test binary");
            return;
        }
        let owner = Lock::try_acquire(&layout.lock())
            .expect("the lock file opens")
            .expect("nothing else holds a fresh box");
        assert!(is_stale(&layout, &[]));
        materialize(&layout, &[], &owner).expect("the aliases are placed");
        assert!(!is_stale(&layout, &[]));
    }
}
