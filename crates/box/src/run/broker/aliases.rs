//! The shell aliases: what the contained workload finds on its `PATH`.
//!
//! | File | Holds |
//! |---|---|
//! | `bin/.alias-image` | this box's own copy of the installed alias image, one inode per box |
//! | `bin/<name>` | one hard link to that image per interpreter name and per MCP server |
//! | `bin/.replaced-python` | the workspace, then the Python names a tool `replaces`, present only while one does |
//! | `private/alias-image.stamp` | the SHA-256 of the installed image the copy was taken from |

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use crate::error::{BoxError, ShellError};
use crate::record::layout::{ALIAS_IMAGE_FILE, BoxRoot};
use crate::run::lock::Lock;

/// The installed image's filename, which must sit beside the box executable.
const ALIAS_IMAGE_NAME: &str = "strands-box-sock-alias";

/// Place one alias per conventional shell name in the box's `bin/`.
///
/// The run lock proves no workload of this box is executing an alias name while one is replaced.
pub(crate) fn materialize(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
    owner: &Lock,
) -> Result<(), BoxError> {
    let installation = crate::run::installation::TrustedInstallation::load()?;
    let (installed, image) = installation.alias_image();
    materialize_opened(layout, servers, installed, image, owner)
}

/// `_owner` is the run lock as a token: `run` takes it before the first call and holds it until
/// the workload has exited.
fn materialize_opened(
    layout: &BoxRoot,
    servers: &[crate::record::config::mcp::McpServer],
    installed: &Path,
    source: &File,
    _owner: &Lock,
) -> Result<(), BoxError> {
    let materialize_error = |path: &Path, reason: String| ShellError::Materialize {
        path: path.to_path_buf(),
        reason,
    };
    let digest = image_digest(source).map_err(|error| {
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
            .install_private_image(source, &image, 0o500)
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
        .chain(std::iter::once(std::ffi::OsString::from(
            crate::run::broker::protocol::REPLACED_PYTHON_FILE,
        )))
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

/// Write the agent's workspace and the Python names a tool replaces beside the aliases, or remove
/// the file when no name is replaced.
///
/// Every `run` rewrites it from the record before the workload starts, so a Python alias reads the
/// names and the workspace of this run. `_owner` is the run lock, as for [`materialize`].
pub(crate) fn write_replaced_python(
    layout: &BoxRoot,
    replaced: &std::collections::BTreeSet<String>,
    workspace: &Path,
    _owner: &Lock,
) -> Result<(), BoxError> {
    let path = layout.replaced_python_file();
    let names: Vec<&str> = replaced
        .iter()
        .map(String::as_str)
        .filter(|name| crate::run::broker::protocol::PYTHON_ALIAS_NAMES.contains(name))
        .collect();
    if names.is_empty() {
        return layout.remove_file(&path);
    }
    let workspace = workspace
        .to_str()
        .filter(|text| workspace.is_absolute() && !text.contains('\n'))
        .ok_or_else(|| ShellError::Materialize {
            path: path.clone(),
            reason: format!(
                "the workspace {} must be an absolute UTF-8 path with no newline for a \
                 replaced Python alias to read it",
                workspace.display()
            ),
        })?;
    let mut contents = format!("{workspace}\n");
    for name in names {
        contents.push_str(name);
        contents.push('\n');
    }
    let limit = crate::run::broker::protocol::MAX_REPLACED_PYTHON_BYTES;
    if contents.len() > limit {
        return Err(ShellError::Materialize {
            path,
            reason: format!(
                "the workspace {workspace} is too long for a replaced Python alias to read: the \
                 file would be {} bytes, and the limit is {limit}",
                contents.len()
            ),
        }
        .into());
    }
    layout.write_private_file(&path, &contents, 0o444)
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
    let Ok(current) = crate::record::layout::open_without_following(installed)
        .and_then(|image| image_digest(&image))
    else {
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
fn image_digest(installed: &File) -> io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut offset = 0;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = installed.read_at(&mut buffer, offset)?;
        if read == 0 {
            return Ok(hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>());
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
    }
}

/// Find the shim beside the box's own executable, and nowhere else.
fn installed_image() -> Result<PathBuf, BoxError> {
    let current = crate::run::installation::executable().map_err(|source| ShellError::Missing {
        path: PathBuf::from(ALIAS_IMAGE_NAME),
        source,
    })?;
    installed_image_for(&current)
}

fn installed_image_for(current: &Path) -> Result<PathBuf, BoxError> {
    let installed = crate::run::installation::directory(current)
        .map(|directory| directory.join(ALIAS_IMAGE_NAME))
        .ok_or_else(|| ShellError::NotExecutable {
            path: current.to_path_buf(),
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
    use std::io::Seek as _;
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

    fn materialize_from(
        layout: &BoxRoot,
        servers: &[crate::record::config::mcp::McpServer],
        installed: &Path,
        owner: &Lock,
    ) -> Result<(), BoxError> {
        let source = crate::record::layout::open_without_following(installed)
            .expect("the fixture image opens");
        materialize_opened(layout, servers, installed, &source, owner)
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
            argument_wildcards: false,
            name: name.to_string(),
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

    #[test]
    fn materialization_uses_the_opened_image_after_its_path_is_replaced() {
        let (layout, owner, installed, _home) = fixture(b"opened image");
        let source = File::open(&installed).expect("the installed image opens");
        let digest = image_digest(&source).expect("the opened image hashes");
        std::fs::rename(&installed, installed.with_extension("retained"))
            .expect("the original image moves aside");
        write_image(&installed, b"replacement image");

        materialize_opened(&layout, &[], &installed, &source, &owner)
            .expect("the opened image materializes");

        assert_eq!(
            std::fs::read(layout.alias_image()).expect("the placed image reads"),
            b"opened image"
        );
        assert_eq!(
            layout
                .read_text(&layout.alias_stamp())
                .expect("the stamp reads"),
            digest
        );
        assert!(is_stale_against(&layout, &[], &installed));
        materialize_from(&layout, &[], &installed, &owner)
            .expect("a later materialization opens the replacement");
        assert_eq!(
            std::fs::read(layout.alias_image()).expect("the refreshed image reads"),
            b"replacement image"
        );
        assert!(!is_stale_against(&layout, &[], &installed));
    }

    #[test]
    fn materialization_reads_the_whole_image_without_changing_a_shared_offset() {
        let (layout, owner, installed, _home) = fixture(b"complete installed image");
        let source = File::open(&installed).expect("the installed image opens");
        let digest = image_digest(&source).expect("the whole image hashes");
        let mut shared = source.try_clone().expect("the descriptor clones");
        shared
            .seek(std::io::SeekFrom::Start(7))
            .expect("the shared offset advances");

        materialize_opened(&layout, &[], &installed, &source, &owner)
            .expect("the image materializes from its beginning");

        assert_eq!(
            std::fs::read(layout.alias_image()).expect("the image reads"),
            b"complete installed image"
        );
        assert_eq!(
            layout
                .read_text(&layout.alias_stamp())
                .expect("the stamp reads"),
            digest
        );
        assert_eq!(shared.stream_position().expect("the offset reads"), 7);
        assert_eq!(
            image_digest(&source).expect("the image hashes again"),
            digest
        );
        assert_eq!(shared.stream_position().expect("the offset stays"), 7);
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

    /// **The replaced-Python list holds only replaced Python names, is gone when no tool replaces
    /// one, and survives a `materialize` that cleans up unknown names.**
    #[test]
    fn the_replaced_python_list_follows_the_record_and_survives_materialize() {
        let (layout, owner, installed, _home) = fixture(b"image one");
        materialize_from(&layout, &[], &installed, &owner).expect("the aliases are placed");
        let list = layout.replaced_python_file();
        let names = |names: &[&str]| -> std::collections::BTreeSet<String> {
            names.iter().map(|name| (*name).to_string()).collect()
        };

        let workspace = Path::new("/work/project");

        write_replaced_python(
            &layout,
            &names(&["python3", "python", "curl"]),
            workspace,
            &owner,
        )
        .expect("the list is written");
        assert_eq!(
            std::fs::read_to_string(&list).expect("the list reads"),
            "/work/project\npython\npython3\n"
        );
        write_replaced_python(&layout, &names(&["python3"]), workspace, &owner)
            .expect("the list is rewritten");
        assert_eq!(
            std::fs::read_to_string(&list).expect("the list reads"),
            "/work/project\npython3\n"
        );

        materialize_from(&layout, &[], &installed, &owner).expect("the aliases are placed again");
        assert!(list.exists(), "materialize keeps the list");

        write_replaced_python(&layout, &names(&[]), workspace, &owner)
            .expect("the list is removed");
        assert!(!list.exists(), "no replaced name leaves no list");
        write_replaced_python(&layout, &names(&[]), workspace, &owner)
            .expect("removing it again is a no-op");
    }

    /// **A workspace the alias couldn't read back is refused** rather than written in part.
    #[test]
    fn the_replaced_python_list_refuses_a_workspace_it_cannot_write_as_one_line() {
        let (layout, owner, _installed, _home) = fixture(b"image one");
        let names: std::collections::BTreeSet<String> = ["python3".to_string()].into();

        let too_long = format!(
            "/{}",
            "a".repeat(crate::run::broker::protocol::MAX_REPLACED_PYTHON_BYTES)
        );
        for workspace in ["relative/project", "/work/two\nlines", too_long.as_str()] {
            write_replaced_python(&layout, &names, Path::new(workspace), &owner)
                .expect_err(workspace);
            assert!(!layout.replaced_python_file().exists(), "{workspace:?}");
        }
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

    #[test]
    fn cargo_alias_freshness_uses_the_same_installation_as_materialization() {
        let (layout, owner, installed, _home) = fixture(b"current profile image");
        let profile = installed.parent().expect("the installation directory");
        let dependencies = profile.join("deps");
        std::fs::create_dir(&dependencies).expect("the test binary directory");
        let stale_copy = dependencies.join(ALIAS_IMAGE_NAME);
        write_image(&stale_copy, b"earlier dependency image");
        let current = dependencies.join("strands_box-tests");
        let materialization_source = crate::run::installation::directory(&current)
            .expect("the helper installation directory")
            .join(ALIAS_IMAGE_NAME);
        materialize_from(&layout, &[], &materialization_source, &owner)
            .expect("the current profile image materializes");

        let freshness_source = installed_image_for(&current).expect("the installed alias image");
        assert!(!is_stale_against(&layout, &[], &freshness_source));
        assert_eq!(
            std::fs::read(layout.alias_image()).expect("the placed image reads"),
            b"current profile image"
        );
        write_image(&stale_copy, b"another dependency image");
        assert!(!is_stale_against(&layout, &[], &freshness_source));
        write_image(&installed, b"rebuilt profile image");
        assert!(is_stale_against(&layout, &[], &freshness_source));
        materialize_from(&layout, &[], &materialization_source, &owner)
            .expect("the rebuilt profile image materializes");
        assert!(!is_stale_against(&layout, &[], &freshness_source));
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
