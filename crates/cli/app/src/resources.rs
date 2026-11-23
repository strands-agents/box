use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::Error;

/// The variable that names the resource directory.
pub(crate) const VARIABLE: &str = "BOX_RESOURCES";

/// The file name of the profile editing guide in the resource directory.
pub(crate) const GUIDE: &str = "editing-box-profile.md";

/// The profile editing guide that ships in the resource directory `root`.
pub(crate) fn guide(root: &Path) -> Result<PathBuf, Error> {
    let path = root.join(GUIDE);
    if path.is_file() {
        Ok(path)
    } else {
        Err(Error::GuideMissing { path })
    }
}

/// The resource directory from the override, installed package, or debug source tree.
pub(crate) fn root() -> Result<PathBuf, Error> {
    root_from(
        std::env::var_os(VARIABLE),
        crate::installation::executable().ok().as_deref(),
    )
}

pub(crate) fn root_from(variable: Option<OsString>, exe: Option<&Path>) -> Result<PathBuf, Error> {
    let candidates: Vec<PathBuf> = match variable.filter(|value| !value.is_empty()) {
        Some(named) => vec![PathBuf::from(named)],
        None => exe
            .and_then(crate::installation::resources)
            .into_iter()
            .chain(cfg!(debug_assertions).then(source_tree))
            .collect(),
    };
    candidates
        .iter()
        .find(|candidate| candidate.join("packs").is_dir())
        .cloned()
        .ok_or_else(|| Error::Resources {
            looked: candidates
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        })
}

/// The `resources/` directory of this source tree.
pub(crate) fn source_tree() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .ancestors()
        .nth(3)
        .unwrap_or(crate_dir)
        .join("resources")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn an_app_bundle_uses_its_resource_directory_and_preserves_the_override() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let executable = root.join("Box.app/Contents/MacOS/box");
        let bundled = root.join("Box.app/Contents/Resources/resources");
        let sibling = root.join("Box.app/Contents/MacOS/resources");
        let override_root = root.join("override");
        for directory in [&bundled, &sibling, &override_root] {
            std::fs::create_dir_all(directory.join("packs")).unwrap();
        }
        assert_eq!(root_from(None, Some(&executable)).unwrap(), bundled);
        assert_eq!(
            root_from(Some(OsString::new()), Some(&executable)).unwrap(),
            bundled
        );
        assert_eq!(
            root_from(Some(override_root.into_os_string()), Some(&executable)).unwrap(),
            root.join("override")
        );
        assert!(
            root_from(
                Some(root.join("missing").into_os_string()),
                Some(&executable)
            )
            .is_err()
        );
    }

    #[test]
    fn the_installed_bundle_launcher_finds_resources_after_an_upgrade() {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::process::Command;

        const CHILD: &str = "BOX_TEST_RUNNING_BUNDLE";
        if let Some(directory) = std::env::var_os(CHILD) {
            let directory = PathBuf::from(directory);
            let resources = directory.join("old/Box.app/Contents/Resources/resources");
            assert_eq!(root().unwrap(), resources);
            assert_eq!(
                fs::read_to_string(guide(&resources).unwrap()).unwrap(),
                "old guide"
            );
            assert_eq!(
                crate::installation::executable().unwrap().parent().unwrap(),
                directory.join("old/Box.app/Contents/MacOS")
            );
            let mut host = crate::host::Host::current();
            host.set_home(directory.join("home"));
            assert!(
                crate::run::protected(&host, crate::run::install_root().as_deref(), &[])
                    .contains(&directory.join("old"))
            );
            fs::rename(directory.join("next"), directory.join("current")).unwrap();
            assert_eq!(root().unwrap(), resources);
            assert!(
                crate::run::protected(&host, crate::run::install_root().as_deref(), &[])
                    .contains(&directory.join("old"))
            );
            fs::write(directory.join("verified"), "").unwrap();
            return;
        }

        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        for release in ["old", "new"] {
            fs::create_dir_all(directory.join(release).join("Box.app/Contents/MacOS")).unwrap();
            let resources = directory
                .join(release)
                .join("Box.app/Contents/Resources/resources");
            fs::create_dir_all(resources.join("packs")).unwrap();
            fs::write(resources.join(GUIDE), format!("{release} guide")).unwrap();
        }
        fs::copy(
            std::env::current_exe().unwrap(),
            directory.join("old/Box.app/Contents/MacOS/box"),
        )
        .unwrap();
        let launcher = include_str!("../../../../scripts/macos-release-cli.py")
            .split_once("NATIVE_LAUNCHER = '''")
            .unwrap()
            .1
            .split_once("\n'''")
            .unwrap()
            .0;
        fs::write(directory.join("old/box"), format!("{launcher}\n")).unwrap();
        fs::set_permissions(directory.join("old/box"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("old", directory.join("current")).unwrap();
        symlink("new", directory.join("next")).unwrap();
        fs::create_dir(directory.join("bin")).unwrap();
        let command = directory.join("bin/box");
        symlink("../current/box", &command).unwrap();
        let output = Command::new(command)
            .args([
                "--exact",
                "resources::tests::the_installed_bundle_launcher_finds_resources_after_an_upgrade",
                "--nocapture",
            ])
            .env(CHILD, &directory)
            .env_remove(VARIABLE)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(directory.join("verified").is_file());
    }

    #[test]
    fn the_editing_guide_documents_every_input_declaration_key() {
        let guide = include_str!("../../../../resources/editing-box-profile.md");
        let section = guide
            .split_once("### Input declarations and values\n")
            .expect("the input reference")
            .1
            .split("\n### ")
            .next()
            .expect("the input section");
        let documented: BTreeSet<_> = section
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .map(|row| row.split('`').next().expect("a field name"))
            .collect();
        assert_eq!(
            documented,
            crate::lang::DECLARATION_KEYS.iter().copied().collect(),
            "keep the standalone editing guide's input table aligned with the parser"
        );
    }

    #[test]
    fn the_guide_is_a_file_in_the_resources_and_its_absence_names_the_path() {
        assert_eq!(guide(&source_tree()).unwrap(), source_tree().join(GUIDE));
        let empty = tempfile::tempdir().unwrap();
        std::fs::create_dir(empty.path().join(GUIDE)).unwrap();
        let error = guide(empty.path()).unwrap_err().to_string();
        assert!(
            error.contains(&empty.path().join(GUIDE).display().to_string()),
            "{error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn running_release_keeps_its_resources_and_protection_after_upgrade() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::process::Command;

        const CHILD: &str = "BOX_TEST_RUNNING_RELEASE";
        if let Some(directory) = std::env::var_os(CHILD) {
            let directory = PathBuf::from(directory);
            let old = directory.join("old");
            assert_eq!(root().unwrap(), old.join("resources"));
            fs::rename(directory.join("next"), directory.join("current")).unwrap();
            assert_eq!(root().unwrap(), old.join("resources"));
            let mut host = crate::host::Host::current();
            host.set_home(directory.join("home"));
            assert!(
                crate::run::protected(&host, crate::run::install_root().as_deref(), &[])
                    .contains(&old)
            );
            fs::write(directory.join("verified"), "").unwrap();
            return;
        }

        let temporary = tempfile::Builder::new()
            .prefix("box-release-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        for release in ["old", "new"] {
            fs::create_dir_all(directory.join(release).join("resources/packs")).unwrap();
        }
        fs::copy(std::env::current_exe().unwrap(), directory.join("old/box")).unwrap();
        fs::copy(directory.join("old/box"), directory.join("new/box")).unwrap();
        symlink("old", directory.join("current")).unwrap();
        symlink("new", directory.join("next")).unwrap();
        fs::create_dir(directory.join("bin")).unwrap();
        let command = directory.join("bin/box");
        symlink("../current/box", &command).unwrap();
        let output = Command::new(command)
            .args([
                "--exact",
                "resources::tests::running_release_keeps_its_resources_and_protection_after_upgrade",
                "--nocapture",
            ])
            .env(CHILD, &directory)
            .env_remove(VARIABLE)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(directory.join("verified").is_file());
    }

    #[test]
    fn the_source_tree_path_has_no_parent_steps() {
        let root = source_tree();
        assert!(
            root.components()
                .all(|part| part != std::path::Component::ParentDir),
            "{}",
            root.display()
        );
        assert!(root.join("packs").is_dir(), "{}", root.display());
    }

    #[test]
    fn every_shipped_pack_names_itself_after_its_folder() {
        let shared = source_tree().join("packs");
        let mut seen = 0;
        for entry in std::fs::read_dir(&shared).expect("the shipped packs") {
            let folder = entry.expect("an entry").path();
            let short = folder
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a name");
            let path = folder.join(crate::lang::PACK_FILE);
            let text = std::fs::read_to_string(&path).expect("a pack.toml in every folder");
            let table: toml::Table = toml::from_str(&text).expect("TOML");
            assert_eq!(
                table
                    .get("pack")
                    .and_then(|header| header.get("name"))
                    .and_then(toml::Value::as_str),
                Some(format!("{}{short}", crate::lang::VENDORED).as_str()),
                "{}",
                path.display()
            );
            seen += 1;
        }
        assert!(seen > 0, "no pack under {}", shared.display());
    }

    #[test]
    fn every_shipped_plugin_names_itself_after_its_folder() {
        let shipped = source_tree().join(crate::plugin::PLUGINS);
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&shipped).expect("the shipped plugins") {
            let folder = entry.expect("an entry").path();
            let short = folder
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a name");
            let path = folder.join(crate::plugin::PLUGIN_FILE);
            let text = std::fs::read_to_string(&path).expect("a plugin.toml in every folder");
            let table: toml::Table = toml::from_str(&text).expect("TOML");
            assert_eq!(
                table
                    .get(crate::plugin::HEADER)
                    .and_then(|header| header.get("name"))
                    .and_then(toml::Value::as_str),
                Some(format!("{}{short}", crate::lang::VENDORED).as_str()),
                "{}",
                path.display()
            );
            names.push(short.to_string());
        }
        names.sort();
        assert_eq!(names, ["1password", "aws-secrets-manager"]);
    }
}
