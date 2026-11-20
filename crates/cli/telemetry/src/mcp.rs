use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{SFlag, fstatat};
use serde_json::Value;

use crate::source::open_at;

/// A resolved section of the harness configuration in storage.
#[derive(Debug, Clone, Copy)]
pub struct McpTarget<'a> {
    pub path: &'a Path,
    pub format: McpFormat,
    pub key: &'a [String],
}

#[derive(Debug, Clone, Copy)]
pub enum McpFormat {
    Json,
    Toml,
}

pub(crate) fn configured<'a>(
    home: &Path,
    targets: impl IntoIterator<Item = McpTarget<'a>>,
) -> Option<bool> {
    let mut result = Some(false);
    for target in targets {
        match target.configured(home) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => result = None,
        }
    }
    result
}

impl McpTarget<'_> {
    fn configured(&self, home: &Path) -> Option<bool> {
        let relative = self.path.strip_prefix(home).ok()?;
        let parts: Vec<_> = relative
            .components()
            .map(|part| match part {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect::<Option<_>>()?;
        let (name, parents) = parts.split_last()?;
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW).bits())
            .open(home)
            .ok()?;
        for parent in parents {
            directory = match open_at(&directory, parent, OFlag::O_DIRECTORY) {
                Ok(directory) => directory,
                Err(Errno::ENOENT) => return Some(false),
                Err(_) => return None,
            };
        }
        match fstatat(
            Some(directory.as_raw_fd()),
            *name,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(metadata)
                if SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT
                    == SFlag::S_IFREG
                    && metadata.st_nlink == 1 => {}
            Err(Errno::ENOENT) => return Some(false),
            _ => return None,
        }
        let mut file = open_at(&directory, name, OFlag::O_NONBLOCK).ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return None;
        }
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        let document: Value = match self.format {
            McpFormat::Json => serde_json::from_str(&text).ok()?,
            McpFormat::Toml => {
                serde_json::to_value(toml::from_str::<toml::Value>(&text).ok()?).ok()?
            }
        };
        let mut section = &document;
        for key in self.key {
            let table = section.as_object()?;
            let Some(inner) = table.get(key) else {
                return Some(false);
            };
            section = inner;
        }
        Some(!section.as_object()?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_mcp_configuration_reads_saved_json_and_toml_sections() {
        for format in [McpFormat::Json, McpFormat::Toml] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("storage/config");
            let target = McpTarget {
                path: &path,
                format,
                key: &["servers".into()],
            };
            assert_eq!(configured(root.path(), [target]), Some(false));
            assert!(!path.parent().unwrap().exists());
            std::fs::create_dir(path.parent().unwrap()).unwrap();
            assert_eq!(configured(root.path(), [target]), Some(false));
            let documents: &[(&str, Option<bool>)] = match format {
                McpFormat::Json => &[
                    ("{}", Some(false)),
                    (r#"{"servers": {}}"#, Some(false)),
                    (
                        r#"{"servers": {"saved": {"url": "https://saved.example.com"}}}"#,
                        Some(true),
                    ),
                    (r#"{"servers": false}"#, None),
                    ("[]", None),
                    ("invalid", None),
                ],
                McpFormat::Toml => &[
                    ("", Some(false)),
                    ("model = 'saved'\n", Some(false)),
                    ("[servers]\n", Some(false)),
                    (
                        "[servers.saved]\nurl = 'https://saved.example.com'\n",
                        Some(true),
                    ),
                    ("servers = false\n", None),
                    ("invalid", None),
                ],
            };
            for (text, expected) in documents {
                std::fs::write(&path, text).unwrap();
                assert_eq!(configured(root.path(), [target]), *expected, "{text}");
                assert_eq!(std::fs::read_to_string(&path).unwrap(), *text);
            }
            std::fs::write(&path, [0xff]).unwrap();
            assert_eq!(configured(root.path(), [target]), None);
        }
    }

    #[test]
    fn stored_mcp_configuration_uses_only_the_resolved_nested_section() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config");
        let target = McpTarget {
            path: &path,
            format: McpFormat::Json,
            key: &["projects".into(), "/current".into(), "mcpServers".into()],
        };
        for (text, expected) in [
            (
                r#"{"projects": {"/other": {"mcpServers": {"docs": {}}}}}"#,
                Some(false),
            ),
            (
                r#"{"projects": {"/current": {"mcpServers": {}}}}"#,
                Some(false),
            ),
            (
                r#"{"projects": {"/current": {"mcpServers": {"docs": {}}}}}"#,
                Some(true),
            ),
            (r#"{"projects": false}"#, None),
            (r#"{"projects": {"/current": null}}"#, None),
            (r#"{"projects": {"/current": {"mcpServers": []}}}"#, None),
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(configured(root.path(), [target]), expected, "{text}");
        }
    }

    #[test]
    fn stored_mcp_configuration_combines_known_and_unknown_sections() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config");
        std::fs::write(
            &path,
            r#"{"empty": {}, "present": {"docs": {}}, "invalid": false}"#,
        )
        .unwrap();
        for (keys, expected) in [
            (vec![], Some(false)),
            (vec!["missing", "empty"], Some(false)),
            (vec!["empty", "invalid"], None),
            (vec!["invalid", "present"], Some(true)),
            (vec!["present", "invalid"], Some(true)),
        ] {
            let keys: Vec<_> = keys.into_iter().map(|key| [key.to_string()]).collect();
            let targets = keys.iter().map(|key| McpTarget {
                path: &path,
                format: McpFormat::Json,
                key,
            });
            assert_eq!(configured(root.path(), targets), expected);
        }
    }

    #[test]
    fn stored_mcp_configuration_refuses_links_and_nonregular_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("storage/config");
        let target = McpTarget {
            path: &path,
            format: McpFormat::Json,
            key: &["servers".into()],
        };
        let parent = path.parent().unwrap();
        std::fs::create_dir(parent).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, r#"{"servers": {"secret": {}}}"#).unwrap();
        std::fs::write(&path, r#"{"servers": {"saved": {}}}"#).unwrap();
        assert_eq!(configured(root.path(), [target]), Some(true));
        std::fs::remove_file(&path).unwrap();
        for hard_link in [false, true] {
            if hard_link {
                std::fs::hard_link(&outside, &path).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, &path).unwrap();
            }
            assert_eq!(configured(root.path(), [target]), None);
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::create_dir(&path).unwrap();
        assert_eq!(configured(root.path(), [target]), None);
        std::fs::remove_dir(&path).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(configured(root.path(), [target]), None);
        drop(socket);
        std::fs::remove_file(&path).unwrap();
        let moved = root.path().join("moved");
        std::fs::rename(parent, &moved).unwrap();
        std::fs::write(moved.join("config"), r#"{"servers": {"secret": {}}}"#).unwrap();
        std::os::unix::fs::symlink(&moved, parent).unwrap();
        assert_eq!(configured(root.path(), [target]), None);
        std::fs::remove_file(parent).unwrap();
        std::fs::write(parent, "not a directory").unwrap();
        assert_eq!(configured(root.path(), [target]), None);
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            r#"{"servers": {"secret": {}}}"#
        );
    }
}
