//! The MCP section imported into the agent's configuration when absent.

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use nix::libc;
use serde_json::{Map, Value};

use crate::error::Error;
use crate::files::{
    create_real_directory, io_error, metadata_at, open_at, open_directory, publish_at,
};
use crate::mcp::Format;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub path: PathBuf,
    pub kind: Format,
    /// The keys, one for each level, of the section that receives the servers.
    pub key: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub target: Target,
    pub(crate) servers: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    Empty,
    Imported,
    Kept,
    Different {
        missing: Vec<String>,
        changed: Vec<String>,
        extra: Vec<String>,
    },
    InvalidSection,
    Skipped,
}

/// An import's lock on its target directory, released when it drops.
struct ImportLock(std::fs::File);

impl Drop for ImportLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl Config {
    fn invalid(&self, reason: &str) -> Error {
        Error::Profile {
            path: self.target.path.clone(),
            line: None,
            reason: format!("cannot copy MCP configuration: {reason}"),
        }
    }

    fn text(&self) -> Result<String, Error> {
        let document = json_at_path(Map::new(), &self.target.key, self.servers.clone());
        match self.target.kind {
            Format::Json => serde_json::to_string_pretty(&document)
                .map_err(|_| self.invalid("the MCP section cannot be written as JSON")),
            Format::Toml => {
                let document = toml::Value::try_from(&document)
                    .map_err(|_| self.invalid("the MCP section cannot be written as TOML"))?;
                toml::to_string_pretty(&document)
                    .map_err(|_| self.invalid("the MCP section cannot be written as TOML"))
            }
        }
    }

    fn insert(&self, text: &str) -> Result<Option<String>, Error> {
        match self.target.kind {
            Format::Json => {
                let mut document: Map<String, Value> =
                    serde_json::from_str(text).map_err(|_| {
                        self.invalid(
                            "the target is not a JSON object; repair it or disable MCP import",
                        )
                    })?;
                if !json_insert(&mut document, &self.target.key, &self.servers) {
                    return Ok(None);
                }
                serde_json::to_string_pretty(&document)
                    .map(Some)
                    .map_err(|_| self.invalid("the MCP section cannot be written as JSON"))
            }
            Format::Toml => {
                let mut document: toml_edit::DocumentMut = text.parse().map_err(|_| {
                    self.invalid("the target is not valid TOML; repair it or disable MCP import")
                })?;
                let Some((last, parents)) = self.target.key.split_last() else {
                    return Ok(None);
                };
                let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
                let mut inline = false;
                for key in parents {
                    let item = table.entry(key).or_insert(if inline {
                        toml_edit::Item::Value(toml_edit::InlineTable::new().into())
                    } else {
                        toml_edit::Item::Table(toml_edit::Table::new())
                    });
                    inline |= item.is_inline_table();
                    let Some(inner) = item.as_table_like_mut() else {
                        return Ok(None);
                    };
                    table = inner;
                }
                let empty_default = !parents.is_empty()
                    && table
                        .get(last)
                        .and_then(toml_edit::Item::as_table_like)
                        .is_some_and(|section| section.is_empty());
                if table.contains_key(last) && !empty_default {
                    return Ok(None);
                }
                let mut imported: toml_edit::DocumentMut = self
                    .text()?
                    .parse()
                    .map_err(|_| self.invalid("the MCP section cannot be written as TOML"))?;
                let mut source = imported.as_table_mut();
                for key in parents {
                    source = source
                        .get_mut(key)
                        .and_then(toml_edit::Item::as_table_mut)
                        .ok_or_else(|| self.invalid("the MCP section cannot be written as TOML"))?;
                }
                let mut section = source
                    .remove(last)
                    .ok_or_else(|| self.invalid("the MCP section cannot be written as TOML"))?;
                if inline {
                    section =
                        toml_edit::Item::Value(section.into_value().map_err(|_| {
                            self.invalid("the MCP section cannot be written as TOML")
                        })?);
                } else if let Some(table) = section.as_table_mut() {
                    append_table(table);
                }
                table.insert(last, section);
                Ok(Some(document.to_string()))
            }
        }
    }

    fn compare(&self, text: &str) -> Result<Import, Error> {
        let document = self
            .target
            .kind
            .parse(text)
            .map_err(|_| self.invalid("the saved MCP section cannot be compared"))?;
        let mut section = &document;
        for key in &self.target.key {
            let Some(table) = section.as_object() else {
                return Ok(Import::InvalidSection);
            };
            let Some(inner) = table.get(key) else {
                return Ok(Import::Empty);
            };
            section = inner;
        }
        let Some(saved) = section.as_object() else {
            return Ok(Import::InvalidSection);
        };
        let mut missing = Vec::new();
        let mut changed = Vec::new();
        let mut extra = Vec::new();
        for (name, expected) in &self.servers {
            match saved.get(name) {
                None => missing.push(name.clone()),
                Some(actual) if actual != expected => changed.push(name.clone()),
                _ => {}
            }
        }
        for name in saved.keys() {
            if !self.servers.contains_key(name) {
                extra.push(name.clone());
            }
        }
        if missing.is_empty() && changed.is_empty() && extra.is_empty() {
            return Ok(Import::Kept);
        }
        missing.sort();
        changed.sort();
        extra.sort();
        Ok(Import::Different {
            missing,
            changed,
            extra,
        })
    }

    fn open_parent(&self, base: &Path, relative: &Path) -> Result<OwnedFd, Error> {
        let mut directory = open_directory(base).map_err(|e| io_error("open", base, e))?;
        for component in relative.parent().into_iter().flat_map(Path::components) {
            let Component::Normal(part) = component else {
                return Err(self.invalid(
                    "the target must use plain names below the folder that holds the box home",
                ));
            };
            let part = part
                .to_str()
                .ok_or_else(|| self.invalid("the target is not UTF-8"))?;
            directory = open_at(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map_err(|e| io_error("open", &self.target.path, e))?;
        }
        Ok(directory)
    }

    /// Import only when the target's MCP key is absent.
    pub fn copy_if_absent(&self, base: &Path, run: &Path) -> Result<Import, Error> {
        if self.servers.is_empty() {
            return Ok(Import::Empty);
        }
        let path = &self.target.path;
        let parent = path
            .parent()
            .ok_or_else(|| self.invalid("the target needs a parent directory"))?;
        let relative = path.strip_prefix(base).map_err(|_| {
            self.invalid("the target must be below the folder that holds the box home")
        })?;
        let name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| self.invalid("the target needs a file name"))?;
        create_real_directory(parent, base)?;
        let directory = self.open_parent(base, relative)?;
        let lock = std::fs::File::from(
            directory
                .try_clone()
                .map_err(|e| io_error("open", parent, e))?,
        );
        let _held = match lock.try_lock() {
            Ok(()) => ImportLock(lock),
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(
                    self.invalid("another import is using this directory; retry after it finishes")
                );
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(io_error("lock", parent, error));
            }
        };
        match metadata_at(&directory, name) {
            Ok(metadata)
                if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 =>
            {
                return Ok(Import::Skipped);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("inspect", path, error)),
        }
        let previous = match open_at(&directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(file) => {
                let mut file = std::fs::File::from(file);
                let metadata = file.metadata().map_err(|e| io_error("read", path, e))?;
                if !metadata.is_file() || metadata.nlink() != 1 {
                    return Ok(Import::Skipped);
                }
                let mut text = String::new();
                file.read_to_string(&mut text)
                    .map_err(|e| io_error("read", path, e))?;
                Some((metadata, text))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Ok(Import::Skipped),
            Err(error) => return Err(io_error("open", path, error)),
        };
        let text = match &previous {
            Some((_, text)) => match self.insert(text)? {
                Some(text) => text,
                None => return self.compare(text),
            },
            None => self.text()?,
        };
        let mut staged =
            tempfile::NamedTempFile::new_in(run).map_err(|e| io_error("create", path, e))?;
        staged
            .write_all(text.as_bytes())
            .map_err(|e| io_error("write", path, e))?;
        if let Some((metadata, _)) = &previous {
            staged
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(metadata.mode() & 0o777))
                .map_err(|e| io_error("write", path, e))?;
        }
        self.publish(&directory, name, &staged, previous.as_ref())?;
        Ok(Import::Imported)
    }

    fn publish(
        &self,
        directory: &OwnedFd,
        name: &str,
        staged: &tempfile::NamedTempFile,
        previous: Option<&(std::fs::Metadata, String)>,
    ) -> Result<(), Error> {
        let changed = || {
            self.invalid(
            "the target changed during import; stop other runs of this profile, in every project, and retry"
        )
        };
        if let Some((before, text)) = previous {
            let file = open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
                .map_err(|_| changed())?;
            let mut file = std::fs::File::from(file);
            let now = file.metadata().map_err(|_| changed())?;
            if !now.is_file()
                || now.nlink() != 1
                || now.dev() != before.dev()
                || now.ino() != before.ino()
                || now.mode() != before.mode()
            {
                return Err(changed());
            }
            let mut current = String::new();
            file.read_to_string(&mut current).map_err(|_| changed())?;
            if current != *text {
                return Err(changed());
            }
        }
        publish_at(staged.path(), directory, name, previous.is_some()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                changed()
            } else {
                io_error("copy", &self.target.path, error)
            }
        })
    }
}

/// `document` with `servers` at `path`.
fn json_at_path(
    mut document: Map<String, Value>,
    path: &[String],
    servers: Map<String, Value>,
) -> Map<String, Value> {
    json_insert(&mut document, path, &servers);
    document
}

/// Insert `servers` at `path` in `document` when the path is absent, creating each missing table,
/// and whether it was inserted. A parent that is not a table, or a present section, stops it. Below
/// the top level, an empty section counts as absent, because the agent writes one by default.
fn json_insert(
    document: &mut Map<String, Value>,
    path: &[String],
    servers: &Map<String, Value>,
) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return false;
    };
    let mut map = document;
    for key in parents {
        let Value::Object(inner) = map
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()))
        else {
            return false;
        };
        map = inner;
    }
    let empty_default = !parents.is_empty()
        && map
            .get(last)
            .is_some_and(|section| section == &Value::Object(Map::new()));
    if map.contains_key(last) && !empty_default {
        return false;
    }
    map.insert(last.clone(), Value::Object(servers.clone()));
    true
}

fn append_table(table: &mut toml_edit::Table) {
    table.set_position(Some(isize::MAX));
    table.decor_mut().set_prefix("\n");
    for (_, item) in table.iter_mut() {
        match item {
            toml_edit::Item::Table(table) => append_table(table),
            toml_edit::Item::ArrayOfTables(tables) => {
                for table in tables.iter_mut() {
                    append_table(table);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, kind: Format) -> Config {
        Config {
            target: Target {
                path: root.join("storage/config"),
                kind,
                key: vec!["servers".into()],
            },
            servers: serde_json::from_value(serde_json::json!({
                "docs": {"url": "https://docs.example.com"}
            }))
            .unwrap(),
        }
    }

    #[test]
    fn import_skips_a_socket_target() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path(), Format::Json);
        std::fs::create_dir(root.path().join("storage")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(&config.target.path).unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Skipped
        );
        use std::os::unix::fs::FileTypeExt as _;
        assert!(
            std::fs::symlink_metadata(&config.target.path)
                .unwrap()
                .file_type()
                .is_socket()
        );
    }

    #[test]
    fn import_refuses_an_intermediate_parent_replaced_after_preflight() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), Format::Json);
        config.target.path = root.path().join("storage/agent/config");
        create_real_directory(config.target.path.parent().unwrap(), root.path()).unwrap();
        std::fs::create_dir(outside.path().join("agent")).unwrap();
        std::fs::rename(
            root.path().join("storage"),
            root.path().join("original-storage"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("storage")).unwrap();

        let relative = config.target.path.strip_prefix(root.path()).unwrap();
        assert!(config.open_parent(root.path(), relative).is_err());
    }

    #[test]
    fn import_fills_a_missing_section_and_preserves_agent_settings() {
        for (kind, before) in [
            (
                Format::Json,
                r#"{"onboarded":true,"projects":{"work":{"trusted":true}}}"#,
            ),
            (
                Format::Toml,
                "# Agent settings\nonboarded = true\n[projects.work]\ntrusted = true # keep me\n",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), kind);
            std::fs::create_dir(root.path().join("storage")).unwrap();
            std::fs::write(&config.target.path, before).unwrap();
            std::fs::set_permissions(&config.target.path, std::fs::Permissions::from_mode(0o640))
                .unwrap();
            config.copy_if_absent(root.path(), root.path()).unwrap();
            assert_eq!(
                std::fs::metadata(&config.target.path).unwrap().mode() & 0o777,
                0o640
            );
            let text = std::fs::read_to_string(&config.target.path).unwrap();
            let document: Value = match kind {
                Format::Json => serde_json::from_str(&text).unwrap(),
                Format::Toml => {
                    assert!(text.contains("# Agent settings"));
                    assert!(text.contains("trusted = true # keep me"));
                    serde_json::to_value(toml::from_str::<toml::Table>(&text).unwrap()).unwrap()
                }
            };
            assert_eq!(
                document,
                serde_json::json!({
                    "onboarded": true,
                    "projects": {"work": {"trusted": true}},
                    "servers": {"docs": {"url": "https://docs.example.com"}}
                })
            );
        }
    }

    #[test]
    fn import_keeps_toml_server_tables_together_after_agent_settings() {
        let mut config = config(Path::new("/unused"), Format::Toml);
        config.target.key = vec!["mcp_servers".into()];
        config.servers = serde_json::from_value(serde_json::json!({
            "docs": {
                "url": "https://docs.example.com",
                "http_headers": {"X-Client": "agent"},
                "extra": [{"name": "saved"}]
            },
            "local": {"command": "server"}
        }))
        .unwrap();
        let before = r#"# Agent settings
model = "saved"

[projects."/work"]
trust_level = "trusted"

[notice]
hide = true # keep me

[features]
enabled = true

[ui]
theme = "dark"
"#;
        let expected = format!(
            r#"{before}
[mcp_servers.docs]
url = "https://docs.example.com"

[[mcp_servers.docs.extra]]
name = "saved"

[mcp_servers.docs.http_headers]
X-Client = "agent"

[mcp_servers.local]
command = "server"
"#
        );
        assert_eq!(config.insert(before).unwrap().unwrap(), expected);
        assert_eq!(config.insert(&expected).unwrap(), None);
    }

    #[test]
    fn import_preserves_an_existing_section_even_when_empty_or_not_a_table() {
        for (kind, before) in [
            (Format::Json, "{ \"servers\": {}, \"model\": \"saved\" }\n"),
            (Format::Json, "{ \"servers\": null }\n"),
            (Format::Toml, "# opted out\n[servers]\n"),
            (Format::Toml, "servers = {}\n"),
            (Format::Toml, "servers = false\n"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), kind);
            std::fs::create_dir(root.path().join("storage")).unwrap();
            std::fs::write(&config.target.path, before).unwrap();
            config.copy_if_absent(root.path(), root.path()).unwrap();
            assert_eq!(
                std::fs::read_to_string(&config.target.path).unwrap(),
                before
            );
        }
    }

    #[test]
    fn import_compares_sections_without_rewriting_or_reporting_values() {
        for kind in [Format::Json, Format::Toml] {
            let root = tempfile::tempdir().unwrap();
            let mut config = config(root.path(), kind);
            config.servers = serde_json::from_value(serde_json::json!({
                "docs": {"url": "https://docs.example.com", "headers": {"Token": "private-key"}},
                "local": {"command": "first"}
            }))
            .unwrap();
            std::fs::create_dir(root.path().join("storage")).unwrap();
            for (section, expected) in [
                (
                    serde_json::json!({"local": {"command": "first"}, "docs": {"headers": {"Token": "private-key"}, "url": "https://docs.example.com"}}),
                    Import::Kept,
                ),
                (
                    serde_json::json!({"local": {"command": "first"}, "docs": {"url": "https://changed.example.com"}, "saved\nonly": {"url": "https://private.example.com"}}),
                    Import::Different {
                        missing: vec![],
                        changed: vec!["docs".into()],
                        extra: vec!["saved\nonly".into()],
                    },
                ),
                (
                    serde_json::json!({"local": {"command": "first"}, "docs": {"url": "https://docs.example.com", "headers": {"Token": "changed-private-key"}}}),
                    Import::Different {
                        missing: vec![],
                        changed: vec!["docs".into()],
                        extra: vec![],
                    },
                ),
                (
                    serde_json::json!({"local": {"command": "second"}, "docs": {"url": "https://docs.example.com", "headers": {"Token": "private-key"}}}),
                    Import::Different {
                        missing: vec![],
                        changed: vec!["local".into()],
                        extra: vec![],
                    },
                ),
                (
                    serde_json::json!({}),
                    Import::Different {
                        missing: vec!["docs".into(), "local".into()],
                        changed: vec![],
                        extra: vec![],
                    },
                ),
                (serde_json::json!(false), Import::InvalidSection),
            ] {
                let document =
                    serde_json::json!({"unrelated": "private-setting", "servers": section});
                let text = match kind {
                    Format::Json => serde_json::to_string_pretty(&document).unwrap(),
                    Format::Toml => {
                        format!("# saved comment\n{}", toml::to_string(&document).unwrap())
                    }
                };
                std::fs::write(&config.target.path, &text).unwrap();
                let outcome = config.copy_if_absent(root.path(), root.path()).unwrap();
                assert_eq!(outcome, expected);
                let report = format!("{outcome:?}");
                for private in [
                    "private-key",
                    "private-setting",
                    "private.example.com",
                    "changed.example.com",
                ] {
                    assert!(!report.contains(private), "{report}");
                }
                assert_eq!(std::fs::read_to_string(&config.target.path).unwrap(), text);
            }
        }
    }

    #[test]
    fn an_empty_import_leaves_saved_targets_alone() {
        for kind in [Format::Json, Format::Toml] {
            let root = tempfile::tempdir().unwrap();
            let mut config = config(root.path(), kind);
            config.servers.clear();
            assert_eq!(
                config.copy_if_absent(root.path(), root.path()).unwrap(),
                Import::Empty
            );
            assert!(!config.target.path.parent().unwrap().exists());
            std::fs::create_dir(root.path().join("storage")).unwrap();
            let documents: &[&str] = match kind {
                Format::Json => &[
                    "",
                    "{ broken",
                    "{}",
                    r#"{"servers":{"old":{"url":"https://private.example.com"}}}"#,
                ],
                Format::Toml => &[
                    "model = \n",
                    "# saved\nmodel = 'saved'\n",
                    "[servers.old]\nurl = 'https://private.example.com'\n",
                ],
            };
            for text in documents {
                std::fs::write(&config.target.path, text).unwrap();
                assert_eq!(
                    config.copy_if_absent(root.path(), root.path()).unwrap(),
                    Import::Empty
                );
                assert_eq!(std::fs::read_to_string(&config.target.path).unwrap(), *text);
            }
            std::fs::remove_file(&config.target.path).unwrap();
            let outside = root.path().join("saved");
            std::fs::write(&outside, "private").unwrap();
            for hard_link in [false, true] {
                if hard_link {
                    std::fs::hard_link(&outside, &config.target.path).unwrap();
                } else {
                    std::os::unix::fs::symlink(&outside, &config.target.path).unwrap();
                }
                assert_eq!(
                    config.copy_if_absent(root.path(), root.path()).unwrap(),
                    Import::Empty
                );
                assert_eq!(std::fs::read_to_string(&outside).unwrap(), "private");
                std::fs::remove_file(&config.target.path).unwrap();
            }
            std::fs::create_dir(&config.target.path).unwrap();
            assert_eq!(
                config.copy_if_absent(root.path(), root.path()).unwrap(),
                Import::Empty
            );
            assert!(config.target.path.is_dir());
        }
    }

    #[test]
    fn import_refuses_invalid_documents_without_overwriting_or_printing_them() {
        for (kind, before) in [
            (Format::Json, "private-invalid-content"),
            (Format::Json, "[]"),
            (Format::Toml, "secret = private-invalid-content"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), kind);
            std::fs::create_dir(root.path().join("storage")).unwrap();
            std::fs::write(&config.target.path, before).unwrap();
            let error = config.copy_if_absent(root.path(), root.path()).unwrap_err();
            assert!(error.to_string().contains("cannot copy MCP configuration"));
            assert!(!error.to_string().contains("private-invalid-content"));
            assert_eq!(
                std::fs::read_to_string(&config.target.path).unwrap(),
                before
            );
        }
    }

    #[test]
    fn import_refuses_a_target_changed_before_publication() {
        for change in ["contents", "replacement", "permissions", "hard link"] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), Format::Json);
            let parent = root.path().join("storage");
            std::fs::create_dir(&parent).unwrap();
            std::fs::write(&config.target.path, "{}").unwrap();
            let previous = (
                std::fs::metadata(&config.target.path).unwrap(),
                "{}".to_string(),
            );
            let directory = open_directory(&parent).unwrap();
            let mut staged = tempfile::NamedTempFile::new_in(root.path()).unwrap();
            staged.write_all(config.text().unwrap().as_bytes()).unwrap();
            let agent = if change == "contents" {
                r#"{"saved":true}"#
            } else {
                "{}"
            };
            match change {
                "replacement" => {
                    let replacement = root.path().join("replacement");
                    std::fs::write(&replacement, agent).unwrap();
                    std::fs::rename(replacement, &config.target.path).unwrap();
                }
                "permissions" => {
                    std::fs::set_permissions(
                        &config.target.path,
                        std::fs::Permissions::from_mode(0o400),
                    )
                    .unwrap();
                }
                "hard link" => {
                    std::fs::hard_link(&config.target.path, root.path().join("alias")).unwrap();
                }
                _ => std::fs::write(&config.target.path, agent).unwrap(),
            }
            let error = config
                .publish(&directory, "config", &staged, Some(&previous))
                .unwrap_err();
            assert!(error.to_string().contains("target changed during import"));
            assert_eq!(std::fs::read_to_string(&config.target.path).unwrap(), agent);
        }
    }

    #[test]
    fn import_never_replaces_a_concurrently_created_target() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path(), Format::Json);
        let parent = root.path().join("storage");
        std::fs::create_dir(&parent).unwrap();
        let directory = open_directory(&parent).unwrap();
        let mut staged = tempfile::NamedTempFile::new_in(root.path()).unwrap();
        staged.write_all(config.text().unwrap().as_bytes()).unwrap();
        let agent = r#"{"saved":true}"#;
        std::fs::write(&config.target.path, agent).unwrap();
        assert!(config.publish(&directory, "config", &staged, None).is_err());
        assert_eq!(std::fs::read_to_string(&config.target.path).unwrap(), agent);
    }

    #[test]
    fn import_publication_stays_in_the_opened_directory() {
        for existing in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), Format::Json);
            let parent = root.path().join("storage");
            let outside = root.path().join("outside");
            let moved = root.path().join("moved");
            std::fs::create_dir(&parent).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("config"), "private").unwrap();
            let previous = existing.then(|| {
                std::fs::write(&config.target.path, "{}").unwrap();
                (
                    std::fs::metadata(&config.target.path).unwrap(),
                    "{}".to_string(),
                )
            });
            let directory = open_directory(&parent).unwrap();
            let mut staged = tempfile::NamedTempFile::new_in(root.path()).unwrap();
            let imported = config.text().unwrap();
            staged.write_all(imported.as_bytes()).unwrap();
            std::fs::rename(&parent, &moved).unwrap();
            std::os::unix::fs::symlink(&outside, &parent).unwrap();
            config
                .publish(&directory, "config", &staged, previous.as_ref())
                .unwrap();
            assert_eq!(
                std::fs::read_to_string(outside.join("config")).unwrap(),
                "private"
            );
            assert_eq!(
                std::fs::read_to_string(moved.join("config")).unwrap(),
                imported
            );
        }
    }

    #[test]
    fn import_refuses_another_imports_directory_lock() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path(), Format::Json);
        let parent = root.path().join("storage");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(&config.target.path, "{}").unwrap();
        let lock = std::fs::File::open(&parent).unwrap();
        lock.try_lock().unwrap();
        let error = config.copy_if_absent(root.path(), root.path()).unwrap_err();
        assert!(error.to_string().contains("another import"));
        assert_eq!(std::fs::read_to_string(&config.target.path).unwrap(), "{}");
        lock.unlock().unwrap();
        config.copy_if_absent(root.path(), root.path()).unwrap();
        assert!(
            std::fs::read_to_string(&config.target.path)
                .unwrap()
                .contains("servers")
        );
    }

    #[test]
    fn import_fills_a_nested_section_and_compares_a_present_one_by_its_own_path() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), Format::Json);
        config.target.key = vec!["projects".into(), "/w".into(), "mcpServers".into()];
        std::fs::create_dir_all(root.path().join("storage")).unwrap();
        let path = root.path().join("storage/config");
        std::fs::write(
            &path,
            r#"{"projects": {"/other": {"mcpServers": {}}}, "theme": "dark"}"#,
        )
        .unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Imported
        );
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written,
            serde_json::json!({
                "projects": {
                    "/other": {"mcpServers": {}},
                    "/w": {"mcpServers": {"docs": {"url": "https://docs.example.com"}}},
                },
                "theme": "dark",
            })
        );
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Kept
        );
        let saved = r#"{"mcpServers": {"docs": {"url": "https://top.example.com"}}, "projects": {"/w": {"mcpServers": {"docs": {"url": "https://changed.example.com"}}}}}"#;
        std::fs::write(&path, saved).unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Different {
                missing: vec![],
                changed: vec!["docs".into()],
                extra: vec![],
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);
        std::fs::write(&path, r#"{"projects": "not a table"}"#).unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::InvalidSection
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"projects": "not a table"}"#
        );
    }

    #[test]
    fn import_writes_a_nested_toml_section_into_an_inline_table_parent() {
        for before in [
            "projects = { \"/w\" = { trust = true } }\n",
            "[projects]\n\"/w\" = { trust = true }\n",
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut config = config(root.path(), Format::Toml);
            config.target.key = vec!["projects".into(), "/w".into(), "mcp_servers".into()];
            std::fs::create_dir_all(root.path().join("storage")).unwrap();
            let path = root.path().join("storage/config");
            std::fs::write(&path, before).unwrap();
            assert_eq!(
                config.copy_if_absent(root.path(), root.path()).unwrap(),
                Import::Imported,
                "{before}"
            );
            let written: toml::Value =
                toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(
                written["projects"]["/w"],
                toml::toml! {
                    trust = true
                    [mcp_servers.docs]
                    url = "https://docs.example.com"
                }
                .into(),
                "{before}"
            );
            assert_eq!(
                config.copy_if_absent(root.path(), root.path()).unwrap(),
                Import::Kept,
                "{before}"
            );
        }
    }

    #[test]
    fn import_writes_a_nested_toml_section_into_a_new_file() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), Format::Toml);
        config.target.key = vec!["profiles".into(), "w".into(), "mcp_servers".into()];
        std::fs::create_dir_all(root.path().join("storage")).unwrap();
        config.copy_if_absent(root.path(), root.path()).unwrap();
        let written: toml::Table =
            toml::from_str(&std::fs::read_to_string(root.path().join("storage/config")).unwrap())
                .unwrap();
        assert_eq!(
            written["profiles"]["w"]["mcp_servers"]["docs"]["url"].as_str(),
            Some("https://docs.example.com")
        );
    }

    #[test]
    fn import_fills_a_nested_toml_section_in_an_existing_file_and_keeps_the_rest() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), Format::Toml);
        config.target.key = vec!["profiles".into(), "w".into(), "mcp_servers".into()];
        std::fs::create_dir_all(root.path().join("storage")).unwrap();
        let path = root.path().join("storage/config");
        std::fs::write(&path, "model = \"o3\" # kept\n\n[profiles.other]\nx = 1\n").unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Imported
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# kept"), "{text}");
        let written: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(written["model"].as_str(), Some("o3"));
        assert_eq!(written["profiles"]["other"]["x"].as_integer(), Some(1));
        assert_eq!(
            written["profiles"]["w"]["mcp_servers"]["docs"]["url"].as_str(),
            Some("https://docs.example.com")
        );
        assert!(written.get("mcp_servers").is_none());
    }

    #[test]
    fn import_fills_a_project_section_that_claude_code_left_empty_but_keeps_an_empty_top_level_one()
    {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), Format::Json);
        config.target.key = vec!["projects".into(), "/w".into(), "mcpServers".into()];
        std::fs::create_dir_all(root.path().join("storage")).unwrap();
        let path = root.path().join("storage/config");
        let default = serde_json::json!({"projects": {"/w": {
            "allowedTools": [], "mcpContextUris": [], "mcpServers": {},
            "enabledMcpjsonServers": [], "hasTrustDialogAccepted": false,
        }}});
        std::fs::write(&path, default.to_string()).unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Imported
        );
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written,
            serde_json::json!({"projects": {"/w": {
                "allowedTools": [], "mcpContextUris": [],
                "mcpServers": {"docs": {"url": "https://docs.example.com"}},
                "enabledMcpjsonServers": [], "hasTrustDialogAccepted": false,
            }}})
        );

        config.target.key = vec!["servers".into()];
        std::fs::write(&path, r#"{"servers": {}}"#).unwrap();
        assert_eq!(
            config.copy_if_absent(root.path(), root.path()).unwrap(),
            Import::Different {
                missing: vec!["docs".into()],
                changed: vec![],
                extra: vec![],
            }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"servers": {}}"#
        );
    }
}
