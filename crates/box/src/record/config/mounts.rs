//! Incoming mount declarations and their platform and policy checks.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;

use super::ExperimentalFeatures;
use super::process::{ProcessSpec, validate_path_spelling};

pub(crate) fn validate_paths(paths: &[PathBuf], table: &str) -> Result<(), ConfigError> {
    let refuse = |reason| ConfigError::Process {
        table: table.into(),
        reason,
    };
    for (index, path) in paths.iter().enumerate() {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(refuse(format!(
                "`filesystem.receive_mounts` path {} must be an absolute directory path other than `/`",
                path.display()
            )));
        }
        validate_path_spelling("receive_mounts", path).map_err(refuse)?;
        if let Some(other) = paths[..index]
            .iter()
            .find(|other| path.starts_with(other) || other.starts_with(path))
        {
            return Err(refuse(format!(
                "`filesystem.receive_mounts` paths {} and {} overlap in the same process table",
                other.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_selection(
    spec: &ProcessSpec,
    table: &str,
    features: &ExperimentalFeatures,
) -> Result<(), ConfigError> {
    if spec.filesystem.receive_mounts.is_empty() {
        return Ok(());
    }
    let refuse = |reason: &str| ConfigError::Process {
        table: table.into(),
        reason: reason.into(),
    };
    if spec
        .native_filesystem_policy
        .unwrap_or(features.native_filesystem_policy)
    {
        return Err(refuse(
            "`filesystem.receive_mounts` cannot be combined with native filesystem policy checks in this build",
        ));
    }
    Ok(())
}

/// Non-Linux startup refuses the setting itself, including an explicitly empty list.
/// Stored records remain readable on every platform; only configuration loading calls this.
#[cfg(any(test, not(target_os = "linux")))]
pub(super) fn refuse_unsupported_config(text: &str, path: &Path) -> Result<(), ConfigError> {
    let document: toml::Value = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let check = |spec: &toml::Value, table: String| {
        if spec
            .get("filesystem")
            .and_then(toml::Value::as_table)
            .is_some_and(|filesystem| filesystem.contains_key("receive_mounts"))
        {
            Err(ConfigError::Process {
                table,
                reason:
                    "`filesystem.receive_mounts` is supported only on Linux; mount forwarding is \
                         not implemented on this platform. Remove this setting, including an empty \
                         list, to start Box"
                        .into(),
            })
        } else {
            Ok(())
        }
    };
    if let Some(agent) = document.get("agent") {
        check(agent, "[agent]".into())?;
    }
    for section in ["tool", "mcp"] {
        if let Some(entries) = document.get(section).and_then(toml::Value::as_table) {
            for (name, spec) in entries {
                check(spec, format!("[{section}.{name}]"))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::config::process::Filesystem;

    fn paths(entries: &[&str]) -> Vec<PathBuf> {
        entries.iter().map(PathBuf::from).collect()
    }

    fn process(mounts: &[&str]) -> ProcessSpec {
        let mut spec: ProcessSpec = toml::from_str("command = ['agent']").unwrap();
        spec.filesystem.receive_mounts = paths(mounts);
        spec
    }

    #[test]
    fn roots_are_absolute_literal_non_overlapping_paths() {
        for invalid in [
            "",
            "/",
            "/.",
            "relative",
            "~/data",
            "/mnt/../data",
            "/mnt/*",
            "/mnt/?",
            "/mnt/[data]",
            "/mnt/{data}",
            "/mnt/data\nother",
            "/mnt/data\0other",
        ] {
            assert!(
                validate_paths(&paths(&[invalid]), "[agent]").is_err(),
                "accepted {invalid:?}"
            );
        }
        for relative in ["data", "~/data"] {
            let error = validate_paths(&paths(&[relative]), "[agent]").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("must be an absolute directory path")
            );
            assert!(!error.to_string().contains("or start with"));
        }
        for entries in [
            ["/mnt/data", "/mnt/data"],
            ["/mnt/data", "/mnt/data/child"],
            ["/mnt/data/child", "/mnt/data"],
            ["/mnt/data", "/mnt//data/"],
            ["/mnt/data", "/mnt/./data"],
        ] {
            assert!(validate_paths(&paths(&entries), "[agent]").is_err());
        }
        validate_paths(
            &paths(&["/mnt/data", "/mnt/database", "/elsewhere"]),
            "[agent]",
        )
        .unwrap();
        validate_paths(&[], "[agent]").unwrap();
    }

    #[test]
    fn different_processes_may_select_the_same_path() {
        for table in ["[agent]", "[tool.reader]", "[mcp.reader]"] {
            validate_paths(&paths(&["/mnt/data"]), table).unwrap();
        }
    }

    #[test]
    fn mount_declarations_are_preserved_without_becoming_grants() {
        let filesystem: Filesystem = toml::from_str("receive_mounts = ['/mnt/data']").unwrap();
        assert!(!filesystem.is_empty());
        assert_eq!(filesystem.entries().count(), 0);
        let encoded = toml::to_string(&filesystem).unwrap();
        let decoded: Filesystem = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, filesystem);
        assert!(toml::to_string(&Filesystem::default()).unwrap().is_empty());
    }

    #[test]
    fn selection_needs_no_flag_and_checks_each_process_policy() {
        for table in ["[agent]", "[tool.reader]", "[mcp.reader]"] {
            let mut spec = process(&["/mnt/data"]);
            let mut features = ExperimentalFeatures::default();
            validate_selection(&spec, table, &features).unwrap();
            features.native_filesystem_policy = true;
            let error = validate_selection(&spec, table, &features).unwrap_err();
            assert!(error.to_string().contains(table));
            assert!(error.to_string().contains("cannot be combined"));
            spec.native_filesystem_policy = Some(false);
            validate_selection(&spec, table, &features).unwrap();
            features.native_filesystem_policy = false;
            spec.native_filesystem_policy = Some(true);
            assert!(validate_selection(&spec, table, &features).is_err());
            validate_selection(&process(&[]), table, &features).unwrap();
        }
    }

    fn declaration(table: &str, kind: &str, mounts: &str) -> String {
        format!(
            "[{table}]\n{kind}command = ['reader']\n\
             [{table}.filesystem]\nreceive_mounts = {mounts}\n"
        )
    }

    #[test]
    fn loading_checks_each_table_and_keeps_forwarding_unavailable() {
        use super::super::ConfigFile;

        for (table, kind) in [
            ("agent", ""),
            ("tool.reader", ""),
            ("mcp.reader", "type = 'stdio'\n"),
        ] {
            let base = "name = 'mounts'\nbox_dir = '/tmp/box-mount-test'\n";
            let text = format!("{base}{}", declaration(table, kind, "['/mnt/data']"));
            let error = ConfigFile::parse(&text, Path::new("box.toml")).unwrap_err();
            if cfg!(target_os = "linux") {
                assert!(matches!(error, ConfigError::Contract { ref reason }
                    if reason.contains("not available in this build")));
                let malformed = text.replace("'/mnt/data'", "'/mnt/data', '/mnt/data/child'");
                assert!(matches!(
                    ConfigFile::parse(&malformed, Path::new("box.toml")),
                    Err(ConfigError::Process { ref reason, .. }) if reason.contains("overlap")
                ));
            } else {
                assert!(
                    matches!(error, ConfigError::Process { table: ref actual, ref reason }
                    if actual == &format!("[{table}]") && reason.contains("only on Linux"))
                );
            }
            let empty = format!("{base}{}", declaration(table, kind, "[]"));
            let result = ConfigFile::parse(&empty, Path::new("box.toml"));
            assert_eq!(
                result.is_ok(),
                cfg!(target_os = "linux"),
                "{table}: {result:?}"
            );
            let omitted = empty.replace("receive_mounts = []\n", "");
            ConfigFile::parse(&omitted, Path::new("box.toml")).unwrap();
        }
        let unrecognized_spelling = "name = 'unrecognized'\nbox_dir = '/tmp/box-mount-test'\n\
             [agent]\ncommand = ['reader']\n[agent.filesystem]\nmounts = ['/mnt/data']\n";
        assert!(ConfigFile::parse(unrecognized_spelling, Path::new("box.toml")).is_err());
        for value in ["true", "false"] {
            let text = format!(
                "name = 'legacy'\nbox_dir = '/tmp/box-mount-test'\n\
                 [experimental-features]\nlinux-storage-mounts = {value}\n"
            );
            let error = ConfigFile::parse(&text, Path::new("box.toml")).unwrap_err();
            assert!(matches!(
                error,
                ConfigError::RemovedKey { key, replacement, .. }
                    if key == "[experimental-features] linux-storage-mounts"
                        && replacement.contains("remove this key")
                        && replacement.contains("not available in this build")
                        && !replacement.contains("linux-passthrough-mounts")
            ));
            let removed_flag = text.replace("linux-storage-mounts", "linux-passthrough-mounts");
            assert!(matches!(
                ConfigFile::parse(&removed_flag, Path::new("box.toml")),
                Err(ConfigError::Parse { .. })
            ));
        }
    }

    #[test]
    fn unsupported_platform_rejects_key_presence_including_empty_and_inline_tables() {
        for (table, kind) in [
            ("agent", ""),
            ("tool.reader", ""),
            ("mcp.reader", "type = 'stdio'\n"),
        ] {
            for mounts in ["[]", "['/mnt/data']"] {
                for text in [
                    declaration(table, kind, mounts),
                    format!(
                        "[{table}]\n{kind}command = ['reader']\nfilesystem = {{ receive_mounts = {mounts} }}"
                    ),
                    format!(
                        "[{table}]\n{kind}command = ['reader']\nfilesystem.receive_mounts = {mounts}"
                    ),
                ] {
                    assert!(
                        matches!(
                            refuse_unsupported_config(&text, Path::new("box.toml")),
                            Err(ConfigError::Process { table: ref actual, ref reason })
                                if actual == &format!("[{table}]") && reason.contains("only on Linux")
                        ),
                        "{text}"
                    );
                }
            }
        }
        for text in [
            "# receive_mounts = []\n[agent]\ncommand = ['receive_mounts = []']",
            "[agent.filesystem]\nread = ['/mnt/receive_mounts']",
            "[tool.receive_mounts]\ncommand = ['reader']",
            "[mcp.receive_mounts]\ntype = 'stdio'\ncommand = ['reader']",
        ] {
            refuse_unsupported_config(text, Path::new("box.toml")).unwrap();
        }
    }

    #[test]
    fn a_mount_request_refuses_startup_before_creating_box_state() {
        use super::super::RunContract;

        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        for (index, (table, kind)) in [
            ("agent", ""),
            ("tool.reader", ""),
            ("mcp.reader", "type = 'stdio'\n"),
        ]
        .into_iter()
        .enumerate()
        {
            let state = directory.path().join(format!("box-state-{index}"));
            let path = directory.path().join("box.toml");
            let ordinary = format!(
                "name = 'mounts'\nbox_dir = {:?}\n",
                state.display().to_string()
            );
            std::fs::write(
                &path,
                format!("{ordinary}{}", declaration(table, kind, "['/mnt/data']")),
            )
            .unwrap();
            let error = RunContract::read(&path, &workspace)
                .err()
                .expect("must refuse");
            let expected = if cfg!(target_os = "linux") {
                "not available in this build"
            } else {
                "only on Linux"
            };
            assert!(error.to_string().contains(expected), "{error}");
            assert!(!state.exists());
            if !cfg!(target_os = "linux") {
                std::fs::write(
                    &path,
                    format!("{ordinary}{}", declaration(table, kind, "[]")),
                )
                .unwrap();
                assert!(RunContract::read(&path, &workspace).is_err());
                assert!(!state.exists());
            }
            std::fs::write(&path, ordinary).unwrap();
            RunContract::read(&path, &workspace).unwrap();
            assert!(
                state.is_dir(),
                "the ordinary control reaches state creation"
            );
        }
    }

    #[test]
    fn stored_mounts_require_their_version_and_keep_process_ownership() {
        use super::super::{MOUNTS_RECORD_VERSION, Record};

        let text = format!(
            "version = {MOUNTS_RECORD_VERSION}\n\
             box_id = 'box-0123456789abcdef'\nbox_dir = '/tmp/box-mount-test'\nname = 'mounts'\n\
             [agent]\ncommand = ['agent']\n\
             [agent.filesystem]\nreceive_mounts = ['/mnt/data', '/mnt/agent-only']\n\
             read = ['/mnt/data', '/mnt/agent-only']\nwrite = ['/mnt/data', '/mnt/agent-only']\n\
             exec = ['/mnt/data', '/mnt/agent-only']\n\
             [tool.reader]\ncommand = ['reader']\n\
             [tool.reader.filesystem]\nreceive_mounts = ['/mnt/data']\n\
             read = ['/mnt/data']\nwrite = ['/mnt/data']\n\
             [[mcp]]\nname = 'local'\ncommand = ['local-server']\n\
             [contained_mcp.local.spec]\ncommand = ['local-server']\n\
             [contained_mcp.local.spec.filesystem]\nreceive_mounts = ['/mnt/server-only']\n"
        );
        let record = Record::parse(&text, Path::new("record.toml")).unwrap();
        assert_eq!(
            record
                .agent
                .as_ref()
                .unwrap()
                .filesystem
                .receive_mounts
                .len(),
            2
        );
        assert_eq!(
            record.tool["reader"].filesystem.receive_mounts,
            paths(&["/mnt/data"])
        );
        assert_eq!(
            record.contained_mcp["local"].spec.filesystem.receive_mounts,
            paths(&["/mnt/server-only"])
        );
        let encoded = record.to_toml().unwrap();
        assert_eq!(
            Record::parse(&encoded, Path::new("record.toml")).unwrap(),
            record
        );
        let old_stamp = text.replacen("version = 42", "version = 41", 1);
        assert!(matches!(
            Record::parse(&old_stamp, Path::new("record.toml")),
            Err(ConfigError::RecordVersion {
                expected: MOUNTS_RECORD_VERSION,
                ..
            })
        ));
        let mut empty_record = record.clone();
        empty_record
            .agent
            .as_mut()
            .unwrap()
            .filesystem
            .receive_mounts
            .clear();
        empty_record
            .tool
            .get_mut("reader")
            .unwrap()
            .filesystem
            .receive_mounts
            .clear();
        empty_record
            .contained_mcp
            .get_mut("local")
            .unwrap()
            .spec
            .filesystem
            .receive_mounts
            .clear();
        let error =
            Record::parse(&empty_record.to_toml().unwrap(), Path::new("record.toml")).unwrap_err();
        let ConfigError::RecordVersion { found, expected } = error else {
            panic!("expected a lower record version: {error}");
        };
        assert_eq!(found, MOUNTS_RECORD_VERSION);
        assert!(expected < MOUNTS_RECORD_VERSION);
        empty_record.version = expected;
        assert_eq!(
            Record::parse(&empty_record.to_toml().unwrap(), Path::new("record.toml")).unwrap(),
            empty_record
        );
        for table in ["[agent]", "[tool.reader]", "[mcp.local]"] {
            for native in [false, true] {
                let mut isolated = empty_record.clone();
                isolated.version = MOUNTS_RECORD_VERSION;
                let spec = match table {
                    "[agent]" => isolated.agent.as_mut().unwrap(),
                    "[tool.reader]" => isolated.tool.get_mut("reader").unwrap(),
                    _ => &mut isolated.contained_mcp.get_mut("local").unwrap().spec,
                };
                spec.filesystem.receive_mounts = paths(&["/mnt/data"]);
                spec.native_filesystem_policy = Some(native);
                let result = Record::parse(&isolated.to_toml().unwrap(), Path::new("record.toml"));
                if native {
                    assert!(
                        matches!(result, Err(ConfigError::Process { table: ref actual, ref reason })
                            if actual == table && reason.contains("cannot be combined")),
                        "{table}: {result:?}"
                    );
                } else {
                    assert_eq!(result.unwrap(), isolated);
                }
            }
        }
    }
}
