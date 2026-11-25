//! Incoming mount declarations and their experimental feature selection.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;

use super::ExperimentalFeatures;
use super::process::{ProcessSpec, validate_path_spelling};

pub(super) fn validate_paths(paths: &[PathBuf], table: &str) -> Result<(), ConfigError> {
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

pub(super) fn validate_selection(
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
    if !features.linux_passthrough_mounts {
        return Err(refuse(
            "`filesystem.receive_mounts` requires `linux-passthrough-mounts = true` in `[experimental-features]`",
        ));
    }
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
    fn selection_requires_the_flag_and_checks_each_process_policy() {
        let mut spec = process(&["/mnt/data"]);
        let mut features = ExperimentalFeatures::default();
        for table in ["[agent]", "[tool.reader]", "[mcp.reader]"] {
            let error = validate_selection(&spec, table, &features).unwrap_err();
            assert!(error.to_string().contains(table));
            assert!(error.to_string().contains("linux-passthrough-mounts"));
        }
        features.linux_passthrough_mounts = true;
        validate_selection(&spec, "[agent]", &features).unwrap();
        features.native_filesystem_policy = true;
        assert!(validate_selection(&spec, "[agent]", &features).is_err());
        spec.native_filesystem_policy = Some(false);
        validate_selection(&spec, "[agent]", &features).unwrap();
        features.native_filesystem_policy = false;
        spec.native_filesystem_policy = Some(true);
        assert!(validate_selection(&spec, "[agent]", &features).is_err());
        validate_selection(&process(&[]), "[agent]", &features).unwrap();
    }

    #[test]
    fn loading_checks_each_table_and_keeps_forwarding_unavailable() {
        use super::super::ConfigFile;

        for (table, kind) in [
            ("agent", ""),
            ("tool.reader", ""),
            ("mcp.reader", "type = 'stdio'\n"),
        ] {
            let declaration = format!(
                "[{table}]\n{kind}command = ['reader']\n\
                 [{table}.filesystem]\nreceive_mounts = ['/mnt/data']\n"
            );
            let base = "name = 'mounts'\nbox_dir = '/tmp/box-mount-test'\n";
            let error = ConfigFile::parse(&format!("{base}{declaration}"), Path::new("box.toml"))
                .unwrap_err();
            assert!(
                matches!(error, ConfigError::Process { table: ref actual, .. } if actual == &format!("[{table}]"))
            );
            let enabled = format!(
                "{base}[experimental-features]\nlinux-passthrough-mounts = true\n{declaration}"
            );
            let error = ConfigFile::parse(&enabled, Path::new("box.toml")).unwrap_err();
            assert!(
                matches!(error, ConfigError::Contract { ref reason } if reason.contains("not available in this build"))
            );
            let malformed = enabled.replace("'/mnt/data'", "'/mnt/data', '/mnt/data/child'");
            let error = ConfigFile::parse(&malformed, Path::new("box.toml")).unwrap_err();
            assert!(
                matches!(error, ConfigError::Process { ref reason, .. } if reason.contains("overlap"))
            );
        }
        ConfigFile::parse(
            "name = 'ordinary'\nbox_dir = '/tmp/box-mount-test'\n\
             [experimental-features]\nlinux-passthrough-mounts = false\n\
             [agent]\ncommand = ['reader']\n",
            Path::new("box.toml"),
        )
        .unwrap();
        let flag_without_paths = "name = 'unavailable'\nbox_dir = '/tmp/box-mount-test'\n\
             [experimental-features]\nlinux-passthrough-mounts = true\n";
        assert!(matches!(
            ConfigFile::parse(flag_without_paths, Path::new("box.toml")),
            Err(ConfigError::Contract { .. })
        ));
        let unrecognized_spelling = "name = 'unrecognized'\nbox_dir = '/tmp/box-mount-test'\n\
             [agent]\ncommand = ['reader']\n[agent.filesystem]\nmounts = ['/mnt/data']\n";
        assert!(ConfigFile::parse(unrecognized_spelling, Path::new("box.toml")).is_err());
        for value in ["true", "false"] {
            let text = format!(
                "name = 'legacy'\nbox_dir = '/tmp/box-mount-test'\n\
                 [experimental-features]\nlinux-storage-mounts = {value}\n"
            );
            let error = ConfigFile::parse(&text, Path::new("box.toml")).unwrap_err();
            assert!(
                matches!(error, ConfigError::RemovedKey { key, .. } if key == "[experimental-features] linux-storage-mounts")
            );
        }
    }

    #[test]
    fn a_mount_request_refuses_startup_before_creating_box_state() {
        use super::super::RunContract;

        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let state = directory.path().join("box-state");
        let path = directory.path().join("box.toml");
        let ordinary = format!(
            "name = 'mounts'\nbox_dir = {:?}\n",
            state.display().to_string()
        );
        std::fs::write(
            &path,
            format!(
                "{ordinary}[experimental-features]\nlinux-passthrough-mounts = true\n\
                 [agent]\ncommand = ['reader']\n\
                 [agent.filesystem]\nreceive_mounts = ['/mnt/data']\n"
            ),
        )
        .unwrap();
        let error = RunContract::read(&path, &workspace)
            .err()
            .expect("must refuse");
        assert!(error.to_string().contains("not available in this build"));
        assert!(!state.exists());
        std::fs::write(&path, ordinary).unwrap();
        RunContract::read(&path, &workspace).unwrap();
        assert!(
            state.is_dir(),
            "the ordinary control reaches state creation"
        );
    }

    #[test]
    fn stored_mounts_require_their_version_and_keep_process_ownership() {
        use super::super::{MOUNTS_RECORD_VERSION, Record};

        let text = format!(
            "version = {MOUNTS_RECORD_VERSION}\n\
             box_id = 'box-0123456789abcdef'\nbox_dir = '/tmp/box-mount-test'\nname = 'mounts'\n\
             [experimental-features]\nlinux-passthrough-mounts = true\n\
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
        let mut flag_only = record.clone();
        flag_only
            .agent
            .as_mut()
            .unwrap()
            .filesystem
            .receive_mounts
            .clear();
        flag_only
            .tool
            .get_mut("reader")
            .unwrap()
            .filesystem
            .receive_mounts
            .clear();
        flag_only
            .contained_mcp
            .get_mut("local")
            .unwrap()
            .spec
            .filesystem
            .receive_mounts
            .clear();
        assert_eq!(
            Record::parse(&flag_only.to_toml().unwrap(), Path::new("record.toml")).unwrap(),
            flag_only
        );
        for table in ["[agent]", "[tool.reader]", "[mcp.local]"] {
            for native in [false, true] {
                let mut isolated = flag_only.clone();
                isolated.experimental_features.linux_passthrough_mounts = native;
                let spec = match table {
                    "[agent]" => isolated.agent.as_mut().unwrap(),
                    "[tool.reader]" => isolated.tool.get_mut("reader").unwrap(),
                    _ => &mut isolated.contained_mcp.get_mut("local").unwrap().spec,
                };
                spec.filesystem.receive_mounts = paths(&["/mnt/data"]);
                spec.native_filesystem_policy = Some(native);
                let error = Record::parse(&isolated.to_toml().unwrap(), Path::new("record.toml"))
                    .unwrap_err();
                let expected = if native {
                    "cannot be combined"
                } else {
                    "requires"
                };
                assert!(
                    matches!(error, ConfigError::Process { table: ref actual, ref reason }
                        if actual == table && reason.contains(expected)),
                    "{table}: {error}"
                );
            }
        }
    }
}
