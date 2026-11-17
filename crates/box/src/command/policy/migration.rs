//! Offline history conversion while one existing box remains exclusively owned.

use std::fs::File;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use policy::{MigrationInput, MigrationTarget, PolicyMigration};

use crate::error::{BoxError, HistoryMigrationError};
use crate::record::config::HistoryMigrationConfig;
use crate::record::layout::{BoxRoot, open_without_following};
use crate::run::lock::Lock;

#[cfg(test)]
use crate::run::installation::HISTORY_MIGRATION_HELPER as LEGACY_HELPER;

pub(crate) fn migrate_history(config: &Path, to: &str, apply: bool) -> Result<ExitCode, BoxError> {
    let target = match to {
        "1.0.0" => MigrationTarget::Dogwood1_0_0,
        "1.1.2" => MigrationTarget::Dogwood1_1_2,
        target => {
            return Err(HistoryMigrationError::Target {
                target: target.to_owned(),
            }
            .into());
        }
    };
    let selection = HistoryMigrationConfig::read(config)?;
    let (root, _operation) = BoxRoot::lock_directory(selection.box_directory())?;
    if !root.is_configured() {
        return Err(HistoryMigrationError::NotConfigured {
            path: root.root().to_path_buf(),
        }
        .into());
    }
    let lock = root
        .open_lock_file(false)?
        .ok_or_else(|| HistoryMigrationError::MissingLock { path: root.lock() })?;
    let _owned = Lock::try_acquire_file(lock, &root.lock())?.ok_or_else(|| {
        HistoryMigrationError::Running {
            path: root.root().to_path_buf(),
        }
    })?;
    let history = root.open_existing_dogwood_database()?;
    root.verify_history_matches_record()?;
    let sources = selection.capture(&root)?;
    let helper = installed_helper()?;
    let input = MigrationInput::new(history, sources.policies.clone())
        .with_tool_grammars(sources.grammars.clone())
        .with_legacy_validator(helper);
    let migration = PolicyMigration::prepare_for(input, target)
        .map_err(|source| HistoryMigrationError::Policy { source })?;
    println!(
        "{}",
        serde_json::to_string_pretty(migration.summary())
            .map_err(|source| HistoryMigrationError::Summary { source })?
    );
    sources.verify()?;
    root.read_record()?;
    if migration.summary().already_completed {
        println!(
            "The history already targets Dogwood {to}. No conversion is needed. Start a compatible Box build."
        );
        return Ok(ExitCode::SUCCESS);
    }
    if !apply {
        println!(
            "Preparation complete. No policy or event records were changed. Keep Box stopped and repeat with --apply to convert this history."
        );
        return Ok(ExitCode::SUCCESS);
    }
    let (prepare, validate) = root.history_migration_scratch()?;
    let prepare_file = prepare
        .reopen()
        .map_err(|source| HistoryMigrationError::Scratch {
            path: prepare.path().to_path_buf(),
            source,
        })?;
    let validate_file = validate
        .reopen()
        .map_err(|source| HistoryMigrationError::Scratch {
            path: validate.path().to_path_buf(),
            source,
        })?;
    sources.verify()?;
    root.read_record()?;
    let summary = migration
        .apply(prepare_file, validate_file)
        .map_err(|source| HistoryMigrationError::Policy { source })?;
    println!(
        "History conversion complete: {}",
        serde_json::to_string(&summary)
            .map_err(|source| HistoryMigrationError::Summary { source })?
    );
    println!(
        "The history is ready for Dogwood {to}. Start a compatible Box build; this command does not replace the installed Box executable."
    );
    Ok(ExitCode::SUCCESS)
}

fn installed_helper() -> Result<File, BoxError> {
    let path = crate::run::installation::history_migration_helper()
        .map_err(|source| HistoryMigrationError::Executable { source })?;
    open_helper(&path)
}

fn open_helper(path: &Path) -> Result<File, BoxError> {
    let file = open_without_following(path).map_err(|source| HistoryMigrationError::Helper {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| HistoryMigrationError::Helper {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(HistoryMigrationError::InvalidHelper {
            path: path.to_path_buf(),
            required: "regular executable file",
        }
        .into());
    }
    let mut magic = [0; 4];
    file.read_exact_at(&mut magic, 0)
        .map_err(|source| HistoryMigrationError::Helper {
            path: path.to_path_buf(),
            source,
        })?;
    let native = if cfg!(target_os = "linux") {
        magic == *b"\x7fELF"
    } else if cfg!(target_os = "macos") {
        matches!(
            magic,
            [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
    } else {
        false
    };
    if !native {
        return Err(HistoryMigrationError::InvalidHelper {
            path: PathBuf::from(path),
            required: "native executable image for this platform",
        }
        .into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::record::config::{RECORD_VERSION, Record};

    struct Fixture {
        _temporary: tempfile::TempDir,
        config: PathBuf,
        directory: PathBuf,
    }

    impl Fixture {
        fn unconfigured() -> Self {
            let temporary = tempfile::tempdir().expect("temporary parent");
            let parent = temporary.path().canonicalize().expect("canonical parent");
            let directory = parent.join("state");
            std::fs::create_dir(&directory).expect("empty box directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let config = parent.join("box.toml");
            std::fs::write(
                &config,
                format!(
                    "name = \"migration\"\nbox_dir = {:?}\n",
                    directory.display().to_string()
                ),
            )
            .unwrap();
            Self {
                _temporary: temporary,
                config,
                directory,
            }
        }

        fn configured() -> Self {
            let fixture = Self::unconfigured();
            let (mut root, _operation) = BoxRoot::lock_directory(&fixture.directory).unwrap();
            root.settle_identity(None).unwrap();
            let record = Record::parse(&format!(
                "version = {RECORD_VERSION}\nbox_id = {:?}\nbox_dir = {:?}\nname = \"migration\"\n",
                root.box_id(), root.root().display().to_string(),
            ), &root.record()).unwrap();
            root.initialize_first_use(&record).unwrap();
            root.open_lock_file(true).unwrap().expect("ownership lock");
            root.open_dogwood_database()
                .unwrap()
                .write_all(b"history must not be opened during refusal controls")
                .unwrap();
            fixture
        }

        fn contents(&self) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            fn read(path: &Path, result: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
                for entry in std::fs::read_dir(path).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        read(&path, result);
                    } else {
                        result.insert(path.clone(), std::fs::read(path).unwrap());
                    }
                }
            }
            let mut files = std::collections::BTreeMap::new();
            read(&self.directory, &mut files);
            files
        }
    }

    #[test]
    fn an_unconfigured_directory_stays_empty() {
        let fixture = Fixture::unconfigured();
        let error = migrate_history(&fixture.config, "1.0.0", true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("existing configured box"), "{error}");
        assert_eq!(std::fs::read_dir(&fixture.directory).unwrap().count(), 0);
    }

    #[test]
    fn a_missing_box_directory_is_not_created() {
        let fixture = Fixture::unconfigured();
        std::fs::remove_dir(&fixture.directory).unwrap();
        assert!(migrate_history(&fixture.config, "1.1.2", true).is_err());
        assert!(!fixture.directory.exists());
    }

    #[test]
    fn a_running_box_is_refused_before_history_or_helper_open() {
        let fixture = Fixture::configured();
        let (root, operation) = BoxRoot::lock_directory(&fixture.directory).unwrap();
        let _running =
            Lock::try_acquire_file(root.open_lock_file(false).unwrap().unwrap(), &root.lock())
                .unwrap()
                .unwrap();
        drop(operation);
        let before = fixture.contents();
        let error = migrate_history(&fixture.config, "1.0.0", true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("while Box is running"), "{error}");
        assert_eq!(fixture.contents(), before);
    }

    #[test]
    fn an_existing_operation_excludes_migration() {
        let fixture = Fixture::configured();
        let (_root, _operation) = BoxRoot::lock_directory(&fixture.directory).unwrap();
        let before = fixture.contents();
        let error = migrate_history(&fixture.config, "1.1.2", false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("another strands-box operation"), "{error}");
        assert_eq!(fixture.contents(), before);
    }

    #[test]
    fn missing_or_empty_history_is_not_replaced() {
        for missing in [false, true] {
            let fixture = Fixture::configured();
            let history = fixture.directory.join("private/dogwood.redb");
            if missing {
                std::fs::remove_file(&history).unwrap();
            } else {
                std::fs::write(&history, []).unwrap();
            }
            let before = fixture.contents();
            let error = migrate_history(&fixture.config, "1.0.0", true)
                .unwrap_err()
                .to_string();
            assert!(error.contains("existing, nonempty history"), "{error}");
            assert_eq!(fixture.contents(), before);
            assert_eq!(history.exists(), !missing);
        }
    }

    #[test]
    fn helper_loading_refuses_missing_symlink_script_and_nonexecutable_images() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join(LEGACY_HELPER);
        assert!(open_helper(&helper).is_err());
        let native = directory.path().join("native");
        std::fs::write(&native, b"\x7fELFtest").unwrap();
        symlink(&native, &helper).unwrap();
        assert!(open_helper(&helper).is_err());
        std::fs::remove_file(&helper).unwrap();
        std::fs::write(&helper, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            open_helper(&helper)
                .unwrap_err()
                .to_string()
                .contains("native executable image")
        );
        std::fs::write(&helper, b"\x7fELFtest").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            open_helper(&helper)
                .unwrap_err()
                .to_string()
                .contains("regular executable file")
        );
    }
}
