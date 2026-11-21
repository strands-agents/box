//! Declared storage attachment points. These names confer no filesystem permissions.

use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ExperimentalFeatures;
use crate::error::ConfigError;

/// Runtime-owned filesystems whose contents require asynchronous Box admission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Storage {
    #[serde(default)]
    pub(crate) mounts: Vec<PathBuf>,
}

impl Storage {
    pub(crate) fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Validate names without inspecting storage that may not have arrived yet.
    pub(crate) fn validate(
        &self,
        features: &ExperimentalFeatures,
        box_directory: &Path,
    ) -> Result<(), ConfigError> {
        if !self.mounts.is_empty() && !features.linux_storage_mounts {
            return Err(refuse(
                "set `linux-storage-mounts = true` in `[experimental-features]` to declare mounts",
            ));
        }
        for (index, root) in self.mounts.iter().enumerate() {
            if !root.is_absolute()
                || root == Path::new("/")
                || root.as_os_str().as_bytes().contains(&0)
                || root
                    .as_os_str()
                    .as_bytes()
                    .split(|byte| *byte == b'/')
                    .any(|part| part == b"." || part == b"..")
            {
                return Err(refuse(format!(
                    "mount {} must be an absolute directory path other than /, without . or ..",
                    root.display()
                )));
            }
            if self.mounts[..index]
                .iter()
                .any(|other| root.starts_with(other) || other.starts_with(root))
            {
                return Err(refuse(format!(
                    "mount {} repeats or overlaps another declared mount",
                    root.display()
                )));
            }
            if root.starts_with(box_directory) || box_directory.starts_with(root) {
                return Err(refuse(format!(
                    "mount {} overlaps the Box state directory {}",
                    root.display(),
                    box_directory.display()
                )));
            }
        }
        Ok(())
    }
}

fn refuse(reason: impl Into<String>) -> ConfigError {
    ConfigError::Storage {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected() -> ExperimentalFeatures {
        ExperimentalFeatures {
            linux_storage_mounts: true,
            ..Default::default()
        }
    }

    #[test]
    fn declarations_do_not_require_available_storage_or_grant_access() {
        let storage: Storage =
            toml::from_str("mounts = [\"/mnt/box-test-absent-a\", \"/mnt/box-test-absent-b\"]")
                .unwrap();
        storage
            .validate(&selected(), Path::new("/var/lib/box"))
            .unwrap();
        assert_eq!(storage.mounts.len(), 2);
        assert!(Storage::default().is_empty());
    }

    #[test]
    fn mounts_require_selection_and_safe_nonoverlapping_names() {
        for roots in [
            vec!["relative"],
            vec!["/"],
            vec!["/mnt/../data"],
            vec!["/mnt/./data"],
            vec!["/mnt/data", "/mnt/data"],
            vec!["/mnt/data", "/mnt/data/child"],
            vec!["/mnt/data/child", "/mnt/data"],
            vec!["/var/lib"],
            vec!["/var/lib/box/child"],
        ] {
            let storage = Storage {
                mounts: roots.iter().map(PathBuf::from).collect(),
            };
            assert!(
                storage
                    .validate(&selected(), Path::new("/var/lib/box"))
                    .is_err(),
                "{roots:?}"
            );
        }
        let storage = Storage {
            mounts: vec![PathBuf::from("/mnt/data")],
        };
        assert!(
            storage
                .validate(&ExperimentalFeatures::default(), Path::new("/var/lib/box"))
                .is_err()
        );
        assert!(toml::from_str::<Storage>("mounts = []\npermissions = 'all'").is_err());
    }
}
