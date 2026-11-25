//! Opened directory identities selected for Linux mount propagation, without access grants.

use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ContainmentError;
use crate::model::ObjectIdentity;
#[cfg(target_os = "linux")]
use crate::model::ObjectPin;

/// A source selected by a caller that already approved this directory's permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "ReceivingMountWire")]
pub(crate) struct ReceivingMount {
    path: PathBuf,
    identity: ObjectIdentity,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pin: ObjectPin,
}

/// The identity is mandatory: a new selection must never adopt a replacement object at load.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivingMountWire {
    path: PathBuf,
    identity: ObjectIdentity,
}

impl ReceivingMount {
    pub(crate) fn from_opened(path: &Path, directory: &File) -> crate::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, directory);
            Err(unsupported())
        }
        #[cfg(target_os = "linux")]
        {
            let metadata = directory.metadata().map_err(|error| failure(path, error))?;
            if !metadata.is_dir() {
                return Err(ContainmentError::ExpectedDirectory(path.to_path_buf()));
            }
            let identity = ObjectIdentity::from_metadata(&metadata);
            let pin = ObjectPin::from_file(
                directory
                    .try_clone()
                    .map_err(|error| failure(path, error))?,
            )
            .map_err(|error| failure(path, error))?;
            let source = Self {
                path: path.to_path_buf(),
                identity,
                pin,
            };
            source.validate_live_identity()?;
            Ok(source)
        }
    }

    pub(crate) fn require_disjoint(&self, previous: &[Self]) -> crate::Result<()> {
        if previous.iter().any(|source| {
            self.path.starts_with(&source.path) || source.path.starts_with(&self.path)
        }) {
            return Err(ContainmentError::ConfigValidation(format!(
                "invalid or overlapping incoming mount path '{}'",
                self.path.display()
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_live_identity(&self) -> crate::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported())
        }
        #[cfg(target_os = "linux")]
        {
            let current = open_current(&self.path)?;
            let metadata = current
                .metadata()
                .map_err(|error| failure(&self.path, error))?;
            if ObjectIdentity::from_metadata(&metadata) != self.identity {
                return Err(ContainmentError::ConfigValidation(format!(
                    "incoming mount '{}' changed after its directory was approved",
                    self.path.display()
                )));
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn identity(&self) -> ObjectIdentity {
        self.identity
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn pin(&self) -> &ObjectPin {
        &self.pin
    }
}

impl TryFrom<ReceivingMountWire> for ReceivingMount {
    type Error = ContainmentError;

    fn try_from(wire: ReceivingMountWire) -> crate::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (wire.path, wire.identity);
            Err(unsupported())
        }
        #[cfg(target_os = "linux")]
        {
            let current = open_current(&wire.path)?;
            let source = Self::from_opened(&wire.path, &current)?;
            if source.identity != wire.identity {
                return Err(ContainmentError::ConfigValidation(format!(
                    "incoming mount '{}' changed after its directory was approved",
                    wire.path.display()
                )));
            }
            Ok(source)
        }
    }
}

pub(crate) fn deserialize_sources<'de, D>(deserializer: D) -> Result<Vec<ReceivingMount>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let sources = Vec::<ReceivingMount>::deserialize(deserializer)?;
    for (index, source) in sources.iter().enumerate() {
        source
            .require_disjoint(&sources[..index])
            .map_err(serde::de::Error::custom)?;
    }
    Ok(sources)
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> ContainmentError {
    ContainmentError::ConfigValidation(
        "incoming mount forwarding is supported only on Linux".to_string(),
    )
}

#[cfg(target_os = "linux")]
fn failure(path: &Path, error: std::io::Error) -> ContainmentError {
    ContainmentError::ConfigValidation(format!(
        "cannot inspect approved incoming mount '{}': {error}",
        path.display()
    ))
}

#[cfg(target_os = "linux")]
fn open_current(path: &Path) -> crate::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(ContainmentError::ConfigValidation(format!(
            "incoming mount '{}' must be a canonical absolute directory other than '/'",
            path.display()
        )));
    }
    let canonical = path.canonicalize().map_err(|error| failure(path, error))?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err(ContainmentError::ConfigValidation(format!(
            "incoming mount '{}' must name its canonical directory",
            path.display()
        )));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| failure(path, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContainmentConfig;

    #[test]
    fn omitted_and_empty_receiving_sources_keep_the_existing_config() {
        let config = ContainmentConfig::new().to_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&config).unwrap();
        assert!(value.get("receiving_mounts").is_none());
        ContainmentConfig::from_json(&config).unwrap();
        value["receiving_mounts"] = serde_json::json!([]);
        let restored = ContainmentConfig::from_json(&value.to_string()).unwrap();
        assert_eq!(restored.to_json().unwrap(), config);
    }

    #[cfg(target_os = "linux")]
    fn fixture() -> (tempfile::TempDir, PathBuf, File) {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().canonicalize().unwrap().join("selected");
        std::fs::create_dir(&path).unwrap();
        let directory = File::open(&path).unwrap();
        (temporary, path, directory)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiving_sources_roundtrip_without_creating_permission_grants() {
        let (_temporary, path, directory) = fixture();
        let config = ContainmentConfig::new()
            .receive_mounts_from(&path, &directory)
            .unwrap();
        drop(directory);
        let json = config.to_json().unwrap();
        let restored = ContainmentConfig::from_json(&json).unwrap();
        assert_eq!(restored.to_json().unwrap(), json);
        assert!(restored.authorizations().is_empty());
        assert_eq!(restored.receiving_mounts().len(), 1);
        assert_eq!(restored.receiving_mounts()[0].path(), path);
        restored.require_live_path_identities().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiving_sources_refuse_replacement_before_handoff_reload_and_apply() {
        let (_temporary, path, directory) = fixture();
        let config = ContainmentConfig::new()
            .receive_mounts_from(&path, &directory)
            .unwrap();
        let json = config.to_json().unwrap();
        std::fs::rename(&path, path.with_file_name("approved-object")).unwrap();
        std::fs::create_dir(&path).unwrap();
        for error in [
            ContainmentConfig::new()
                .receive_mounts_from(&path, &directory)
                .unwrap_err(),
            ContainmentConfig::from_json(&json).unwrap_err(),
            config.require_live_path_identities().unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("changed after its directory was approved"),
                "{error}"
            );
        }
        let replacement = File::open(&path).unwrap();
        ContainmentConfig::new()
            .receive_mounts_from(&path, &replacement)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiving_source_wire_requires_identity_and_valid_directory_paths() {
        let (_temporary, path, directory) = fixture();
        let config = ContainmentConfig::new()
            .receive_mounts_from(&path, &directory)
            .unwrap();
        let original: serde_json::Value = serde_json::from_str(&config.to_json().unwrap()).unwrap();
        for field in ["identity", "path"] {
            let mut value = original.clone();
            value["receiving_mounts"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                ContainmentConfig::from_json(&value.to_string()).is_err(),
                "missing {field}"
            );
        }
        for field in ["device", "inode", "kind"] {
            let mut value = original.clone();
            value["receiving_mounts"][0]["identity"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                ContainmentConfig::from_json(&value.to_string()).is_err(),
                "missing identity.{field}"
            );
        }
        let mut changed = original.clone();
        changed["receiving_mounts"][0]["identity"]["inode"] = serde_json::json!(0);
        assert!(
            ContainmentConfig::from_json(&changed.to_string())
                .unwrap_err()
                .to_string()
                .contains("changed after")
        );
        let mut extra = original.clone();
        extra["receiving_mounts"][0]["grant"] = serde_json::json!("write");
        assert!(ContainmentConfig::from_json(&extra.to_string()).is_err());
        let alias = path.with_file_name("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        for invalid in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            alias,
            path.join("."),
        ] {
            let mut value = original.clone();
            value["receiving_mounts"][0]["path"] = serde_json::json!(invalid);
            assert!(
                ContainmentConfig::from_json(&value.to_string()).is_err(),
                "{}",
                invalid.display()
            );
        }
        let regular = path.join("file");
        std::fs::write(&regular, b"not a directory").unwrap();
        let file = File::open(&regular).unwrap();
        assert!(matches!(
            ContainmentConfig::new().receive_mounts_from(&regular, &file),
            Err(ContainmentError::ExpectedDirectory(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiving_source_overlap_is_refused_by_builder_and_wire() {
        let (_temporary, path, directory) = fixture();
        let nested = path.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let child = File::open(&nested).unwrap();
        let first = ContainmentConfig::new()
            .receive_mounts_from(&path, &directory)
            .unwrap();
        let second = ContainmentConfig::new()
            .receive_mounts_from(&nested, &child)
            .unwrap();
        for result in [
            first.clone().receive_mounts_from(&nested, &child),
            second.clone().receive_mounts_from(&path, &directory),
            first.clone().receive_mounts_from(&path, &directory),
        ] {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("overlapping incoming mount")
            );
        }
        let a: serde_json::Value = serde_json::from_str(&first.to_json().unwrap()).unwrap();
        let b: serde_json::Value = serde_json::from_str(&second.to_json().unwrap()).unwrap();
        for pair in [
            serde_json::json!([a["receiving_mounts"][0], b["receiving_mounts"][0]]),
            serde_json::json!([b["receiving_mounts"][0], a["receiving_mounts"][0]]),
            serde_json::json!([a["receiving_mounts"][0], a["receiving_mounts"][0]]),
        ] {
            let mut config = a.clone();
            config["receiving_mounts"] = pair;
            assert!(
                ContainmentConfig::from_json(&config.to_string())
                    .unwrap_err()
                    .to_string()
                    .contains("overlapping incoming mount")
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn receiving_sources_are_refused_on_other_platforms() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let error = ContainmentConfig::new()
            .receive_mounts_from(temporary.path(), &directory)
            .unwrap_err();
        assert!(error.to_string().contains("supported only on Linux"));
        let mut config: serde_json::Value =
            serde_json::from_str(&ContainmentConfig::new().to_json().unwrap()).unwrap();
        config["receiving_mounts"] = serde_json::json!([{"path": "/selected", "identity": {"device": 1, "inode": 1, "kind": 16384}}]);
        assert!(
            ContainmentConfig::from_json(&config.to_string())
                .unwrap_err()
                .to_string()
                .contains("supported only on Linux")
        );
    }
}
