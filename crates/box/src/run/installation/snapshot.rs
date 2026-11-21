//! Transfer the run's original installation inventory, without locating or reopening executables.
#![cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "Captured-storage authority transport is enabled only on Linux"
    )
)]

use std::collections::BTreeSet;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{InstalledBinary, TrustedInstallation};
use crate::error::BoxError;
use crate::run::commands::snapshot::{
    DescriptorSnapshot, OwnerVerifier, ReplicaVerifier, digest, invalid, validate_path,
};

const VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Main,
    Trampoline,
    SocketAlias,
    ApplicationWrapper,
    StorageCompiler,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinarySnapshot {
    role: Role,
    path: PathBuf,
    names: Vec<PathBuf>,
    identity: (u64, u64),
    descriptor: DescriptorSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    version: u32,
    binaries: Vec<BinarySnapshot>,
}

pub(crate) struct Export {
    pub(crate) manifest: Manifest,
    pub(crate) descriptors: Vec<File>,
    pub(crate) owner: Arc<Owner>,
}

pub(crate) struct Owner {
    original: Arc<TrustedInstallation>,
    descriptors: Vec<DescriptorSnapshot>,
    manifest_digest: [u8; 32],
}

impl Owner {
    pub(crate) fn verify(
        &self,
        descriptor: u32,
        manifest_digest: [u8; 32],
    ) -> Result<(), BoxError> {
        if manifest_digest != self.manifest_digest {
            return Err(invalid(
                "installation manifest differs from the original owner's snapshot",
            ));
        }
        let index = descriptor as usize;
        let binary = self
            .original
            .binaries
            .get(index)
            .ok_or_else(|| invalid("unknown original installation descriptor"))?;
        self.descriptors[index].verify_owner(&binary.opened)?;
        if !binary.unchanged_owner_state() {
            return Err(invalid(
                "original installation descriptor changed after export",
            ));
        }
        Ok(())
    }
}

impl OwnerVerifier for Owner {
    fn verify(&self, descriptor: u32, manifest_digest: [u8; 32]) -> Result<(), BoxError> {
        Self::verify(self, descriptor, manifest_digest)
    }
}

impl TrustedInstallation {
    /// Export all original roles. Ordinary installations need only the existing three roles.
    pub(crate) fn export_snapshot(self: &Arc<Self>) -> Result<Export, BoxError> {
        self.verify()?;
        let mut binaries = Vec::new();
        let mut files = Vec::new();
        for (index, binary) in self.binaries.iter().enumerate() {
            if binary.verification.is_some() {
                return Err(invalid(
                    "a compiler replica cannot export original installation authority",
                ));
            }
            let role = match index {
                0 => Role::Main,
                1 => Role::Trampoline,
                2 => Role::SocketAlias,
                _ if self.compiler_index == Some(index) => Role::StorageCompiler,
                3 => Role::ApplicationWrapper,
                _ => return Err(invalid("unknown original installation role")),
            };
            binaries.push(BinarySnapshot {
                role,
                path: binary.path.clone(),
                names: binary.names.clone(),
                identity: binary.identity,
                descriptor: DescriptorSnapshot::capture(index as u32, &binary.opened)?,
            });
            files.push(
                binary
                    .opened
                    .try_clone()
                    .map_err(|error| invalid(error.to_string()))?,
            );
        }
        let manifest = Manifest {
            version: VERSION,
            binaries,
        };
        manifest.validate()?;
        let manifest_digest = digest(&manifest)?;
        let descriptors = manifest
            .binaries
            .iter()
            .map(|binary| binary.descriptor.clone())
            .collect();
        let owner = Arc::new(Owner {
            original: Arc::clone(self),
            descriptors,
            manifest_digest,
        });
        Ok(Export {
            manifest,
            descriptors: files,
            owner,
        })
    }

    /// A storage-enabled controller must export an installation that pinned its compiler at load.
    pub(crate) fn export_snapshot_for_storage(self: &Arc<Self>) -> Result<Export, BoxError> {
        if self.compiler_index.is_none() {
            return Err(invalid(
                "storage compiler was not pinned by the original installation",
            ));
        }
        self.export_snapshot()
    }
}

impl Manifest {
    pub(crate) fn descriptor_count(&self) -> usize {
        self.binaries.len()
    }

    pub(crate) fn validate(&self) -> Result<(), BoxError> {
        if self.version != VERSION || !(3..=5).contains(&self.binaries.len()) {
            return Err(invalid(
                "unsupported installation snapshot version or role count",
            ));
        }
        let mut roles = BTreeSet::new();
        for (index, binary) in self.binaries.iter().enumerate() {
            let expected = match index {
                0 => Some(Role::Main),
                1 => Some(Role::Trampoline),
                2 => Some(Role::SocketAlias),
                _ => None,
            };
            if expected.is_some_and(|role| role != binary.role)
                || (index >= 3
                    && !matches!(
                        binary.role,
                        Role::ApplicationWrapper | Role::StorageCompiler
                    ))
                || (binary.role == Role::ApplicationWrapper && index != 3)
                || !roles.insert(binary.role)
                || binary.descriptor.index as usize != index
                || binary.identity != binary.descriptor.identity()
                || binary.names.is_empty()
                || binary.names.len() > 16 * 1024
                || binary.names.len() as u64 != binary.descriptor.links()
                || !binary.names.contains(&binary.path)
                || binary.names.iter().collect::<BTreeSet<_>>().len() != binary.names.len()
            {
                return Err(invalid(
                    "invalid or duplicate installation role, inventory, or descriptor index",
                ));
            }
            let filename = match binary.role {
                Role::Trampoline => Some("strands-box-contain-trampoline"),
                Role::SocketAlias => Some("strands-box-sock-alias"),
                Role::StorageCompiler => Some("strands-box-storage-compiler"),
                Role::ApplicationWrapper => Some("box"),
                Role::Main => None,
            };
            if filename
                .is_some_and(|name| binary.path.file_name() != Some(std::ffi::OsStr::new(name)))
            {
                return Err(invalid(
                    "installation role does not match its pinned program path",
                ));
            }
            validate_path(&binary.path)?;
            for name in &binary.names {
                validate_path(name)?;
            }
        }
        Ok(())
    }

    pub(crate) fn import(
        self,
        descriptors: Vec<File>,
        owner: Arc<dyn OwnerVerifier>,
    ) -> Result<TrustedInstallation, BoxError> {
        self.validate()?;
        if descriptors.len() != self.descriptor_count() {
            return Err(invalid(
                "installation descriptor count does not match its manifest",
            ));
        }
        let manifest_digest = digest(&self)?;
        let mut binaries = Vec::new();
        let mut compiler_index = None;
        for (index, (entry, opened)) in self.binaries.into_iter().zip(descriptors).enumerate() {
            if entry.role == Role::StorageCompiler {
                compiler_index = Some(index);
            }
            binaries.push(InstalledBinary {
                path: entry.path,
                names: entry.names,
                opened,
                identity: entry.identity,
                verification: Some(ReplicaVerifier::new(
                    entry.descriptor,
                    manifest_digest,
                    Arc::clone(&owner),
                )),
            });
        }
        let installation = TrustedInstallation {
            binaries,
            preparation: std::sync::Mutex::new(()),
            compiler_index,
        };
        installation.verify()?;
        Ok(installation)
    }
}

#[cfg(test)]
mod tests;
