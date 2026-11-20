//! Confirm the container's own empty directory scaffolds and kernel null device.
//! All data-bearing grants, including executables, must name the same open object in both views.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use containment::{BackendOverride, ContainmentConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ANCHORS: [&str; 4] = ["/", "/etc", "/var", "/dev/null"];

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    kind: u32,
}

struct Anchors {
    identities: [Identity; 4],
    _pins: [File; 4],
}

fn invalid(reason: &str) -> io::Error {
    io::Error::other(reason)
}

impl Anchors {
    fn open() -> io::Result<Self> {
        let mut pins = Vec::new();
        let mut identities = Vec::new();
        for path in ANCHORS {
            let pin = File::options()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(path)?;
            let meta = pin.metadata()?;
            let kind = meta.mode() & libc::S_IFMT;
            if (path == "/dev/null"
                && (kind != libc::S_IFCHR || meta.rdev() != libc::makedev(1, 3)))
                || (path != "/dev/null" && kind != libc::S_IFDIR)
                || Path::new(path).canonicalize()? != Path::new(path)
            {
                return Err(invalid("invalid container runtime anchor"));
            }
            identities.push(Identity {
                device: meta.dev(),
                inode: meta.ino(),
                kind,
            });
            pins.push(pin);
        }
        Ok(Self {
            identities: identities
                .try_into()
                .map_err(|_| invalid("incomplete anchor identities"))?,
            _pins: pins
                .try_into()
                .map_err(|_| invalid("incomplete anchor pins"))?,
        })
    }
}

// Only these directory entries lower to empty scaffolds. No read root, executable,
// projected credential or writable directory may receive a container-local identity.
fn target_config(
    source: &str,
    local: &[Identity; 4],
    expected: Option<&[Identity; 4]>,
) -> io::Result<String> {
    let mut config: Value = serde_json::from_str(source)?;
    let grants = config["paths"]
        .as_array_mut()
        .ok_or_else(|| invalid("missing grants"))?;
    for grant in grants {
        if grant["operation"] == "deny" {
            continue;
        }
        let stamp: Identity = serde_json::from_value(grant["identity"].clone())?;
        if grant["original"] != grant["resolved"] {
            continue;
        }
        let index = match (
            grant["original"].as_str(),
            grant["operation"].as_str(),
            grant["scope"].as_str(),
        ) {
            (Some("/"), Some("read"), Some("dir")) => 0,
            (Some("/etc"), Some("metadata"), Some("dir")) => 1,
            (Some("/var"), Some("metadata"), Some("dir")) => 2,
            (Some("/dev/null"), Some("read" | "write"), Some("file")) => 3,
            _ => continue,
        };
        if local[index].kind != stamp.kind || expected.is_some_and(|ids| ids[index] != stamp) {
            return Err(invalid(
                "container anchor does not match the approved object",
            ));
        }
        grant["identity"] = serde_json::to_value(local[index])?;
    }
    Ok(serde_json::to_string(&config)?)
}

pub(super) fn approve(stream: &mut UnixStream, source: &str) -> io::Result<()> {
    let validated = ContainmentConfig::from_json(source).map_err(io::Error::other)?;
    if !matches!(
        validated.backend_override(),
        BackendOverride::LinuxContainer
    ) {
        return Err(invalid("expected container backend"));
    }
    let anchors = Anchors::open()?;
    let mut len = [0; 2];
    stream.read_exact(&mut len)?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > 1024 {
        return Err(invalid("invalid container anchor receipt length"));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    let received: [Identity; 4] = serde_json::from_slice(&bytes)?;
    let target = target_config(source, &received, Some(&anchors.identities))?;
    stream.write_all(&Sha256::digest(target.as_bytes()))
}

pub(super) fn load(source: &str, lifetime: BorrowedFd<'_>) -> io::Result<ContainmentConfig> {
    let anchors = Anchors::open()?;
    let target = target_config(source, &anchors.identities, None)?;
    // Load every grant and acquire its final pin before releasing the original anchors.
    let checked = ContainmentConfig::from_json(&target).map_err(io::Error::other)?;
    if !matches!(checked.backend_override(), BackendOverride::LinuxContainer) {
        return Err(invalid("expected container backend"));
    }
    let mut stream = UnixStream::from(lifetime.as_fd().try_clone_to_owned()?);
    let timeout = Some(Duration::from_secs(20));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let receipt = serde_json::to_vec(&anchors.identities)?;
    let len = u16::try_from(receipt.len()).map_err(io::Error::other)?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&receipt)?;
    let mut ack = [0; 32];
    stream.read_exact(&mut ack)?;
    if ack[..] != Sha256::digest(target.as_bytes())[..] {
        return Err(invalid(
            "supervisor did not approve this container configuration",
        ));
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use containment::{Operation, Scope};

    #[test]
    fn both_launchers_must_approve_the_same_configuration() {
        let config = ContainmentConfig::new()
            .with_backend_override(BackendOverride::LinuxContainer)
            .allow("/", Operation::Read, Scope::Dir)
            .unwrap();
        let source = config.to_json().unwrap();
        let (mut supervisor, workload) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| approve(&mut supervisor, &source).unwrap());
            load(&source, workload.as_fd()).unwrap();
        });

        let (mut peer, workload) = UnixStream::pair().unwrap();
        peer.write_all(&[0; 32]).unwrap();
        assert!(
            load(&source, workload.as_fd())
                .unwrap_err()
                .to_string()
                .contains("did not approve")
        );
    }

    #[test]
    fn replacing_a_shared_directory_prevents_the_receipt() {
        let tree = tempfile::tempdir().unwrap();
        let shared = tree.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let config = ContainmentConfig::new()
            .with_backend_override(BackendOverride::LinuxContainer)
            .allow("/", Operation::Read, Scope::Dir)
            .unwrap()
            .allow(&shared, Operation::Read, Scope::Root)
            .unwrap();
        let source = config.to_json().unwrap();
        std::fs::rename(&shared, tree.path().join("old")).unwrap();
        std::fs::create_dir(&shared).unwrap();
        let (_supervisor, workload) = UnixStream::pair().unwrap();
        assert!(
            load(&source, workload.as_fd())
                .unwrap_err()
                .to_string()
                .contains("object changed")
        );
    }
}
