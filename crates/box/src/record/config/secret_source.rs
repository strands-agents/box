//! PROTOTYPE (throwaway): `[secret-source.<scheme>]`, a program the box's trusted process runs to
//! read a secret, and the checks that keep the workload away from it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::record::config::egress::EgressEntry;
use crate::record::config::process::ProcessSpec;

/// The protocol a declaration names.
const PROTOCOL: &str = "box.secret-source.v1";

/// The schemes Box resolves itself.
const RESERVED: &[&str] = &["env", "aws", "credsd", "file"];

/// One `[secret-source.<scheme>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct SecretSource {
    pub(crate) protocol: String,
    pub(crate) command: PathBuf,
    pub(crate) args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pass_env: Vec<String>,
    /// The files and directories the program reads, which the workload may never reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reads: Vec<PathBuf>,
    /// Other paths no box may reach, such as the vendor app's socket.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny: Vec<PathBuf>,
    /// The program's device and inode, judged at configure; the run refuses any other file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity: Option<[u64; 2]>,
}

/// Judge the program: a file owned by root or the operator, which no other user can write, in
/// directories no other user can write. Returns its identity.
pub(crate) fn judge_program(scheme: &str, command: &Path) -> Result<[u64; 2], ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(command)
        .map_err(|e| refuse(scheme, format!("command {}: {e}", command.display())))?;
    // SAFETY: `geteuid` reads the calling process's effective user id and cannot fail.
    let operator = unsafe { libc::geteuid() };
    let mut path = Some(real.as_path());
    while let Some(here) = path {
        let metadata = std::fs::metadata(here)
            .map_err(|e| refuse(scheme, format!("{}: {e}", here.display())))?;
        let mode = metadata.mode();
        let sticky = mode & 0o1000 != 0 && metadata.is_dir();
        if metadata.uid() != 0 && metadata.uid() != operator {
            return Err(refuse(
                scheme,
                format!(
                    "{} is owned by uid {}, not by root or you",
                    here.display(),
                    metadata.uid()
                ),
            ));
        }
        if mode & 0o002 != 0 && !sticky {
            return Err(refuse(
                scheme,
                format!(
                    "{} is writable by every user, so anyone could replace the program",
                    here.display()
                ),
            ));
        }
        path = here.parent();
    }
    let metadata = std::fs::metadata(&real).map_err(|e| refuse(scheme, e))?;
    Ok([metadata.dev(), metadata.ino()])
}

fn refuse(scheme: &str, reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::Contract {
        reason: format!("[secret-source.{scheme}] {reason}"),
    }
}

fn expand(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}

fn canonical(path: &Path) -> PathBuf {
    let path = expand(path);
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Whether a grant on `grant` reaches `target`, or a path below it.
fn overlaps(grant: &Path, target: &Path) -> bool {
    let (grant, target) = (canonical(grant), canonical(target));
    target.starts_with(&grant) || grant.starts_with(&target)
}

/// Refuse a declaration the box cannot run safely, before anything is stored.
pub(crate) fn validate(
    sources: &BTreeMap<String, SecretSource>,
    egress: &BTreeMap<String, EgressEntry>,
    processes: &[(String, &ProcessSpec)],
) -> Result<(), ConfigError> {
    for (scheme, source) in sources {
        if RESERVED.contains(&scheme.as_str())
            || scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(refuse(
                scheme,
                "names a scheme Box reserves, or one that is not a-z0-9",
            ));
        }
        if source.protocol != PROTOCOL {
            return Err(refuse(scheme, format!("protocol must be {PROTOCOL:?}")));
        }
        if !source.command.is_absolute() {
            return Err(refuse(scheme, "command must be an absolute path"));
        }
        let metadata = std::fs::metadata(&source.command)
            .map_err(|e| refuse(scheme, format!("command {}: {e}", source.command.display())))?;
        if !metadata.is_file() {
            return Err(refuse(scheme, "command is not a file"));
        }
        if source.identity.is_some() {
            return Err(refuse(
                scheme,
                "identity is recorded by Box, not written in box.toml",
            ));
        }
        judge_program(scheme, &source.command)?;
        if source
            .args
            .iter()
            .filter(|arg| *arg == credentials::REFERENCE_ARGUMENT)
            .count()
            != 1
        {
            return Err(refuse(scheme, "args must hold \"{ref}\" exactly once"));
        }
        // The workload must not replace the program, edit what it reads, run it, or read its
        // configuration.
        let guarded: Vec<&Path> = std::iter::once(source.command.as_path())
            .chain(source.reads.iter().map(PathBuf::as_path))
            .chain(source.deny.iter().map(PathBuf::as_path))
            .collect();
        for (table, spec) in processes {
            let fs = &spec.filesystem;
            // A read or exec grant is overridden by the deny every box gets. A write grant on a
            // path or a directory above it is not: the workload could replace the file.
            for grant in fs.write.iter().chain(&fs.write_file) {
                for target in &guarded {
                    if overlaps(grant, target) {
                        return Err(refuse(
                            scheme,
                            format!(
                                "{table} has a write grant on {} that reaches {}, so the \
                                 workload could replace the secret source or its files",
                                grant.display(),
                                target.display()
                            ),
                        ));
                    }
                }
            }
            if let Some(name) = spec.env.keys().find(|name| source.pass_env.contains(name)) {
                return Err(refuse(
                    scheme,
                    format!("{table} sets {name}, which only the secret source may receive"),
                ));
            }
        }
    }
    for (name, entry) in egress {
        let Some(secret) = &entry.secret else {
            continue;
        };
        let Some((scheme, _)) = secret.reference.split_once("://") else {
            continue;
        };
        if RESERVED.contains(&scheme) {
            let variable = secret.reference.strip_prefix("env://");
            if secret.env.is_some() && (scheme != "env" || secret.env.as_deref() != variable) {
                return Err(ConfigError::Contract {
                    reason: format!(
                        "[egress.{name}] secret.env must match the env:// variable, or name a secret source's placeholder"
                    ),
                });
            }
            continue;
        }
        if !sources.contains_key(scheme) {
            return Err(ConfigError::Contract {
                reason: format!(
                    "[egress.{name}] names {scheme}://, and no [secret-source.{scheme}] declares it"
                ),
            });
        }
        if secret.env.is_none() {
            return Err(ConfigError::Contract {
                reason: format!(
                    "[egress.{name}] needs secret.env: the variable the agent gets the \
                     placeholder under"
                ),
            });
        }
    }
    Ok(())
}

/// Every path a box must never reach for these sources: each program and each path it reads, as
/// the kernel resolves it. Only paths that exist, because Linux refuses a deny on a missing path.
pub(crate) fn denied_paths(sources: &BTreeMap<String, SecretSource>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for source in sources.values() {
        for path in std::iter::once(&source.command)
            .chain(&source.reads)
            .chain(&source.deny)
        {
            if let Ok(real) = std::fs::canonicalize(expand(path))
                && !paths.contains(&real)
            {
                paths.push(real);
            }
        }
    }
    paths
}

/// Add every denied path to a box's `deny` list.
pub(crate) fn deny_in(spec: &mut ProcessSpec, denied: &[PathBuf]) {
    for path in denied {
        if !spec.filesystem.deny.contains(path) {
            spec.filesystem.deny.push(path.clone());
        }
    }
}

/// The declarations as the credentials crate runs them.
pub(crate) fn commands(
    sources: &BTreeMap<String, SecretSource>,
) -> Vec<credentials::SecretSourceCommand> {
    sources
        .iter()
        .map(|(scheme, source)| credentials::SecretSourceCommand {
            scheme: scheme.clone(),
            command: source.command.clone(),
            args: source.args.clone(),
            pass_env: source.pass_env.clone(),
            identity: source.identity.map(|[device, inode]| (device, inode)),
        })
        .collect()
}
