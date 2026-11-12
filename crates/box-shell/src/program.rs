//! Which host file a command the Shell does not implement names.

use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// The absolute file each bare name runs, looked up before `PATH`.
pub type HostPrograms = Arc<BTreeMap<String, PathBuf>>;

/// One host-binary spawn handed to a [`HostSpawner`].
pub struct HostSpawn {
    /// The canonical identity of the program that runs.
    pub program: PathBuf,
    /// The spelling the caller used, made absolute, which the program reads as `argv[0]`.
    pub invoked: PathBuf,
    /// The arguments, without the program.
    pub args: Vec<String>,
    /// The directory the program's decision checked.
    pub cwd: PathBuf,
}

/// The captured result of one host-binary spawn.
pub struct HostSpawnOutcome {
    /// The program's exit status.
    pub status: i32,
    /// What the program wrote to stdout.
    pub stdout: Vec<u8>,
    /// What the program wrote to stderr.
    pub stderr: Vec<u8>,
}

/// The future a [`HostSpawner`] returns.
pub type HostSpawnFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<HostSpawnOutcome>> + Send>>;

/// Runs one host binary.
pub type HostSpawner = Arc<dyn Fn(HostSpawn) -> HostSpawnFuture + Send + Sync>;

/// A host program a `shell:spawn` decision names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostProgram {
    /// The canonical identity of a bound file, else the spelling made absolute.
    pub(super) path: String,
    /// The spelling the caller used, made absolute.
    pub(super) spelling: String,
    /// Whether an existing file was bound at decision time.
    pub(super) bound: bool,
}

impl HostProgram {
    fn bound(identity: &Path, spelling: &Path) -> Self {
        Self {
            path: identity.to_string_lossy().into_owned(),
            spelling: spelling.to_string_lossy().into_owned(),
            bound: true,
        }
    }

    fn unbound(spelling: &Path) -> Self {
        let spelling = lexical_absolute(spelling).to_string_lossy().into_owned();
        Self {
            path: spelling.clone(),
            spelling,
            bound: false,
        }
    }
}

/// Whether the Shell runs `name` itself, so a host file declared under it is never reached.
pub fn implements_program(name: &str) -> bool {
    strands_shell::builtins::lookup(name).is_some()
        || strands_shell::commands::lookup(name).is_some()
        || matches!(name, "lash" | "sh" | "python" | "python3")
}

/// The host program `program` names: a declared file, a spelling with a separator, or the first
/// executable file on the operator's host `PATH`.
pub(super) fn host_program(
    declared: &HostPrograms,
    program: &str,
    cwd: &Path,
) -> Option<HostProgram> {
    if !program.contains('/')
        && let Some(declared) = declared.get(program)
    {
        return Some(match declared.canonicalize() {
            Ok(identity) => HostProgram::bound(&identity, &lexical_absolute(declared)),
            Err(_) => HostProgram::unbound(declared),
        });
    }
    let path_var = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    host_program_on(program, cwd, &path_var.to_string_lossy())
}

fn host_program_on(program: &str, cwd: &Path, path_var: &str) -> Option<HostProgram> {
    if program.contains('/') {
        let spelled = Path::new(program);
        let candidate = if spelled.is_absolute() {
            spelled.to_path_buf()
        } else {
            cwd.join(spelled)
        };
        return Some(match candidate.canonicalize() {
            Ok(identity) => HostProgram::bound(&identity, &lexical_absolute(&candidate)),
            Err(_) => HostProgram::unbound(&candidate),
        });
    }
    let found = PathBuf::from(host_path_lookup(program, path_var)?);
    let identity = found.canonicalize().ok()?;
    Some(HostProgram::bound(&identity, &lexical_absolute(&found)))
}

/// The spelling made absolute by the path grammar alone.
fn lexical_absolute(candidate: &Path) -> PathBuf {
    let mut folded = PathBuf::from("/");
    for component in candidate.components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                folded.pop();
            }
            Component::Normal(part) => folded.push(part),
        }
    }
    folded
}

/// The first executable regular file named `program` on `path_var`; an empty entry is skipped.
fn host_path_lookup(program: &str, path_var: &str) -> Option<String> {
    path_var
        .split(':')
        .filter(|directory| !directory.is_empty())
        .map(|directory| Path::new(directory).join(program))
        .find(|candidate| is_host_executable(candidate))
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

fn is_host_executable(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(candidate)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_is_named_by_its_canonical_identity_and_its_spelling() {
        let directory = tempfile::tempdir().expect("a directory");
        let real = directory.path().join("real");
        std::fs::write(&real, "#!/bin/sh\n").expect("a program");
        std::fs::set_permissions(&real, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
        let link = directory.path().join("tool");
        std::os::unix::fs::symlink(&real, &link).expect("a link");

        let found = host_program_on("tool", Path::new("/"), &directory.path().to_string_lossy())
            .expect("found on PATH");

        let identity = real.canonicalize().expect("canonical");
        assert_eq!(found.path, identity.to_string_lossy());
        assert_eq!(found.spelling, link.to_string_lossy());
        assert!(found.bound);
    }

    #[test]
    fn a_spelling_that_names_no_file_is_unbound() {
        let found = host_program_on("./missing/tool", Path::new("/work"), "/usr/bin")
            .expect("a spelling with a separator is a program");
        assert_eq!(found.path, "/work/missing/tool");
        assert!(!found.bound);
    }

    #[test]
    fn a_declared_file_that_is_gone_is_not_searched_on_path() {
        let declared: HostPrograms = Arc::new(BTreeMap::from([(
            "git".to_string(),
            PathBuf::from("/nonexistent/declared/git"),
        )]));
        let found = host_program(&declared, "git", Path::new("/")).expect("declared");
        assert!(!found.bound);
        assert_eq!(found.path, "/nonexistent/declared/git");
    }

    #[test]
    fn the_shell_implements_its_own_programs_and_python() {
        for name in ["echo", "cat", "curl", "sh", "lash", "python", "python3"] {
            assert!(implements_program(name), "{name}");
        }
        assert!(!implements_program("git"));
    }
}
