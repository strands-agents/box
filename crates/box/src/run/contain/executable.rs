//! Resolving a `command` to the one executable its profile permits.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

use containment::{ContainmentConfig, PreparedFilesystemPath};

use crate::error::{BoxError, ExecutableError};

/// The one program a process may start: the route the child is exec'd through, and the canonical
/// identity the profile authorizes.
#[derive(Debug)]
pub(crate) struct Program {
    invoked: PathBuf,
    granted: PreparedFilesystemPath,
}

impl Program {
    /// The path the child is exec'd through. Absolute.
    pub(crate) fn invoked(&self) -> &Path {
        &self.invoked
    }

    /// The canonical identity the grant names, which is what the kernel checks at exec.
    pub(crate) fn granted_path(&self) -> &Path {
        self.granted.resolved_path()
    }

    /// Consume this value into the grant the containment config takes.
    pub(crate) fn into_grant(self) -> PreparedFilesystemPath {
        self.granted
    }
}

/// Resolve `program` to the route to start and the canonical identity to authorize.
///
/// An absolute path is used as authored. A bare name is searched on `search_path`. A relative path
/// with a separator is refused, because no directory is its root.
pub(crate) fn resolve(program: &str, search_path: &OsStr) -> Result<Program, BoxError> {
    let candidate = Resolver { search_path }.resolve(Path::new(program))?;

    // Prepared from the ROUTE, so the spelling the profile renders and the spelling the box execs
    // are one string.
    let route = canonical_route(&candidate);
    let granted = ContainmentConfig::prepare_filesystem_path(&route)?;
    if !is_executable(granted.resolved_path()) {
        return Err(ExecutableError::NotExecutable {
            path: granted.resolved_path().to_path_buf(),
        }
        .into());
    }
    Ok(Program {
        invoked: route,
        granted,
    })
}

/// The route with a canonical directory and its own final component.
fn canonical_route(candidate: &Path) -> PathBuf {
    let Some(directory) = candidate.parent() else {
        return candidate.to_path_buf();
    };
    let Some(name) = candidate.file_name() else {
        return candidate.to_path_buf();
    };
    match directory.canonicalize() {
        Ok(resolved) => resolved.join(name),
        Err(_) => candidate.to_path_buf(),
    }
}

struct Resolver<'a> {
    search_path: &'a OsStr,
}

impl Resolver<'_> {
    fn resolve(&self, program: &Path) -> Result<PathBuf, ExecutableError> {
        utf8(program.as_os_str(), "process executable")?;
        if program.is_absolute() {
            return Ok(program.to_path_buf());
        }
        if program.components().count() > 1 {
            return Err(ExecutableError::RelativeProgram {
                program: program.to_path_buf(),
            });
        }
        for directory in std::env::split_paths(self.search_path) {
            // A non-absolute entry means "the current directory", which a process does not have.
            if !directory.is_absolute() {
                continue;
            }
            let candidate = directory.join(program);
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }

        Err(ExecutableError::NotOnPath {
            program: program.to_path_buf(),
        })
    }
}

/// Whether `path` is an executable regular file.
pub(crate) fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        metadata.mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn utf8(value: &OsStr, description: &'static str) -> Result<String, ExecutableError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| ExecutableError::NotUtf8 {
            description,
            value: value.to_string_lossy().into_owned(),
        })
}

/// The longest shebang line the kernel honours; a longer first line is not a shebang launch.
const SHEBANG_LINE_MAX: usize = 512;
/// A shebang chain is short in practice; the bound stops a cycle or a pathological file looping.
const SHEBANG_CHAIN_MAX: usize = 8;

/// The interpreter chain a script launches through its shebang: each existing hop as the kernel or
/// `env` spells it, one per identity, in chain order, following `#!/usr/bin/env <interp>` on
/// `search_path`. Empty for a native binary.
pub(crate) fn shebang_interpreter_chain(target: &Path, search_path: &OsStr) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut current = target.to_path_buf();
    for _ in 0..SHEBANG_CHAIN_MAX {
        let Some((interp, args)) = read_shebang(&current) else {
            break;
        };
        // The kernel execs `env` itself before `env` finds the interpreter, so an `env` shebang
        // needs both: `env` as the shebang spells it, then the interpreter it resolves to.
        let via_env = env_shebang_target(&interp, &args, Some(search_path));
        if via_env.is_some() {
            let env = interp.canonicalize().unwrap_or_else(|_| interp.clone());
            if env.is_file() && seen.insert(env) {
                chain.push(interp.clone());
            }
        }
        // A hop is granted under the name that is looked up, because a view built from names must
        // hold that name; the grant carries the resolved identity as well.
        let spelled = via_env.unwrap_or(interp);
        let canonical = spelled.canonicalize().unwrap_or_else(|_| spelled.clone());
        if !canonical.is_file() || !seen.insert(canonical.clone()) {
            break;
        }
        chain.push(spelled);
        // macOS's `/bin/sh` is a selector that execs the variant `/var/select/sh` names, so that
        // variant runs too.
        if let Some(variant) = sh_variant(&canonical)
            && variant.is_file()
            && seen.insert(variant.clone())
        {
            chain.push(variant);
        }
        current = canonical;
    }
    chain
}

/// The shell macOS's `/bin/sh` execs, read from the `xcode-select`-style pointer it consults.
fn sh_variant(interpreter: &Path) -> Option<PathBuf> {
    if !cfg!(target_os = "macos") || interpreter != Path::new("/bin/sh") {
        return None;
    }
    ["/private/var/select/sh", "/var/select/sh"]
        .iter()
        .map(Path::new)
        .find_map(|pointer| {
            std::fs::read_link(pointer)
                .ok()
                .map(|target| link_target(pointer, target))
        })
        .map(|target| target.canonicalize().unwrap_or(target))
}

/// The file a symbolic link names, with a relative target joined to the link's own directory.
fn link_target(pointer: &Path, target: PathBuf) -> PathBuf {
    if target.is_absolute() {
        return target;
    }
    pointer
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(target)
}

/// Read a script's shebang into `(interpreter, remaining tokens)`, or `None` when the file has no
/// `#!` first line. Reads only the head, so a large binary is not slurped.
fn read_shebang(path: &Path) -> Option<(PathBuf, Vec<String>)> {
    use std::io::Read as _;
    // A single `read` may return short, truncating the shebang line; `take` + `read_to_end` fills up
    // to the cap reliably, and the cap keeps a large binary from being slurped.
    let file = std::fs::File::open(path).ok()?;
    let mut head = Vec::with_capacity(SHEBANG_LINE_MAX);
    file.take(SHEBANG_LINE_MAX as u64)
        .read_to_end(&mut head)
        .ok()?;
    let rest = head.strip_prefix(b"#!")?;
    let line = rest.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim();
    let mut tokens = line.split_whitespace();
    let interpreter = tokens.next()?;
    Some((
        PathBuf::from(interpreter),
        tokens.map(str::to_owned).collect(),
    ))
}

/// Resolve the real interpreter behind a `#!/usr/bin/env <interp>` shebang, or `None` when the
/// interpreter is not `env`. `env` finds `<interp>` dynamically, so the sandbox must grant the
/// resolved target, not `env`. A pinned `-P`/`PATH=` is authoritative; otherwise the shebang's own
/// `PATH` argument, else the supervisor `PATH`.
fn env_shebang_target(
    interp: &Path,
    args: &[String],
    host_path: Option<&OsStr>,
) -> Option<PathBuf> {
    if interp.file_name() != Some(OsStr::new("env")) {
        return None;
    }
    let mut search_path: Option<String> = None;
    let mut iter = args.iter();
    let target = loop {
        let arg = iter.next()?;
        match arg.as_str() {
            "--" => break iter.next()?.clone(),
            "-u" | "-C" | "--unset" | "--chdir" => {
                iter.next()?;
            }
            "-P" => search_path = iter.next().cloned(),
            // `-S`/`--split-string` re-splits its argument; the shebang line is already tokenized, so
            // the bare form is a no-op and the attached form (`--split-string=python3`, `-Spython3`)
            // carries the interpreter after the prefix. The remainder is one token here — a leading
            // `NAME=value` in it splits into its own token and is skipped below.
            "-S" | "--split-string" => {}
            other
                if other.starts_with("--split-string=")
                    || (other.starts_with("-S") && other.len() > 2) =>
            {
                let rest = other
                    .strip_prefix("--split-string=")
                    .or_else(|| other.strip_prefix("-S"))
                    .unwrap_or(other);
                if !rest.is_empty() && !rest.starts_with('-') && !rest.contains('=') {
                    break rest.to_string();
                }
            }
            other if other.starts_with("PATH=") => {
                search_path = Some(other["PATH=".len()..].to_owned());
            }
            // `env` accepts leading `NAME=value` assignments before the command; skip them so the
            // interpreter name, not `FOO=bar`, is taken as the target.
            other if other.contains('=') => {}
            other if !other.starts_with('-') => break other.to_string(),
            _ => {}
        }
    };
    let candidate = PathBuf::from(&target);
    if candidate.is_absolute() {
        return Some(candidate);
    }
    let search = search_path
        .map(std::ffi::OsString::from)
        .or_else(|| host_path.map(OsStr::to_owned))?;
    std::env::split_paths(&search)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(&target))
        .find(|path| is_executable(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An executable file at `path`, created with mode 0700.
    fn executable_at(path: &Path) {
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// A search path naming `directory` and nothing else.
    fn search(directory: &Path) -> std::ffi::OsString {
        directory.as_os_str().to_os_string()
    }

    /// A relative path with a separator has no root to resolve against, so it is refused by name.
    #[test]
    fn a_relative_path_with_a_separator_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().canonicalize().unwrap();
        executable_at(&home.join("agent"));

        let error = resolve("./agent", &search(&home))
            .expect_err("a relative path with a separator names no root");

        assert!(
            error.to_string().contains("relative path"),
            "the refusal must name the shape, not a resolution failure: {error}"
        );
    }

    #[test]
    fn an_absolute_path_is_used_as_authored() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().canonicalize().unwrap();
        let executable = home.join("agent");
        executable_at(&executable);

        let resolved = resolve(executable.to_str().unwrap(), OsStr::new("")).unwrap();

        assert_eq!(resolved.invoked(), executable);
        assert_eq!(resolved.granted_path(), executable);
    }

    /// A linked program is exec'd through the link and granted on what the link names.
    #[test]
    fn a_linked_program_is_started_through_the_link_and_granted_on_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let target = root.join("real-agent");
        executable_at(&target);
        let link = root.join("agent");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = resolve(link.to_str().unwrap(), OsStr::new("")).unwrap();

        assert_eq!(
            resolved.invoked(),
            link,
            "the route is the spelling authored"
        );
        assert_eq!(
            resolved.granted_path(),
            target,
            "the grant names the identity the kernel checks at exec"
        );
    }

    /// The route's directory is canonical even when the program's own name is a link.
    #[test]
    fn the_route_carries_a_canonical_directory() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().canonicalize().unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        executable_at(&real.join("agent"));

        let resolved = resolve(alias.join("agent").to_str().unwrap(), OsStr::new("")).unwrap();

        assert_eq!(
            resolved.invoked(),
            real.join("agent"),
            "the directory is canonical so the profile and the exec spell one path"
        );
    }

    #[test]
    fn a_non_executable_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().canonicalize().unwrap().join("data");
        std::fs::write(&file, "not a program").unwrap();

        let error = resolve(file.to_str().unwrap(), OsStr::new(""))
            .expect_err("a file without an execute bit must be refused");

        assert!(
            error.to_string().contains("not an executable regular file"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_bare_name_absent_from_the_search_path_is_refused() {
        let error = Resolver {
            search_path: OsStr::new("/nonexistent-a:/nonexistent-b"),
        }
        .resolve(Path::new("definitely-not-a-real-command"))
        .expect_err("a bare name absent from the search path must be refused");

        assert!(error.to_string().contains("PATH"), "unexpected: {error}");
    }

    #[test]
    fn a_bare_name_resolves_on_the_declared_search_path() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().canonicalize().unwrap().join("hostbin");
        std::fs::create_dir(&bin).unwrap();
        executable_at(&bin.join("agent"));

        let resolved = Resolver {
            search_path: bin.as_os_str(),
        }
        .resolve(Path::new("agent"))
        .unwrap();

        assert_eq!(resolved, bin.join("agent"));
    }

    /// A non-absolute search entry means "the current directory", which a process does not have,
    /// so it is skipped rather than rebased.
    #[test]
    fn a_non_absolute_search_entry_is_skipped() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let bin = root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        executable_at(&bin.join("agent"));
        let spelled = std::ffi::OsString::from(format!("bin:{}", bin.display()));

        let resolved = Resolver {
            search_path: &spelled,
        }
        .resolve(Path::new("agent"))
        .expect("the absolute entry still resolves beside a skipped one");

        assert_eq!(resolved, bin.join("agent"));
        let error = Resolver {
            search_path: OsStr::new("bin:."),
        }
        .resolve(Path::new("agent"))
        .expect_err("a search path holding only relative entries resolves nothing");
        assert!(error.to_string().contains("PATH"), "{error}");
    }

    #[test]
    fn read_shebang_parses_the_interpreter_and_its_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("tool");
        std::fs::write(&script, "#!/usr/bin/env python3\nprint('x')\n").unwrap();
        let (interpreter, tokens) = read_shebang(&script).expect("a shebang line");
        assert_eq!(interpreter, PathBuf::from("/usr/bin/env"));
        assert_eq!(tokens, vec!["python3".to_string()]);
    }

    #[test]
    fn read_shebang_is_none_without_a_hashbang() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("bin");
        std::fs::write(&binary, b"\x7fELFnot-a-script").unwrap();
        assert!(read_shebang(&binary).is_none());
    }

    #[test]
    fn env_shebang_resolves_the_real_interpreter_on_the_search_path() {
        let dir = tempfile::tempdir().unwrap();
        let interpreter = dir.path().join("myinterp");
        executable_at(&interpreter);
        let host = std::ffi::OsString::from(dir.path());
        let resolved = env_shebang_target(
            Path::new("/usr/bin/env"),
            &["myinterp".to_string()],
            Some(host.as_os_str()),
        )
        .expect("env resolves its target on the search path");
        assert_eq!(resolved, interpreter);
    }

    #[test]
    fn env_shebang_skips_leading_name_value_assignments() {
        // `#!/usr/bin/env FOO=bar myinterp` — the assignment must not be taken as the interpreter.
        let dir = tempfile::tempdir().unwrap();
        let interpreter = dir.path().join("myinterp");
        executable_at(&interpreter);
        let host = std::ffi::OsString::from(dir.path());
        let resolved = env_shebang_target(
            Path::new("/usr/bin/env"),
            &["FOO=bar".to_string(), "myinterp".to_string()],
            Some(host.as_os_str()),
        )
        .expect("env resolves past the assignment to the real interpreter");
        assert_eq!(resolved, interpreter);
    }

    #[test]
    fn env_shebang_resolves_a_split_string_interpreter() {
        // `#!/usr/bin/env --split-string=myinterp` — the interpreter is attached to the flag.
        let dir = tempfile::tempdir().unwrap();
        let interpreter = dir.path().join("myinterp");
        executable_at(&interpreter);
        let host = std::ffi::OsString::from(dir.path());
        let resolved = env_shebang_target(
            Path::new("/usr/bin/env"),
            &["--split-string=myinterp".to_string()],
            Some(host.as_os_str()),
        )
        .expect("env resolves the --split-string interpreter");
        assert_eq!(resolved, interpreter);
    }

    #[test]
    fn env_shebang_is_none_for_a_direct_path_interpreter() {
        assert!(env_shebang_target(Path::new("/bin/sh"), &[], None).is_none());
    }

    #[test]
    fn a_direct_path_shebang_chain_names_its_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("tool");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        let sh = Path::new("/bin/sh").canonicalize().unwrap();
        let chain = shebang_interpreter_chain(&script, OsStr::new("/usr/bin:/bin"));
        assert_eq!(
            chain.first(),
            Some(&PathBuf::from("/bin/sh")),
            "the chain names the shebang interpreter as spelled: {chain:?}"
        );
        assert!(
            chain
                .iter()
                .skip(1)
                .all(|hop| Some(hop) == sh_variant(&sh).as_ref()),
            "only the interpreter's own variant may follow it: {chain:?}"
        );
    }

    /// **An `env` shebang grants `env` and the interpreter it resolves**, because the kernel runs
    /// `env` first and `env` then execs the interpreter.
    #[cfg(unix)]
    #[test]
    fn an_env_shebang_chain_names_env_and_the_interpreter() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().expect("a directory");
        let script = directory.path().join("tool.sh");
        std::fs::write(&script, "#!/usr/bin/env sh\nprintf ran\n").expect("a script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("executable");

        let chain = shebang_interpreter_chain(&script, OsStr::new("/usr/bin:/bin"));

        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");
        assert_eq!(
            chain.first(),
            Some(&PathBuf::from("/usr/bin/env")),
            "`env` is granted as the shebang spells it: {chain:?}"
        );
        let found = ["/usr/bin/sh", "/bin/sh"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_file())
            .expect("sh is on the search path");
        assert!(
            chain.iter().skip(1).any(|hop| *hop == found),
            "the interpreter is granted as `env` finds it on the search path: {chain:?}"
        );
        assert!(
            chain
                .iter()
                .skip(1)
                .any(|hop| hop.canonicalize().ok().as_deref() == Some(sh.as_path())),
            "that spelling resolves to the shell: {chain:?}"
        );
    }

    /// **A `#!/bin/sh` script on macOS grants the variant `/bin/sh` selects**, because that shim
    /// execs `/var/select/sh`'s target rather than interpreting the script itself.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_sh_shebang_chain_names_the_selected_variant_on_macos() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().expect("a directory");
        let script = directory.path().join("tool.sh");
        std::fs::write(&script, "#!/bin/sh\nprintf ran\n").expect("a script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("executable");

        let chain = shebang_interpreter_chain(&script, OsStr::new("/usr/bin:/bin"));

        let variant = sh_variant(Path::new("/bin/sh")).expect("macOS selects an sh variant");
        assert_eq!(chain.first(), Some(&PathBuf::from("/bin/sh")), "{chain:?}");
        assert!(chain.contains(&variant), "{chain:?}");
    }

    #[test]
    fn a_relative_link_target_joins_the_links_directory() {
        assert_eq!(
            link_target(Path::new("/var/select/sh"), PathBuf::from("../../bin/bash")),
            PathBuf::from("/var/select/../../bin/bash")
        );
        assert_eq!(
            link_target(Path::new("/var/select/sh"), PathBuf::from("/bin/bash")),
            PathBuf::from("/bin/bash")
        );
    }

    #[test]
    fn a_native_binary_has_no_shebang_chain() {
        // `/bin/sh` is a Mach-O binary, not a `#!`-script.
        assert!(
            shebang_interpreter_chain(Path::new("/bin/sh"), OsStr::new("/usr/bin:/bin")).is_empty()
        );
    }
}
