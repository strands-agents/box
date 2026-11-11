//! Verified native interpreter discovery and configuration for integration probes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::{Platform, is_executable};

/// The search path the native probe declares for its agent, so the composed workload PATH is
/// exactly the alias directory followed by these entries (`boundary.rs::composed_path`).
pub const NATIVE_PROBE_SEARCH_PATH: &str = "/usr/bin:/bin";

/// A CPython selected and verified on the host for the `NativePython` route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePython {
    /// The canonical executable image the interpreter reported for itself while running — the
    /// file the kernel actually maps, not a launcher that would exec it.
    pub executable: PathBuf,
    /// Canonical, EXISTING directories the interpreter's runtime lives in — the required roots
    /// (base prefix, stdlib, the framework version root of a framework build) and those optional
    /// hints (prefix, `LIBDIR`) that name a real directory on this host — each a `read` grant for
    /// the probe's agent. Deduplicated to the outermost; nothing above them is granted, and a path
    /// that is not there is never granted (the box refuses a grant on a nonexistent path at load).
    pub runtime_reads: Vec<PathBuf>,
    /// Verified Linux Python extension directories that must load native code.
    pub runtime_execs: Vec<PathBuf>,
    /// Compile-time hints the interpreter reported that do not exist on this host, each with why
    /// it was dropped (e.g. `sysconfig`'s `LIBDIR` naming the build machine's Xcode). Reported, not
    /// granted, not fabricated.
    pub rejected_hints: Vec<String>,
}

/// What a candidate interpreter says about itself when the host runs it (see [`PY_IDENTITY_QUERY`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyIdentity {
    pub implementation: String,
    pub image: PathBuf,
    /// Runtime identities the interpreter is actually using: `sys.base_prefix` and the stdlib
    /// directory. Each MUST exist, or the candidate is not a usable runtime.
    pub roots: Vec<PathBuf>,
    /// Build-configuration hints: `sys.prefix` and `sysconfig`'s `LIBDIR`. These can name the
    /// machine the interpreter was built on rather than this host; each is used only if it exists.
    pub hints: Vec<PathBuf>,
    pub extensions: Vec<PathBuf>,
}

/// The query run on the host against a candidate: prints one JSON object with the implementation
/// name, the executing image (`_NSGetExecutablePath` on macOS, `/proc/self/exe` on Linux,
/// `sys.executable` otherwise), the runtime roots it is using, and its build-configuration hints.
pub const PY_IDENTITY_QUERY: &str = r#"
import json, os, sys, sysconfig
def image():
    try:
        return os.readlink("/proc/self/exe")
    except OSError:
        pass
    try:
        import ctypes
        buf = ctypes.create_string_buffer(4096); size = ctypes.c_uint32(4096)
        if ctypes.CDLL(None)._NSGetExecutablePath(buf, ctypes.byref(size)) == 0:
            return buf.value.decode()
    except Exception:
        pass
    return sys.executable
roots = [sysconfig.get_paths().get("stdlib", "")]
hints = [sysconfig.get_config_var("LIBDIR") or ""]
if sys.platform != "linux":
    roots.append(sys.base_prefix)
    hints.append(sys.prefix)
extensions = []
if sys.platform == "linux":
    try:
        import _ctypes
        extension = getattr(_ctypes, "__file__", None)
        if extension:
            extensions.append(os.path.dirname(os.path.realpath(extension)))
    except ImportError:
        pass
print(json.dumps({"implementation": sys.implementation.name, "image": image(),
                  "roots": [d for d in roots if d], "hints": [d for d in hints if d],
                  "extensions": extensions}))
"#;

/// Whether `path` is Apple's launcher shim (or any `/usr/bin` interpreter, which on macOS is one):
/// a shim asks `xcode-select` for the developer directory, which the agent boundary never reaches.
pub fn is_apple_shim(path: &Path) -> bool {
    path.starts_with("/usr/bin")
}

/// The canonical form of `dir` if it names an existing directory on this host, else why not. Never
/// falls back to the unresolved spelling: a grant on a path that is not there grants nothing and
/// makes the box refuse the whole configuration at load (measured, native run of 2026-09-22).
fn existing_directory(dir: &Path) -> Result<PathBuf, String> {
    match dir.canonicalize() {
        Ok(canonical) if canonical.is_dir() => Ok(canonical),
        Ok(canonical) => Err(format!("{} is not a directory", canonical.display())),
        Err(e) => Err(format!("{} is not there ({e})", dir.display())),
    }
}

/// Choose the first candidate that is not a shim, answers the identity query as CPython, and whose
/// image and runtime roots exist on this host. `query` runs a candidate on the host and returns what
/// it reports; it is a parameter so a test can stand in for real interpreters. The reads granted are
/// the existing canonical roots plus those hints that exist; a hint that does not is recorded in
/// [`NativePython::rejected_hints`], never granted and never replaced by a made-up directory. Errors
/// name every rejection.
pub fn select_native_python_from<I, Q>(candidates: I, query: Q) -> Result<NativePython, String>
where
    I: IntoIterator<Item = PathBuf>,
    Q: Fn(&Path) -> Result<PyIdentity, String>,
{
    let host = if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    };
    select_native_python_on(host, candidates, query)
}

fn select_native_python_on<I, Q>(
    platform: Platform,
    candidates: I,
    query: Q,
) -> Result<NativePython, String>
where
    I: IntoIterator<Item = PathBuf>,
    Q: Fn(&Path) -> Result<PyIdentity, String>,
{
    let mut rejected = Vec::new();
    for candidate in candidates {
        let canonical = candidate.canonicalize().unwrap_or(candidate.clone());
        if platform == Platform::Macos && (is_apple_shim(&candidate) || is_apple_shim(&canonical)) {
            rejected.push(format!(
                "{}: Apple launcher shim under /usr/bin",
                candidate.display()
            ));
            continue;
        }
        let identity = match query(&canonical) {
            Ok(identity) if identity.implementation == "cpython" => identity,
            Ok(identity) => {
                rejected.push(format!(
                    "{}: implementation {:?} is not cpython",
                    candidate.display(),
                    identity.implementation
                ));
                continue;
            }
            Err(e) => {
                rejected.push(format!("{}: {e}", candidate.display()));
                continue;
            }
        };
        // The image is what the kernel maps: it must be a real file, and not a /usr/bin launcher.
        let image = match identity.image.canonicalize() {
            Ok(image) if image.is_file() => image,
            Ok(image) => {
                rejected.push(format!(
                    "{}: reported image {} is not a file",
                    candidate.display(),
                    image.display()
                ));
                continue;
            }
            Err(e) => {
                rejected.push(format!(
                    "{}: reported image {} is not there ({e})",
                    candidate.display(),
                    identity.image.display()
                ));
                continue;
            }
        };
        if platform == Platform::Macos && is_apple_shim(&image) {
            rejected.push(format!(
                "{}: executes as a /usr/bin image",
                candidate.display()
            ));
            continue;
        }
        // Required roots: what the running interpreter is using. Missing one means this is not a
        // usable runtime, so the candidate is rejected by name rather than granted a phantom path.
        let mut reads: Vec<PathBuf> = Vec::new();
        let mut missing_root = None;
        for root in identity.roots.iter().chain(framework_root(&image).iter()) {
            if root.as_os_str().is_empty() || root == Path::new("/") {
                continue;
            }
            match existing_directory(root) {
                Ok(dir) => {
                    if !reads.contains(&dir) {
                        reads.push(dir);
                    }
                }
                Err(why) => {
                    missing_root = Some(why);
                    break;
                }
            }
        }
        if let Some(why) = missing_root {
            rejected.push(format!("{}: runtime root {why}", candidate.display()));
            continue;
        }
        if reads.is_empty() {
            rejected.push(format!("{}: reported no runtime root", candidate.display()));
            continue;
        }
        // Optional hints: build-configuration values that may name the build machine. Used only
        // when they exist here; otherwise reported and dropped.
        let mut rejected_hints = Vec::new();
        for hint in &identity.hints {
            if hint.as_os_str().is_empty() || hint == Path::new("/") {
                continue;
            }
            match existing_directory(hint) {
                Ok(dir) => {
                    if !reads.contains(&dir) {
                        reads.push(dir);
                    }
                }
                Err(why) => rejected_hints.push(format!("build-time hint {why}")),
            }
        }
        // Keep only the outermost of nested directories: one grant per identity.
        let mut outer: Vec<PathBuf> = reads
            .iter()
            .filter(|dir| {
                !reads
                    .iter()
                    .any(|other| other != *dir && dir.starts_with(other))
            })
            .cloned()
            .collect();
        outer.sort();
        let runtime_execs = if platform == Platform::Linux {
            match identity
                .extensions
                .iter()
                .map(|path| existing_directory(path))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(paths) => paths,
                Err(why) => {
                    rejected.push(format!(
                        "{}: extension directory {why}",
                        candidate.display()
                    ));
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        if runtime_execs
            .iter()
            .any(|path| !outer.iter().any(|root| path.starts_with(root)))
        {
            rejected.push(format!(
                "{}: extension directory is outside its runtime reads",
                candidate.display()
            ));
            continue;
        }
        return Ok(NativePython {
            executable: image,
            runtime_reads: outer,
            runtime_execs,
            rejected_hints,
        });
    }
    Err(format!(
        "no native CPython on this host; rejected: {}",
        if rejected.is_empty() {
            "no candidates".to_string()
        } else {
            rejected.join("; ")
        }
    ))
}

/// For a framework build (`…/Python3.framework/Versions/3.9/…`), the version root that holds the
/// dylib, the stdlib and the app bundle; otherwise nothing.
pub fn framework_root(image: &Path) -> Option<PathBuf> {
    let mut cur = image;
    while let Some(parent) = cur.parent() {
        if parent.file_name().is_some_and(|n| n == "Versions") {
            return Some(cur.to_path_buf());
        }
        cur = parent;
    }
    None
}

/// Run [`PY_IDENTITY_QUERY`] on the host with `candidate`, isolated from the operator's
/// environment (`-I`), and parse its answer.
pub fn query_python_identity(candidate: &Path) -> Result<PyIdentity, String> {
    let output = Command::new(candidate)
        .arg("-I")
        .arg("-c")
        .arg(PY_IDENTITY_QUERY)
        .output()
        .map_err(|e| format!("cannot run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("identity is not JSON: {e}"))?;
    let paths = |key: &str| -> Vec<PathBuf> {
        value[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .map(PathBuf::from)
            .collect()
    };
    Ok(PyIdentity {
        implementation: value["implementation"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        image: PathBuf::from(value["image"].as_str().unwrap_or_default()),
        roots: paths("roots"),
        hints: paths("hints"),
        extensions: paths("extensions"),
    })
}

/// The host's candidates, in order: the developer directory's `python3` (`xcrun --find`, macOS),
/// then every `python3` on the host PATH. Shims are rejected by [`select_native_python_from`].
pub fn native_python_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(found) = macos_developer_tool("python3") {
        candidates.push(found);
    }
    for dir in std::env::var_os("PATH")
        .iter()
        .flat_map(|p| std::env::split_paths(p).collect::<Vec<_>>())
    {
        let cand = dir.join("python3");
        if is_executable(&cand) && !candidates.contains(&cand) {
            candidates.push(cand);
        }
    }
    candidates
}

/// The verified native CPython for this process, selected once. Panics with DET_ERROR when none
/// qualifies, naming every rejected candidate.
pub fn native_python() -> &'static NativePython {
    static SELECTED: OnceLock<NativePython> = OnceLock::new();
    SELECTED.get_or_init(|| {
        let python = select_native_python_from(native_python_candidates(), query_python_identity)
            .unwrap_or_else(|e| panic!("DET_ERROR: {e}"));
        // Dropped hints are evidence, not a fault: say so once, in the case output.
        for hint in &python.rejected_hints {
            eprintln!(
                "DET_NOTE: native python {}: {hint} (not granted)",
                python.executable.display()
            );
        }
        python
    })
}

/// The developer directory's real program `name` on macOS, through `xcrun --find`, canonicalized
/// and verified not to be a `/usr/bin` launcher shim.
pub fn macos_developer_tool(name: &str) -> Result<PathBuf, String> {
    let output = Command::new("xcrun")
        .arg("--find")
        .arg(name)
        .output()
        .map_err(|e| format!("xcrun --find {name}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun --find {name}: exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let found = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let canonical = found
        .canonicalize()
        .map_err(|e| format!("{}: {e}", found.display()))?;
    if is_apple_shim(&canonical) {
        return Err(format!(
            "xcrun --find {name} answered a /usr/bin shim: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// The probe grants the verified Python runtime, including native extension execution on Linux.
pub fn native_probe_config(template: &str, workspace: &Path, python: &NativePython) -> String {
    let quoted = |p: &Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
    let command = serde_json::to_string(&[python.executable.to_string_lossy()]).unwrap();
    let extra: Vec<String> = python.runtime_reads.iter().map(|p| quoted(p)).collect();
    let mut config = template.replacen("{command}", &command, 1);
    if !extra.is_empty() {
        config = config.replacen("read = [", &format!("read = [{}, ", extra.join(", ")), 1);
    }
    if !python.runtime_execs.is_empty() {
        let entries = python
            .runtime_execs
            .iter()
            .map(|path| quoted(path))
            .collect::<Vec<_>>()
            .join(", ");
        config = config.replacen(
            "[agent.filesystem]",
            &format!("[agent.filesystem]\nexec = [{entries}]"),
            1,
        );
    }
    // The CLT interpreter needs an entropy source during hash initialization.
    // This is one read-only device in this probe's fixture, not a wider Core minimum.
    config = config.replacen("read_file = [", "read_file = [\"/dev/urandom\", ", 1);
    config.push_str(&format!(
        "\n[agent.env]\nHOME = {}\nPATH = {}\n",
        quoted(workspace),
        serde_json::to_string(NATIVE_PROBE_SEARCH_PATH).unwrap()
    ));
    config
}

/// The developer directory's real `git` on this macOS host: `xcrun --find git`, canonicalized,
/// refused if it is the `/usr/bin/git` launcher shim. This one path is the `[tool.git]` command,
/// the program a case spells on the Shell's command line, and the program the git-only policy
/// names — so the invocation, the declaration and the permit agree by construction, and the
/// journaled `shell:spawn` resource (the resolved `program_path`) must read exactly this.
/// Panics with DET_ERROR when the host has no such git.
pub fn macos_git_identity() -> PathBuf {
    macos_developer_tool("git").unwrap_or_else(|e| panic!("DET_ERROR: {e}"))
}

/// The `[tool.git]` declaration for a verified developer-directory git: declaring it puts it in the
/// agent's reach, and the tool reads the developer directory git lives in (`<dir>/usr/bin/git`) and
/// the workspace. Nothing else is declared — in particular no `[agent.env] PATH`, which would not
/// affect what the hosted Shell resolves (see [`crate::BoxFixture::with_macos_git_tool`]).
pub fn git_tool_config(template: String, git: &Path, workspace_json: &str) -> String {
    let git_json = serde_json::to_string(&git.to_string_lossy()).unwrap();
    let developer = git
        .ancestors()
        .nth(3)
        .expect("git lives at <developer directory>/usr/bin/git");
    let developer_json = serde_json::to_string(&developer.to_string_lossy()).unwrap();
    template
        + &format!(
            "\n[tool.git]\ncommand = [{git_json}]\nworkspace = {ws}\n\n[tool.git.filesystem]\nread = [{developer_json}, {ws}]\nwrite = [{ws}]\n\n\
         [tool.git.env]\nHOME = {ws}\nGIT_CONFIG_NOSYSTEM = \"1\"\nGIT_CONFIG_GLOBAL = \"/dev/null\"\n",
            ws = workspace_json
        )
}

/// A `shell:spawn` permit for exactly one host program: the one whose spelled `program` AND resolved
/// `program_path` (`crates/policy/src/schema.rs`: `context.input.program`, `context.input.program_path`)
/// both equal `git`'s canonical path. As narrow as the former `program == "git"` — one program — but
/// pinned to the identity the box will execute rather than to a bare name the broker's `PATH`
/// resolves. A bare `git`, `/usr/bin/git`, or `ssh` never matches.
pub fn git_only_spawn_policy(git: &Path) -> String {
    let git_json = serde_json::to_string(&git.to_string_lossy()).unwrap();
    format!(
        "permit(principal, action == Box::Action::\"shell:spawn\", resource)\nwhen {{ context.input.program == {git_json} && context.input.program_path == {git_json} }};"
    )
}

#[cfg(test)]
mod tests;
