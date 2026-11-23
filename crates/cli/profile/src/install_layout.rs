//! Installation layouts and the files a program needs from them.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

const MAX_BYTES: u64 = 1_048_576;
const MAX_ITEMS: usize = 1024;

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Requirements {
    pub(crate) read: Vec<PathBuf>,
    pub(crate) read_file: Vec<PathBuf>,
    pub(crate) list: Vec<PathBuf>,
    pub(crate) sources: Vec<String>,
}

impl Requirements {
    pub(crate) fn extend(&mut self, other: Self) {
        self.read.extend(other.read);
        self.read = crate::host::unique(std::mem::take(&mut self.read));
        self.read_file.extend(other.read_file);
        self.read_file.sort();
        self.read_file.dedup();
        self.read_file
            .retain(|path| !self.read.iter().any(|root| path.starts_with(root)));
        self.list.extend(other.list);
        self.list.sort();
        self.list.dedup();
        self.list
            .retain(|path| !self.read.iter().any(|root| path.starts_with(root)));
        self.sources.extend(other.sources);
        self.sources.sort();
        self.sources.dedup();
    }
}

/// Box Core's judgment of a read grant, as `reference::Sources::read_grant` gives it.
pub(crate) type Grant<'a> = &'a dyn Fn(&Path) -> Result<bool, (strands_box::GrantRefusal, String)>;

pub(crate) fn check_path(
    path: &Path,
    home: &Path,
    workspace: &Path,
    refusals: &crate::storage_files::Refusals,
    grant: Grant<'_>,
) -> Result<(), String> {
    if home.starts_with(path) {
        return Err(format!(
            "its install directory {} holds your home folder",
            path.display()
        ));
    }
    if workspace.starts_with(path) {
        return Err(format!(
            "its install directory {} holds the project",
            crate::host::tilde(home, path)
        ));
    }
    if let Some(real) = crate::host::canonical(path) {
        let store = |detail: String| {
            Err(format!(
                "its install directory {} {detail}, which box grants no installation",
                crate::host::tilde(home, path)
            ))
        };
        match grant(&real) {
            Ok(false) => {}
            Ok(true) => return store("lies in a credential store".into()),
            Err((kind, reason)) => match kind {
                strands_box::GrantRefusal::Absent
                | strands_box::GrantRefusal::Link
                | strands_box::GrantRefusal::NotCanonical
                | strands_box::GrantRefusal::NotAbsolute
                | strands_box::GrantRefusal::Forbidden(
                    strands_box::ForbiddenClass::SystemTree
                    | strands_box::ForbiddenClass::LoaderDirectory
                    | strands_box::ForbiddenClass::WholeFilesystem
                    | strands_box::ForbiddenClass::HomeNamespace,
                ) => {}
                _ => return store(format!("is one the box refuses: {reason}")),
            },
        }
    }
    if let Some(reason) = refusals.reach(path) {
        return Err(format!(
            "installation {reason}; box reads no installation from there"
        ));
    }
    Ok(())
}

/// An installer's file layout that `box` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layout {
    Directory,
    Homebrew,
    Node,
    Npm,
    Python,
}

/// The paths one layout finds for one program path.
#[derive(Debug, Default)]
struct Found {
    path: PathBuf,
    read: Vec<PathBuf>,
    read_file: Vec<PathBuf>,
    list: Vec<PathBuf>,
    keg: Option<Keg>,
}

/// A Homebrew keg and the prefix that holds it.
#[derive(Debug)]
struct Keg {
    prefix: PathBuf,
    root: PathBuf,
}

/// The files that `spelling`, and each dependency it names, needs under `layouts`.
pub(crate) fn resolve(
    spelling: &Path,
    layouts: &[Layout],
    os: &str,
    check: &impl Fn(&Path) -> Result<(), String>,
) -> Result<Requirements, String> {
    let mut result = Requirements::default();
    let mut pending = VecDeque::from([spelling.to_path_buf()]);
    let mut seen = BTreeSet::new();
    while let Some(spelling) = pending.pop_front() {
        let real = fs::canonicalize(&spelling)
            .map_err(|error| format!("installation path {}: {error}", spelling.display()))?;
        check(&spelling)?;
        check(&real)?;
        if !seen.insert((spelling.clone(), real.clone())) {
            continue;
        }
        if seen.len() > MAX_ITEMS {
            return Err("installation dependency limit exceeded".into());
        }
        let mut matched = false;
        for fallback in [false, true] {
            if fallback && matched {
                break;
            }
            for layout in Layout::ALL
                .iter()
                .filter(|layout| layouts.contains(layout) && layout.fallback() == fallback)
            {
                for found in layout.find(&spelling, &real, os, check)? {
                    matched = true;
                    result
                        .sources
                        .push(format!("{}: {}", layout.name(), found.path.display()));
                    grant(found.read, &mut result.read, true, check)?;
                    grant(found.read_file, &mut result.read_file, false, check)?;
                    grant(found.list, &mut result.list, true, check)?;
                    if let Some(keg) = found.keg {
                        let receipt = dependencies(&keg, check, &mut pending)?;
                        result.sources.push(format!(
                            "{} receipt: {}",
                            layout.name(),
                            receipt.display()
                        ));
                    }
                }
            }
        }
    }
    result.read = crate::host::unique(result.read);
    result.read_file.sort();
    result.read_file.dedup();
    result
        .read_file
        .retain(|file| !result.read.iter().any(|root| file.starts_with(root)));
    result.list.sort();
    result.list.dedup();
    result
        .list
        .retain(|dir| !result.read.iter().any(|root| dir.starts_with(root)));
    result.sources.sort();
    result.sources.dedup();
    Ok(result)
}

impl Layout {
    pub(crate) const ALL: &[Self] = &[
        Self::Directory,
        Self::Homebrew,
        Self::Node,
        Self::Npm,
        Self::Python,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Homebrew => "homebrew",
            Self::Node => "node",
            Self::Npm => "npm",
            Self::Python => "python",
        }
    }

    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|layout| layout.name() == name)
    }

    fn fallback(self) -> bool {
        self == Self::Directory
    }

    fn find(
        self,
        spelling: &Path,
        real: &Path,
        os: &str,
        check: &impl Fn(&Path) -> Result<(), String>,
    ) -> Result<Vec<Found>, String> {
        let parts = parts(real)?;
        let at = |path: &Path| Found {
            path: path.to_path_buf(),
            ..Found::default()
        };
        let mut found = Vec::new();
        match self {
            Self::Directory => {
                if let Some(parent) = real.parent().filter(|_| !parts.is_empty()) {
                    found.push(Found {
                        read: vec![parent.to_path_buf()],
                        ..at(real)
                    });
                }
            }
            Self::Homebrew => {
                if let Some(cellar) = last(&parts, |i| parts[i] == "Cellar" && i + 2 < parts.len())
                {
                    let prefix = join(&parts[..cellar]);
                    let formula = parts[cellar + 1];
                    let root = join(&parts[..cellar + 3]);
                    found.push(Found {
                        read: vec![root.clone(), prefix.join("etc").join(formula)],
                        list: if os == "macos" {
                            vec![prefix.join("bin"), prefix.join("opt")]
                        } else {
                            Vec::new()
                        },
                        keg: Some(Keg { prefix, root }),
                        ..at(real)
                    });
                }
            }
            Self::Node => {
                if let Some(root) = in_bin(&parts, |name| {
                    name.strip_prefix("node")
                        .is_some_and(|rest| rest.is_empty() || digits(rest.strip_prefix('-')))
                }) {
                    found.push(Found {
                        read: [
                            vec![root.join("bin")],
                            children(&root.join("share"), "node-", check)?,
                        ]
                        .concat(),
                        read_file: vec![real.to_path_buf()],
                        ..at(real)
                    });
                }
            }
            Self::Npm => {
                if let Some(modules) =
                    (1..parts.len()).find(|&i| parts[i] == "node_modules" && i + 1 < parts.len())
                {
                    found.push(Found {
                        read: vec![join(&parts[..=modules])],
                        ..at(real)
                    });
                }
                if let Some(root) = in_bin(&parts, |name| matches!(name, "npm" | "npm-cli.js")) {
                    found.push(Found {
                        read: vec![root],
                        ..at(real)
                    });
                }
            }
            Self::Python => {
                for path in [spelling, real] {
                    if let Some(root) = environment(path, check)? {
                        found.push(Found {
                            read: vec![root],
                            ..at(path)
                        });
                    }
                }
                if let Some(root) = in_bin(&parts, |name| {
                    name.strip_prefix("python").is_some_and(|rest| {
                        rest.is_empty() || rest.split('.').all(|part| digits(Some(part)))
                    })
                }) {
                    found.push(Found {
                        read: vec![root.join("lib")],
                        read_file: vec![real.to_path_buf()],
                        ..at(real)
                    });
                }
                for kind in ["tools", "python"] {
                    if let Some(uv) = last(&parts, |i| {
                        parts[i] == "uv" && i + 3 < parts.len() && parts[i + 1] == kind
                    }) {
                        found.push(Found {
                            read: vec![join(&parts[..uv + 3])],
                            ..at(real)
                        });
                    }
                }
            }
        }
        Ok(found)
    }
}

/// The components of an absolute path.
fn parts(path: &Path) -> Result<Vec<&str>, String> {
    Ok(path
        .to_str()
        .ok_or("installation path is not UTF-8")?
        .split('/')
        .filter(|part| !part.is_empty())
        .collect())
}

fn join(parts: &[&str]) -> PathBuf {
    PathBuf::from(format!("/{}", parts.join("/")))
}

/// The last index, below a first component, that `test` accepts.
fn last(parts: &[&str], test: impl Fn(usize) -> bool) -> Option<usize> {
    (1..parts.len()).rev().find(|&index| test(index))
}

/// The folder that holds `bin/<name>`, when `name` passes `test`.
fn in_bin(parts: &[&str], test: impl Fn(&str) -> bool) -> Option<PathBuf> {
    match parts {
        [root @ .., "bin", name] if !root.is_empty() && test(name) => Some(join(root)),
        _ => None,
    }
}

fn digits(text: Option<&str>) -> bool {
    text.is_some_and(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The nearest folder above `path` that holds `pyvenv.cfg`.
fn environment(
    path: &Path,
    check: &impl Fn(&Path) -> Result<(), String>,
) -> Result<Option<PathBuf>, String> {
    for root in path.ancestors().skip(1).take(64) {
        let marker = root.join("pyvenv.cfg");
        if marker.is_file() {
            let domain = fs::canonicalize(root).map_err(|error| error.to_string())?;
            confined(&marker, &domain, check)?;
            return Ok(Some(root.to_path_buf()));
        }
    }
    Ok(None)
}

/// The entries of `directory` whose names start with `prefix`.
fn children(
    directory: &Path,
    prefix: &str,
    check: &impl Fn(&Path) -> Result<(), String>,
) -> Result<Vec<PathBuf>, String> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    check(directory)?;
    let identity = fs::canonicalize(directory).map_err(|error| error.to_string())?;
    check(&identity)?;
    let mut found = Vec::new();
    for entry in fs::read_dir(identity).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
        {
            found.push(entry.path());
        }
        if found.len() > MAX_ITEMS {
            return Err("installation entry limit exceeded".into());
        }
    }
    Ok(found)
}

fn grant(
    paths: Vec<PathBuf>,
    entries: &mut Vec<PathBuf>,
    directory: bool,
    check: &impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    for path in paths {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(format!(
                "installation path {} is not absolute or contains traversal",
                path.display()
            ));
        }
        if !path.exists() {
            continue;
        }
        let identity = fs::canonicalize(&path).map_err(|error| error.to_string())?;
        check(&path)?;
        check(&identity)?;
        if directory != identity.is_dir() {
            return Err(format!(
                "installation grant {} has the wrong file type",
                path.display()
            ));
        }
        entries.push(identity);
    }
    Ok(())
}

/// Queues each runtime dependency in a keg's receipt, and returns the receipt.
fn dependencies(
    keg: &Keg,
    check: &impl Fn(&Path) -> Result<(), String>,
    pending: &mut VecDeque<PathBuf>,
) -> Result<PathBuf, String> {
    let receipt = confined(&keg.root.join("INSTALL_RECEIPT.json"), &keg.root, check)?;
    let document: serde_json::Value = serde_json::from_str(&read_text(&receipt)?)
        .map_err(|error| format!("installation metadata {}: {error}", receipt.display()))?;
    let dependencies = document
        .get("runtime_dependencies")
        .ok_or_else(|| {
            format!(
                "installation metadata {} has no runtime_dependencies",
                receipt.display()
            )
        })?
        .as_array()
        .ok_or("installation dependencies are not a list")?;
    if dependencies.len() > MAX_ITEMS {
        return Err("installation dependency limit exceeded".into());
    }
    for dependency in dependencies {
        let name = dependency
            .get("full_name")
            .and_then(serde_json::Value::as_str)
            .ok_or("an installation dependency has no name")?;
        if !name.split('/').all(component) {
            return Err(format!("invalid installation dependency name {name:?}"));
        }
        let name = name.rsplit('/').next().unwrap_or("");
        pending.push_back(confined(
            &keg.prefix.join("opt").join(name),
            &keg.prefix.join("Cellar").join(name),
            check,
        )?);
    }
    Ok(receipt)
}

fn component(text: &str) -> bool {
    !text.is_empty()
        && !matches!(text, "." | "..")
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '@' | '+' | '_' | '-' | '.'))
}

fn confined(
    path: &Path,
    domain: &Path,
    check: &impl Fn(&Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    check(path)?;
    let real = fs::canonicalize(path)
        .map_err(|error| format!("installation dependency {}: {error}", path.display()))?;
    let physical_domain = fs::canonicalize(domain)
        .map_err(|error| format!("installation domain {}: {error}", domain.display()))?;
    if physical_domain != domain {
        return Err(format!(
            "installation domain {} contains a link",
            domain.display()
        ));
    }
    let domain = physical_domain;
    if !real.starts_with(&domain) {
        return Err(format!(
            "installation dependency {} resolves outside {}",
            path.display(),
            domain.display()
        ));
    }
    check(&real)?;
    Ok(real)
}

fn read_text(path: &Path) -> Result<String, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > MAX_BYTES {
        return Err(format!(
            "installation file {} exceeds 1 MiB",
            path.display()
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn file(root: &Path, relative: &str, content: &str) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn npm_entries_read_the_containing_installation_tree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for entry in [
            "server/bin/start.js",
            "@acme/server/dist/cli/start.js",
            "server/node_modules/nested/bin/start.js",
            ".pnpm/server@1/node_modules/server/bin/start.js",
            ".bin/server",
        ] {
            let script = file(&root, &format!("lib/node_modules/{entry}"), "");
            let found = resolve(&script, Layout::ALL, "macos", &|_| Ok(())).unwrap();
            assert_eq!(found.read, vec![root.join("lib/node_modules")], "{entry}");
            assert!(found.read_file.is_empty());
            assert!(found.list.is_empty());
        }
    }

    #[test]
    fn an_npm_installation_tree_passes_the_grant_check() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let script = file(&root, "lib/node_modules/server/bin/start.js", "");
        let error = resolve(&script, Layout::ALL, "macos", &|path| {
            if path == root.join("lib/node_modules") {
                Err("refused installation tree".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error, "refused installation tree");
    }

    #[test]
    fn a_python_alias_keeps_its_environment_and_actual_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let python = file(&root, "runtime/bin/python3.12", "");
        file(&root, "runtime/lib/python3.12/os.py", "");
        file(&root, "venv/pyvenv.cfg", "home = /unused");
        fs::create_dir_all(root.join("venv/bin")).unwrap();
        symlink(&python, root.join("venv/bin/python")).unwrap();
        let found = resolve(&root.join("venv/bin/python"), Layout::ALL, "macos", &|_| {
            Ok(())
        })
        .unwrap();
        assert!(found.read.contains(&root.join("venv")));
        assert!(found.read.contains(&root.join("runtime/lib")));
        assert_eq!(found.read_file, vec![python]);
    }

    #[test]
    fn a_match_needs_a_folder_before_it() {
        let ok = |_: &Path| Ok(());
        for (layout, path) in [
            (Layout::Homebrew, "/Cellar/node/24/bin/node"),
            (Layout::Npm, "/node_modules/server/cli.js"),
            (Layout::Npm, "/tools/node_modules"),
            (Layout::Python, "/uv/tools/server/bin/server"),
        ] {
            let path = Path::new(path);
            assert!(
                layout.find(path, path, "macos", &ok).unwrap().is_empty(),
                "{layout:?} {}",
                path.display()
            );
        }
    }

    #[test]
    fn homebrew_reads_current_dependency_kegs_and_specific_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[{"full_name":"openssl@4","version":"old"}]}"#,
        );
        file(
            &root,
            "Cellar/openssl@4/4.1/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[]}"#,
        );
        file(&root, "etc/openssl@4/openssl.cnf", "");
        fs::create_dir(root.join("opt")).unwrap();
        symlink("../Cellar/openssl@4/4.1", root.join("opt/openssl@4")).unwrap();
        file(&root, "Cellar/unrelated/1/secret", "");
        let found = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap();
        assert_eq!(
            found.read,
            vec![
                root.join("Cellar/node/24"),
                root.join("Cellar/openssl@4/4.1"),
                root.join("etc/openssl@4"),
            ]
        );
        assert!(found.read_file.is_empty());
        assert_eq!(found.list, vec![root.join("opt")]);
        assert_eq!(
            found.sources,
            vec![
                format!(
                    "homebrew receipt: {}",
                    root.join("Cellar/node/24/INSTALL_RECEIPT.json").display()
                ),
                format!(
                    "homebrew receipt: {}",
                    root.join("Cellar/openssl@4/4.1/INSTALL_RECEIPT.json")
                        .display()
                ),
                format!(
                    "homebrew: {}",
                    root.join("Cellar/node/24/bin/node").display()
                ),
                format!("homebrew: {}", root.join("Cellar/openssl@4/4.1").display()),
                format!("node: {}", root.join("Cellar/node/24/bin/node").display()),
            ]
        );
    }

    #[test]
    fn a_uv_program_reads_its_tool_and_its_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let tool = file(&root, "uv/tools/server/bin/server", "");
        let python = file(&root, "uv/python/cpython-3.12/bin/python3.12", "");
        let found = resolve(&tool, Layout::ALL, "linux", &|_| Ok(())).unwrap();
        assert_eq!(found.read, vec![root.join("uv/tools/server")]);
        let found = resolve(&python, Layout::ALL, "linux", &|_| Ok(())).unwrap();
        assert_eq!(found.read, vec![root.join("uv/python/cpython-3.12")]);
    }

    #[test]
    fn homebrew_lists_bin_and_opt_only_on_macos() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        file(&root, "bin/unrelated", "not an installation grant");
        file(&root, "Cellar/unrelated/1/secret", "");
        fs::create_dir(root.join("opt")).unwrap();
        for (formula, program) in [("uv", "uvx"), ("python@3.12", "python3.12")] {
            let keg = root.join("Cellar").join(formula).join("1");
            let executable = file(&keg, &format!("bin/{program}"), "");
            file(
                &keg,
                "INSTALL_RECEIPT.json",
                r#"{"runtime_dependencies":[]}"#,
            );
            let spelling = root.join("bin").join(program);
            symlink(&executable, &spelling).unwrap();
            let macos = resolve(&spelling, Layout::ALL, "macos", &|_| Ok(())).unwrap();
            assert_eq!(
                macos.list,
                vec![root.join("bin"), root.join("opt")],
                "{formula}"
            );
            assert_eq!(macos.read, vec![keg], "{formula}");
            assert!(macos.read_file.is_empty(), "{formula}");
            let linux = resolve(&spelling, Layout::ALL, "linux", &|_| Ok(())).unwrap();
            assert!(linux.list.is_empty(), "{formula}");
        }
    }

    #[test]
    fn homebrew_listings_check_their_paths_and_link_targets() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let program = file(&root, "Cellar/uv/1/bin/uvx", "");
        file(
            &root,
            "Cellar/uv/1/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[]}"#,
        );
        for name in ["bin", "opt"] {
            let target = root.join(format!("protected-{name}"));
            fs::create_dir(&target).unwrap();
            symlink(&target, root.join(name)).unwrap();
            for blocked in [root.join(name), target] {
                let error = resolve(&program, Layout::ALL, "macos", &|path| {
                    if path == blocked {
                        Err("blocked listing".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                assert_eq!(error, "blocked listing", "{}", blocked.display());
            }
        }
    }

    #[test]
    fn a_spelling_with_traversal_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        file(&root, "venv/pyvenv.cfg", "");
        file(&root, "venv/bin/server", "");
        fs::create_dir(root.join("sub")).unwrap();
        let error = resolve(
            &root.join("sub/../venv/bin/server"),
            Layout::ALL,
            "linux",
            &|_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("contains traversal"), "{error}");
    }

    #[test]
    fn a_dependency_link_cannot_leave_its_formula() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[{"full_name":"lib"}]}"#,
        );
        fs::create_dir_all(root.join("Cellar/lib")).unwrap();
        file(
            &root,
            "outside/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[]}"#,
        );
        fs::create_dir(root.join("opt")).unwrap();
        symlink("../outside", root.join("opt/lib")).unwrap();
        assert!(
            resolve(&node, Layout::ALL, "macos", &|_| Ok(()))
                .unwrap_err()
                .contains("outside")
        );
    }

    #[test]
    fn metadata_is_checked_before_it_is_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(&root, "Cellar/node/24/INSTALL_RECEIPT.json", "not json");
        let check = |path: &Path| {
            if path
                .file_name()
                .is_some_and(|name| name == "INSTALL_RECEIPT.json")
            {
                Err("blocked metadata".to_string())
            } else {
                Ok(())
            }
        };
        assert_eq!(
            resolve(&node, Layout::ALL, "macos", &check).unwrap_err(),
            "blocked metadata"
        );
    }

    #[test]
    fn dependency_names_cannot_construct_parent_or_absolute_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        for name in ["../secret", "/secret", "tap/../secret", "bad${{name}}"] {
            file(
                &root,
                "Cellar/node/24/INSTALL_RECEIPT.json",
                &serde_json::json!({"runtime_dependencies": [{"full_name": name}]}).to_string(),
            );
            let error = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
            assert!(
                error.contains("invalid installation dependency name"),
                "{error}"
            );
        }
    }

    #[test]
    fn cyclic_dependency_metadata_terminates_without_broad_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[{"full_name":"lib"}]}"#,
        );
        file(
            &root,
            "Cellar/lib/1/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[{"full_name":"node"}]}"#,
        );
        fs::create_dir(root.join("opt")).unwrap();
        symlink("../Cellar/node/24", root.join("opt/node")).unwrap();
        symlink("../Cellar/lib/1", root.join("opt/lib")).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(resolve(&node, Layout::ALL, "macos", &|_| Ok(())));
        });
        let found = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("a dependency cycle must terminate")
            .unwrap();
        assert_eq!(
            found.read,
            vec![root.join("Cellar/node/24"), root.join("Cellar/lib/1")]
        );
    }

    #[test]
    fn an_environment_under_a_directory_alias_keeps_its_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let python = file(&root, "runtime/bin/python3.12", "");
        file(&root, "environment/pyvenv.cfg", "home = /unused");
        fs::create_dir_all(root.join("environment/bin")).unwrap();
        symlink(&python, root.join("environment/bin/python")).unwrap();
        symlink(root.join("environment"), root.join("alias")).unwrap();
        let found = resolve(
            &root.join("alias/bin/python"),
            Layout::ALL,
            "macos",
            &|_| Ok(()),
        )
        .unwrap();
        assert!(found.read.contains(&root.join("environment")), "{found:?}");
    }

    #[test]
    fn a_wildcard_in_a_host_path_is_literal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "node*/bin/node", "");
        file(&root, "node*/share/node-docs/index", "");
        file(&root, "node-private/share/node-extra/secret", "");
        let found = resolve(&node, Layout::ALL, "linux", &|_| Ok(())).unwrap();
        assert_eq!(
            found.read,
            vec![root.join("node*/bin"), root.join("node*/share/node-docs")]
        );
    }

    #[test]
    fn metadata_reads_reject_special_files_without_waiting_for_a_writer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("receipt");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(read_text(&path)).unwrap());
        let error = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("a special file must not block resolution")
            .unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn a_listing_checks_a_link_target_before_it_lists() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("protected")).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root.join("protected"), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(root.join("protected")).is_ok() {
            eprintln!("skipping order proof: this user can list a mode-000 directory");
            return;
        }
        symlink(root.join("protected"), root.join("alias")).unwrap();
        let error = children(&root.join("alias"), "node-", &|path| {
            if path == root.join("protected") {
                Err("protected before listing".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error, "protected before listing");
    }

    #[test]
    fn oversized_metadata_and_dependency_lists_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        let receipt = file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            &" ".repeat(MAX_BYTES as usize + 1),
        );
        let error = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
        assert!(error.contains("exceeds 1 MiB"), "{error}");
        fs::write(receipt, serde_json::json!({"runtime_dependencies": vec![serde_json::json!({"full_name":"lib"}); MAX_ITEMS+1]}).to_string()).unwrap();
        let error = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
        assert!(error.contains("dependency limit exceeded"), "{error}");
    }

    #[test]
    fn an_excessive_dependency_closure_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("opt")).unwrap();
        let program = file(&root, "Cellar/pkg0/1/bin/server", "");
        for index in 0..=MAX_ITEMS {
            let deps = if index == MAX_ITEMS {
                vec![]
            } else {
                vec![serde_json::json!({"full_name":format!("pkg{}", index+1)})]
            };
            file(
                &root,
                &format!("Cellar/pkg{index}/1/INSTALL_RECEIPT.json"),
                &serde_json::json!({"runtime_dependencies":deps}).to_string(),
            );
            symlink(
                format!("../Cellar/pkg{index}/1"),
                root.join(format!("opt/pkg{index}")),
            )
            .unwrap();
        }
        let error = resolve(&program, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
        assert!(error.contains("dependency limit exceeded"), "{error}");
    }

    #[test]
    fn an_excessive_listing_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "bin/node", "");
        for index in 0..=MAX_ITEMS {
            fs::create_dir_all(root.join(format!("share/node-{index}"))).unwrap();
        }
        let error = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
        assert!(error.contains("entry limit exceeded"), "{error}");
    }

    #[test]
    fn a_linked_dependency_domain_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[{"full_name":"lib"}]}"#,
        );
        file(
            &root,
            "other/1/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[]}"#,
        );
        fs::create_dir(root.join("opt")).unwrap();
        symlink("../other", root.join("Cellar/lib")).unwrap();
        symlink("../Cellar/lib/1", root.join("opt/lib")).unwrap();
        let error = resolve(&node, Layout::ALL, "macos", &|_| Ok(())).unwrap_err();
        assert!(error.contains("contains a link"), "{error}");
    }

    #[test]
    fn only_the_named_layouts_apply() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "Cellar/node/24/bin/node", "");
        file(
            &root,
            "Cellar/node/24/INSTALL_RECEIPT.json",
            r#"{"runtime_dependencies":[]}"#,
        );
        let found = resolve(&node, &[Layout::Node], "macos", &|_| Ok(())).unwrap();
        assert_eq!(
            found.read,
            vec![root.join("Cellar/node/24/bin")],
            "{found:?}"
        );
        assert!(
            found
                .sources
                .iter()
                .all(|source| !source.contains("receipt"))
        );
        let program = file(&root, "programs/server", "");
        assert!(
            resolve(&program, &[Layout::Node], "macos", &|_| Ok(()))
                .unwrap()
                .read
                .is_empty()
        );
        assert_eq!(
            resolve(&program, &[Layout::Directory], "macos", &|_| Ok(()))
                .unwrap()
                .read,
            vec![root.join("programs")]
        );
    }

    #[test]
    fn box_core_decides_which_install_paths_a_tool_cannot_read() {
        use strands_box::{ForbiddenClass, GrantRefusal};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = root.join("install");
        fs::create_dir(&path).unwrap();
        let refusals = crate::storage_files::Refusals::default();
        let check = |answer: Result<bool, (GrantRefusal, String)>| {
            check_path(
                &path,
                &root.join("home"),
                &root.join("work"),
                &refusals,
                &|_| answer.clone(),
            )
        };
        assert_eq!(check(Ok(false)), Ok(()));
        for passed in [
            GrantRefusal::Forbidden(ForbiddenClass::SystemTree),
            GrantRefusal::Forbidden(ForbiddenClass::LoaderDirectory),
            GrantRefusal::Link,
            GrantRefusal::Absent,
        ] {
            assert_eq!(check(Err((passed, "core".into()))), Ok(()), "{passed:?}");
        }
        assert!(
            check(Ok(true))
                .unwrap_err()
                .contains("lies in a credential store")
        );
        for refused in [
            GrantRefusal::Forbidden(ForbiddenClass::CredentialStore),
            GrantRefusal::Forbidden(ForbiddenClass::MachineCredential),
            GrantRefusal::Other,
        ] {
            let error = check(Err((refused, "core reason".into()))).unwrap_err();
            assert!(error.contains("core reason"), "{refused:?}: {error}");
        }
    }

    #[test]
    fn a_layout_is_known_by_its_name() {
        for layout in Layout::ALL {
            assert_eq!(Layout::named(layout.name()), Some(*layout));
        }
        assert_eq!(Layout::named("conda"), None);
    }

    #[test]
    fn an_nvm_runtime_does_not_pick_up_a_neighboring_homebrew_installation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let node = file(&root, "nvm/v24/bin/node", "");
        file(&root, "brew/Cellar/node/24/bin/node", "");
        let found = resolve(&node, &[Layout::Node, Layout::Homebrew], "macos", &|_| {
            Ok(())
        })
        .unwrap();
        assert_eq!(found.read, vec![root.join("nvm/v24/bin")]);
        assert!(found.read_file.is_empty());
        assert!(
            found
                .sources
                .iter()
                .all(|source| !source.contains("homebrew"))
        );
    }
}
