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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// The layouts that can resolve which file is the program, not only add reads.
pub(crate) const PROGRAM_LAYOUTS: &[Layout] = &[Layout::Npm];

/// The platform that a program must run on, in npm's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Platform<'a> {
    pub(crate) os: &'a str,
    pub(crate) cpu: &'a str,
    pub(crate) libc: Option<&'a str>,
}

impl Platform<'static> {
    /// The host that `os` and `arch` name, as `std::env::consts` names them, with its libc as
    /// npm detects it.
    pub(crate) fn host(os: &str, arch: &str) -> Self {
        Self {
            os: match os {
                "macos" => "darwin",
                "linux" => "linux",
                _ => "unknown",
            },
            cpu: match arch {
                "aarch64" => "arm64",
                "x86_64" => "x64",
                _ => "unknown",
            },
            libc: (os == "linux").then(host_libc).flatten(),
        }
    }
}

/// The libc family that npm reads from `/usr/bin/ldd`, without running it.
fn host_libc() -> Option<&'static str> {
    let text = read_text(Path::new("/usr/bin/ldd")).ok()?;
    if text.contains("musl") {
        Some("musl")
    } else if text.contains("GNU C Library") {
        Some("glibc")
    } else {
        None
    }
}

/// The native program that an npm launcher runs, and each file that chose it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Resolved {
    pub(crate) program: PathBuf,
    pub(crate) sources: Vec<PathBuf>,
    /// The device and inode of `program` when it was chosen.
    pub(crate) identity: (u64, u64),
}

/// The package manager whose launcher `box` does not resolve, by the launcher's real file.
pub(crate) fn unsupported_launcher(real: &Path) -> Option<&'static str> {
    let text = real.to_string_lossy();
    if text.contains("/node_modules/.pnpm/") {
        return Some("pnpm");
    }
    if real.file_name().is_some_and(|name| name == "volta-shim") || text.contains("/.volta/") {
        return Some("Volta");
    }
    if text.contains("/yarn/global/node_modules/") {
        return Some("Yarn Classic");
    }
    if text.contains("/.bun/install/global/") {
        return Some("Bun");
    }
    let words = crate::program::shebang(real);
    if words.first().is_some_and(|first| first == "/bin/sh")
        && read_text(real).is_ok_and(|script| script.contains(".pnpm"))
    {
        return Some("pnpm");
    }
    None
}

/// The native program that the npm launcher `launcher`, whose real file is `real`, runs for
/// `name` on `platform`, or none when `real` is not in an npm global installation.
pub(crate) fn resolve_program(
    launcher: &Path,
    real: &Path,
    name: &str,
    platform: &Platform<'_>,
) -> Result<Option<Resolved>, String> {
    let parts = parts(real)?;
    let Some(boundary) = (1..parts.len())
        .find(|&i| parts[i] == "node_modules" && parts[i - 1] == "lib" && i + 2 < parts.len())
    else {
        return Ok(None);
    };
    let root = join(&parts[..=boundary]);
    let package_len = if parts[boundary + 1].starts_with('@') {
        2
    } else {
        1
    };
    if parts.len() <= boundary + package_len + 1 {
        return Ok(None);
    }
    let package: Vec<&str> = parts[boundary + 1..=boundary + package_len].to_vec();
    if !package.iter().all(|part| component(part)) {
        return Err(format!(
            "the npm package folder {} has an unexpected name",
            real.display()
        ));
    }
    let tree = Tree::open(&root)?;
    let launcher_rel: Vec<&str> = parts[boundary + 1..].to_vec();
    tree.check_file(&launcher_rel, real)?;
    let manifest = tree.read_json(&[package.as_slice(), &["package.json"]].concat())?;
    let package_name = package.join("/");
    let bin = normalized_bin(&manifest)?;
    let launcher_target = launcher_rel[package_len..].join("/");
    if bin.get(name) != Some(&launcher_target) {
        return Err(format!(
            "the npm package {package_name} does not name {} as its `{name}` command",
            launcher.display()
        ));
    }
    let mut sources = vec![
        launcher.to_path_buf(),
        real.to_path_buf(),
        tree.path(&[package.as_slice(), &["package.json"]].concat()),
    ];
    let optional = match manifest.get("optionalDependencies") {
        None => serde_json::Map::new(),
        Some(serde_json::Value::Object(map)) => map.clone(),
        Some(_) => {
            return Err(format!(
                "the npm package {package_name} has an `optionalDependencies` that is not an object"
            ));
        }
    };
    if optional.len() > 64 {
        return Err(format!(
            "the npm package {package_name} lists over 64 optional dependencies"
        ));
    }
    let mut eligible = Vec::new();
    let mut found = Vec::new();
    for key in optional.keys() {
        let key_parts: Vec<&str> = key.split('/').collect();
        let valid = match key_parts.as_slice() {
            [scope, name] => scope.starts_with('@') && component(scope) && component(name),
            [name] => !name.starts_with('@') && component(name),
            _ => false,
        };
        if !valid {
            return Err(format!(
                "the npm package {package_name} lists the optional dependency {key:?}, which is not a package name"
            ));
        }
        let (folder, probed) = tree.lookup(&package, &key_parts)?;
        sources.extend(probed);
        let Some(folder) = folder else {
            continue;
        };
        let file: Vec<&str> = folder
            .iter()
            .map(String::as_str)
            .chain(["package.json"])
            .collect();
        let dependency = tree.read_json(&file)?;
        let file = tree.path(&file);
        found.push(key.clone());
        let native = check_platform(&dependency, platform, platform.cpu)?;
        let translated = platform.os == "darwin"
            && platform.cpu == "arm64"
            && check_platform(&dependency, platform, "x64")?;
        if native || translated {
            eligible.push((native, key.clone(), folder, dependency, file));
        }
    }
    let native: Vec<_> = eligible.iter().filter(|entry| entry.0).collect();
    let pool: Vec<_> = if native.is_empty() {
        eligible.iter().collect()
    } else {
        native
    };
    let chosen = match pool.as_slice() {
        [one] => *one,
        [] => {
            let found = if found.is_empty() {
                "none is installed".to_string()
            } else {
                format!("found {}", found.join(", "))
            };
            return Err(format!(
                "npm installed {package_name} without a platform package for {} {} ({found}); \
                 reinstall it with npm",
                platform.os, platform.cpu
            ));
        }
        several => {
            let keys: Vec<&str> = several.iter().map(|entry| entry.1.as_str()).collect();
            return Err(format!(
                "more than one platform package of {package_name} fits this host: {}",
                keys.join(", ")
            ));
        }
    };
    let (_, key, folder, dependency, file) = chosen;
    let folder: Vec<&str> = folder.iter().map(String::as_str).collect();
    let folder = folder.as_slice();
    sources.push(file.clone());
    let (entry, manifest_file) = entrypoint(&tree, folder, dependency, name)
        .map_err(|why| format!("the platform package {key} of {package_name} {why}"))?;
    sources.extend(manifest_file);
    let program_rel: Vec<&str> = folder
        .iter()
        .copied()
        .chain(entry.iter().map(String::as_str))
        .collect();
    let identity = tree.program(&program_rel)?;
    let program = tree.path(&program_rel);
    sources.push(program.clone());
    Ok(Some(Resolved {
        program,
        sources,
        identity,
    }))
}

/// The entry point of the platform package in `folder` for `name`: its `bin` mapping, else a
/// Codex package manifest, with the manifest that named it.
fn entrypoint(
    tree: &Tree,
    folder: &[&str],
    dependency: &serde_json::Value,
    name: &str,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    if let Some(target) = normalized_bin(dependency)?.get(name) {
        return Ok((target.split('/').map(str::to_string).collect(), None));
    }
    let vendor = [folder, &["vendor"]].concat();
    let mut manifests = Vec::new();
    for target in tree.list(&vendor)? {
        let file = [vendor.as_slice(), &[target.as_str(), "codex-package.json"]].concat();
        if !tree.exists(&file)? {
            continue;
        }
        let manifest = tree.read_json(&file)?;
        if manifest.get("layoutVersion") != Some(&serde_json::Value::from(1)) {
            return Err(format!(
                "has a {} with an unknown `layoutVersion`",
                tree.path(&file).display()
            ));
        }
        if manifest.get("target").and_then(serde_json::Value::as_str) != Some(target.as_str()) {
            return Err(format!(
                "has a {} whose `target` is not its folder",
                tree.path(&file).display()
            ));
        }
        let entry = manifest
            .get("entrypoint")
            .and_then(serde_json::Value::as_str)
            .map(|entry| entry.split('/').map(str::to_string).collect::<Vec<_>>())
            .filter(|parts| parts.iter().all(|part| component(part)))
            .ok_or_else(|| {
                format!(
                    "has a {} whose `entrypoint` is not a relative path inside it",
                    tree.path(&file).display()
                )
            })?;
        if entry.last().map(String::as_str) != Some(name) {
            return Err(format!(
                "has a {} whose `entrypoint` is not `{name}`",
                tree.path(&file).display()
            ));
        }
        manifests.push((
            ["vendor".to_string(), target.clone()]
                .into_iter()
                .chain(entry)
                .collect::<Vec<_>>(),
            tree.path(&file),
        ));
    }
    match manifests.len() {
        1 => {
            let (entry, file) = manifests.remove(0);
            Ok((entry, Some(file)))
        }
        0 => Err(format!(
            "names no entry point for `{name}`: no `bin` and no vendor/<target>/codex-package.json"
        )),
        _ => Err("has more than one vendor/<target>/codex-package.json".to_string()),
    }
}

/// The `bin` of an npm `package.json`, as npm normalizes it: each command name to its file.
fn normalized_bin(
    manifest: &serde_json::Value,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let base = |key: &str| -> Option<String> {
        let key = key.replace(['\\', ':'], "/");
        let name = key.rsplit('/').next().unwrap_or_default();
        (!name.is_empty() && !matches!(name, "." | "..")).then(|| name.to_string())
    };
    let entries: Vec<(String, String)> = match manifest.get("bin") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(target)) => manifest
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(base)
            .map(|name| vec![(name, target.clone())])
            .unwrap_or_default(),
        Some(serde_json::Value::Array(targets)) => targets
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter_map(|target| base(target).map(|name| (name, target.to_string())))
            .collect(),
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .filter_map(|(key, target)| Some((base(key)?, target.as_str()?.to_string())))
            .collect(),
        Some(_) => Vec::new(),
    };
    Ok(entries
        .into_iter()
        .filter_map(|(name, target)| Some((name, normalized_target(&target)?)))
        .collect())
}

/// A `bin` target as npm joins it to `/`: `.` and `..` fold, and the leading `/` goes.
fn normalized_target(target: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Whether npm's `checkPlatform` accepts the package `manifest` on `platform` with `cpu`.
fn check_platform(
    manifest: &serde_json::Value,
    platform: &Platform<'_>,
    cpu: &str,
) -> Result<bool, String> {
    let field = |key: &str| -> Result<Option<Vec<String>>, String> {
        match manifest.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(entry)) => Ok(Some(vec![entry.clone()])),
            Some(serde_json::Value::Array(entries)) => entries
                .iter()
                .map(|entry| entry.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .map(Some)
                .ok_or_else(|| {
                    format!("a platform package has a `{key}` that is not a list of strings")
                }),
            Some(_) => Err(format!(
                "a platform package has a `{key}` that is not a list of strings"
            )),
        }
    };
    let os_ok = field("os")?.is_none_or(|list| check_list(platform.os, &list));
    let cpu_ok = field("cpu")?.is_none_or(|list| check_list(cpu, &list));
    let libc_ok = match (field("libc")?, platform.libc) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(list), Some(libc)) => check_list(libc, &list),
    };
    Ok(os_ok && cpu_ok && libc_ok)
}

/// npm's `checkList`: `any` alone accepts, an exclusion wins, and a list of only exclusions
/// accepts each value it does not exclude.
fn check_list(value: &str, list: &[String]) -> bool {
    if let [only] = list
        && only == "any"
    {
        return true;
    }
    let mut negated = 0;
    let mut matched = false;
    for entry in list {
        match entry.strip_prefix('!') {
            Some(excluded) => {
                negated += 1;
                if value == excluded {
                    return false;
                }
            }
            None => matched |= value == entry,
        }
    }
    matched || negated == list.len()
}

/// The device and inode of `stat`, whose field types differ between macOS and Linux.
#[allow(clippy::unnecessary_cast)]
fn identity(stat: &nix::libc::stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

/// An npm installation folder, opened once and walked by descriptor without following a link.
struct Tree {
    root: PathBuf,
    fd: std::os::fd::OwnedFd,
}

impl Tree {
    fn open(root: &Path) -> Result<Self, String> {
        let fd = crate::files::open_directory_below(root, Path::new("/"))
            .map_err(|error| format!("npm installation {}: {error}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
            fd,
        })
    }

    fn path(&self, rel: &[&str]) -> PathBuf {
        rel.iter()
            .fold(self.root.clone(), |path, part| path.join(part))
    }

    fn refused(&self, rel: &[&str], error: std::io::Error) -> String {
        let path = self.path(rel);
        match error.raw_os_error() {
            Some(nix::libc::ELOOP | nix::libc::ENOTDIR) => {
                format!(
                    "{} is a link, and box follows no link in an npm installation",
                    path.display()
                )
            }
            _ => format!("{}: {error}", path.display()),
        }
    }

    /// The folder `rel`, or none when one of its components does not exist.
    fn folder(&self, rel: &[&str]) -> Result<Option<std::os::fd::OwnedFd>, String> {
        let mut fd = self
            .fd
            .try_clone()
            .map_err(|error| format!("{}: {error}", self.root.display()))?;
        for (index, part) in rel.iter().enumerate() {
            match crate::files::open_at(&fd, part, nix::libc::O_RDONLY | nix::libc::O_DIRECTORY, 0)
            {
                Ok(next) => fd = next,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(self.refused(&rel[..=index], error)),
            }
        }
        Ok(Some(fd))
    }

    /// The parent folder of `rel` and the last component's status, never through a link.
    fn entry(
        &self,
        rel: &[&str],
    ) -> Result<Option<(std::os::fd::OwnedFd, nix::libc::stat)>, String> {
        let (last, parent) = rel.split_last().ok_or("an empty npm path")?;
        let Some(fd) = self.folder(parent)? else {
            return Ok(None);
        };
        match crate::files::metadata_at(&fd, last) {
            Ok(stat) if stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFLNK => {
                Err(self.refused(rel, std::io::Error::from_raw_os_error(nix::libc::ELOOP)))
            }
            Ok(stat) => Ok(Some((fd, stat))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(self.refused(rel, error)),
        }
    }

    fn exists(&self, rel: &[&str]) -> Result<bool, String> {
        Ok(self.entry(rel)?.is_some())
    }

    /// Open the regular file `rel` and check it is the file `real` names.
    fn check_file(&self, rel: &[&str], real: &Path) -> Result<(), String> {
        let (file, stat) = self.regular(rel)?;
        drop(file);
        let expected =
            fs::metadata(real).map_err(|error| format!("{}: {error}", real.display()))?;
        if identity(&stat)
            != (
                std::os::unix::fs::MetadataExt::dev(&expected),
                std::os::unix::fs::MetadataExt::ino(&expected),
            )
        {
            return Err(format!("{} changed while box read it", real.display()));
        }
        Ok(())
    }

    fn regular(&self, rel: &[&str]) -> Result<(fs::File, nix::libc::stat), String> {
        let (last, parent) = rel.split_last().ok_or("an empty npm path")?;
        let fd = self
            .folder(parent)?
            .ok_or_else(|| format!("{} does not exist", self.path(rel).display()))?;
        let file = crate::files::open_at(&fd, last, nix::libc::O_RDONLY | nix::libc::O_NONBLOCK, 0)
            .map_err(|error| self.refused(rel, error))?;
        let file = fs::File::from(file);
        let metadata = file.metadata().map_err(|error| self.refused(rel, error))?;
        if !metadata.is_file() {
            return Err(format!(
                "{} is not a regular file",
                self.path(rel).display()
            ));
        }
        let stat =
            crate::files::metadata_at(&fd, last).map_err(|error| self.refused(rel, error))?;
        if identity(&stat)
            != (
                std::os::unix::fs::MetadataExt::dev(&metadata),
                std::os::unix::fs::MetadataExt::ino(&metadata),
            )
        {
            return Err(format!(
                "{} changed while box read it",
                self.path(rel).display()
            ));
        }
        Ok((file, stat))
    }

    fn read_json(&self, rel: &[&str]) -> Result<serde_json::Value, String> {
        let (file, _) = self.regular(rel)?;
        let mut text = String::new();
        file.take(MAX_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|error| format!("{}: {error}", self.path(rel).display()))?;
        if text.len() as u64 > MAX_BYTES {
            return Err(format!("{} exceeds 1 MiB", self.path(rel).display()));
        }
        serde_json::from_str(&text)
            .map_err(|error| format!("{} is not valid JSON: {error}", self.path(rel).display()))
    }

    /// The device and inode of the executable regular file `rel`.
    fn program(&self, rel: &[&str]) -> Result<(u64, u64), String> {
        let (file, stat) = self.regular(rel)?;
        let metadata = file.metadata().map_err(|error| self.refused(rel, error))?;
        if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 == 0 {
            return Err(format!("{} is not executable", self.path(rel).display()));
        }
        Ok(identity(&stat))
    }

    /// The names in the folder `rel`, refusing over `MAX_ITEMS`.
    fn list(&self, rel: &[&str]) -> Result<Vec<String>, String> {
        let Some(fd) = self.folder(rel)? else {
            return Ok(Vec::new());
        };
        let names = crate::files::list_at(&fd, MAX_ITEMS)
            .map_err(|error| format!("{}: {error}", self.path(rel).display()))?
            .ok_or_else(|| {
                format!(
                    "{} holds over {MAX_ITEMS} entries",
                    self.path(rel).display()
                )
            })?;
        Ok(names)
    }

    /// The folder of the dependency `key` of `package`, in Node's ancestor order inside this
    /// installation, where the nearest existing folder shadows the others.
    fn lookup(
        &self,
        package: &[&str],
        key: &[&str],
    ) -> Result<(Option<Vec<String>>, Vec<PathBuf>), String> {
        let mut base: Vec<&str> = package.to_vec();
        let mut probed = Vec::new();
        loop {
            let at: Option<Vec<&str>> = match base.last() {
                None => Some(key.to_vec()),
                Some(&"node_modules") => None,
                Some(_) => Some([base.as_slice(), &["node_modules"], key].concat()),
            };
            if let Some(at) = at {
                probed.push(self.path(&at));
                match self.entry(&at)? {
                    Some((_, stat)) if stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR => {
                        return Ok((
                            Some(at.iter().map(|part| part.to_string()).collect()),
                            probed,
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "{} is not a package folder",
                            self.path(&at).display()
                        ));
                    }
                    None => {}
                }
            }
            if base.pop().is_none() {
                return Ok((None, probed));
            }
        }
    }
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

    const MAC_ARM: Platform<'static> = Platform {
        os: "darwin",
        cpu: "arm64",
        libc: None,
    };
    const LINUX_X64: Platform<'static> = Platform {
        os: "linux",
        cpu: "x64",
        libc: Some("glibc"),
    };

    /// An npm prefix under a fresh root, and the root that owns it.
    fn prefix() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap().join("npm-global");
        (temp, prefix)
    }

    fn resolve_codex(prefix: &Path, platform: &Platform<'_>) -> Result<Option<Resolved>, String> {
        let launcher = prefix.join("bin/codex");
        let real = fs::canonicalize(&launcher).unwrap();
        resolve_program(&launcher, &real, "codex", platform)
    }

    #[test]
    fn an_npm_launcher_resolves_to_the_entry_point_its_platform_package_names() {
        let (_temp, prefix) = prefix();
        let programs = crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let package = prefix.join("lib/node_modules/@openai/codex");
        let platform = package.join("node_modules/@openai/codex-darwin-arm64");
        let resolved = resolve_codex(&prefix, &MAC_ARM)
            .unwrap()
            .expect("an npm launcher");
        assert_eq!(resolved.program, programs[0]);
        for source in [
            prefix.join("bin/codex"),
            package.join("bin/codex.js"),
            package.join("package.json"),
            platform.join("package.json"),
            platform.join("vendor/aarch64-apple-darwin/codex-package.json"),
            programs[0].clone(),
        ] {
            assert!(
                resolved.sources.contains(&source),
                "{source:?} in {:?}",
                resolved.sources
            );
        }
    }

    #[test]
    fn a_same_name_executable_that_no_entry_point_names_is_not_the_program() {
        let (_temp, prefix) = prefix();
        let programs = crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let platform =
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64");
        crate::fixtures::binary(&platform.join("codex"));
        crate::fixtures::binary(&platform.join("vendor/aarch64-apple-darwin/codex-path/codex"));
        let resolved = resolve_codex(&prefix, &MAC_ARM).unwrap().unwrap();
        assert_eq!(resolved.program, programs[0]);
        fs::remove_file(platform.join("vendor/aarch64-apple-darwin/codex-package.json")).unwrap();
        let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
        assert!(
            error.contains("names no entry point for `codex`"),
            "{error}"
        );
    }

    #[test]
    fn the_platform_package_for_the_host_is_chosen_by_npms_os_and_cpu_fields() {
        let (_temp, prefix) = prefix();
        let programs = crate::fixtures::npm_codex(&prefix, &["darwin-arm64", "linux-x64"]);
        assert_eq!(
            resolve_codex(&prefix, &LINUX_X64).unwrap().unwrap().program,
            programs[1]
        );
        assert_eq!(
            resolve_codex(&prefix, &MAC_ARM).unwrap().unwrap().program,
            programs[0]
        );
        let error = resolve_codex(
            &prefix,
            &Platform {
                os: "linux",
                cpu: "arm64",
                libc: None,
            },
        )
        .unwrap_err();
        assert!(
            error.contains("without a platform package for linux arm64")
                && error.contains("@openai/codex-darwin-arm64")
                && error.contains("@openai/codex-linux-x64"),
            "{error}"
        );
    }

    #[test]
    fn an_arm64_mac_takes_its_native_package_first_and_an_x64_one_alone() {
        let (_temp, prefix) = prefix();
        let programs = crate::fixtures::npm_codex(&prefix, &["darwin-x64", "darwin-arm64"]);
        assert_eq!(
            resolve_codex(&prefix, &MAC_ARM).unwrap().unwrap().program,
            programs[1]
        );
        let (_other, prefix) = self::prefix();
        let programs = crate::fixtures::npm_codex(&prefix, &["darwin-x64"]);
        assert_eq!(
            resolve_codex(&prefix, &MAC_ARM).unwrap().unwrap().program,
            programs[0]
        );
        let intel = Platform {
            os: "darwin",
            cpu: "x64",
            libc: None,
        };
        let (_third, prefix) = self::prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        assert!(
            resolve_codex(&prefix, &intel).is_err(),
            "an Intel Mac runs no arm64 program"
        );
    }

    #[test]
    fn two_platform_packages_that_both_fit_the_host_are_refused() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["linux-x64", "linux-arm64"]);
        let other =
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64");
        file(
            &other,
            "package.json",
            r#"{"name":"@openai/codex","os":"linux","cpu":["!arm64"]}"#,
        );
        let error = resolve_codex(&prefix, &LINUX_X64).unwrap_err();
        assert!(error.contains("more than one platform package"), "{error}");
    }

    #[test]
    fn the_nearest_dependency_folder_shadows_a_farther_one() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let modules = prefix.join("lib/node_modules");
        let hoisted = crate::fixtures::codex_platform_package(
            &modules.join("@openai/codex-linux-x64"),
            "linux-x64",
        );
        assert_eq!(
            resolve_codex(&prefix, &LINUX_X64).unwrap().unwrap().program,
            hoisted
        );
        crate::fixtures::codex_platform_package(
            &modules.join("@openai/codex/node_modules/@openai/codex-linux-x64"),
            "linux-x64",
        );
        let nested = modules.join("@openai/codex/node_modules/@openai/codex-linux-x64");
        file(
            &nested,
            "package.json",
            r#"{"name":"@openai/codex","os":["linux"],"cpu":["arm64"]}"#,
        );
        assert!(
            resolve_codex(&prefix, &LINUX_X64).is_err(),
            "a nearer package that does not fit hides the hoisted one"
        );
    }

    #[test]
    fn npm_check_list_accepts_what_npm_accepts() {
        let list = |entries: &[&str]| {
            entries
                .iter()
                .map(|entry| entry.to_string())
                .collect::<Vec<_>>()
        };
        for (value, entries, expected) in [
            ("linux", &["linux"][..], true),
            ("darwin", &["linux"][..], false),
            ("darwin", &[][..], true),
            ("darwin", &["any"][..], true),
            ("darwin", &["!win32"][..], true),
            ("win32", &["!win32"][..], false),
            ("linux", &["linux", "!linux"][..], false),
            ("linux", &["!win32", "darwin"][..], false),
        ] {
            assert_eq!(
                check_list(value, &list(entries)),
                expected,
                "{value} in {entries:?}"
            );
        }
        let manifest = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
        assert!(check_platform(&manifest(r#"{"os":"linux"}"#), &LINUX_X64, "x64").unwrap());
        assert!(check_platform(&manifest(r#"{}"#), &LINUX_X64, "x64").unwrap());
        let unknown = Platform {
            libc: None,
            ..LINUX_X64
        };
        assert!(!check_platform(&manifest(r#"{"libc":["!musl"]}"#), &unknown, "x64").unwrap());
        assert!(check_platform(&manifest(r#"{"libc":["!musl"]}"#), &LINUX_X64, "x64").unwrap());
        let musl = Platform {
            libc: Some("musl"),
            ..LINUX_X64
        };
        assert!(!check_platform(&manifest(r#"{"libc":["glibc"]}"#), &musl, "x64").unwrap());
        assert!(check_platform(&manifest(r#"{"os":[1]}"#), &LINUX_X64, "x64").is_err());
    }

    #[test]
    fn a_bin_maps_names_as_npm_normalizes_them() {
        let bin = |text: &str| normalized_bin(&serde_json::from_str(text).unwrap()).unwrap();
        assert_eq!(
            bin(r#"{"name":"@openai/codex","bin":"./bin/../bin/codex.js"}"#).get("codex"),
            Some(&"bin/codex.js".to_string())
        );
        assert_eq!(
            bin(r#"{"bin":["bin/a.js","lib/b"]}"#).get("b"),
            Some(&"lib/b".to_string())
        );
        assert_eq!(
            bin(r#"{"bin":{"@scope/tool":"../../x.js"}}"#).get("tool"),
            Some(&"x.js".to_string())
        );
    }

    #[test]
    fn a_launcher_that_its_package_bin_does_not_name_is_refused() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let package = prefix.join("lib/node_modules/@openai/codex");
        file(
            &package,
            "package.json",
            r#"{"name":"@openai/codex","bin":{"codex":"bin/other.js"}}"#,
        );
        let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
        assert!(error.contains("does not name"), "{error}");
    }

    #[test]
    fn malformed_oversized_and_special_metadata_is_refused() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let platform =
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64");
        let manifest = platform.join("package.json");
        fs::write(&manifest, "{").unwrap();
        assert!(
            resolve_codex(&prefix, &MAC_ARM)
                .unwrap_err()
                .contains("is not valid JSON")
        );
        fs::write(&manifest, " ".repeat(MAX_BYTES as usize + 1)).unwrap();
        assert!(
            resolve_codex(&prefix, &MAC_ARM)
                .unwrap_err()
                .contains("exceeds 1 MiB")
        );
        fs::remove_file(&manifest).unwrap();
        nix::unistd::mkfifo(&manifest, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert!(
            resolve_codex(&prefix, &MAC_ARM)
                .unwrap_err()
                .contains("not a regular file")
        );
    }

    #[test]
    fn a_link_inside_the_installation_is_never_followed() {
        let (temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &[]);
        let outside = temp.path().canonicalize().unwrap().join("outside");
        crate::fixtures::codex_platform_package(&outside, "darwin-arm64");
        fs::create_dir_all(prefix.join("lib/node_modules/@openai/codex/node_modules/@openai"))
            .unwrap();
        symlink(
            &outside,
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64"),
        )
        .unwrap();
        let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
        assert!(error.contains("is a link"), "{error}");
        fs::remove_file(
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64"),
        )
        .unwrap();
        let platform =
            prefix.join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64");
        crate::fixtures::codex_platform_package(&platform, "darwin-arm64");
        let vendor = platform.join("vendor/aarch64-apple-darwin");
        fs::rename(&vendor, temp.path().join("moved")).unwrap();
        symlink(temp.path().join("moved"), &vendor).unwrap();
        let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
        assert!(
            error.contains("is a link"),
            "a swapped-in folder link: {error}"
        );
    }

    #[test]
    fn an_entry_point_that_leaves_its_package_is_refused() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let vendor = prefix.join(
            "lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin",
        );
        for (manifest, why) in [
            (
                r#"{"layoutVersion":1,"target":"aarch64-apple-darwin","entrypoint":"../../../../codex"}"#,
                "not a relative path inside it",
            ),
            (
                r#"{"layoutVersion":2,"target":"aarch64-apple-darwin","entrypoint":"bin/codex"}"#,
                "unknown `layoutVersion`",
            ),
            (
                r#"{"layoutVersion":1,"target":"x86_64-apple-darwin","entrypoint":"bin/codex"}"#,
                "`target` is not its folder",
            ),
        ] {
            file(&vendor, "codex-package.json", manifest);
            let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
            assert!(error.contains(why), "{manifest}: {error}");
        }
    }

    #[test]
    fn a_folder_past_the_traversal_limit_is_refused() {
        let (_temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let vendor = prefix
            .join("lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor");
        for index in 0..MAX_ITEMS {
            fs::create_dir(vendor.join(format!("extra-{index}"))).unwrap();
        }
        let error = resolve_codex(&prefix, &MAC_ARM).unwrap_err();
        assert!(error.contains("entries"), "{error}");
    }

    #[test]
    fn discovery_runs_no_package_command() {
        let (temp, prefix) = prefix();
        crate::fixtures::npm_codex(&prefix, &["darwin-arm64"]);
        let marker = temp.path().join("ran");
        let package = prefix.join("lib/node_modules/@openai/codex");
        let run = format!("touch {}", marker.display());
        crate::fixtures::script(&package.join("bin/codex.js"), &run);
        crate::fixtures::write(
            &package.join("bin/codex.js"),
            &format!("#!/usr/bin/env node\nrequire('child_process').execSync('{run}')\n"),
        );
        crate::fixtures::executable(&package.join("bin/codex.js"));
        let manifest = fs::read_to_string(package.join("package.json"))
            .unwrap()
            .replacen(
                "\"type\": \"module\",",
                &format!("\"type\": \"module\",\n  \"scripts\": {{ \"postinstall\": \"{run}\" }},"),
                1,
            );
        fs::write(package.join("package.json"), manifest).unwrap();
        let vendor =
            package.join("node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin");
        crate::fixtures::script(&vendor.join("bin/codex"), &run);
        resolve_codex(&prefix, &MAC_ARM).unwrap().unwrap();
        assert!(!marker.exists(), "discovery ran a package command");
    }

    #[test]
    fn launchers_of_other_package_managers_are_named() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let shim = file(
            &root,
            "Library/pnpm/codex",
            "#!/bin/sh\nbasedir=$(dirname \"$0\")\nexec node \"$basedir/global/5/.pnpm/node_modules/@openai/codex/bin/codex.js\" \"$@\"\n",
        );
        assert_eq!(unsupported_launcher(&shim), Some("pnpm"));
        for (path, manager) in [
            (
                "pnpm/global/5/node_modules/.pnpm/@openai+codex@0.171.0/node_modules/@openai/codex/bin/codex.js",
                "pnpm",
            ),
            (".volta/bin/volta-shim", "Volta"),
            (
                ".config/yarn/global/node_modules/@openai/codex/bin/codex.js",
                "Yarn Classic",
            ),
            (
                ".bun/install/global/node_modules/@openai/codex/bin/codex.js",
                "Bun",
            ),
        ] {
            let path = file(&root, path, "#!/usr/bin/env node\n");
            assert_eq!(unsupported_launcher(&path), Some(manager), "{path:?}");
        }
        let npm = file(
            &root,
            "npm-global/lib/node_modules/@openai/codex/bin/codex.js",
            "#!/usr/bin/env node\n",
        );
        assert_eq!(unsupported_launcher(&npm), None);
    }
}
