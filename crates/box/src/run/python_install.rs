//! What a Python install loads code from, read from its files without running it.
//!
//! [`detect`] takes the command a Python tool names and returns the folders that Python reads
//! code from, each link hop from the command to the real file, the certificate bundle its `ssl`
//! module uses, and the sources of any editable installs. Running the install to ask it would
//! need read on the whole filesystem, which Box's floors refuse, and it would run the install's
//! startup code before the box exists.
//!
//! Recognized layouts:
//!
//! | Layout | Marker | Extra folders |
//! |---|---|---|
//! | venv | `pyvenv.cfg` beside the command's `bin/` | its own `site-packages` plus the base's standard library |
//! | standard (python.org, pyenv, uv, conda, source) | `bin/..` holds `lib/python3.X/os.py` | none |
//! | Homebrew | real file in `Cellar/python@3.X/`, standard library holds `sitecustomize.py` | the folders `sitecustomize.py` adds |
//! | Debian | real file is `/usr/bin/python3.X`, `/usr/lib/python3/dist-packages` exists | `dist-packages` folders |
//!
//! Anything else is refused with "Use a venv", and so is a standard layout whose standard library
//! holds a `sitecustomize.py` Box doesn't model.
//!
//! [`detect`] then walks every protected folder without following links. A file with a second
//! hard link refuses startup, because the agent could change it through the other name. A link
//! that points outside the protected folders and the read-only system folders adds its target's
//! folder to what is protected and granted read.

// Only the protected folders and editable sources are wired in so far.
#![allow(dead_code)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::record::layout::lies_within;

/// Symbolic links followed before the chain counts as a loop, matching the kernel's `ELOOP` bound.
const MAXIMUM_HOPS: usize = 40;

/// Folder entries [`detect`] reads while checking the install for links before it refuses.
const MAXIMUM_WALK_ENTRIES: usize = 200_000;

/// Time [`detect`] spends checking the install for links before it refuses.
const WALK_BUDGET: Duration = Duration::from_secs(10);

/// One Python install, as its files describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonInstall {
    /// `major.minor`, e.g. `"3.14"`.
    pub(crate) version: String,
    pub(crate) kind: InstallKind,
    /// The folder above the real file's `bin/`, or the venv root.
    pub(crate) prefix: PathBuf,
    /// Every folder this Python loads code from, canonical. Nested entries stay; pass them through
    /// [`outermost`] before turning them into grants.
    pub(crate) code_folders: Vec<PathBuf>,
    /// The command, then each link hop, ending at the canonical real file.
    pub(crate) link_chain: Vec<PathBuf>,
    /// The certificate bundle the `ssl` module reads, as the install names it.
    pub(crate) cert_bundle: Option<PathBuf>,
    /// Each link hop after [`Self::cert_bundle`], ending at the canonical file.
    pub(crate) cert_link_chain: Vec<PathBuf>,
    /// Source folders of editable installs (`direct_url.json` with `dir_info.editable`) and the
    /// folders `.pth` path lines name.
    pub(crate) editable_sources: Vec<PathBuf>,
    /// What nothing in the box may write: [`Self::code_folders`], the venv root, the base install's
    /// `lib/` and framework `Python` file, and the folders the install would load code from if
    /// they existed (user site, Homebrew and Debian extras). A missing folder is its deepest
    /// existing ancestor, canonical, with the rest appended.
    pub(crate) protected: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallKind {
    Standard,
    Venv { base: Box<PythonInstall> },
    Homebrew,
    Debian,
}

/// Where the platform's fixed folders live. Tests point these at temporary folders.
#[derive(Debug, Clone)]
pub(crate) struct InstallRoots {
    /// Homebrew prefixes: `/opt/homebrew` (Apple silicon), `/usr/local` (Intel) and
    /// `/home/linuxbrew/.linuxbrew` (Linux).
    pub(crate) homebrew: Vec<PathBuf>,
    /// The folder holding `Python/3.X/site-packages`: `/Library` on macOS.
    pub(crate) macos_library: PathBuf,
    /// The root under which Debian's `usr/bin`, `usr/lib/python3`, `usr/local/lib` and
    /// `etc/ssl/certs` live: `/`.
    pub(crate) system: PathBuf,
    /// The operator's home folder, for the user site.
    pub(crate) home: Option<PathBuf>,
    pub(crate) user_site: UserSiteLayout,
}

/// Where the user site lives under the home folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserSiteLayout {
    /// `~/Library/Python/3.X/lib/python/site-packages`
    MacOs,
    /// `~/.local/lib/python3.X/site-packages`
    Linux,
}

impl InstallRoots {
    /// This host's folders.
    pub(crate) fn host() -> Self {
        Self {
            homebrew: vec![
                PathBuf::from("/opt/homebrew"),
                PathBuf::from("/usr/local"),
                PathBuf::from("/home/linuxbrew/.linuxbrew"),
            ],
            macos_library: PathBuf::from("/Library"),
            system: PathBuf::from("/"),
            home: std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|home| home.is_absolute()),
            user_site: if cfg!(target_os = "macos") {
                UserSiteLayout::MacOs
            } else {
                UserSiteLayout::Linux
            },
        }
    }
}

#[derive(Debug)]
pub(crate) enum InstallError {
    /// The command is no layout Box recognizes.
    Unrecognized(PathBuf),
    /// The command is a venv whose base install is no layout Box recognizes.
    UnrecognizedVenvBase { command: PathBuf, base: PathBuf },
    /// A file in the install has a second hard link.
    HardLink(PathBuf),
    /// The install holds too many entries to check for links in the walk's budget.
    TooLarge { folder: PathBuf },
    /// A file the layout depends on could not be read.
    Unreadable { path: PathBuf, source: io::Error },
}

impl fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrecognized(path) => write!(
                formatter,
                "{} is not a Python install Box recognizes. Use a venv",
                path.display()
            ),
            Self::UnrecognizedVenvBase { command, base } => write!(
                formatter,
                "{} is a venv, but the venv's base install {} is not one Box recognizes",
                command.display(),
                base.display()
            ),
            Self::HardLink(file) => write!(
                formatter,
                "{} has another name outside the install, so the agent could change it through \
                 that name. Rebuild the venv without hard links (for uv: --link-mode=copy)",
                file.display()
            ),
            Self::TooLarge { folder } => write!(
                formatter,
                "Box stopped checking the Python install for links at {} after \
                 {MAXIMUM_WALK_ENTRIES} entries or {} seconds. Use a smaller venv",
                folder.display(),
                WALK_BUDGET.as_secs()
            ),
            Self::Unreadable { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Describe the Python install `command` starts, from its files alone. `command` must be
/// absolute.
pub(crate) fn detect(command: &Path, roots: &InstallRoots) -> Result<PythonInstall, InstallError> {
    let unrecognized = || InstallError::Unrecognized(command.to_path_buf());
    if !command.is_absolute() {
        return Err(unrecognized());
    }
    let link_chain = link_chain(command).ok_or_else(unrecognized)?;
    let real = link_chain.last().cloned().ok_or_else(unrecognized)?;
    if !real.is_file() {
        return Err(unrecognized());
    }
    let mut install = if let Some(venv_root) = venv_root(command) {
        detect_venv(command, &venv_root, &real, link_chain, roots)?
    } else {
        let mut install = detect_installed(command, &real, roots)?;
        install.link_chain = link_chain;
        install
    };
    check_links(&mut install, roots)?;
    install.editable_sources = editable_sources(&install.code_folders)?;
    Ok(install)
}

/// The venv root when `command`'s `bin/..` holds `pyvenv.cfg`.
fn venv_root(command: &Path) -> Option<PathBuf> {
    let root = command.parent()?.parent()?;
    root.join("pyvenv.cfg")
        .is_file()
        .then(|| root.to_path_buf())
}

struct VenvConfig {
    home: Option<PathBuf>,
    include_system_site_packages: bool,
    version: Option<String>,
}

fn read_venv_config(path: &Path) -> Result<VenvConfig, InstallError> {
    let text = fs::read_to_string(path).map_err(|source| InstallError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let mut config = VenvConfig {
        home: None,
        include_system_site_packages: false,
        version: None,
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "home" => config.home = Some(PathBuf::from(value)),
            "include-system-site-packages" => {
                config.include_system_site_packages = value.eq_ignore_ascii_case("true");
            }
            // `venv` writes `version`, `uv` and `virtualenv` write `version_info`.
            "version" | "version_info" => config.version = major_minor(value),
            _ => {}
        }
    }
    Ok(config)
}

/// `"3.14.7"` → `"3.14"`.
fn major_minor(version: &str) -> Option<String> {
    let mut parts = version.split('.');
    let major = parts.next().filter(|part| !part.is_empty())?;
    let minor = parts.next().filter(|part| !part.is_empty())?;
    Some(format!("{major}.{minor}"))
}

fn detect_venv(
    command: &Path,
    venv_root: &Path,
    real: &Path,
    link_chain: Vec<PathBuf>,
    roots: &InstallRoots,
) -> Result<PythonInstall, InstallError> {
    let unrecognized = || InstallError::Unrecognized(command.to_path_buf());
    let config = read_venv_config(&venv_root.join("pyvenv.cfg"))?;
    let venv_canonical = canonical(venv_root);
    let unrecognized_base = |base: &Path| InstallError::UnrecognizedVenvBase {
        command: command.to_path_buf(),
        base: base.to_path_buf(),
    };

    // A venv made with `--copies` holds its own interpreter; its base is named by `home`.
    let base_real = if lies_within(real, &venv_canonical) {
        let home = config.home.as_deref().ok_or_else(unrecognized)?;
        let names = config
            .version
            .iter()
            .map(|version| format!("python{version}"))
            .chain(["python3".to_owned(), "python".to_owned()]);
        names
            .map(|name| home.join(name))
            .find(|candidate| candidate.is_file())
            .map(|candidate| canonical(&candidate))
            .ok_or_else(|| unrecognized_base(home))?
    } else {
        real.to_path_buf()
    };
    let mut base =
        detect_installed(&base_real, &base_real, roots).map_err(|error| match error {
            InstallError::Unrecognized(_) => unrecognized_base(&base_real),
            other => other,
        })?;
    base.link_chain = vec![base_real.clone()];
    if config
        .version
        .as_deref()
        .is_some_and(|version| version != base.version)
    {
        return Err(unrecognized());
    }

    let site_packages = venv_root
        .join("lib")
        .join(format!("python{}", base.version))
        .join("site-packages");
    if !site_packages.is_dir() {
        return Err(unrecognized());
    }
    let mut code_folders = vec![canonical(&site_packages), stdlib(&base)];
    // Protected whether or not they exist; extended below with what the base adds.
    let mut protected = vec![venv_canonical.clone()];
    protected.extend(install_core(&base.prefix));
    if config.include_system_site_packages {
        code_folders.extend(base.code_folders.iter().cloned());
        protected.extend(base.protected.iter().cloned());
    } else if base.kind == InstallKind::Homebrew {
        // Homebrew's `sitecustomize.py` adds its own `site-packages` only when
        // `sys.base_prefix in site.PREFIXES`, which a venv without system packages isn't. It
        // adds the split `python-tk` and `python-gdbm` folders in every venv.
        let libexec = |folder: &&PathBuf| folder.file_name().is_some_and(|name| name == "libexec");
        code_folders.extend(base.code_folders.iter().filter(libexec).cloned());
        protected.extend(base.protected.iter().filter(libexec).cloned());
    }
    let code_folders = dedup(code_folders);
    let mut protected_all = code_folders.clone();
    protected_all.extend(protected);
    Ok(PythonInstall {
        version: base.version.clone(),
        cert_bundle: base.cert_bundle.clone(),
        cert_link_chain: base.cert_link_chain.clone(),
        kind: InstallKind::Venv {
            base: Box::new(base),
        },
        prefix: venv_canonical,
        code_folders,
        link_chain,
        editable_sources: Vec::new(),
        protected: dedup(protected_all),
    })
}

/// What a base install at `prefix` loads code from beyond its standard library, protected
/// whether or not it exists: all of `lib/`, which holds `python3XY.zip` (on `sys.path` ahead of
/// the standard library) and the shared `libpython`, and a framework build's `Python` library.
fn install_core(prefix: &Path) -> Vec<PathBuf> {
    let mut core = vec![prefix.join("lib")];
    let framework = prefix.join("Python");
    if framework.is_file() {
        core.push(framework);
    }
    core
}

/// The base install's standard library, always its first code folder.
fn stdlib(install: &PythonInstall) -> PathBuf {
    install
        .prefix
        .join("lib")
        .join(format!("python{}", install.version))
}

/// A standard, Homebrew or Debian install whose canonical real file is `real`.
fn detect_installed(
    command: &Path,
    real: &Path,
    roots: &InstallRoots,
) -> Result<PythonInstall, InstallError> {
    let unrecognized = || InstallError::Unrecognized(command.to_path_buf());
    let bin = real.parent().ok_or_else(unrecognized)?;
    if bin.file_name().is_none_or(|name| name != "bin") {
        return Err(unrecognized());
    }
    let prefix = bin.parent().ok_or_else(unrecognized)?.to_path_buf();
    let version = stdlib_version(&prefix, real).ok_or_else(unrecognized)?;
    let library = prefix.join("lib").join(format!("python{version}"));

    let mut code_folders = vec![library.clone()];
    push_existing(&mut code_folders, &library.join("site-packages"));
    // Folders this install would load code from if they existed: protected either way.
    let mut expected = install_core(&prefix);
    if let Some(home) = &roots.home {
        // Only a framework build (python.org, Homebrew) uses `~/Library/Python` on macOS; pyenv,
        // uv and other builds there use `~/.local`, as on Linux.
        let framework = real
            .components()
            .any(|component| component.as_os_str() == "Python.framework");
        let layout = match roots.user_site {
            UserSiteLayout::MacOs if framework => UserSiteLayout::MacOs,
            _ => UserSiteLayout::Linux,
        };
        let user_site = match layout {
            UserSiteLayout::MacOs => home
                .join("Library/Python")
                .join(&version)
                .join("lib/python/site-packages"),
            UserSiteLayout::Linux => home
                .join(".local/lib")
                .join(format!("python{version}"))
                .join("site-packages"),
        };
        push_expected(&mut code_folders, &mut expected, &user_site);
    }

    let mut kind = InstallKind::Standard;
    let mut cert_bundle = None;
    if let Some(brew) = homebrew_root(real, &version, &library, roots) {
        kind = InstallKind::Homebrew;
        push_expected(
            &mut code_folders,
            &mut expected,
            &brew
                .join("lib")
                .join(format!("python{version}"))
                .join("site-packages"),
        );
        push_expected(
            &mut code_folders,
            &mut expected,
            &roots
                .macos_library
                .join("Python")
                .join(&version)
                .join("site-packages"),
        );
        for module in ["tk", "gdbm"] {
            push_expected(
                &mut code_folders,
                &mut expected,
                &brew
                    .join("opt")
                    .join(format!("python-{module}@{version}"))
                    .join("libexec"),
            );
        }
        cert_bundle = Some(brew.join("etc/openssl@3/cert.pem"));
    } else if is_debian(real, &version, roots) {
        kind = InstallKind::Debian;
        let system = canonical(&roots.system);
        push_existing(
            &mut code_folders,
            &system.join("usr/lib/python3/dist-packages"),
        );
        push_expected(
            &mut code_folders,
            &mut expected,
            &system
                .join("usr/local/lib")
                .join(format!("python{version}"))
                .join("dist-packages"),
        );
        cert_bundle = Some(system.join("etc/ssl/certs/ca-certificates.crt"));
    } else if library.join("sitecustomize.py").exists() {
        // A `sitecustomize.py` can add folders Box can't see from the files.
        return Err(unrecognized());
    }

    let cert_bundle = cert_bundle.filter(|bundle| bundle.is_file());
    let cert_link_chain = cert_bundle
        .as_deref()
        .and_then(link_chain)
        .map(|chain| chain.into_iter().skip(1).collect())
        .unwrap_or_default();
    let code_folders = dedup(code_folders);
    let mut protected = code_folders.clone();
    protected.extend(expected);
    Ok(PythonInstall {
        version,
        kind,
        prefix,
        protected: dedup(protected),
        code_folders,
        link_chain: vec![real.to_path_buf()],
        cert_bundle,
        cert_link_chain,
        editable_sources: Vec::new(),
    })
}

/// `X.Y` of the `lib/pythonX.Y` folder holding `os.py`. When more than one does, the real file's
/// own name (`python3.12`) picks; otherwise the layout is ambiguous.
fn stdlib_version(prefix: &Path, real: &Path) -> Option<String> {
    let entries = fs::read_dir(prefix.join("lib")).ok()?;
    let mut versions: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let version = name.strip_prefix("python3.")?;
            entry
                .path()
                .join("os.py")
                .is_file()
                .then(|| format!("3.{version}"))
        })
        .collect();
    match versions.len() {
        0 => None,
        1 => versions.pop(),
        _ => {
            let named = real.file_name()?.to_str()?.strip_prefix("python")?;
            versions.into_iter().find(|version| version == named)
        }
    }
}

/// The Homebrew prefix whose `Cellar/python@X.Y/` holds `real`, when the standard library holds
/// Homebrew's `sitecustomize.py`.
fn homebrew_root(
    real: &Path,
    version: &str,
    library: &Path,
    roots: &InstallRoots,
) -> Option<PathBuf> {
    if !library.join("sitecustomize.py").is_file() {
        return None;
    }
    roots
        .homebrew
        .iter()
        .map(|brew| canonical(brew))
        .find(|brew| lies_within(real, &brew.join("Cellar").join(format!("python@{version}"))))
}

fn is_debian(real: &Path, version: &str, roots: &InstallRoots) -> bool {
    let system = canonical(&roots.system);
    real == system.join("usr/bin").join(format!("python{version}"))
        && system.join("usr/lib/python3/dist-packages").is_dir()
}

/// The command, then each symbolic-link hop, ending at the canonical real file. `None` on a loop
/// or a dangling link.
fn link_chain(command: &Path) -> Option<Vec<PathBuf>> {
    let mut chain = vec![command.to_path_buf()];
    let mut current = command.to_path_buf();
    for _ in 0..MAXIMUM_HOPS {
        let Ok(target) = fs::read_link(&current) else {
            let real = current.canonicalize().ok()?;
            if real != current {
                chain.push(real);
            }
            return Some(chain);
        };
        // Join a relative target to the link's directory as it is on disk, so `..` leaves the
        // folder the link really sits in.
        let directory = canonical(current.parent()?);
        current = normalize(&directory.join(target));
        chain.push(current.clone());
    }
    None
}

/// Lexically fold `.` and `..`. Sound here because the joined prefix is already canonical.
fn normalize(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other.as_os_str()),
        }
    }
    normal
}

/// Every editable install's source folder, from `*.dist-info/direct_url.json` in `folders`, and
/// every folder a `*.pth` path line in `folders` names.
fn editable_sources(folders: &[PathBuf]) -> Result<Vec<PathBuf>, InstallError> {
    let mut sources = Vec::new();
    for folder in folders {
        let Ok(entries) = fs::read_dir(folder) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.ends_with(".pth") {
                let path = entry.path();
                let text = match fs::read(&path) {
                    Ok(text) => text,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(source) => return Err(InstallError::Unreadable { path, source }),
                };
                sources.extend(pth_folders(folder, &text));
                continue;
            }
            if !name.ends_with(".dist-info") {
                continue;
            }
            let record = entry.path().join("direct_url.json");
            let text = match fs::read_to_string(&record) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(InstallError::Unreadable {
                        path: record,
                        source,
                    });
                }
            };
            if let Some(source) = editable_source(&text) {
                sources.push(canonical(&source));
            }
        }
    }
    sources.sort();
    Ok(dedup(sources))
}

/// The folders one `.pth` file in `folder` adds to `sys.path`, as `site` reads it: every line
/// that is not blank, not a `#` comment and not an `import` line names a folder relative to
/// `folder`. Python skips a folder that doesn't exist, but the agent could create it, so missing
/// ones count too.
fn pth_folders(folder: &Path, text: &[u8]) -> Vec<PathBuf> {
    text.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| {
            !line.iter().all(u8::is_ascii_whitespace)
                && !line.starts_with(b"#")
                && !line.starts_with(b"import ")
                && !line.starts_with(b"import\t")
        })
        .map(|line| {
            let end = line
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .map_or(0, |index| index + 1);
            let named = PathBuf::from(OsString::from_vec(line[..end].to_vec()));
            canonical_lenient(&normalize(&folder.join(named)))
        })
        .collect()
}

/// Walk every protected folder without following links, in a budget of
/// [`MAXIMUM_WALK_ENTRIES`] entries and [`WALK_BUDGET`]. A regular file with a second hard link
/// refuses; a link whose target lies outside the protected folders, the read-only system folders
/// and the interpreter's own link chain adds the target's folder to `protected`, to
/// `code_folders` when it exists, and to the walk.
fn check_links(install: &mut PythonInstall, roots: &InstallRoots) -> Result<(), InstallError> {
    let system = system_trees(roots);
    let in_system = |path: &Path| {
        system.trees.iter().any(|tree| lies_within(path, tree))
            && !system.writable.iter().any(|tree| lies_within(path, tree))
    };
    let started = Instant::now();
    let mut entries = 0usize;
    let mut pending: Vec<PathBuf> = outermost(&install.protected)
        .into_iter()
        .filter(|path| !in_system(path))
        .collect();
    while let Some(path) = pending.pop() {
        entries += 1;
        if entries > MAXIMUM_WALK_ENTRIES || started.elapsed() > WALK_BUDGET {
            return Err(InstallError::TooLarge { folder: path });
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        let kind = metadata.file_type();
        if kind.is_dir() {
            let Ok(children) = fs::read_dir(&path) else {
                continue;
            };
            pending.extend(children.filter_map(Result::ok).map(|child| child.path()));
        } else if kind.is_file() {
            if metadata.nlink() > 1 {
                return Err(InstallError::HardLink(path));
            }
        } else if kind.is_symlink() {
            let Some(target) = link_target(&path) else {
                continue;
            };
            if install.link_chain.contains(&target)
                || install
                    .protected
                    .iter()
                    .any(|folder| lies_within(&target, folder))
                || in_system(&target)
            {
                continue;
            }
            let folder = target_folder(&target);
            install.protected.push(folder.clone());
            if folder.is_dir() {
                install.code_folders.push(folder.clone());
                pending.push(folder);
            }
        }
    }
    Ok(())
}

/// Where the link at `path` points, canonical as far as it exists.
fn link_target(path: &Path) -> Option<PathBuf> {
    let target = fs::read_link(path).ok()?;
    let directory = canonical(path.parent()?);
    Some(canonical_lenient(&normalize(&directory.join(target))))
}

/// The folder to protect for a link target: its nearest `site-packages` or `dist-packages`
/// folder, so one package tree stays one entry; otherwise the target folder, or the folder that
/// holds a target file.
fn target_folder(target: &Path) -> PathBuf {
    if let Some(packages) = target.ancestors().find(|ancestor| {
        ancestor
            .file_name()
            .is_some_and(|name| name == "site-packages" || name == "dist-packages")
    }) {
        return packages.to_path_buf();
    }
    if target.is_dir() {
        return target.to_path_buf();
    }
    target.parent().unwrap_or(target).to_path_buf()
}

/// The folders only an administrator writes, where a link target needs no protection of its own:
/// `/usr` (but not `/usr/local`), `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc` and `/System`.
struct SystemTrees {
    trees: Vec<PathBuf>,
    writable: Vec<PathBuf>,
}

fn system_trees(roots: &InstallRoots) -> SystemTrees {
    let system = canonical(&roots.system);
    SystemTrees {
        trees: ["usr", "bin", "sbin", "lib", "lib64", "etc", "System"]
            .iter()
            .map(|name| canonical(&system.join(name)))
            .collect(),
        writable: vec![canonical(&system.join("usr/local"))],
    }
}

/// The `file://` source of one `direct_url.json` whose `dir_info.editable` is true.
fn editable_source(text: &str) -> Option<PathBuf> {
    let record: serde_json::Value = serde_json::from_str(text).ok()?;
    if record.pointer("/dir_info/editable") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let url = record.get("url")?.as_str()?;
    let rest = url.strip_prefix("file://")?;
    let path = rest.strip_prefix("localhost").unwrap_or(rest);
    if !path.starts_with('/') {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(percent_decode(path)?)))
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = text.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

/// Drop every path that lies inside another in the list (Box refuses nested grants of the same
/// kind). Order of the survivors is kept; exact duplicates collapse to the first.
pub(crate) fn outermost(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut kept: Vec<PathBuf> = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let inside_another = paths.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && lies_within(path, other)
                && (path != other || other_index < index)
        });
        if !inside_another {
            kept.push(path.clone());
        }
    }
    kept
}

fn push_existing(folders: &mut Vec<PathBuf>, folder: &Path) {
    if folder.is_dir() {
        folders.push(canonical(folder));
    }
}

/// `folder` into `expected` whether or not it exists, and into `folders` when it does.
fn push_expected(folders: &mut Vec<PathBuf>, expected: &mut Vec<PathBuf>, folder: &Path) {
    push_existing(folders, folder);
    expected.push(canonical_lenient(folder));
}

/// `path` with its deepest existing ancestor canonical and the missing rest appended.
fn canonical_lenient(path: &Path) -> PathBuf {
    if let Ok(real) = path.canonicalize() {
        return real;
    }
    let mut missing = Vec::new();
    let mut current = path;
    while let Some(parent) = current.parent() {
        if let Some(name) = current.file_name() {
            missing.push(name.to_os_string());
        }
        if let Ok(real) = parent.canonicalize() {
            return missing
                .iter()
                .rev()
                .fold(real, |path, name| path.join(name));
        }
        current = parent;
    }
    path.to_path_buf()
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn dedup(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct Tree {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().canonicalize().expect("canonical tempdir");
            Self { _dir: dir, root }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        fn dir(&self, relative: &str) -> PathBuf {
            let path = self.path(relative);
            fs::create_dir_all(&path).expect("create dir");
            path
        }

        fn file(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.path(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
            fs::write(&path, contents).expect("write file");
            path
        }

        fn link(&self, relative: &str, target: &str) -> PathBuf {
            let path = self.path(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
            symlink(target, &path).expect("symlink");
            path
        }

        fn roots(&self) -> InstallRoots {
            InstallRoots {
                homebrew: vec![self.path("brew")],
                macos_library: self.path("Library"),
                system: self.path("system"),
                home: Some(self.path("home")),
                user_site: UserSiteLayout::MacOs,
            }
        }

        /// `prefix/bin/python3.X`, `bin/python3 -> python3.X`, and a standard library.
        fn standard(&self, prefix: &str, version: &str) -> PathBuf {
            self.file(&format!("{prefix}/bin/python{version}"), "binary");
            self.link(
                &format!("{prefix}/bin/python3"),
                &format!("python{version}"),
            );
            self.file(&format!("{prefix}/lib/python{version}/os.py"), "");
            self.dir(&format!("{prefix}/lib/python{version}/lib-dynload"));
            self.dir(&format!("{prefix}/lib/python{version}/site-packages"));
            self.path(&format!("{prefix}/bin/python3"))
        }

        fn venv(&self, venv: &str, base: &str, version: &str, include_system: bool) -> PathBuf {
            let base_bin = self.path(&format!("{base}/bin"));
            self.file(
                &format!("{venv}/pyvenv.cfg"),
                &format!(
                    "home = {}\ninclude-system-site-packages = {include_system}\nversion = {version}.4\n",
                    base_bin.display()
                ),
            );
            self.link(
                &format!("{venv}/bin/python{version}"),
                &base_bin.join(format!("python{version}")).to_string_lossy(),
            );
            self.link(&format!("{venv}/bin/python3"), &format!("python{version}"));
            self.dir(&format!("{venv}/lib/python{version}/site-packages"));
            self.path(&format!("{venv}/bin/python3"))
        }
    }

    #[test]
    fn a_standard_install_loads_its_library_site_packages_and_user_site() {
        let tree = Tree::new();
        let command = tree.standard("base", "3.12");
        // Not a framework build, so on macOS too its user site is `~/.local`.
        tree.dir("home/Library/Python/3.12/lib/python/site-packages");
        let user_site = tree.dir("home/.local/lib/python3.12/site-packages");

        let install = detect(&command, &tree.roots()).expect("standard install");

        assert_eq!(install.kind, InstallKind::Standard);
        assert_eq!(install.version, "3.12");
        assert_eq!(install.prefix, tree.path("base"));
        assert_eq!(
            install.code_folders,
            vec![
                tree.path("base/lib/python3.12"),
                tree.path("base/lib/python3.12/site-packages"),
                user_site.clone(),
            ]
        );
        assert_eq!(
            install.protected,
            vec![
                tree.path("base/lib/python3.12"),
                tree.path("base/lib/python3.12/site-packages"),
                user_site,
                tree.path("base/lib"),
            ]
        );
        assert_eq!(install.cert_bundle, None);
    }

    #[test]
    fn folders_that_dont_exist_yet_are_protected_but_not_granted() {
        let tree = Tree::new();
        let command = tree.standard("base", "3.12");

        let install = detect(&command, &tree.roots()).expect("standard install");

        let user_site = tree.path("home/.local/lib/python3.12/site-packages");
        assert!(!user_site.exists());
        assert!(install.protected.contains(&user_site), "{install:#?}");
        assert!(!install.code_folders.contains(&user_site));
        // The zip that every CPython puts ahead of the standard library is inside `lib/`.
        assert!(
            install
                .protected
                .iter()
                .any(|folder| lies_within(&tree.path("base/lib/python312.zip"), folder))
        );

        let (tree, command) = homebrew_tree();
        let install = detect(&command, &tree.roots()).expect("homebrew");
        let gdbm = tree.path("brew/opt/python-gdbm@3.14/libexec");
        assert!(install.protected.contains(&gdbm), "{install:#?}");
        assert!(!install.code_folders.contains(&gdbm));
    }

    #[test]
    fn a_missing_folder_is_its_canonical_ancestor_with_the_rest_appended() {
        let tree = Tree::new();
        tree.dir("real");
        tree.link("alias", "real");

        assert_eq!(
            canonical_lenient(&tree.path("alias/missing/deeper")),
            tree.path("real/missing/deeper")
        );
    }

    #[test]
    fn a_hard_linked_install_file_is_refused() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("venv", "base", "3.12", false);
        let cached = tree.file("cache/archive/pkg/__init__.py", "");
        fs::create_dir_all(tree.path("venv/lib/python3.12/site-packages/pkg")).expect("pkg");
        let installed = tree.path("venv/lib/python3.12/site-packages/pkg/__init__.py");
        fs::hard_link(&cached, &installed).expect("hard link");

        let error = detect(&command, &tree.roots()).expect_err("a hard link refuses");

        assert!(matches!(&error, InstallError::HardLink(file) if *file == installed));
        assert!(
            error.to_string().ends_with(
                "has another name outside the install, so the agent could change it \
                            through that name. Rebuild the venv without hard links (for uv: \
                            --link-mode=copy)"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_link_out_of_site_packages_protects_and_grants_its_target() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("venv", "base", "3.12", false);
        let archive = tree.dir("cache/archive/pkg");
        tree.file("cache/archive/pkg/__init__.py", "");
        tree.link(
            "venv/lib/python3.12/site-packages/pkg",
            &archive.to_string_lossy(),
        );
        let cellar = tree.file("cellar/other/lib/python3.12/site-packages/other/a.py", "");
        tree.link(
            "venv/lib/python3.12/site-packages/other/a.py",
            &cellar.to_string_lossy(),
        );

        let install = detect(&command, &tree.roots()).expect("venv");

        let packages = tree.path("cellar/other/lib/python3.12/site-packages");
        for folder in [&archive, &packages] {
            assert!(install.protected.contains(folder), "{install:#?}");
            assert!(install.code_folders.contains(folder), "{install:#?}");
        }
    }

    #[test]
    fn a_link_to_a_hard_linked_file_is_refused() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("venv", "base", "3.12", false);
        let cached = tree.file("cache/archive/pkg/__init__.py", "");
        fs::hard_link(&cached, tree.path("cache/second-name.py")).expect("hard link");
        tree.link(
            "venv/lib/python3.12/site-packages/pkg",
            &tree.path("cache/archive/pkg").to_string_lossy(),
        );

        let error = detect(&command, &tree.roots()).expect_err("the walk follows into the target");

        assert!(matches!(&error, InstallError::HardLink(file) if *file == cached));
    }

    #[test]
    fn pth_path_lines_name_folders_and_import_lines_dont() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("project/.venv", "base", "3.12", false);
        let packages = "project/.venv/lib/python3.12/site-packages";
        tree.file(
            &format!("{packages}/easy-install.pth"),
            "# a comment\n\nimport os; os.getcwd()\n../../../../src  \r\n/elsewhere/lib\n",
        );

        let install = detect(&command, &tree.roots()).expect("venv");

        assert_eq!(
            install.editable_sources,
            vec![PathBuf::from("/elsewhere/lib"), tree.path("project/src")]
        );
    }

    #[test]
    fn an_unmodeled_sitecustomize_is_refused() {
        let tree = Tree::new();
        let command = tree.standard("base", "3.12");
        tree.file("base/lib/python3.12/sitecustomize.py", "import sys\n");

        let error = detect(&command, &tree.roots()).expect_err("unmodeled sitecustomize");
        assert!(matches!(error, InstallError::Unrecognized(_)), "{error}");

        let venv = tree.venv("venv", "base", "3.12", false);
        let error = detect(&venv, &tree.roots()).expect_err("a venv over it");
        assert_eq!(
            error.to_string(),
            format!(
                "{} is a venv, but the venv's base install {} is not one Box recognizes",
                venv.display(),
                tree.path("base/bin/python3.12").display()
            )
        );
    }

    #[test]
    fn only_a_framework_build_uses_the_library_user_site_on_macos() {
        let tree = Tree::new();
        let command = tree.standard("fw/Python.framework/Versions/3.12", "3.12");
        let user_site = tree.dir("home/Library/Python/3.12/lib/python/site-packages");
        tree.dir("home/.local/lib/python3.12/site-packages");

        let install = detect(&command, &tree.roots()).expect("framework install");
        assert_eq!(install.code_folders.last(), Some(&user_site));

        let mut linux = tree.roots();
        linux.user_site = UserSiteLayout::Linux;
        let install = detect(&command, &linux).expect("framework install on Linux roots");
        assert_eq!(
            install.code_folders.last(),
            Some(&tree.path("home/.local/lib/python3.12/site-packages"))
        );
    }

    #[test]
    fn a_venv_over_homebrew_gets_the_split_module_folders_but_not_brews_site_packages() {
        let (tree, _) = homebrew_tree();
        let command = tree.venv("venv", "brew/Cellar/python@3.14/3.14.7", "3.14", false);

        let install = detect(&command, &tree.roots()).expect("venv over Homebrew");

        assert_eq!(
            install.code_folders,
            vec![
                tree.path("venv/lib/python3.14/site-packages"),
                tree.path("brew/Cellar/python@3.14/3.14.7/lib/python3.14"),
                tree.path("brew/opt/python-tk@3.14/libexec"),
            ]
        );
    }

    #[test]
    fn a_venv_over_a_standard_base_loads_its_packages_and_the_base_library_only() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("project/.venv", "base", "3.12", false);

        let install = detect(&command, &tree.roots()).expect("venv");

        let InstallKind::Venv { base } = &install.kind else {
            panic!("expected a venv, got {:?}", install.kind);
        };
        assert_eq!(base.kind, InstallKind::Standard);
        assert_eq!(base.prefix, tree.path("base"));
        assert_eq!(install.version, "3.12");
        assert_eq!(install.prefix, tree.path("project/.venv"));
        assert_eq!(
            install.code_folders,
            vec![
                tree.path("project/.venv/lib/python3.12/site-packages"),
                tree.path("base/lib/python3.12"),
            ]
        );
        assert!(install.protected.contains(&tree.path("project/.venv")));
        assert!(
            !install
                .code_folders
                .contains(&tree.path("base/lib/python3.12/site-packages")),
            "the base's packages stay out without include-system-site-packages"
        );
    }

    #[test]
    fn a_venv_with_system_site_packages_also_loads_the_base_packages() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("project/.venv", "base", "3.12", true);

        let install = detect(&command, &tree.roots()).expect("venv");

        assert_eq!(
            install.code_folders,
            vec![
                tree.path("project/.venv/lib/python3.12/site-packages"),
                tree.path("base/lib/python3.12"),
                tree.path("base/lib/python3.12/site-packages"),
            ]
        );
    }

    #[test]
    fn a_venv_whose_version_disagrees_with_its_base_is_refused() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("project/.venv", "base", "3.12", false);
        fs::write(
            tree.path("project/.venv/pyvenv.cfg"),
            "home = /nowhere\nversion_info = 3.11.2\n",
        )
        .expect("rewrite pyvenv.cfg");

        let error = detect(&command, &tree.roots()).expect_err("mismatched venv");

        assert!(matches!(error, InstallError::Unrecognized(_)), "{error}");
    }

    fn homebrew_tree() -> (Tree, PathBuf) {
        let tree = Tree::new();
        let cellar = "brew/Cellar/python@3.14/3.14.7";
        tree.file(&format!("{cellar}/bin/python3.14"), "binary");
        tree.link(&format!("{cellar}/bin/python3"), "python3.14");
        tree.file(&format!("{cellar}/lib/python3.14/os.py"), "");
        tree.file(&format!("{cellar}/lib/python3.14/sitecustomize.py"), "");
        tree.link(
            "brew/bin/python3",
            "../Cellar/python@3.14/3.14.7/bin/python3",
        );
        tree.dir("brew/lib/python3.14/site-packages");
        tree.dir("brew/opt/python-tk@3.14/libexec");
        tree.dir("Library/Python/3.14/site-packages");
        tree.file("brew/etc/ca-certificates/cert.pem", "certs");
        tree.link("brew/etc/openssl@3/cert.pem", "../ca-certificates/cert.pem");
        let command = tree.path("brew/bin/python3");
        (tree, command)
    }

    #[test]
    fn homebrew_adds_the_folders_its_sitecustomize_adds_and_its_certificates() {
        let (tree, command) = homebrew_tree();

        let install = detect(&command, &tree.roots()).expect("homebrew");

        assert_eq!(install.kind, InstallKind::Homebrew);
        assert_eq!(install.version, "3.14");
        assert_eq!(
            install.code_folders,
            vec![
                tree.path("brew/Cellar/python@3.14/3.14.7/lib/python3.14"),
                tree.path("brew/lib/python3.14/site-packages"),
                tree.path("Library/Python/3.14/site-packages"),
                tree.path("brew/opt/python-tk@3.14/libexec"),
            ],
            "absent folders (gdbm) stay out"
        );
        assert_eq!(
            install.cert_bundle,
            Some(tree.path("brew/etc/openssl@3/cert.pem"))
        );
        assert_eq!(
            install.cert_link_chain,
            vec![tree.path("brew/etc/ca-certificates/cert.pem")]
        );
    }

    #[test]
    fn the_link_chain_names_every_hop_to_the_real_file() {
        let (tree, command) = homebrew_tree();

        let install = detect(&command, &tree.roots()).expect("homebrew");

        assert_eq!(
            install.link_chain,
            vec![
                tree.path("brew/bin/python3"),
                tree.path("brew/Cellar/python@3.14/3.14.7/bin/python3"),
                tree.path("brew/Cellar/python@3.14/3.14.7/bin/python3.14"),
            ]
        );
    }

    #[test]
    fn a_homebrew_python_without_sitecustomize_is_a_standard_install() {
        let (tree, command) = homebrew_tree();
        fs::remove_file(
            tree.path("brew/Cellar/python@3.14/3.14.7/lib/python3.14/sitecustomize.py"),
        )
        .expect("remove sitecustomize");

        let install = detect(&command, &tree.roots()).expect("standard");

        assert_eq!(install.kind, InstallKind::Standard);
        assert_eq!(install.cert_bundle, None);
    }

    #[test]
    fn debian_adds_dist_packages_and_its_certificate_bundle() {
        let tree = Tree::new();
        tree.standard("system/usr", "3.12");
        // A second interpreter beside it: the real file's name picks the library.
        tree.file("system/usr/lib/python3.11/os.py", "");
        tree.dir("system/usr/lib/python3/dist-packages");
        tree.dir("system/usr/local/lib/python3.12/dist-packages");
        tree.file("system/etc/ssl/certs/ca-certificates.crt", "certs");
        let mut roots = tree.roots();
        roots.user_site = UserSiteLayout::Linux;
        let user_site = tree.dir("home/.local/lib/python3.12/site-packages");

        let install = detect(&tree.path("system/usr/bin/python3"), &roots).expect("debian");

        assert_eq!(install.kind, InstallKind::Debian);
        assert_eq!(install.version, "3.12");
        assert_eq!(
            install.code_folders,
            vec![
                tree.path("system/usr/lib/python3.12"),
                tree.path("system/usr/lib/python3.12/site-packages"),
                user_site,
                tree.path("system/usr/lib/python3/dist-packages"),
                tree.path("system/usr/local/lib/python3.12/dist-packages"),
            ]
        );
        assert_eq!(
            install.cert_bundle,
            Some(tree.path("system/etc/ssl/certs/ca-certificates.crt"))
        );
    }

    #[test]
    fn an_unknown_layout_is_refused_with_use_a_venv() {
        let tree = Tree::new();
        let shim = tree.file("pyenv/shims/python3", "#!/bin/sh\nexec python3 \"$@\"\n");

        let error = detect(&shim, &tree.roots()).expect_err("unknown layout");

        assert_eq!(
            error.to_string(),
            format!(
                "{} is not a Python install Box recognizes. Use a venv",
                shim.display()
            )
        );
    }

    #[test]
    fn a_relative_or_dangling_command_is_refused() {
        let tree = Tree::new();
        let dangling = tree.link("bin/python3", "missing");

        assert!(detect(Path::new("python3"), &tree.roots()).is_err());
        assert!(detect(&dangling, &tree.roots()).is_err());
    }

    #[test]
    fn an_editable_install_names_its_source_folder_percent_decoded() {
        let tree = Tree::new();
        tree.standard("base", "3.12");
        let command = tree.venv("project/.venv", "base", "3.12", false);
        let source = tree.dir("project/my lib");
        let packages = "project/.venv/lib/python3.12/site-packages";
        tree.file(
            &format!("{packages}/my_lib-0.1.dist-info/direct_url.json"),
            &format!(
                r#"{{"url": "file://{}", "dir_info": {{"editable": true}}}}"#,
                source.display().to_string().replace(' ', "%20")
            ),
        );
        tree.file(
            &format!("{packages}/wheel_pkg-1.0.dist-info/direct_url.json"),
            r#"{"url": "file:///tmp/wheel_pkg-1.0.whl", "archive_info": {}}"#,
        );
        tree.file(
            &format!("{packages}/plain-2.0.dist-info/direct_url.json"),
            r#"{"url": "file:///tmp/plain", "dir_info": {"editable": false}}"#,
        );

        let install = detect(&command, &tree.roots()).expect("venv");

        assert_eq!(install.editable_sources, vec![source]);
    }

    #[test]
    fn percent_decoding_rejects_a_truncated_escape() {
        assert_eq!(percent_decode("/a%20b"), Some(b"/a b".to_vec()));
        assert_eq!(percent_decode("/a%2"), None);
        assert_eq!(percent_decode("/a%zz"), None);
    }

    #[test]
    fn outermost_drops_every_path_inside_another() {
        let paths = [
            PathBuf::from("/p/lib/python3.12/site-packages"),
            PathBuf::from("/p/lib/python3.12"),
            PathBuf::from("/q/site-packages"),
            PathBuf::from("/p/lib/python3.12"),
            PathBuf::from("/p/lib/python3.120"),
        ];

        assert_eq!(
            outermost(&paths),
            vec![
                PathBuf::from("/p/lib/python3.12"),
                PathBuf::from("/q/site-packages"),
                PathBuf::from("/p/lib/python3.120"),
            ]
        );
    }

    /// Prints what this machine's Python installs look like, and how long [`detect`] took on each:
    /// `/opt/homebrew/bin/python3`, then each `:`-separated command in `PYTHON_INSTALL_PROBE`.
    /// Run by hand:
    /// `PYTHON_INSTALL_PROBE=/path/to/.venv/bin/python3 cargo test -p strands-box --lib
    /// --all-features python_install::tests::this_machine -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this machine's real Python installs"]
    fn this_machine() {
        let roots = InstallRoots::host();
        let extra = std::env::var_os("PYTHON_INSTALL_PROBE").unwrap_or_default();
        let commands = std::iter::once(PathBuf::from("/opt/homebrew/bin/python3"))
            .chain(std::env::split_paths(&extra).filter(|path| path.is_absolute()));
        for command in commands {
            let command = command.as_path();
            if !command.exists() {
                println!("{}: absent, skipped", command.display());
                continue;
            }
            let started = Instant::now();
            match detect(command, &roots) {
                Ok(install) => println!(
                    "{}: detected in {:?}\n{install:#?}\n",
                    command.display(),
                    started.elapsed()
                ),
                Err(error) => panic!("{error}"),
            }
        }
    }
}
