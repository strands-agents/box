use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::Error;

/// How long a detection probe may run before it is killed.
#[cfg(not(test))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Held while a probe is spawned.
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The most a host program that `box` asks may print.
const COMMAND_OUTPUT_CAP: usize = 64 * 1024;

/// The folder of Apple's `xcode-select` stubs on macOS.
pub const APPLE_STUBS: &str = "/usr/bin";

/// The operator's host as `strands-box run` will see it.
#[derive(Debug, Clone)]
pub struct Host {
    pub search_path: OsString,
    pub home: PathBuf,
    /// The profiles, storage, and runs: `BOX_HOME`, else `~/.strands/box`.
    pub box_home: PathBuf,
    /// The OS that a `when` tests.
    pub os: &'static str,
    /// The CPU architecture, as `std::env::consts::ARCH` names it.
    pub arch: &'static str,
    /// The variables a run reads in place of the environment of `box`.
    pub variables: Option<Vec<(String, String)>>,
    /// Command outputs that stand in for running the command.
    pub answers: Vec<(Vec<String>, String)>,
    /// Whether `box` runs with effective user ID 0.
    pub root: bool,
    /// The folder of Apple's `xcode-select` stubs, such as `/usr/bin/git`.
    pub apple_stubs: PathBuf,
}

impl Host {
    pub fn current() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|home| canonical(&home))
            .unwrap_or_default();
        let box_home = box_home(std::env::var_os(BOX_HOME_VARIABLE), &home)
            .unwrap_or_else(|_| default_box_home(&home));
        Self {
            search_path: std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
            home,
            box_home,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            variables: None,
            answers: Vec::new(),
            root: nix::unistd::geteuid().is_root(),
            apple_stubs: PathBuf::from(APPLE_STUBS),
        }
    }

    /// This host with `home` as the operator home.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_home(&mut self, home: PathBuf) {
        self.home = canonical(&home).unwrap_or(home);
        self.box_home = default_box_home(&self.home);
    }

    /// Each box home that a box may not write: this host's, and `~/.strands/box`, where the installed
    /// `box` lives.
    pub fn box_homes(&self) -> Vec<PathBuf> {
        box_homes(&self.home, &self.box_home)
    }

    /// The first executable regular file named `name` in an absolute search-path directory.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        find_on(&self.search_path, name)
    }

    /// The variable `name`: from the stand-in variables when this host has them, else from the
    /// environment of `box`.
    pub fn variable(&self, name: &str) -> Option<String> {
        match &self.variables {
            Some(variables) => variables
                .iter()
                .find(|(known, _)| known == name)
                .map(|(_, value)| value.clone()),
            None => std::env::var(name).ok(),
        }
    }

    /// The variable `name` as set, including a value that is not valid UTF-8.
    pub fn variable_os(&self, name: &str) -> Option<OsString> {
        match &self.variables {
            Some(_) => self.variable(name).map(OsString::from),
            None => std::env::var_os(name),
        }
    }

    /// `path` as a policy decision reports it: `~/...` under the operator home.
    pub(crate) fn tilde(&self, path: &Path) -> String {
        tilde(&self.home, path)
    }

    /// The output of `argv`, run in `/` with the operator's environment, with one trailing newline
    /// trimmed.
    pub fn command(&self, argv: &[String]) -> Result<String, String> {
        if let Some((_, answer)) = self.answers.iter().rev().find(|(asked, _)| asked == argv) {
            return match answer.is_empty() {
                true => Err("printed nothing".to_string()),
                false => Ok(answer.clone()),
            };
        }
        let (program, args) = argv.split_first().ok_or("names no program")?;
        if !is_executable_file(Path::new(program)) {
            return Err(format!("runs {program}, which is not an executable file"));
        }
        let mut child = {
            let _serialized = SPAWN
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Command::new(program)
                .args(args)
                .current_dir("/")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("cannot start: {error}"))?
        };
        let mut stdout = child.stdout.take().ok_or("has no output")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = (&mut stdout)
                .take(COMMAND_OUTPUT_CAP as u64 + 1)
                .read_to_end(&mut output);
            let _ = sender.send(output);
        });
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let output = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break None,
            }
        };
        let Some(status) = status else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "did not finish within {} seconds",
                PROBE_TIMEOUT.as_secs()
            ));
        };
        let output = output.ok_or("kept its output open")?;
        if !status.success() {
            return Err(format!("exited with {status}"));
        }
        if output.len() > COMMAND_OUTPUT_CAP {
            return Err(format!("printed more than {COMMAND_OUTPUT_CAP} bytes"));
        }
        let text = String::from_utf8(output).map_err(|_| "printed text that is not UTF-8")?;
        let text = text.strip_suffix('\n').unwrap_or(&text);
        if text.is_empty() {
            return Err("printed nothing".to_string());
        }
        Ok(text.to_string())
    }
}

/// The first executable regular file named `name` in an absolute directory of `search_path`. Box
/// Core skips every other entry, `~` included.
pub(crate) fn find_on(search_path: &OsStr, name: &str) -> Option<PathBuf> {
    let folders = std::env::split_paths(search_path).filter(|directory| directory.is_absolute());
    crate::program::candidates(folders, name).find(|candidate| is_executable_file(candidate))
}

/// `path` with a leading `~` component read as `home`.
pub(crate) fn expand_home(home: &Path, path: &Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(rest) if rest.as_os_str().is_empty() => home.to_path_buf(),
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// `path` as a policy decision reports it: `~/...` under `home`.
pub fn tilde(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    }
}

/// The variable that moves the box home.
pub(crate) const BOX_HOME_VARIABLE: &str = "BOX_HOME";

/// `~/.strands/box`, the box home when `BOX_HOME` is not set.
pub fn default_box_home(home: &Path) -> PathBuf {
    home.join(".strands/box")
}

/// The box home: `variable` when it is set and not empty, with its links followed, else
/// `~/.strands/box`. A relative `variable` is an error.
pub(crate) fn box_home(variable: Option<OsString>, home: &Path) -> Result<PathBuf, Error> {
    match variable
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        None => Ok(default_box_home(home)),
        Some(path) if path.is_absolute() => Ok(resolved(&path)),
        Some(path) => Err(Error::BoxHomeRelative { path }),
    }
}

/// The folder below which the box home and its ancestors must be real directories.
pub fn box_home_base<'a>(home: &'a Path, box_home: &'a Path) -> &'a Path {
    if box_home == default_box_home(home) {
        home
    } else {
        box_home.parent().unwrap_or(box_home)
    }
}

/// `box_home`, and `~/.strands/box` when it is another folder.
pub fn box_homes(home: &Path, box_home: &Path) -> Vec<PathBuf> {
    let installed = default_box_home(home);
    if box_home == installed {
        vec![installed]
    } else {
        vec![box_home.to_path_buf(), installed]
    }
}

/// Check `BOX_HOME` before a command reads it.
pub fn check_box_home() -> Result<(), Error> {
    box_home(std::env::var_os(BOX_HOME_VARIABLE), Path::new("")).map(|_| ())
}

pub fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// `path` with each link in its deepest existing ancestor followed, and the absent rest kept.
pub fn resolved(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut existing = path;
    loop {
        if let Some(found) = canonical(existing) {
            return tail.iter().rev().fold(found, |base, part| base.join(part));
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                existing = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

pub(crate) fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Whether `path` is `directory` or lies below it.
pub fn within(path: &Path, directory: &Path) -> bool {
    path.starts_with(directory)
}

pub(crate) fn utf8(path: &Path) -> Result<String, Error> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| Error::NotUtf8 {
            path: path.to_path_buf(),
        })
}

/// The entries in order, without one that lies at or below an entry already kept.
pub(crate) fn unique(items: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut kept: Vec<PathBuf> = Vec::new();
    for item in items {
        if kept.iter().any(|entry| item.starts_with(entry)) {
            continue;
        }
        kept.retain(|entry| !entry.starts_with(&item));
        kept.push(item);
    }
    kept
}
#[cfg(test)]
mod box_home_tests {
    use super::*;

    #[test]
    fn an_unset_or_empty_box_home_is_the_default() {
        let home = Path::new("/h");
        for variable in [None, Some(OsString::new())] {
            assert_eq!(
                box_home(variable, home).unwrap(),
                Path::new("/h/.strands/box")
            );
        }
    }

    #[test]
    fn a_full_box_home_is_used_with_its_links_followed() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().canonicalize().unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("link")).unwrap();
        let variable = root.path().join("link/home").into_os_string();
        assert_eq!(
            box_home(Some(variable), Path::new("/h")).unwrap(),
            real.join("home")
        );
    }

    #[test]
    fn a_relative_box_home_is_an_error() {
        let error = box_home(Some("try/home".into()), Path::new("/h")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "BOX_HOME must be a full path, not try/home"
        );
    }

    #[test]
    fn a_moved_box_home_keeps_the_installed_one_protected() {
        let home = Path::new("/h");
        assert_eq!(
            box_homes(home, Path::new("/h/.strands/box")),
            [PathBuf::from("/h/.strands/box")]
        );
        assert_eq!(
            box_homes(home, Path::new("/t/home")),
            [PathBuf::from("/t/home"), PathBuf::from("/h/.strands/box")]
        );
    }
}
