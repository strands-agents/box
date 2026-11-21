//! The host files and directories that `[[storage.files]]` copies into storage once.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};

use nix::libc;

use crate::error::Error;
use crate::files::{
    create_real_directory, io_error, make_directory_at, open_at, open_directory, remove_if_present,
    rename_at, unlink_at,
};
use crate::host::{canonical, resolved, tilde, within};
use crate::storage_edit::{Edit, Failure, Kept, shown};
use crate::storage_sync::{Entry, entry};

/// One `[[storage.files]]` row, resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageFile {
    pub source: PathBuf,
    pub target: PathBuf,
    /// The target relative to the storage root: `agent/<dir>/...` or `tool/<tool>/<dir>/...`.
    pub relative: String,
    pub optional: bool,
    /// The row as an error names it, such as `storage.files[0]`.
    pub at: String,
    /// The `kind`, `keep`, and `set` of the row, when it has them.
    pub edit: Option<Edit>,
    /// Whether each run brings the copy up to date with the host.
    pub sync: bool,
    /// The names that a folder copy leaves out, at any depth.
    pub exclude: Vec<String>,
}

/// The places a source and each link it follows may not reach.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Refusals {
    pub home: PathBuf,
    /// Each directory a box can write or a later run trusts, with what it is.
    pub roots: Vec<(PathBuf, String)>,
    /// The folder of box's own packs, which a copy's source may lie in, as written and real,
    /// though a root holds it.
    pub shipped: Option<PathBuf>,
    /// Each path that a secret source protects, which no copy or link reads.
    pub protected: Vec<Protected>,
}

/// A path that a secret source lists in `reads` or `deny`, which Box Core keeps from every
/// workload.
#[derive(Debug, Clone, PartialEq)]
pub struct Protected {
    pub path: PathBuf,
    /// The list that holds the path, as a message names it: `[protect] paths` of a plugin, and
    /// `reads` or `deny` of a source of the profile.
    pub key: &'static str,
    /// The source, such as `the plugin 1password`.
    pub source: String,
}

impl Refusals {
    /// Check a host configuration root before a source path is joined to it.
    pub fn check_root(&self, path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("{} is not an absolute directory", path.display()));
        }
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(format!("{} holds `..`", path.display()));
        }
        if let Some(reason) = self.refusal(path, false) {
            return Err(format!("{reason}; box copies no file from there"));
        }
        if path.exists() && !path.is_dir() {
            return Err(format!("{} is not a directory", path.display()));
        }
        Ok(())
    }

    /// Refuse a copy from `path` when it is, holds, or lies in a refused root, as written or real,
    /// and not in box's own packs, or in a protected path.
    pub fn check(&self, path: &Path) -> Result<(), String> {
        let shipped = self.shipped.as_ref().is_some_and(|shipped| {
            (within(path, shipped) || within(path, &resolved(shipped)))
                && within(&resolved(path), &resolved(shipped))
        });
        let refused = match shipped {
            true => self.protects(path),
            false => self.reach(path).or_else(|| self.protects(path)),
        };
        match refused {
            Some(reason) => Err(format!("{reason}; box copies no file from there")),
            None => Ok(()),
        }
    }

    /// How `path` is, holds, or lies in a path that a secret source protects, as written or real,
    /// if it does.
    pub fn protects(&self, path: &Path) -> Option<String> {
        self.protected.iter().find_map(|protected| {
            let how = overlap(path, &protected.path)?;
            let entry = tilde(&self.home, &protected.path);
            let named = format!(
                "{} lists in `{}`, which the box keeps from every workload",
                protected.source, protected.key
            );
            let shown = self.shown(path);
            Some(match how {
                Overlap::Same => format!("{shown} is a path that {named}"),
                Overlap::Inside => format!("{shown} lies in {entry}, a path that {named}"),
                Overlap::Holds => format!("{shown} holds {entry}, a path that {named}"),
            })
        })
    }

    /// `path` as a reason names it, with its real path when a link leads there.
    fn shown(&self, path: &Path) -> String {
        let real = resolved(path);
        if real == path {
            tilde(&self.home, path)
        } else {
            format!(
                "{} (a link to {})",
                tilde(&self.home, path),
                tilde(&self.home, &real)
            )
        }
    }

    /// How `path` is, holds, or lies in a refused root, as written or real, if it does.
    pub fn reach(&self, path: &Path) -> Option<String> {
        self.refusal(path, true)
    }

    fn refusal(&self, path: &Path, include_contents: bool) -> Option<String> {
        for (root, what) in &self.roots {
            let Some(how) = overlap(path, root) else {
                continue;
            };
            if !include_contents && matches!(how, Overlap::Holds) {
                continue;
            }
            let shown = self.shown(path);
            let reason = match how {
                Overlap::Same => format!("{shown} is {what}"),
                Overlap::Inside => format!("{shown} lies in {what}, {}", tilde(&self.home, root)),
                Overlap::Holds => format!("{shown} holds {what}, {}", tilde(&self.home, root)),
            };
            return Some(reason);
        }
        None
    }
}

enum Overlap {
    Same,
    Inside,
    Holds,
}

/// How `path` meets `root`, as written or real, if it does.
fn overlap(path: &Path, root: &Path) -> Option<Overlap> {
    let real = resolved(path);
    let real_root = resolved(root);
    let pairs = [
        (path, root),
        (path, real_root.as_path()),
        (real.as_path(), root),
        (real.as_path(), real_root.as_path()),
    ];
    if pairs.iter().any(|(path, root)| path == root) {
        return Some(Overlap::Same);
    }
    if pairs.iter().any(|(path, root)| within(path, root)) {
        return Some(Overlap::Inside);
    }
    pairs
        .iter()
        .any(|(path, root)| within(root, path))
        .then_some(Overlap::Holds)
}

/// What one copy does now.
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// The target exists, so the copy belongs to the box.
    InStorage,
    /// The target exists, and a row with `fill` adds to it what it lacks of `text`, the `keep`
    /// values of the host file.
    Fill { text: String, kept: Kept },
    /// The host file holds none of the `keep` values of a row with `fill`.
    NothingKept,
    /// An optional source that the host lacks.
    Absent,
    /// The copy that this run makes.
    WillCopy(Plan),
}

/// Each directory and file of one copy, and each link it follows or does not follow.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    /// Each item, relative to the target, in the order it is made. An empty path is the target.
    items: Vec<(PathBuf, Item)>,
    /// Each link that leaves its source and passes the checks, with its real target.
    pub followed: Vec<(PathBuf, PathBuf)>,
    /// Each link or entry that is not copied, with the reason.
    pub skipped: Vec<(PathBuf, String)>,
    /// What `keep` takes from the source, for a row with `keep`.
    pub kept: Option<Kept>,
}

#[derive(Debug, Clone, PartialEq)]
enum Item {
    Directory,
    /// A file, with its stamp when `box` planned the copy.
    File {
        from: PathBuf,
        mode: u32,
        stamp: Stamp,
    },
}

/// What tells a host file apart from a changed one: its device, inode, size, and modification and
/// change times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// What `file` does now: nothing when its target exists, else the copy it makes.
pub(crate) fn state(file: &StorageFile, refusals: &Refusals) -> Result<State, String> {
    if std::fs::symlink_metadata(&file.target).is_ok() {
        return match file.edit.as_ref().filter(|edit| edit.fill) {
            Some(edit) => fill_state(file, edit, refusals),
            None => Ok(State::InStorage),
        };
    }
    let Some(root) = canonical(&file.source) else {
        if file.optional {
            return Ok(State::Absent);
        }
        return Err(format!(
            "{} does not exist; mark the row `optional = true` if a host can lack it",
            file.source.display()
        ));
    };
    refusals.check(&root)?;
    if let Some(edit) = &file.edit {
        return edited_plan(file, edit, &root);
    }
    refuse_exclude_on_a_file(file, &root)?;
    let mut plan = Plan::default();
    add(
        &root,
        PathBuf::new(),
        &root,
        &mut Vec::new(),
        &Walk {
            refusals,
            exclude: &file.exclude,
        },
        &mut plan,
    );
    if plan.items.is_empty() {
        let why = plan
            .skipped
            .first()
            .map_or_else(String::new, |(_, why)| why.clone());
        return Err(format!("{} cannot be copied: {why}", root.display()));
    }
    Ok(State::WillCopy(plan))
}

/// The host side of `file` as a copy would take it now, or `None` for an optional source the host
/// lacks.
pub(crate) fn host_tree(file: &StorageFile, refusals: &Refusals) -> Result<Option<Plan>, String> {
    let Some(root) = canonical(&file.source) else {
        if file.optional {
            return Ok(None);
        }
        return Err(format!(
            "{} does not exist; mark the row `optional = true` if a host can lack it",
            file.source.display()
        ));
    };
    refusals.check(&root)?;
    refuse_exclude_on_a_file(file, &root)?;
    let mut plan = Plan::default();
    add(
        &root,
        PathBuf::new(),
        &root,
        &mut Vec::new(),
        &Walk {
            refusals,
            exclude: &file.exclude,
        },
        &mut plan,
    );
    Ok(Some(plan))
}

/// Refuse `exclude` on a row whose source `root` is one file, which has no entries to leave out.
fn refuse_exclude_on_a_file(file: &StorageFile, root: &Path) -> Result<(), String> {
    if file.exclude.is_empty() || root.is_dir() {
        return Ok(());
    }
    Err(format!(
        "`{} exclude` names entries of a folder, and {} is not a folder",
        file.at,
        root.display()
    ))
}

impl Plan {
    /// Whether the copy is a folder rather than one file.
    pub(crate) fn is_folder(&self) -> bool {
        matches!(self.items.first(), Some((path, Item::Directory)) if path.as_os_str().is_empty())
    }

    /// Each file of the copy, as it was when `box` planned the copy.
    pub(crate) fn files(&self) -> impl Iterator<Item = HostFile<'_>> {
        self.items.iter().filter_map(|(relative, item)| match item {
            Item::File { from, mode, stamp } => Some(HostFile {
                relative,
                from,
                mode: *mode,
                device: stamp.device,
                inode: stamp.inode,
            }),
            Item::Directory => None,
        })
    }

    /// The first host file that is gone or whose stamp is not the one the plan took.
    fn changed(&self) -> Option<&Path> {
        self.items.iter().find_map(|(_, item)| match item {
            Item::File { from, stamp, .. } => std::fs::symlink_metadata(from)
                .map_or(true, |now| Stamp::of(&now) != *stamp)
                .then_some(from.as_path()),
            Item::Directory => None,
        })
    }
}

/// One file of a planned copy.
pub(crate) struct HostFile<'a> {
    /// The path in the copy. An empty path is the target.
    pub(crate) relative: &'a Path,
    /// The real host path.
    pub(crate) from: &'a Path,
    pub(crate) mode: u32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl HostFile<'_> {
    /// Read the file, refusing one that is no longer the file `box` planned to copy.
    pub(crate) fn read(&self) -> Result<Vec<u8>, Error> {
        let changed = || Error::Copy {
            path: self.from.to_path_buf(),
            reason: "the file changed while box copied it".into(),
        };
        let mut input = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.from)
        {
            Ok(input) => input,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(changed()),
            Err(error) => return Err(io_error("read", self.from, error)),
        };
        let opened = input
            .metadata()
            .map_err(|source| io_error("read", self.from, source))?;
        if opened.dev() != self.device || opened.ino() != self.inode || !opened.is_file() {
            return Err(changed());
        }
        let mut bytes = Vec::new();
        input
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read", self.from, source))?;
        Ok(bytes)
    }
}

/// What a row with `fill` adds to its copy: the host file, read now and checked as for a copy. A
/// host that lacks the file adds nothing.
fn fill_state(file: &StorageFile, edit: &Edit, refusals: &Refusals) -> Result<State, String> {
    let Some(root) = canonical(&file.source) else {
        if file.optional {
            return Ok(State::InStorage);
        }
        return Err(format!(
            "{} does not exist; mark the row `optional = true` if a host can lack it",
            file.source.display()
        ));
    };
    refusals.check(&root)?;
    if !std::fs::metadata(&root)
        .map_err(|error| format!("box cannot read it: {error}"))?
        .is_file()
    {
        return Err(format!(
            "`{}`: it is a folder; `fill` needs a file",
            file.at
        ));
    }
    let host =
        std::fs::read_to_string(&root).map_err(|error| format!("box cannot read it: {error}"))?;
    let (text, kept) = edit.first_copy(&host).map_err(|failure| {
        let (row, reason) = failure_text(file, edit, "the source", failure);
        format!("`{row}`: {reason}")
    })?;
    Ok(State::Fill { text, kept })
}

/// The plan of a row with `kind`: one file, parsed now so that a source that is not its kind stops
/// the run before anything is copied.
fn edited_plan(file: &StorageFile, edit: &Edit, root: &Path) -> Result<State, String> {
    let metadata =
        std::fs::metadata(root).map_err(|error| format!("box cannot read it: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "`{}`: it is a folder; `keep` and `set` need a file",
            file.at
        ));
    }
    let text =
        std::fs::read_to_string(root).map_err(|error| format!("box cannot read it: {error}"))?;
    let kept = edit.kept(&text).map_err(|failure| {
        let (row, reason) = failure_text(file, edit, "the source", failure);
        format!("`{row}`: {reason}")
    })?;
    if edit.fill && kept.kept.is_empty() {
        return Ok(State::NothingKept);
    }
    Ok(State::WillCopy(Plan {
        items: vec![(
            PathBuf::new(),
            Item::File {
                from: root.to_path_buf(),
                mode: metadata.permissions().mode() & 0o755,
                stamp: Stamp::of(&metadata),
            },
        )],
        followed: Vec::new(),
        skipped: Vec::new(),
        kept: edit.keep.as_ref().map(|_| kept),
    }))
}

/// The row and the reason of `failure` on the file that `subject` names.
fn failure_text(
    file: &StorageFile,
    edit: &Edit,
    subject: &str,
    failure: Failure,
) -> (String, String) {
    match failure {
        Failure::Parse(reason) => {
            let keys: Vec<String> = edit.set.iter().map(|setting| shown(&setting.key)).collect();
            let reason = if keys.is_empty() {
                format!("{subject} is {reason}")
            } else {
                format!(
                    "{subject} is {reason}, so box cannot set {}",
                    keys.join(", ")
                )
            };
            (file.at.clone(), reason)
        }
        Failure::Set(index, blocked) => {
            let place = if blocked.at.is_empty() {
                subject.to_string()
            } else {
                format!("{} in {subject}", shown(&blocked.at))
            };
            (
                format!("{} set[{index}]", file.at),
                format!(
                    "{place} is {}, so box cannot set {}",
                    blocked.what,
                    shown(&edit.set[index].key)
                ),
            )
        }
    }
}

/// What a walk of a source checks each entry against.
struct Walk<'a> {
    refusals: &'a Refusals,
    /// The names the row's `exclude` leaves out.
    exclude: &'a [String],
}

/// Add the real path `real` at `relative` to `plan`. `root` is the real directory that its links
/// stay in, and `stack` holds each real directory being added. An entry that cannot be read, or
/// that `exclude` names, is left out and reported.
fn add(
    real: &Path,
    relative: PathBuf,
    root: &Path,
    stack: &mut Vec<PathBuf>,
    walk: &Walk<'_>,
    plan: &mut Plan,
) {
    let refusals = walk.refusals;
    let metadata = match std::fs::metadata(real) {
        Ok(metadata) => metadata,
        Err(error) => {
            plan.skipped
                .push((relative, format!("box cannot read it: {error}")));
            return;
        }
    };
    if metadata.is_file() {
        plan.items.push((
            relative,
            Item::File {
                from: real.to_path_buf(),
                mode: metadata.permissions().mode() & 0o755,
                stamp: Stamp::of(&metadata),
            },
        ));
        return;
    }
    if !metadata.is_dir() {
        plan.skipped
            .push((relative, "it is not a file or a directory".into()));
        return;
    }
    let mut entries = Vec::new();
    match std::fs::read_dir(real) {
        Ok(listing) => {
            for entry in listing {
                match entry {
                    Ok(entry) => entries.push(entry),
                    Err(error) => {
                        plan.skipped
                            .push((relative.clone(), format!("box cannot list it: {error}")));
                        return;
                    }
                }
            }
        }
        Err(error) => {
            plan.skipped
                .push((relative, format!("box cannot list it: {error}")));
            return;
        }
    }
    plan.items.push((relative.clone(), Item::Directory));
    stack.push(real.to_path_buf());
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let child = relative.join(entry.file_name());
        // Without regard to case: macOS file systems usually ignore case, so the agent would
        // read `MCP.json` as `mcp.json`. Leaving out one more entry is the safe side.
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if walk
            .exclude
            .iter()
            .any(|excluded| excluded.to_lowercase() == name)
        {
            plan.skipped
                .push((child, "the row's `exclude` names it".into()));
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                plan.skipped
                    .push((child, format!("box cannot read it: {error}")));
                continue;
            }
        };
        if !kind.is_symlink() {
            if kind.is_dir() || kind.is_file() {
                add(&path, child, root, stack, walk, plan);
            } else {
                plan.skipped
                    .push((child, "it is not a file or a directory".into()));
            }
            continue;
        }
        let Some(target) = canonical(&path) else {
            plan.skipped
                .push((child, "the link points at nothing".into()));
            continue;
        };
        if stack.iter().any(|directory| within(directory, &target)) {
            plan.skipped
                .push((child, "the link points at a folder that holds it".into()));
            continue;
        }
        if within(&target, root) {
            add(&target, child, root, stack, walk, plan);
            continue;
        }
        if let Err(reason) = refusals.check(&target) {
            plan.skipped.push((child, reason));
            continue;
        }
        plan.followed.push((child.clone(), target.clone()));
        add(&target, child, &target, stack, walk, plan);
    }
    stack.pop();
}

/// Copy `file` as `plan` states. `box` builds the copy in `staging`, a fresh directory that no box
/// can reach, then renames it into place beside nothing: a target that exists by then is kept.
/// A host file that changed or went between the plan and the end of the whole copy fails it with
/// [`Error::Changed`], and nothing reaches storage.
/// For a `sync` row, return what each file of the copy holds, or nothing if the copy was kept.
pub(crate) fn copy(
    file: &StorageFile,
    plan: &Plan,
    staging: &Path,
    home: &Path,
) -> Result<Vec<(PathBuf, Entry)>, Error> {
    let parent = file.target.parent().unwrap_or(&file.target);
    create_real_directory(parent, home)?;
    remove_if_present(staging)?;
    let made = make(staging, plan, file).and_then(|made| match plan.changed() {
        Some(path) => Err(Error::Changed {
            path: path.to_path_buf(),
        }),
        None => Ok(made),
    });
    if made.is_ok() && std::fs::symlink_metadata(&file.target).is_err() {
        create_real_directory(parent, home)?;
        if let Err(source) = std::fs::rename(staging, &file.target) {
            remove_if_present(staging)?;
            return Err(io_error("copy", &file.target, source));
        }
        return made;
    }
    remove_if_present(staging)?;
    made.map(|_| Vec::new())
}

/// Write a new copy of a row whose host file is absent, holding only its `set` values. `box`
/// writes it in `staging` and renames it into place beside nothing, as [`copy`] does. A row that
/// sets nothing writes nothing.
pub(crate) fn create(file: &StorageFile, staging: &Path, home: &Path) -> Result<(), Error> {
    let Some(edit) = &file.edit else {
        return Ok(());
    };
    let text = edit.fresh().map_err(|failure| {
        let (at, reason) = failure_text(file, edit, "the new file", failure);
        Error::Set { at, reason }
    })?;
    let Some(text) = text else {
        return Ok(());
    };
    let parent = file.target.parent().unwrap_or(&file.target);
    create_real_directory(parent, home)?;
    remove_if_present(staging)?;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging)
        .and_then(|mut output| output.write_all(text.as_bytes()))
        .map_err(|source| io_error("write", staging, source));
    if written.is_ok() && std::fs::symlink_metadata(&file.target).is_err() {
        create_real_directory(parent, home)?;
        if let Err(source) = std::fs::rename(staging, &file.target) {
            remove_if_present(staging)?;
            return Err(io_error("copy", &file.target, source));
        }
        return Ok(());
    }
    remove_if_present(staging)?;
    written
}

/// Make each item of `plan` under `staging`, and refuse a file that changed since the plan.
fn make(staging: &Path, plan: &Plan, file: &StorageFile) -> Result<Vec<(PathBuf, Entry)>, Error> {
    let mut made = Vec::new();
    for (relative, item) in &plan.items {
        let path = if relative.as_os_str().is_empty() {
            staging.to_path_buf()
        } else {
            staging.join(relative)
        };
        match item {
            Item::Directory => std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|source| io_error("create", &path, source))?,
            Item::File { from, mode, stamp } => {
                let changed = || Error::Changed { path: from.clone() };
                let mut input = match std::fs::File::open(from) {
                    Ok(input) => input,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Err(changed());
                    }
                    Err(source) => return Err(io_error("read", from, source)),
                };
                let opened = input
                    .metadata()
                    .map_err(|source| io_error("read", from, source))?;
                if Stamp::of(&opened) != *stamp || !opened.is_file() {
                    return Err(changed());
                }
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(*mode | 0o600)
                    .open(&path)
                    .map_err(|source| io_error("write", &path, source))?;
                if let Some(edit) = &file.edit {
                    let mut text = String::new();
                    input
                        .read_to_string(&mut text)
                        .map_err(|source| io_error("read", from, source))?;
                    let (text, _) = edit.first_copy(&text).map_err(|failure| {
                        let (row, reason) = failure_text(file, edit, "the source", failure);
                        Error::Copy {
                            path: from.clone(),
                            reason: format!("`{row}`: {reason}"),
                        }
                    })?;
                    output
                        .write_all(text.as_bytes())
                        .map_err(|source| io_error("write", &path, source))?;
                } else if file.sync {
                    let mut bytes = Vec::new();
                    input
                        .read_to_end(&mut bytes)
                        .map_err(|source| io_error("read", from, source))?;
                    output
                        .write_all(&bytes)
                        .map_err(|source| io_error("write", &path, source))?;
                    made.push((relative.clone(), entry(&bytes)));
                } else {
                    std::io::copy(&mut input, &mut output)
                        .map_err(|source| io_error("write", &path, source))?;
                }
                #[cfg(test)]
                AFTER_EACH_FILE.with(|hook| {
                    if let Some(hook) = &*hook.borrow() {
                        hook(from);
                    }
                });
            }
        }
    }
    Ok(made)
}

/// A test's step that [`make`] runs after it copies each host file, so a test can change a host
/// file in the middle of a copy.
#[cfg(test)]
type AfterEachFile = Option<Box<dyn Fn(&Path)>>;

#[cfg(test)]
thread_local! {
    static AFTER_EACH_FILE: std::cell::RefCell<AfterEachFile> =
        const { std::cell::RefCell::new(None) };
}

/// Apply each `set` row of `file` to its copy in storage. `box` opens each directory from the
/// storage root down and the copy without following a link, so a box that swaps a link in cannot
/// make a run write anywhere else. It reads nothing else from the copy.
pub(crate) fn rewrite(file: &StorageFile) -> Result<(), Error> {
    let Some(edit) = file.edit.as_ref().filter(|edit| !edit.set.is_empty()) else {
        return Ok(());
    };
    let in_storage = format!("{} in storage", file.relative);
    edit_copy(file, false, |text| {
        edit.rewrite(text).map_err(|failure| {
            let (at, reason) = failure_text(file, edit, &in_storage, failure);
            Error::Set { at, reason }
        })
    })
    .map(|_| ())
}

/// Add to the copy of a row with `fill` each `keep` value of `kept` that it lacks, through the
/// same walk as [`rewrite`]. A copy that is a link, not a file, or a file with another hard link is
/// left alone, and the reason is returned.
pub(crate) fn fill(file: &StorageFile, kept: &str) -> Result<Option<String>, Error> {
    let Some(edit) = file.edit.as_ref().filter(|edit| edit.fill) else {
        return Ok(None);
    };
    let in_storage = format!("{} in storage", file.relative);
    edit_copy(file, true, |text| {
        edit.fill(text, kept)
            .map(|filled| filled.map(|(text, _)| text))
            .map_err(|failure| {
                let (at, reason) = failure_text(file, edit, &in_storage, failure);
                Error::Set { at, reason }
            })
    })
}

/// Replace the copy of `file` with what `change` makes of its text, when `change` returns a text.
/// `box` opens each directory from the storage root down and the copy without following a link,
/// so a box that swaps a link in cannot make a run write anywhere else.
fn edit_copy(
    file: &StorageFile,
    leave: bool,
    change: impl FnOnce(&str) -> Result<Option<String>, Error>,
) -> Result<Option<String>, Error> {
    let copy = Copy {
        target: &file.target,
        relative: &file.relative,
        at: &file.at,
        create: false,
        limit: None,
    };
    edit_in_storage(&copy, leave, |text| change(text.unwrap_or_default()))
}

/// A file in storage that [`edit_in_storage`] rewrites.
pub struct Copy<'a> {
    pub target: &'a Path,
    /// The target relative to the storage root.
    pub relative: &'a str,
    /// The row as an error names it.
    pub at: &'a str,
    /// Whether an absent file is created, with `change` given `None`.
    pub create: bool,
    /// The most bytes the file may hold.
    pub limit: Option<u64>,
}

/// [`edit_copy`] for any file in storage: open each directory from the storage root down and the
/// file without following a link, refuse a file with another hard link, and replace the file with
/// what `change` makes of its text.
pub fn edit_in_storage(
    copy: &Copy<'_>,
    leave: bool,
    change: impl FnOnce(Option<&str>) -> Result<Option<String>, Error>,
) -> Result<Option<String>, Error> {
    let file = copy;
    let refused = |reason: String| Error::Set {
        at: file.at.to_string(),
        reason,
    };
    let names: Vec<&str> = Path::new(file.relative)
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    let Some((name, directories)) = names.split_last() else {
        return Err(refused(format!(
            "{} is not a path in storage",
            file.relative
        )));
    };
    let root = file
        .target
        .ancestors()
        .nth(names.len())
        .ok_or_else(|| refused(format!("{} is not a path in storage", file.relative)))?;
    let in_storage = format!("{} in storage", file.relative);
    let opened = |error: std::io::Error, what: &str| {
        if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
            refused(format!(
                "{what} in storage is a link or not a folder; box rewrites through no link"
            ))
        } else {
            io_error("open", file.target, error)
        }
    };
    let mut directory = open_directory(root).map_err(|error| io_error("open", root, error))?;
    let mut walked = PathBuf::new();
    for part in directories {
        walked.push(part);
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        let next = match open_at(&directory, part, flags, 0) {
            Err(error) if file.create && error.kind() == std::io::ErrorKind::NotFound => {
                match make_directory_at(&directory, part, 0o700) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(io_error("create", &root.join(&walked), error)),
                }
                open_at(&directory, part, flags, 0)
            }
            opened => opened,
        };
        directory = next.map_err(|error| opened(error, &walked.display().to_string()))?;
    }
    let odd = |reason: String| {
        if leave {
            Ok(Some(reason))
        } else {
            Err(refused(reason))
        }
    };
    let copy = match open_at(&directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(copy) => copy,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return odd(format!("{in_storage} is a link; box rewrites no link"));
        }
        Err(error) if file.create && error.kind() == std::io::ErrorKind::NotFound => {
            let Some(text) = change(None)? else {
                return Ok(None);
            };
            write_beside(&directory, name, 0o600, &text)
                .map_err(|error| io_error("write", file.target, error))?;
            return Ok(None);
        }
        Err(error) => return Err(io_error("open", file.target, error)),
    };
    let copy = std::fs::File::from(copy);
    let metadata = copy
        .metadata()
        .map_err(|source| io_error("read", file.target, source))?;
    if !metadata.is_file() {
        return odd(format!(
            "{in_storage} is not a file; box rewrites only a file"
        ));
    }
    if metadata.nlink() != 1 {
        return odd(format!(
            "{in_storage} has another hard link; box rewrites no linked file"
        ));
    }
    if let Some(limit) = file.limit
        && metadata.len() > limit
    {
        return Err(refused(format!("{in_storage} is more than {limit} bytes")));
    }
    let mut text = String::new();
    copy.take(file.limit.map_or(u64::MAX, |limit| limit + 1))
        .read_to_string(&mut text)
        .map_err(|source| io_error("read", file.target, source))?;
    if file.limit.is_some_and(|limit| text.len() as u64 > limit) {
        return Err(refused(format!(
            "{in_storage} is more than {} bytes",
            file.limit.unwrap_or_default()
        )));
    }
    let Some(text) = change(Some(&text))? else {
        return Ok(None);
    };
    let mode = (metadata.permissions().mode() & 0o755) | 0o600;
    write_beside(&directory, name, mode, &text)
        .map_err(|error| io_error("write", file.target, error))?;
    Ok(None)
}

/// Write `text` to a new file beside `name` in `directory`, then rename it over `name`.
fn write_beside(
    directory: &std::os::fd::OwnedFd,
    name: &str,
    mode: u32,
    text: &str,
) -> std::io::Result<()> {
    let staged = format!(".{name}.box-{}", std::process::id());
    let written = open_at(
        directory,
        &staged,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        mode,
    )
    .map(std::fs::File::from)
    .and_then(|mut output| output.write_all(text.as_bytes()))
    .and_then(|()| rename_at(directory, &staged, name));
    if written.is_err() {
        let _ = unlink_at(directory, &staged);
    }
    written
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::mcp::Format;
    use crate::storage_edit::Setting;

    fn shell(value: &str) -> Edit {
        Edit {
            kind: Format::Json,
            keep: None,
            set: vec![Setting {
                key: vec!["shellPath".into()],
                value: value.into(),
            }],
            fill: false,
        }
    }

    fn json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON")
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let home = directory.path().canonicalize().expect("canonical");
            Self {
                _directory: directory,
                home,
            }
        }

        fn refusals(&self) -> Refusals {
            Refusals {
                home: self.home.clone(),
                roots: vec![
                    (self.home.join("work/app"), "the workspace".into()),
                    (self.home.join(".strands/box"), "the box home".into()),
                ],
                shipped: None,
                protected: Vec::new(),
            }
        }

        fn write(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.home.join(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
            std::fs::write(&path, text).expect("a file");
            path
        }

        fn staging(&self) -> PathBuf {
            let runs = self.home.join(".strands/box/r/r");
            std::fs::create_dir_all(&runs).expect("a run folder");
            runs.join("copy")
        }

        fn row(&self, source: &str, target: &str) -> StorageFile {
            StorageFile {
                source: self.home.join(source),
                target: self.home.join(".strands/box/storage/p/w").join(target),
                relative: target.into(),
                optional: true,
                at: "storage.files[0]".into(),
                edit: None,
                sync: false,
                exclude: Vec::new(),
            }
        }

        fn edited(&self, source: &str, target: &str, edit: Edit) -> StorageFile {
            StorageFile {
                edit: Some(edit),
                ..self.row(source, target)
            }
        }

        fn plan(&self, file: &StorageFile) -> Plan {
            match state(file, &self.refusals()).expect("a state") {
                State::WillCopy(plan) => plan,
                other => panic!("a copy, not {other:?}"),
            }
        }
    }

    #[test]
    fn a_source_reached_through_a_link_is_checked_as_its_real_path() {
        let fixture = Fixture::new();
        fixture.write(".strands/box/packs/notes.md", "notes");
        let link = fixture.home.join("notes");
        symlink(fixture.home.join(".strands/box/packs"), &link).expect("a link");
        let reason = fixture.refusals().check(&link).expect_err("a refusal");
        assert_eq!(
            reason,
            "~/notes (a link to ~/.strands/box/packs) lies in the box home, ~/.strands/box; box copies no \
             file from there"
        );
    }

    #[test]
    fn a_copy_from_boxs_own_packs_through_a_linked_release_folder_is_planned() {
        let fixture = Fixture::new();
        fixture.write(
            ".strands/box/packages/v1/resources/packs/kiro/box.md",
            "guidance",
        );
        symlink(
            fixture.home.join(".strands/box/packages/v1"),
            fixture.home.join(".strands/box/packages/current"),
        )
        .expect("a link");
        let refusals = Refusals {
            shipped: Some(
                fixture
                    .home
                    .join(".strands/box/packages/current/resources/packs"),
            ),
            ..fixture.refusals()
        };
        let file = fixture.row(
            ".strands/box/packages/current/resources/packs/kiro/box.md",
            "home/.kiro/steering/box.md",
        );
        assert!(matches!(
            state(&file, &refusals).expect("a state"),
            State::WillCopy(_)
        ));
    }

    #[test]
    fn a_copy_from_boxs_own_packs_in_a_path_that_a_secret_source_protects_is_refused() {
        let fixture = Fixture::new();
        fixture.write(
            ".strands/box/packages/v1/resources/packs/kiro/box.md",
            "guidance",
        );
        let packs = fixture
            .home
            .join(".strands/box/packages/v1/resources/packs");
        let refusals = Refusals {
            shipped: Some(packs.clone()),
            protected: vec![Protected {
                path: fixture.home.join(".strands/box/packages"),
                key: "reads",
                source: "`[secret-source.op]` of the profile".to_string(),
            }],
            ..fixture.refusals()
        };
        assert_eq!(
            refusals.check(&packs.join("kiro/box.md")),
            Err(
                "~/.strands/box/packages/v1/resources/packs/kiro/box.md lies in ~/.strands/box/packages, a path \
                 that `[secret-source.op]` of the profile lists in `reads`, which the box keeps \
                 from every workload; box copies no file from there"
                    .to_string()
            )
        );
        assert_eq!(
            Refusals {
                protected: Vec::new(),
                ..refusals
            }
            .check(&packs.join("kiro/box.md")),
            Ok(()),
            "box's own packs pass the roots"
        );
    }

    #[test]
    fn a_source_in_or_holding_a_refused_root_is_refused() {
        let fixture = Fixture::new();
        let refusals = fixture.refusals();
        for source in [
            "work/app/CLAUDE.md",
            "work",
            ".strands/box/packs",
            ".strands/box",
        ] {
            assert!(
                refusals.check(&fixture.home.join(source)).is_err(),
                "{source:?} is refused"
            );
        }
    }

    #[test]
    fn a_link_inside_the_source_is_copied_as_its_content() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/SKILL.md", "a");
        symlink(
            fixture.home.join(".claude/skills/a"),
            fixture.home.join(".claude/skills/b"),
        )
        .expect("a link");
        let file = fixture.row(".claude/skills", "config/skills");
        let plan = fixture.plan(&file);
        assert!(
            plan.followed.is_empty() && plan.skipped.is_empty(),
            "{plan:?}"
        );
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        let copied = file.target.join("b/SKILL.md");
        assert!(
            std::fs::symlink_metadata(file.target.join("b"))
                .expect("stat")
                .is_dir(),
            "the link becomes a folder"
        );
        assert_eq!(std::fs::read_to_string(copied).expect("read"), "a");
    }

    #[test]
    fn a_link_that_leaves_the_source_is_followed_only_to_a_target_that_passes_the_checks() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/own/SKILL.md", "own");
        fixture.write("tools/skills/installed/SKILL.md", "installed");
        fixture.write(".strands/box/packs/pack/pack.toml", "pack");
        fixture.write("work/app/planted/SKILL.md", "planted");
        let skills = fixture.home.join(".claude/skills");
        symlink(
            fixture.home.join("tools/skills/installed"),
            skills.join("installed"),
        )
        .expect("a link");
        symlink(
            fixture.home.join(".strands/box/packs"),
            skills.join("packs"),
        )
        .expect("a link");
        symlink(
            fixture.home.join("work/app/planted"),
            skills.join("planted"),
        )
        .expect("a link");
        symlink(fixture.home.join("nowhere"), skills.join("dangling")).expect("a link");
        let file = fixture.row(".claude/skills", "config/skills");
        let plan = fixture.plan(&file);
        assert_eq!(
            plan.followed,
            vec![(
                PathBuf::from("installed"),
                fixture.home.join("tools/skills/installed")
            )]
        );
        assert_eq!(
            plan.skipped,
            vec![
                (
                    PathBuf::from("dangling"),
                    "the link points at nothing".to_string()
                ),
                (
                    PathBuf::from("packs"),
                    "~/.strands/box/packs lies in the box home, ~/.strands/box; box copies no file from there"
                        .to_string()
                ),
                (
                    PathBuf::from("planted"),
                    "~/work/app/planted lies in the workspace, ~/work/app; box copies no file \
                     from there"
                        .to_string()
                ),
            ]
        );
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        assert!(file.target.join("installed/SKILL.md").is_file());
        assert!(!file.target.join("packs").exists());
        assert!(!file.target.join("planted").exists());
    }

    #[test]
    fn a_link_inside_a_followed_target_is_checked_against_that_target() {
        let fixture = Fixture::new();
        fixture.write("tools/skill/SKILL.md", "skill");
        fixture.write("tools/other/notes.md", "other");
        symlink(
            fixture.home.join("work/app"),
            fixture.home.join("tools/skill/project"),
        )
        .expect("a link");
        fixture.write("work/app/README.md", "project");
        symlink(
            fixture.home.join("tools/other"),
            fixture.home.join("tools/skill/other"),
        )
        .expect("a link");
        let skills = fixture.home.join(".claude/skills");
        std::fs::create_dir_all(&skills).expect("a folder");
        symlink(fixture.home.join("tools/skill"), skills.join("skill")).expect("a link");
        let plan = fixture.plan(&fixture.row(".claude/skills", "config/skills"));
        assert_eq!(
            plan.followed,
            vec![
                (PathBuf::from("skill"), fixture.home.join("tools/skill")),
                (
                    PathBuf::from("skill/other"),
                    fixture.home.join("tools/other")
                ),
            ]
        );
        assert_eq!(
            plan.skipped,
            vec![(
                PathBuf::from("skill/project"),
                "~/work/app is the workspace; box copies no file from there".to_string()
            )]
        );
    }

    #[test]
    fn a_link_to_a_folder_that_holds_it_is_not_followed() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/SKILL.md", "a");
        symlink(
            fixture.home.join(".claude/skills"),
            fixture.home.join(".claude/skills/a/loop"),
        )
        .expect("a link");
        let plan = fixture.plan(&fixture.row(".claude/skills", "config/skills"));
        assert!(plan.followed.is_empty(), "{plan:?}");
        assert_eq!(
            plan.skipped,
            vec![(
                PathBuf::from("a/loop"),
                "the link points at a folder that holds it".to_string()
            )]
        );
    }

    #[test]
    fn exclude_leaves_out_each_entry_of_that_name_at_any_depth() {
        let fixture = Fixture::new();
        fixture.write(".kiro/powers/installed/a/POWER.md", "a");
        fixture.write(".kiro/powers/installed/a/mcp.json", "{}");
        fixture.write(".kiro/powers/installed/a/steering/a.md", "steering");
        fixture.write(".kiro/powers/installed/b/mcp.json/server.json", "{}");
        fixture.write(".kiro/powers/installed/e/MCP.json", "{}");
        fixture.write(".kiro/powers/installed/mcp.json.bak", "kept");
        fixture.write("tools/linked/POWER.md", "linked");
        fixture.write("tools/linked/mcp.json", "{}");
        fixture.write("tools/named/POWER.md", "named");
        let installed = fixture.home.join(".kiro/powers/installed");
        symlink(fixture.home.join("tools/linked"), installed.join("c")).expect("a link");
        symlink(
            fixture.home.join("tools/named"),
            installed.join("a/mcp.json.d"),
        )
        .expect("a link");
        symlink(
            fixture.home.join("tools/named/POWER.md"),
            installed.join("d"),
        )
        .expect("a link");
        let file = StorageFile {
            exclude: vec!["mcp.json".into(), "d".into()],
            ..fixture.row(".kiro/powers/installed", "home/.kiro/powers/installed")
        };
        let plan = fixture.plan(&file);
        let named = "the row's `exclude` names it".to_string();
        assert_eq!(
            plan.skipped,
            vec![
                (PathBuf::from("a/mcp.json"), named.clone()),
                (PathBuf::from("b/mcp.json"), named.clone()),
                (PathBuf::from("c/mcp.json"), named.clone()),
                (PathBuf::from("d"), named.clone()),
                (PathBuf::from("e/MCP.json"), named),
            ]
        );
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        for kept in [
            "a/POWER.md",
            "a/steering/a.md",
            "a/mcp.json.d/POWER.md",
            "c/POWER.md",
            "mcp.json.bak",
        ] {
            assert!(file.target.join(kept).is_file(), "{kept}");
        }
        for left_out in ["a/mcp.json", "b/mcp.json", "c/mcp.json", "d", "e/MCP.json"] {
            assert!(!file.target.join(left_out).exists(), "{left_out}");
        }
        assert!(file.target.join("b").is_dir(), "the folder around it stays");
    }

    #[test]
    fn exclude_on_a_source_that_is_one_file_is_refused() {
        let fixture = Fixture::new();
        fixture.write(".kiro/powers/installed.json", "{}");
        let file = StorageFile {
            exclude: vec!["mcp.json".into()],
            ..fixture.row(
                ".kiro/powers/installed.json",
                "home/.kiro/powers/installed.json",
            )
        };
        let source = fixture.home.join(".kiro/powers/installed.json");
        let reason = format!(
            "`storage.files[0] exclude` names entries of a folder, and {} is not a folder",
            source.display()
        );
        assert_eq!(state(&file, &fixture.refusals()), Err(reason.clone()));
        assert_eq!(
            host_tree(&file, &fixture.refusals()).map(|_| ()),
            Err(reason)
        );
    }

    #[test]
    fn a_target_that_exists_is_left_as_the_box_left_it() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md");
        let plan = fixture.plan(&file);
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        assert_eq!(std::fs::read_to_string(&file.target).expect("read"), "host");
        std::fs::write(&file.target, "edited in the box").expect("an edit");
        fixture.write(".claude/CLAUDE.md", "host, changed");
        assert_eq!(
            state(&file, &fixture.refusals()).expect("a state"),
            State::InStorage
        );
        std::fs::remove_file(&file.target).expect("remove");
        symlink(fixture.home.join(".ssh"), &file.target).expect("a planted link");
        assert_eq!(
            state(&file, &fixture.refusals()).expect("a state"),
            State::InStorage,
            "a link at the target is not followed and not replaced"
        );
        std::fs::remove_file(&file.target).expect("remove");
        let plan = fixture.plan(&file);
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a second copy");
        assert_eq!(
            std::fs::read_to_string(&file.target).expect("read"),
            "host, changed",
            "a deleted copy is copied again"
        );
    }

    #[test]
    fn a_missing_source_is_absent_when_optional_and_refused_otherwise() {
        let fixture = Fixture::new();
        let mut file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md");
        assert_eq!(
            state(&file, &fixture.refusals()).expect("a state"),
            State::Absent
        );
        file.optional = false;
        assert!(state(&file, &fixture.refusals()).is_err());
    }

    #[test]
    fn a_link_above_the_target_is_refused() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/SKILL.md", "a");
        let file = fixture.row(".claude/skills", "config/deep/skills");
        let storage = fixture.home.join(".strands/box/storage/p/w/config");
        std::fs::create_dir_all(&storage).expect("a folder");
        std::fs::create_dir_all(fixture.home.join("elsewhere")).expect("a folder");
        symlink(fixture.home.join("elsewhere"), storage.join("deep")).expect("a planted link");
        let plan = fixture.plan(&file);
        let error = copy(&file, &plan, &fixture.staging(), &fixture.home).expect_err("a refusal");
        assert!(matches!(error, Error::Symlink { .. }), "{error}");
        assert_eq!(
            std::fs::read_dir(fixture.home.join("elsewhere"))
                .expect("list")
                .count(),
            0
        );
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_left_out_and_reported() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/SKILL.md", "a");
        let locked = fixture.home.join(".claude/skills/locked");
        std::fs::create_dir_all(&locked).expect("a folder");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let readable = std::fs::read_dir(&locked).is_ok();
        let plan = fixture.plan(&fixture.row(".claude/skills", "config/skills"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        if readable {
            eprintln!("skipping: this user reads a mode-000 folder");
            return;
        }
        assert_eq!(plan.skipped.len(), 1, "{plan:?}");
        assert_eq!(plan.skipped[0].0, PathBuf::from("locked"));
        assert!(plan.skipped[0].1.contains("box cannot list it"), "{plan:?}");
    }

    #[test]
    fn a_file_replaced_after_the_plan_is_not_copied() {
        let fixture = Fixture::new();
        let skill = fixture.write(".claude/skills/a/SKILL.md", "a");
        fixture.write(".ssh/id_ed25519", "key");
        let file = fixture.row(".claude/skills", "config/skills");
        let plan = fixture.plan(&file);
        std::fs::remove_file(&skill).expect("remove");
        symlink(fixture.home.join(".ssh/id_ed25519"), &skill).expect("a swapped link");
        let error = copy(&file, &plan, &fixture.staging(), &fixture.home).expect_err("a refusal");
        assert!(matches!(error, Error::Changed { .. }), "{error}");
        assert!(!file.target.exists(), "nothing reaches storage");
        assert!(!fixture.staging().exists(), "the staging folder is removed");
    }

    #[test]
    fn a_file_rewritten_in_place_or_gone_after_the_plan_is_not_copied() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db 1");
        let wal = fixture.write(".kiro/memories/memories.db-wal", "wal 1");
        let file = fixture.row(".kiro/memories", "home/.kiro/memories");

        let plan = fixture.plan(&file);
        let later = std::fs::metadata(&database)
            .expect("stat")
            .modified()
            .expect("a time")
            + std::time::Duration::from_secs(5);
        let output = std::fs::OpenOptions::new()
            .write(true)
            .open(&database)
            .expect("open");
        output.set_modified(later).expect("a new time");
        drop(output);
        let error = copy(&file, &plan, &fixture.staging(), &fixture.home).expect_err("a change");
        assert!(
            matches!(&error, Error::Changed { path } if *path == database),
            "same inode and size, a new time: {error}"
        );
        assert!(!file.target.exists(), "nothing reaches storage");
        assert!(!fixture.staging().exists(), "the staging folder is removed");

        let plan = fixture.plan(&file);
        std::fs::remove_file(&wal).expect("remove");
        let error = copy(&file, &plan, &fixture.staging(), &fixture.home).expect_err("a change");
        assert!(
            matches!(&error, Error::Changed { path } if *path == wal),
            "{error}"
        );
        assert!(!file.target.exists(), "nothing reaches storage");
    }

    #[test]
    fn a_file_written_after_box_copied_it_is_seen_at_the_end_of_the_copy() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db 1");
        fixture.write(".kiro/memories/memories.db-wal", "wal 1");
        let file = fixture.row(".kiro/memories", "home/.kiro/memories");
        let plan = fixture.plan(&file);
        let staging = fixture.staging();
        make(&staging, &plan, &file).expect("a copy in staging");
        assert_eq!(plan.changed(), None);
        std::fs::write(&database, "db 1, and a page").expect("a write");
        assert_eq!(plan.changed(), Some(database.as_path()));
    }

    #[test]
    fn a_file_that_changes_after_box_copied_it_fails_the_copy_and_nothing_reaches_storage() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db 1");
        fixture.write(".kiro/memories/memories.db-wal", "wal 1");
        let file = fixture.row(".kiro/memories", "home/.kiro/memories");
        let plan = fixture.plan(&file);
        // The open-time check has passed for the database by now, so only the check at the end
        // of the copy can see this write.
        let written = database.clone();
        AFTER_EACH_FILE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |from: &Path| {
                if from == written.as_path() {
                    std::fs::write(&written, "db 1, and a page").expect("a write");
                }
            }));
        });
        let copied = copy(&file, &plan, &fixture.staging(), &fixture.home);
        AFTER_EACH_FILE.with(|hook| hook.borrow_mut().take());
        let error = copied.expect_err("a change");
        assert!(
            matches!(&error, Error::Changed { path } if *path == database),
            "{error}"
        );
        assert!(!file.target.exists(), "nothing reaches storage");
        assert!(!fixture.staging().exists(), "the staging folder is removed");
    }

    #[test]
    fn a_row_with_keep_copies_only_the_kept_parts() {
        let fixture = Fixture::new();
        fixture.write(
            ".claude/settings.json",
            r#"{"model": "opus", "env": {"KEY": "sk"}, "apiKeyHelper": "x"}"#,
        );
        let file = fixture.edited(
            ".claude/settings.json",
            "config/settings.json",
            Edit {
                kind: Format::Json,
                keep: Some(vec![vec!["model".into()], vec!["theme".into()]]),
                set: Vec::new(),
                fill: false,
            },
        );
        let plan = fixture.plan(&file);
        let kept = plan.kept.clone().expect("what keep takes");
        assert_eq!(kept.kept, vec![vec!["model".to_string()]]);
        assert_eq!(
            kept.dropped,
            vec![vec!["env".to_string()], vec!["apiKeyHelper".to_string()]]
        );
        assert_eq!(kept.missing, vec![vec!["theme".to_string()]]);
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        assert_eq!(
            std::fs::read_to_string(&file.target).expect("read"),
            "{\n  \"model\": \"opus\"\n}\n"
        );
    }

    #[test]
    fn set_writes_its_value_on_every_run_and_leaves_the_rest_as_the_box_left_it() {
        let fixture = Fixture::new();
        let host = fixture.write(
            ".pi/agent/settings.json",
            r#"{"defaultModel": "opus", "shellPath": "/opt/homebrew/bin/bash"}"#,
        );
        let first = fixture.edited(
            ".pi/agent/settings.json",
            "agent/settings.json",
            shell("/run-1/bin/bash"),
        );
        let plan = fixture.plan(&first);
        assert_eq!(plan.kept, None, "a row without keep keeps the whole file");
        copy(&first, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        assert_eq!(json(&first.target)["shellPath"], "/run-1/bin/bash");
        let mut edited = json(&first.target);
        edited["defaultModel"] = "sonnet".into();
        edited["shellPath"] = "/bin/false".into();
        std::fs::write(&first.target, edited.to_string()).expect("a box edit");
        let second = fixture.edited(
            ".pi/agent/settings.json",
            "agent/settings.json",
            shell("/run-2/bin/bash"),
        );
        assert_eq!(state(&second, &fixture.refusals()), Ok(State::InStorage));
        rewrite(&second).expect("a rewrite");
        let copy = json(&second.target);
        assert_eq!(
            copy["shellPath"], "/run-2/bin/bash",
            "the box's change is put back"
        );
        assert_eq!(copy["defaultModel"], "sonnet", "the box's own edit stays");
        assert!(
            std::fs::read_to_string(host)
                .expect("read")
                .contains("/opt/homebrew/bin/bash"),
            "the host file is never written"
        );
        let directory = second.target.parent().expect("a parent");
        assert_eq!(
            std::fs::read_dir(directory).expect("list").count(),
            1,
            "no staged file is left beside the copy"
        );
    }

    #[test]
    fn a_rewrite_follows_no_link_at_the_copy_or_above_it() {
        let fixture = Fixture::new();
        let secret = fixture.write(".ssh/config.json", r#"{"shellPath": "host"}"#);
        let file = fixture.edited(
            ".pi/settings.json",
            "agent/pi/settings.json",
            shell("/box/bin/bash"),
        );
        let agent = file.target.parent().expect("a parent").to_path_buf();
        std::fs::create_dir_all(&agent).expect("a folder");
        symlink(&secret, &file.target).expect("a planted link");
        let error = rewrite(&file).expect_err("a refusal").to_string();
        assert_eq!(
            error,
            "`storage.files[0]`: agent/pi/settings.json in storage is a link; box rewrites no link"
        );
        std::fs::remove_file(&file.target).expect("remove");
        std::fs::remove_dir(&agent).expect("remove");
        symlink(fixture.home.join(".ssh"), &agent).expect("a planted folder link");
        std::fs::rename(&secret, fixture.home.join(".ssh/settings.json")).expect("move");
        let error = rewrite(&file).expect_err("a refusal").to_string();
        assert!(
            error.contains("agent/pi in storage is a link or not a folder"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.home.join(".ssh/settings.json")).expect("read"),
            r#"{"shellPath": "host"}"#,
            "the host file is unchanged"
        );
    }

    #[test]
    fn a_copy_that_no_longer_parses_or_is_not_a_file_stops_the_run() {
        let fixture = Fixture::new();
        let file = fixture.edited(
            ".pi/settings.json",
            "agent/settings.json",
            shell("/box/bin/bash"),
        );
        std::fs::create_dir_all(file.target.parent().expect("a parent")).expect("a folder");
        std::fs::write(&file.target, "not json").expect("a broken copy");
        let error = rewrite(&file).expect_err("a refusal").to_string();
        assert!(
            error.starts_with("`storage.files[0]`: agent/settings.json in storage is not JSON: ")
                && error.ends_with(", so box cannot set shellPath"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&file.target).expect("read"),
            "not json"
        );
        std::fs::remove_file(&file.target).expect("remove");
        std::fs::create_dir(&file.target).expect("a folder at the target");
        let error = rewrite(&file).expect_err("a refusal").to_string();
        assert!(
            error.contains("is not a file; box rewrites only a file"),
            "{error}"
        );
    }

    #[test]
    fn keep_or_set_on_a_folder_or_on_a_source_not_of_its_kind_is_refused() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/SKILL.md", "a");
        let folder = fixture.edited(".claude/skills", "config/skills", shell("x"));
        assert_eq!(
            state(&folder, &fixture.refusals()),
            Err("`storage.files[0]`: it is a folder; `keep` and `set` need a file".into())
        );
        fixture.write(".pi/settings.json", "// jsonc\n{}");
        let file = fixture.edited(".pi/settings.json", "agent/settings.json", shell("x"));
        let reason = state(&file, &fixture.refusals()).expect_err("a refusal");
        assert!(
            reason.starts_with("`storage.files[0]`: the source is not JSON: "),
            "{reason}"
        );
    }

    #[test]
    fn a_copied_file_keeps_its_execute_bit() {
        let fixture = Fixture::new();
        let script = fixture.write(".claude/skills/a/run.sh", "#!/bin/sh\n");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let file = fixture.row(".claude/skills", "config/skills");
        let plan = fixture.plan(&file);
        copy(&file, &plan, &fixture.staging(), &fixture.home).expect("a copy");
        let mode = std::fs::metadata(file.target.join("a/run.sh"))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    fn filling() -> Edit {
        Edit {
            kind: Format::Json,
            keep: Some(vec![vec!["done".into()]]),
            set: Vec::new(),
            fill: true,
        }
    }

    #[test]
    fn a_set_row_with_no_host_file_writes_a_new_file_of_only_its_values() {
        let fixture = Fixture::new();
        let file = fixture.edited(
            ".pi/agent/settings.json",
            "agent/settings.json",
            shell("/b"),
        );
        assert_eq!(state(&file, &fixture.refusals()), Ok(State::Absent));
        create(&file, &fixture.staging(), &fixture.home).expect("a new file");
        assert_eq!(json(&file.target), serde_json::json!({"shellPath": "/b"}));
        assert_eq!(
            std::fs::metadata(&file.target)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(state(&file, &fixture.refusals()), Ok(State::InStorage));

        let plain = fixture.row(".pi/agent/AGENTS.md", "agent/AGENTS.md");
        create(&plain, &fixture.staging(), &fixture.home).expect("nothing to write");
        assert!(std::fs::symlink_metadata(&plain.target).is_err());
    }

    #[test]
    fn a_fill_leaves_a_linked_or_hard_linked_copy_alone_and_a_set_refuses_a_hard_link() {
        let fixture = Fixture::new();
        fixture.write(".claude.json", r#"{"done": true}"#);
        let secret = fixture.write("secret.json", r#"{"token": "s3cret"}"#);
        let file = fixture.edited(".claude.json", "config/.claude.json", filling());
        std::fs::create_dir_all(file.target.parent().expect("a parent")).expect("a folder");
        std::fs::hard_link(&secret, &file.target).expect("a hard link");
        let State::Fill { text, .. } = state(&file, &fixture.refusals()).expect("a state") else {
            panic!("a fill");
        };
        let why = fill(&file, &text).expect("a fill").expect("left alone");
        assert!(why.contains("hard link"), "{why}");
        assert_eq!(
            std::fs::read_to_string(&file.target).expect("read"),
            r#"{"token": "s3cret"}"#
        );
        assert_eq!(
            std::fs::metadata(&file.target).expect("metadata").ino(),
            std::fs::metadata(&secret).expect("metadata").ino()
        );
        let set = fixture.edited(".claude.json", "config/.claude.json", shell("/bin/zsh"));
        let error = rewrite(&set).expect_err("a refusal").to_string();
        assert!(error.contains("hard link"), "{error}");

        std::fs::remove_file(&file.target).expect("remove");
        symlink(&secret, &file.target).expect("a link");
        let why = fill(&file, &text).expect("a fill").expect("left alone");
        assert!(why.contains("is a link"), "{why}");
        assert_eq!(
            std::fs::read_to_string(&secret).expect("read"),
            r#"{"token": "s3cret"}"#
        );
    }

    #[test]
    fn a_fill_checks_its_source_on_each_run() {
        let fixture = Fixture::new();
        fixture.write("work/app/.claude.json", r#"{"done": true}"#);
        let link = fixture.home.join(".claude.json");
        symlink(fixture.home.join("work/app/.claude.json"), &link).expect("a link");
        let file = fixture.edited(".claude.json", "config/.claude.json", filling());
        fixture.write(".strands/box/storage/p/w/config/.claude.json", "{}");
        let reason = state(&file, &fixture.refusals()).expect_err("a refusal");
        assert!(reason.contains("the workspace"), "{reason}");
    }
}
