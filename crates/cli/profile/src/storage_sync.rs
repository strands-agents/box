//! The record of what `box` last copied for each `sync = true` row, and the update that brings a
//! copy in storage up to date with the host.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use nix::libc;

use crate::error::Error;
use crate::files::{
    io_error, make_directory_at, metadata_at, open_at, open_directory, rename_at, unlink_at,
};
use crate::host::tilde;
use crate::lang::Storage;
use crate::storage_files::{self, HostFile, Refusals, State, StorageFile, host_tree};

/// The name of the record in the storage root, where no grant reaches.
pub const RECORD: &str = "copies.json";

const VERSION: u32 = 1;

/// One file as `box` last copied it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    sha256: String,
    size: u64,
}

/// What `box` last copied, by row target and then by path in the copy. A row with no files still
/// has an entry once `box` has synced it.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    version: u32,
    rows: BTreeMap<String, BTreeMap<String, Entry>>,
}

impl Record {
    pub fn row(&self, relative: &str) -> Option<&BTreeMap<String, Entry>> {
        self.rows.get(relative)
    }

    pub(crate) fn set(&mut self, relative: &str, files: BTreeMap<String, Entry>) {
        self.version = VERSION;
        self.rows.insert(relative.to_string(), files);
    }
}

/// Hold the lock on the storage root `root`, waiting up to `wait` for another run of the profile.
pub fn lock(root: &Path, wait: Duration) -> Result<std::fs::File, Error> {
    let lock =
        std::fs::File::from(open_directory(root).map_err(|error| io_error("open", root, error))?);
    let start = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < wait => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Error::Copy {
                    path: root.to_path_buf(),
                    reason: "another run of this profile is updating its copies; retry when it \
                             finishes"
                        .into(),
                });
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(io_error("lock", root, error)),
        }
    }
}

/// Read the record in `root`. A record that is missing, unreadable, a link, a linked file, or not
/// this version reads as empty, so each copy keeps what the box left in it.
pub fn load(root: &Path) -> Result<Record, Error> {
    let directory = match open_directory(root) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Record::default()),
        Err(error) => return Err(io_error("open", root, error)),
    };
    let Ok(file) = open_at(&directory, RECORD, libc::O_RDONLY | libc::O_NONBLOCK, 0) else {
        return Ok(Record::default());
    };
    let mut file = std::fs::File::from(file);
    let Ok(metadata) = file.metadata() else {
        return Ok(Record::default());
    };
    if !metadata.is_file() || std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Ok(Record::default());
    }
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return Ok(Record::default());
    }
    Ok(serde_json::from_str::<Record>(&text)
        .ok()
        .filter(|record| record.version == VERSION)
        .unwrap_or_default())
}

/// Replace the record in `root` with `record`.
pub(crate) fn save(root: &Path, record: &Record) -> Result<(), Error> {
    let path = root.join(RECORD);
    let text = serde_json::to_string_pretty(record).map_err(|error| Error::Copy {
        path: path.clone(),
        reason: format!("box cannot write its record of copies: {error}"),
    })?;
    let directory = open_directory(root).map_err(|error| io_error("open", root, error))?;
    let staged = format!(".{RECORD}.box-{}", std::process::id());
    let written = open_at(
        &directory,
        &staged,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map(std::fs::File::from)
    .and_then(|mut output| output.write_all(text.as_bytes()))
    .and_then(|()| rename_at(&directory, &staged, RECORD));
    if let Err(error) = written {
        let _ = unlink_at(&directory, &staged);
        return Err(io_error("write", &path, error));
    }
    Ok(())
}

/// What one `sync = true` row does on this run, each list naming paths in storage.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Update {
    /// Files copied from the host, where the box had not changed its copy.
    pub(crate) copied: Vec<String>,
    /// Files where a host edit replaced an edit the box made.
    pub(crate) replaced: Vec<String>,
    /// Files the box changed and the host did not, kept as the box left them.
    pub(crate) kept: Vec<String>,
    /// Files of a row with no record that differ from the host, kept as the box left them.
    pub(crate) adopted: Vec<String>,
    /// Files `box` copied before that the host no longer has, kept as the box left them.
    pub(crate) gone: Vec<String>,
    /// Files `box` copied before that the row's `exclude` now names, kept as the box left them.
    pub(crate) excluded: Vec<String>,
    /// Files `box` could not update, with the reason.
    pub(crate) blocked: Vec<(String, String)>,
    /// Each link or entry on the host that the copy leaves out, as `(host path, reason)`.
    pub skipped: Vec<(PathBuf, String)>,
    /// The record of the row after this run.
    pub(crate) record: BTreeMap<String, Entry>,
}

impl Update {
    /// The lines a run prints for this row.
    pub(crate) fn notices(&self, file: &StorageFile, home: &Path) -> Vec<String> {
        let source = tilde(home, &file.source);
        let mut lines = Vec::new();
        if !self.copied.is_empty() {
            lines.push(format!("updated {} from {source}", self.copied.join(", ")));
        }
        if !self.replaced.is_empty() {
            lines.push(format!(
                "replaced the box's edit of {} with the host's version from {source}",
                self.replaced.join(", ")
            ));
        }
        if !self.adopted.is_empty() {
            lines.push(format!(
                "kept the box's copy of {}, which differs from {source}; a later edit on the host \
                 replaces it",
                self.adopted.join(", ")
            ));
        }
        if !self.gone.is_empty() {
            lines.push(format!(
                "kept {}, which {source} no longer has",
                self.gone.join(", ")
            ));
        }
        if !self.excluded.is_empty() {
            lines.push(format!(
                "kept {} from an earlier copy, which the row's `exclude` now names; delete it in \
                 storage to take it out of the box",
                self.excluded.join(", ")
            ));
        }
        lines.extend(
            self.blocked
                .iter()
                .map(|(path, why)| format!("did not update {path}: {why}")),
        );
        lines
    }

    /// What `box profile show` says the row does.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.copied.is_empty() {
            parts.push(format!(
                "will update {} from the host",
                self.copied.join(", ")
            ));
        }
        if !self.replaced.is_empty() {
            parts.push(format!(
                "the host's edit will replace the box's edit of {}",
                self.replaced.join(", ")
            ));
        }
        if !self.kept.is_empty() {
            parts.push(format!("keeps the box's edit of {}", self.kept.join(", ")));
        }
        if !self.adopted.is_empty() {
            parts.push(format!(
                "keeps the box's copy of {}, which differs from the host",
                self.adopted.join(", ")
            ));
        }
        if !self.gone.is_empty() {
            parts.push(format!(
                "keeps {}, which the host no longer has",
                self.gone.join(", ")
            ));
        }
        if !self.excluded.is_empty() {
            parts.push(format!(
                "keeps {} from an earlier copy, which the row's `exclude` now names",
                self.excluded.join(", ")
            ));
        }
        parts.extend(
            self.blocked
                .iter()
                .map(|(path, why)| format!("cannot update {path}: {why}")),
        );
        if parts.is_empty() {
            "in sync with the host".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// The copy of one file in storage, as the box left it.
#[derive(Debug, PartialEq)]
enum Copy {
    Missing,
    /// A link, a folder, a file with another hard link, a file below a link, a file `box` cannot
    /// read, or a file of a size that matches neither the host nor the record.
    Other,
    Same(Entry),
}

/// The folders above the file a run reaches, each opened from the storage root down without
/// following a link. The host tree lists files depth first, so each folder opens once.
struct Folders<'a> {
    root: &'a Path,
    open: HashMap<Vec<String>, OwnedFd>,
}

enum Reach<'a> {
    Open(&'a OwnedFd),
    Missing,
    Blocked,
}

impl<'a> Folders<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            open: HashMap::new(),
        }
    }

    /// Open `folders`, creating a missing one when `create` holds. Any failure below the storage
    /// root blocks it.
    fn reach(&mut self, folders: &[String], create: bool) -> Result<Reach<'_>, Error> {
        self.open.retain(|open, _| folders.starts_with(open));
        if !self.open.contains_key(&[][..]) {
            let root =
                open_directory(self.root).map_err(|error| io_error("open", self.root, error))?;
            self.open.insert(Vec::new(), root);
        }
        let known = (0..=folders.len())
            .rev()
            .find(|length| self.open.contains_key(&folders[..*length]))
            .unwrap_or(0);
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        for length in known..folders.len() {
            let parent = &self.open[&folders[..length]];
            let part = &folders[length];
            let next = match open_at(parent, part, flags, 0) {
                Ok(next) => next,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !create {
                        return Ok(Reach::Missing);
                    }
                    if make_directory_at(parent, part, 0o700).is_err() {
                        return Ok(Reach::Blocked);
                    }
                    match open_at(parent, part, flags, 0) {
                        Ok(next) => next,
                        Err(_) => return Ok(Reach::Blocked),
                    }
                }
                Err(_) => return Ok(Reach::Blocked),
            };
            self.open.insert(folders[..=length].to_vec(), next);
        }
        Ok(Reach::Open(&self.open[folders]))
    }
}

/// The SHA-256 and size of `bytes`.
pub(crate) fn entry(bytes: &[u8]) -> Entry {
    Entry {
        sha256: ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        size: bytes.len() as u64,
    }
}

/// The record of a first copy, from what [`crate::storage_files::copy`] wrote.
pub(crate) fn first_record(made: Vec<(PathBuf, Entry)>) -> BTreeMap<String, Entry> {
    made.into_iter()
        .filter_map(|(relative, entry)| Some((relative.to_str()?.to_string(), entry)))
        .collect()
}

/// The names of `path`, or `None` when one is not UTF-8.
fn names(path: &Path) -> Option<Vec<String>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_str().map(str::to_string)),
            _ => None,
        })
        .collect()
}

/// Read the copy at `path`, hashing it only when its size is one of `sizes`.
fn read_copy(folders: &mut Folders<'_>, path: &[String], sizes: &[u64]) -> Result<Copy, Error> {
    let Some((name, parents)) = path.split_last() else {
        return Ok(Copy::Other);
    };
    let directory = match folders.reach(parents, false)? {
        Reach::Open(directory) => directory,
        Reach::Missing => return Ok(Copy::Missing),
        Reach::Blocked => return Ok(Copy::Other),
    };
    let metadata = match metadata_at(directory, name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Copy::Missing),
        Err(_) => return Ok(Copy::Other),
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
        return Ok(Copy::Other);
    }
    let Ok(file) = open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) else {
        return Ok(Copy::Other);
    };
    let file = std::fs::File::from(file);
    let size = match file.metadata() {
        Ok(opened) if opened.is_file() => opened.len(),
        _ => return Ok(Copy::Other),
    };
    if !sizes.contains(&size) {
        return Ok(Copy::Other);
    }
    let mut bytes = Vec::new();
    match file.take(size + 1).read_to_end(&mut bytes) {
        Ok(read) if read as u64 == size => Ok(Copy::Same(entry(&bytes))),
        _ => Ok(Copy::Other),
    }
}

/// Replace the copy at `path` with `bytes`. A link at the copy is replaced, not followed.
fn write_copy(
    folders: &mut Folders<'_>,
    path: &[String],
    bytes: &[u8],
    mode: u32,
) -> Result<(), String> {
    let Some((name, parents)) = path.split_last() else {
        return Err("it is not a path in storage".into());
    };
    let directory = match folders.reach(parents, true) {
        Ok(Reach::Open(directory)) => directory,
        _ => {
            return Err(
                "a folder on the way in storage is a link or not a folder; box writes through no \
                 link"
                    .into(),
            );
        }
    };
    if let Ok(metadata) = metadata_at(directory, name)
        && metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
    {
        return Err("the copy in storage is a folder".into());
    }
    let staged = format!(".{name}.box-{}", std::process::id());
    let written = open_at(
        directory,
        &staged,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        mode | 0o600,
    )
    .map(std::fs::File::from)
    .and_then(|mut output| output.write_all(bytes))
    .and_then(|()| rename_at(directory, &staged, name));
    if let Err(error) = written {
        let _ = unlink_at(directory, &staged);
        return Err(format!("box cannot write it: {error}"));
    }
    Ok(())
}

/// What is at the top of the row's copy.
#[derive(PartialEq)]
enum Top {
    Folder,
    File,
    Other,
}

fn top(folders: &mut Folders<'_>, path: &[String]) -> Result<Top, Error> {
    let Some((name, parents)) = path.split_last() else {
        return Ok(Top::Other);
    };
    let Reach::Open(directory) = folders.reach(parents, false)? else {
        return Ok(Top::Other);
    };
    Ok(match metadata_at(directory, name) {
        Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => Top::Folder,
        Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFREG => Top::File,
        _ => Top::Other,
    })
}

/// The path of `host` in storage, and its key in the record, or `None` when a name is not UTF-8.
fn place(file: &StorageFile, host: &HostFile<'_>) -> Option<(Vec<String>, String)> {
    let key = host.relative.to_str()?.to_string();
    let path = names(Path::new(&file.relative))?
        .into_iter()
        .chain(names(host.relative)?)
        .collect();
    Some((path, key))
}

/// Bring the copy of `file` in storage `root` up to date with the host, as the record of the row
/// `last` says what `box` copied before, and write only when `write` holds.
pub fn update(
    file: &StorageFile,
    last: Option<&BTreeMap<String, Entry>>,
    refusals: &Refusals,
    root: &Path,
    write: bool,
) -> Result<Update, Error> {
    let shown = |key: &str| {
        if key.is_empty() {
            file.relative.clone()
        } else {
            format!("{}/{key}", file.relative)
        }
    };
    let mut update = Update::default();
    let tree = match host_tree(file, refusals) {
        Ok(tree) => tree,
        Err(reason) => {
            update.blocked.push((file.relative.clone(), reason));
            update.record = last.cloned().unwrap_or_default();
            return Ok(update);
        }
    };
    let Some(tree) = tree else {
        update.gone = last
            .into_iter()
            .flat_map(BTreeMap::keys)
            .map(|key| shown(key))
            .collect();
        return Ok(update);
    };
    let target = names(Path::new(&file.relative)).unwrap_or_default();
    let mut folders = Folders::new(root);
    let block = |update: &mut Update, why: &str| {
        update
            .blocked
            .push((file.relative.clone(), why.to_string()));
        update.record = last.cloned().unwrap_or_default();
    };
    match (tree.is_folder(), top(&mut folders, &target)?) {
        (true, Top::File) => {
            block(
                &mut update,
                "the host has a folder and storage has a file; delete the copy in storage to take \
                 a fresh one",
            );
            return Ok(update);
        }
        (false, Top::Folder) => {
            block(
                &mut update,
                "the host has a file and storage has a folder; delete the copy in storage to take \
                 a fresh one",
            );
            return Ok(update);
        }
        (true, Top::Other) => {
            block(
                &mut update,
                "the copy in storage is a link or not a folder; box writes through no link",
            );
            return Ok(update);
        }
        _ => {}
    }
    update.skipped = tree
        .skipped
        .iter()
        .map(|(path, why)| (file.source.join(path), why.clone()))
        .collect();
    let mut seen = Vec::new();
    for host in tree.files() {
        let Some((path, key)) = place(file, &host) else {
            update.skipped.push((
                file.source.join(host.relative),
                "its name is not UTF-8".into(),
            ));
            continue;
        };
        seen.push(key.clone());
        let recorded = last.and_then(|row| row.get(&key));
        let bytes = match host.read() {
            Ok(bytes) => bytes,
            Err(error) => {
                let why = match error {
                    Error::Copy { reason, .. } => reason,
                    other => other.to_string(),
                };
                update.blocked.push((shown(&key), why));
                if let Some(recorded) = recorded {
                    update.record.insert(key, recorded.clone());
                }
                continue;
            }
        };
        let now = entry(&bytes);
        let sizes: Vec<u64> = std::iter::once(now.size)
            .chain(recorded.map(|entry| entry.size))
            .collect();
        let copy = read_copy(&mut folders, &path, &sizes)?;
        let in_copy = copy == Copy::Same(now.clone());
        let take = match recorded {
            Some(recorded) if *recorded == now => {
                if !in_copy {
                    update.kept.push(shown(&key));
                }
                false
            }
            Some(recorded) => {
                if in_copy {
                    false
                } else if copy == Copy::Same(recorded.clone()) {
                    update.copied.push(shown(&key));
                    true
                } else {
                    update.replaced.push(shown(&key));
                    true
                }
            }
            None if in_copy => false,
            None if copy == Copy::Missing => {
                update.copied.push(shown(&key));
                true
            }
            None if last.is_none() => {
                update.adopted.push(shown(&key));
                false
            }
            None => {
                update.replaced.push(shown(&key));
                true
            }
        };
        if take
            && write
            && let Err(why) = write_copy(&mut folders, &path, &bytes, host.mode)
        {
            for list in [&mut update.copied, &mut update.replaced] {
                list.retain(|name| *name != shown(&key));
            }
            update.blocked.push((shown(&key), why));
            if let Some(recorded) = recorded {
                update.record.insert(key, recorded.clone());
            }
            continue;
        }
        update.record.insert(key, now);
    }
    // A key the walk did not see because `exclude` names a part of it is still on the host, so
    // it is not gone. The copy in storage stays: `box` deletes nothing the box may hold. The
    // record keeps the key while the copy is there, so each run and `box profile show` name it
    // until the operator deletes it.
    let unseen = last
        .into_iter()
        .flatten()
        .filter(|(key, _)| !seen.contains(key));
    for (key, recorded) in unseen {
        if !excluded_by(file, key) {
            update.gone.push(shown(key));
            continue;
        }
        let path = names(Path::new(&file.relative))
            .into_iter()
            .chain(names(Path::new(key.as_str())))
            .flatten()
            .collect::<Vec<_>>();
        if read_copy(&mut folders, &path, &[])? != Copy::Missing {
            update.excluded.push(shown(key));
            update.record.insert(key.clone(), recorded.clone());
        }
    }
    Ok(update)
}

/// Whether the row's `exclude` names a part of `key`, a `/`-separated path in the copy. A name
/// matches without regard to case, as the walk matches it.
fn excluded_by(file: &StorageFile, key: &str) -> bool {
    key.split('/').any(|part| {
        let part = part.to_lowercase();
        file.exclude.iter().any(|name| name.to_lowercase() == part)
    })
}

/// How long a run waits for another run of the profile to finish updating its copies.
pub const SYNC_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The links and entries the copies leave out, as `(link, reason)`, and each line about a copy
/// that a run brought up to date with the host.
#[derive(Debug, Default)]
pub struct Copied {
    pub not_copied: Vec<(String, String)>,
    pub synced: Vec<String>,
    pub import_warnings: Vec<String>,
}

/// Copy each `[[storage.files]]` row whose target storage lacks, building each copy in the run
/// directory `run`, bring each `sync = true` copy up to date with the host, and apply each `set`
/// row to a copy already in storage.
pub fn copy_files(
    storage: &Storage,
    run: &Path,
    home: &Path,
    base: &Path,
) -> Result<Copied, Error> {
    copy_files_waiting(storage, run, home, base, SYNC_LOCK_WAIT)
}

/// [`copy_files`], waiting up to `wait` for another run of the profile.
pub(crate) fn copy_files_waiting(
    storage: &Storage,
    run: &Path,
    home: &Path,
    base: &Path,
    wait: std::time::Duration,
) -> Result<Copied, Error> {
    let mut copied = Copied {
        not_copied: storage
            .skipped
            .iter()
            .map(|(path, reason)| (tilde(home, path), reason.clone()))
            .collect(),
        ..Copied::default()
    };
    let not_copied = &mut copied.not_copied;
    let syncs = storage.files.iter().any(|file| file.sync);
    let _lock = if syncs {
        Some(lock(&storage.root, wait)?)
    } else {
        None
    };
    let mut record = if syncs {
        load(&storage.root)?
    } else {
        Record::default()
    };
    let before = record.clone();
    for file in &storage.files {
        clear_tool_link(file, &storage.root)?;
    }
    for (index, file) in storage.files.iter().enumerate() {
        if file.sync && std::fs::symlink_metadata(&file.target).is_ok() {
            let update = update(
                file,
                record.row(&file.relative),
                &storage.refusals,
                &storage.root,
                true,
            )?;
            not_copied.extend(
                update
                    .skipped
                    .iter()
                    .map(|(path, why)| (tilde(home, path), why.clone())),
            );
            copied.synced.extend(update.notices(file, home));
            record.set(&file.relative, update.record);
            continue;
        }
        let state = match copy_state(file, storage)? {
            State::WillCopy(plan) => {
                let staging = run.join(format!("copy-{index}"));
                let copy = |plan: &_| storage_files::copy(file, plan, &staging, base);
                match first_copy(file, plan, storage, copy)? {
                    FirstCopy::Made(plan, made) => {
                        not_copied.extend(plan.skipped.iter().map(|(path, why)| {
                            (tilde(home, &file.source.join(path)), why.clone())
                        }));
                        if file.sync {
                            record.set(&file.relative, first_record(made));
                        }
                        continue;
                    }
                    FirstCopy::Now(state) => state,
                }
            }
            state => state,
        };
        match state {
            State::WillCopy(_) | State::NothingKept => {}
            State::InStorage => storage_files::rewrite(file)?,
            State::Fill { text, .. } => {
                let (skipped, different) = storage_files::fill(file, &text)?;
                if let Some(why) = skipped {
                    not_copied.push((tilde(home, &file.source), why));
                }
                if !different.is_empty() {
                    copied.import_warnings.push(format!(
                        "Saved settings in {:?} differ from {:?} at {}; kept the saved values. \
                         If intentional, no action is needed.",
                        tilde(home, &file.target),
                        tilde(home, &file.source),
                        different.join(", "),
                    ));
                }
            }
            State::Absent => {
                storage_files::create(file, &run.join(format!("copy-{index}")), base)?;
            }
        }
    }
    if record != before {
        save(&storage.root, &record)?;
    }
    Ok(copied)
}

/// How many times a run tries the first copy of a row whose host files change while `box` copies
/// them.
pub const COPY_TRIES: u32 = 3;

/// What the first copy of a row did.
enum FirstCopy {
    /// The copy reached storage, as the last plan states.
    Made(storage_files::Plan, Vec<(PathBuf, Entry)>),
    /// A new plan after a change copies nothing: the source went, or the target is there. The
    /// state is never [`State::WillCopy`].
    Now(State),
}

/// Copy `file` as `plan` states with `copy`. When a host file changes during the copy, plan it
/// again and try again, up to [`COPY_TRIES`] times in all. When it changes on every try, the run
/// stops, so that the agent never starts without the copy and makes the target itself.
fn first_copy(
    file: &StorageFile,
    mut plan: storage_files::Plan,
    storage: &Storage,
    mut copy: impl FnMut(&storage_files::Plan) -> Result<Vec<(PathBuf, Entry)>, Error>,
) -> Result<FirstCopy, Error> {
    let mut tries = 1;
    loop {
        match copy(&plan) {
            Ok(made) => return Ok(FirstCopy::Made(plan, made)),
            Err(Error::Changed { path }) if tries >= COPY_TRIES => {
                return Err(Error::Unsettled {
                    path: file.source.clone(),
                    file: path,
                    tries,
                });
            }
            Err(Error::Changed { .. }) => {
                std::thread::sleep(Duration::from_millis(100 * u64::from(tries)));
                tries += 1;
                match copy_state(file, storage)? {
                    State::WillCopy(next) => plan = next,
                    state => return Ok(FirstCopy::Now(state)),
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Clear what an earlier link row left at a tool copy row's target, or at a folder above it in the
/// tool's storage directory, so the row copies. The link is removed, never followed: a link in a
/// tool's storage is never box's copy. A folder
/// that holds links to entries of the source, which a `link-children` row made, stops the run and
/// names the folder, because the tool may have put its own entries beside them.
fn clear_tool_link(file: &StorageFile, root: &Path) -> Result<(), Error> {
    if !file.relative.starts_with("tool/") {
        return Ok(());
    }
    // The tool's storage directory, `<root>/tool/<tool>/<dir>`, then each folder below it down to
    // the target. The first link on that path is what an earlier link row left: remove it.
    let directory: PathBuf = root.join(file.relative.split('/').take(3).collect::<PathBuf>());
    let below = file
        .target
        .strip_prefix(&directory)
        .unwrap_or(Path::new(""));
    let mut path = directory.clone();
    for part in below.components() {
        path.push(part);
        if is_link(&path) {
            return remove_link(&path);
        }
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(());
        }
    }
    if !is_real_path(&file.target, root) {
        return Ok(());
    }
    let entries =
        std::fs::read_dir(&file.target).map_err(|source| io_error("list", &file.target, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("list", &file.target, source))?;
        if std::fs::read_link(entry.path()).is_ok_and(|to| to.starts_with(&file.source)) {
            return Err(Error::Copy {
                path: file.target.clone(),
                reason: format!(
                    "`{}` copies here, and this folder still holds the links of an earlier \
                     `link-children` row; delete the folder, and the next run copies it",
                    file.at
                ),
            });
        }
    }
    Ok(())
}

/// What a run does with the copy for `file`.
pub fn copy_state(file: &storage_files::StorageFile, storage: &Storage) -> Result<State, Error> {
    storage_files::state(file, &storage.refusals).map_err(|reason| Error::Copy {
        path: file.source.clone(),
        reason,
    })
}

pub fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// Whether `path` and each folder between it and `base` is a real folder, not a link.
pub fn is_real_path(path: &Path, base: &Path) -> bool {
    path.ancestors()
        .take_while(|ancestor| ancestor.starts_with(base))
        .all(|ancestor| std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| metadata.is_dir()))
}

pub fn remove_link(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("remove", path, error)),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::PathBuf;

    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        home: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let home = directory.path().canonicalize().expect("canonical");
            let root = home.join(".strands/box/storage/p/default");
            std::fs::create_dir_all(root.join("config")).expect("storage");
            Self {
                _directory: directory,
                home,
                root,
            }
        }

        fn write(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.home.join(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
            std::fs::write(&path, text).expect("a file");
            path
        }

        fn read(&self, relative: &str) -> String {
            std::fs::read_to_string(self.root.join(relative)).expect("a copy")
        }

        fn row(&self, source: &str, target: &str, sync: bool) -> StorageFile {
            StorageFile {
                source: self.home.join(source),
                target: self.root.join(target),
                relative: target.into(),
                optional: true,
                at: "storage.files[0]".into(),
                edit: None,
                sync,
                exclude: Vec::new(),
            }
        }

        fn run(&self, file: &StorageFile) -> Copied {
            let run = self.home.join(".strands/box/r/r");
            std::fs::create_dir_all(&run).expect("a run folder");
            copy_files(&self.storage(file), &run, &self.home, &self.home).expect("the copies")
        }

        fn storage(&self, file: &StorageFile) -> Storage {
            Storage {
                root: self.root.clone(),
                directories: vec![self.root.join("config")],
                tool_states: Vec::new(),
                launcher_caches: Vec::new(),
                files: vec![file.clone()],
                skipped: Vec::new(),
                links: Vec::new(),
                hooks: Vec::new(),
                hook_scripts: Vec::new(),
                refusals: Refusals {
                    home: self.home.clone(),
                    roots: vec![
                        (self.home.join("work/app"), "the workspace".into()),
                        (self.home.join(".strands/box"), "the box home".into()),
                    ],
                    shipped: None,
                    protected: Vec::new(),
                },
            }
        }
    }

    #[test]
    fn only_selected_present_values_that_differ_produce_an_import_warning() {
        use crate::mcp::Format;
        use crate::storage_edit::Edit;
        use serde_json::json;

        for kind in [Format::Json, Format::Toml] {
            let encode = |value: &serde_json::Value| match kind {
                Format::Json => serde_json::to_string_pretty(value).expect("JSON"),
                Format::Toml => toml::to_string(value).expect("TOML"),
            };
            let fixture = Fixture::new();
            let mut file = fixture.row("settings", "config/settings", false);
            file.edit = Some(Edit {
                kind,
                keep: Some(vec![vec!["model".into()], vec!["theme".into()]]),
                set: Vec::new(),
                fill: true,
                warn_if_different: vec![vec!["model".into()]],
            });
            let source = json!({"model": "host-private-model", "theme": "light"});
            fixture.write("settings", &encode(&source));
            assert!(fixture.run(&file).import_warnings.is_empty(), "first copy");
            for (saved, source, warns) in [
                (
                    json!({"model": "saved-private-model", "theme": "dark"}),
                    source.clone(),
                    true,
                ),
                (
                    json!({"model": "host-private-model", "theme": "dark"}),
                    source.clone(),
                    false,
                ),
                (json!({"theme": "dark"}), source.clone(), false),
                (
                    json!({"model": false, "theme": "dark"}),
                    source.clone(),
                    true,
                ),
                (source.clone(), json!({"theme": "dark"}), false),
                (source.clone(), json!({"model": false}), true),
            ] {
                std::fs::write(&file.target, encode(&saved)).expect("saved settings");
                fixture.write("settings", &encode(&source));
                let copied = fixture.run(&file);
                assert_eq!(copied.import_warnings.len(), usize::from(warns));
                if warns {
                    assert_eq!(
                        copied.import_warnings,
                        [
                            "Saved settings in \"~/.strands/box/storage/p/default/config/settings\" \
                             differ from \"~/settings\" at model; kept the saved values. \
                             If intentional, no action is needed."
                        ]
                    );
                    assert_eq!(fixture.read("config/settings"), encode(&saved));
                }
            }
            if kind == Format::Toml {
                std::fs::write(&file.target, "model = inf\n").unwrap();
                fixture.write("settings", "model = -inf\n");
                assert_eq!(fixture.run(&file).import_warnings.len(), 1);
                assert_eq!(fixture.read("config/settings"), "model = inf\n");
            }
            fixture.write("settings", &encode(&source));
            let saved = encode(&json!({"model": "saved-private-model", "theme": "dark"}));
            std::fs::write(&file.target, &saved).expect("saved settings");
            file.edit.as_mut().unwrap().warn_if_different =
                vec![vec!["model".into()], vec!["theme".into()]];
            let copied = fixture.run(&file);
            assert_eq!(copied.import_warnings.len(), 1);
            assert!(copied.import_warnings[0].contains("at model, theme;"));
            file.edit.as_mut().unwrap().warn_if_different.clear();
            assert!(
                fixture.run(&file).import_warnings.is_empty(),
                "no selection"
            );
            for path in [vec!["theme".into()], vec!["nested".into(), "choice".into()]] {
                file.edit.as_mut().unwrap().keep = Some(vec![path.clone()]);
                file.edit.as_mut().unwrap().warn_if_different = vec![path.clone()];
                std::fs::write(
                    &file.target,
                    encode(&json!({"theme": "dark", "nested": {"choice": false}})),
                )
                .unwrap();
                fixture.write(
                    "settings",
                    &encode(&json!({"theme": "light", "nested": {"choice": true}})),
                );
                let copied = fixture.run(&file);
                assert_eq!(copied.import_warnings.len(), 1);
                assert!(
                    copied.import_warnings[0]
                        .contains(&format!("at {};", crate::storage_edit::shown(&path)))
                );
            }
            fixture.write("settings", &encode(&source));
            std::fs::write(&file.target, &saved).unwrap();
            file.edit.as_mut().unwrap().keep = Some(vec![vec!["model".into()]]);
            file.edit.as_mut().unwrap().warn_if_different = vec![vec!["model".into()]];
            file.edit.as_mut().unwrap().fill = false;
            assert!(fixture.run(&file).import_warnings.is_empty(), "copy once");
            file.edit.as_mut().unwrap().fill = true;
            std::fs::remove_file(&file.source).expect("remove source");
            assert!(
                fixture.run(&file).import_warnings.is_empty(),
                "absent source"
            );
            fixture.write("settings", &encode(&source));
            let private = fixture.write("private-settings", &saved);
            std::fs::remove_file(&file.target).expect("remove copy");
            for hard in [false, true] {
                if hard {
                    std::fs::hard_link(&private, &file.target).expect("hard link");
                } else {
                    symlink(&private, &file.target).expect("symbolic link");
                }
                let copied = fixture.run(&file);
                assert!(copied.import_warnings.is_empty(), "unsafe copy");
                assert_eq!(copied.not_copied.len(), 1);
                assert_eq!(std::fs::read_to_string(&private).unwrap(), saved);
                std::fs::remove_file(&file.target).expect("remove link");
            }
        }
    }

    #[test]
    fn a_file_follows_the_host_unless_only_the_box_changed_it() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        assert!(fixture.run(&file).synced.is_empty(), "a first copy");
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 1");
        assert!(fixture.run(&file).synced.is_empty(), "nothing changed");

        std::fs::write(&file.target, "box edit").expect("a box edit");
        assert!(fixture.run(&file).synced.is_empty());
        assert_eq!(
            fixture.read("config/CLAUDE.md"),
            "box edit",
            "the box's edit stays"
        );

        fixture.write(".claude/CLAUDE.md", "host 2");
        assert_eq!(
            fixture.run(&file).synced,
            [
                "replaced the box's edit of config/CLAUDE.md with the host's version from \
              ~/.claude/CLAUDE.md"
            ]
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2", "the host wins");

        fixture.write(".claude/CLAUDE.md", "host 3");
        assert_eq!(
            fixture.run(&file).synced,
            ["updated config/CLAUDE.md from ~/.claude/CLAUDE.md"]
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 3");
        assert!(fixture.run(&file).synced.is_empty());
    }

    fn planned(fixture: &Fixture, file: &StorageFile) -> storage_files::Plan {
        match copy_state(file, &fixture.storage(file)).expect("a state") {
            State::WillCopy(plan) => plan,
            other => panic!("a copy, not {other:?}"),
        }
    }

    #[test]
    fn a_first_copy_that_the_host_changes_is_planned_and_made_again() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db 1");
        let file = fixture.row(".kiro/memories", "config/memories", false);
        let storage = fixture.storage(&file);
        let staging = fixture.home.join(".strands/box/r/r/copy-0");
        std::fs::create_dir_all(staging.parent().expect("a parent")).expect("a run folder");
        let mut tries = 0;
        let outcome = first_copy(&file, planned(&fixture, &file), &storage, |plan| {
            tries += 1;
            if tries == 1 {
                std::fs::write(&database, "db 1, and a page").expect("a write");
            }
            storage_files::copy(&file, plan, &staging, &fixture.home)
        })
        .expect("a copy");
        assert!(matches!(outcome, FirstCopy::Made(..)));
        assert_eq!(tries, 2);
        assert_eq!(
            fixture.read("config/memories/memories.db"),
            "db 1, and a page"
        );
    }

    #[test]
    fn a_first_copy_that_changes_on_every_try_stops_the_run_with_no_copy() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db");
        let file = fixture.row(".kiro/memories", "config/memories", false);
        let storage = fixture.storage(&file);
        let staging = fixture.home.join(".strands/box/r/r/copy-0");
        std::fs::create_dir_all(staging.parent().expect("a parent")).expect("a run folder");
        let mut tries = 0;
        let outcome = first_copy(&file, planned(&fixture, &file), &storage, |plan| {
            tries += 1;
            std::fs::write(&database, "db, and a page".repeat(tries)).expect("a write");
            storage_files::copy(&file, plan, &staging, &fixture.home)
        });
        let Err(error) = outcome else {
            panic!("the run stops");
        };
        assert!(
            matches!(&error, Error::Unsettled { path, file: changed, tries: 3 }
                if *path == file.source && *changed == database),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("stop the program that writes it"),
            "{error}"
        );
        assert_eq!(tries, COPY_TRIES as usize);
        assert!(!file.target.exists(), "nothing reaches storage");
        assert!(!staging.exists(), "the staging folder is removed");
        assert!(
            matches!(copy_state(&file, &storage), Ok(State::WillCopy(_))),
            "the next run copies it"
        );
    }

    #[test]
    fn a_first_copy_whose_source_goes_between_tries_hands_back_the_new_state() {
        let fixture = Fixture::new();
        let database = fixture.write(".kiro/memories/memories.db", "db");
        let file = fixture.row(".kiro/memories", "config/memories", false);
        let storage = fixture.storage(&file);
        let staging = fixture.home.join(".strands/box/r/r/copy-0");
        std::fs::create_dir_all(staging.parent().expect("a parent")).expect("a run folder");
        let outcome = first_copy(&file, planned(&fixture, &file), &storage, |plan| {
            std::fs::remove_dir_all(database.parent().expect("a folder")).expect("remove");
            storage_files::copy(&file, plan, &staging, &fixture.home)
        })
        .expect("no error");
        assert!(matches!(outcome, FirstCopy::Now(State::Absent)));
    }

    #[test]
    fn a_row_without_sync_keeps_the_first_copy() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", false);
        fixture.run(&file);
        fixture.write(".claude/CLAUDE.md", "host 2");
        assert!(fixture.run(&file).synced.is_empty());
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 1");
        assert!(
            !fixture.root.join(RECORD).exists(),
            "no record without a sync row"
        );
    }

    #[test]
    fn a_folder_follows_the_host_file_by_file_and_keeps_what_only_the_box_has() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a.md", "a 1");
        fixture.write(".claude/skills/b/c.md", "c 1");
        let file = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&file);

        std::fs::write(fixture.root.join("config/skills/a.md"), "a, box").expect("an edit");
        std::fs::write(fixture.root.join("config/skills/own.md"), "own").expect("a box file");
        fixture.write(".claude/skills/b/c.md", "c 2");
        fixture.write(".claude/skills/d/e.md", "e 1");
        assert_eq!(
            fixture.run(&file).synced,
            ["updated config/skills/b/c.md, config/skills/d/e.md from ~/.claude/skills"]
        );
        assert_eq!(fixture.read("config/skills/a.md"), "a, box");
        assert_eq!(fixture.read("config/skills/own.md"), "own");
        assert_eq!(fixture.read("config/skills/b/c.md"), "c 2");
        assert_eq!(fixture.read("config/skills/d/e.md"), "e 1");

        std::fs::remove_file(fixture.home.join(".claude/skills/a.md")).expect("a host delete");
        assert_eq!(
            fixture.run(&file).synced,
            ["kept config/skills/a.md, which ~/.claude/skills no longer has"]
        );
        assert_eq!(fixture.read("config/skills/a.md"), "a, box");
        assert!(fixture.run(&file).synced.is_empty(), "said once");

        fixture.write(".claude/skills/a.md", "a 2");
        assert_eq!(
            fixture.run(&file).synced,
            [
                "replaced the box's edit of config/skills/a.md with the host's version from \
              ~/.claude/skills"
            ]
        );
        assert_eq!(fixture.read("config/skills/a.md"), "a 2");
    }

    #[test]
    fn a_synced_folder_never_brings_in_what_exclude_names() {
        let fixture = Fixture::new();
        fixture.write(".kiro/powers/installed/a/POWER.md", "a 1");
        fixture.write(".kiro/powers/installed/a/mcp.json", "{\"key\": 1}");
        let file = StorageFile {
            exclude: vec!["mcp.json".into()],
            ..fixture.row(".kiro/powers/installed", "config/powers", true)
        };
        let left_out = |copied: &Copied| -> Vec<String> {
            copied
                .not_copied
                .iter()
                .map(|(path, why)| format!("{path}: {why}"))
                .collect()
        };
        let first = fixture.run(&file);
        assert_eq!(
            left_out(&first),
            ["~/.kiro/powers/installed/a/mcp.json: the row's `exclude` names it"]
        );
        assert_eq!(fixture.read("config/powers/a/POWER.md"), "a 1");
        assert!(!fixture.root.join("config/powers/a/mcp.json").exists());

        fixture.write(".kiro/powers/installed/a/mcp.json", "{\"key\": 2}");
        fixture.write(".kiro/powers/installed/b/mcp.json", "{}");
        fixture.write(".kiro/powers/installed/b/POWER.md", "b 1");
        let second = fixture.run(&file);
        assert_eq!(
            second.synced,
            ["updated config/powers/b/POWER.md from ~/.kiro/powers/installed"]
        );
        assert_eq!(
            left_out(&second),
            [
                "~/.kiro/powers/installed/a/mcp.json: the row's `exclude` names it",
                "~/.kiro/powers/installed/b/mcp.json: the row's `exclude` names it",
            ]
        );
        for path in ["config/powers/a/mcp.json", "config/powers/b/mcp.json"] {
            assert!(!fixture.root.join(path).exists(), "{path}");
        }
        let record = load(&fixture.root).expect("a record");
        let row = record.row("config/powers").expect("the row's record");
        assert_eq!(
            row.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a/POWER.md", "b/POWER.md"]
        );
    }

    #[test]
    fn exclude_added_after_a_first_copy_reports_the_copy_it_now_names_and_not_as_gone() {
        let fixture = Fixture::new();
        fixture.write(".kiro/powers/installed/a/POWER.md", "a 1");
        fixture.write(".kiro/powers/installed/a/mcp.json", "{\"key\": 1}");
        let row = fixture.row(".kiro/powers/installed", "config/powers", true);
        fixture.run(&row);
        assert_eq!(fixture.read("config/powers/a/mcp.json"), "{\"key\": 1}");
        let file = StorageFile {
            exclude: vec!["MCP.json".into()],
            ..row
        };
        assert_eq!(
            fixture.run(&file).synced,
            [
                "kept config/powers/a/mcp.json from an earlier copy, which the row's `exclude` now \
                 names; delete it in storage to take it out of the box"
            ]
        );
        assert_eq!(fixture.read("config/powers/a/mcp.json"), "{\"key\": 1}");
        // Each run names the copy again, until the operator deletes it in storage.
        assert_eq!(
            fixture.run(&file).synced,
            [
                "kept config/powers/a/mcp.json from an earlier copy, which the row's `exclude` now \
                 names; delete it in storage to take it out of the box"
            ]
        );
        std::fs::remove_file(fixture.root.join("config/powers/a/mcp.json")).expect("a delete");
        assert!(fixture.run(&file).synced.is_empty());
        let record = load(&fixture.root).expect("a record");
        let recorded = record.row("config/powers").expect("the row's record");
        assert_eq!(
            recorded.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a/POWER.md"]
        );
    }

    #[test]
    fn a_link_the_box_puts_in_storage_is_replaced_or_refused_and_never_followed() {
        let fixture = Fixture::new();
        let outside = fixture.write("outside/secret.md", "secret");
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        std::fs::remove_file(&file.target).expect("remove");
        symlink(&outside, &file.target).expect("a planted link");
        fixture.write(".claude/CLAUDE.md", "host 2");
        assert_eq!(
            fixture.run(&file).synced,
            [
                "replaced the box's edit of config/CLAUDE.md with the host's version from \
              ~/.claude/CLAUDE.md"
            ]
        );
        assert!(
            !std::fs::symlink_metadata(&file.target)
                .expect("a copy")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2");
        assert_eq!(std::fs::read_to_string(&outside).expect("read"), "secret");

        fixture.write(".claude/skills/b/c.md", "c 1");
        let folder = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&folder);
        std::fs::remove_dir_all(fixture.root.join("config/skills/b")).expect("remove");
        symlink(
            fixture.home.join("outside"),
            fixture.root.join("config/skills/b"),
        )
        .expect("a planted folder link");
        fixture.write(".claude/skills/b/secret.md", "c 2");
        let copied = fixture.run(&folder);
        assert!(
            !copied.synced.is_empty()
                && copied
                    .synced
                    .iter()
                    .all(|line| line.starts_with("did not update")),
            "{:?}",
            copied.synced
        );
        assert_eq!(std::fs::read_to_string(&outside).expect("read"), "secret");

        std::fs::remove_dir_all(fixture.root.join("config/skills")).expect("remove");
        symlink(
            fixture.home.join("outside"),
            fixture.root.join("config/skills"),
        )
        .expect("a planted top link");
        assert_eq!(
            fixture.run(&folder).synced,
            [
                "did not update config/skills: the copy in storage is a link or not a folder; box \
              writes through no link"
            ]
        );
        assert_eq!(std::fs::read_to_string(&outside).expect("read"), "secret");
    }

    #[test]
    fn a_copy_made_before_the_record_is_kept_until_the_host_changes() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        fixture.write(".claude/rules/same.md", "same");
        fixture.run(&fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", false));
        fixture.run(&fixture.row(".claude/rules", "config/rules", false));
        std::fs::write(fixture.root.join("config/CLAUDE.md"), "box edit").expect("an edit");

        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        assert_eq!(
            fixture.run(&file).synced,
            [
                "kept the box's copy of config/CLAUDE.md, which differs from ~/.claude/CLAUDE.md; a \
              later edit on the host replaces it"
            ]
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "box edit");
        assert!(fixture.run(&file).synced.is_empty(), "said once");
        assert!(
            fixture
                .run(&fixture.row(".claude/rules", "config/rules", true))
                .synced
                .is_empty(),
            "a copy that matches the host is recorded without a line"
        );

        fixture.write(".claude/CLAUDE.md", "host 2");
        fixture.run(&file);
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2");
    }

    #[test]
    fn an_unreadable_or_linked_record_reads_as_none() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        assert_ne!(load(&fixture.root).expect("a record"), Record::default());
        std::fs::write(&file.target, "box edit").expect("an edit");

        std::fs::write(fixture.root.join(RECORD), "not json").expect("a broken record");
        assert_eq!(load(&fixture.root).expect("a record"), Record::default());
        fixture.write(".claude/CLAUDE.md", "host 2");
        fixture.run(&file);
        assert_eq!(
            fixture.read("config/CLAUDE.md"),
            "box edit",
            "with no record, the box's copy is kept"
        );

        let elsewhere = fixture.write("outside/copies.json", "{}");
        std::fs::remove_file(fixture.root.join(RECORD)).expect("remove");
        symlink(&elsewhere, fixture.root.join(RECORD)).expect("a linked record");
        assert_eq!(load(&fixture.root).expect("a record"), Record::default());
        fixture.run(&file);
        assert_eq!(std::fs::read_to_string(&elsewhere).expect("read"), "{}");
        assert!(
            !std::fs::symlink_metadata(fixture.root.join(RECORD))
                .expect("a record")
                .file_type()
                .is_symlink(),
            "box replaces a linked record and writes nothing through it"
        );
    }

    #[test]
    fn show_says_what_a_run_would_do_and_changes_nothing() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        let refusals = Refusals {
            home: fixture.home.clone(),
            ..Refusals::default()
        };
        let record = load(&fixture.root).expect("a record");
        let preview = |record: &Record| {
            update(
                &file,
                record.row(&file.relative),
                &refusals,
                &fixture.root,
                false,
            )
            .expect("an update")
            .summary()
        };
        assert_eq!(preview(&record), "in sync with the host");
        fixture.write(".claude/CLAUDE.md", "host 2");
        assert_eq!(
            preview(&record),
            "will update config/CLAUDE.md from the host"
        );
        std::fs::write(&file.target, "box edit").expect("an edit");
        assert_eq!(
            preview(&record),
            "the host's edit will replace the box's edit of config/CLAUDE.md"
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "box edit");
        assert_eq!(load(&fixture.root).expect("a record"), record);
    }

    #[test]
    fn a_copy_the_box_cannot_read_or_reach_is_reported_and_stops_no_run() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        std::fs::set_permissions(&file.target, std::fs::Permissions::from_mode(0o000))
            .expect("an unreadable copy");
        assert!(
            fixture.run(&file).synced.is_empty(),
            "an unreadable copy is a box edit"
        );
        fixture.write(".claude/CLAUDE.md", "host 2");
        assert_eq!(
            fixture.run(&file).synced,
            [
                "replaced the box's edit of config/CLAUDE.md with the host's version from \
              ~/.claude/CLAUDE.md"
            ]
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2");

        fixture.write(".claude/skills/b/c.md", "c 1");
        let folder = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&folder);
        let closed = fixture.root.join("config/skills/b");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
            .expect("a closed folder");
        fixture.write(".claude/skills/b/c.md", "c 2");
        let lines = fixture.run(&folder).synced;
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
            .expect("an open folder");
        assert_eq!(
            lines,
            [
                "did not update config/skills/b/c.md: a folder on the way in storage is a link or \
              not a folder; box writes through no link"
            ]
        );
    }

    #[test]
    fn a_hard_linked_copy_or_record_is_never_written_through() {
        let fixture = Fixture::new();
        let outside = fixture.write("outside/notes.md", "host 1");
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        std::fs::remove_file(&file.target).expect("remove");
        std::fs::hard_link(&outside, &file.target).expect("a hard link");
        let refusals = Refusals {
            home: fixture.home.clone(),
            ..Refusals::default()
        };
        let record = load(&fixture.root).expect("a record");
        assert_eq!(
            update(
                &file,
                record.row(&file.relative),
                &refusals,
                &fixture.root,
                false
            )
            .expect("an update")
            .kept,
            ["config/CLAUDE.md"],
            "a hard-linked copy is a box edit, even with the host's text"
        );
        fixture.write(".claude/CLAUDE.md", "host 2");
        fixture.run(&file);
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2");
        assert_eq!(std::fs::read_to_string(&outside).expect("read"), "host 1");

        let record = fixture.root.join(RECORD);
        let elsewhere = fixture.home.join("outside/record.json");
        std::fs::rename(&record, &elsewhere).expect("move the record");
        std::fs::hard_link(&elsewhere, &record).expect("a hard-linked record");
        assert_eq!(load(&fixture.root).expect("a record"), Record::default());
    }

    #[test]
    fn a_host_file_that_comes_back_replaces_the_boxs_file() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        fixture.run(&file);
        std::fs::remove_file(fixture.home.join(".claude/CLAUDE.md")).expect("a host delete");
        fixture.run(&file);
        std::fs::write(&file.target, "box edit").expect("an edit");
        fixture.write(".claude/CLAUDE.md", "host 2");
        assert_eq!(
            fixture.run(&file).synced,
            [
                "replaced the box's edit of config/CLAUDE.md with the host's version from \
              ~/.claude/CLAUDE.md"
            ]
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 2");

        fixture.write(".claude/skills/a.md", "a");
        let folder = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&folder);
        std::fs::write(fixture.root.join("config/skills/new.md"), "box").expect("a box file");
        fixture.write(".claude/skills/new.md", "host");
        fixture.run(&folder);
        assert_eq!(fixture.read("config/skills/new.md"), "host");
    }

    #[test]
    fn a_host_folder_and_a_copied_file_do_not_mix() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills", "a file");
        let folder = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&folder);
        std::fs::remove_file(fixture.home.join(".claude/skills")).expect("remove");
        fixture.write(".claude/skills/a.md", "a");
        assert_eq!(
            fixture.run(&folder).synced,
            [
                "did not update config/skills: the host has a folder and storage has a file; delete \
              the copy in storage to take a fresh one"
            ]
        );
        assert_eq!(fixture.read("config/skills"), "a file");
    }

    #[test]
    fn a_copy_of_another_size_is_not_read() {
        let fixture = Fixture::new();
        fixture.write(".strands/box/storage/p/default/config/big.md", "0123456789");
        let path = vec!["config".to_string(), "big.md".to_string()];
        assert_eq!(
            read_copy(&mut Folders::new(&fixture.root), &path, &[3]).expect("a read"),
            Copy::Other
        );
        assert_eq!(
            read_copy(&mut Folders::new(&fixture.root), &path, &[10]).expect("a read"),
            Copy::Same(entry(b"0123456789"))
        );
    }

    #[test]
    fn a_host_file_replaced_after_the_plan_is_refused() {
        let fixture = Fixture::new();
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        let refusals = Refusals {
            home: fixture.home.clone(),
            ..Refusals::default()
        };
        let tree = host_tree(&file, &refusals)
            .expect("a tree")
            .expect("a host file");
        let source = fixture.home.join(".claude/CLAUDE.md");
        let swapped = fixture.write(".claude/swapped.md", "swapped");
        std::fs::rename(&swapped, &source).expect("a swapped file");
        let error = tree
            .files()
            .next()
            .expect("a file")
            .read()
            .expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("the file changed while box copied it"),
            "{error}"
        );
        std::fs::remove_file(&source).expect("remove");
        symlink(fixture.write("outside/secret.md", "secret"), &source).expect("a swapped link");
        let error = tree
            .files()
            .next()
            .expect("a file")
            .read()
            .expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("the file changed while box copied it"),
            "{error}"
        );
    }

    #[test]
    fn a_second_run_waits_for_the_lock_and_then_refuses() {
        let fixture = Fixture::new();
        let held = lock(&fixture.root, Duration::ZERO).expect("the lock");
        let error = lock(&fixture.root, Duration::from_millis(200)).expect_err("a busy lock");
        assert!(
            error
                .to_string()
                .contains("another run of this profile is updating its copies"),
            "{error}"
        );
        fixture.write(".claude/CLAUDE.md", "host 1");
        let file = fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true);
        let run = fixture.home.join(".strands/box/r/r");
        std::fs::create_dir_all(&run).expect("a run folder");
        let error = copy_files_waiting(
            &fixture.storage(&file),
            &run,
            &fixture.home,
            &fixture.home,
            Duration::ZERO,
        )
        .expect_err("a run with a sync row takes the lock");
        assert!(
            error
                .to_string()
                .contains("another run of this profile is updating its copies"),
            "{error}"
        );
        held.unlock().expect("the lock, released");
        lock(&fixture.root, Duration::ZERO).expect("the lock, once free");
    }

    #[test]
    fn a_host_problem_on_a_copy_in_storage_is_reported_and_stops_no_run() {
        let fixture = Fixture::new();
        fixture.write(".claude/skills/a/open.md", "open 1");
        let private = fixture.write(".claude/skills/a/private.md", "private");
        let folder = fixture.row(".claude/skills", "config/skills", true);
        fixture.run(&folder);
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000))
            .expect("an unreadable host file");
        fixture.write(".claude/skills/a/open.md", "open 2");
        let lines = fixture.run(&folder).synced;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600))
            .expect("a readable host file");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(
            lines[0],
            "updated config/skills/a/open.md from ~/.claude/skills"
        );
        assert!(
            lines[1].starts_with("did not update config/skills/a/private.md: "),
            "{lines:?}"
        );
        assert_eq!(fixture.read("config/skills/a/private.md"), "private");

        let skills = fixture.home.join(".claude/skills");
        std::fs::create_dir_all(fixture.home.join("work/app")).expect("a workspace");
        std::fs::rename(&skills, fixture.home.join("work/app/skills")).expect("move the skills");
        symlink(fixture.home.join("work/app/skills"), &skills).expect("a link into the workspace");
        let lines = fixture.run(&folder).synced;
        assert!(
            lines.len() == 1
                && lines[0].starts_with("did not update config/skills: ")
                && lines[0].contains("the workspace"),
            "{lines:?}"
        );
        assert_eq!(fixture.read("config/skills/a/open.md"), "open 2");

        fixture.write(".claude/CLAUDE.md", "host 1");
        let required = StorageFile {
            optional: false,
            ..fixture.row(".claude/CLAUDE.md", "config/CLAUDE.md", true)
        };
        fixture.run(&required);
        std::fs::remove_file(fixture.home.join(".claude/CLAUDE.md")).expect("a host delete");
        let lines = fixture.run(&required).synced;
        assert!(
            lines.len() == 1 && lines[0].starts_with("did not update config/CLAUDE.md: "),
            "{lines:?}"
        );
        assert_eq!(fixture.read("config/CLAUDE.md"), "host 1");
    }

    #[test]
    fn a_run_holds_only_the_folders_above_the_file_it_reaches() {
        let fixture = Fixture::new();
        let mut folders = Folders::new(&fixture.root);
        for index in 0..300 {
            let path = vec![
                "config".to_string(),
                "skills".to_string(),
                format!("skill-{index}"),
            ];
            assert!(matches!(
                folders.reach(&path, true).expect("a reach"),
                Reach::Open(_)
            ));
            assert!(
                folders.open.len() <= path.len() + 1,
                "{} folders open",
                folders.open.len()
            );
        }
        assert!(fixture.root.join("config/skills/skill-299").is_dir());
    }
}
