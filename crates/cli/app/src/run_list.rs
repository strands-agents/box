//! Discover saved run IDs without loading profiles or starting workloads.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use nix::{dir::Dir, libc};
use serde::Serialize;

use crate::files::{io_error, metadata_at, open_at, open_directory_below};
use crate::host::box_home_base;
use crate::run::{PROFILE_RECORD, RUNS};
use crate::{Error, OutputFormat};

const PROFILE_LIMIT: usize = 64 * 1024;

#[derive(Serialize)]
struct SavedRun {
    profile: Option<String>,
    updated: Option<DateTime<Utc>>,
    id: String,
}

pub(crate) fn show(
    home: &Path,
    box_home: &Path,
    profile: Option<&str>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<(), Error> {
    let mut runs = read(home, box_home)?;
    if let Some(profile) = profile {
        runs.retain(|run| crate::run::owns(&run.id, run.profile.as_deref(), profile));
    }
    let result = match format {
        OutputFormat::Json => crate::output::json(output, &runs).and_then(|()| writeln!(output)),
        OutputFormat::Text => write_text(output, &runs, profile),
    };
    result.map_err(|source| Error::RunListOutput { source })
}

fn read(home: &Path, box_home: &Path) -> Result<Vec<SavedRun>, Error> {
    if !box_home.is_absolute() {
        return Err(Error::NoHome);
    }
    let directory = match open_directory_below(box_home, box_home_base(home, box_home)) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io_error("list", box_home, source)),
    };
    let path = box_home.join(RUNS);
    let directory = match open_at(&directory, RUNS, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io_error("list", &path, source)),
    };
    let mut entries = Dir::from(
        directory
            .try_clone()
            .map_err(|source| io_error("list", &path, source))?,
    )
    .map_err(|source| io_error("list", &path, source.into()))?;
    let mut runs = Vec::new();
    for entry in entries.iter() {
        let entry = entry.map_err(|source| io_error("list", &path, source.into()))?;
        let Ok(id) = entry.file_name().to_str() else {
            continue;
        };
        if matches!(id, "." | "..") {
            continue;
        }
        let metadata = match metadata_at(&directory, id) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io_error("inspect", &path.join(id), source)),
        };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
            continue;
        }
        let run = open_at(&directory, id, libc::O_RDONLY | libc::O_DIRECTORY, 0).ok();
        runs.push(SavedRun {
            profile: run.as_ref().and_then(read_profile),
            updated: run.as_ref().and_then(read_updated),
            id: id.to_owned(),
        });
    }
    runs.sort_by(|left, right| {
        right
            .updated
            .cmp(&left.updated)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(runs)
}

fn read_updated(directory: &OwnedFd) -> Option<DateTime<Utc>> {
    let metadata = metadata_at(directory, "box.toml").ok()?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let time =
        DateTime::from_timestamp(metadata.st_mtime, metadata.st_mtime_nsec.try_into().ok()?)?;
    (0..=9999).contains(&time.year()).then_some(time)
}

fn read_profile(directory: &OwnedFd) -> Option<String> {
    let file = File::from(
        open_at(
            directory,
            PROFILE_RECORD,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .ok()?,
    );
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > PROFILE_LIMIT as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take((PROFILE_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > PROFILE_LIMIT {
        return None;
    }
    let record = String::from_utf8(bytes).ok()?;
    crate::run::profile_of(&record).map(str::to_owned)
}

fn write_text(output: &mut impl Write, runs: &[SavedRun], profile: Option<&str>) -> io::Result<()> {
    if runs.is_empty() {
        return match profile {
            Some(profile) => writeln!(
                output,
                "No saved runs for profile {}.",
                profile.escape_debug()
            ),
            None => writeln!(output, "No saved runs."),
        };
    }
    writeln!(output, "PROFILE\tUPDATED (UTC)\tBOX ID")?;
    for run in runs {
        writeln!(
            output,
            "{}\t{}\t{}",
            run.profile.as_deref().unwrap_or("unknown").escape_debug(),
            run.updated
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
                .as_deref()
                .unwrap_or("unknown"),
            run.id.escape_debug()
        )?;
    }
    Ok(())
}
