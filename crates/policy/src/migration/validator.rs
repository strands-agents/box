//! Run the installed legacy engine against bounded private inputs.

use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use dogwood_local_engine::PolicyEntry;
use serde::{Deserialize, Serialize};

use super::storage;
use crate::PolicyError;

const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const MAX_ERROR: usize = 64 * 1024;
const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    protocol: u32,
    engine_version: String,
    language_version: String,
    pub(super) policies: Vec<PolicyEntry>,
    pub(super) next_id: u64,
    pub(super) action_schema: String,
    pub(super) last_ts: i64,
    pub(super) offset: u64,
    pub(super) engine_sha256: String,
}

#[derive(Serialize)]
struct CompileInput<'a> {
    source: &'a str,
    event_schema: &'a str,
    action_schema: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Compiled {
    protocol: u32,
    engine_version: String,
    language_version: String,
    statements: Vec<String>,
}

fn fail(error: impl std::fmt::Display) -> PolicyError {
    PolicyError::Evaluation(format!("Dogwood legacy validator refused: {error}"))
}

fn versions(protocol: u32, engine: &str, language: &str) -> Result<(), PolicyError> {
    if protocol != 1 || engine != "1.0.0" || language != "1.0.0" {
        return Err(fail("installed helper protocol or pinned versions differ"));
    }
    Ok(())
}

pub(super) fn describe(executable: &File) -> Result<String, PolicyError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Description {
        protocol: u32,
        engine_version: String,
        language_version: String,
    }
    let bytes = invoke(executable, "describe", Input::Empty)?;
    let description: Description = serde_json::from_slice(&bytes).map_err(fail)?;
    versions(
        description.protocol,
        &description.engine_version,
        &description.language_version,
    )?;
    executable_hash(executable)
}

pub(super) fn compile(
    executable: &File,
    source: &str,
    event_schema: &str,
    action_schema: &str,
) -> Result<Vec<String>, PolicyError> {
    let request = serde_json::to_vec(&CompileInput {
        source,
        event_schema,
        action_schema,
    })
    .map_err(fail)?;
    if request.len() > MAX_MESSAGE {
        return Err(fail("original policy and schema input exceeds 8 MiB"));
    }
    let bytes = invoke(executable, "compile", Input::Message(request))?;
    let compiled: Compiled = serde_json::from_slice(&bytes).map_err(fail)?;
    versions(
        compiled.protocol,
        &compiled.engine_version,
        &compiled.language_version,
    )?;
    Ok(compiled.statements)
}

pub(super) fn recover(
    executable: &File,
    scratch: &File,
    checkpoint: bool,
) -> Result<State, PolicyError> {
    let mode = if checkpoint { "checkpoint" } else { "validate" };
    let bytes = invoke(executable, mode, Input::Database(scratch))?;
    let state: State = serde_json::from_slice(&bytes).map_err(fail)?;
    versions(
        state.protocol,
        &state.engine_version,
        &state.language_version,
    )?;
    Ok(state)
}

enum Input<'a> {
    Empty,
    Message(Vec<u8>),
    Database(&'a File),
}

fn executable_hash(executable: &File) -> Result<String, PolicyError> {
    let metadata = executable.metadata().map_err(fail)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.len() == 0 {
        return Err(fail("helper must be an opened executable regular file"));
    }
    storage::image_hash(executable, MAX_EXECUTABLE)
        .map(|(hash, _)| hash)
        .map_err(fail)
}

fn bounded(mut source: impl Read, bound: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take((bound + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper output exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn invoke(executable: &File, mode: &str, input: Input<'_>) -> Result<Vec<u8>, PolicyError> {
    let before = executable_hash(executable)?;
    // The descriptor remains owned until the child has exited.
    let held = executable.try_clone().map_err(fail)?;
    #[cfg(target_os = "linux")]
    let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    #[cfg(target_os = "macos")]
    let copied = macos::Executable::copy(&held, &before)?;
    #[cfg(target_os = "macos")]
    let path = copied.path();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(fail(
        "legacy validation is supported only on Linux and macOS",
    ));

    let mut command = Command::new(path);
    command
        .arg(mode)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let message = match input {
        Input::Empty => {
            command.stdin(Stdio::null());
            None
        }
        Input::Message(bytes) => {
            command.stdin(Stdio::piped());
            Some(bytes)
        }
        Input::Database(file) => {
            if !file.metadata().map_err(fail)?.is_file() {
                return Err(fail(
                    "helper database input must be an opened private regular file",
                ));
            }
            command.stdin(Stdio::from(file.try_clone().map_err(fail)?));
            None
        }
    };
    let mut child = command.spawn().map_err(fail)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("helper stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| fail("helper stderr unavailable"))?;
    let stdin = child.stdin.take();
    let result = std::thread::scope(|scope| {
        let output = scope.spawn(|| bounded(stdout, MAX_MESSAGE));
        let errors = scope.spawn(|| bounded(stderr, MAX_ERROR));
        let writer = scope.spawn(move || -> Result<(), std::io::Error> {
            if let (Some(mut stream), Some(bytes)) = (stdin, message) {
                stream.write_all(&bytes)?;
            }
            Ok(())
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(fail("helper exceeded the 120-second execution limit"));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(fail(error));
                }
            }
        };
        let output = output
            .join()
            .map_err(|_| fail("helper output reader panicked"))?
            .map_err(fail)?;
        let errors = errors
            .join()
            .map_err(|_| fail("helper error reader panicked"))?
            .map_err(fail)?;
        let written = writer
            .join()
            .map_err(|_| fail("helper input writer panicked"))?;
        let status = status?;
        if !status.success() {
            return Err(fail(format!(
                "{mode} failed ({status}): {}",
                String::from_utf8_lossy(&errors)
            )));
        }
        written.map_err(fail)?;
        Ok(output)
    });
    if executable_hash(executable)? != before {
        return Err(fail("installed helper changed while it ran"));
    }
    result
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };
    static SERIAL: AtomicU64 = AtomicU64::new(0);

    pub(super) struct Executable {
        directory: PathBuf,
        path: PathBuf,
    }
    impl Executable {
        pub(super) fn copy(source: &File, expected: &str) -> Result<Self, PolicyError> {
            let directory = loop {
                let name = format!(
                    "strands-box-legacy-{}-{}",
                    std::process::id(),
                    SERIAL.fetch_add(1, Ordering::Relaxed)
                );
                let path = std::env::temp_dir().join(name);
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => break path,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(fail(error)),
                }
            };
            let result = Self {
                path: directory.join("validator"),
                directory,
            };
            let target = OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .mode(0o600)
                .open(&result.path)
                .map_err(fail)?;
            let limits = storage::MigrationLimits {
                max_image_bytes: MAX_EXECUTABLE,
                ..Default::default()
            };
            storage::copy_image(source, &target, &limits).map_err(fail)?;
            target
                .set_permissions(fs::Permissions::from_mode(0o500))
                .map_err(fail)?;
            target.sync_all().map_err(fail)?;
            if executable_hash(&target)? != expected {
                return Err(fail("copied helper differs from its held identity"));
            }
            drop(target);
            Ok(result)
        }
        pub(super) fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for Executable {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}
