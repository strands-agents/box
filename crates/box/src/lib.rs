//! `strands-box` runs workloads inside a zero-trust box through the command line or library.
//!
//! | Module | Owns |
//! |---|---|
//! | [`command`] | one module per verb, and the argv parser |
//! | [`record`] | what a box *is*, before anything is running |
//! | [`run`] | one box's trusted half, alive for one run |
//! | [`error`] | the typed taxonomy, one variant group per phase |

#![warn(missing_docs, unreachable_pub)]

mod command;
mod error;
mod record;
mod run;
#[cfg(test)]
mod test_support;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use command::cli::{Cli, Command, PolicyCommand};

pub use policy::{Finding, Location, Policy, PolicyCheck, RuleRef};

static STARTED: AtomicBool = AtomicBool::new(false);

/// Optional terminal attachment and host initialization for one run.
#[derive(Default)]
pub struct RunOptions<'a> {
    /// The workload's controlling terminal; `None` inherits the process's standard streams.
    pub terminal: Option<std::fs::File>,
    /// Called after hardening and signal registration, before workload setup; an error aborts the run.
    pub on_ready: Option<Box<dyn FnOnce() -> std::io::Result<()> + 'a>>,
    /// The box ID a new box takes; `None` generates one, a configured box refuses any other ID, and a
    /// malformed ID is refused before `run` uses the process's one attempt.
    pub box_id: Option<String>,
}

/// Run the existing Box command with a configuration.
pub fn run(config: PathBuf, workload: Vec<OsString>, options: RunOptions<'_>) -> ExitCode {
    if let Some(found) = options.box_id.as_deref()
        && !record::config::valid_box_identity(found)
    {
        let error = error::ConfigError::SuppliedIdentity {
            found: found.to_string(),
        };
        eprintln!("strands-box: error: {error}");
        return ExitCode::FAILURE;
    }
    if STARTED.swap(true, Ordering::SeqCst) {
        eprintln!("strands-box: refusing to run: this process already attempted to run a box");
        return ExitCode::FAILURE;
    }

    command::execute(
        Cli {
            command: Command::Run { config, workload },
        },
        options,
    )
}

/// Replace the running box's authored policies with the supplied text.
pub fn reload(sources: &[Policy]) -> Result<(), ReloadRefused> {
    run::hosted::reload(sources).map_err(ReloadRefused)
}

/// A reload that the box refused, or that found no box open in this process.
#[derive(Debug)]
pub struct ReloadRefused(error::BoxError);

impl ReloadRefused {
    /// Whether no box is open for reload in this process.
    pub fn is_not_running(&self) -> bool {
        self.0.is_not_running()
    }
}

impl std::fmt::Display for ReloadRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ReloadRefused {}

/// Check the policy that a Box configuration selects, as a box checks it when it opens.
pub fn check_policy(config: PathBuf) -> Result<PolicyCheck, CheckFailed> {
    let (source, complete, grammars) =
        record::config::read_checked_policy(&config).map_err(CheckFailed)?;
    let operator = record::config::policy_operator().map_err(CheckFailed)?;
    Ok(policy::PolicyEngine::check_with_grammars(
        &operator,
        source.as_slice(),
        complete,
        &grammars,
    ))
}

/// A policy check that could not run: the configuration or its policy file cannot be read.
#[derive(Debug)]
pub struct CheckFailed(error::BoxError);

impl std::fmt::Display for CheckFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for CheckFailed {}

/// The program names the box keeps for its own shell and Python runtime, which no MCP server takes.
pub const INTERPRETER_ALIASES: [&str; 5] = [
    run::broker::protocol::SHELL_ALIAS_NAMES[0],
    run::broker::protocol::SHELL_ALIAS_NAMES[1],
    run::broker::protocol::SHELL_ALIAS_NAMES[2],
    run::broker::protocol::PYTHON_ALIAS_NAMES[0],
    run::broker::protocol::PYTHON_ALIAS_NAMES[1],
];

const _: () = assert!(
    run::broker::protocol::SHELL_ALIAS_NAMES.len()
        + run::broker::protocol::PYTHON_ALIAS_NAMES.len()
        == INTERPRETER_ALIASES.len()
);

/// Check a read grant on the absolute `path` as a box checks a `read` entry, and return whether it
/// lies in a credential store, which a box grants only when a grant names it, and announces.
pub fn check_read_grant(path: &Path) -> Result<bool, GrantRefused> {
    record::config::filesystem::judge_read_grant(path)
        .map_err(|(kind, error)| GrantRefused { kind, error })
}

/// A read grant that a box refuses, with its kind and the reason.
#[derive(Debug)]
pub struct GrantRefused {
    kind: GrantRefusal,
    error: error::BoxError,
}

impl GrantRefused {
    /// The kind of refusal.
    pub fn kind(&self) -> GrantRefusal {
        self.kind
    }
}

impl std::fmt::Display for GrantRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for GrantRefused {}

/// The class of a floor row: what the row protects.
pub use containment::ForbiddenClass;

/// The kind of a read grant that a box refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantRefusal {
    /// The path is neither absolute nor `~`-relative.
    NotAbsolute,
    /// The path, or a directory on the way to it, does not exist.
    Absent,
    /// The path is a symbolic link.
    Link,
    /// The path is not the canonical spelling, such as `/etc/hosts` for `/private/etc/hosts` on
    /// macOS, or a spelling with `.` or `..`.
    NotCanonical,
    /// A row of the floor beneath every grant refuses the path, and the class names what it protects.
    Forbidden(ForbiddenClass),
    /// Any other refusal, such as a path that encloses a credential store without naming it.
    Other,
}

/// Check one `env` entry of `[agent]`, a `[tool.<name>]`, or a stdio `[mcp.<name>]` with the checks
/// that need no other key; a box also refuses an `env.HOME` in or above `box_dir`.
pub fn check_workload_env(name: &str, value: &str) -> Result<(), EnvRefused> {
    let refused = |kind| EnvRefused {
        kind,
        reason: record::config::env::refusal_reason(kind, name, value),
    };
    match record::config::env::refused_name(name) {
        Some(kind) => Err(refused(kind)),
        None => record::config::env::refused_value(name, value)
            .map_or(Ok(()), |kind| Err(refused(kind))),
    }
}

/// An `env` entry that a box refuses, with its kind and the reason.
#[derive(Debug)]
pub struct EnvRefused {
    kind: EnvRefusal,
    reason: String,
}

impl EnvRefused {
    /// The kind of refusal.
    pub fn kind(&self) -> EnvRefusal {
        self.kind
    }
}

impl std::fmt::Display for EnvRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for EnvRefused {}

/// The kind of an `env` entry that a box refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvRefusal {
    /// The name is not a valid environment variable name.
    InvalidName,
    /// The box sets the name itself: proxy routing, CA trust, the OTLP exporter, `PWD`, or `USER`.
    SetByBox,
    /// The dynamic loader reads the name: `LD_*` or `DYLD_*`. A member of the family need not load
    /// code (`LD_BIND_NOW`).
    LoadsCode,
    /// The name is `HOME` or `TMPDIR`, and the value is not an absolute path.
    NotAbsolute,
}

/// Generate policy action and event schemas from a Box configuration.
pub fn generate_policy_schema(config: PathBuf, output_dir: PathBuf) -> ExitCode {
    command::execute(
        Cli {
            command: Command::Policy {
                command: PolicyCommand::GenerateSchema { config, output_dir },
            },
        },
        RunOptions::default(),
    )
}
