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
pub use run::decisions::{
    DecisionEnforcement, PolicyDecision, PolicyDecisionReceiver, PolicyDecisionSender,
    policy_decisions,
};
pub use run::events::{
    ContainmentStage, RefusalKind, RunEvent, RunEventReceiver, RunEventSender, run_events,
};

static STARTED: AtomicBool = AtomicBool::new(false);

/// The voice of every message this crate writes with `diagnostics::diag!`.
const DIAGNOSTIC_SOURCE: ::diagnostics::Source = ::diagnostics::Source::StrandsBox;

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
    /// The channel that receives each policy decision of the run as it is made; a full channel
    /// drops the decision rather than delay it.
    pub policy_decisions: Option<PolicyDecisionSender>,
    /// The channel that receives what happens to the run, such as the kind of a failure of the
    /// box itself; no event is ever dropped.
    pub events: Option<RunEventSender>,
}

/// Run the existing Box command with a configuration.
pub fn run(config: PathBuf, workload: Vec<OsString>, options: RunOptions<'_>) -> ExitCode {
    if let Some(found) = options.box_id.as_deref()
        && !record::config::valid_box_identity(found)
    {
        let error = error::ConfigError::SuppliedIdentity {
            found: found.to_string(),
        };
        ::diagnostics::diag!({ error.code() }, "{error}");
        refuse(options.events.as_ref(), RefusalKind::BoxId, error.code());
        return ExitCode::FAILURE;
    }
    if STARTED.swap(true, Ordering::SeqCst) {
        ::diagnostics::diag!(
            B0106,
            "refusing to run: this process already attempted to run a box"
        );
        refuse(
            options.events.as_ref(),
            RefusalKind::AlreadyRan,
            ::diagnostics::Code::B0106.into(),
        );
        return ExitCode::FAILURE;
    }

    command::execute(
        Cli {
            command: Command::Run { config, workload },
        },
        options,
    )
}

/// Tell the caller's channel, if it gave one, the kind of the box's own failure and the code its
/// stderr line carries.
pub(crate) fn refuse(
    events: Option<&RunEventSender>,
    kind: RefusalKind,
    code: ::diagnostics::Kind,
) {
    if let Some(events) = events {
        events.send(RunEvent::Refused { kind, code });
    }
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
    /// The path is a symbolic link that a grant cannot name: a link to a directory, a link outside
    /// its real folder or inside a credential store, or a link in any list but `read` and
    /// `read_file`.
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

/// The kind of environment variable name a box reserves, or `None` for a name it leaves to the
/// operator, such as `HOME`, `PATH`, or `NODE_PATH`.
///
/// A caller that writes `box.toml` can use it to drop the names Box sets and refuse the names that
/// load code, without copying Box's lists.
pub fn reserved_env(name: &str) -> Option<ReservedEnv> {
    record::config::env::reserved_kind(name)
}

/// The kind of a name [`reserved_env`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservedEnv {
    /// A proxy setting, such as `HTTPS_PROXY` or `NO_PROXY`, that Box sets in a process whose
    /// egress goes through the gateway. A table with `contain_egress = false` may set it in `env`.
    GatewayProxy,
    /// A CA file setting, such as `SSL_CERT_FILE` or `GIT_SSL_CAINFO`, that Box points at the
    /// gateway's CA in a process whose egress goes through the gateway. A table with
    /// `contain_egress = false` may set it in `env`, and also needs a `read_file` entry for the file.
    GatewayCaFile,
    /// A name Box sets in every process: `PWD`, `USER`, or an `OTEL_EXPORTER_OTLP_` name.
    SetByBox,
    /// A name that makes a program load code before its first line, such as `LD_PRELOAD`,
    /// `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, or a `PYTHON` name. A credential cannot take it.
    /// A table's `env` refuses only the `LD_` and `DYLD_` names, and may set the others.
    LoadsCode,
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
