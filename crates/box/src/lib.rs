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
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use command::cli::{Cli, Command, PolicyCommand};

pub use policy::{Finding, Location, PolicyCheck, RuleRef};

static STARTED: AtomicBool = AtomicBool::new(false);

/// Optional terminal attachment and host initialization for one run.
#[derive(Default)]
pub struct RunOptions<'a> {
    /// The workload's controlling terminal; `None` inherits the process's standard streams.
    pub terminal: Option<std::fs::File>,
    /// Called after hardening and signal registration, before workload setup; an error aborts the run.
    pub on_ready: Option<Box<dyn FnOnce() -> std::io::Result<()> + 'a>>,
}

/// Run the existing Box command with a configuration.
pub fn run(config: PathBuf, workload: Vec<OsString>, options: RunOptions<'_>) -> ExitCode {
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

/// Check the policy that a Box configuration selects, as a box checks it when it opens.
pub fn check_policy(config: PathBuf) -> Result<PolicyCheck, CheckFailed> {
    let (source, complete) = record::config::read_checked_policy(&config).map_err(CheckFailed)?;
    let operator = record::config::policy_operator().map_err(CheckFailed)?;
    Ok(policy::PolicyEngine::check(
        &operator,
        source.as_slice(),
        complete,
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
