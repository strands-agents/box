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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use command::cli::{Cli, Command, PolicyCommand};

pub use policy::Policy;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Run the existing Box command with a configuration.
pub fn run(config: PathBuf, workload: Vec<OsString>) -> ExitCode {
    run_box(config, workload, None)
}

/// Run a box, and hand `on_open` the policy authority this run decides against.
///
/// `on_open` is called once, after the box is open and before the workload starts. It runs on the
/// box's own task, so it is expected to pass the handle onward rather than do work of its own.
///
/// This function does not return until the workload exits, which is the reason the handle exists:
/// a caller that reloads a policy mid-run drives this on its own thread and reloads through the
/// handle it was given. A box that fails to open hands out no handle.
pub fn run_with_handle<F>(config: PathBuf, workload: Vec<OsString>, on_open: F) -> ExitCode
where
    F: FnOnce(BoxHandle) + Send + 'static,
{
    run_box(config, workload, Some(Box::new(on_open)))
}

/// Generate policy action and event schemas from a Box configuration.
pub fn generate_policy_schema(config: PathBuf, output_dir: PathBuf) -> ExitCode {
    command::execute(
        Cli {
            command: Command::Policy {
                command: PolicyCommand::GenerateSchema { config, output_dir },
            },
        },
        None,
    )
}

/// The one-run guard both public run paths share, so asking for a handle cannot bypass it.
fn run_box(
    config: PathBuf,
    workload: Vec<OsString>,
    on_open: Option<command::run::OnOpen>,
) -> ExitCode {
    if STARTED.swap(true, Ordering::SeqCst) {
        eprintln!("strands-box: refusing to run: this process already attempted to run a box");
        return ExitCode::FAILURE;
    }

    command::execute(
        Cli {
            command: Command::Run { config, workload },
        },
        on_open,
    )
}

/// One open box's policy authority.
///
/// Holds the engine this box already decides against, so a reload reaches the running box. A
/// caller that opened an engine of its own would be reloading a different one, and the box would
/// not notice.
pub struct BoxHandle {
    policy: Arc<policy::PolicyEngine>,
}

impl BoxHandle {
    pub(crate) fn new(policy: Arc<policy::PolicyEngine>) -> Self {
        Self { policy }
    }

    /// Install an authored policy set over this box's live authority.
    ///
    /// The box keeps its decision history, so a rule whose canonical text is unchanged keeps the
    /// budget it has already spent. A set that does not validate is refused whole, and the policy
    /// already installed keeps deciding every request.
    ///
    /// Canonical text is literal: a reformatted rule counts as a changed rule and starts a new
    /// budget (`Dogwood` issue 59).
    ///
    /// Nothing here asks who is calling, so whatever drives a reload owns that question. Which
    /// component owns an authored policy source, and where a reload trigger belongs, are open
    /// questions this type does not settle.
    pub fn reload(&self, sources: &[Policy]) -> Result<(), ReloadRefused> {
        self.policy.reload(sources).map_err(ReloadRefused)
    }
}

/// A reload the box refused. The policy already installed still decides every request.
///
/// Opaque on purpose: the staging taxonomy behind it belongs to the policy crate, and to expose it
/// would make every internal variant part of this contract.
#[derive(Debug)]
pub struct ReloadRefused(policy::PolicyStagingError);

impl std::fmt::Display for ReloadRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ReloadRefused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}
