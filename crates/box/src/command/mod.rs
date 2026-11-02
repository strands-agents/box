//! One module per CLI verb: what each of `strands-box`'s commands does.
//!
//! | Lifetime | Verbs |
//! |---|---|
//! | workspace | [`policy`] |
//! | run | [`run`] |
//!
//! `run::configure` is not a verb. It is the creation mechanism `run` uses, and `run` is the only
//! caller.

pub(crate) mod cli;
mod platform;
pub(crate) mod policy;
pub(crate) mod run;

use std::process::ExitCode;

use crate::command::cli::{Cli, Command, PolicyCommand};
use crate::error::BoxError;
use crate::run::hardening::Hardening;

pub(crate) fn execute(cli: Cli, options: crate::RunOptions<'_>) -> ExitCode {
    if let Err(error) = platform::preflight() {
        eprintln!("strands-box: refusing to run: {error}");
        return ExitCode::FAILURE;
    }

    // Disable core dumps and restrict process-memory inspection before Box starts its runtime or loads credentials.
    if matches!(cli.command, Command::Run { .. })
        && let Err(error) = Hardening::apply()
    {
        eprintln!("strands-box: refusing to run: {error}");
        return ExitCode::FAILURE;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("strands-box: failed to start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    // A plain multi-threaded runtime. The Shell is `!Send` and needs a `LocalSet`, but it builds its
    // own runtime on its own thread, so a non-yielding Lua loop cannot pin the thread serving
    match runtime.block_on(async {
        let signals = if options.on_ready.is_some() {
            Some(crate::run::contain::supervise::Signals::listen()?)
        } else {
            None
        };
        if let Some(on_ready) = options.on_ready {
            on_ready().map_err(|source| crate::error::SuperviseError::Control {
                reason: format!("on_ready callback failed: {source}"),
            })?;
        }
        dispatch(cli, options.terminal, signals).await
    }) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("strands-box: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Route one invocation to the verb it named.
async fn dispatch(
    cli: Cli,
    terminal: Option<std::fs::File>,
    signals: Option<crate::run::contain::supervise::Signals>,
) -> Result<ExitCode, BoxError> {
    match &cli.command {
        Command::Run { config, workload } => {
            run::execute(config, workload, terminal, signals).await
        }
        Command::Policy {
            command: PolicyCommand::GenerateSchema { config, output_dir },
        } => policy::generate_schema(config, output_dir).await,
    }
}
