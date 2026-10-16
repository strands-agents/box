//! `strands-box` — run workloads inside a zero-trust box.
//!
//! **The command line and library share one implementation.** `box.toml` states a box's authority
//! and both act on it. There was a `[lib]` façade beside this — `Box`, `Run`, `Running`, `BoxConfig` — which
//! was a second vocabulary for the same thing: a caller staged program *content* through
//! `Run::staged` where an operator names `--code <dir> -- python main.py`. Two spellings of one idea,
//! and only one of them was reachable by anyone reading `--help`.
//!
//! | Module | Owns |
//! |---|---|
//! | `command` | one module per verb, and the argv parser |
//! | `record` | what a box *is*, before anything is running |
//! | `run` | one box's trusted half, alive for one run |
//! | `error` | the typed taxonomy, one variant group per phase |

#![warn(unreachable_pub)]

mod command;
mod error;
mod record;
mod run;
#[cfg(test)]
mod test_support;

/// Run the existing Box command with a configuration.
pub fn run(config: std::path::PathBuf) -> std::process::ExitCode {
    command::execute(command::cli::Cli {
        command: command::cli::Command::Run {
            config,
            workload: Vec::new(),
        },
    })
}

/// The standalone Box command-line entry point.
pub fn cli_main() -> std::process::ExitCode {
    command::cli_main()
}
