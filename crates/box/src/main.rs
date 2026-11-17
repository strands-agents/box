#[path = "command/cli.rs"]
mod cli;

use clap::Parser;
use cli::{Cli, Command, PolicyCommand};
use std::process::ExitCode;

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run { config, workload } => strands_box::run(config, workload, Default::default()),
        Command::Policy {
            command: PolicyCommand::GenerateSchema { config, output_dir },
        } => strands_box::generate_policy_schema(config, output_dir),
        Command::Policy {
            command: PolicyCommand::MigrateHistory { config, to, apply },
        } => strands_box::migrate_policy_history(config, &to, apply),
    }
}
