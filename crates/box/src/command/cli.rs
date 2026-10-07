//! The CLI as an operator spells it: the verbs, their flags, and nothing else.
//!
//! **Separated from `config` because a clap derive tree is not a box.** `config` answers what the
//! four inputs are and which are refused; this answers only how an operator types them. The two
//! shared a 2,572-line file and no types: every field here is a `String`, an `Option<String>`, a
//! `bool`, or a `Vec<OsString>`, and the domain types are built from them afterwards.
//!
//! The verb set is a frozen surface. Read `strands-box --help` for the live list rather than
//! trusting a comment — the root `AGENTS.md` row for it has been stale twice.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `strands-box`, as the operator spells it.
#[derive(Debug, Parser)]
#[command(
    name = "strands-box",
    version,
    about = "Run workloads inside a zero-trust box",
    long_about = None
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The verbs, one per operator action.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run one workload from one complete Box configuration.
    Run {
        /// The complete Box configuration.
        #[arg(long, value_name = "FILE", required = true)]
        config: PathBuf,

        /// Workload executable and arguments, after `--`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "WORKLOAD"
        )]
        workload: Vec<OsString>,
    },

    /// Work with the policy artifacts in this workspace.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

/// Operations on a workspace's policy artifacts.
#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    /// Generate the action and event schemas for policy authoring.
    GenerateSchema {
        /// The Box configuration whose MCP servers supply the schema.
        #[arg(long, value_name = "FILE", required = true)]
        config: PathBuf,

        /// Directory for the generated action and event schemas.
        #[arg(long, value_name = "OUTPUT_DIR", required = true)]
        output_dir: PathBuf,
    },
}
