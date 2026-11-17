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

    /// Work with policy schemas and saved policy history.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

/// Operations on policy schemas and saved policy history.
#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    /// Prepare or apply an offline conversion of one box's saved policy history.
    MigrateHistory {
        /// The configuration of the stopped, existing box.
        #[arg(long, value_name = "FILE", required = true)]
        config: PathBuf,

        /// The Dogwood version that will read the converted history.
        #[arg(long, value_name = "VERSION", value_parser = ["1.0.0", "1.1.2"], required = true)]
        to: String,

        /// Apply the prepared conversion after validating private copies.
        #[arg(long)]
        apply: bool,
    },

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

#[cfg(test)]
mod history_migration_tests {
    use super::*;

    #[test]
    fn history_migration_requires_an_explicit_config_and_supported_target() {
        for args in [
            vec!["strands-box", "policy", "migrate-history", "--to", "1.0.0"],
            vec![
                "strands-box",
                "policy",
                "migrate-history",
                "--config",
                "box.toml",
            ],
            vec![
                "strands-box",
                "policy",
                "migrate-history",
                "--config",
                "box.toml",
                "--to",
                "1.1.1",
            ],
            vec![
                "strands-box",
                "policy",
                "migrate-history",
                "--config",
                "box.toml",
                "--to",
                "1.0.0",
                "--history",
                "other.redb",
            ],
            vec![
                "strands-box",
                "policy",
                "migrate-history",
                "--config",
                "box.toml",
                "--to",
                "1.0.0",
                "--helper",
                "other",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn history_migration_prepares_by_default_and_apply_is_explicit() {
        for target in ["1.0.0", "1.1.2"] {
            for apply in [false, true] {
                let mut args = vec![
                    "strands-box",
                    "policy",
                    "migrate-history",
                    "--config",
                    "box.toml",
                    "--to",
                    target,
                ];
                if apply {
                    args.push("--apply");
                }
                let parsed = Cli::try_parse_from(args).expect("supported offline command");
                let Command::Policy {
                    command:
                        PolicyCommand::MigrateHistory {
                            config,
                            to,
                            apply: found,
                        },
                } = parsed.command
                else {
                    panic!("migration command was not selected");
                };
                assert_eq!(config, PathBuf::from("box.toml"));
                assert_eq!(to, target);
                assert_eq!(found, apply);
            }
        }
    }

    #[test]
    fn history_migration_help_explains_target_and_apply() {
        let help = Cli::try_parse_from(["strands-box", "policy", "migrate-history", "--help"])
            .expect_err("clap returns its help as a display result")
            .to_string();
        for expected in ["--config", "--to", "1.0.0", "1.1.2", "--apply", "stopped"] {
            assert!(help.contains(expected), "missing {expected}: {help}");
        }
    }
}
