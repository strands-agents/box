//! `strands-box` — run workloads inside a zero-trust box.
//!
//! **One interface, and it is the command line.** `box.toml` states a box's authority and the CLI
//! acts on it. There was a `[lib]` façade beside this — `Box`, `Run`, `Running`, `BoxConfig` — which
//! was a second vocabulary for the same thing: a caller staged program *content* through
//! `Run::staged` where an operator names `--code <dir> -- python main.py`. Two spellings of one idea,
//! and only one of them was reachable by anyone reading `--help`.
//!
//! | Module | Owns |
//! |---|---|
//! | [`command`] | one module per verb, and the argv parser |
//! | [`record`] | what a box *is*, before anything is running |
//! | [`run`] | one box's trusted half, alive for one run |
//! | [`error`] | the typed taxonomy, one variant group per phase |

#![warn(unreachable_pub)]

mod command;
mod error;
mod record;
mod run;
#[cfg(test)]
mod test_support;

fn main() -> std::process::ExitCode {
    command::cli_main()
}
