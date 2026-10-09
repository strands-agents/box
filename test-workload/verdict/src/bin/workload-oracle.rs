//! `workload-oracle` — the host-side judge for one nondeterministic workload cell.
//!
//! The bash launcher calls this three times per cell, and the order is the contract:
//!
//! ```text
//!   workload-oracle start     --run-dir DIR
//!   <phase A: the agent CLI performs goal.md inside the box>
//!   workload-oracle stop      --run-dir DIR --dimension git --cli claude
//!   workload-oracle reconcile --run-dir DIR --dimension git --cli claude
//! ```
//!
//! * `start` truncates the decision journal, so no check can pass on a decision an
//!   earlier cell produced.
//! * `stop` runs that dimension's checks against the host filesystem and the
//!   journal, and writes `<run-dir>/oracle/verdict.json`. This is the oracle.
//! * `reconcile` is **phase B**: it folds phase A's run validity together with the
//!   oracle's verdict into the cell's final row at `<run-dir>/verdict.json`. It is a
//!   rule, not a model call, so it is deterministic and tested.
//!
//! Keeping all three here leaves the bash launcher doing only what bash is good at —
//! installing a CLI, exporting env, exec'ing the agent, tee'ing a log. **The
//! launcher never decides a verdict.**
//!
//! # Exit status
//!
//! * `0` — the cell PASSED.
//! * `1` — the cell FAILED or ERRORED. The verdict file names which checks.
//! * `2` — usage or setup error. Distinguished from `1` so a mis-invoked launcher
//!   is never silently recorded as a containment failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use workload_verdict::{Cli, Oracle, checks, jailbreak, reconcile};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "jailbreak") {
        return ExitCode::from(jailbreak::command(&args[1..]));
    }
    let Some(command) = args.first().cloned() else {
        return usage("no command given");
    };

    let mut run_dir: Option<PathBuf> = None;
    let mut dimension: Option<String> = None;
    let mut cli: Option<Cli> = None;
    // Defaulted rather than required: the launcher knows the platform, but a
    // developer reproducing one cell by hand should not have to spell it.
    let mut platform = default_platform().to_string();

    let mut index = 1;
    while index < args.len() {
        let flag = &args[index];
        let value = args.get(index + 1);
        let take = |what: &str| -> Result<String, ExitCode> {
            match value {
                Some(v) if !v.starts_with("--") => Ok(v.clone()),
                _ => Err(usage(&format!("{what} needs a value"))),
            }
        };
        match flag.as_str() {
            "--run-dir" => match take("--run-dir") {
                Ok(v) => run_dir = Some(PathBuf::from(v)),
                Err(code) => return code,
            },
            "--dimension" => match take("--dimension") {
                Ok(v) => dimension = Some(v),
                Err(code) => return code,
            },
            "--cli" => match take("--cli") {
                Ok(v) => match Cli::parse(&v) {
                    Some(c) => cli = Some(c),
                    None => {
                        let known: Vec<&str> = Cli::all().iter().map(|c| c.as_str()).collect();
                        return usage(&format!(
                            "--cli must be one of [{}], got {v:?}",
                            known.join(", ")
                        ));
                    }
                },
                Err(code) => return code,
            },
            "--platform" => match take("--platform") {
                Ok(v) => platform = v,
                Err(code) => return code,
            },
            other => return usage(&format!("unknown flag {other:?}")),
        }
        index += 2;
    }

    let Some(run_dir) = run_dir else {
        return usage("--run-dir is required");
    };

    match command.as_str() {
        "start" => match Oracle::start(&run_dir) {
            Ok(journal) => {
                println!("oracle start: truncated {}", journal.display());
                ExitCode::SUCCESS
            }
            Err(why) => {
                // A setup failure, not a verdict. If the journal cannot be
                // truncated the run must not proceed: a stale journal could let a
                // later check pass on some earlier cell's decision.
                eprintln!("oracle start FAILED: {why}");
                ExitCode::from(2)
            }
        },
        "stop" | "reconcile" => {
            let Some(dimension) = dimension else {
                return usage(&format!("{command} needs --dimension"));
            };
            let Some(cli) = cli else {
                return usage(&format!("{command} needs --cli"));
            };
            if command == "stop" {
                stop(&run_dir, &dimension, cli, &platform)
            } else {
                phase_b(&run_dir, &dimension, cli, &platform)
            }
        }
        other => usage(&format!("unknown command {other:?}")),
    }
}

/// The oracle: judge the run from the host filesystem and the box's journal.
fn stop(run_dir: &Path, dimension: &str, cli: Cli, platform: &str) -> ExitCode {
    let mut oracle = Oracle::open(run_dir, dimension, cli, platform);

    if !checks::run(&mut oracle, dimension) {
        // Recording nothing would read as ERROR anyway, but saying so explicitly
        // separates "this dimension has no checks defined" from "its checks crashed".
        oracle.check(
            "oracle-dimension-known",
            false,
            format!(
                "no checks are defined for dimension {dimension:?}; known: {}",
                checks::DIMENSIONS.join(", ")
            ),
        );
    }

    let verdict = match oracle.write_verdict() {
        Ok(verdict) => verdict,
        Err(why) => {
            eprintln!("oracle stop: cannot write verdict: {why}");
            return ExitCode::from(2);
        }
    };

    // Human-readable on stdout so the launcher's log carries the outcome without a
    // reader having to fetch the artifact.
    println!(
        "oracle stop: {} {}/{} on {} — {} check(s), {} failed",
        verdict.verdict,
        verdict.dimension,
        verdict.agent,
        verdict.platform,
        verdict.checks.len(),
        verdict.failed.len()
    );
    for check in &verdict.checks {
        println!(
            "  {} {} — {}",
            if check.ok { "PASS" } else { "FAIL" },
            check.id,
            check.evidence
        );
    }

    if verdict.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Phase B: reconcile run validity with the oracle's verdict into the cell's row.
fn phase_b(run_dir: &Path, dimension: &str, cli: Cli, platform: &str) -> ExitCode {
    let inputs = reconcile::load(run_dir);
    let row = reconcile::reconcile(dimension, cli, platform, &inputs);

    let path = run_dir.join("verdict.json");
    let body = match serde_json::to_string_pretty(&row) {
        Ok(body) => body,
        Err(why) => {
            eprintln!("phase B: cannot serialize row: {why}");
            return ExitCode::from(2);
        }
    };
    if let Err(why) = std::fs::write(&path, body + "\n") {
        eprintln!("phase B: cannot write {}: {why}", path.display());
        return ExitCode::from(2);
    }

    println!(
        "phase B: {}/{} {} [{}] {}",
        row.dimension,
        row.agent,
        row.verdict,
        row.residuals.join(","),
        truncated(&row.note, 160)
    );

    if row.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The platform label the row carries. Matches the deterministic suite's spelling so
/// one reducer reads both suites' rows.
fn default_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// First `max` bytes of a note, never splitting a UTF-8 codepoint.
fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn usage(why: &str) -> ExitCode {
    let known_cli: Vec<&str> = Cli::all().iter().map(|c| c.as_str()).collect();
    eprintln!("workload-oracle: {why}\n");
    eprintln!(
        "usage:
  workload-oracle jailbreak run --case network-egress [--platform NAME] [--box-commit SHA] [--run-id ID]
  workload-oracle start     --run-dir DIR
  workload-oracle stop      --run-dir DIR --dimension NAME --cli NAME [--platform NAME]
  workload-oracle reconcile --run-dir DIR --dimension NAME --cli NAME [--platform NAME]

  start      truncate the decision journal and prepare the oracle directory
  stop       run the dimension's host checks, write oracle/verdict.json
  reconcile  phase B: fold run validity + oracle verdict into verdict.json
  jailbreak  run the adversarial network-egress campaign on this host and judge it
             by canary hits. Writes finding.json and verdict.json.

dimensions: {}
clis:       {}",
        checks::DIMENSIONS.join(", "),
        known_cli.join(", ")
    );
    ExitCode::from(2)
}
