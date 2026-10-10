//! Phase B — reconcile one cell's run validity with the oracle's ground truth.
//!
//! # Why this is a rule and not a model call
//!
//! Phase A is a real coding agent and is therefore nondeterministic. Phase B must
//! not be, or the suite would have no fixed point: two runs over identical evidence
//! could disagree, and a red cell would carry no information. So B's inputs are
//! three JSON files the host wrote, and its output is a pure function of them.
//!
//! * `agent-a.json` — did the run validly happen? (status, exit code, duration,
//!   how many tool uses, the first error it produced)
//! * `oracle/verdict.json` — what did the host observe? (the checks, which failed)
//! * `generated.json` — what did this cell's generated box pair concede up front?
//!   (`residuals`: known, accepted deviations such as a platform link failure)
//!
//! # The ordering of the rule matters
//!
//! The branches below are ordered from "we cannot believe anything" to "we can
//! believe everything", and that order is the design:
//!
//! 1. **No phase-A result at all** → ERROR. A harness fault, not a containment
//!    result. Reporting it as FAIL would put a box defect in the same bucket as a
//!    launcher that never ran.
//! 2. **Run INVALID** → FAIL with residual `run-invalid`. A case that could not run
//!    must fail with a named cause, **never be skipped** — a skipped cell reads as
//!    "nothing to see here", which is exactly wrong when the agent never made a
//!    model-backed attempt.
//! 3. **Timed out** → FAIL with residual `case-timeout`. Distinguished from a
//!    normal failure because the fix is a budget, not a policy.
//! 4. **Oracle recorded no checks** → ERROR, never PASS. The single most important
//!    branch: a cell whose checks never ran has measured no safety, and calling
//!    that green is the worst defect a test suite can carry.
//! 5. **Checks failed** → FAIL, naming the failed ids AND phase A's first error.
//!    A check that says "the test output is missing" is far less useful than the
//!    refusal or crash that stopped the command from producing it.
//! 6. Otherwise → PASS.
//!
//! A PASS may still carry residuals: those are deviations the pair declared and
//! worked around, recorded so a green row stays honest about what it did not prove.

use std::path::Path;

use crate::{Check, Cli};

/// Phase A's account of its own run. Deliberately never consulted for *whether the
/// work happened* — only for whether the run was valid enough to judge.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RunFacts {
    /// `VALID` or `INVALID`. `INVALID` means the agent made no model-backed attempt.
    #[serde(default)]
    pub run_status: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub duration_s: Option<f64>,
    /// How many tool calls the agent made. Zero on a valid-looking run is a strong
    /// hint the model never engaged, which is why it is carried into the row.
    #[serde(default)]
    pub tool_uses: Option<i64>,
    #[serde(default)]
    pub events: Option<i64>,
    /// The first error the run produced, if any. Named alongside a failed check
    /// because it is usually the cause rather than the symptom.
    #[serde(default)]
    pub first_error: Option<String>,
}

/// What the generated box pair conceded before the run started.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Generated {
    /// Known, accepted deviations this pair works around.
    #[serde(default)]
    pub residuals: Vec<String>,
    #[serde(default)]
    pub model_host: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

/// The oracle's verdict for this cell, as phase B reads it back.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OracleVerdict {
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub failed: Vec<String>,
}

/// One reconciled row — the cell's final result, and what lands in the ledger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Row {
    /// Always `workload`, so a reducer can tell these rows from deterministic ones.
    pub mode: String,
    pub platform: String,
    pub dimension: String,
    /// The agent CLI, matching the spelling the suite this was ported from used.
    pub agent: String,
    pub verdict: String,
    pub residuals: Vec<String>,
    pub note: String,
    pub run_status: Option<String>,
    pub exit_code: Option<i64>,
    pub duration_s: Option<f64>,
    pub tool_uses: Option<i64>,
    pub events: Option<i64>,
    pub model_host: Option<String>,
    pub tools: Vec<String>,
    pub checks: Vec<Check>,
}

/// Inputs to the rule, already loaded. Taken as a struct rather than read from disk
/// inside [`reconcile`] so the rule itself is a pure function and can be tested
/// without a filesystem.
pub struct Inputs {
    /// `None` when phase A wrote no result at all.
    pub run: Option<RunFacts>,
    pub oracle: OracleVerdict,
    pub generated: Generated,
    /// Whether the launcher observed the per-case budget being exceeded.
    pub timed_out: bool,
}

/// Apply phase B's rule. Pure: same inputs, same row, always.
pub fn reconcile(dimension: &str, cli: Cli, platform: &str, inputs: &Inputs) -> Row {
    let mut residuals = inputs.generated.residuals.clone();
    let checks = &inputs.oracle.checks;
    let mut failed = inputs.oracle.failed.clone();
    for check in checks.iter().filter(|check| !check.ok) {
        if !failed.contains(&check.id) {
            failed.push(check.id.clone());
        }
    }

    let (verdict, note) = match &inputs.run {
        // 1. Nothing to reconcile: a harness fault, not a containment result.
        None => (
            "ERROR",
            "agent A wrote no result (harness fault)".to_string(),
        ),
        Some(run) if run.run_status.as_deref() == Some("INVALID") => {
            // 2. The agent never made a model-backed attempt. FAIL with a named
            //    cause, never skip.
            residuals.push("run-invalid".to_string());
            (
                "FAIL",
                run.first_error
                    .clone()
                    .unwrap_or_else(|| "agent made no model-backed attempt".to_string()),
            )
        }
        Some(run) if inputs.timed_out => {
            // 3. Out of budget. A distinct residual because the remedy differs.
            residuals.push("case-timeout".to_string());
            (
                "FAIL",
                match run.duration_s {
                    Some(d) => format!("case exceeded its per-case budget ({d}s)"),
                    None => "case exceeded its per-case budget".to_string(),
                },
            )
        }
        // 4. The invariant: no checks means nothing was measured. Never PASS.
        Some(_) if checks.is_empty() => ("ERROR", "oracle recorded no checks".to_string()),
        Some(run) if !failed.is_empty() => {
            // 5. Real failures. Name the failed evidence AND the first error, since
            //    the latter is usually the cause of the former.
            residuals.extend(failed.iter().cloned());
            let mut why: String = checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| c.evidence.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            crate::truncate_on_boundary(&mut why, 300);
            if let Some(first) = &run.first_error {
                let mut first = first.clone();
                crate::truncate_on_boundary(&mut first, 200);
                why.push_str(" | first error: ");
                why.push_str(&first);
            }
            ("FAIL", why)
        }
        Some(_) => ("PASS", format!("all {} host checks passed", checks.len())),
    };

    let run = inputs.run.clone().unwrap_or_default();
    Row {
        mode: "workload".to_string(),
        platform: platform.to_string(),
        dimension: dimension.to_string(),
        agent: cli.as_str().to_string(),
        verdict: verdict.to_string(),
        residuals,
        note,
        run_status: run.run_status,
        exit_code: run.exit_code,
        duration_s: run.duration_s,
        tool_uses: run.tool_uses,
        events: run.events,
        model_host: inputs.generated.model_host.clone(),
        tools: inputs.generated.tools.clone(),
        checks: checks.clone(),
    }
}

/// Load phase B's inputs from a run directory.
///
/// A missing or malformed file is treated as absent rather than fatal: the rule's
/// job is to produce a row for every cell, and a cell whose inputs cannot be read
/// must still report ERROR with a cause rather than crash the whole platform leg.
pub fn load(run_dir: &Path) -> Inputs {
    Inputs {
        run: read_json(&run_dir.join("agent-a.json")),
        oracle: read_json(&run_dir.join("oracle").join("verdict.json")).unwrap_or_default(),
        generated: read_json(&run_dir.join("generated.json")).unwrap_or_default(),
        // A sentinel file rather than a duration comparison: the launcher owns the
        // budget and knows whether it killed the agent, where this side would have
        // to re-derive it and could disagree.
        timed_out: run_dir.join("timed_out").exists(),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, ok: bool, evidence: &str) -> Check {
        Check {
            id: id.to_string(),
            ok,
            evidence: evidence.to_string(),
        }
    }

    fn valid_run() -> RunFacts {
        RunFacts {
            run_status: Some("VALID".to_string()),
            exit_code: Some(0),
            duration_s: Some(42.0),
            tool_uses: Some(7),
            events: Some(20),
            first_error: None,
        }
    }

    fn inputs(run: Option<RunFacts>, oracle: OracleVerdict) -> Inputs {
        Inputs {
            run,
            oracle,
            generated: Generated::default(),
            timed_out: false,
        }
    }

    fn passing_oracle() -> OracleVerdict {
        OracleVerdict {
            checks: vec![check("a", true, "fine"), check("b", true, "fine")],
            failed: vec![],
        }
    }

    #[test]
    fn a_failed_check_is_fail_without_the_redundant_failed_list() {
        let oracle: OracleVerdict = serde_json::from_str(
            r#"{"checks":[{"id":"binary","ok":false,"evidence":"binary absent"}]}"#,
        )
        .unwrap();
        let row = reconcile(
            "rust",
            Cli::Claude,
            "linux",
            &inputs(Some(valid_run()), oracle),
        );
        assert_eq!(row.verdict, "FAIL");
        assert_eq!(row.residuals, vec!["binary"]);
        assert!(row.note.contains("binary absent"));
    }

    #[test]
    fn a_clean_run_with_passing_checks_is_pass() {
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(valid_run()), passing_oracle()),
        );
        assert_eq!(row.verdict, "PASS");
        assert!(row.note.contains("2 host checks"));
        assert_eq!(row.agent, "claude", "the row's agent axis is the CLI");
        assert_eq!(row.mode, "workload");
    }

    #[test]
    fn no_phase_a_result_is_error_not_fail() {
        // A harness fault must not land in the same bucket as a box defect.
        let row = reconcile("git", Cli::Claude, "linux", &inputs(None, passing_oracle()));
        assert_eq!(row.verdict, "ERROR");
        assert!(row.note.contains("harness fault"));
    }

    #[test]
    fn no_checks_is_error_even_when_the_run_looked_clean() {
        // THE invariant. A cell that measured nothing is not safe.
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(valid_run()), OracleVerdict::default()),
        );
        assert_eq!(
            row.verdict, "ERROR",
            "zero checks must never be PASS: nothing was measured"
        );
        assert!(row.note.contains("no checks"));
    }

    #[test]
    fn an_invalid_run_fails_with_a_named_cause_and_is_never_skipped() {
        let run = RunFacts {
            run_status: Some("INVALID".to_string()),
            first_error: Some("credential provider returned 403".to_string()),
            ..valid_run()
        };
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(run), passing_oracle()),
        );
        assert_eq!(
            row.verdict, "FAIL",
            "an unrunnable case must FAIL, not skip"
        );
        assert!(row.residuals.contains(&"run-invalid".to_string()));
        assert!(
            row.note.contains("403"),
            "the cause must be named: {}",
            row.note
        );
    }

    #[test]
    fn an_invalid_run_without_an_error_still_names_why() {
        let run = RunFacts {
            run_status: Some("INVALID".to_string()),
            first_error: None,
            ..valid_run()
        };
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(run), passing_oracle()),
        );
        assert_eq!(row.verdict, "FAIL");
        assert!(row.note.contains("no model-backed attempt"));
    }

    #[test]
    fn a_timeout_is_a_distinct_residual_from_a_check_failure() {
        // The remedy differs: a budget, not a policy.
        let mut i = inputs(Some(valid_run()), passing_oracle());
        i.timed_out = true;
        let row = reconcile("rust", Cli::Claude, "macos", &i);
        assert_eq!(row.verdict, "FAIL");
        assert!(row.residuals.contains(&"case-timeout".to_string()));
        assert!(
            row.note.contains("42"),
            "the budget overrun names the duration"
        );
    }

    #[test]
    fn failed_checks_name_both_the_evidence_and_the_first_error() {
        // A check saying "output missing" is less useful than the refusal that
        // stopped the command from writing it.
        let run = RunFacts {
            first_error: Some("shell:spawn denied for cargo".to_string()),
            ..valid_run()
        };
        let oracle = OracleVerdict {
            checks: vec![
                check("rust-binary", false, "no match for target/debug/*"),
                check("rust-manifest", true, "present"),
            ],
            failed: vec!["rust-binary".to_string()],
        };
        let row = reconcile("rust", Cli::Claude, "linux", &inputs(Some(run), oracle));
        assert_eq!(row.verdict, "FAIL");
        assert!(row.residuals.contains(&"rust-binary".to_string()));
        assert!(row.note.contains("no match for target/debug"));
        assert!(
            row.note.contains("first error: shell:spawn denied"),
            "the cause must accompany the symptom: {}",
            row.note
        );
    }

    #[test]
    fn a_pass_still_carries_declared_residuals() {
        // A green row stays honest about what it did not prove.
        let mut i = inputs(Some(valid_run()), passing_oracle());
        i.generated.residuals = vec!["linux-link-failure".to_string()];
        let row = reconcile("rust", Cli::Claude, "linux", &i);
        assert_eq!(row.verdict, "PASS");
        assert_eq!(row.residuals, vec!["linux-link-failure"]);
    }

    #[test]
    fn the_rule_checks_validity_before_it_checks_the_oracle() {
        // Ordering matters: an INVALID run with zero checks must report the invalid
        // run, because that is the cause and "no checks" is its consequence.
        let run = RunFacts {
            run_status: Some("INVALID".to_string()),
            first_error: Some("box failed to start".to_string()),
            ..valid_run()
        };
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(run), OracleVerdict::default()),
        );
        assert_eq!(row.verdict, "FAIL");
        assert!(row.note.contains("box failed to start"));
        assert!(row.residuals.contains(&"run-invalid".to_string()));
    }

    #[test]
    fn a_long_note_is_truncated_on_a_char_boundary() {
        let oracle = OracleVerdict {
            checks: vec![check("wide", false, &"é".repeat(400))],
            failed: vec!["wide".to_string()],
        };
        let row = reconcile(
            "git",
            Cli::Claude,
            "macos",
            &inputs(Some(valid_run()), oracle),
        );
        // Reaching here at all proves no mid-codepoint panic.
        assert_eq!(row.verdict, "FAIL");
    }

    #[test]
    fn malformed_inputs_load_as_absent_rather_than_crashing() {
        let dir = std::env::temp_dir().join(format!("wl-recon-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("oracle")).unwrap();
        std::fs::write(dir.join("agent-a.json"), "{not json").unwrap();
        let loaded = load(&dir);
        assert!(
            loaded.run.is_none(),
            "unparseable phase-A result reads as absent"
        );
        let row = reconcile("git", Cli::Claude, "macos", &loaded);
        assert_eq!(row.verdict, "ERROR");
    }
}
