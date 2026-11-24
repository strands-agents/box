use std::collections::BTreeSet;
use std::process::Command;

use strands_det_harness::egress::{HostRecorder, RECORDER_BODY};
#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{box_sibling, broker_socket, place_server};
use strands_det_harness::{BoxFixture, Decision, RunResult, det_case};

// Policy PO-LO (log-only parity: design 0005's two success criteria)
//
// One workload runs three times, each under the same policy text in a different mode: enforcing,
// log-only, and a permit-all control. The workload mixes permitted and denied actions on four
// boundaries, and no action depends on the outcome of an earlier one:
// - the Shell reads one permitted and one forbidden workspace file;
// - Monty reads one permitted and one forbidden workspace file;
// - an MCP server's `add` tool is permitted, and its `echo` tool is forbidden for one value;
// - the same server's `reach` tool fetches a loopback recorder through the egress gateway, and a
//   `forbid` refuses that `http:request`.
//
// Criterion 1: the actions the log-only run records `enforced = false` are the actions the
// enforcing run denies, and the log-only run's `first_flip` names the first of them.
// Criterion 2: the log-only run's workload output, tool results, and recorder traffic match the
// permit-all run's, so a trial behaves as if nothing were denied.
// The policy has no temporal rule, so no decision depends on history and the three runs may share
// one box.

/// The MCP program name, unique to this case so no two cases copy over one executing file.
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-lo-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-lo-macos";

/// The Monty script, which reads one permitted and one forbidden file.
const MONTY_SCRIPT: &str = r#"from pathlib import Path
print("MONTY_ALLOWED", Path("monty-allowed.txt").read_text())
try:
    print("MONTY_SECRET", Path("monty-secret.txt").read_text())
except Exception:
    print("MONTY_SECRET_REFUSED")
"#;

/// The workload: write the files, run the Shell and Monty reads, then hold the box open for the
/// MCP calls the host drives.
fn workload() -> String {
    format!(
        "printf shell-allowed-text > shell-allowed.txt; printf shell-secret-text > shell-secret.txt; \
         printf monty-allowed-text > monty-allowed.txt; printf monty-secret-text > monty-secret.txt; \
         printf '%s' {script} > parity.py; \
         zsh -lc 'echo SHELL_ALLOWED $(cat shell-allowed.txt); echo SHELL_SECRET $(cat shell-secret.txt); python3 parity.py'; \
         : > .det-ready; while [ ! -e .det-go ]; do :; done",
        script = strands_det_harness::sh_quote(MONTY_SCRIPT),
    )
}

/// The rules each run adds to the fixture's baseline: start and call the server, reach the
/// recorder, and forbid one action on each boundary.
fn rules(port: u16) -> String {
    format!(
        r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
@id("fetch_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when {{ context.input.server == "fetch" }};
@id("recorder_connect") permit (principal, action == Box::Action::"net:connect", resource)
    when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};
@id("recorder_request") permit (principal, action == Box::Action::"http:request", resource)
    when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};
@id("no_shell_secret") forbid (principal, action == Box::Action::"fs:read", resource)
    when {{ context.input.path like "*/shell-secret.txt" }};
@id("no_monty_secret") forbid (principal, action == Box::Action::"fs:read", resource)
    when {{ context.input.path like "*/monty-secret.txt" }};
@id("no_echo_secret") forbid (principal, action == fetch::Action::"echo", resource)
    when {{ context.input has text && context.input.text == "secret" }};
@id("no_recorder_path") forbid (principal, action == Box::Action::"http:request", resource)
    when {{ context.input.host == "127.0.0.1" && context.input.port == {port} && context.input.path like "/trial*" }};"#
    )
}

/// The policy mode of one run.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Enforce,
    LogOnly,
    PermitAll,
}

/// What one run produced: the workload's own lines, each tool call's result, the recorder's
/// request lines, and the decisions the run journaled.
struct Run {
    lines: Vec<String>,
    tools: Vec<String>,
    requests: Vec<String>,
    result: RunResult,
}

impl Run {
    fn decisions(&self) -> &[Decision] {
        &self.result.decisions
    }
}

/// Add the proxy-aware `fetch` server, pointed at `url`, and select `mode`.
fn configure(config: String, url: &str, mode: Mode) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let config = if mode == Mode::LogOnly {
        let edited = config.replace(
            "policy = \"policy.dw\"",
            "policy = { source = \"policy.dw\", enforcement = \"log_only\" }",
        );
        assert_ne!(
            edited, config,
            "DET_ERROR: the fixture names its policy file"
        );
        edited
    } else {
        config
    };
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.env]\nFIXTURE_FETCH_PROXY = \"1\"\nFIXTURE_FETCH_TARGET = {}\n",
        quote(FETCH_PROGRAM),
        quote(url),
    );
    #[cfg(target_os = "macos")]
    {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}

/// Run the workload once in `mode`, against `recorder`, which every run shares so each names the
/// same resources.
fn run(b: &BoxFixture, recorder: &HostRecorder, mode: Mode) -> Run {
    let port = recorder.port();
    let before = recorder.request_lines().len();
    match mode {
        Mode::PermitAll => {
            std::fs::write(b.policy_path(), "permit (principal, action, resource);\n")
                .expect("DET_ERROR: write the permit-all policy");
        }
        Mode::Enforce | Mode::LogOnly => {
            b.reset_policy();
            b.apply_policy(&rules(port));
        }
    }
    let url = format!("http://127.0.0.1:{port}/trial");
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut tools = Vec::new();
    let meanwhile = || {
        for (tool, arguments) in [
            ("add", r#"{"a":2,"b":3}"#),
            ("echo", r#"{"text":"secret"}"#),
            ("reach", "{}"),
        ] {
            let output = Command::new(&probe)
                .arg(&socket)
                .arg(FETCH_PROGRAM)
                .arg(tool)
                .arg(arguments)
                .output()
                .expect("run box-mcp-call-probe");
            tools.push(format!(
                "{tool} rc={} {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
    };
    let edit = |config| configure(config, &url, mode);
    #[cfg(target_os = "macos")]
    let result = {
        let path = format!(
            "{}:{}",
            server_dir().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        b.run_sh_with_config_meanwhile_env(edit, &workload(), &[("PATH", path.as_str())], meanwhile)
    };
    #[cfg(not(target_os = "macos"))]
    let result = b.run_sh_with_config_meanwhile(edit, &workload(), meanwhile);
    result.assert_entered();
    let lines = result
        .out
        .lines()
        .filter(|line| line.starts_with("SHELL_") || line.starts_with("MONTY_"))
        .map(str::to_string)
        .collect();
    Run {
        lines,
        tools,
        requests: recorder.request_lines().split_off(before),
        result,
    }
}

/// The `(action, resource)` of each policy denial: a deny whose rule is not an enforcement gate.
fn policy_denials<'a>(
    decisions: impl IntoIterator<Item = &'a Decision>,
) -> BTreeSet<(String, String)> {
    decisions
        .into_iter()
        .filter(|decision| decision.denied() && !decision.rule.starts_with("enforcement"))
        .map(|decision| (decision.action.clone(), decision.resource.clone()))
        .collect()
}

/// Every decision as one line, for a failure message.
fn listed(decisions: &[Decision]) -> String {
    decisions
        .iter()
        .map(|decision| {
            format!(
                "{} {} {} rule={} enforced={} first_flip={} would_deny={:?}",
                decision.action,
                decision.resource,
                decision.verdict,
                decision.rule,
                decision.enforced,
                decision.first_flip,
                decision.would_deny
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

det_case! {
    name: po_log_only_parity,
    id:   "PO-LO-01",
    platforms: [Linux, Macos],
    desc: "Log-only parity: a log-only run records enforced=false on exactly the actions an enforcing run denies, with first_flip on the first, and its workload output, tool results, and egress match a permit-all run",
    run: |b| {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let enforcing = run(b, &recorder, Mode::Enforce);
        let trial = run(b, &recorder, Mode::LogOnly);
        let open = run(b, &recorder, Mode::PermitAll);

        // The enforcing run denies one action on each boundary, so the comparison is not vacuous.
        let denied = policy_denials(enforcing.decisions());
        for forbid in ["no_shell_secret", "no_monty_secret", "no_echo_secret", "no_recorder_path"] {
            assert!(
                enforcing.decisions().iter().any(|decision| decision.forbidden_by(forbid)),
                "the enforcing run must deny by {forbid}; decisions:\n{}",
                listed(enforcing.decisions())
            );
        }
        assert!(
            enforcing.decisions().iter().all(|decision| decision.enforced && !decision.first_flip),
            "an enforcing run marks nothing let through; decisions:\n{}",
            listed(enforcing.decisions())
        );

        // Criterion 2: the trial behaves like the permit-all run.
        assert_eq!(trial.result.rc, open.result.rc, "exit codes;\nlog-only:\n{}\npermit-all:\n{}", trial.result.out, open.result.out);
        assert_eq!(trial.lines, open.lines, "workload output");
        assert_eq!(trial.tools, open.tools, "tool results");
        assert_eq!(trial.requests, open.requests, "recorder traffic");
        assert!(
            trial.lines.contains(&"SHELL_SECRET shell-secret-text".to_string())
                && trial.lines.contains(&"MONTY_SECRET monty-secret-text".to_string()),
            "the trial's denied reads went ahead: {:?}",
            trial.lines
        );
        assert!(
            trial.tools.iter().any(|tool| tool == "echo rc=0 echo:secret")
                && trial.tools.iter().any(|tool| tool.contains(&format!("fetched:{RECORDER_BODY}"))),
            "the trial's denied tool call and request went ahead: {:?}",
            trial.tools
        );

        // Criterion 1: the let-through set is the enforcing run's deny set.
        let let_through: Vec<&Decision> =
            trial.decisions().iter().filter(|decision| !decision.enforced).collect();
        assert!(
            let_through.iter().all(|decision| decision.denied() && !decision.would_deny.is_empty()),
            "a let-through decision keeps its deny and names its rule; decisions:\n{}",
            listed(trial.decisions())
        );
        assert_eq!(
            let_through
                .iter()
                .map(|decision| (decision.action.clone(), decision.resource.clone()))
                .collect::<BTreeSet<_>>(),
            denied,
            "the log-only run lets through exactly what the enforcing run denies;\nlog-only:\n{}\nenforcing:\n{}",
            listed(trial.decisions()),
            listed(enforcing.decisions())
        );
        assert!(
            policy_denials(trial.decisions().iter().filter(|decision| decision.enforced)).is_empty(),
            "a log-only run applies no policy denial; decisions:\n{}",
            listed(trial.decisions())
        );
        let first_flips: Vec<&&Decision> =
            let_through.iter().filter(|decision| decision.first_flip).collect();
        assert_eq!(first_flips.len(), 1, "one first flip; decisions:\n{}", listed(trial.decisions()));
        let earliest = let_through
            .iter()
            .min_by_key(|decision| decision.at_unix_nano)
            .expect("a let-through decision");
        assert_eq!(
            (&first_flips[0].action, &first_flips[0].resource),
            (&earliest.action, &earliest.resource),
            "the first flip is the first let-through decision; decisions:\n{}",
            listed(trial.decisions())
        );
        let first_denial = enforcing
            .decisions()
            .iter()
            .filter(|decision| decision.denied() && !decision.rule.starts_with("enforcement"))
            .min_by_key(|decision| decision.at_unix_nano)
            .expect("a policy denial");
        assert_eq!(
            (&first_flips[0].action, &first_flips[0].resource),
            (&first_denial.action, &first_denial.resource),
            "the first flip is the enforcing run's first denial"
        );

        // The enforcing run is the paired control: its denials took effect.
        assert_ne!(enforcing.lines, open.lines, "the enforcing run refused the reads: {:?}", enforcing.lines);
        assert_ne!(enforcing.tools, open.tools, "the enforcing run refused the calls: {:?}", enforcing.tools);
        assert!(enforcing.requests.is_empty(), "the enforcing run sent no request: {:?}", enforcing.requests);
    }
}
