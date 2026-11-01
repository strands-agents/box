use std::process::Command;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{
    box_sibling, broker_socket, place_server, with_fetch_server,
};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-MT (MCP tool policy: the per-tool gate on a contained MCP leaf)
//
// A `tools/call` meets two gates in the broker: the coarse `Box::Action::"mcp:call"` (may the agent
// call this server), then the server-namespaced per-tool action `fetch::Action::"<tool>"`, typed by
// the arguments schema discovered from `tools/list`. The per-tool gate rides the coarse permit unless
// a `forbid` on the tool, or on its arguments, matches.
//
// `box-mcp-fetch-server` declares two tools: `reach`, and `add` with typed integer arguments `a` and
// `b` (it returns `sum:<a+b>`). Three runs, one policy each:
// - baseline: the coarse permit alone admits `add` and `reach`;
// - tool-name block: a `forbid` on `fetch::Action::"add"` with no `when` refuses every `add` call,
//   while `reach` on the same server still runs;
// - tool-argument block: a `forbid` on `add` when `a > 100` refuses `add {a:200}` and admits
//   `add {a:2}`;
// - string-argument block: a `forbid` on `echo` when `text == "secret"` refuses that value alone.
// Each refusal is asserted in the journal by its `@id`, so the per-tool forbid, not a default-deny,
// is what refused the call.

/// The MCP program name (`command[0]`): a unique bare name on the operator PATH, distinct from the
/// CN-NE-01 and CN-ME-01 names so no two cases copy over one executing file (`ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-mt-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-mt-macos";

/// The typed per-tool action for `add`, as the policy names it.
const ADD_ACTION: &str = r#"fetch::Action::"add""#;
/// The same decision as the journal records it: the bare tool name, with the server in the resource.
const ADD_JOURNAL_ACTION: &str = "add";
const ADD_RESOURCE: &str = "fetch/add";

/// A blocking agent workload: touch the ready marker, then spin until the host writes the go marker.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// The coarse server permit every run carries.
const SERVER_PERMIT: &str = r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
@id("fetch_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" };"#;

/// Spawn one box and drive each `(tool, arguments)` as its own `tools/call` in order. Returns each
/// call's probe output and the run, whose `decisions` hold the journal.
fn call_tools(b: &BoxFixture, calls: &[(&str, &str)]) -> (Vec<String>, RunResult) {
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut outputs = Vec::new();
    let meanwhile = || {
        for (tool, arguments) in calls {
            let output = Command::new(&probe)
                .arg(&socket)
                .arg(FETCH_PROGRAM)
                .arg(tool)
                .arg(arguments)
                .output()
                .expect("run box-mcp-call-probe");
            outputs.push(
                String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr),
            );
        }
    };
    #[cfg(target_os = "macos")]
    let run = {
        let path = format!(
            "{}:{}",
            server_dir().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        b.run_sh_with_config_meanwhile_env(
            |config| with_fetch_server(config, FETCH_PROGRAM),
            BLOCK,
            &[("PATH", path.as_str())],
            meanwhile,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let run = b.run_sh_with_config_meanwhile(
        |config| with_fetch_server(config, FETCH_PROGRAM),
        BLOCK,
        meanwhile,
    );
    (outputs, run)
}

/// Assert a probe output is the tool's own result.
fn assert_ran(output: &str, run: &RunResult, expected: &str) {
    RunResult::bare(format!("{output}\n[box output]\n{}", run.out), 0).assert_contains(expected);
}

/// Assert a probe output is a refusal, not a tool result.
fn assert_refused(output: &str, forbidden_result: &str) {
    assert!(
        output.contains("box-mcp-call-probe:") && !output.contains(forbidden_result),
        "the call must be refused, not answered; out=[{output}]"
    );
}

det_case! {
    name: cn_mcp_tool_policy,
    id:   "CN-MT-01",
    platforms: [Linux, Macos],
    desc: "MCP tool policy: a contained MCP leaf's tools/call is gated per tool — the coarse server permit admits every tool, a forbid on the tool name refuses that tool alone, and a forbid on an integer or a string argument value refuses only the calls whose argument matches",
    run: |b| {
        // Baseline: the coarse server permit alone admits both tools.
        b.apply_policy(SERVER_PERMIT);
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#), ("reach", "{}")]);
        assert_ran(&out[0], &run, "sum:5");
        assert_ran(&out[1], &run, "fetch-failed:FIXTURE_FETCH_TARGET is unset");
        run.assert_mediated_permitted("mcp:call", ADD_RESOURCE);

        // Tool-name block: a forbid on `add` with no `when` refuses every `add`; `reach` still runs.
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n@id(\"forbid_add_tool\") forbid (principal, action == {ADD_ACTION}, resource);"
        ));
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#), ("reach", "{}")]);
        assert_refused(&out[0], "sum:");
        run.assert_forbidden_by(ADD_JOURNAL_ACTION, ADD_RESOURCE, "forbid_add_tool");
        assert_ran(&out[1], &run, "fetch-failed:FIXTURE_FETCH_TARGET is unset");

        // Tool-argument block: a forbid on `add` when `a > 100` refuses only the matching call.
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n@id(\"forbid_add_large_a\") forbid (principal, action == {ADD_ACTION}, resource)\n    when {{ context.input has a && context.input.a > 100 }};"
        ));
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#), ("add", r#"{"a":200,"b":1}"#)]);
        assert_ran(&out[0], &run, "sum:5");
        assert_refused(&out[1], "sum:201");
        run.assert_forbidden_by(ADD_JOURNAL_ACTION, ADD_RESOURCE, "forbid_add_large_a");

        // String-argument block: a forbid on `echo` when `text == "secret"` refuses that value alone.
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n@id(\"forbid_echo_secret\") forbid (principal, action == fetch::Action::\"echo\", resource)\n    when {{ context.input has text && context.input.text == \"secret\" }};"
        ));
        let (out, run) = call_tools(b, &[("echo", r#"{"text":"hello"}"#), ("echo", r#"{"text":"secret"}"#)]);
        assert_ran(&out[0], &run, "echo:hello");
        assert_refused(&out[1], "echo:secret");
        run.assert_forbidden_by("echo", "fetch/echo", "forbid_echo_secret");
    }
}
