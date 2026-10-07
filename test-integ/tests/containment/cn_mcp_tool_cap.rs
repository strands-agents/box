use std::process::Command;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{
    box_sibling, broker_socket, place_server, with_fetch_server,
};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-MT (MCP tool policy), temporal half
//
// A rate cap on a contained MCP leaf's tool calls: a `forbid` on `mcp:call` with a `when temporal`
// clause that counts this server's answered `tools/call` responses within 300 seconds. The first
// two `add` calls run, and the third is refused by the cap's `@id`. The calls are sequential, so each
// response is recorded before the next call is decided. This case has its own box, so the engine's
// durable history holds only its own calls.

/// The MCP program name (`command[0]`): a unique bare name on the operator PATH, distinct from every other
/// case's name so no two cases copy over one executing file (`ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-cap-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-cap-macos";

const ADD_RESOURCE: &str = "fetch/add";

/// A blocking agent workload: touch the ready marker, then spin until the host writes the go marker.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// The cap: refuse a `fetch` `tools/call` once two answered calls lie within the last 300 seconds.
const ADD_CAP: &str = r#"@id("cap_add_calls") forbid (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" && context.input.method == "tools/call" }
    when temporal {
      exists (n: Long). (
        (count for (t: Timepoint). where (
          formerly within 300s (
            Box::Action::"mcp:call"::response{ input.server: "fetch", input.method: "tools/call" } && tp(t)
          )
        )) == n
        && n >= 2
      )
    };"#;

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
    name: cn_mcp_tool_cap,
    id:   "CN-MT-02",
    platforms: [Linux, Macos],
    desc: "MCP tool rate cap: a temporal forbid on a contained MCP leaf's tools/call admits the first two calls in its window and refuses the third by its @id",
    run: |b| {
        b.apply_policy(&format!("{SERVER_PERMIT}\n{ADD_CAP}"));
        let add = ("add", r#"{"a":1,"b":1}"#);
        let (out, run) = call_tools(b, &[add, add, add]);
        assert_ran(&out[0], &run, "sum:2");
        assert_ran(&out[1], &run, "sum:2");
        assert_refused(&out[2], "sum:");
        run.assert_forbidden_by("mcp:call", ADD_RESOURCE, "cap_add_calls");
    }
}
