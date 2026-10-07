use std::process::Command;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{
    box_sibling, broker_socket, place_server, with_fetch_server,
};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-MD (MCP discovery degrade: a denied tools/list fails closed)
//
// A `forbid` on a server's `tools/list` stops the box from accepting that server's tool catalog.
// The server degrades rather than taking the box down: the box keeps running and exits normally, and
// every `tools/call` to that server fails closed with the catalog refusal, so no tool runs. A tool
// rule does not reopen a degraded server: a tool-argument `forbid` is a refinement, and the call is
// refused before it is judged.

/// The MCP program name (`command[0]`): a unique bare name on the operator PATH, distinct from every other
/// case's name so no two cases copy over one executing file (`ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-md-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-md-macos";

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

/// The broker's refusal for a call to a server whose catalog was not accepted.
const CATALOG_REFUSAL: &str = "the MCP tool catalog is not accepted";

/// Forbid the `fetch` server's `tools/list`.
const BLOCK_LIST: &str = r#"@id("block_fetch_list") forbid (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" && context.input.method == "tools/list" };"#;

/// Assert the denied list degrades the server: the list is refused by its forbid, each call fails
/// closed with the catalog refusal and no tool result, and the box itself exits normally.
fn assert_degraded(outputs: &[String], run: &RunResult, tools: &[&str]) {
    run.assert_forbidden_by("mcp:call", "fetch/tools/list", "block_fetch_list");
    for (output, tool) in outputs.iter().zip(tools) {
        assert!(
            output.contains("-32003")
                && output.contains(CATALOG_REFUSAL)
                && !output.contains("sum:")
                && !output.contains("fetch"),
            "a call to the degraded server fails closed with the catalog refusal; tool {tool}, out=[{output}]"
        );
        assert!(
            run.decisions.iter().any(|d| d.is_action("mcp:call")
                && d.resource == format!("fetch/{tool}")
                && d.denied()
                && d.reason == CATALOG_REFUSAL),
            "the journal records the fail-closed refusal of {tool}; decisions: {:?}",
            run.decisions
        );
    }
    assert_eq!(
        run.rc, 0,
        "the box keeps running and exits normally; out=[{}]",
        run.out
    );
}

det_case! {
    name: cn_mcp_list_degrade,
    id:   "CN-MD-01",
    platforms: [Linux, Macos],
    desc: "MCP discovery degrade: a forbid on a server's tools/list degrades that server — every tools/call fails closed with the catalog refusal while the box keeps running — and a tool-argument rule does not reopen it",
    run: |b| {
        // Degrade: the list is refused, and both tools fail closed.
        b.apply_policy(&format!("{SERVER_PERMIT}\n{BLOCK_LIST}"));
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#), ("reach", "{}")]);
        assert_degraded(&out, &run, &["add", "reach"]);

        // A tool-argument forbid on the same server does not reopen it: an argument it admits is
        // still refused with the catalog refusal.
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n{BLOCK_LIST}\n@id(\"forbid_add_large_a\") forbid (principal, action == fetch::Action::\"add\", resource)\n    when {{ context.input has a && context.input.a > 100 }};"
        ));
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#)]);
        assert_degraded(&out, &run, &["add"]);
    }
}
