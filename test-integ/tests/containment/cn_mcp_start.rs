use std::process::Command;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{
    box_sibling, broker_socket, place_server, with_fetch_server,
};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-MS (MCP start: a stdio server starts only under a `shell:spawn` permit)
//
// The box decides `shell:spawn` on a stdio MCP server's declared program before the process exists.
// A `forbid` on that program refuses the open, the server never runs, and the journal records the
// refusal against the forbid. A start permit alone lets the same server start and answer.

/// The MCP program name (`command[0]`): a unique bare name on the operator PATH, distinct from every other
/// case's name so no two cases copy over one executing file (`ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-ms-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-ms-macos";

/// A blocking agent workload: touch the ready marker, then spin until the host writes the go marker.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// The start permit and the coarse server permit every run carries.
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

/// Forbid the start of the `fetch` server's program.
fn forbid_start() -> String {
    format!(
        r#"@id("no_fetch_start") forbid (principal, action == Box::Action::"shell:spawn", resource)
    when {{ context.input.program == "{FETCH_PROGRAM}" }};"#
    )
}

det_case! {
    name: cn_mcp_start,
    id:   "CN-MS-01",
    platforms: [Linux, Macos],
    desc: "MCP start: a stdio MCP server starts only under a shell:spawn permit — a forbid on its program refuses the open and the server never runs, while the box keeps running",
    run: |b| {
        // Control: the start permit lets the server start, and its tool answers.
        b.apply_policy(SERVER_PERMIT);
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#)]);
        assert!(out[0].contains("sum:5"), "a permitted start answers; out=[{}]", out[0]);
        assert!(
            run.decisions
                .iter()
                .any(|d| d.is_action("shell:spawn") && d.resource.contains(FETCH_PROGRAM) && !d.denied()),
            "the journal records the permitted start; decisions: {:?}",
            run.decisions
        );

        // A forbid on the program refuses the start, even beside a permit for every start.
        b.apply_policy(&format!("{SERVER_PERMIT}\n{}", forbid_start()));
        let (out, run) = call_tools(b, &[("add", r#"{"a":2,"b":3}"#)]);
        assert!(
            out[0].contains("may not start") && !out[0].contains("sum:"),
            "a forbidden start refuses the open and no tool runs; out=[{}]",
            out[0]
        );
        run.assert_forbidden_by("shell:spawn", FETCH_PROGRAM, "no_fetch_start");
        assert!(
            !run.decisions.iter().any(|d| d.is_action("mcp:call") && d.resource == "fetch/add"),
            "no tool call reaches policy for a server that never started; decisions: {:?}",
            run.decisions
        );
        assert_eq!(run.rc, 0, "the box keeps running and exits normally; out=[{}]", run.out);
    }
}
