use std::process::Command;

use strands_det_harness::mcp_fixture::{box_sibling, place_server, server_dir};
use strands_det_harness::{BoxFixture, Platform, RunResult, det_case};

// The native-egress downgrade is auditable: once a `[mcp.<name>.network] contain_egress = false`
// server starts, the box writes one `egress:native` decision naming it to its telemetry,
// `<box_dir>/private/telemetry/records.jsonl`
// (docs/design/decisions.md#native-egress-is-an-operator-declared-leaf-escape). A gateway server
// that starts writes none, and a native-egress server whose start policy refuses writes none either,
// because the decision follows the start and not the declaration. Each run answers one `add` call, so
// a server that started is proven by its answer and one that did not by its refusal.

#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-ne3-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-ne3-macos";

include!("../probes/fetch_server.rs");

fn with_fetch_server(config: String, native: bool) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let mut tables = format!("\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n", quote(FETCH_PROGRAM));
    if native {
        tables.push_str("[mcp.fetch.network]\ncontain_egress = false\n");
    }
    if Platform::current() == Platform::Macos {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}

/// One box, one `add` call. Answers the call's output, the run, and the telemetry lines it added.
fn call_add(b: &BoxFixture, native: bool) -> (String, RunResult, Vec<String>) {
    let socket = b.box_dir().join("run").join("box.sock");
    let client = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let before = b.journal().lines().count();
    let mut output = String::new();
    let meanwhile = || {
        let called = Command::new(&client)
            .arg(&socket)
            .arg(FETCH_PROGRAM)
            .arg("add")
            .arg(r#"{"a":2,"b":3}"#)
            .output()
            .expect("run box-mcp-call-probe");
        output = String::from_utf8_lossy(&called.stdout).into_owned() + &String::from_utf8_lossy(&called.stderr);
    };
    let path = format!("{}:{}", server_dir().display(), std::env::var("PATH").unwrap_or_default());
    let run = b.run_sh_with_config_meanwhile_env(
        |config| with_fetch_server(config, native),
        BLOCK,
        &[("PATH", path.as_str())],
        meanwhile,
    );
    let added = b.journal().lines().skip(before).map(str::to_string).collect();
    (output, run, added)
}

fn native_records(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|line| line.contains("egress:native")).collect()
}

det_case! {
    name: cn_ne_03,
    id:   "CN-NE-03",
    platforms: [Linux, Macos],
    desc: "Native-egress telemetry: a started contain_egress=false MCP server writes one egress:native record naming it to records.jsonl; a started gateway server writes none; a native-egress server refused at start writes none",
    run: |b| {
        b.apply_policy(SERVER_PERMIT);

        let (out, run, lines) = call_add(b, true);
        RunResult::bare(format!("{out}\n[box output]\n{}", run.out), 0).assert_contains("sum:5");
        let records = native_records(&lines);
        assert!(
            !records.is_empty() && records.iter().all(|line| line.contains("\"fetch\"")),
            "the telemetry the run wrote holds no egress:native record naming the server: {lines:#?}"
        );
        run.assert_mediated_permitted("egress:native", "fetch");
        let decisions: Vec<_> = run.decisions.iter().filter(|d| d.is_action("egress:native")).collect();
        assert_eq!(decisions.len(), 1, "one start is one egress:native decision: {decisions:?}");
        assert_eq!(decisions[0].resource, "fetch", "the egress:native decision names another server: {decisions:?}");

        let (out, run, lines) = call_add(b, false);
        RunResult::bare(format!("{out}\n[box output]\n{}", run.out), 0).assert_contains("sum:5");
        assert!(!lines.is_empty(), "DET_ERROR: the gateway run wrote no telemetry at all");
        assert!(native_records(&lines).is_empty(), "a gateway server wrote an egress:native record: {lines:#?}");

        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n@id(\"no_fetch_start\") forbid (principal, action == Box::Action::\"shell:spawn\", resource)\n    when {{ context.input.program == \"{FETCH_PROGRAM}\" }};"
        ));
        let (out, run, lines) = call_add(b, true);
        let refused = RunResult::bare(format!("{out}\n[box output]\n{}", run.out), 0);
        refused.assert_contains("may not start");
        refused.assert_absent("sum:");
        run.assert_forbidden_by("shell:spawn", FETCH_PROGRAM, "no_fetch_start");
        assert!(native_records(&lines).is_empty(), "a server refused at start wrote an egress:native record: {lines:#?}");
    }
}
