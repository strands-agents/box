use std::path::PathBuf;

use serde_json::{Value, json};
use strands_det_harness::mcp_origin::McpOrigin;
use strands_det_harness::mcp_fixture::box_sibling;
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-MR (remote MCP door: policy on an HTTP MCP server the agent calls)
//
// The agent posts JSON-RPC frames through the box's egress gateway to a loopback HTTP MCP origin
// declared as `[mcp.demo] type = "http"`. The gateway classifies each frame and raises `mcp:call`
// after `http:request`, and a per-tool action after that. A refused frame is answered `403` with a
// JSON-RPC error naming the rule, and never reaches the origin:
// - server permit: `tools/list` and an `echo` call pass and reach the origin;
// - tool-name forbid: a `forbid` on the tool `blocked` refuses it;
// - tool-argument forbid: a `forbid` on `demo::Action::"echo"` when `text == "denied"` refuses that
//   value alone;
// - catalog membership: a tool the accepted `tools/list` does not name exactly, such as `hidden`
//   or `echo ` with a trailing space, is refused under the server permit;
// - absent server permit: with no `mcp:call` permit, a call is refused by default-deny;
// - temporal cap: a temporal `forbid` refuses the third `echo` call once two answered calls lie
//   within 300 seconds.

/// The probe that sends each frame through `HTTPS_PROXY` and prints each reply as one JSON line.
const PROBE_BINARY: &str = "box-egress-probe";

/// Copy the probe into the fixture's exec tree, which `with_exec_tree` grants the agent.
fn place_probe(b: &BoxFixture) -> PathBuf {
    let placed = b.exec_tree().join("det-mcp-remote-probe");
    std::fs::copy(box_sibling(PROBE_BINARY), &placed).expect("copy the egress probe");
    placed
}

/// Declare the origin as the remote server `demo`, and a dormant stdio server so a per-tool rule
/// on `demo` validates against the staged catalog.
fn with_remote_server(b: &BoxFixture, origin: &McpOrigin) -> impl Fn(String) -> String {
    let exec_tree = b.with_exec_tree();
    let tables = format!(
        "\n[mcp.demo]\ntype = \"http\"\ndestinations = [{}]\n\
         [mcp.unused]\ntype = \"stdio\"\ncommand = [\"false\"]\n",
        serde_json::to_string(&origin.authority).unwrap()
    );
    move |config: String| {
        exec_tree(config) + &tables
    }
}

/// Permit the transport to the origin, so every refusal below is an `mcp:call` decision.
fn transport_permit(origin: &McpOrigin) -> String {
    format!(
        r#"@id("origin_connect") permit (principal, action == Box::Action::"net:connect", resource)
    when {{ context.input.port == {port} }};
@id("origin_request") permit (principal, action == Box::Action::"http:request", resource)
    when {{ context.input.port == {port} }};"#,
        port = origin.port()
    )
}

const SERVER_PERMIT: &str = r#"@id("demo_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "demo" };"#;

fn list_frame(id: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

fn call_frame(id: &str, tool: &str, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": {"text": text}}
    })
}

/// Send `frames` in order from inside the box. Returns each reply's `(status, body)` and the run.
fn send(b: &BoxFixture, origin: &McpOrigin, frames: &[Value]) -> (Vec<(u64, Value)>, RunResult) {
    let probe = place_probe(b);
    let requests: Vec<Value> = frames
        .iter()
        .map(|frame| json!({"url": format!("http://{}/mcp", origin.authority), "body": frame}))
        .collect();
    let requests = Value::Array(requests).to_string();
    assert!(!requests.contains('\''), "the frames must quote safely in the shell");
    let run = b.run_sh_with_config(
        with_remote_server(b, origin),
        &format!("{} trace-requests '{requests}'", probe.display()),
    );
    let replies: Vec<(u64, Value)> = run
        .out
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|reply| reply.get("status").is_some())
        .map(|reply| {
            let body = reply["body"].as_str().and_then(|body| serde_json::from_str(body).ok());
            (reply["status"].as_u64().unwrap_or(0), body.unwrap_or(Value::Null))
        })
        .collect();
    assert_eq!(
        replies.len(),
        frames.len(),
        "every frame gets a reply; out=[{}]; decisions: {:?}",
        run.out,
        run.decisions
    );
    (replies, run)
}

fn assert_answered(reply: &(u64, Value), out: &str) {
    assert_eq!(reply.0, 200, "the frame is answered by the origin: {reply:?}; out=[{out}]");
    assert!(reply.1.get("result").is_some(), "{reply:?}");
}

fn assert_refused(reply: &(u64, Value), rule: Option<&str>, out: &str) {
    assert_eq!(reply.0, 403, "the frame is refused: {reply:?}; out=[{out}]");
    assert_eq!(reply.1["error"]["code"], -32001, "{reply:?}");
    if let Some(rule) = rule {
        assert!(
            reply.1["error"]["message"].as_str().unwrap_or("").contains(rule),
            "the refusal names {rule}: {reply:?}"
        );
    }
}

det_case! {
    name: cn_mcp_remote,
    id:   "CN-MR-01",
    platforms: [Linux, Macos],
    desc: "Remote MCP door: an HTTP MCP server the agent calls through the gateway meets mcp:call — a server permit, a tool-name forbid, a tool-argument forbid, default-deny, and a temporal cap each hold, and a refused frame never reaches the origin",
    run: |b| {
        let origin = McpOrigin::start();
        let transport = transport_permit(&origin);

        // Temporal cap first, so no earlier answered call counts toward it.
        b.apply_policy(&format!(
            r#"{transport}
{SERVER_PERMIT}
@id("cap_demo_calls") forbid (principal, action == Box::Action::"mcp:call", resource)
    when {{ context.input.server == "demo" && context.input.method == "tools/call" }}
    when temporal {{
      exists (n: Long). (
        (count for (t: Timepoint). where (
          formerly within 300s (
            Box::Action::"mcp:call"::response{{ input.server: "demo", input.method: "tools/call" }} && tp(t)
          )
        )) == n
        && n >= 2
      )
    }};"#
        ));
        let frames = [
            list_frame("cap-list"),
            call_frame("cap-1", "echo", "one"),
            call_frame("cap-2", "echo", "two"),
            call_frame("cap-3", "echo", "three"),
        ];
        let (replies, run) = send(b, &origin, &frames);
        assert_answered(&replies[0], &run.out);
        assert_answered(&replies[1], &run.out);
        assert_answered(&replies[2], &run.out);
        assert_refused(&replies[3], Some("cap_demo_calls"), &run.out);
        run.assert_forbidden_by("mcp:call", "demo", "cap_demo_calls");
        assert_eq!(origin.calls(), [("echo".into(), "one".into()), ("echo".into(), "two".into())]);
        origin.clear();

        // Server permit, tool-name forbid, and tool-argument forbid.
        b.apply_policy(&format!(
            r#"{transport}
{SERVER_PERMIT}
@id("block_tool") forbid (principal, action == Box::Action::"mcp:call", resource)
    when {{ context.input.server == "demo" && context.input has tool && context.input.tool == "blocked" }};
@id("deny_text") forbid (principal, action == demo::Action::"echo", resource)
    when {{ context.input.text == "denied" }};"#
        ));
        let frames = [
            list_frame("list"),
            call_frame("allowed", "echo", "allowed"),
            call_frame("argument", "echo", "denied"),
            call_frame("name", "blocked", "anything"),
        ];
        let (replies, run) = send(b, &origin, &frames);
        assert_answered(&replies[0], &run.out);
        assert_answered(&replies[1], &run.out);
        assert_eq!(replies[1].1["result"]["content"][0]["text"], "origin:allowed");
        assert_refused(&replies[2], Some("deny_text"), &run.out);
        assert_refused(&replies[3], Some("block_tool"), &run.out);
        run.assert_forbidden_by("mcp:call", "demo", "block_tool");
        assert_eq!(
            origin.calls(),
            [("echo".into(), "allowed".into())],
            "only the permitted call reaches the origin"
        );
        origin.clear();

        // A tool the catalog does not list, and a respelled listed tool, are refused under the
        // server permit.
        b.apply_policy(&format!("{transport}\n{SERVER_PERMIT}"));
        let frames = [
            list_frame("catalog"),
            call_frame("unlisted", "hidden", "x"),
            call_frame("respelled", "echo ", "x"),
        ];
        let (replies, run) = send(b, &origin, &frames);
        assert_answered(&replies[0], &run.out);
        assert_refused(&replies[1], None, &run.out);
        assert_refused(&replies[2], None, &run.out);
        assert!(origin.calls().is_empty(), "no refused call reaches the origin: {:?}", origin.calls());
        origin.clear();

        // No server permit: default-deny refuses the call.
        b.apply_policy(&transport);
        let (replies, run) = send(b, &origin, &[call_frame("default", "echo", "default")]);
        assert_refused(&replies[0], None, &run.out);
        assert!(
            run.decisions.iter().any(|d| d.is_action("mcp:call") && d.denied()),
            "the journal records the default-deny; decisions: {:?}",
            run.decisions
        );
        assert!(origin.calls().is_empty(), "a refused call never reaches the origin");
    }
}
