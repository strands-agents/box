use std::process::Command;

use strands_det_harness::egress::{HostRecorder, RECORDER_BODY};
use strands_det_harness::mcp_fixture::{box_sibling, place_server, server_dir};
use strands_det_harness::{BoxFixture, Platform, RunResult, det_case, sh_quote};

// Every leaf gets every egress route as a phantom
// (docs/design/decisions.md#the-box-is-the-credential-boundary). One `[egress.r]` route reads its
// secret from `env://DET_ME02_SECRET`, which only the environment of `strands-box run` holds. A tool
// leaf and a stdio MCP leaf each hold the route's phantom under that name, and the MCP leaf's is the
// agent's own for that run; neither holds the real value. Both leaves reach a host recorder that no
// route names through the gateway, which is the control. A plaintext request to the route's own
// recorder is refused by the gateway before it leaves ("credential not permitted on a plaintext
// request"), so that recorder receives no byte, neither the phantom nor the secret. The box trusts no
// fixture CA upstream, so this suite cannot observe the secret on a TLS wire.

#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-me2-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-me2-macos";

const VARIABLE: &str = "DET_ME02_SECRET";
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

include!("../probes/fetch_server.rs");

fn policy(ports: [u16; 2]) -> String {
    let [route, open] = ports;
    format!(
        r#"@id("leaf_start") permit (principal, action == Box::Action::"shell:spawn", resource);
@id("fetch_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when {{ context.input.server == "fetch" }};
@id("recorder_connect") permit (principal, action == Box::Action::"net:connect", resource)
    when {{ context.input.host == "127.0.0.1" && (context.input.port == {route} || context.input.port == {open}) }};
@id("recorder_request") permit (principal, action == Box::Action::"http:request", resource)
    when {{ context.input.host == "127.0.0.1" && (context.input.port == {route} || context.input.port == {open}) }};"#
    )
}

/// The route, the tool, and the proxy-aware MCP server, all in one configuration.
fn configuration(config: String, port: u16, probe: &std::path::Path, mcp_target: &str) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let mut text = format!(
        "{config}\n[egress.r]\ndestinations = [\"127.0.0.1:{port}\"]\nsecret.ref = \"env://{VARIABLE}\"\n\
         secret.inject = \"always\"\n\n[tool.me02]\ncommand = [{}]\n\n\
         [mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.env]\nFIXTURE_FETCH_PROXY = \"1\"\n\
         FIXTURE_FETCH_TARGET = {}\n",
        quote(&probe.to_string_lossy()),
        quote(FETCH_PROGRAM),
        quote(mcp_target),
    );
    if Platform::current() == Platform::Macos {
        let dir = quote(&server_dir().display().to_string());
        text.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    text
}

/// One `tools/call` per `(tool, arguments)`, while the agent holds the box up.
fn call_tools(b: &BoxFixture, edit: impl FnOnce(String) -> String, env: &[(&str, &str)], calls: &[(&str, &str)]) -> (Vec<String>, RunResult) {
    let socket = b.box_dir().join("run").join("box.sock");
    let client = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut outputs = Vec::new();
    let meanwhile = || {
        for (tool, arguments) in calls {
            let output = Command::new(&client)
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
    let run = b.run_sh_with_config_meanwhile_env(
        edit,
        &format!("printf 'AGENT_PHANTOM=%s\\n' \"${VARIABLE}\"; : > .det-ready; while [ ! -e .det-go ]; do :; done"),
        env,
        meanwhile,
    );
    (outputs, run)
}

fn phantom_of<'a>(out: &'a str, prefix: &str) -> &'a str {
    out.lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or_else(|| panic!("DET_ERROR: no {prefix:?} line; out=[{out}]"))
}

det_case! {
    name: cn_me_02,
    id:   "CN-ME-02",
    platforms: [Linux, Macos],
    desc: "Leaf phantoms: a tool leaf and a stdio MCP leaf each hold the env:// route's phantom and never the real secret; each reaches an unrouted recorder through the gateway, and the gateway refuses their plaintext request to the route, so its recorder receives no byte",
    run: |b| {
        let route = HostRecorder::start();
        let open = HostRecorder::start();
        route.self_test();
        open.self_test();
        let (route_port, open_port) = (route.port(), open.port());
        let real = format!("DET_REAL_SECRET_ME02_{}", std::process::id());
        let probe = b.compile_probe("leafprobe-me02", PROBE);
        b.apply_policy(&policy([route_port, open_port]));
        let path = format!("{}:{}", server_dir().display(), std::env::var("PATH").unwrap_or_default());
        let env = [(VARIABLE, real.as_str()), ("PATH", path.as_str())];
        let open_url = |leaf: &str| format!("http://127.0.0.1:{open_port}/cn-me02-{leaf}");
        let route_url = |leaf: &str| format!("http://127.0.0.1:{route_port}/cn-me02-{leaf}");
        let refusal = "credential not permitted on a plaintext request";

        // The MCP leaf, pointed at the unrouted recorder: it holds the run's phantom, and it reaches.
        let name_argument = serde_json::json!({ "name": VARIABLE }).to_string();
        let target = open_url("mcp");
        let (out, run) = call_tools(
            b,
            |config| configuration(config, route_port, &probe, &target),
            &env,
            &[("env", name_argument.as_str()), ("reach", "{}")],
        );
        RunResult::bare(format!("{}\n{}\n[box output]\n{}", out[0], out[1], run.out), 0)
            .assert_absent_secret(&real, "CN-ME-02 real secret (MCP leaf)");
        let agent_phantom = phantom_of(&run.out, "AGENT_PHANTOM=");
        assert!(agent_phantom.starts_with("strands_box_"), "the agent holds no minted phantom: {agent_phantom:?}");
        let mcp_phantom = phantom_of(&out[0], "env:").to_string();
        assert_eq!(mcp_phantom, agent_phantom, "the MCP leaf does not hold the run's phantom");
        assert!(out[1].contains(&format!("fetched:{RECORDER_BODY}")), "the MCP leaf did not reach the unrouted recorder; out=[{}]", out[1]);

        // The MCP leaf, pointed at the route's recorder: the gateway refuses the plaintext request.
        let target = route_url("mcp");
        let (out, run) = call_tools(
            b,
            |config| configuration(config, route_port, &probe, &target),
            &env,
            &[("reach", "{}")],
        );
        let refused = RunResult::bare(format!("{}\n[box output]\n{}", out[0], run.out), 0);
        refused.assert_absent_secret(&real, "CN-ME-02 real secret (MCP leaf, route)");
        refused.assert_contains("fetch-failed:HTTP/1.1 403");
        refused.assert_contains(refusal);

        // The tool leaf: its phantom, an unrouted request that reaches, a routed one that is refused.
        let p = sh_quote(&probe.to_string_lossy());
        let (open_tool, route_tool) = (open_url("tool"), route_url("tool"));
        let r = b.run_mediated_with_config_env(
            |config| configuration(config, route_port, &probe, &open_url("mcp")),
            &format!(
                "{p} env {VARIABLE}; {p} fetch {} DET_ME02_UNSET; {p} fetch {} {VARIABLE}",
                sh_quote(&open_tool), sh_quote(&route_tool)
            ),
            &env,
        );
        r.assert_mediated_permitted("shell:spawn", "leafprobe-me02");
        r.assert_absent_secret(&real, "CN-ME-02 real secret (tool leaf)");
        let tool_phantom = phantom_of(&r.out, &format!("ENV_SET \"{VARIABLE}\" value=")).to_string();
        assert!(tool_phantom.starts_with("strands_box_"), "the tool leaf holds no minted phantom: {tool_phantom:?}");
        r.assert_contains(&format!("FETCH_STATUS \"{open_tool}\" status=200 :: {RECORDER_BODY}"));
        r.assert_contains(&format!("FETCH_STATUS \"{route_tool}\" status=403 :: {refusal}"));

        // The wire: the unrouted recorder got both leaves' requests with no phantom and no secret, and
        // the route's recorder received no byte.
        let seen = open.snapshot();
        for leaf in ["mcp", "tool"] {
            let wanted = format!("/cn-me02-{leaf}");
            let request = seen.requests().into_iter()
                .find(|r| r.lines().next().is_some_and(|l| l.contains(&wanted)))
                .unwrap_or_else(|| panic!("the unrouted recorder did not receive {wanted}: {:?}", seen.request_lines()));
            assert!(!request.contains(&real), "the request for {wanted} carried the real secret to an unrouted host");
            assert!(!request.contains("strands_box_"), "the request for {wanted} carried a phantom to the wire");
        }
        let route_seen = route.snapshot();
        assert!(
            route_seen.bytes() == 0 && route_seen.request_lines().is_empty(),
            "the route's recorder received bytes over plaintext: {:?}", route_seen
        );
    }
}
