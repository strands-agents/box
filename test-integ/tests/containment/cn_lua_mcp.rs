use std::process::Command;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{
    box_sibling, broker_socket, place_server, with_fetch_server,
};
use strands_det_harness::{BoxFixture, RunResult, det_case, sh_quote};

// The Lua-to-MCP tool bridge.
//
// With a live `fetch` server that the broker serves, the hosted Shell's Lua has no `fetch` module,
// so no Lua script can call the server's tools.

#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-lua-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-lua-macos";

const PERMITS: &str = r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
@id("fetch_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" };"#;

const LUA: &str = r#"print("HAS_REQUIRE=" .. tostring(type(require) == "function"))
local ok, m = pcall(require, "fetch")
print("REQ=" .. tostring(ok))
print("LOADED=" .. tostring(package.loaded["fetch"] ~= nil))
if ok then print("LUA_SUM=" .. tostring(m.add({a = 1, b = 1}))) end"#;

/// Run the Lua attempt in the hosted Shell, then hold the box open while the broker serves one real
/// `add` call. Returns the broker call's output and the run.
fn lua_then_broker_call(b: &BoxFixture) -> (String, RunResult) {
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let shell = format!("echo DET_MEDIATED; lua -e {}", sh_quote(LUA));
    let cmd = format!(
        "zsh -lc {}; : > .det-ready; while [ ! -e .det-go ]; do :; done",
        sh_quote(&shell)
    );
    let mut broker = String::new();
    let meanwhile = || {
        let output = Command::new(&probe)
            .arg(&socket)
            .arg(FETCH_PROGRAM)
            .arg("add")
            .arg(r#"{"a":1,"b":1}"#)
            .output()
            .expect("run box-mcp-call-probe");
        broker = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
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
            &cmd,
            &[("PATH", path.as_str())],
            meanwhile,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let run = b.run_sh_with_config_meanwhile(
        |config| with_fetch_server(config, FETCH_PROGRAM),
        &cmd,
        meanwhile,
    );
    (broker, run)
}

det_case! {
    name: cn_lua_mcp,
    id:   "CN-LUA-MCP",
    platforms: [Linux, Macos],
    desc: "No Lua MCP bridge: with a live fetch server the broker serves, the hosted Shell's Lua has no fetch module and its tool call never runs",
    run: |b| {
        b.apply_policy(PERMITS);
        let (broker, run) = lua_then_broker_call(b);
        RunResult::bare(format!("{broker}\n[box output]\n{}", run.out), 0).assert_contains("sum:2");
        run.assert_contains("DET_MEDIATED");
        assert!(
            run.decisions
                .iter()
                .any(|d| d.is_action("shell:exec") && d.resource == "lua" && d.permitted()),
            "lua must run as the hosted Shell's own command; out=[{}]",
            run.snippet()
        );
        assert!(
            !run.decisions
                .iter()
                .any(|d| d.is_action("shell:spawn") && d.resource.ends_with("/lua")),
            "lua must not run as a host binary; out=[{}]",
            run.snippet()
        );
        run.assert_contains("HAS_REQUIRE=true");
        run.assert_contains("REQ=false");
        run.assert_contains("LOADED=false");
        run.assert_absent("LUA_SUM=");
    }
}
