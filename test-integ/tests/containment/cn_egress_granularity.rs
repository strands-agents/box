use std::process::Command;

use strands_det_harness::egress::{GATEWAY_ORIGIN_HEADER, HostRecorder, RECORDER_BODY};
#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{box_sibling, broker_socket, place_server};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-EG (egress granularity: L4 and L7 policy on a contained MCP leaf)
//
// The companion to CN-ME-01, on the same plumbing: the proxy-aware `box-mcp-fetch-server` sends a
// GET through the box's egress gateway to a loopback `HostRecorder`. CN-ME-01 proves the permit and
// the default-deny. This case proves three finer controls, each against its own recorder so no run
// can feed another's temporal count:
// - L7 path: `http:request` is permitted to recorder A, and a `forbid` on the path `/blocked*`
//   refuses that path alone. The recorder sees `/ok` and never `/blocked`.
// - L4 forbid over a permit: `net:connect` is permitted to every loopback port, and a `forbid` on
//   recorder B's port refuses the connect. Deny overrides the permit, and B is never contacted.
// - L7 method: `http:request` is permitted to recorder D, and a `forbid` on `POST` refuses that
//   method alone. D sees the GET and never the POST.
// - L4 host forbid: `net:connect` is permitted to recorder E's port for any host, and a `forbid` on
//   the host `localhost` refuses that spelling alone, before any connect. `127.0.0.1` still reaches E.
// - L7 temporal cap: `http:request` is permitted to recorder C, and a temporal `forbid` refuses the
//   third request once two responses from C lie within 300 seconds. C sees exactly two requests.

/// The MCP program name (`command[0]`), a UNIQUE bare name on the box's operator PATH — same
/// placement rationale and per-platform split as CN-NE-01 (see `server_dir`). Distinct from
/// CN-NE-01's name so the two cases never contend on ONE file (copying over a binary another case's
/// leaf is still executing fails with `ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-eg-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-eg-macos";

/// A blocking agent workload (pure bash builtins, needs no `shell:spawn`): touch the ready marker,
/// then spin until the host writes the go marker, so the box stays up for `meanwhile`.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// The coarse server permit every run carries.
const SERVER_PERMIT: &str = r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
permit (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" };"#;

/// Permit the connect and the request to one loopback `port`.
fn permit_port(port: u16) -> String {
    format!(
        r#"permit (principal, action == Box::Action::"net:connect", resource)
    when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};
permit (principal, action == Box::Action::"http:request", resource)
    when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};"#
    )
}

/// Add the `fetch` MCP server in its DEFAULT (gateway) posture, proxy-aware, pointed at `url`.
fn with_fetch_server(config: String, url: &str, method: &str) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.env]\nFIXTURE_FETCH_PROXY = \"1\"\nFIXTURE_FETCH_TARGET = {}\nFIXTURE_FETCH_METHOD = {}\n",
        quote(FETCH_PROGRAM),
        quote(url),
        quote(method),
    );
    // macOS Seatbelt reads the binary in place, so the leaf needs read+exec of the server dir (Linux
    // needs neither — /usr/bin binds and the baseline exec grant covers it).
    #[cfg(target_os = "macos")]
    {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}

/// Spawn one box with the proxy-aware `fetch` server pointed at `url`, and drive `times` sequential
/// `tools/call`s with the request `method`. Returns each call's probe output and the run.
fn call_reach(b: &BoxFixture, url: &str, times: usize, method: &str) -> (Vec<String>, RunResult) {
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut outputs = Vec::new();
    let edit = |config| with_fetch_server(config, url, method);
    let meanwhile = || {
        for _ in 0..times {
            let output = Command::new(&probe)
                .arg(&socket)
                .arg(FETCH_PROGRAM)
                .arg("reach")
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
        b.run_sh_with_config_meanwhile_env(edit, BLOCK, &[("PATH", path.as_str())], meanwhile)
    };
    #[cfg(not(target_os = "macos"))]
    let run = b.run_sh_with_config_meanwhile(edit, BLOCK, meanwhile);
    (outputs, run)
}

/// Assert a probe output is the recorder's body, fetched through the gateway.
fn assert_fetched(output: &str, run: &RunResult) {
    RunResult::bare(format!("{output}\n[box output]\n{}", run.out), 0)
        .assert_contains(&format!("fetched:{RECORDER_BODY}"));
}

/// Assert a probe output is the gateway's policy refusal.
fn assert_refused(output: &str) {
    assert!(
        output.contains("fetch-failed")
            && output.contains("403")
            && output.contains(&format!("{GATEWAY_ORIGIN_HEADER}: refused")),
        "the gateway must refuse with the authority's 403; out=[{output}]"
    );
}

det_case! {
    name: cn_egress_granularity,
    id:   "CN-EG-01",
    platforms: [Linux, Macos],
    desc: "Egress granularity: on a contained MCP leaf's gateway egress, a path forbid refuses one L7 path, a method forbid refuses one L7 method, an L4 port forbid and an L4 host forbid each override a connect permit, and a temporal forbid caps L7 requests to one host",
    run: |b| {
        // L7 path: `/ok` passes and `/blocked` is refused by the path forbid.
        let a = HostRecorder::start();
        a.self_test();
        let pa = a.port();
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n{}\n@id(\"forbid_blocked_path\") forbid (principal, action == Box::Action::\"http:request\", resource)\n    when {{ context.input.host == \"127.0.0.1\" && context.input.port == {pa} && context.input.path like \"/blocked*\" }};",
            permit_port(pa)
        ));
        let (ok_out, ok_run) = call_reach(b, &format!("http://127.0.0.1:{pa}/ok"), 1, "GET");
        assert_fetched(&ok_out[0], &ok_run);
        let (blocked_out, blocked_run) = call_reach(b, &format!("http://127.0.0.1:{pa}/blocked"), 1, "GET");
        assert_refused(&blocked_out[0]);
        blocked_run.assert_forbidden_by("http:request", &format!("127.0.0.1:{pa}/blocked"), "forbid_blocked_path");
        let seen = a.snapshot().request_lines();
        assert!(
            seen.iter().any(|line| line.contains("/ok")) && !seen.iter().any(|line| line.contains("/blocked")),
            "recorder A sees /ok and never /blocked: {seen:?}"
        );

        // L4 forbid over a permit: every loopback port may connect, but recorder B's port is forbidden.
        let rb = HostRecorder::start();
        rb.self_test();
        let pb = rb.port();
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\npermit (principal, action == Box::Action::\"net:connect\", resource)\n    when {{ context.input.host == \"127.0.0.1\" }};\n@id(\"forbid_port_b\") forbid (principal, action == Box::Action::\"net:connect\", resource)\n    when {{ context.input.port == {pb} }};"
        ));
        let (port_out, port_run) = call_reach(b, &format!("http://127.0.0.1:{pb}/b"), 1, "GET");
        assert_refused(&port_out[0]);
        port_run.assert_forbidden_by("net:connect", &format!("127.0.0.1:{pb}"), "forbid_port_b");
        assert!(
            rb.snapshot().observations.is_empty(),
            "recorder B is never contacted: {:?}",
            rb.snapshot()
        );

        // L7 method: GET passes and POST is refused by the method forbid.
        let d = HostRecorder::start();
        d.self_test();
        let pd = d.port();
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n{}\n@id(\"forbid_post\") forbid (principal, action == Box::Action::\"http:request\", resource)\n    when {{ context.input.host == \"127.0.0.1\" && context.input.port == {pd} && context.input.method == \"POST\" }};",
            permit_port(pd)
        ));
        let (get_out, get_run) = call_reach(b, &format!("http://127.0.0.1:{pd}/d"), 1, "GET");
        assert_fetched(&get_out[0], &get_run);
        let (post_out, post_run) = call_reach(b, &format!("http://127.0.0.1:{pd}/d"), 1, "POST");
        assert_refused(&post_out[0]);
        post_run.assert_forbidden_by("http:request", &format!("127.0.0.1:{pd}"), "forbid_post");
        let d_seen = d.snapshot().request_lines();
        assert!(
            d_seen.iter().any(|line| line.starts_with("GET")) && !d_seen.iter().any(|line| line.starts_with("POST")),
            "recorder D sees the GET and never the POST: {d_seen:?}"
        );

        // L4 host forbid: the same port is reached through `127.0.0.1` and refused through `localhost`.
        let e = HostRecorder::start();
        e.self_test();
        let pe = e.port();
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\npermit (principal, action == Box::Action::\"net:connect\", resource)\n    when {{ context.input.port == {pe} }};\npermit (principal, action == Box::Action::\"http:request\", resource)\n    when {{ context.input.port == {pe} }};\n@id(\"forbid_localhost\") forbid (principal, action == Box::Action::\"net:connect\", resource)\n    when {{ context.input.host == \"localhost\" }};"
        ));
        let (ip_out, ip_run) = call_reach(b, &format!("http://127.0.0.1:{pe}/e"), 1, "GET");
        assert_fetched(&ip_out[0], &ip_run);
        let (name_out, name_run) = call_reach(b, &format!("http://localhost:{pe}/e"), 1, "GET");
        assert_refused(&name_out[0]);
        name_run.assert_forbidden_by("net:connect", &format!("localhost:{pe}"), "forbid_localhost");
        let e_seen = e.snapshot().request_lines();
        assert_eq!(e_seen.len(), 1, "recorder E sees only the 127.0.0.1 request: {e_seen:?}");

        // L7 temporal cap: two responses from recorder C, then the third request is refused.
        let c = HostRecorder::start();
        c.self_test();
        let pc = c.port();
        b.apply_policy(&format!(
            "{SERVER_PERMIT}\n{}\n@id(\"cap_recorder_c\") forbid (principal, action == Box::Action::\"http:request\", resource)\n    when {{ context.input.host == \"127.0.0.1\" && context.input.port == {pc} }}\n    when temporal {{\n      exists (n: Long). (\n        (count for (t: Timepoint). where (\n          formerly within 300s (\n            Box::Action::\"http:request\"::response{{ input.host: \"127.0.0.1\", input.port: {pc} }} && tp(t)\n          )\n        )) == n\n        && n >= 2\n      )\n    }};",
            permit_port(pc)
        ));
        let (cap_out, cap_run) = call_reach(b, &format!("http://127.0.0.1:{pc}/c"), 3, "GET");
        assert_fetched(&cap_out[0], &cap_run);
        assert_fetched(&cap_out[1], &cap_run);
        assert_refused(&cap_out[2]);
        cap_run.assert_forbidden_by("http:request", &format!("127.0.0.1:{pc}"), "cap_recorder_c");
        let c_seen = c.snapshot().request_lines();
        assert_eq!(c_seen.len(), 2, "recorder C sees exactly the two admitted requests: {c_seen:?}");
    }
}
