use std::process::Command;

use strands_det_harness::egress::{GATEWAY_ORIGIN_HEADER, HostRecorder, RECORDER_BODY};
#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{box_sibling, broker_socket, place_server};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-ME (MCP egress through the gateway: the DEFAULT posture, policy-gated)
//
// The companion to CN-NE-01. There, a `contain_egress = false` MCP leaf joins the host network and
// reaches an un-proxied endpoint. Here, a DEFAULT (gateway) MCP leaf — a *proxy-aware* server that
// honors `$HTTPS_PROXY` — has its outbound HTTP mediated by the box's egress gateway and gated by
// policy, exactly as the agent's own egress is (PO-13), but driven from a contained MCP leaf. This
// is the first time an MCP leaf's gateway egress is exercised on Linux.
//
// The same one-binary server (`box-mcp-fetch-server`) runs in its proxy-aware mode
// (`FIXTURE_FETCH_PROXY` set): it connects to the proxy in `$HTTPS_PROXY` (the box points it at the
// gateway; on Linux the port is teleported into the leaf's routeless namespace) and sends an
// absolute-URI GET. Two host-owned recorders stand on loopback where the gateway forwards a
// permitted request. Policy permits `net:connect` + `http:request` to the FIRST recorder only. The
// gateway forwards the permitted request there (the tool returns `fetched:<recorder body>`, the
// recorder logs the GET, the journal holds the permit) and refuses the second as a policy deny (the
// tool returns the gateway's `403 Forbidden` carrying the `x-strands-box-egress: refused` marker,
// the recorder is never contacted, the journal holds the deny).
//
// The client is `box-mcp-call-probe`, driving one `tools/call` over the broker socket per target.

/// The MCP program name (`command[0]`), a UNIQUE bare name on the box's operator PATH — same
/// placement rationale and per-platform split as CN-NE-01 (see `server_dir`). Distinct from
/// CN-NE-01's name so the two cases never contend on ONE file (copying over a binary another case's
/// leaf is still executing fails with `ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-gw-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-gw-macos";

/// A blocking agent workload (pure bash builtins, needs no `shell:spawn`): touch the ready marker,
/// then spin until the host writes the go marker, so the box stays up for `meanwhile`.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// Permit the `tools/call` this case makes, and the gateway egress to the ALLOWED recorder only.
/// The DENIED recorder gets no `net:connect`/`http:request` permit, so the gateway default-denies it.
fn policy(allowed_port: u16) -> String {
    format!(
        r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
permit (principal, action == Box::Action::"mcp:call", resource)
           when {{ context.input.server == "fetch" }};

           permit (principal, action == fetch::Action::"reach", resource);

           @id("recorder_connect") permit (principal, action == Box::Action::"net:connect", resource)
           when {{ context.input.host == "127.0.0.1" && context.input.port == {allowed_port} }};

           @id("recorder_request") permit (principal, action == Box::Action::"http:request", resource)
           when {{ context.input.host == "127.0.0.1" && context.input.port == {allowed_port} }};"#
    )
}

/// Add the `fetch` MCP server in its DEFAULT (gateway) posture, proxy-aware, pointed at `url`.
fn with_fetch_server(config: String, url: &str) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.env]\nFIXTURE_FETCH_PROXY = \"1\"\nFIXTURE_FETCH_TARGET = {}\n",
        quote(FETCH_PROGRAM),
        quote(url),
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

/// Spawn the box with the proxy-aware `fetch` server pointed at `url` and drive one `tools/call`.
/// Returns the probe's combined output and the whole `RunResult` (its `decisions` carry the
/// gateway's `net:connect`/`http:request` journal).
fn call_reach(b: &BoxFixture, url: &str) -> (String, RunResult) {
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut probe_output = String::new();
    let edit = |config| with_fetch_server(config, url);
    let meanwhile = || {
        let output = Command::new(&probe)
            .arg(&socket)
            .arg(FETCH_PROGRAM)
            .arg("reach")
            .output()
            .expect("run box-mcp-call-probe");
        probe_output = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
    };
    // macOS: inject the server dir onto the box's operator PATH (it is not on the default PATH).
    // Linux: /usr/bin is already on PATH.
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
    (probe_output, run)
}

det_case! {
    name: cn_mcp_gateway_egress,
    id:   "CN-ME-01",
    platforms: [Linux, Macos],
    desc: "Gateway-mediated MCP egress: a default (gateway) proxy-aware MCP leaf reaches a policy-permitted loopback recorder through the gateway and is refused at a policy-denied one by the authority's 403; the denied recorder is never contacted",
    run: |b| {
        let allowed = HostRecorder::start();
        let denied = HostRecorder::start();
        allowed.self_test();
        denied.self_test();
        let (allowed_port, denied_port) = (allowed.port(), denied.port());
        b.apply_policy(&policy(allowed_port));

        // Permitted destination: the gateway forwards to the recorder, so the tool returns the
        // recorder's body, the recorder logs the one GET, and the journal holds the permit.
        let allowed_url = format!("http://127.0.0.1:{allowed_port}/cn-me-allowed");
        let (allowed_out, allowed_run) = call_reach(b, &allowed_url);
        RunResult::bare(
            format!("{allowed_out}\n[box output]\n{}", allowed_run.out),
            0,
        )
        .assert_contains(&format!("fetched:{RECORDER_BODY}"));
        allowed_run.assert_mediated_permitted("net:connect", &format!("127.0.0.1:{allowed_port}"));
        allowed_run.assert_mediated_permitted("http:request", &format!("127.0.0.1:{allowed_port}"));
        let allowed_seen = allowed.snapshot();
        assert!(
            allowed_seen
                .request_lines()
                .iter()
                .any(|line| line.contains("/cn-me-allowed")),
            "the permitted recorder received the forwarded GET: {allowed_seen:?}"
        );

        // Denied destination: the gateway refuses at policy — the tool carries the authority's 403
        // and its `x-strands-box-egress: refused` marker, the journal holds the deny, and the
        // recorder is never contacted.
        let denied_url = format!("http://127.0.0.1:{denied_port}/cn-me-denied");
        let (denied_out, denied_run) = call_reach(b, &denied_url);
        RunResult::bare(
            format!("{denied_out}\n[box output]\n{}", denied_run.out),
            0,
        )
        .assert_contains("fetch-failed");
        assert!(
            denied_out.contains("403") && denied_out.contains(&format!("{GATEWAY_ORIGIN_HEADER}: refused")),
            "the denied destination is refused by the authority's 403 naming the marker; out=[{denied_out}]"
        );
        denied_run.assert_mediated_denied("net:connect", &format!("127.0.0.1:{denied_port}"));
        let denied_seen = denied.snapshot();
        assert!(
            denied_seen.observations.is_empty(),
            "the denied destination was never contacted: {denied_seen:?}"
        );
    }
}
