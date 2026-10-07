use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

#[cfg(target_os = "macos")]
use strands_det_harness::mcp_fixture::server_dir;
use strands_det_harness::mcp_fixture::{box_sibling, broker_socket, place_server};
use strands_det_harness::{BoxFixture, RunResult, det_case};

// Containment CN-NE (native egress: the operator's `contain_egress = false` trust grant)
//
// A stdio MCP server declared `[mcp.fetch.network] contain_egress = false` runs its contained leaf in
// the HOST network namespace (Linux side of
// docs/design/decisions.md#native-egress-is-an-operator-declared-leaf-escape), so it reaches a
// host endpoint the box never proxied. The same server without the escape runs in a private,
// routeless network namespace and cannot. The endpoint is a throwaway HTTP listener bound on the
// host's loopback — outside any box — so reaching it is proof of real egress: a routeless leaf's
// `127.0.0.1` is its own empty namespace, while a host-network leaf's `127.0.0.1` is the host's.
// The server is one self-contained binary (`box-mcp-fetch-server`) that execs nothing else, so the
// leaf needs only the one exec grant every profile carries — no broad exec (a currently-missing
// Linux-leaf feature). The client is `box-mcp-call-probe`, which drives one `tools/call` over the
// broker socket.

const BODY: &str = "STRANDS_NATIVE_EGRESS_OK";

/// The MCP program name (`command[0]`), a UNIQUE bare name resolved on the box's operator PATH,
/// placed in a directory that is on the PATH and NOT agent-writable (so the box accepts it as the
/// MCP search path). Per platform (see [`server_dir`]):
/// - **Linux:** copied to `/usr/bin/<this>` — world-accessible + binds into the leaf's mount view.
/// - **macOS:** copied to a test-owned dir injected onto the box PATH, with a read+exec grant
///   (Seatbelt reads the binary in place; there is no mount view to bind).
/// The name differs from `FETCH_BINARY` so it never collides with the built copy in `target/`.
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-macos";

/// A blocking agent workload: touch the ready marker, then spin until the host writes the go marker.
/// Pure bash builtins, so it needs no `shell:spawn` — the box stays up for `meanwhile`.
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// Permit the one `tools/call` this case makes: the `mcp:call` door for the `fetch` server and the
/// `reach` tool's own action.
fn mcp_call_policy() -> &'static str {
    r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
permit (principal, action == Box::Action::"mcp:call", resource)
       when { context.input.server == "fetch" };

       permit (principal, action == fetch::Action::"reach", resource);"#
}

/// A throwaway HTTP/1.0 listener on the host's loopback answering every request with [`BODY`]. Kept
/// alive by the returned `TcpListener`; the accept loop ends when the process exits.
fn host_endpoint() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a host endpoint");
    let url = format!(
        "http://{}/",
        listener.local_addr().expect("endpoint address")
    );
    let accepting = listener
        .try_clone()
        .expect("clone the host endpoint listener");
    thread::spawn(move || {
        for stream in accepting.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut scratch = [0u8; 1024];
            let _ = stream.read(&mut scratch);
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                BODY.len(),
                BODY
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (url, listener)
}

/// Add the `fetch` MCP server to the box config, optionally with the native-egress escape, pointed at
/// `url` through the environment.
fn with_fetch_server(config: String, native_egress: bool, url: &str) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n",
        quote(FETCH_PROGRAM)
    );
    if native_egress {
        tables.push_str("[mcp.fetch.network]\ncontain_egress = false\n");
    }
    tables.push_str(&format!(
        "[mcp.fetch.env]\nFIXTURE_FETCH_TARGET = {}\n",
        quote(url)
    ));
    // macOS Seatbelt reads the binary in place (no mount view), so the leaf needs read+exec of the
    // dir holding the server. Linux needs neither (the /usr/bin copy binds + the baseline exec grant
    // covers it). Harmless everywhere, but only emitted where required.
    #[cfg(target_os = "macos")]
    {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}

/// Spawn the box with the `fetch` server and drive one `tools/call` from the host while it runs.
/// Returns the probe's combined output and the box's own output — the latter surfaces a startup or
/// config failure, in which case `meanwhile` (the probe) never ran and the probe output is empty.
fn call_reach(b: &BoxFixture, native_egress: bool, url: &str) -> (String, RunResult) {
    let socket = broker_socket(b);
    let probe = box_sibling("box-mcp-call-probe");
    // Place the server where a contained leaf can resolve+run it (see `server_dir`): the dir must be
    // on the box's operator PATH and NOT agent-writable (the box refuses an agent-writable MCP search
    // path). `/usr/bin` satisfies this inherently on Linux; on macOS we use a test-owned dir and
    // inject it onto the box PATH below.
    place_server(FETCH_PROGRAM);

    let mut probe_output = String::new();
    let edit = |config| with_fetch_server(config, native_egress, url);
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
    // macOS: the server dir is not on the default PATH, so inject it as the box's operator PATH (the
    // box resolves the bare `command[0]` there). Linux: /usr/bin is already on PATH.
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
    name: cn_native_egress,
    id:   "CN-NE-01",
    platforms: [Linux, Macos],
    desc: "Native egress: a contain_egress=false MCP leaf joins the host network namespace and reaches an un-proxied host endpoint, while the gateway default (routeless namespace) cannot",
    run: |b| {
        b.apply_policy(mcp_call_policy());

        // Negative control FIRST (diagnostic ordering): the same server without the escape runs in a
        // routeless namespace, so the direct connect is refused and the tool reports the failure.
        let (gateway_url, gateway_listener) = host_endpoint();
        let (gateway, gateway_box) = call_reach(b, false, &gateway_url);
        // `RunResult::bare(...).assert_contains` rather than a bare `assert!`, so this registers as a
        // RunResult assertion (the harness errors a case that makes none); the box output rides along
        // for the failure message.
        RunResult::bare(format!("{gateway}\n[box output]\n{}", gateway_box.out), 0)
            .assert_contains("fetch-failed");
        assert!(
            !gateway_box.decisions.iter().any(|d| d.is_action("egress:native")),
            "a gateway leaf records no native-egress downgrade; decisions: {:?}",
            gateway_box.decisions
        );
        drop(gateway_listener);

        // Native egress: the leaf shares the host network, so its `reach` tool connects to the host
        // endpoint and echoes the body back.
        let (native_url, native_listener) = host_endpoint();
        let (native, native_box) = call_reach(b, true, &native_url);
        RunResult::bare(format!("{native}\n[box output]\n{}", native_box.out), 0)
            .assert_contains(&format!("fetched:{BODY}"));
        // The audit trail: the box records the native-egress downgrade for this server, and the
        // gateway journals nothing for the endpoint, because the connect never reached it.
        native_box.assert_mediated_permitted("egress:native", "fetch");
        let port = native_url.trim_end_matches('/').rsplit(':').next().unwrap_or_default();
        assert!(
            !native_box.decisions.iter().any(|d| {
                (d.is_action("net:connect") || d.is_action("http:request")) && d.resource.contains(port)
            }),
            "a native leaf's connect bypasses the gateway, so no egress decision names :{port}; decisions: {:?}",
            native_box.decisions
        );
        drop(native_listener);
    }
}
