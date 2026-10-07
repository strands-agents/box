//! Native-egress MCP, end-to-end against the real box.
//!
//! A contained stdio MCP server declared with `[mcp.<name>.network] contain_egress = false` reaches
//! a host endpoint the box did not proxy; the gateway default cannot. This is the box-level proof of
//! the native-egress escape: on macOS the leaf runs under a seatbelt profile with
//! outbound to IP hosts and the system resolver, on Linux it joins the host network namespace. The fetch target is a
//! throwaway HTTP listener bound in the host's own network — outside the box — so only a leaf with
//! real egress can reach it.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use serde_json::json;

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};

const BOX_STARTUP: Duration = Duration::from_secs(45);
const STARTUP: Duration = Duration::from_secs(8);
const SHUTDOWN: Duration = Duration::from_secs(8);
const FETCH: Duration = Duration::from_secs(20);

const BLOCKING_WORKLOAD: &str = r#"
set -eu
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

/// The body the host endpoint answers with; the tool echoes it back, so its presence in the tool
/// result proves the leaf actually reached the endpoint rather than merely trying.
const BODY: &str = "STRANDS_NATIVE_EGRESS_OK";

/// A throwaway HTTP/1.0 listener on `127.0.0.1`, answering every connection with `BODY`. Returned
/// alongside the owning `TcpListener` so the caller keeps it alive for the test's duration; the
/// accept loop ends when the process exits. It binds in the host's network — outside any box — so a
/// gateway-routed (routeless / proxy-only) leaf has no path to it, and only native egress does.
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
            let _ = stream.read(&mut scratch); // drain the request line; the path does not matter
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

/// Permit `mcp:call` for one server and the one tool it exposes.
fn mcp_call_policy(server: &str, tool: &str) -> String {
    let namespace: String = server
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
        when {{ context.input.server == "{server}" }};

        permit (principal, action == {namespace}::Action::"{tool}", resource);"#
    )
}

/// Drive one `tools/call` against a freshly spawned box and return the tool's result text.
fn call_fetch_tool(box_: &RuntimeMcpBox) -> String {
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("fetch-mcp");
    run.wait_for(box_.server_started("fetch-mcp"), STARTUP);
    client.initialize_and_activate(json!("init"), STARTUP);
    client.list_root(json!("list"), STARTUP);
    let result = client.call(json!("call"), "reach", FETCH);
    let text = result["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("the tool result must carry text: {result}"))
        .to_string();

    drop(client);
    box_.release_workload();
    let _ = run.wait(SHUTDOWN);
    text
}

/// **Native egress reaches an un-proxied host endpoint.** A `[mcp.fetch.network] contain_egress =
/// false` server's tool connects straight to the host listener and echoes its body back.
#[test]
fn a_native_egress_mcp_server_reaches_an_unproxied_host_endpoint() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let (url, _listener) = host_endpoint();

    let box_ = RuntimeMcpBox::new("native-egress");
    let server = Server::new("fetch", "fetch-mcp", "reach", DiscoveryBehavior::Ready)
        .native_egress()
        .with_env("FIXTURE_FETCH_TARGET", &url);
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy("fetch", "reach"),
        &[server],
        BLOCKING_WORKLOAD,
    );

    let text = call_fetch_tool(&box_);
    assert!(
        text.contains(&format!("fetched:{BODY}")),
        "native egress must reach the un-proxied host endpoint: got {text:?}"
    );
}

/// **The gateway default cannot.** The same server without the escape routes through the box's
/// gateway, so a direct connect to the un-proxied endpoint is refused and the tool reports failure.
#[test]
fn a_gateway_mcp_server_cannot_reach_an_unproxied_host_endpoint() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let (url, _listener) = host_endpoint();

    let box_ = RuntimeMcpBox::new("gateway-egress");
    let server = Server::new("fetch", "fetch-mcp", "reach", DiscoveryBehavior::Ready)
        .with_env("FIXTURE_FETCH_TARGET", &url);
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy("fetch", "reach"),
        &[server],
        BLOCKING_WORKLOAD,
    );

    let text = call_fetch_tool(&box_);
    assert!(
        text.contains("fetch-failed"),
        "gateway egress must refuse a direct connect to an un-proxied endpoint: got {text:?}"
    );
}

/// A second running box, whose `run/box.sock` is a live sibling broker.
fn running_sibling() -> (RuntimeMcpBox, runtime_mcp::RunningBox) {
    let sibling = RuntimeMcpBox::new("sibling");
    sibling.write_workspace("", &[], BLOCKING_WORKLOAD);
    let mut run = sibling.spawn();
    run.wait_for(sibling.workload_path("workload.started"), BOX_STARTUP);
    (sibling, run)
}

/// From a leaf, `connect()` to an unlisted pathname socket and to a sibling box's broker.
fn unix_connect_report(box_name: &str, native: bool) -> String {
    let outside = fixture::short_temporary_home();
    let unlisted = outside.path().join("unlisted.sock");
    let _unlisted_listener = UnixListener::bind(&unlisted).expect("bind an unlisted socket");
    let (sibling, sibling_run) = running_sibling();
    let broker = sibling.root().join("run").join("box.sock");
    for target in [&unlisted, &broker] {
        UnixStream::connect(target).unwrap_or_else(|error| {
            panic!(
                "the uncontained control must reach {}: {error}",
                target.display()
            )
        });
    }

    let box_ = RuntimeMcpBox::new(box_name);
    let mut server = Server::new("fetch", "fetch-mcp", "reach", DiscoveryBehavior::Ready).with_env(
        "FIXTURE_CONNECT_UNIX",
        &format!("{}|{}", unlisted.display(), broker.display()),
    );
    if native {
        server = server.native_egress();
    }
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy("fetch", "reach"),
        &[server],
        BLOCKING_WORKLOAD,
    );
    let text = call_fetch_tool(&box_);

    sibling.release_workload();
    let _ = sibling_run.wait(SHUTDOWN);
    text
}

/// The lines of a connect report that the boundary refused: `EPERM` on macOS, any errno elsewhere.
fn boundary_refusals(text: &str) -> usize {
    text.lines()
        .filter(|line| line.starts_with("refused:"))
        .filter(|line| !cfg!(target_os = "macos") || line.ends_with(":EPERM"))
        .count()
}

/// **Native egress reaches no pathname socket outside the leaf's own grants.** The leaf can
/// `connect()` to neither an unlisted socket nor a sibling box's `run/box.sock`, while the test
/// process itself reaches both.
#[test]
fn a_native_egress_mcp_server_cannot_connect_to_an_unlisted_unix_socket() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let text = unix_connect_report("native-unix", true);
    assert_eq!(
        boundary_refusals(&text),
        2,
        "a native-egress leaf must reach neither pathname socket: got {text:?}"
    );
}

/// **The gateway default refuses the same two sockets.**
#[test]
fn a_gateway_mcp_server_cannot_connect_to_an_unlisted_unix_socket() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let text = unix_connect_report("gateway-unix", false);
    assert_eq!(
        boundary_refusals(&text),
        2,
        "a gateway leaf must reach neither pathname socket: got {text:?}"
    );
}

/// **Native egress still resolves a name through the system resolver.**
#[test]
fn a_native_egress_mcp_server_resolves_a_name() {
    if !fixture::namespace_launcher_is_usable() {
        println!("skipping: this platform has no usable containment backend");
        return;
    }
    let box_ = RuntimeMcpBox::new("native-resolve");
    let server = Server::new("fetch", "fetch-mcp", "reach", DiscoveryBehavior::Ready)
        .native_egress()
        .with_env("FIXTURE_RESOLVE", "localhost");
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy("fetch", "reach"),
        &[server],
        BLOCKING_WORKLOAD,
    );

    let text = call_fetch_tool(&box_);
    assert_eq!(
        text, "resolved:localhost",
        "a native-egress leaf must resolve a name"
    );
}
