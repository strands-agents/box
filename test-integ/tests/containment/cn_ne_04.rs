use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::thread;

use strands_det_harness::{RunResult, det_case, sh_quote};

// A `[tool.<name>.network] contain_egress = false` tool runs its leaf with direct egress
// (docs/design/decisions.md#native-egress-is-an-operator-declared-leaf-escape), so it reaches a host
// endpoint the box never proxied, and the box records the downgrade as `egress:native`. The same tool
// without the key, or with `contain_egress = true`, stays on the gateway: its leaf reaches only the
// box's own local ports, so the direct connect fails and no `egress:native` decision appears. The endpoint listens on the host's
// loopback, outside any box, so reaching it is proof of real egress.
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

const BODY: &str = "STRANDS_TOOL_NATIVE_EGRESS_OK";

/// A throwaway HTTP/1.0 listener on the host's loopback that answers every request with [`BODY`].
fn host_endpoint() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a host endpoint");
    let url = format!("http://{}/", listener.local_addr().expect("endpoint address"));
    let accepting = listener.try_clone().expect("clone the host endpoint listener");
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

det_case! {
    name: cn_ne_04,
    id:   "CN-NE-04",
    platforms: [Linux, Macos],
    desc: "A [tool.x.network] contain_egress=false tool reaches an un-proxied host endpoint and records egress:native, while the same tool with no network table or contain_egress=true cannot and records none",
    run: |b| {
        let probe = b.compile_probe("leafprobe-ne04", PROBE);
        let quoted = serde_json::to_string(&probe.to_string_lossy()).unwrap();
        // `None` declares no network table; `Some(value)` declares `contain_egress = value`.
        let tool = |contain_egress: Option<bool>| {
            let quoted = quoted.clone();
            move |text: String| {
                let mut tables = format!("{text}\n[tool.netprobe]\ncommand = [{quoted}]\n");
                if let Some(value) = contain_egress {
                    tables.push_str(&format!("\n[tool.netprobe.network]\ncontain_egress = {value}\n"));
                }
                tables
            }
        };
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let command = |url: &str| format!("{} http-connect {}", sh_quote(&probe.to_string_lossy()), url);

        // Negative controls first: with no network table, and with `contain_egress = true`, the leaf
        // reaches only the box's local ports.
        for (label, contain_egress) in [("no network table", None), ("contain_egress = true", Some(true))] {
            let (gateway_url, gateway_listener) = host_endpoint();
            let gateway = b.run_mediated_with_config(tool(contain_egress), &command(&gateway_url));
            gateway.assert_mediated_permitted("shell:spawn", "leafprobe-ne04");
            assert!(
                gateway.out.lines().any(|l| l.starts_with("HTTP_CONNECT_REFUSED ")),
                "{label}: a gateway tool reached an un-proxied host endpoint; out=[{}]", gateway.snippet()
            );
            assert!(
                !gateway.decisions.iter().any(|d| d.is_action("egress:native")),
                "{label}: a gateway tool records no native-egress downgrade; decisions: {:?}", gateway.decisions
            );
            drop(gateway_listener);
        }

        // Native egress: the leaf connects directly and reads the endpoint's body.
        let (native_url, native_listener) = host_endpoint();
        let native = b.run_mediated_with_config(tool(Some(false)), &command(&native_url));
        RunResult::bare(native.out.clone(), 0).assert_contains(&format!(":: {BODY}"));
        native.assert_mediated_permitted("egress:native", "netprobe");
        let port = native_url.trim_end_matches('/').rsplit(':').next().unwrap_or_default();
        assert!(
            !native.decisions.iter().any(|d| {
                (d.is_action("net:connect") || d.is_action("http:request")) && d.resource.contains(port)
            }),
            "a native tool's connect bypasses the gateway, so no egress decision names :{port}; decisions: {:?}",
            native.decisions
        );
        drop(native_listener);
    }
}
