//! `ShellBuilder::egress_proxy`: outbound HTTP routes through the configured proxy and
//! trusts its CA, the SSRF floor still runs before any transport, and a network-off Shell
//! still refuses (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway).
//!
//! The fake proxy speaks just enough HTTP to prove routing: a plain-HTTP request through an
//! HTTP proxy is sent in absolute-form (`GET http://host/ ...`), so a bare TCP listener can
//! observe that the request arrived via the proxy and answer a canned 200. No TLS handshake
//! happens on this path, so the embedded CA only has to be a valid certificate the client can
//! parse — which is what exercises the CA wiring. TLS/CONNECT validation belongs to the box
//! end-to-end suite, which stands up a real gateway with a real intercept CA.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use strands_shell::Shell;

/// A valid self-signed certificate, used only so the client can parse and trust a CA. It is
/// never presented in a handshake on the plain-HTTP proxy path.
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUWvZ83fvQSkhM8ESVH4/LuooeWoQwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTc3RyYW5kcy1ib3gtdGVzdC1jYTAeFw0yNjA4MjAwMzEz
MzlaFw0zNjA4MTcwMzEzMzlaMB4xHDAaBgNVBAMME3N0cmFuZHMtYm94LXRlc3Qt
Y2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVrHwdb+/Ai4tlk54f
DrVp5v4cKnWlCPvVBZp+F09cuU/dzpWGmtFDGgI5kX1YISVnaZAPn+9djFBs81Cg
o4yVGBwl8+fwi3A2iT0gFWp006CEh/s6mMujmypmhUAOkkByVoIqK3lESTD22oPu
Zy6kn/RkLxtBG61d7oUYuVykUuiIk/2jpnpTFOE9YdiUx/tbivPoz9kdIndOIZsN
7pdjFo27Ly4dcCNvbbG7EqcFej/Z/y9i+X4Eig3eivLPVSqdx3EQojtW5PsXe1c2
A1vV6JVe4DT44kgPe9Piq3KeFS00guYndEA3aLWWwZrjQtflUgsxdNksDi/iY6ZI
QHlHAgMBAAGjUzBRMB0GA1UdDgQWBBTjpmA5tSNFSUn5QqTg+MVFUuCLJzAfBgNV
HSMEGDAWgBTjpmA5tSNFSUn5QqTg+MVFUuCLJzAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAR2X3gXcjCbE1NASySK+SFSbqgngHO+VagjtqGd1o5
xFM3dydrOwzD2OFEa9E14F5IxaVSuilWzKsUoiArAZD1QY/rrh3fTxeiTbZfhfmw
VyuLdncEJtyz3PJYBwwU5MuvzoKsSB4VwvODujRqlGCweeLwXKqWuq+3b2zTMBkk
8ei4BeABfi+PfvN0IE3tiuA3hI74an6LLF9ejaZe1B6zygNsb4FlW98mwPyvK/7A
LLtVsZ4Z+0reC2XJhE3bRdDT608J/k3ByV4wwv2H9ut7jnxDQ9OTbvmlaYCf9RMm
dI3BXhTI3m9FbDOav3znV09ITinjJLABCQ87LQH+RbyY
-----END CERTIFICATE-----
";

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (runtime, tokio::task::LocalSet::new())
}

/// Write `contents` to a per-test temp file and return its path. The crate has no
/// `tempfile` dev-dependency, so the label plus the pid keeps concurrent tests apart.
fn write_ca(label: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "strands-shell-egress-{label}-{}.pem",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write the test CA");
    path
}

/// A one-shot fake HTTP proxy. Accepts one connection, records its request line, and answers
/// `HELLO`. Returns the proxy URL and a receiver for the observed request line.
fn fake_proxy() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let addr = listener.local_addr().expect("the proxy has an address");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut data = Vec::new();
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&data);
            let request_line = text.lines().next().unwrap_or_default().to_string();
            let _ = tx.send(request_line);
            let body = b"HELLO";
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), rx)
}

/// The full head and body a one-shot proxy observed on the wire.
struct SeenRequest {
    /// The raw request line, e.g. `GET http://example.com/ HTTP/1.1`.
    request_line: String,
    /// Every header line below the request line, lower-cased names kept as sent.
    headers: Vec<String>,
    /// The request body, empty when none was sent.
    body: String,
}

impl SeenRequest {
    /// Whether a header line (case-insensitive) is present, matched as `name: value`.
    fn has_header(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.headers
            .iter()
            .any(|line| line.to_ascii_lowercase().contains(&needle))
    }
}

/// A one-shot fake HTTP proxy that captures the whole request (head + body) and answers
/// `status` with `body`. Returns the proxy URL and a receiver for the observed request.
///
/// It reads the head, parses `Content-Length`, then reads exactly that many body bytes, so a
/// `POST`/`PUT` body is observed in full rather than truncated at the head boundary.
fn capturing_proxy(
    status: u16,
    reason: &str,
    body: &'static str,
) -> (String, mpsc::Receiver<SeenRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let addr = listener.local_addr().expect("the proxy has an address");
    let reason = reason.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut data = Vec::new();
            let mut buf = [0u8; 1024];
            // Read until the head terminator is seen.
            let head_end = loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break data.len(),
                    Ok(n) => {
                        data.extend_from_slice(&buf[..n]);
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    }
                }
            };
            let head_text = String::from_utf8_lossy(&data[..head_end]).into_owned();
            let mut lines = head_text.lines();
            let request_line = lines.next().unwrap_or_default().to_string();
            let headers: Vec<String> = lines
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            // Parse Content-Length so a body is read in full.
            let content_length: usize = headers
                .iter()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let mut body_bytes = data[head_end..].to_vec();
            while body_bytes.len() < content_length {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body_bytes.extend_from_slice(&buf[..n]),
                }
            }
            let seen = SeenRequest {
                request_line,
                headers,
                body: String::from_utf8_lossy(&body_bytes).into_owned(),
            };
            let _ = tx.send(seen);

            let head = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), rx)
}

/// Build a routed Shell for one request against `proxy_url`, trusting the test CA at `ca`.
fn routed_shell(proxy_url: String, ca: &PathBuf) -> Shell {
    Shell::builder()
        .egress_proxy(proxy_url, ca)
        .expect("the CA reads")
        .build()
        .expect("a routed Shell builds")
}

/// The request reaches the proxy in absolute-form, and the proxied response comes back.
#[test]
fn a_curl_routes_through_the_egress_proxy() {
    let ca = write_ca("route", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = fake_proxy();

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .egress_proxy(proxy_url, &ca)
            .expect("the CA reads")
            .build()
            .expect("a routed Shell builds");
        let out = shell.run("curl http://example.com/").await;
        assert_eq!(
            out.status, 0,
            "routed curl should succeed; stderr: {}",
            out.stderr
        );
        assert_eq!(out.stdout, "HELLO", "the proxied body is returned");
    }));

    let line = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("the proxy saw a request");
    assert!(
        line.starts_with("GET http://example.com/"),
        "the request must reach the proxy in absolute-form, got: {line}"
    );
    let _ = std::fs::remove_file(&ca);
}

/// The SSRF floor runs before any transport, so a floored origin never reaches the proxy.
#[test]
fn the_ssrf_floor_still_blocks_a_loopback_origin_when_proxied() {
    let ca = write_ca("floor", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = fake_proxy();

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .egress_proxy(proxy_url, &ca)
            .expect("the CA reads")
            .build()
            .expect("a routed Shell builds");
        let out = shell.run("curl http://localhost/secret").await;
        assert_ne!(
            out.status, 0,
            "the SSRF floor must block a loopback origin even when proxied"
        );
    }));

    assert!(
        seen.recv_timeout(Duration::from_millis(300)).is_err(),
        "a floored request must never reach the proxy"
    );
    let _ = std::fs::remove_file(&ca);
}

/// Configuring an egress proxy enables the network.
#[test]
fn egress_proxy_enables_the_network() {
    let ca = write_ca("cfg", TEST_CA_PEM.as_bytes());
    let shell = Shell::builder()
        .egress_proxy("http://127.0.0.1:9", &ca)
        .expect("the CA reads")
        .build()
        .expect("the Shell builds");
    assert!(shell.config().network_enabled);
    let _ = std::fs::remove_file(&ca);
}

/// Already-loaded CA bytes configure the same proxy route without another pathname read.
#[test]
fn egress_proxy_pem_enables_the_network() {
    let shell = Shell::builder()
        .egress_proxy_pem("http://127.0.0.1:9", TEST_CA_PEM.as_bytes().to_vec())
        .expect("the CA parses")
        .build()
        .expect("the Shell builds");
    assert!(shell.config().network_enabled);
}

/// An unreadable CA path is a build-time error, not a silent misconfiguration.
#[test]
fn egress_proxy_errors_on_an_unreadable_ca() {
    let result = Shell::builder().egress_proxy("http://127.0.0.1:9", "/no/such/ca.pem");
    assert!(result.is_err(), "an unreadable CA must fail the builder");
}

/// A readable-but-malformed CA fails the builder, not every later request. The PEM is
/// parsed at configuration time, so a bad certificate is refused here rather than
/// building a client that cannot validate anything the gateway forges.
#[test]
fn egress_proxy_errors_on_a_malformed_ca() {
    let ca = write_ca(
        "bad",
        b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n",
    );
    let result = Shell::builder().egress_proxy("http://127.0.0.1:9", &ca);
    assert!(
        result.is_err(),
        "a readable but non-PEM CA must fail the builder at config time"
    );
}

/// `disable_network` after `egress_proxy` wins — the safe direction.
#[test]
fn disable_network_after_egress_proxy_wins() {
    let ca = write_ca("mx", TEST_CA_PEM.as_bytes());
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .egress_proxy("http://127.0.0.1:9", &ca)
            .expect("the CA reads")
            .disable_network()
            .build()
            .expect("the Shell builds");
        assert!(
            !shell.config().network_enabled,
            "the later disable_network wins"
        );
        let out = shell.run("curl http://example.com/").await;
        assert_ne!(out.status, 0, "a network-off Shell refuses the request");
    }));
    let _ = std::fs::remove_file(&ca);
}

// ── Routed server-backed behaviour (enabled by the proxy route) ──────────────
// The proxy is the Shell's only route to a listener again (the SSRF floor blocks a direct
// loopback dial), so these cover the request/response shaping that had no test after the
// transport seam was removed — see `curl_integration.rs`.

/// A `-d` body and its method reach the proxy, and a custom `-H` header rides along.
#[test]
fn a_post_body_and_header_reach_the_proxy() {
    let ca = write_ca("post", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "STORED");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sS -X POST -H 'X-Test: yes' -d 'name=value' http://example.com/submit")
            .await;
        assert_eq!(
            out.status, 0,
            "routed POST should succeed; stderr: {}",
            out.stderr
        );
        assert_eq!(out.stdout, "STORED", "the proxied body is returned");
    }));

    let req = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("the proxy saw a request");
    assert!(
        req.request_line
            .starts_with("POST http://example.com/submit"),
        "the method and absolute-form target must reach the proxy: {}",
        req.request_line
    );
    assert!(
        req.has_header("x-test: yes"),
        "the custom header must ride along: {:?}",
        req.headers
    );
    assert_eq!(
        req.body, "name=value",
        "the request body must reach the proxy"
    );
    let _ = std::fs::remove_file(&ca);
}

/// `--json` sets the body and the JSON content-type through the proxy.
#[test]
fn a_json_body_sets_content_type_through_the_proxy() {
    let ca = write_ca("json", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "OK");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sS --json '{\"k\":1}' http://example.com/api")
            .await;
        assert_eq!(
            out.status, 0,
            "routed --json should succeed; stderr: {}",
            out.stderr
        );
    }));

    let req = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("the proxy saw a request");
    assert!(
        req.has_header("content-type: application/json"),
        "--json must set the JSON content-type: {:?}",
        req.headers
    );
    assert_eq!(req.body, "{\"k\":1}", "the JSON body must reach the proxy");
    let _ = std::fs::remove_file(&ca);
}

/// An explicit `-X PUT` reaches the proxy verbatim.
#[test]
fn an_explicit_method_reaches_the_proxy() {
    let ca = write_ca("put", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "OK");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -sS -X PUT http://example.com/thing").await;
        assert_eq!(
            out.status, 0,
            "routed PUT should succeed; stderr: {}",
            out.stderr
        );
    }));

    let req = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("the proxy saw a request");
    assert!(
        req.request_line.starts_with("PUT http://example.com/thing"),
        "the explicit method must reach the proxy: {}",
        req.request_line
    );
    let _ = std::fs::remove_file(&ca);
}

/// `-f`/`--fail` turns a proxied 404 into a non-zero exit, and no body is emitted.
#[test]
fn fail_flag_makes_a_proxied_404_a_nonzero_exit() {
    let ca = write_ca("fail", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(404, "Not Found", "nope");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -sS -f http://example.com/missing").await;
        assert_ne!(out.status, 0, "--fail must make a 404 a non-zero exit");
        assert!(
            !out.stdout.contains("nope"),
            "--fail must not print the error body: {}",
            out.stdout
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

/// `-i`/`--include` prints the proxied status line and headers ahead of the body.
#[test]
fn include_flag_prints_the_proxied_status_line() {
    let ca = write_ca("include", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(201, "Created", "BODY");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -sS -i http://example.com/new").await;
        assert_eq!(
            out.status, 0,
            "routed -i should succeed; stderr: {}",
            out.stderr
        );
        assert!(
            out.stdout.contains("201"),
            "the proxied status must be printed with -i: {}",
            out.stdout
        );
        assert!(
            out.stdout.contains("BODY"),
            "the body must still follow the head: {}",
            out.stdout
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

/// `curl -o FILE` writes the proxied body to a file — the fetch is routed, and the `fs:write`
/// lands after it. A permissive default kernel governs nothing, so this proves the write path
/// runs end to end for a routed fetch.
#[test]
fn output_flag_writes_the_proxied_body_to_a_file() {
    let ca = write_ca("output", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(200, "OK", "DOWNLOADED");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        // Write inside the Shell's own filesystem, then read it back through the Shell.
        let out = shell
            .run("curl -sS -o /tmp/dl.txt http://example.com/file; cat /tmp/dl.txt")
            .await;
        assert_eq!(
            out.status, 0,
            "routed -o should succeed; stderr: {}",
            out.stderr
        );
        assert!(
            out.stdout.contains("DOWNLOADED"),
            "the proxied body must be written to the file and read back: {}",
            out.stdout
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

/// `-w` writes to stdout even when `-o` sends the body to a file. `-o` redirects the body
/// alone, so a script probing `%{http_code}` still reads it.
#[test]
fn write_out_reaches_stdout_when_output_goes_to_a_file() {
    let ca = write_ca("writeout", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(200, "OK", "BODY");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sS -o /tmp/dl.txt -w 'code=%{http_code}\\n' http://example.com/file")
            .await;
        assert_eq!(
            out.status, 0,
            "routed -o with -w should succeed; stderr: {}",
            out.stderr
        );
        assert!(
            out.stdout.contains("code=200"),
            "-w must print to stdout even with -o: {}",
            out.stdout
        );
        assert!(
            !out.stdout.contains("BODY"),
            "-o must keep the body off stdout: {}",
            out.stdout
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

/// The floor blocks an IP-literal loopback origin before the proxy, too.
#[test]
fn the_ssrf_floor_blocks_a_loopback_ip_when_proxied() {
    let ca = write_ca("floor-ip", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "leaked");

    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -sS http://127.0.0.1/secret").await;
        assert_ne!(
            out.status, 0,
            "a loopback IP literal must be floored even when proxied"
        );
    }));

    assert!(
        seen.recv_timeout(Duration::from_millis(300)).is_err(),
        "a floored request must never reach the proxy"
    );
    let _ = std::fs::remove_file(&ca);
}

/// A proxy that answers one absolute-form request with `status`, `extra` headers and `body`.
fn proxy_answering(
    status: &'static str,
    extra: &'static [(&'static str, &'static str)],
    body: &'static str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let addr = listener.local_addr().expect("the proxy has an address");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut data = Vec::new();
            let mut buf = [0_u8; 1024];
            // Read the head only: the client sends no body on these requests.
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..read]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let mut response = format!("HTTP/1.1 {status}\r\n");
            for (name, value) in extra {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n", body.len()));
            response.push_str("Connection: close\r\n\r\n");
            response.push_str(body);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// The marker the box's gateway sets on a refusal it originates.
const REFUSAL_MARKER: &str = "x-strands-box-egress";

/// Run one `curl` through `proxy_url`, optionally naming the refusal marker.
fn curl_through(proxy_url: String, ca: &PathBuf, name_marker: bool) -> (i32, String) {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut builder = Shell::builder();
        if name_marker {
            builder = builder.egress_refusal_header(REFUSAL_MARKER);
        }
        let mut shell = builder
            .egress_proxy(proxy_url, ca)
            .expect("the CA reads")
            .build()
            .expect("a routed Shell builds");
        let out = shell.run("curl http://example.com/").await;
        (out.status, out.stdout)
    }))
}

/// **A refusal the gateway originated exits non-zero and is never rendered.** The gateway forges the
/// origin's certificate, so its own refusal arrives as an ordinary status; `curl` exits `0` for any
/// status without `-f`, which would report a refused request as a server answer. The marker makes the
/// two distinguishable, and the response becomes a refusal rather than a body.
#[test]
fn a_gateway_refusal_exits_non_zero_and_is_not_rendered() {
    let ca = write_ca("refusal", TEST_CA_PEM.as_bytes());
    let proxy = proxy_answering(
        "403 forbidden",
        &[(REFUSAL_MARKER, "refused")],
        "http:request gate: policy denied this operation [default-deny]: No permit policy matched.",
    );
    let (status, stdout) = curl_through(proxy, &ca, true);
    assert_ne!(status, 0, "a refused request must not report success");
    assert!(
        !stdout.contains("policy denied"),
        "the refusal is not delivered as a response body: {stdout}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains(REFUSAL_MARKER),
        "the marker never reaches the caller: {stdout}"
    );
}

/// **An origin's own `403` keeps `curl`'s semantics**, so this narrows nothing: an unmarked status is
/// the server's answer, and its body still reaches the caller at exit `0`.
#[test]
fn an_unmarked_403_stays_the_origins_answer() {
    let ca = write_ca("origin403", TEST_CA_PEM.as_bytes());
    let proxy = proxy_answering("403 forbidden", &[], "the origin said no");
    let (status, stdout) = curl_through(proxy, &ca, true);
    assert_eq!(status, 0, "an origin 4xx is not a refusal");
    assert!(
        stdout.contains("the origin said no"),
        "the origin's body still reaches the caller: {stdout}"
    );
}

/// **A permitted response is untouched**, so the check costs a successful request nothing.
#[test]
fn a_permitted_response_is_unaffected_by_the_marker_check() {
    let ca = write_ca("permitted", TEST_CA_PEM.as_bytes());
    let proxy = proxy_answering("200 OK", &[], "hello");
    let (status, stdout) = curl_through(proxy, &ca, true);
    assert_eq!(status, 0);
    assert!(stdout.contains("hello"), "the body is delivered: {stdout}");
}

/// **An embedder that names no marker keeps the pinned behaviour**, so the rule is opt-in and a
/// re-vendor without the box's wiring is unchanged.
#[test]
fn without_a_named_marker_the_response_is_unchanged() {
    let ca = write_ca("nomarker", TEST_CA_PEM.as_bytes());
    let proxy = proxy_answering("403 forbidden", &[(REFUSAL_MARKER, "refused")], "unchanged");
    let (status, stdout) = curl_through(proxy, &ca, false);
    assert_eq!(status, 0, "no named marker means no refusal detection");
    assert!(stdout.contains("unchanged"), "{stdout}");
}

// ── Options the Strands harness `web_fetch` tool sends ──────────────

/// A fake proxy that answers one connection per entry of `responses`, in order, with that raw
/// HTTP response. Each observed request head is sent on the receiver.
fn scripted_proxy(responses: Vec<String>) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let addr = listener.local_addr().expect("the proxy has an address");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut data = Vec::new();
            let mut buf = [0_u8; 1024];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..read]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&data).into_owned());
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), rx)
}

/// A raw `HTTP/1.1` response with `headers` and `body`.
fn response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut r = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        r.push_str(&format!("{name}: {value}\r\n"));
    }
    r.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    r
}

fn redirect_to(location: &str) -> String {
    response("302 Found", &[("Location", location)], "")
}

fn html(body: &str) -> String {
    response(
        "200 OK",
        &[("Content-Type", "text/html; charset=utf-8")],
        body,
    )
}

#[test]
fn globoff_is_accepted() {
    let ca = write_ca("globoff", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(200, "OK", "HELLO");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -g --globoff http://example.com/").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "HELLO");
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn user_agent_reaches_the_proxy() {
    let ca = write_ca("useragent", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "HELLO");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -A 'agent/1.0' http://example.com/").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
    }));
    let seen = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("a request");
    assert!(
        seen.has_header("user-agent: agent/1.0"),
        "{:?}",
        seen.headers
    );
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn a_header_user_agent_overrides_a() {
    let ca = write_ca("useragent-h", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "HELLO");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -A 'agent/1.0' -H 'User-Agent: explicit' http://example.com/")
            .await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
    }));
    let seen = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("a request");
    assert!(
        seen.has_header("user-agent: explicit"),
        "{:?}",
        seen.headers
    );
    assert!(!seen.has_header("agent/1.0"), "{:?}", seen.headers);
    let _ = std::fs::remove_file(&ca);
}

/// A proxy that accepts and never answers, so only `--max-time` ends the transfer.
#[test]
fn max_time_exits_28() {
    let ca = write_ca("maxtime", TEST_CA_PEM.as_bytes());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let started = std::time::Instant::now();
        let out = shell
            .run("curl -sS --max-time 0.2 http://example.com/")
            .await;
        assert_eq!(out.status, 28, "stderr: {}", out.stderr);
        assert!(out.stderr.contains("(28)"), "{}", out.stderr);
        assert!(started.elapsed() < Duration::from_secs(5));
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn proto_redir_refuses_a_redirect() {
    let ca = write_ca("protoredir", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = scripted_proxy(vec![redirect_to("/next"), html("NEXT")]);
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sSL --proto-redir '=https' http://example.com/")
            .await;
        assert_eq!(out.status, 1, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "");
    }));
    seen.recv_timeout(Duration::from_secs(5))
        .expect("the first request");
    assert!(
        seen.recv_timeout(Duration::from_millis(200)).is_err(),
        "the refused hop must not reach the proxy"
    );
    let _ = std::fs::remove_file(&ca);
}

/// A `Location` naming another scheme is absolute, so `--proto-redir` judges that scheme.
#[test]
fn a_non_http_redirect_is_refused() {
    let ca = write_ca("ftpredir", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = scripted_proxy(vec![redirect_to("ftp://example.com/file")]);
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sSL --proto '=http,https' --proto-redir '=http,https' http://example.com/")
            .await;
        assert_eq!(out.status, 1, "stderr: {}", out.stderr);
        assert!(
            out.stderr.contains("Protocol \"ftp\" not supported"),
            "{}",
            out.stderr
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn write_out_reports_content_type_and_effective_url() {
    let ca = write_ca("writeout-vars", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = scripted_proxy(vec![redirect_to("/next"), html("NEXT")]);
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sL -w '\\n%{content_type}\\n%{url_effective}' http://example.com/")
            .await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert_eq!(
            out.stdout,
            "NEXT\ntext/html; charset=utf-8\nhttp://example.com/next"
        );
    }));
    let _ = std::fs::remove_file(&ca);
}

/// The full command line `web_fetch` sends: the body goes to the file, `-w` to stdout.
#[test]
fn the_web_fetch_command_line_works() {
    let ca = write_ca("webfetch", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = scripted_proxy(vec![redirect_to("/next"), html("<p>page</p>")]);
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run(
                "curl -sSL -g --fail --proto '=http,https' --proto-redir '=http,https' \
                 --max-time 30 -A 'web-fetch/1.0' -o /tmp/page.html \
                 -w '%{content_type}\\n%{url_effective}' -- http://example.com/; \
                 echo; cat /tmp/page.html",
            )
            .await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert_eq!(
            out.stdout,
            "text/html; charset=utf-8\nhttp://example.com/next\n<p>page</p>"
        );
    }));
    for _ in 0..2 {
        let head = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("a request");
        assert!(
            head.to_ascii_lowercase()
                .contains("user-agent: web-fetch/1.0"),
            "every hop carries -A: {head}"
        );
    }
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn write_out_is_written_on_fail() {
    let ca = write_ca("writeout-fail", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(404, "Not Found", "gone");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sf -w '%{http_code}' http://example.com/")
            .await;
        assert_eq!(out.status, 22, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "404");
    }));
    let _ = std::fs::remove_file(&ca);
}

/// A proxy that answers the first connection with `first` and holds every later one open
/// unanswered, so only `--max-time` ends the transfer.
fn proxy_then_hang(first: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
    let addr = listener.local_addr().expect("the proxy has an address");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(first.as_bytes());
            let _ = stream.flush();
        }
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    format!("http://{addr}")
}

#[test]
fn max_time_spans_redirect_hops_and_writes_write_out() {
    let ca = write_ca("maxtime-hops", TEST_CA_PEM.as_bytes());
    let proxy_url = proxy_then_hang(redirect_to("/slow"));
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -sL -m 0.3 -w '%{http_code} %{url_effective}' http://example.com/")
            .await;
        assert_eq!(out.status, 28, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "000 http://example.com/slow");
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn max_time_zero_and_huge_are_no_limit() {
    let ca = write_ca("maxtime-huge", TEST_CA_PEM.as_bytes());
    let (rt, local) = rt();
    for limit in ["0", "1e19", "1e300", "99999999999999999999"] {
        let (proxy_url, _seen) = capturing_proxy(200, "OK", "HELLO");
        rt.block_on(local.run_until(async {
            let mut shell = routed_shell(proxy_url, &ca);
            let out = shell
                .run(&format!("curl -m {limit} http://example.com/"))
                .await;
            assert_eq!(out.status, 0, "-m {limit}: {}", out.stderr);
            assert_eq!(out.stdout, "HELLO", "-m {limit}");
        }));
    }
    let _ = std::fs::remove_file(&ca);
}

/// A server's `Content-Type` is written as sent, never expanded again.
#[test]
fn write_out_does_not_expand_a_substituted_value() {
    let ca = write_ca("writeout-rescan", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = scripted_proxy(vec![response(
        "200 OK",
        &[("Content-Type", r"text/plain;%{url_effective}\n")],
        "body",
    )]);
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -s -o /dev/null -w '%{content_type}|' http://example.com/")
            .await;
        assert_eq!(out.stdout, r"text/plain;%{url_effective}\n|");
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn include_with_output_writes_headers_to_the_file() {
    let ca = write_ca("include-output", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(200, "OK", "BODY");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl -s -i -o /tmp/inc.txt http://example.com/")
            .await;
        assert_eq!(out.stdout, "", "stderr: {}", out.stderr);
        let out = shell.run("cat /tmp/inc.txt").await;
        assert!(
            out.stdout.starts_with("HTTP/1.1 200 OK\r\n"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.ends_with("\r\n\r\nBODY"), "{}", out.stdout);
    }));
    let _ = std::fs::remove_file(&ca);
}

#[test]
fn an_empty_user_agent_sends_none() {
    let ca = write_ca("useragent-empty", TEST_CA_PEM.as_bytes());
    let (proxy_url, seen) = capturing_proxy(200, "OK", "HELLO");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell.run("curl -A '' http://example.com/").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
    }));
    let seen = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("a request");
    assert!(!seen.has_header("user-agent:"), "{:?}", seen.headers);
    let _ = std::fs::remove_file(&ca);
}

/// Each `--proto` replaces the one before it.
#[test]
fn the_last_proto_wins() {
    let ca = write_ca("proto-last", TEST_CA_PEM.as_bytes());
    let (proxy_url, _seen) = capturing_proxy(200, "OK", "HELLO");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = routed_shell(proxy_url, &ca);
        let out = shell
            .run("curl --proto -http --proto -https http://example.com/")
            .await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "HELLO");
    }));
    let _ = std::fs::remove_file(&ca);
}
