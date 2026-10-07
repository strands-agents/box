//! The one `fetch` host function, which sends a Monty script's request through the egress gateway.

use std::time::Duration;

use monty_types::{
    CallArgs, ExcType, ExtFunctionResult, MontyException, MontyObject, ObjectRef, unstable,
};

use crate::run::broker::shell::EgressRouting;

/// The one curated name a Monty script calls to make an outbound request
/// (docs/design/decisions.md#a-monty-script-reaches-the-network-through-one-fetch-function).
pub(super) const FETCH_NAME: &str = "fetch";

/// Cap on a response body handed back to a script.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Per-request bound on the gateway call, below the transport's request timeout so a hung fetch
/// surfaces as a fetch error rather than the transport deadline.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

const _: () = assert!(
    NETWORK_TIMEOUT.as_nanos() < crate::run::broker::host::SERVE_REQUEST_TIMEOUT.as_nanos(),
    "a fetch's own timeout must fire before the transport's request timeout, so a hung request \
     reports as a fetch error rather than the transport's generic kill"
);

/// The parsed shape of one `fetch` call, at parity with the gateway's `InterceptedRequest`:
/// a method, a url, request headers, and an optional body. The gateway governs the method through
/// `http:request`, so the client passes any method the guest names.
struct FetchRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

/// Resolve one argument by its positional index or its keyword name — the two ways a Python call
/// may supply `fetch(url, method=…, headers=…, body=…)`.
fn fetch_arg<'a>(args: &'a CallArgs, index: usize, name: &str) -> Option<ObjectRef<'a>> {
    args.arg(index).or_else(|| args.kwarg(name))
}

/// Whether `value` is Python `None`.
fn is_none(value: &ObjectRef<'_>) -> bool {
    matches!(unstable::node(*value), unstable::MontyNode::None)
}

/// A `TypeError` result carrying `message`, the catchable exception the guest sees for a bad
/// argument.
fn fetch_type_error(message: &str) -> ExtFunctionResult {
    ExtFunctionResult::Error(MontyException::new(
        ExcType::TypeError,
        Some(message.to_string()),
    ))
}

/// Parse `fetch(url, method="GET", headers=None, body=None)` from its positional and keyword
/// arguments, or return the `TypeError` a bad argument raises.
fn parse_fetch_request(args: &CallArgs) -> Result<FetchRequest, ExtFunctionResult> {
    // Reject unknown keyword names and extra positionals, like Python's own call semantics — a typo
    // (`header=`, `data=`) must be a catchable error, not a silently dropped header or body that
    // sends an unauthenticated or empty request with no signal.
    const PARAMS: [&str; 4] = ["url", "method", "headers", "body"];
    let positional = args.args().len();
    if positional > PARAMS.len() {
        return Err(fetch_type_error(&format!(
            "fetch() takes at most {} positional arguments but {} were given",
            PARAMS.len(),
            positional
        )));
    }
    for (key, _) in args.kwargs() {
        match key.as_str() {
            Some(name) if PARAMS.contains(&name) => {}
            Some(name) => {
                return Err(fetch_type_error(&format!(
                    "fetch() got an unexpected keyword argument '{name}'"
                )));
            }
            None => {
                return Err(fetch_type_error(
                    "fetch() keyword arguments must be strings",
                ));
            }
        }
    }
    // One argument given both positionally and by keyword drops one value silently otherwise
    // (`fetch_arg` prefers the positional). Python raises here, so we do too.
    for (index, name) in PARAMS.iter().enumerate() {
        if args.arg(index).is_some() && args.kwarg(name).is_some() {
            return Err(fetch_type_error(&format!(
                "fetch() got multiple values for argument '{name}'"
            )));
        }
    }

    let url = match fetch_arg(args, 0, "url") {
        Some(url) => match url.as_str() {
            Some(url) => url.to_string(),
            None => return Err(fetch_type_error("fetch() url must be a string")),
        },
        None => return Err(fetch_type_error("fetch() takes a url string")),
    };

    let method = match fetch_arg(args, 1, "method") {
        None => "GET".to_string(),
        Some(method) if is_none(&method) => "GET".to_string(),
        Some(method) => match method.as_str() {
            Some(method) => method.to_string(),
            None => return Err(fetch_type_error("fetch() method must be a string")),
        },
    };

    let headers = match fetch_arg(args, 2, "headers") {
        None => Vec::new(),
        Some(headers) if is_none(&headers) => Vec::new(),
        Some(headers) if headers.type_name() == "dict" => {
            let pairs = headers.pairs().unwrap_or_default();
            let mut parsed = Vec::with_capacity(pairs.len());
            for (name, value) in pairs {
                let (Some(name), Some(value)) = (name.as_str(), value.as_str()) else {
                    return Err(fetch_type_error(
                        "fetch() headers must be a {str: str} dict",
                    ));
                };
                parsed.push((name.to_string(), value.to_string()));
            }
            parsed
        }
        Some(_) => return Err(fetch_type_error("fetch() headers must be a dict")),
    };

    let body = match fetch_arg(args, 3, "body") {
        None => None,
        Some(body) => match unstable::node(body) {
            unstable::MontyNode::None => None,
            unstable::MontyNode::String(body) => Some(body.clone().into_bytes()),
            unstable::MontyNode::Bytes(body) => Some(body.clone()),
            _ => return Err(fetch_type_error("fetch() body must be str or bytes")),
        },
    };

    Ok(FetchRequest {
        method,
        url,
        headers,
        body,
    })
}

/// Perform one `fetch` through the box's egress gateway and map the response to a guest dict
/// `{status, headers, body}`. The gateway raises `net:connect`/`http:request`; this raises no
/// decision of its own. This is the only network client in the Monty host path, and it always
/// routes through `EgressRouting` — never the origin.
pub(super) async fn fetch_through_gateway(
    routing: &EgressRouting,
    args: &CallArgs,
) -> ExtFunctionResult {
    let request = match parse_fetch_request(args) {
        Ok(request) => request,
        Err(type_error) => return type_error,
    };
    // The Shell's own pre-transport SSRF check, reused (not copied) so the floor list cannot drift:
    // a scheme allowlist plus a literal private/loopback/link-local/IMDS refusal, before any client
    // is built. Parity with the Shell; the gateway floor remains the authority for
    // DNS-resolved destinations.
    if let Err(error) = strands_shell::vfs_kernel::check_url_safe(&request.url) {
        // This floor fires before the gateway is contacted, so the gateway journals nothing for it;
        // record the deny to the operator's stderr so it stays reconstructable (Tenet 4). A gateway
        // net:connect/http:request denial is journaled by the gateway itself.
        eprintln!(
            "strands-box: monty fetch refused before transport (SSRF floor): principal=agent url={} reason={error}",
            request.url
        );
        return ExtFunctionResult::Error(MontyException::new(
            ExcType::OSError,
            Some(error.to_string()),
        ));
    }
    match fetch_inner(routing, request).await {
        Ok(response) => ExtFunctionResult::Return(response),
        Err(error) => ExtFunctionResult::Error(MontyException::new(ExcType::OSError, Some(error))),
    }
}

/// Build the routed client, send the request, and shape the response — dials the gateway (never
/// the origin) and trusts only the gateway CA.
async fn fetch_inner(
    routing: &EgressRouting,
    mut request: FetchRequest,
) -> Result<MontyObject, String> {
    telemetry::Correlation::current().inject_http(&mut request.headers);
    let ca = reqwest::Certificate::from_pem(&routing.ca_pem).map_err(|error| error.to_string())?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .proxy(reqwest::Proxy::all(&routing.proxy_target).map_err(|error| error.to_string())?)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .timeout(NETWORK_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;

    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut builder = client.request(method, &request.url);
    for (name, value) in &request.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| error.to_string())?;
        let value =
            reqwest::header::HeaderValue::from_str(value).map_err(|error| error.to_string())?;
        builder = builder.header(name, value);
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }
    let mut response = builder.send().await.map_err(|error| error.to_string())?;

    let status = i64::from(response.status().as_u16());
    // Coalesce repeated header lines into one value per name, so the guest dict loses none of them
    // rather than silently keeping the last. Comma-folding (RFC 7230 §3.2.2) joins most repeats, but
    // `Set-Cookie` is exempt — cookie values legitimately contain commas (an `Expires` date), so it
    // joins with a newline, which a header value can never contain, leaving the guest able to split.
    // Values are decoded lossily rather than with `to_str().unwrap_or("")`, so a non-ASCII value is
    // not silently emptied.
    let mut merged: Vec<(String, String)> = Vec::new();
    for (name, value) in response.headers().iter() {
        let name = name.to_string();
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match merged.iter_mut().find(|(seen, _)| *seen == name) {
            Some((_, existing)) => {
                existing.push_str(if name.eq_ignore_ascii_case("set-cookie") {
                    "\n"
                } else {
                    ", "
                });
                existing.push_str(&value);
            }
            None => merged.push((name, value)),
        }
    }
    let headers: Vec<(MontyObject, MontyObject)> = merged
        .into_iter()
        .map(|(name, value)| (MontyObject::string(name), MontyObject::string(value)))
        .collect();
    // Read the body in chunks and stop at the cap: a post-read buffer would let a large upstream
    // balloon the trusted process's memory before the cap applies. Over-cap is a catchable error.
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body_bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(format!(
                "response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            ));
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&body_bytes).into_owned();

    Ok(MontyObject::dict(vec![
        (
            MontyObject::string("status".to_string()),
            MontyObject::int(status),
        ),
        (
            MontyObject::string("headers".to_string()),
            MontyObject::dict(headers),
        ),
        (
            MontyObject::string("body".to_string()),
            MontyObject::string(body),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use policy::GovernedBox;

    use crate::run::broker::python::tests::{fixture, permissive};
    use crate::run::broker::python::{
        BROKER_FAILURE_STATUS, PYTHON_ORIGIN, SCRIPT_RAISED_STATUS, drive_monty,
    };
    use crate::run::telemetry::DecisionRecorder;

    /// `fetch` with positional and keyword arguments, built as Monty passes them.
    async fn fetch_through_gateway(
        routing: &EgressRouting,
        args: &[MontyObject],
        kwargs: &[(MontyObject, MontyObject)],
    ) -> ExtFunctionResult {
        let mut call = CallArgs::new();
        for value in args {
            call.push_arg(value.clone());
        }
        for (name, value) in kwargs {
            let name = name.as_ref().as_str().expect("a keyword name is a string");
            call.push_kwarg(name, value.clone());
        }
        super::fetch_through_gateway(routing, &call).await
    }

    // ---- Egress: the `fetch` host function ----
    //
    // Modelled on `shell/tests/egress_proxy.rs`. A plain-HTTP request through an HTTP proxy is
    // sent in absolute form (`GET http://host/path ...`), so a bare TCP listener proves routing
    // without a TLS handshake. The CA only has to parse — TLS/CONNECT validation belongs to the
    // box end-to-end suite against a real gateway.

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

    /// A one-shot fake HTTP proxy. Records the request head it saw (request line and headers) and
    /// answers `status`/`body`.
    fn proxy_returning(
        status: u16,
        reason: &str,
        body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
        let addr = listener.local_addr().expect("the proxy has an address");
        let reason = reason.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
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
                let request_head = String::from_utf8_lossy(&data).into_owned();
                let _ = tx.send(request_head);
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

    /// A one-shot fake proxy that answers `200` with a body of exactly `body_len` bytes — to
    /// exercise the `MAX_RESPONSE_BYTES` streaming cap without a real network.
    fn proxy_returning_body_of(body_len: usize) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
        let addr = listener.local_addr().expect("the proxy has an address");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {body_len}\r\nconnection: close\r\n\r\n"
                );
                if stream.write_all(head.as_bytes()).is_err() {
                    return;
                }
                let chunk = vec![b'x'; 64 * 1024];
                let mut sent = 0;
                while sent < body_len {
                    let n = (body_len - sent).min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        break; // the client hit the cap and dropped the connection
                    }
                    sent += n;
                }
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    /// A routing value against `proxy_url`.
    fn routing_with_proxy(proxy_url: String) -> (tempfile::TempDir, EgressRouting) {
        let dir = tempfile::tempdir().expect("a CA dir");
        (
            dir,
            EgressRouting {
                proxy_target: proxy_url,
                ca_pem: Arc::new(TEST_CA_PEM.as_bytes().to_vec()),
            },
        )
    }

    /// Read one value out of a dict by string key.
    fn dict_get(obj: &MontyObject, key: &str) -> Option<MontyObject> {
        obj.as_ref()
            .pairs()?
            .into_iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v.to_owned())
    }

    /// A `fetch(url)` routes through the gateway (absolute-form request) and its response maps to
    /// a guest dict `{status, body}`.
    #[tokio::test]
    async fn fetch_routes_through_the_gateway_and_maps_the_response() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "HELLO");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string(
                "http://origin.example/data".to_string(),
            )],
            &[],
        )
        .await;

        let request_head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy saw a request");
        assert!(
            request_head.starts_with("GET http://origin.example/data"),
            "the request must route through the proxy in absolute form: {request_head}"
        );
        match result {
            ExtFunctionResult::Return(dict) => {
                assert_eq!(dict_get(&dict, "status"), Some(MontyObject::int(200)));
                assert_eq!(
                    dict_get(&dict, "body"),
                    Some(MontyObject::string("HELLO".to_string()))
                );
                // The response headers map into a guest dict, keyed by (lowercased) header name.
                let headers = dict_get(&dict, "headers").expect("a headers dict is present");
                assert_eq!(
                    dict_get(&headers, "content-length"),
                    Some(MontyObject::string("5".to_string())),
                    "the response headers must map into the guest dict"
                );
            }
            _ => panic!("a permitted fetch must return a response dict"),
        }
    }

    #[tokio::test]
    async fn monty_fetch_carries_call_context_and_preserves_explicit_headers() {
        const FIRST: &str = "00-11111111111111111111111111111111-aaaaaaaaaaaaaaaa-03";
        const SECOND: &str = "00-22222222222222222222222222222222-bbbbbbbbbbbbbbbb-01";
        async fn request(parent: Option<&str>, state: Option<&str>, headers: &str) -> String {
            let (_root, reach) = fixture();
            let policy = permissive();
            let (proxy_url, received) = proxy_returning(200, "OK", "FETCH_OK");
            let (_ca, routing) = routing_with_proxy(proxy_url);
            let recorder = DecisionRecorder::discarding()
                .for_request(telemetry::Correlation::from_headers(parent, state));
            let outcome = drive_monty(
                format!("print(fetch(\"http://origin.example/data\"{headers})[\"body\"])"),
                PYTHON_ORIGIN.to_string(),
                &reach,
                &policy,
                &GovernedBox::assigned("fetch-tracing"),
                Some(&routing),
                &recorder,
            )
            .await;
            assert_eq!(outcome.status, 0, "{}", outcome.stderr);
            assert!(outcome.stdout.contains("FETCH_OK"));
            received.recv_timeout(Duration::from_secs(5)).unwrap()
        }

        let (first, second) = tokio::join!(
            request(Some(FIRST), Some("caller=first"), ""),
            request(Some(SECOND), Some("caller=second"), ""),
        );
        for (wire, parent, state, other) in [
            (first, FIRST, "caller=first", SECOND),
            (second, SECOND, "caller=second", FIRST),
        ] {
            assert!(
                wire.contains(&format!("traceparent: {parent}\r\n")),
                "{wire}"
            );
            assert!(wire.contains(&format!("tracestate: {state}\r\n")), "{wire}");
            assert!(!wire.contains(other), "{wire}");
        }
        let explicit = request(
            Some(FIRST),
            Some("caller=first"),
            &format!(
                ", headers={{\"TraceParent\": \"{SECOND}\", \"TraceState\": \"explicit=yes\"}}"
            ),
        )
        .await;
        assert!(explicit.contains(&format!("traceparent: {SECOND}\r\n")));
        assert!(explicit.contains("tracestate: explicit=yes\r\n"));
        assert!(!explicit.contains(FIRST));
        assert!(!explicit.contains("caller=first"));

        let invalid = request(
            Some(FIRST),
            None,
            ", headers={\"traceparent\": \"invalid\"}",
        )
        .await;
        assert!(invalid.contains("traceparent: invalid\r\n"));
        assert!(!invalid.contains(FIRST));
        let absent = request(None, None, "").await;
        assert!(!absent.contains("traceparent:"));
        assert!(!absent.contains("tracestate:"));
    }

    /// A non-200 status is an ordinary value the script reads, not a host error.
    #[tokio::test]
    async fn a_non_200_status_flows_to_the_script_as_a_value() {
        let (proxy_url, _rx) = proxy_returning(404, "Not Found", "missing");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string(
                "http://origin.example/missing".to_string(),
            )],
            &[],
        )
        .await;

        match result {
            ExtFunctionResult::Return(dict) => {
                assert_eq!(dict_get(&dict, "status"), Some(MontyObject::int(404)));
            }
            _ => panic!("a 404 is a normal response, not an error"),
        }
    }

    /// `fetch()` with no url argument is a catchable `TypeError`, and no client is built.
    #[tokio::test]
    async fn fetch_with_no_url_argument_is_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(&routing, &[], &[]).await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("a missing url must be a TypeError"),
        }
    }

    /// With no egress, `fetch` is not the curated route: its own arm fails it closed at the
    /// broker-failure status — the network is off by absence.
    #[tokio::test]
    async fn a_fetch_with_no_egress_is_not_serviced() {
        let (_root, reach) = fixture();
        let policy = permissive();

        let outcome = drive_monty(
            "fetch(\"http://origin.example/x\")".to_string(),
            PYTHON_ORIGIN.to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
        )
        .await;

        assert_eq!(
            outcome.status, BROKER_FAILURE_STATUS,
            "no egress means fetch is not serviced and the run fails closed"
        );
    }

    /// Only `fetch` is serviced: a call to any other name is an unresolved callable, so it raises a
    /// catchable `NameError` at status `1` and the proxy is never contacted.
    #[tokio::test]
    async fn a_non_fetch_call_raises_a_name_error_even_with_egress() {
        let (_root, reach) = fixture();
        let policy = permissive();
        let (proxy_url, _rx) = proxy_returning(200, "OK", "HELLO");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let outcome = drive_monty(
            "nope(1)".to_string(),
            PYTHON_ORIGIN.to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            Some(&routing),
            &DecisionRecorder::discarding(),
        )
        .await;

        assert_eq!(
            outcome.status, SCRIPT_RAISED_STATUS,
            "a non-fetch call is a Python error, not the curated route"
        );
        assert!(
            outcome.stderr.contains("NameError"),
            "the script sees a NameError: status={} stderr={}",
            outcome.status,
            outcome.stderr
        );
    }

    /// A `fetch` with a method, headers, and a body routes all three through the gateway at parity
    /// with the Shell — the proxy sees the method, the custom header, and the body length.
    #[tokio::test]
    async fn a_post_with_headers_and_body_routes_through_the_gateway() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "OK");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string(
                "http://origin.example/submit".to_string(),
            )],
            &[
                (
                    MontyObject::string("method".to_string()),
                    MontyObject::string("POST".to_string()),
                ),
                (
                    MontyObject::string("headers".to_string()),
                    MontyObject::dict(vec![(
                        MontyObject::string("X-Custom".to_string()),
                        MontyObject::string("value".to_string()),
                    )]),
                ),
                (
                    MontyObject::string("body".to_string()),
                    MontyObject::string("hello body".to_string()),
                ),
            ],
        )
        .await;

        let head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy saw a request");
        assert!(
            head.starts_with("POST http://origin.example/submit"),
            "the method must route through in absolute form: {head}"
        );
        let head = head.to_lowercase();
        assert!(
            head.contains("x-custom: value"),
            "the custom header must reach the gateway: {head}"
        );
        assert!(
            head.contains("content-length: 10"),
            "the 10-byte body must be sent: {head}"
        );
        assert!(
            matches!(result, ExtFunctionResult::Return(_)),
            "a permitted POST returns a response dict"
        );
    }

    /// A non-string `method` is a catchable `TypeError`, and no client is built.
    #[tokio::test]
    async fn a_non_string_method_is_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/x".to_string())],
            &[(
                MontyObject::string("method".to_string()),
                MontyObject::int(7),
            )],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("a non-string method must be a TypeError"),
        }
    }

    /// A `headers` value that is not a `{str: str}` dict is a catchable `TypeError`.
    #[tokio::test]
    async fn non_string_header_values_are_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/x".to_string())],
            &[(
                MontyObject::string("headers".to_string()),
                MontyObject::dict(vec![(
                    MontyObject::string("X-Custom".to_string()),
                    MontyObject::int(7),
                )]),
            )],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("a non-string header value must be a TypeError"),
        }
    }

    /// A fetch to a floored literal IP (IMDS/link-local) is refused before any transport, reusing
    /// the Shell's `check_url_safe` (parity with the Shell) — the proxy is never contacted.
    #[tokio::test]
    async fn a_fetch_to_a_floored_ip_is_refused_before_transport() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "OK");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string(
                "http://169.254.169.254/latest/meta-data/".to_string(),
            )],
            &[],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::OSError);
            }
            _ => panic!("a floored literal IP must be refused before transport"),
        }
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "no request should reach the proxy — the refusal is pre-transport"
        );
    }

    /// A response body over `MAX_RESPONSE_BYTES` is a catchable error, not a truncated value — the
    /// streaming cap bounds the trusted process's memory.
    #[tokio::test]
    async fn a_response_over_the_cap_is_an_error() {
        let proxy_url = proxy_returning_body_of(MAX_RESPONSE_BYTES + 1);
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/big".to_string())],
            &[],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::OSError);
            }
            _ => panic!("a response over the cap must be an error, not a truncated value"),
        }
    }

    /// An unresolved callable with no egress is a language error too, not the network-off `125`:
    /// the `fetch`-name guard, not the presence of egress, is what gates the fail-closed status.
    #[tokio::test]
    async fn a_non_fetch_call_with_no_egress_raises_a_name_error() {
        let (_root, reach) = fixture();
        let policy = permissive();

        let outcome = drive_monty(
            "nope(1)".to_string(),
            PYTHON_ORIGIN.to_string(),
            &reach,
            &policy,
            &GovernedBox::assigned("codex"),
            None,
            &DecisionRecorder::discarding(),
        )
        .await;

        assert_eq!(
            outcome.status, SCRIPT_RAISED_STATUS,
            "a non-fetch call is a Python error, not the network-off status"
        );
        assert!(
            outcome.stderr.contains("NameError"),
            "the script sees a NameError: status={} stderr={}",
            outcome.status,
            outcome.stderr
        );
    }

    /// A `bytes` body is sent as-is (not just a `str`), at parity with the gateway's `BodyRef`.
    #[tokio::test]
    async fn a_bytes_body_is_sent_as_is() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "OK");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/b".to_string())],
            &[
                (
                    MontyObject::string("method".to_string()),
                    MontyObject::string("POST".to_string()),
                ),
                (
                    MontyObject::string("body".to_string()),
                    MontyObject::bytes(vec![1, 2, 3, 4]),
                ),
            ],
        )
        .await;

        let head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy saw a request")
            .to_lowercase();
        assert!(head.starts_with("post http://origin.example/b"), "{head}");
        assert!(
            head.contains("content-length: 4"),
            "a 4-byte bytes body is sent as-is: {head}"
        );
        assert!(matches!(result, ExtFunctionResult::Return(_)));
    }

    /// `url` may be supplied as a keyword argument, not only positionally.
    #[tokio::test]
    async fn a_url_keyword_argument_is_accepted() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "OK");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[],
            &[(
                MontyObject::string("url".to_string()),
                MontyObject::string("http://origin.example/kw".to_string()),
            )],
        )
        .await;

        let head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy saw a request");
        assert!(head.starts_with("GET http://origin.example/kw"), "{head}");
        assert!(matches!(result, ExtFunctionResult::Return(_)));
    }

    /// `method`, `headers`, and `body` may be supplied positionally, not only as keywords.
    #[tokio::test]
    async fn method_and_body_may_be_positional() {
        let (proxy_url, rx) = proxy_returning(200, "OK", "OK");
        let (_dir, routing) = routing_with_proxy(proxy_url);

        let result = fetch_through_gateway(
            &routing,
            &[
                MontyObject::string("http://origin.example/p".to_string()),
                MontyObject::string("POST".to_string()), // method, positional
                MontyObject::none(),                     // headers, positional
                MontyObject::string("hi".to_string()),   // body, positional
            ],
            &[],
        )
        .await;

        let head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy saw a request")
            .to_lowercase();
        assert!(head.starts_with("post http://origin.example/p"), "{head}");
        assert!(
            head.contains("content-length: 2"),
            "a positional body is sent: {head}"
        );
        assert!(matches!(result, ExtFunctionResult::Return(_)));
    }

    /// Repeated response headers are coalesced, losing none: an ordinary header comma-folds
    /// (RFC 7230), but `Set-Cookie` joins with a newline (it is comma-exempt — cookie values contain
    /// commas), so the guest can split it back.
    #[tokio::test]
    async fn duplicate_response_headers_are_coalesced() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
        let addr = listener.local_addr().expect("the proxy has an address");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = "HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n\
                    vary: accept\r\nvary: origin\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi";
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.flush();
            }
        });
        let (_dir, routing) = routing_with_proxy(format!("http://{addr}"));

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/c".to_string())],
            &[],
        )
        .await;

        match result {
            ExtFunctionResult::Return(dict) => {
                let headers = dict_get(&dict, "headers").expect("a headers dict is present");
                assert_eq!(
                    dict_get(&headers, "set-cookie"),
                    Some(MontyObject::string("a=1\nb=2".to_string())),
                    "both Set-Cookie values must survive, newline-joined (not comma-folded)"
                );
                assert_eq!(
                    dict_get(&headers, "vary"),
                    Some(MontyObject::string("accept, origin".to_string())),
                    "an ordinary repeated header comma-folds per RFC 7230"
                );
            }
            _ => panic!("a permitted fetch must return a response dict"),
        }
    }

    /// An unknown keyword argument (a typo like `header=` for `headers=`) is a catchable TypeError,
    /// not a silently dropped value — no transport, no client built.
    #[tokio::test]
    async fn an_unknown_keyword_argument_is_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/x".to_string())],
            &[(
                MontyObject::string("header".to_string()), // typo for "headers"
                MontyObject::dict(vec![(
                    MontyObject::string("Authorization".to_string()),
                    MontyObject::string("Bearer t".to_string()),
                )]),
            )],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("an unknown keyword argument must be a TypeError"),
        }
    }

    /// Extra positional arguments are a catchable TypeError, matching Python's call semantics.
    #[tokio::test]
    async fn too_many_positional_arguments_is_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(
            &routing,
            &[
                MontyObject::string("http://origin.example/x".to_string()),
                MontyObject::string("GET".to_string()),
                MontyObject::none(),
                MontyObject::none(),
                MontyObject::string("extra".to_string()), // a fifth positional
            ],
            &[],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("too many positional arguments must be a TypeError"),
        }
    }

    /// One argument given both positionally and by keyword is a catchable TypeError, not a silently
    /// dropped keyword value — matching Python's "got multiple values for argument".
    #[tokio::test]
    async fn both_positional_and_keyword_for_one_arg_is_a_type_error() {
        let (_dir, routing) = routing_with_proxy("http://127.0.0.1:1".to_string());

        let result = fetch_through_gateway(
            &routing,
            &[MontyObject::string("http://origin.example/x".to_string())],
            &[(
                MontyObject::string("url".to_string()),
                MontyObject::string("http://other.example/".to_string()),
            )],
        )
        .await;

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::TypeError);
            }
            _ => panic!("both positional and keyword for one argument must be a TypeError"),
        }
    }
}
