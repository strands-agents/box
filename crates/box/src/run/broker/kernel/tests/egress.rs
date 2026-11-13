//! The Shell's HTTP goes through the egress gateway and meets the SSRF floor in the kernel.

use std::io::Write as _;
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use box_shell::ShellKernel;

use super::{PermitAll, backend, run as on_shell_runtime};
use crate::run::broker::kernel::GatewayNetwork;
use crate::run::broker::shell::EgressRouting;

fn read_head(stream: &mut impl std::io::Read) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
        head.push(byte[0]);
    }
    head
}

/// A self-signed certificate for `a.example` and its PEM.
fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["a.example".to_string()]).expect("a certificate")
}

/// The head and body of one request the fake gateway received.
struct SeenRequest {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

impl SeenRequest {
    /// Whether a header line contains `needle`, without regard to case.
    fn has_header(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.headers
            .iter()
            .any(|line| line.to_ascii_lowercase().contains(&needle))
    }
}

/// Read one request head and its `Content-Length` body from `stream`.
fn read_request(stream: &mut impl std::io::Read) -> SeenRequest {
    let head = String::from_utf8_lossy(&read_head(stream)).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers: Vec<String> = lines
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    let length = headers
        .iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    let _ = stream.read_exact(&mut body);
    SeenRequest {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// The routing to a fake gateway at `address`.
fn routing(address: std::net::SocketAddr) -> EgressRouting {
    EgressRouting {
        proxy_target: format!("http://{address}"),
        ca_pem: Arc::new(certificate().cert.pem().into_bytes()),
    }
}

/// A fake gateway that answers one connection per entry of `responses`, and reports each request.
fn scripted(
    responses: impl IntoIterator<Item = String> + Send + 'static,
) -> (EgressRouting, mpsc::Receiver<SeenRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
    let address = listener.local_addr().expect("the gateway has an address");
    let (seen, requests) = mpsc::channel();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = seen.send(read_request(&mut stream));
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (routing(address), requests)
}

/// A fake gateway that answers each connection with `response`, and reports each request.
fn gateway(response: &'static str) -> (EgressRouting, mpsc::Receiver<SeenRequest>) {
    scripted(std::iter::repeat(response.to_string()))
}

/// A fake gateway that answers the first connection with `first` and never answers a later one.
fn then_hang(first: Option<String>) -> EgressRouting {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
    let address = listener.local_addr().expect("the gateway has an address");
    std::thread::spawn(move || {
        if let Some(first) = first
            && let Ok((mut stream, _)) = listener.accept()
        {
            read_head(&mut stream);
            let _ = stream.write_all(first.as_bytes());
        }
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    routing(address)
}

/// A raw `HTTP/1.1` response with `headers` and `body`.
fn response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    response
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

/// A gateway that answers every request with `status` and `body`.
fn answering(status: &str, body: &str) -> (EgressRouting, mpsc::Receiver<SeenRequest>) {
    scripted(std::iter::repeat(response(status, &[], body)))
}

/// The one request a gateway received.
fn first(requests: &mpsc::Receiver<SeenRequest>) -> SeenRequest {
    requests
        .recv_timeout(Duration::from_secs(5))
        .expect("the gateway saw a request")
}

fn run(egress: Option<EgressRouting>, command: &str) -> (i32, String, String) {
    run_each(egress, &[command]).remove(0)
}

/// Run each of `commands` in turn on one Shell.
fn run_each(egress: Option<EgressRouting>, commands: &[&str]) -> Vec<(i32, String, String)> {
    let mut kernel = ShellKernel::over(backend(&[]), Arc::new(PermitAll));
    if let Some(egress) = egress {
        kernel = kernel.network(Arc::new(GatewayNetwork::new(
            egress,
            telemetry::Correlation::from_headers(None, None),
        )));
    }
    on_shell_runtime(async {
        let mut shell = kernel.shell();
        let mut outputs = Vec::new();
        for command in commands {
            let output = shell.run(command).await;
            outputs.push((output.status, output.stdout, output.stderr));
        }
        outputs
    })
}

#[test]
fn with_no_gateway_every_request_is_refused() {
    let (status, _stdout, stderr) = run(None, "curl -sS https://a.example/");

    assert_eq!(status, 1, "{stderr}");
    assert!(stderr.contains("network access disabled"), "{stderr}");
}

#[test]
fn a_marked_refusal_fails_curl() {
    let (routing, _connections) = gateway(
        "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nContent-Length: 13\r\n\
         Connection: close\r\n\r\npolicy denied",
    );

    let (status, stdout, stderr) = run(Some(routing), "curl -sS http://a.example/");

    assert_eq!(status, 1, "{stdout} {stderr}");
    assert!(stderr.contains("policy denied"), "{stderr}");
    assert!(!stdout.contains("policy denied"), "{stdout}");
}

#[test]
fn a_private_address_is_refused_before_transport() {
    let (routing, connections) =
        gateway("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nLEAKED");

    let (_status, stdout, stderr) = run(
        Some(routing),
        "curl -sS http://169.254.169.254/; echo \" status=$?\"\n\
         curl -sS http://127.0.0.1/; echo \" status=$?\"",
    );

    assert_eq!(stdout.matches(" status=1").count(), 2, "{stdout} {stderr}");
    assert!(!stdout.contains("LEAKED"), "{stdout}");
    assert!(
        connections
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "no private address reaches the gateway"
    );
}

#[test]
fn a_redirect_hop_meets_the_floor_in_the_wrapper() {
    let (routing, connections) = gateway(
        "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    let (status, stdout, stderr) = run(Some(routing), "curl -sSL http://a.example/");

    assert_eq!(status, 1, "{stdout} {stderr}");
    assert!(stderr.contains("169.254.169.254"), "{stderr}");
    assert!(connections.recv_timeout(Duration::from_secs(5)).is_ok());
    assert!(
        connections
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "the private hop never reaches the gateway"
    );
}

#[test]
fn insecure_does_not_widen_trust() {
    let leaf = certificate();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf.signing_key.serialize_der().into());
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.cert.der().clone()], key)
            .expect("server TLS config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
    let address = listener.local_addr().expect("the gateway has an address");
    let (tunnel, tunnelled) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        read_head(&mut stream);
        let _ = tunnel.send(());
        let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(config).expect("a TLS server"),
            stream,
        );
        read_head(&mut tls);
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTRUSTED");
    });
    let routing = EgressRouting {
        proxy_target: format!("http://{address}"),
        ca_pem: Arc::new(certificate().cert.pem().into_bytes()),
    };

    let (status, stdout, stderr) = run(Some(routing), "curl -sSk https://a.example/");

    assert_ne!(status, 0, "{stdout} {stderr}");
    assert!(!stdout.contains("TRUSTED"), "{stdout}");
    assert!(
        tunnelled.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the request reached the gateway and failed at its certificate"
    );
}

#[test]
fn a_curl_reaches_the_gateway_in_absolute_form() {
    let (routing, requests) = answering("200 OK", "HELLO");

    let (status, stdout, stderr) = run(Some(routing), "curl http://a.example/");

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "HELLO");
    let seen = first(&requests);
    assert!(
        seen.request_line.starts_with("GET http://a.example/"),
        "{}",
        seen.request_line
    );
}

#[test]
fn the_floor_refuses_a_loopback_name_before_the_gateway() {
    let (routing, requests) = answering("200 OK", "LEAKED");

    let (status, stdout, _stderr) = run(Some(routing), "curl http://localhost/secret");

    assert_ne!(status, 0);
    assert!(!stdout.contains("LEAKED"), "{stdout}");
    assert!(
        requests.recv_timeout(Duration::from_millis(300)).is_err(),
        "a floored request never reaches the gateway"
    );
}

#[test]
fn a_post_body_and_header_reach_the_gateway() {
    let (routing, requests) = answering("200 OK", "STORED");

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sS -X POST -H 'X-Test: yes' -d 'name=value' http://a.example/submit",
    );

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "STORED");
    let seen = first(&requests);
    assert!(
        seen.request_line
            .starts_with("POST http://a.example/submit"),
        "{}",
        seen.request_line
    );
    assert!(seen.has_header("x-test: yes"), "{:?}", seen.headers);
    assert_eq!(seen.body, "name=value");
}

#[test]
fn a_json_body_sets_the_content_type() {
    let (routing, requests) = answering("200 OK", "OK");

    let (status, _stdout, stderr) = run(
        Some(routing),
        "curl -sS --json '{\"k\":1}' http://a.example/api",
    );

    assert_eq!(status, 0, "{stderr}");
    let seen = first(&requests);
    assert!(
        seen.has_header("content-type: application/json"),
        "{:?}",
        seen.headers
    );
    assert_eq!(seen.body, "{\"k\":1}");
}

#[test]
fn an_explicit_method_reaches_the_gateway() {
    let (routing, requests) = answering("200 OK", "OK");

    let (status, _stdout, stderr) = run(Some(routing), "curl -sS -X PUT http://a.example/thing");

    assert_eq!(status, 0, "{stderr}");
    let seen = first(&requests);
    assert!(
        seen.request_line.starts_with("PUT http://a.example/thing"),
        "{}",
        seen.request_line
    );
}

#[test]
fn fail_makes_a_404_a_nonzero_exit_without_the_body() {
    let (routing, _requests) = answering("404 Not Found", "nope");

    let (status, stdout, _stderr) = run(Some(routing), "curl -sS -f http://a.example/missing");

    assert_ne!(status, 0);
    assert!(!stdout.contains("nope"), "{stdout}");
}

#[test]
fn include_prints_the_status_line_before_the_body() {
    let (routing, _requests) = answering("201 Created", "BODY");

    let (status, stdout, stderr) = run(Some(routing), "curl -sS -i http://a.example/new");

    assert_eq!(status, 0, "{stderr}");
    assert!(stdout.contains("201"), "{stdout}");
    assert!(stdout.contains("BODY"), "{stdout}");
}

#[test]
fn output_writes_the_body_to_a_file() {
    let (routing, _requests) = answering("200 OK", "DOWNLOADED");

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sS -o /tmp/dl.txt http://a.example/file; cat /tmp/dl.txt",
    );

    assert_eq!(status, 0, "{stderr}");
    assert!(stdout.contains("DOWNLOADED"), "{stdout}");
}

#[test]
fn write_out_reaches_stdout_when_output_goes_to_a_file() {
    let (routing, _requests) = answering("200 OK", "BODY");

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sS -o /tmp/dl.txt -w 'code=%{http_code}\\n' http://a.example/file",
    );

    assert_eq!(status, 0, "{stderr}");
    assert!(stdout.contains("code=200"), "{stdout}");
    assert!(!stdout.contains("BODY"), "{stdout}");
}

#[test]
fn an_unmarked_403_stays_the_origins_answer() {
    let (routing, _requests) = answering("403 Forbidden", "the origin said no");

    let (status, stdout, stderr) = run(Some(routing), "curl http://a.example/");

    assert_eq!(status, 0, "{stderr}");
    assert!(stdout.contains("the origin said no"), "{stdout}");
}

#[test]
fn globoff_is_accepted() {
    let (routing, _requests) = answering("200 OK", "HELLO");

    let (status, stdout, stderr) = run(Some(routing), "curl -g --globoff http://a.example/");

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "HELLO");
}

#[test]
fn user_agent_reaches_the_gateway() {
    let (routing, requests) = answering("200 OK", "HELLO");

    let (status, _stdout, stderr) = run(Some(routing), "curl -A 'agent/1.0' http://a.example/");

    assert_eq!(status, 0, "{stderr}");
    let seen = first(&requests);
    assert!(
        seen.has_header("user-agent: agent/1.0"),
        "{:?}",
        seen.headers
    );
}

#[test]
fn a_user_agent_header_overrides_the_agent_flag() {
    let (routing, requests) = answering("200 OK", "HELLO");

    let (status, _stdout, stderr) = run(
        Some(routing),
        "curl -A 'agent/1.0' -H 'User-Agent: explicit' http://a.example/",
    );

    assert_eq!(status, 0, "{stderr}");
    let seen = first(&requests);
    assert!(
        seen.has_header("user-agent: explicit"),
        "{:?}",
        seen.headers
    );
    assert!(!seen.has_header("agent/1.0"), "{:?}", seen.headers);
}

#[test]
fn an_empty_user_agent_sends_none() {
    let (routing, requests) = answering("200 OK", "HELLO");

    let (status, _stdout, stderr) = run(Some(routing), "curl -A '' http://a.example/");

    assert_eq!(status, 0, "{stderr}");
    let seen = first(&requests);
    assert!(!seen.has_header("user-agent:"), "{:?}", seen.headers);
}

#[test]
fn max_time_exits_28() {
    let routing = then_hang(None);
    let started = std::time::Instant::now();

    let (status, _stdout, stderr) = run(Some(routing), "curl -sS --max-time 0.2 http://a.example/");

    assert_eq!(status, 28, "{stderr}");
    assert!(stderr.contains("(28)"), "{stderr}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn max_time_spans_redirect_hops_and_writes_write_out() {
    let routing = then_hang(Some(redirect_to("/slow")));

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sL -m 0.3 -w '%{http_code} %{url_effective}' http://a.example/",
    );

    assert_eq!(status, 28, "{stderr}");
    assert_eq!(stdout, "000 http://a.example/slow");
}

#[test]
fn max_time_zero_and_huge_are_no_limit() {
    let (routing, _requests) = answering("200 OK", "HELLO");

    for limit in ["0", "1e19", "1e300", "99999999999999999999"] {
        let (status, stdout, stderr) = run(
            Some(routing.clone()),
            &format!("curl -m {limit} http://a.example/"),
        );

        assert_eq!(status, 0, "-m {limit}: {stderr}");
        assert_eq!(stdout, "HELLO", "-m {limit}");
    }
}

#[test]
fn proto_redir_refuses_a_redirect() {
    let (routing, requests) = scripted(vec![redirect_to("/next"), html("NEXT")]);

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sSL --proto-redir '=https' http://a.example/",
    );

    assert_eq!(status, 1, "{stderr}");
    assert_eq!(stdout, "");
    first(&requests);
    assert!(
        requests.recv_timeout(Duration::from_millis(200)).is_err(),
        "the refused hop never reaches the gateway"
    );
}

#[test]
fn a_non_http_redirect_is_refused() {
    let (routing, _requests) = scripted(vec![redirect_to("ftp://a.example/file")]);

    let (status, _stdout, stderr) = run(
        Some(routing),
        "curl -sSL --proto '=http,https' --proto-redir '=http,https' http://a.example/",
    );

    assert_eq!(status, 1, "{stderr}");
    assert!(
        stderr.contains("Protocol \"ftp\" not supported"),
        "{stderr}"
    );
}

#[test]
fn the_last_proto_wins() {
    let (routing, _requests) = answering("200 OK", "HELLO");

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl --proto -http --proto -https http://a.example/",
    );

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "HELLO");
}

#[test]
fn write_out_reports_content_type_and_effective_url() {
    let (routing, _requests) = scripted(vec![redirect_to("/next"), html("NEXT")]);

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sL -w '\\n%{content_type}\\n%{url_effective}' http://a.example/",
    );

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(
        stdout,
        "NEXT\ntext/html; charset=utf-8\nhttp://a.example/next"
    );
}

#[test]
fn write_out_is_written_on_fail() {
    let (routing, _requests) = answering("404 Not Found", "gone");

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sf -w '%{http_code}' http://a.example/",
    );

    assert_eq!(status, 22, "{stderr}");
    assert_eq!(stdout, "404");
}

#[test]
fn write_out_does_not_expand_a_substituted_value() {
    let (routing, _requests) = scripted(vec![response(
        "200 OK",
        &[("Content-Type", r"text/plain;%{url_effective}\n")],
        "body",
    )]);

    let (_status, stdout, _stderr) = run(
        Some(routing),
        "curl -s -o /dev/null -w '%{content_type}|' http://a.example/",
    );

    assert_eq!(stdout, r"text/plain;%{url_effective}\n|");
}

#[test]
fn include_with_output_writes_headers_to_the_file() {
    let (routing, _requests) = answering("200 OK", "BODY");

    let outputs = run_each(
        Some(routing),
        &[
            "curl -s -i -o /tmp/inc.txt http://a.example/",
            "cat /tmp/inc.txt",
        ],
    );

    assert_eq!(outputs[0].1, "", "{}", outputs[0].2);
    assert!(
        outputs[1].1.starts_with("HTTP/1.1 200 OK\r\n"),
        "{}",
        outputs[1].1
    );
    assert!(outputs[1].1.ends_with("\r\n\r\nBODY"), "{}", outputs[1].1);
}

#[test]
fn the_web_fetch_command_line_works() {
    let (routing, requests) = scripted(vec![redirect_to("/next"), html("<p>page</p>")]);

    let (status, stdout, stderr) = run(
        Some(routing),
        "curl -sSL -g --fail --proto '=http,https' --proto-redir '=http,https' \
         --max-time 30 -A 'web-fetch/1.0' -o /tmp/page.html \
         -w '%{content_type}\\n%{url_effective}' -- http://a.example/; \
         echo; cat /tmp/page.html",
    );

    assert_eq!(status, 0, "{stderr}");
    assert_eq!(
        stdout,
        "text/html; charset=utf-8\nhttp://a.example/next\n<p>page</p>"
    );
    for _ in 0..2 {
        let seen = first(&requests);
        assert!(
            seen.has_header("user-agent: web-fetch/1.0"),
            "every hop carries -A: {:?}",
            seen.headers
        );
    }
}
