//! `box-egress-probe` — a test-only workload that makes one governed HTTPS request.
//!
//! Test-only, declared under `tests/support/` and gated on the non-default
//! `test-support` feature so a normal build cannot mistake it for a product binary
//! (the same shape as `containment`'s `containment-test-probe`).
//!
//! It exists because the credential end-to-end tests need a workload that actually
//! *sends* a request, and no host binary can:
//!
//! - macOS `curl` links LibreSSL, which reads `/private/etc/ssl/openssl.cnf` at
//!   startup. Containment denies that path, so `curl` fails before connecting — the
//!   box working as designed, not a defect to route around.
//! - The Strands Shell's `curl` builtin is reached through the box's shell alias, which
//!   is a different integration; these tests are about the credential path, so pulling
//!   the Shell in would make a Shell regression look like a credential regression.
//!
//! So the probe speaks the proxy protocol itself: CONNECT over plain TCP, then TLS to
//! the leaf the proxy mints, reading `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` from its
//! environment exactly as an SDK would. Termination is unconditional, so
//! a plaintext exchange after CONNECT is not reachable — the probe must complete a
//! handshake, which is also what proves the box's CA reaches the workload.
//!
//! Usage: `box-egress-probe <url> <phantom-env-var> [-- <command> <args…>]`, or
//! `box-egress-probe protect-authority <config> <policy> <replacement> <alias>`, or
//! `box-egress-probe move-authority-parent <source> <destination> <relative-authority>`, or
//! `box-egress-probe broker-move-authority-parent <alias> <source> <destination> <moved-config>`.
//!
//! It prints `status=<code>` on success, or `probe-error: <reason>` and exits non-zero.
//! The phantom is read from the named variable and sent as `Authorization: Bearer …`.
//!
//! **With a trailing command it probes twice, and that is what makes a cross-boundary temporal
//! rule measurable.** Such a rule reads history: an `fs:read` through an interpreter must close
//! egress at the gateway. Both effects have to land in **one** history in a known order, so one
//! workload reaches both boundaries. The probe runs inside the cage with the box's `bin/` on
//! `PATH`, so it can exec an interpreter alias itself.
//!
//! The sequence is: request, then the command, then the same request again. It prints
//! `status=<code>`, `read=ok` or `read=failed`, then `status_after=<code>`. A control and its
//! measurement in one run, which is why the first status is printed rather than assumed.

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn main() {
    let mut arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("trace-requests") {
        trace_requests(&arguments[1..]);
        return;
    }
    if arguments.first().map(String::as_str) == Some("http-response") {
        http_response(&arguments[1..]);
        return;
    }
    if arguments.first().map(String::as_str) == Some("protect-authority") {
        protect_authority(&arguments[1..]);
        return;
    }
    if arguments.first().map(String::as_str) == Some("move-authority-parent") {
        move_authority_parent(&arguments[1..]);
        return;
    }
    if arguments.first().map(String::as_str) == Some("broker-move-authority-parent") {
        broker_move_authority_parent(&arguments[1..]);
        return;
    }

    // Everything after `--` is a command to run between the two requests. Split first, so a
    // command's own arguments can never be read as the probe's.
    let between = arguments
        .iter()
        .position(|argument| argument == "--")
        .map(|separator| arguments.split_off(separator)[1..].to_vec());
    let mut arguments = arguments.into_iter();
    let (Some(url), Some(variable)) = (arguments.next(), arguments.next()) else {
        fail("usage: box-egress-probe <url> <phantom-env-var> [-- <command> <args…>]");
    };

    let token = match env::var(&variable) {
        Ok(token) => token,
        Err(_) => fail(&format!(
            "{variable} is not set in the workload environment"
        )),
    };

    // The supervisor seeds this; an SDK would read the same variable.
    let proxy = match env::var("HTTPS_PROXY").or_else(|_| env::var("https_proxy")) {
        Ok(proxy) => proxy,
        Err(_) => fail("HTTPS_PROXY is not set"),
    };
    let proxy_authority = proxy
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();

    let (authority, path) = match split_url(&url) {
        Some(parts) => parts,
        None => fail(&format!("cannot parse url {url:?}")),
    };
    // An HTTPS url with no explicit port means 443, which is also what the CONNECT
    // authority must say for the boundary's Host-binding check to pass.
    let authority = if authority.contains(':') {
        authority
    } else {
        format!("{authority}:443")
    };

    match request(&proxy_authority, &authority, &path, &token) {
        Ok(status) => println!("status={status}"),
        Err(reason) => fail(&reason),
    }

    let Some(command) = between else {
        return;
    };
    let Some((program, rest)) = command.split_first() else {
        fail("`--` was given with no command after it");
    };

    // The interpreter alias, exec'd from inside the cage. Its effect is judged by the same
    // `PolicyEngine` this run's gateway holds, so it lands in the history the rule below reads.
    match std::process::Command::new(program).args(rest).status() {
        Ok(status) if status.success() => println!("read=ok"),
        Ok(status) => println!("read=failed status={status}"),
        Err(error) => println!("read=failed error={error}"),
    }

    // The same request again. A refusal arrives as a status rather than as an error, because the
    // boundary answering `403` at CONNECT *is* the measurement.
    match request(&proxy_authority, &authority, &path, &token) {
        Ok(status) => println!("status_after={status}"),
        Err(reason) => println!("probe-error-after: {reason}"),
    }
}

fn http_response(arguments: &[String]) {
    let [authority, body] = arguments else {
        fail("usage: box-egress-probe http-response <authority> <body>");
    };
    let proxy = env::var("HTTPS_PROXY").unwrap_or_else(|error| fail(&error.to_string()));
    let mut stream = TcpStream::connect(proxy.trim_start_matches("http://"))
        .unwrap_or_else(|error| fail(&error.to_string()));
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap_or_else(|error| fail(&error.to_string()));
    write!(
        stream,
        "POST http://{authority}/mcp HTTP/1.1\r\nHost: {authority}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap_or_else(|error| fail(&error.to_string()));
    let mut response = String::new();
    stream
        .take(32 * 1024)
        .read_to_string(&mut response)
        .unwrap_or_else(|error| fail(&error.to_string()));
    print!("{response}");
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceRequest {
    url: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    body: Option<serde_json::Value>,
}

fn trace_requests(arguments: &[String]) {
    let [requests] = arguments else {
        fail("usage: box-egress-probe trace-requests <requests-json>");
    };
    let requests: Vec<TraceRequest> =
        serde_json::from_str(requests).unwrap_or_else(|error| fail(&error.to_string()));
    for request in requests {
        let response = trace_request(&request).unwrap_or_else(|error| fail(&error.to_string()));
        println!("{response}");
    }
}

fn trace_request(request: &TraceRequest) -> std::io::Result<serde_json::Value> {
    let proxy = env::var("HTTPS_PROXY").map_err(std::io::Error::other)?;
    let mut stream = TcpStream::connect(proxy.trim_start_matches("http://").trim_end_matches('/'))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let (scheme, rest) = request
        .url
        .split_once("://")
        .ok_or_else(|| std::io::Error::other("request URL needs a scheme"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    match scheme {
        "https" => {
            write!(
                stream,
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            )?;
            let head = read_head(&mut stream)?;
            if status_of(&head) != Some(200) {
                return Err(std::io::Error::other(format!("CONNECT refused: {head}")));
            }
            let host = authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host);
            let mut tls = start_tls(stream, host).map_err(std::io::Error::other)?;
            let mut response = trace_exchange(&mut tls, authority, &format!("/{path}"), request)?;
            let protocol = tls
                .conn
                .protocol_version()
                .ok_or_else(|| std::io::Error::other("TLS protocol was not negotiated"))?;
            let cipher = tls
                .conn
                .negotiated_cipher_suite()
                .ok_or_else(|| std::io::Error::other("TLS cipher was not negotiated"))?;
            response["tls"] = serde_json::json!({
                "protocol": format!("{protocol:?}"),
                "cipher_suite": format!("{:?}", cipher.suite())
            });
            Ok(response)
        }
        "http" => trace_exchange(&mut stream, authority, &request.url, request),
        _ => Err(std::io::Error::other("expected http or https")),
    }
}

fn trace_exchange(
    stream: &mut (impl Read + Write),
    authority: &str,
    target: &str,
    request: &TraceRequest,
) -> std::io::Result<serde_json::Value> {
    let body = request
        .body
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let method = if request.body.is_some() {
        "POST"
    } else {
        "GET"
    };
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    for (name, value) in &request.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n{body}")?;
    stream.flush()?;
    let head = read_head(stream)?;
    let status = status_of(&head).ok_or_else(|| std::io::Error::other("missing HTTP status"))?;
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| std::io::Error::other("missing response content-length"))?
        .1
        .trim()
        .parse()
        .map_err(std::io::Error::other)?;
    if length > 64 * 1024 {
        return Err(std::io::Error::other("response exceeds fixture limit"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(serde_json::json!({
        "status": status,
        "body": String::from_utf8(body).map_err(std::io::Error::other)?
    }))
}

fn protect_authority(arguments: &[String]) {
    let [config, policy, replacement, alias] = arguments else {
        fail(
            "usage: box-egress-probe protect-authority \
             <config> <policy> <replacement> <alias>",
        );
    };

    let write = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(config)
        .and_then(|mut file| file.write_all(b"changed"));
    report_mutation("write", write);
    report_mutation("delete", std::fs::remove_file(policy));
    report_mutation("replace", std::fs::rename(replacement, config));
    report_mutation("link", std::fs::hard_link(config, alias));
}

fn move_authority_parent(arguments: &[String]) {
    let [source, destination, relative_authority] = arguments else {
        fail(
            "usage: box-egress-probe move-authority-parent \
             <source> <destination> <relative-authority>",
        );
    };
    let source = std::path::Path::new(source);
    let sibling = source.join("ordinary");
    let moved_sibling = source.join("ordinary-moved");
    let sibling_mutation = std::fs::write(&sibling, "ordinary")
        .and_then(|()| rename_at(&sibling, &moved_sibling))
        .and_then(|()| unlink_at(&moved_sibling, 0))
        .and_then(|()| {
            let path = std::ffi::CString::new(sibling.as_os_str().as_encoded_bytes())?;
            // SAFETY: the path is NUL-terminated and lives through the call.
            if unsafe { libc::mkdirat(libc::AT_FDCWD, path.as_ptr(), 0o700) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
        .and_then(|()| rename_at(&sibling, &moved_sibling))
        .and_then(|()| unlink_at(&moved_sibling, libc::AT_REMOVEDIR));
    report_mutation("sibling_mutation", sibling_mutation);
    let moved = rename_at(source, std::path::Path::new(destination));
    if let Err(error) = &moved {
        println!("parent_move_errno={}", error.raw_os_error().unwrap_or(0));
    }
    let can_replace = moved.is_ok();
    report_mutation("parent_move", moved);
    if can_replace {
        let authority = source.join(relative_authority);
        let replacement = std::fs::create_dir_all(authority.parent().expect("authority parent"))
            .and_then(|()| std::fs::write(&authority, "replacement"));
        report_mutation("source_replacement", replacement);
    }
    report_mutation(
        "source_write",
        std::fs::write(source.join(relative_authority), "replacement"),
    );
}

fn unlink_at(path: &std::path::Path, flags: libc::c_int) -> std::io::Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: the path is NUL-terminated and lives through the call.
    if unsafe { libc::unlinkat(libc::AT_FDCWD, path.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn rename_at(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_encoded_bytes())?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes())?;
    // SAFETY: both paths are NUL-terminated and live through the call.
    if unsafe {
        libc::renameat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn broker_move_authority_parent(arguments: &[String]) {
    let [alias, source, destination, moved_config] = arguments else {
        fail(
            "usage: box-egress-probe broker-move-authority-parent \
             <alias> <source> <destination> <moved-config>",
        );
    };
    let command = format!(
        "printf 'broker_reached=yes\\n'; mv -- {} {}",
        shell_word(source),
        shell_word(destination)
    );
    let move_status = std::process::Command::new(alias)
        .args(["-lc", &command])
        .status();
    report_status("broker_parent_move", move_status);
    let write = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(moved_config)
        .and_then(|mut file| file.write_all(b"changed"));
    report_mutation("moved_write", write);
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn report_mutation(name: &str, result: std::io::Result<()>) {
    println!(
        "{name}={}",
        if result.is_err() {
            "refused"
        } else {
            "allowed"
        }
    );
}

fn report_status(name: &str, result: std::io::Result<std::process::ExitStatus>) {
    println!(
        "{name}={}",
        if matches!(result, Ok(status) if status.success()) {
            "allowed"
        } else {
            "refused"
        }
    );
}

/// CONNECT through the proxy, complete TLS, send one request, and read its status.
fn request(proxy: &str, authority: &str, path: &str, token: &str) -> Result<u16, String> {
    let mut stream =
        TcpStream::connect(proxy).map_err(|error| format!("connect to proxy {proxy}: {error}"))?;

    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .map_err(|error| format!("write CONNECT: {error}"))?;

    let ack = read_head(&mut stream).map_err(|error| format!("read CONNECT ack: {error}"))?;
    let ack_status = status_of(&ack).ok_or_else(|| format!("malformed CONNECT ack: {ack:?}"))?;
    if ack_status != 200 {
        // A refusal at CONNECT is the boundary's answer (a floor deny, or a policy deny
        // of `net:connect`), and it is the status the test wants to see.
        return Ok(ack_status);
    }

    // Termination is unconditional, so the tunnel now expects a ClientHello. The leaf is
    // minted by the box's ephemeral CA, which the supervisor granted us the path to.
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority);
    let mut tls = start_tls(stream, host)?;

    tls.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .map_err(|error| format!("write request: {error}"))?;
    tls.flush().map_err(|error| format!("flush: {error}"))?;

    let head = read_head(&mut tls).map_err(|error| format!("read response: {error}"))?;
    status_of(&head).ok_or_else(|| format!("malformed response: {head:?}"))
}

/// Wrap the open tunnel in TLS, trusting only the box's ephemeral CA.
///
/// The CA path arrives in `NODE_EXTRA_CA_CERTS`, which is how the supervisor tells a
/// workload where the intercept root is. Trusting *only* it (rather than adding it to
/// the system roots) means a handshake success also proves the box wired its own CA in.
fn start_tls(
    stream: TcpStream,
    host: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let ca_path = env::var("NODE_EXTRA_CA_CERTS").map_err(|_| {
        "NODE_EXTRA_CA_CERTS is not set, so the intercept CA is unknown".to_string()
    })?;
    let pem =
        std::fs::read(&ca_path).map_err(|error| format!("read intercept CA {ca_path}: {error}"))?;

    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        let certificate =
            certificate.map_err(|error| format!("parse intercept CA {ca_path}: {error}"))?;
        roots
            .add(certificate)
            .map_err(|error| format!("trust intercept CA {ca_path}: {error}"))?;
    }
    if roots.is_empty() {
        return Err(format!("intercept CA {ca_path} contained no certificate"));
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = host
        .to_string()
        .try_into()
        .map_err(|_| format!("invalid server name {host:?}"))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| format!("TLS init: {error}"))?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

/// Read up to the end of the head, bounded.
///
/// An `UnexpectedEof` after some bytes have arrived is not an error here: the boundary
/// closes the connection after a `Connection: close` exchange, and a TLS peer that closes
/// without `close_notify` surfaces as exactly that. The status line is already in hand by
/// then, so the read has produced what the caller needs. An error with *nothing* read
/// still propagates, since that is a genuine failure to get a response.
fn read_head<S: Read>(stream: &mut S) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") && buffer.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => buffer.push(byte[0]),
            Err(error) if !buffer.is_empty() => {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// The status code from a status line.
fn status_of(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Split `https://authority/path` into its authority and origin-form path.
fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    match rest.split_once('/') {
        Some((authority, path)) => Some((authority.to_string(), format!("/{path}"))),
        None => Some((rest.to_string(), "/".to_string())),
    }
}

/// Report a probe-side failure distinguishably from a governed refusal, and exit.
fn fail(reason: &str) -> ! {
    eprintln!("probe-error: {reason}");
    std::process::exit(2);
}
