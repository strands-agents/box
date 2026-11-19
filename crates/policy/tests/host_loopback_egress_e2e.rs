//! `host.box.internal` through the real gateway and the real policy engine.
//!
//! Each gateway carries the address map the box gives it: the reserved name to `127.0.0.1`, with no
//! DNS lookup. Each origin is a plain-HTTP listener on `127.0.0.1` that counts what it accepts, so
//! a refusal is proven by an origin that saw nothing.

#![cfg(feature = "egress-adapter")]

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egress_gateway::{CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, Principal};

const NAME: &str = "host.box.internal";

/// A plain-HTTP origin on `127.0.0.1` that counts the requests it reads and answers `200`.
struct Origin {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
    accepted: Arc<AtomicUsize>,
}

impl Origin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let (record, count) = (Arc::clone(&heads), Arc::clone(&accepted));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                count.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                record.lock().unwrap().push(head);
                let _ = reader.get_mut().write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        Self {
            port,
            heads,
            accepted,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

/// A gateway under `source`, with the box's address map.
fn gateway(source: &str) -> MitmHandle {
    let engine = support::open_policy(vec![Policy {
        origin: PathBuf::from("host-loopback.dw"),
        text: source.to_string(),
    }])
    .unwrap();
    MitmInterceptor::start(
        MitmConfig {
            dns_overrides: vec![(NAME.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        EgressPolicyInterceptor::into_handle(
            Arc::new(engine),
            Principal::agent(),
            GovernedBox::assigned("host-loopback"),
        ),
    )
    .unwrap()
}

/// Send `request` to the gateway and return the whole reply.
fn exchange(handle: &MitmHandle, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply).into_owned()
}

fn plain_get(handle: &MitmHandle, host: &str, port: u16) -> String {
    exchange(
        handle,
        &format!(
            "GET http://{host}:{port}/v1/models HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        ),
    )
}

fn connect(handle: &MitmHandle, host: &str, port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Permit `net:connect` and `http:request` to the reserved name on `port` alone.
fn permit_name_on(port: u16) -> String {
    format!(
        r#"
@id("local_llm_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{NAME}" && context.input.port == {port} }};

@id("local_llm_request")
permit (principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "{NAME}" && context.input.port == {port} }};
"#
    )
}

#[test]
fn host_box_internal_is_refused_without_a_permit_and_nothing_connects() {
    let origin = Origin::start();
    let handle = gateway(
        r#"permit (principal, action == Box::Action::"net:connect", resource)
           when { context.input.host == "api.example.test" };"#,
    );
    let plain = plain_get(&handle, NAME, origin.port);
    assert!(plain.starts_with("HTTP/1.1 403"), "{plain}");
    assert!(plain.contains("default-deny"), "{plain}");
    let tunnel = connect(&handle, NAME, origin.port);
    assert!(tunnel.starts_with("HTTP/1.1 403"), "{tunnel}");
    assert_eq!(origin.accepted(), 0, "no permit, so nothing connects");
}

#[test]
fn a_per_port_permit_reaches_its_port_and_no_other() {
    let permitted = Origin::start();
    let other = Origin::start();
    let handle = gateway(&permit_name_on(permitted.port));

    let reply = plain_get(&handle, NAME, permitted.port);
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_eq!(permitted.accepted(), 1);
    let head = &permitted.heads()[0];
    assert!(
        head.contains(&format!("Host: {NAME}:{}", permitted.port)),
        "the origin receives the name it was asked by: {head}"
    );

    let refused = plain_get(&handle, NAME, other.port);
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert_eq!(other.accepted(), 0, "another port stays refused");
}

/// The issue expected a loopback `ip4` forbid to leave the name open. It does not: the address
/// decision sees `ip4 = "127.0.0.1"`, so the forbid holds, and an exception for the name opens it.
#[test]
fn a_loopback_address_forbid_still_refuses_host_box_internal() {
    let origin = Origin::start();
    let forbid = r#"
@id("no_loopback")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input has ip4 && context.input.ip4 like "127.*" };
"#;
    let handle = gateway(&format!("{}{forbid}", permit_name_on(origin.port)));
    let reply = plain_get(&handle, NAME, origin.port);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("no_loopback"), "{reply}");
    assert_eq!(origin.accepted(), 0);

    let excepted = r#"
@id("no_loopback")
forbid (principal, action == Box::Action::"net:connect", resource)
when {
  context.input has ip4 && context.input.ip4 like "127.*" &&
  context.input.host != "host.box.internal"
};
"#;
    let handle = gateway(&format!("{}{excepted}", permit_name_on(origin.port)));
    let reply = plain_get(&handle, NAME, origin.port);
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_eq!(origin.accepted(), 1);
}

#[test]
fn a_permit_on_the_name_does_not_admit_literal_loopback() {
    let origin = Origin::start();
    let handle = gateway(&permit_name_on(origin.port));
    for host in ["127.0.0.1", "localhost"] {
        let plain = plain_get(&handle, host, origin.port);
        assert!(plain.starts_with("HTTP/1.1 403"), "{host}: {plain}");
        let tunnel = connect(&handle, host, origin.port);
        assert!(tunnel.starts_with("HTTP/1.1 403"), "{host}: {tunnel}");
    }
    assert_eq!(origin.accepted(), 0);
}
