//! The Shell's HTTP goes through the egress gateway and meets the SSRF floor in the kernel.

use std::io::Write as _;
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use box_shell::ShellKernel;

use super::{PermitAll, backend, run as on_shell_runtime};
use crate::run::broker::kernel::GatewayNetwork;
use crate::run::broker::shell::EgressRouting;

fn read_head(stream: &mut impl std::io::Read) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
        head.push(byte[0]);
    }
}

/// A self-signed certificate for `a.example` and its PEM.
fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["a.example".to_string()]).expect("a certificate")
}

/// A fake gateway that answers each connection with `response`, and reports each connection.
fn gateway(response: &'static str) -> (EgressRouting, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
    let address = listener.local_addr().expect("the gateway has an address");
    let (seen, connections) = mpsc::channel();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = seen.send(());
            read_head(&mut stream);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let routing = EgressRouting {
        proxy_target: format!("http://{address}"),
        ca_pem: Arc::new(certificate().cert.pem().into_bytes()),
    };
    (routing, connections)
}

fn run(egress: Option<EgressRouting>, command: &str) -> (i32, String, String) {
    let mut kernel = ShellKernel::over(backend(&[]), Arc::new(PermitAll));
    if let Some(egress) = egress {
        kernel = kernel.network(Arc::new(GatewayNetwork::new(
            egress,
            telemetry::Correlation::from_headers(None, None),
        )));
    }
    on_shell_runtime(async {
        let mut shell = kernel.shell();
        let output = shell.run(command).await;
        (output.status, output.stdout, output.stderr)
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
