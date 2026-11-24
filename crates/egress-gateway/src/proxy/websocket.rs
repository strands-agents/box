use std::cell::Cell;
use std::time::Duration;

use hyper::header::HeaderMap as WireHeaders;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    None,
    WebSocket,
    Malformed(&'static str),
}

pub(crate) fn classify<B: hyper::body::Body>(request: &hyper::Request<B>) -> Handshake {
    let headers = request.headers();
    if !tokens(headers, "upgrade").any(|token| token.eq_ignore_ascii_case("websocket")) {
        return Handshake::None;
    }
    Handshake::Malformed(if request.method() != hyper::Method::GET {
        "websocket: handshake method is not GET"
    } else if request.version() != hyper::Version::HTTP_11 {
        "websocket: handshake is not HTTP/1.1"
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        "websocket: handshake lacks Connection: upgrade"
    } else if one(headers, "sec-websocket-version") != Some("13") {
        "websocket: handshake version is not 13"
    } else if !request.body().is_end_stream() {
        "websocket: handshake carries a body"
    } else {
        return Handshake::WebSocket;
    })
}

fn tokens<'a>(headers: &'a WireHeaders, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(name)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .map(str::trim)
}

fn one<'a>(headers: &'a WireHeaders, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().map(str::trim),
        _ => None,
    }
}

pub(crate) async fn run<W, U>(workload: W, upstream: U, limit: Duration)
where
    W: AsyncRead + AsyncWrite,
    U: AsyncRead + AsyncWrite,
{
    let (mut from_workload, mut to_workload) = tokio::io::split(workload);
    let (mut from_server, mut to_server) = tokio::io::split(upstream);
    let active = Cell::new(Instant::now());
    let up = copy(&active, &mut from_workload, &mut to_server);
    let down = copy(&active, &mut from_server, &mut to_workload);
    tokio::select! {
        _ = async { tokio::try_join!(up, down) } => {}
        () = idle(&active, limit) => {}
    }
}

async fn copy<R, W>(active: &Cell<Instant>, from: &mut R, to: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        active.set(Instant::now());
        to.write_all(&buffer[..read]).await?;
        to.flush().await?;
    }
}

async fn idle(active: &Cell<Instant>, limit: Duration) {
    while Instant::now() < active.get() + limit {
        tokio::time::sleep_until(active.get() + limit).await;
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{Empty, Full};
    use hyper::body::Bytes;
    use tokio::io::DuplexStream;

    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn handshake(
        edit: impl FnOnce(hyper::http::request::Builder) -> hyper::http::request::Builder,
    ) -> Handshake {
        let request = edit(
            hyper::Request::get("/chat")
                .header("Upgrade", "websocket")
                .header("Connection", "keep-alive, Upgrade")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", KEY),
        );
        classify(&request.body(Empty::<Bytes>::new()).unwrap())
    }

    #[test]
    fn a_valid_handshake_is_classified() {
        assert_eq!(handshake(|request| request), Handshake::WebSocket);
        let plain = hyper::Request::get("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(classify(&plain), Handshake::None);
    }

    #[test]
    fn each_broken_handshake_rule_is_malformed() {
        let malformed = |handshake| matches!(handshake, Handshake::Malformed(_));
        assert!(malformed(handshake(|request| request.method("POST"))));
        assert!(malformed(handshake(
            |request| request.version(hyper::Version::HTTP_10)
        )));
        assert!(malformed(handshake(
            |request| request.header("Sec-WebSocket-Version", "8")
        )));
        assert!(malformed(handshake(|mut request| {
            request.headers_mut().unwrap().remove("Connection");
            request
        })));
        let with_body = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap();
        assert!(malformed(classify(&with_body)));
    }

    async fn relayed(limit: Duration, script: impl Future<Output = ()>, ends: [DuplexStream; 2]) {
        let [workload, upstream] = ends;
        let both = async { tokio::join!(run(workload, upstream, limit), script) };
        tokio::time::timeout(Duration::from_secs(5), both)
            .await
            .expect("the relay and the script end");
    }

    #[tokio::test]
    async fn a_close_from_either_side_reaches_the_other_side() {
        for agent_closes_first in [true, false] {
            let (workload, mut agent) = tokio::io::duplex(64);
            let (upstream, mut server) = tokio::io::duplex(64);
            let script = async {
                let (first, second) = if agent_closes_first {
                    (&mut agent, &mut server)
                } else {
                    (&mut server, &mut agent)
                };
                first.write_all(b"bye").await.unwrap();
                first.shutdown().await.unwrap();
                let mut seen = Vec::new();
                second.read_to_end(&mut seen).await.unwrap();
                assert_eq!(seen, b"bye");
                second.shutdown().await.unwrap();
                let mut rest = Vec::new();
                first.read_to_end(&mut rest).await.unwrap();
                assert!(rest.is_empty());
            };
            relayed(Duration::from_secs(60), script, [workload, upstream]).await;
        }
    }

    #[tokio::test]
    async fn traffic_keeps_a_websocket_open_past_the_idle_limit() {
        let (workload, mut agent) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        let script = async {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                agent.write_all(b"x").await.unwrap();
                let mut byte = [0; 1];
                server.read_exact(&mut byte).await.unwrap();
            }
            agent.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        };
        relayed(Duration::from_millis(300), script, [workload, upstream]).await;
    }
}
