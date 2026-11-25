use std::cell::Cell;
use std::time::Duration;

use hyper::header::HeaderMap as WireHeaders;
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::error::{ProxyError, Result};

const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) enum Handshake {
    None,
    WebSocket(Upgrade),
    Malformed(&'static str),
}

/// The `Sec-WebSocket-Key` of a handshake that `classify` accepted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Key(String);

/// A valid handshake: its key, and the workload connection that a `101` switches.
pub(crate) struct Upgrade {
    key: Key,
    workload: OnUpgrade,
}

impl Upgrade {
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// The relay between the workload and `upstream`, the upstream connection that switched.
    pub(crate) fn relay(self, upstream: Upgraded) -> Relay {
        Relay {
            workload: self.workload,
            upstream,
        }
    }
}

/// Both connections of a WebSocket whose `101` passed `check_reply`.
pub(crate) struct Relay {
    workload: OnUpgrade,
    upstream: Upgraded,
}

impl Relay {
    /// Copy bytes in both directions until both sides close or `limit` passes with no traffic.
    pub(crate) async fn serve(self, limit: Duration) -> Result<()> {
        let workload = self
            .workload
            .await
            .map_err(|e| ProxyError::Io(format!("WebSocket upgrade: {e}")))?;
        run(TokioIo::new(workload), TokioIo::new(self.upstream), limit).await;
        Ok(())
    }
}

pub(crate) fn classify<B: hyper::body::Body>(request: &mut hyper::Request<B>) -> Handshake {
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
    } else if one(headers, "sec-websocket-key").is_none() {
        "websocket: handshake lacks one Sec-WebSocket-Key"
    } else if !request.body().is_end_stream() {
        "websocket: handshake carries a body"
    } else {
        let key = Key(one(headers, "sec-websocket-key")
            .unwrap_or_default()
            .to_string());
        let workload = hyper::upgrade::on(request);
        return Handshake::WebSocket(Upgrade { key, workload });
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

/// Refuse a `101` reply unless it switches to WebSocket and answers `key`, the handshake's key.
pub(crate) fn check_reply(key: Option<&Key>, status: u16, reply: &WireHeaders) -> Result<()> {
    if status != 101 {
        return Ok(());
    }
    let refuse = |reason: &str| Err(ProxyError::Intercept(reason.to_string()));
    let Some(Key(key)) = key else {
        return refuse("HTTP protocol upgrades are not supported");
    };
    if !one(reply, "upgrade").is_some_and(|protocol| protocol.eq_ignore_ascii_case("websocket")) {
        return refuse("a 101 reply to a WebSocket handshake did not switch to WebSocket");
    }
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{ACCEPT_GUID}").as_bytes(),
    );
    // A field that `Connection` names is stripped before the reply reaches the workload.
    let stripped = tokens(reply, "connection")
        .any(|option| option.eq_ignore_ascii_case("sec-websocket-accept"));
    if stripped || one(reply, "sec-websocket-accept") != Some(base64(digest.as_ref()).as_str()) {
        return refuse("a 101 reply to a WebSocket handshake has the wrong Sec-WebSocket-Accept");
    }
    Ok(())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let group = (chunk.iter().enumerate()).fold(0u32, |group, (at, byte)| {
            group | u32::from(*byte) << (16 - 8 * at)
        });
        for at in 0..4 {
            let sextet = (group >> (18 - 6 * at)) as usize & 63;
            out.push(if at <= chunk.len() {
                char::from(ALPHABET[sextet])
            } else {
                '='
            });
        }
    }
    out
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
        classify(&mut request.body(Empty::<Bytes>::new()).unwrap())
    }

    #[test]
    fn a_valid_handshake_is_classified_with_its_key() {
        let key = Key(KEY.to_string());
        assert!(
            matches!(handshake(|request| request), Handshake::WebSocket(upgrade) if *upgrade.key() == key)
        );
        let mut plain = hyper::Request::get("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(matches!(classify(&mut plain), Handshake::None));
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
        assert!(malformed(handshake(|mut request| {
            request.headers_mut().unwrap().remove("Sec-WebSocket-Key");
            request
        })));
        let mut with_body = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap();
        assert!(malformed(classify(&mut with_body)));
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        for (bytes, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (&[0xfb, 0xff], "+/8="),
        ] {
            assert_eq!(base64(bytes), encoded);
        }
    }

    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn reply(pairs: &[(&'static str, &'static str)]) -> WireHeaders {
        let mut headers = WireHeaders::new();
        for (name, value) in pairs {
            headers.append(*name, hyper::header::HeaderValue::from_static(value));
        }
        headers
    }

    fn refusal(key: Option<&str>, status: u16, pairs: &[(&'static str, &'static str)]) -> String {
        let key = key.map(|key| Key(key.to_string()));
        match check_reply(key.as_ref(), status, &reply(pairs)) {
            Ok(()) => String::new(),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn only_the_accept_for_the_key_is_accepted() {
        let upgrade = ("Upgrade", "websocket");
        let wrong = "has the wrong Sec-WebSocket-Accept";
        let with = |accepts: &[&'static str]| {
            let mut pairs = vec![upgrade];
            pairs.extend(
                accepts
                    .iter()
                    .map(|accept| ("Sec-WebSocket-Accept", *accept)),
            );
            pairs
        };
        assert_eq!(refusal(Some(KEY), 101, &with(&[ACCEPT])), "");
        assert!(refusal(Some(KEY), 101, &with(&[])).contains(wrong));
        assert!(refusal(Some(KEY), 101, &with(&["s3pPLMBiTxaQ9kYGzzhZRbK+xOo=x"])).contains(wrong));
        assert!(refusal(Some("other"), 101, &with(&[ACCEPT])).contains(wrong));
        assert!(refusal(Some(KEY), 101, &with(&[ACCEPT, ACCEPT])).contains(wrong));
        let mut nominated = with(&[ACCEPT]);
        nominated.push(("Connection", "Upgrade, Sec-WebSocket-Accept"));
        assert!(refusal(Some(KEY), 101, &nominated).contains(wrong));
    }

    #[test]
    fn a_101_must_switch_to_websocket_exactly_once() {
        let accept = ("Sec-WebSocket-Accept", ACCEPT);
        let switch = "did not switch to WebSocket";
        assert!(refusal(Some(KEY), 101, &[accept]).contains(switch));
        assert!(refusal(Some(KEY), 101, &[("Upgrade", "h2c"), accept]).contains(switch));
        let twice = [("Upgrade", "websocket"), ("Upgrade", "websocket"), accept];
        assert!(refusal(Some(KEY), 101, &twice).contains(switch));
        assert_eq!(
            refusal(Some(KEY), 101, &[("Upgrade", "WebSocket"), accept]),
            ""
        );
    }

    #[test]
    fn a_101_without_a_handshake_is_refused_and_other_statuses_pass() {
        let switched = [("Upgrade", "websocket"), ("Sec-WebSocket-Accept", ACCEPT)];
        assert!(refusal(None, 101, &switched).contains("HTTP protocol upgrades are not supported"));
        assert_eq!(refusal(None, 200, &[]), "");
        assert_eq!(refusal(Some(KEY), 403, &[]), "");
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
