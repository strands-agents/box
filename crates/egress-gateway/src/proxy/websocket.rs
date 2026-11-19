use std::borrow::Cow;
use std::cell::Cell;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use credentials::ResponseRedactor;
use hyper::header::HeaderMap as WireHeaders;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::audit::{Decision as AuditDecision, RequestId};
use crate::boundary::{HeaderMap, Target};
use crate::intercept::mitm::SharedState;
use crate::intercept::mitm::connect::ConnectRequest;
use crate::intercept::mitm::l7;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    None,
    WebSocket { accept: String },
    Malformed(&'static str),
}

pub(crate) fn classify<B: hyper::body::Body>(request: &hyper::Request<B>) -> Handshake {
    let headers = request.headers();
    if !tokens(headers, "upgrade").any(|token| token.eq_ignore_ascii_case("websocket")) {
        return Handshake::None;
    }
    let key = one(headers, "sec-websocket-key")
        .filter(|key| STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 16));
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
    } else if let Some(key) = key {
        return Handshake::WebSocket {
            accept: accept(key),
        };
    } else {
        "websocket: handshake key is not 16 bytes of base64"
    })
}

fn accept(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finish())
}

pub(crate) fn check_101(headers: &WireHeaders, accept: &str) -> Result<(), &'static str> {
    if !one(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        Err("websocket: 101 does not name Upgrade: websocket")
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        Err("websocket: 101 lacks Connection: upgrade")
    } else if one(headers, "sec-websocket-accept") != Some(accept) {
        Err("websocket: 101 carries a wrong Sec-WebSocket-Accept")
    } else if headers.contains_key("sec-websocket-extensions") {
        Err("websocket: 101 negotiates an extension")
    } else {
        Ok(())
    }
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

#[derive(Debug, PartialEq, Eq)]
struct Header {
    fin: bool,
    opcode: u8,
    payload_len: usize,
    header_len: usize,
}

fn header(buffer: &[u8]) -> Result<Option<Header>, &'static str> {
    let [first, second, ..] = *buffer else {
        return Ok(None);
    };
    if first & 0x70 != 0 {
        return Err("frame sets a reserved bit");
    }
    if second & 0x80 != 0 {
        return Err("server frame is masked");
    }
    let (opcode, fin) = (first & 0x0f, first & 0x80 != 0);
    let (len, header_len) = match second & 0x7f {
        126 if buffer.len() >= 4 => (u64::from(u16::from_be_bytes([buffer[2], buffer[3]])), 4),
        127 if buffer.len() >= 10 => {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&buffer[2..10]);
            if bytes[0] & 0x80 != 0 {
                return Err("frame length sets the most significant bit");
            }
            (u64::from_be_bytes(bytes), 10)
        }
        126 | 127 => return Ok(None),
        len => (u64::from(len), 2),
    };
    match opcode {
        CONTINUATION | TEXT | BINARY => {}
        CLOSE | PING | PONG if fin && len <= 125 => {}
        CLOSE | PING | PONG => return Err("control frame is fragmented or too long"),
        _ => return Err("frame has an unknown opcode"),
    }
    let payload_len = usize::try_from(len).map_err(|_| "frame is too long")?;
    Ok(Some(Header {
        fin,
        opcode,
        payload_len,
        header_len,
    }))
}

fn encode_head(fin: bool, opcode: u8, len: usize) -> Vec<u8> {
    let mut head = Vec::with_capacity(10);
    head.push(u8::from(fin) << 7 | opcode);
    match len {
        len @ 0..=125 => head.push(len as u8),
        len @ 126..=0xffff => {
            head.push(126);
            head.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            head.push(127);
            head.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    head
}

pub(crate) struct Relay {
    pub(crate) upstream: Upgraded,
    pub(crate) path: String,
    pub(crate) scrub: Option<Target>,
    pub(crate) correlation: RequestId,
}

type Ended = Result<(), Option<String>>;

pub(crate) async fn run(
    workload: Upgraded,
    relay: Relay,
    state: &SharedState,
    connect: &ConnectRequest,
) {
    let (mut from_workload, mut to_workload) = tokio::io::split(TokioIo::new(workload));
    let (mut from_server, mut to_server) = tokio::io::split(TokioIo::new(relay.upstream));
    let active = Cell::new(Instant::now());
    let ended = {
        let up = copy(&active, &mut from_workload, &mut to_server);
        let down = async {
            match &relay.scrub {
                None => copy(&active, &mut from_server, &mut to_workload).await,
                Some(target) => {
                    scrubbed(state, target, &active, &mut from_server, &mut to_workload).await
                }
            }
        };
        tokio::select! {
            ended = async { tokio::try_join!(up, down).map(drop) } => ended,
            () = idle(&active, state.config.upstream_read_deadline) => Ok(()),
        }
    };
    if let Err(Some(reason)) = ended {
        let request = ("GET", relay.path.as_str());
        l7::emit_decision(
            state,
            connect,
            request,
            AuditDecision::Deny,
            &reason,
            relay.correlation,
        );
    }
    let closing = async { tokio::join!(to_workload.shutdown(), to_server.shutdown()) };
    let _ = tokio::time::timeout(state.config.upstream_read_deadline, closing).await;
}

async fn copy<R, W>(active: &Cell<Instant>, from: &mut R, to: &mut W) -> Ended
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let read = from.read(&mut buffer).await.map_err(|_| None)?;
        if read == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        active.set(Instant::now());
        to.write_all(&buffer[..read]).await.map_err(|_| None)?;
        to.flush().await.map_err(|_| None)?;
    }
}

async fn scrubbed<R, W>(
    state: &SharedState,
    target: &Target,
    active: &Cell<Instant>,
    from: &mut R,
    to: &mut W,
) -> Ended
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let limit = state.config.response_limits.max_body_bytes;
    let refused = |why: &str| Some(format!("websocket: {why}"));
    let mut buffer = Vec::new();
    let mut message = None;
    loop {
        let (mut at, mut out) = (0, Vec::new());
        while let Some(frame) = header(&buffer[at..]).map_err(refused)? {
            if frame.payload_len > limit {
                return Err(refused("server frame exceeds the size limit"));
            }
            let end = at + frame.header_len + frame.payload_len;
            if buffer.len() < end {
                break;
            }
            let payload = &buffer[at + frame.header_len..end];
            let control = frame.opcode >= CLOSE;
            let held = if control { None } else { message.take() };
            let chain = match held {
                Some(chain) => chain,
                None => redactors(state, target).map_err(|why| refused(&why))?,
            };
            let (scrubbed, open) = redact(chain, payload, frame.fin);
            let scrubbed = if control && scrubbed != payload {
                let kept = if frame.opcode == CLOSE { 2 } else { 0 };
                payload.iter().copied().take(kept).collect()
            } else {
                scrubbed
            };
            if !control {
                message = open;
            }
            out.extend(encode_head(frame.fin, frame.opcode, scrubbed.len()));
            out.extend(scrubbed);
            at = end;
        }
        buffer.drain(..at);
        if !out.is_empty() {
            to.write_all(&out).await.map_err(|_| None)?;
            to.flush().await.map_err(|_| None)?;
        }
        buffer.reserve(16 * 1024);
        if from.read_buf(&mut buffer).await.map_err(|_| None)? == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        active.set(Instant::now());
    }
}

fn redactors(state: &SharedState, target: &Target) -> Result<Vec<ResponseRedactor>, String> {
    let controls = state
        .controls
        .response_controls(&mut HeaderMap::new(), target)?;
    Ok(controls.redactors)
}

fn redact(
    chain: Vec<ResponseRedactor>,
    payload: &[u8],
    fin: bool,
) -> (Vec<u8>, Option<Vec<ResponseRedactor>>) {
    let mut data = Cow::Borrowed(payload);
    let mut open = Vec::new();
    for mut redactor in chain {
        let mut next = redactor.push(&data);
        if fin {
            next.extend(redactor.finish());
        } else {
            open.push(redactor);
        }
        data = Cow::Owned(next);
    }
    (data.into_owned(), (!fin).then_some(open))
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

    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

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
    fn a_valid_handshake_is_classified_with_its_accept_value() {
        assert_eq!(
            handshake(|request| request),
            Handshake::WebSocket {
                accept: ACCEPT.to_string()
            }
        );
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
        assert!(malformed(handshake(
            |request| request.header("Sec-WebSocket-Key", "c2hvcnQ=")
        )));
        let without_connection = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(malformed(classify(&without_connection)));
        let with_body = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap();
        assert!(malformed(classify(&with_body)));
    }

    #[test]
    fn a_101_must_answer_the_handshake_and_negotiate_no_extension() {
        let answer = |extra: &[(&'static str, &'static str)]| {
            let mut headers = WireHeaders::new();
            for (name, value) in [("upgrade", "websocket"), ("connection", "Upgrade")]
                .iter()
                .chain(extra)
            {
                headers.append(*name, value.parse().unwrap());
            }
            check_101(&headers, ACCEPT)
        };
        assert_eq!(answer(&[("sec-websocket-accept", ACCEPT)]), Ok(()));
        assert!(answer(&[("sec-websocket-accept", KEY)]).is_err());
        assert!(answer(&[]).is_err());
        let deflate = [
            ("sec-websocket-accept", ACCEPT),
            ("sec-websocket-extensions", "permessage-deflate"),
        ];
        assert!(answer(&deflate).is_err());
    }

    #[test]
    fn a_frame_head_round_trips_and_each_header_rule_is_checked() {
        for (fin, opcode, len) in [
            (true, TEXT, 5),
            (false, BINARY, 300),
            (true, CONTINUATION, 70_000),
        ] {
            let head = encode_head(fin, opcode, len);
            assert_eq!(
                header(&head),
                Ok(Some(Header {
                    fin,
                    opcode,
                    payload_len: len,
                    header_len: head.len(),
                }))
            );
            assert_eq!(header(&head[..head.len() - 1]), Ok(None));
        }
        assert!(header(&[0xC1, 0]).is_err(), "a reserved bit");
        assert!(header(&[0x81, 0x80]).is_err(), "a masked server frame");
        assert!(header(&[0x83, 0]).is_err(), "an unknown opcode");
        assert!(header(&[0x09, 0]).is_err(), "a fragmented Ping");
        assert!(
            header(&[0x89, 126, 0, 126]).is_err(),
            "a Ping over 125 bytes"
        );
    }
}
