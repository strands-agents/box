//! Private wire protocol between the Shell alias and the broker.
//!
//! On the wire a frame is `{version, program, frame_type, body}` — `frame_type` in the header, and
//! `body` carrying only that frame's payload (absent when it has none). `c→d` is alias→daemon,
//! `d→c` is daemon→alias; `data` payloads are base64.
//!
//! | `frame_type` | dir | body | per call | what it is |
//! |---|---|---|---|---|
//! | `open` | c→d | `mode` ([`Interpreter`]) | 1 | start a program; no path/cwd/env |
//! | `call` | c→d | `source` | 1 | one command or script, as text |
//! | `input` | c→d | `data` (b64) | 0+ | bytes for stdin |
//! | `input_eof` | c→d | — | 0–1 | no more stdin (≠ empty input, ≠ `close`) |
//! | `signal` | c→d | `kind` ([`SignalKind`]) | 0+ | end the call, keep the program |
//! | `close` | c→d | — | 0–1 | discard the program and its state |
//! | `output` | d→c | `stream` ([`Stream`]), `data` (b64) | 0+ | one output chunk, streamed |
//! | `exit` | d→c | `status` | 1, terminal | the call RAN; the program's own status |
//! | `denied` | d→c | `kind` ([`DeniedKind`]), `reason` | 1, terminal | boundary REFUSED (transport only) |
//!
//! Discriminants (`frame_type`, `mode`, `stream`, `kind`) are closed `deny_unknown_fields` enums;
//! `reason`/`source`/`data`/`server` are free strings.

#![allow(dead_code)]

use std::io;

use serde::de::{DeserializeOwned, Error};
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame either end will read or write.
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The most captured output the daemon's Shell returns per stream.
pub(crate) const MAX_CAPTURE_STREAM_BYTES: usize = MAX_FRAME_BYTES / 16;

/// The status reported when the boundary itself failed, as distinct from a policy refusal (126)
/// and from any status a program could produce.
pub(crate) const BOUNDARY_FAILURE_STATUS: i32 = 125;

/// The one protocol version either end speaks.
pub(crate) const PROTOCOL_VERSION: u8 = 6;

/// Every name the box materializes its Shell alias under.
pub(crate) const BROKER_SOCKET: &str = "box.sock";

/// The socket's path relative to a box root, which is how an alias derives it from its own path.
///
/// Here rather than in `layout`, because the standalone `strands-box-sock-alias` binary
/// `#[path]`-includes this module and cannot reach the crate's module tree. `layout` imports it, the
/// same way it imports the alias names below. Two spellings of this name meant an alias dialling a
/// socket the box never bound, with no compile error.
pub(crate) const BROKER_SOCKET_RELATIVE: [&str; 2] = ["run", BROKER_SOCKET];

pub(crate) const SHELL_ALIAS_NAMES: [&str; 3] = ["zsh", "bash", "sh"];

/// The Python names a harness resolves, each an alias of the same broker image.
pub(crate) const PYTHON_ALIAS_NAMES: [&str; 2] = ["python3", "python"];

/// Names one Program within one connection.
pub(crate) type ProgramId = u32;

/// The most `Output` payload one frame carries, before base64 expansion.
pub(crate) const MAX_CHUNK_BYTES: usize = 48 * 1024;

/// The most output one Call may produce across every `Output` frame.
pub(crate) const MAX_CALL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// How many Programs one connection may hold open at once.
pub(crate) const MAX_PROGRAMS_PER_CONNECTION: usize = 8;

/// Which of a Program's output streams a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// What a `Signal` frame asks of a running Call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum SignalKind {
    /// End the Call at its next execution-limit check, leaving the Program open.
    Interrupt,
}

/// Which interpreter a Program runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Interpreter {
    /// The Strands Shell — what every `zsh`/`bash` alias reaches.
    Shell,
    /// Python — what every `python3`/`python` alias reaches.
    Python,
    /// One MCP server, named by the alias the agent executed.
    Mcp {
        /// The server name, from the alias's own filename.
        server: String,
    },
}

/// Why the transport refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum DeniedKind {
    /// The client's protocol version is not the one this box speaks.
    VersionMismatch,
    /// The frame was malformed, or a client sent a daemon-only body.
    TransportError,
    /// A size or output budget was exceeded — the per-Call output cap, or the per-connection
    /// program cap.
    OverBudget,
    /// Back-pressure: a second Call on a busy Program, or stdin not read fast enough.
    FlowControl,
    /// A Call outlived its deadline.
    Timeout,
    /// A refusal with no more specific code.
    Internal,
}

/// One transport frame: the header fields plus the typed body.
#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) version: u8,
    pub(crate) program: ProgramId,
    pub(crate) body: Body,
}

/// The payload for one `frame_type`. The tag itself lives in the [`Frame`] header, not here.
#[derive(Debug)]
pub(crate) enum Body {
    // ---- client → daemon ----
    /// Open a Program. Carries no path, cwd, or environment: the daemon fixes all three, so
    /// there is nothing here for a workload to point somewhere else.
    Open { mode: Interpreter },
    /// Submit one Call to an open Program: a shell command or a script, as program text.
    Call {
        source: String,
        correlation: Box<telemetry::Correlation>,
    },
    /// Feed bytes to the Program's standard input.
    Input { data: String },
    /// No more input is coming.
    InputEof,
    /// End the running Call, keeping the Program.
    Signal { kind: SignalKind },
    /// Discard the Program and its state.
    Close,

    // ---- daemon → client ----
    /// A chunk of output, as produced.
    Output { stream: Stream, data: String },
    /// The Call finished with this status.
    Exit { status: i32 },
    /// The request was refused, with a fixed reason-code and a reason for the operator.
    Denied { kind: DeniedKind, reason: String },
}

impl Body {
    /// Whether only the daemon may send this body.
    pub(crate) fn is_daemon_only(&self) -> bool {
        matches!(
            self,
            Body::Output { .. } | Body::Exit { .. } | Body::Denied { .. }
        )
    }

    /// The header tag for this body, and its payload (absent for a bodyless kind).
    fn split(&self) -> (&'static str, Option<Value>) {
        match self {
            Body::Open { mode } => ("open", Some(json!({ "mode": mode }))),
            Body::Call {
                source,
                correlation,
            } => (
                "call",
                Some(json!({ "source": source, "correlation": correlation })),
            ),
            Body::Input { data } => ("input", Some(json!({ "data": data }))),
            Body::InputEof => ("input_eof", None),
            Body::Signal { kind } => ("signal", Some(json!({ "kind": kind }))),
            Body::Close => ("close", None),
            Body::Output { stream, data } => {
                ("output", Some(json!({ "stream": stream, "data": data })))
            }
            Body::Exit { status } => ("exit", Some(json!({ "status": status }))),
            Body::Denied { kind, reason } => {
                ("denied", Some(json!({ "kind": kind, "reason": reason })))
            }
        }
    }
}

impl Serialize for Frame {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (frame_type, body) = self.body.split();
        let mut map = serializer.serialize_map(Some(3 + usize::from(body.is_some())))?;
        map.serialize_entry("version", &self.version)?;
        map.serialize_entry("program", &self.program)?;
        map.serialize_entry("frame_type", frame_type)?;
        if let Some(body) = &body {
            map.serialize_entry("body", body)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The header, with `frame_type` beside `version`/`program`. `deny_unknown_fields` here
        // refuses an unexpected top-level key; each payload struct below refuses an unexpected body
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum FrameType {
            Open,
            Call,
            Input,
            InputEof,
            Signal,
            Close,
            Output,
            Exit,
            Denied,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            version: u8,
            program: ProgramId,
            frame_type: FrameType,
            #[serde(default)]
            body: Option<Value>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OpenBody {
            mode: Interpreter,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CallBody {
            source: String,
            #[serde(default)]
            correlation: Box<telemetry::Correlation>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InputBody {
            data: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SignalBody {
            kind: SignalKind,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OutputBody {
            stream: Stream,
            data: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ExitBody {
            status: i32,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DeniedBody {
            kind: DeniedKind,
            reason: String,
        }

        // A frame carrying a payload requires `body`; one without a payload must omit it.
        fn take<T: DeserializeOwned, E: Error>(body: Option<Value>) -> Result<T, E> {
            let value = body.ok_or_else(|| E::custom("this frame_type requires a body"))?;
            serde_json::from_value(value).map_err(E::custom)
        }
        fn none<E: Error>(body: Option<Value>) -> Result<(), E> {
            match body {
                None => Ok(()),
                Some(_) => Err(E::custom("this frame_type carries no body")),
            }
        }

        let header = Header::deserialize(deserializer)?;
        let body = match header.frame_type {
            FrameType::Open => {
                let OpenBody { mode } = take(header.body)?;
                Body::Open { mode }
            }
            FrameType::Call => {
                let CallBody {
                    source,
                    correlation,
                } = take(header.body)?;
                Body::Call {
                    source,
                    correlation,
                }
            }
            FrameType::Input => {
                let InputBody { data } = take(header.body)?;
                Body::Input { data }
            }
            FrameType::InputEof => {
                none(header.body)?;
                Body::InputEof
            }
            FrameType::Signal => {
                let SignalBody { kind } = take(header.body)?;
                Body::Signal { kind }
            }
            FrameType::Close => {
                none(header.body)?;
                Body::Close
            }
            FrameType::Output => {
                let OutputBody { stream, data } = take(header.body)?;
                Body::Output { stream, data }
            }
            FrameType::Exit => {
                let ExitBody { status } = take(header.body)?;
                Body::Exit { status }
            }
            FrameType::Denied => {
                let DeniedBody { kind, reason } = take(header.body)?;
                Body::Denied { kind, reason }
            }
        };

        Ok(Frame {
            version: header.version,
            program: header.program,
            body,
        })
    }
}

/// Encode bytes for an `Input`/`Output` body.
pub(crate) fn encode_payload(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode an `Input`/`Output` payload, refusing anything that is not valid base64.
pub(crate) fn decode_payload(text: &str) -> io::Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Read one length-prefixed frame, or `None` at a clean end of stream.
pub(crate) async fn read_frame<T, R>(reader: &mut R) -> io::Result<Option<T>>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    // Distinguish "nothing at all" from "a truncated prefix": the first is a peer that
    // finished, the second is a protocol error.
    let first = reader.read(&mut length[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Shell frame is {length} bytes; maximum is {MAX_FRAME_BYTES}"),
        ));
    }

    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Write one length-prefixed frame.
pub(crate) async fn write_frame<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Shell frame is {} bytes; maximum is {MAX_FRAME_BYTES}",
                payload.len()
            ),
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_one_frame_then_reports_end_of_stream() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        write_frame(
            &mut writer,
            &Frame {
                version: PROTOCOL_VERSION,
                program: 1,
                body: Body::Call {
                    correlation: Default::default(),
                    source: "printf routed".to_string(),
                },
            },
        )
        .await
        .unwrap();
        drop(writer);

        let decoded: Frame = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert!(matches!(
            decoded.body,
            Body::Call { ref source, .. } if source == "printf routed"
        ));
        assert!(
            read_frame::<Frame, _>(&mut reader).await.unwrap().is_none(),
            "a closed peer is end-of-stream, not an error"
        );
    }

    /// An oversized length is refused before the body is allocated, so a workload cannot
    /// make the broker reserve memory on its behalf.
    #[tokio::test]
    async fn rejects_an_oversized_frame_without_allocating_it() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            let _ = writer
                .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
                .await;
        });

        let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("maximum is"), "{error}");
    }

    /// An unknown field is a parse error, not a silently ignored hint — so a workload
    /// cannot smuggle a field a later protocol version might honor.
    #[tokio::test]
    async fn rejects_unknown_request_fields() {
        let payload =
            br#"{"version":1,"command":"printf routed","untrusted_scope":"another-workload"}"#;
        let mut frame = Vec::from((payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        let mut reader = frame.as_slice();

        let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A partial length prefix is a protocol error, distinct from a clean close.
    #[tokio::test]
    async fn rejects_a_truncated_length_prefix() {
        let mut reader = [0_u8, 0].as_slice();

        let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A fully-escaped `Denied` reason must still fit one frame.
    #[test]
    fn a_worst_case_refusal_reason_fits_one_frame() {
        let frame = Frame {
            version: PROTOCOL_VERSION,
            program: 1,
            body: Body::Denied {
                kind: DeniedKind::Internal,
                reason: "\0".repeat(MAX_CAPTURE_STREAM_BYTES),
            },
        };

        let payload = serde_json::to_vec(&frame).unwrap();
        assert!(
            payload.len() <= MAX_FRAME_BYTES,
            "a fully-escaped reason must still fit one frame: {} bytes",
            payload.len()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transport (version 4) — the same adversarial properties, extended to every body

    fn frame(body: Body) -> Frame {
        Frame {
            version: PROTOCOL_VERSION,
            program: 1,
            body,
        }
    }

    #[tokio::test]
    async fn a_transport_frame_round_trips() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        write_frame(
            &mut writer,
            &frame(Body::Call {
                correlation: Default::default(),
                source: "printf routed".to_string(),
            }),
        )
        .await
        .unwrap();
        drop(writer);

        let decoded: Frame = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.program, 1);
        match decoded.body {
            Body::Call { source, .. } => assert_eq!(source, "printf routed"),
            other => panic!("expected a call body, got {other:?}"),
        }
    }

    /// Several frames on ONE connection — the property version 1 refused outright.
    #[tokio::test]
    async fn many_frames_ride_one_connection() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        for body in [
            Body::Open {
                mode: Interpreter::Shell,
            },
            Body::Call {
                correlation: Default::default(),
                source: "true".to_string(),
            },
            Body::Close,
        ] {
            write_frame(&mut writer, &frame(body)).await.unwrap();
        }
        drop(writer);

        let mut seen = 0;
        while let Some(_decoded) = read_frame::<Frame, _>(&mut reader).await.unwrap() {
            seen += 1;
        }
        assert_eq!(seen, 3, "every frame on the connection must be readable");
    }

    /// An unknown field is refused on the header AND inside a body variant.
    #[tokio::test]
    async fn unknown_fields_are_refused_on_the_envelope_and_in_a_body() {
        for payload in [
            // An unknown key in the header.
            br#"{"version":4,"program":1,"frame_type":"close","untrusted":"x"}"#.to_vec(),
            // An unknown key inside the body.
            br#"{"version":4,"program":1,"frame_type":"call","body":{"source":"true","untrusted":"x"}}"#
                .to_vec(),
        ] {
            let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(&payload);
            let mut reader = wire.as_slice();

            let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "an unknown field must be a parse error: {}",
                String::from_utf8_lossy(&payload)
            );
        }
    }

    /// `frame_type` lives in the header, and `body` carries only the payload. This locks the wire
    /// layout the doc specifies (`frame_type` "MOVED out of body"), so a reader that logs or routes
    /// on `frame_type` need not descend into `body`. An MCP `open` still round-trips its `mode`.
    #[test]
    fn the_frame_type_is_in_the_header() {
        let wire = serde_json::to_value(frame(Body::Open {
            mode: Interpreter::Shell,
        }))
        .unwrap();
        assert_eq!(wire["frame_type"], "open", "the tag sits in the header");
        assert_eq!(
            wire["body"]["mode"], "shell",
            "the body is the payload only"
        );
        assert!(
            wire["body"].get("frame_type").is_none(),
            "the tag must not also live inside the body"
        );

        // A bodyless kind omits `body` entirely.
        let close = serde_json::to_value(frame(Body::Close)).unwrap();
        assert_eq!(close["frame_type"], "close");
        assert!(close.get("body").is_none(), "a bodyless kind omits body");

        // An MCP `open` carries its server name in `mode`, and round-trips.
        let mcp = frame(Body::Open {
            mode: Interpreter::Mcp {
                server: "agentcore".to_string(),
            },
        });
        let bytes = serde_json::to_vec(&mcp).unwrap();
        let back: Frame = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            back.body,
            Body::Open { mode: Interpreter::Mcp { server } } if server == "agentcore"
        ));
    }

    /// The pre-version-4-shape layout — the tag placed *inside* `body` — is refused, because the
    /// header now carries no `frame_type`. So a pre-change alias image is a refusal, not a misread.
    #[tokio::test]
    async fn a_tag_placed_inside_the_body_is_refused() {
        for payload in [
            // current tag, but in the old (in-body) position.
            br#"{"version":4,"program":1,"body":{"frame_type":"open","mode":"shell"}}"#.to_vec(),
            // older spelling: `frame` tag and `interpreter` field.
            br#"{"version":4,"program":1,"body":{"frame":"open","interpreter":"shell"}}"#.to_vec(),
        ] {
            let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(&payload);
            let mut reader = wire.as_slice();

            let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "the old in-body tag placement must be refused: {}",
                String::from_utf8_lossy(&payload)
            );
        }
    }

    /// A body-bearing kind requires its body, and a bodyless kind must omit it.
    #[tokio::test]
    async fn the_body_presence_matches_the_frame_type() {
        for payload in [
            // `call` needs a body.
            br#"{"version":4,"program":1,"frame_type":"call"}"#.to_vec(),
            // `close` must carry none.
            br#"{"version":4,"program":1,"frame_type":"close","body":{}}"#.to_vec(),
        ] {
            let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(&payload);
            let mut reader = wire.as_slice();

            let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "body presence must match the frame_type: {}",
                String::from_utf8_lossy(&payload)
            );
        }
    }

    /// Each superseded name is refused as an unknown field, so a stale alias built against the old
    /// spelling fails to parse rather than being misread. `a_tag_placed_inside_the_body`
    /// covers the old in-body *placement*; this covers the old *names* in their would-be positions.
    #[tokio::test]
    async fn the_superseded_frame_names_are_refused() {
        for payload in [
            // `frame` was the header tag; it is now `frame_type`, so `frame` is an unknown field
            // and `frame_type` is missing.
            br#"{"version":4,"program":1,"frame":"close"}"#.to_vec(),
            // `interpreter` was the open selector; it is now `mode`.
            br#"{"version":4,"program":1,"frame_type":"open","body":{"interpreter":"shell"}}"#
                .to_vec(),
            // `stdin_eof` was the stdin-end kind; it is now `input_eof`, so this is an unknown kind.
            br#"{"version":4,"program":1,"frame_type":"stdin_eof"}"#.to_vec(),
            // `out` was the output kind; it is now `output`.
            br#"{"version":4,"program":1,"frame_type":"out","body":{"stream":"stdout","data":""}}"#
                .to_vec(),
        ] {
            let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(&payload);
            let mut reader = wire.as_slice();

            let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "a superseded name must be refused: {}",
                String::from_utf8_lossy(&payload)
            );
        }
    }

    /// Every `DeniedKind` serializes to its exact snake_case wire name and round-trips.
    #[test]
    fn every_denied_kind_maps_to_its_wire_name() {
        fn wire_name(kind: DeniedKind) -> &'static str {
            match kind {
                DeniedKind::VersionMismatch => "version_mismatch",
                DeniedKind::TransportError => "transport_error",
                DeniedKind::OverBudget => "over_budget",
                DeniedKind::FlowControl => "flow_control",
                DeniedKind::Timeout => "timeout",
                DeniedKind::Internal => "internal",
            }
        }
        for kind in [
            DeniedKind::VersionMismatch,
            DeniedKind::TransportError,
            DeniedKind::OverBudget,
            DeniedKind::FlowControl,
            DeniedKind::Timeout,
            DeniedKind::Internal,
        ] {
            let denied = || {
                frame(Body::Denied {
                    kind,
                    reason: "r".to_string(),
                })
            };
            let wire = serde_json::to_value(denied()).unwrap();
            assert_eq!(wire["frame_type"], "denied");
            assert_eq!(
                wire["body"]["kind"],
                wire_name(kind),
                "{kind:?} must serialize as its wire name"
            );

            let bytes = serde_json::to_vec(&denied()).unwrap();
            let back: Frame = serde_json::from_slice(&bytes).unwrap();
            assert!(
                matches!(back.body, Body::Denied { kind: k, .. } if k == kind),
                "{kind:?} must round-trip"
            );
        }
    }

    /// A `denied` naming a reason-code outside the closed set is refused, so the vocabulary cannot
    /// grow silently on the wire — a new code is a variant and a version bump.
    #[tokio::test]
    async fn a_denied_kind_outside_the_closed_set_is_refused() {
        let payload =
            br#"{"version":4,"program":1,"frame_type":"denied","body":{"kind":"kaput","reason":"x"}}"#
                .to_vec();
        let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        let mut reader = wire.as_slice();

        let error = read_frame::<Frame, _>(&mut reader).await.unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "a reason-code outside the closed set must be refused"
        );
    }

    /// A body only the daemon may send is recognizable, so the dispatcher can refuse it.
    #[test]
    fn daemon_only_bodies_are_identified() {
        for body in [
            Body::Output {
                stream: Stream::Stdout,
                data: encode_payload(b"x"),
            },
            Body::Exit { status: 0 },
            Body::Denied {
                kind: DeniedKind::Internal,
                reason: "no".to_string(),
            },
        ] {
            assert!(
                body.is_daemon_only(),
                "the client must not be able to send {body:?}"
            );
        }
        for body in [
            Body::Open {
                mode: Interpreter::Shell,
            },
            Body::Call {
                correlation: Default::default(),
                source: "true".to_string(),
            },
            Body::InputEof,
            Body::Close,
        ] {
            assert!(!body.is_daemon_only(), "{body:?} is a client body");
        }
    }

    /// Payloads survive bytes that are not valid UTF-8.
    #[test]
    fn a_payload_carries_non_utf8_bytes() {
        let raw = [0x00_u8, 0xff, 0xfe, 0x80, b'h', b'i'];
        let encoded = encode_payload(&raw);
        assert_eq!(decode_payload(&encoded).unwrap(), raw);
    }

    #[test]
    fn a_malformed_payload_is_refused() {
        let error = decode_payload("not base64!!").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A full chunk still fits one frame after base64 expansion.
    #[test]
    fn the_chunk_cap_fits_worst_case_base64_expansion() {
        let body = Body::Output {
            stream: Stream::Stderr,
            data: encode_payload(&vec![0xff_u8; MAX_CHUNK_BYTES]),
        };
        let payload = serde_json::to_vec(&frame(body)).unwrap();
        assert!(
            payload.len() <= MAX_FRAME_BYTES,
            "a full chunk must still fit one frame: {} bytes",
            payload.len()
        );
    }

    /// Every Program's ceiling must leave room under the frame bound.
    const _: () = assert!(
        MAX_CHUNK_BYTES * 4 / 3 < MAX_FRAME_BYTES,
        "a base64-expanded chunk plus its envelope must fit one frame"
    );
}
