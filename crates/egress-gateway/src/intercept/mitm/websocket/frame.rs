//! The RFC 6455 frame format: read one peer's frames into messages, and write the gateway's own.

/// A continuation frame.
pub(super) const CONTINUATION: u8 = 0x0;
/// A text frame.
pub(super) const TEXT: u8 = 0x1;
/// A binary frame.
pub(super) const BINARY: u8 = 0x2;
/// A close frame.
pub(super) const CLOSE: u8 = 0x8;
/// A ping frame.
pub(super) const PING: u8 = 0x9;
/// A pong frame.
pub(super) const PONG: u8 = 0xA;

/// The close code for an endpoint that goes away.
pub(super) const GOING_AWAY: u16 = 1001;
/// The close code for a protocol error.
pub(super) const PROTOCOL_ERROR: u16 = 1002;
/// The close code for data that does not match its message type.
pub(super) const INVALID_DATA: u16 = 1007;
/// The close code for a message the boundary refuses.
pub(super) const POLICY_VIOLATION: u16 = 1008;
/// The close code for a message above the size limit.
pub(super) const TOO_BIG: u16 = 1009;
/// The close code for a gateway whose upstream failed.
pub(super) const BAD_GATEWAY: u16 = 1014;

/// The largest payload a control frame carries.
const MAX_CONTROL_PAYLOAD: u64 = 125;

/// The decoded bytes a [`Decoder`] keeps before it moves its unread bytes to the front.
const COMPACT_AFTER: usize = 64 * 1024;

/// The smallest payload that takes the decoder's allocation, instead of a copy, when its frame ends
/// the buffer.
const TAKE_BUFFER_AT: usize = 64 * 1024;

/// The largest allocation an emptied relay buffer keeps.
pub(super) const KEEP_CAPACITY: usize = 1024 * 1024;

/// Empty `buffer`, and free its allocation when it is above [`KEEP_CAPACITY`].
pub(super) fn empty(buffer: &mut Vec<u8>) {
    if buffer.capacity() > KEEP_CAPACITY {
        *buffer = Vec::new();
    } else {
        buffer.clear();
    }
}

/// Why the gateway closes a peer: the close code it sends, and a secret-free reason for the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fault {
    /// The close code sent to the peer that caused the fault.
    pub(super) code: u16,
    /// The reason, without payload bytes.
    pub(super) reason: &'static str,
}

impl Fault {
    fn protocol(reason: &'static str) -> Self {
        Self {
            code: PROTOCOL_ERROR,
            reason,
        }
    }
}

/// One thing a peer sent: a whole data message, or a control frame.
#[derive(PartialEq, Eq)]
pub(super) enum Event {
    /// A data message, reassembled from its fragments.
    Message {
        /// Whether the message is text.
        text: bool,
        /// The unmasked payload.
        payload: Vec<u8>,
        /// The largest fragment payload the peer sent, or `None` when the message came in one frame.
        fragment: Option<usize>,
    },
    /// A ping and its payload.
    Ping(Vec<u8>),
    /// A pong and its payload.
    Pong(Vec<u8>),
    /// A close frame and its checked payload.
    Close(Vec<u8>),
}

impl std::fmt::Debug for Event {
    /// The kind and length, never the payload.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, payload) = match self {
            Self::Message {
                text: true,
                payload,
                ..
            } => ("Text", payload),
            Self::Message {
                text: false,
                payload,
                ..
            } => ("Binary", payload),
            Self::Ping(payload) => ("Ping", payload),
            Self::Pong(payload) => ("Pong", payload),
            Self::Close(payload) => ("Close", payload),
        };
        write!(f, "{kind}({} bytes)", payload.len())
    }
}

/// One frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload_len: u64,
    /// The header's own length on the wire.
    len: usize,
}

impl Header {
    /// The header at the start of `bytes`, `None` when it has not fully arrived, or the fault it
    /// shows as soon as the bytes that show it arrive.
    fn parse(bytes: &[u8]) -> Result<Option<Self>, Fault> {
        let Some(&first) = bytes.first() else {
            return Ok(None);
        };
        if first & 0x70 != 0 {
            return Err(Fault::protocol("frame sets a reserved bit"));
        }
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0F;
        if !matches!(opcode, CONTINUATION | TEXT | BINARY | CLOSE | PING | PONG) {
            return Err(Fault::protocol("frame has an unknown opcode"));
        }
        let control = opcode & 0x08 != 0;
        if control && !fin {
            return Err(Fault::protocol("control frame is fragmented"));
        }
        let Some(&second) = bytes.get(1) else {
            return Ok(None);
        };
        let (payload_len, mut len) = match second & 0x7F {
            126 => match bytes.get(2..4) {
                Some(length) => (u64::from(u16::from_be_bytes([length[0], length[1]])), 4),
                None => return Ok(None),
            },
            127 => match bytes.get(2..10) {
                Some(length) => {
                    let mut wide = [0u8; 8];
                    wide.copy_from_slice(length);
                    let length = u64::from_be_bytes(wide);
                    if length >> 63 != 0 {
                        return Err(Fault::protocol("frame length sets the high bit"));
                    }
                    (length, 10)
                }
                None => return Ok(None),
            },
            short => (u64::from(short), 2),
        };
        if control && payload_len > MAX_CONTROL_PAYLOAD {
            return Err(Fault::protocol("control frame payload exceeds 125 bytes"));
        }
        let mask = if second & 0x80 != 0 {
            let Some(key) = bytes.get(len..len + 4) else {
                return Ok(None);
            };
            len += 4;
            Some([key[0], key[1], key[2], key[3]])
        } else {
            None
        };
        Ok(Some(Self {
            fin,
            opcode,
            mask,
            payload_len,
            len,
        }))
    }
}

/// A data message the peer started and has not finished.
struct Open {
    text: bool,
    payload: Vec<u8>,
    /// The largest fragment payload so far.
    fragment: usize,
}

/// Reads the frames one peer sends, checks each, and reassembles its messages.
pub(super) struct Decoder {
    /// Whether the peer is the workload, whose frames are masked.
    masked: bool,
    /// The largest message the peer may send.
    max_message: usize,
    /// Bytes received; the ones before `start` are decoded.
    buffer: Vec<u8>,
    start: usize,
    open: Option<Open>,
}

impl Decoder {
    /// A decoder for the workload's frames when `masked`, or for the upstream's frames.
    pub(super) fn new(masked: bool, max_message: usize) -> Self {
        Self {
            masked,
            max_message,
            buffer: Vec::new(),
            start: 0,
            open: None,
        }
    }

    /// Add bytes the peer sent.
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        if self.start == self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        } else if self.start >= COMPACT_AFTER {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole message or control frame, `None` until more bytes arrive, or the first fault.
    pub(super) fn next_event(&mut self) -> Result<Option<Event>, Fault> {
        loop {
            let Some(header) = Header::parse(&self.buffer[self.start..])? else {
                return Ok(None);
            };
            match (self.masked, header.mask.is_some()) {
                (true, false) => return Err(Fault::protocol("frame not masked")),
                (false, true) => return Err(Fault::protocol("frame masked")),
                _ => {}
            }
            match (header.opcode, self.open.is_some()) {
                (TEXT | BINARY, true) => {
                    return Err(Fault::protocol("data frame inside a fragmented message"));
                }
                (CONTINUATION, false) => {
                    return Err(Fault::protocol("continuation without an open message"));
                }
                _ => {}
            }
            if header.opcode & 0x08 == 0 {
                let open = self.open.as_ref().map_or(0, |open| open.payload.len());
                if (open as u64).saturating_add(header.payload_len) > self.max_message as u64 {
                    return Err(Fault {
                        code: TOO_BIG,
                        reason: "message exceeds the size limit",
                    });
                }
            }
            // The size check above bounds a data frame and the header check a control frame, so the
            // length fits in memory.
            let payload_len = header.payload_len as usize;
            let begin = self.start + header.len;
            let end = begin.saturating_add(payload_len);
            if self.buffer.len() < end {
                return Ok(None);
            }
            let mut payload = if end == self.buffer.len() && payload_len >= TAKE_BUFFER_AT {
                self.buffer.drain(..begin);
                self.start = 0;
                std::mem::take(&mut self.buffer)
            } else {
                let payload = self.buffer[begin..end].to_vec();
                self.start = end;
                if self.start == self.buffer.len() {
                    empty(&mut self.buffer);
                    self.start = 0;
                }
                payload
            };
            if let Some(key) = header.mask {
                apply_mask(&mut payload, key);
            }
            match header.opcode {
                TEXT | BINARY => {
                    let text = header.opcode == TEXT;
                    if header.fin {
                        return complete(text, payload, None).map(Some);
                    }
                    self.open = Some(Open {
                        text,
                        fragment: payload.len(),
                        payload,
                    });
                }
                CONTINUATION => {
                    let open = self.open.as_mut().expect("an open message");
                    open.fragment = open.fragment.max(payload.len());
                    open.payload.extend_from_slice(&payload);
                    if header.fin {
                        let Open {
                            text,
                            payload,
                            fragment,
                        } = self.open.take().expect("an open message");
                        return complete(text, payload, Some(fragment)).map(Some);
                    }
                }
                CLOSE => {
                    check_close(&payload)?;
                    return Ok(Some(Event::Close(payload)));
                }
                PING => return Ok(Some(Event::Ping(payload))),
                _ => return Ok(Some(Event::Pong(payload))),
            }
        }
    }
}

/// A whole data message, or the fault its content shows.
fn complete(text: bool, payload: Vec<u8>, fragment: Option<usize>) -> Result<Event, Fault> {
    if text && std::str::from_utf8(&payload).is_err() {
        return Err(Fault {
            code: INVALID_DATA,
            reason: "text message not UTF-8",
        });
    }
    Ok(Event::Message {
        text,
        payload,
        fragment,
    })
}

/// Check a close payload: empty, or a valid code and a UTF-8 reason.
fn check_close(payload: &[u8]) -> Result<(), Fault> {
    match payload {
        [] => Ok(()),
        [_] => Err(Fault::protocol("close payload of one byte")),
        [high, low, reason @ ..] => {
            if !matches!(
                u16::from_be_bytes([*high, *low]),
                1000..=1003 | 1007..=1014 | 3000..=4999
            ) {
                return Err(Fault::protocol("close code invalid"));
            }
            std::str::from_utf8(reason).map(|_| ()).map_err(|_| Fault {
                code: INVALID_DATA,
                reason: "close reason not UTF-8",
            })
        }
    }
}

/// XOR `bytes` with the four-byte `key`, which masks and unmasks alike.
pub(super) fn apply_mask(bytes: &mut [u8], key: [u8; 4]) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key[index % 4];
    }
}

/// Append one frame to `out`, the last of its message when `fin`, masked with `mask` when it goes
/// to the upstream.
pub(super) fn encode(
    out: &mut Vec<u8>,
    opcode: u8,
    fin: bool,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) {
    out.reserve(14 + payload.len());
    out.push(if fin { 0x80 } else { 0 } | opcode);
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        short @ 0..=125 => out.push(mask_bit | short as u8),
        medium @ 126..=0xFFFF => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(medium as u16).to_be_bytes());
        }
        long => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(long as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(payload);
            apply_mask(&mut out[start..], key);
        }
        None => out.extend_from_slice(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    fn frame(opcode: u8, fin: bool, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, opcode, fin, payload, mask);
        out
    }

    fn decode_all(decoder: &mut Decoder, bytes: &[u8]) -> Result<Vec<Event>, Fault> {
        decoder.feed(bytes);
        let mut events = Vec::new();
        while let Some(event) = decoder.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn workload() -> Decoder {
        Decoder::new(true, 1 << 20)
    }

    fn upstream() -> Decoder {
        Decoder::new(false, 1 << 20)
    }

    #[test]
    fn each_length_form_round_trips_at_its_boundaries() {
        for (length, header_len) in [(0, 2), (125, 2), (126, 4), (65535, 4), (65536, 10)] {
            let payload: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            for mask in [None, Some(KEY)] {
                let wire = frame(BINARY, true, &payload, mask);
                let header = Header::parse(&wire).unwrap().unwrap();
                let expected_len = header_len + if mask.is_some() { 4 } else { 0 };
                assert_eq!(header.len, expected_len, "length {length}");
                assert_eq!(header.payload_len, length as u64);
                assert_eq!(wire.len(), expected_len + length);
                let mut decoder = Decoder::new(mask.is_some(), 1 << 20);
                assert_eq!(
                    decode_all(&mut decoder, &wire).unwrap(),
                    vec![Event::Message {
                        text: false,
                        payload: payload.clone(),
                        fragment: None,
                    }],
                    "length {length}, mask {mask:?}"
                );
            }
        }
    }

    #[test]
    fn a_masked_payload_differs_on_the_wire_and_unmasks() {
        let wire = frame(TEXT, true, b"Hello", Some(KEY));
        assert_eq!(&wire[2..6], &KEY);
        assert_ne!(&wire[6..], b"Hello");
        let mut decoder = workload();
        assert_eq!(
            decode_all(&mut decoder, &wire).unwrap(),
            vec![Event::Message {
                text: true,
                payload: b"Hello".to_vec(),
                fragment: None,
            }]
        );
    }

    #[test]
    fn the_rfc_6455_masked_example_decodes() {
        let wire = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        let mut decoder = workload();
        assert_eq!(
            decode_all(&mut decoder, &wire).unwrap(),
            vec![Event::Message {
                text: true,
                payload: b"Hello".to_vec(),
                fragment: None,
            }]
        );
    }

    #[test]
    fn a_frame_split_across_reads_waits_for_its_last_byte() {
        let wire = frame(BINARY, true, &[7u8; 300], Some(KEY));
        let mut decoder = workload();
        for byte in &wire[..wire.len() - 1] {
            decoder.feed(std::slice::from_ref(byte));
            assert_eq!(decoder.next_event().unwrap(), None);
        }
        decoder.feed(&wire[wire.len() - 1..]);
        assert_eq!(
            decoder.next_event().unwrap(),
            Some(Event::Message {
                text: false,
                payload: vec![7u8; 300],
                fragment: None,
            })
        );
    }

    #[test]
    fn fragments_reassemble_into_one_message() {
        let mut wire = frame(TEXT, false, b"frag", Some(KEY));
        wire.extend(frame(CONTINUATION, false, b"mented ", Some(KEY)));
        wire.extend(frame(CONTINUATION, true, b"text", Some(KEY)));
        assert_eq!(
            decode_all(&mut workload(), &wire).unwrap(),
            vec![Event::Message {
                text: true,
                payload: b"fragmented text".to_vec(),
                fragment: Some(7),
            }]
        );
    }

    #[test]
    fn a_control_frame_between_fragments_comes_out_first() {
        let mut wire = frame(BINARY, false, b"one", Some(KEY));
        wire.extend(frame(PING, true, b"p", Some(KEY)));
        wire.extend(frame(CONTINUATION, true, b"two", Some(KEY)));
        assert_eq!(
            decode_all(&mut workload(), &wire).unwrap(),
            vec![
                Event::Ping(b"p".to_vec()),
                Event::Message {
                    text: false,
                    payload: b"onetwo".to_vec(),
                    fragment: Some(3),
                }
            ]
        );
    }

    #[test]
    fn control_frames_and_close_payloads_decode() {
        let mut wire = frame(PING, true, b"ping", None);
        wire.extend(frame(PONG, true, b"pong", None));
        wire.extend(frame(CLOSE, true, b"\x03\xe8bye", None));
        wire.extend(frame(CLOSE, true, b"", None));
        assert_eq!(
            decode_all(&mut upstream(), &wire).unwrap(),
            vec![
                Event::Ping(b"ping".to_vec()),
                Event::Pong(b"pong".to_vec()),
                Event::Close(b"\x03\xe8bye".to_vec()),
                Event::Close(Vec::new()),
            ]
        );
    }

    fn fault_of(decoder: &mut Decoder, wire: &[u8]) -> Fault {
        decode_all(decoder, wire).expect_err("the frame is refused")
    }

    #[test]
    fn the_masking_rule_follows_the_direction() {
        let unmasked = frame(TEXT, true, b"x", None);
        assert_eq!(
            fault_of(&mut workload(), &unmasked),
            Fault::protocol("frame not masked")
        );
        let masked = frame(TEXT, true, b"x", Some(KEY));
        assert_eq!(
            fault_of(&mut upstream(), &masked),
            Fault::protocol("frame masked")
        );
    }

    #[test]
    fn malformed_headers_are_refused() {
        let mut reserved = frame(TEXT, true, b"x", Some(KEY));
        reserved[0] |= 0x40;
        let mut opcode = frame(TEXT, true, b"x", Some(KEY));
        opcode[0] = 0x83;
        let fragmented_ping = frame(PING, false, b"x", Some(KEY));
        let long_ping = frame(PING, true, &[0u8; 126], Some(KEY));
        let mut high_bit = vec![0x82, 0xFF];
        high_bit.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 1]);
        for (wire, reason) in [
            (reserved, "frame sets a reserved bit"),
            (opcode, "frame has an unknown opcode"),
            (fragmented_ping, "control frame is fragmented"),
            (long_ping, "control frame payload exceeds 125 bytes"),
            (high_bit, "frame length sets the high bit"),
        ] {
            assert_eq!(
                fault_of(&mut workload(), &wire),
                Fault::protocol(reason),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_fault_in_the_first_byte_needs_no_more_bytes() {
        assert_eq!(
            fault_of(&mut workload(), &[0xC1]),
            Fault::protocol("frame sets a reserved bit")
        );
    }

    #[test]
    fn message_order_is_enforced() {
        let continuation = frame(CONTINUATION, true, b"x", Some(KEY));
        assert_eq!(
            fault_of(&mut workload(), &continuation),
            Fault::protocol("continuation without an open message")
        );
        let mut nested = frame(TEXT, false, b"a", Some(KEY));
        nested.extend(frame(TEXT, true, b"b", Some(KEY)));
        assert_eq!(
            fault_of(&mut workload(), &nested),
            Fault::protocol("data frame inside a fragmented message")
        );
    }

    #[test]
    fn a_message_order_fault_is_refused_from_the_header() {
        let continuation = frame(CONTINUATION, true, &[0u8; 1000], Some(KEY));
        assert_eq!(
            fault_of(&mut workload(), &continuation[..8]),
            Fault::protocol("continuation without an open message"),
            "the header alone shows the fault"
        );

        let mut decoder = Decoder::new(true, 10);
        let mut nested = frame(TEXT, false, &[b'a'; 6], Some(KEY));
        nested.extend(frame(TEXT, true, &[b'b'; 6], Some(KEY)));
        assert_eq!(
            fault_of(&mut decoder, &nested),
            Fault::protocol("data frame inside a fragmented message"),
            "an order fault is a protocol error, even when the frame is also above the limit"
        );
    }

    #[test]
    fn a_drained_decoder_frees_a_large_buffer() {
        let mut decoder = Decoder::new(false, 4 << 20);
        let mut wire = frame(BINARY, true, &vec![1u8; 2 << 20], None);
        wire.extend(frame(TEXT, true, b"after", None));
        assert_eq!(decode_all(&mut decoder, &wire).unwrap().len(), 2);
        assert!(
            decoder.buffer.capacity() <= KEEP_CAPACITY,
            "{}",
            decoder.buffer.capacity()
        );
    }

    #[test]
    fn a_message_above_the_limit_is_refused_before_its_payload_arrives() {
        let mut decoder = Decoder::new(true, 10);
        let wire = frame(BINARY, true, &[0u8; 11], Some(KEY));
        assert_eq!(
            fault_of(&mut decoder, &wire[..6]).code,
            TOO_BIG,
            "the header alone shows the size"
        );

        let mut decoder = Decoder::new(true, 10);
        let mut wire = frame(BINARY, false, &[0u8; 6], Some(KEY));
        wire.extend(frame(CONTINUATION, true, &[0u8; 5], Some(KEY)));
        assert_eq!(
            fault_of(&mut decoder, &wire),
            Fault {
                code: TOO_BIG,
                reason: "message exceeds the size limit"
            },
            "the limit covers the whole reassembled message"
        );

        let mut decoder = Decoder::new(true, 10);
        let wire = frame(BINARY, true, &[0u8; 10], Some(KEY));
        assert_eq!(decode_all(&mut decoder, &wire).unwrap().len(), 1);
    }

    #[test]
    fn a_text_message_must_be_utf8_after_reassembly() {
        // A two-byte character split across two fragments is valid once reassembled.
        let mut split = frame(TEXT, false, &[0xC3], Some(KEY));
        split.extend(frame(CONTINUATION, true, &[0xA9], Some(KEY)));
        assert_eq!(
            decode_all(&mut workload(), &split).unwrap(),
            vec![Event::Message {
                text: true,
                payload: "\u{e9}".as_bytes().to_vec(),
                fragment: Some(1),
            }]
        );
        let invalid = frame(TEXT, true, &[0xC3, 0x28], Some(KEY));
        assert_eq!(fault_of(&mut workload(), &invalid).code, INVALID_DATA);
        let binary = frame(BINARY, true, &[0xC3, 0x28], Some(KEY));
        assert!(decode_all(&mut workload(), &binary).is_ok());
    }

    #[test]
    fn close_payloads_are_checked() {
        for (payload, fault) in [
            (
                &b"\x03"[..],
                Some(Fault::protocol("close payload of one byte")),
            ),
            (b"\x03\xed", Some(Fault::protocol("close code invalid"))),
            (b"\x03\xee", Some(Fault::protocol("close code invalid"))),
            (b"\x00\x00", Some(Fault::protocol("close code invalid"))),
            (
                b"\x03\xe8\xff",
                Some(Fault {
                    code: INVALID_DATA,
                    reason: "close reason not UTF-8",
                }),
            ),
            (b"\x03\xe8", None),
            (b"\x03\xf1", None),
            (b"\x0b\xb8", None),
            (b"\x13\x87ok", None),
        ] {
            assert_eq!(check_close(payload).err(), fault, "{payload:?}");
        }
    }

    #[test]
    fn an_event_never_prints_its_payload() {
        let event = Event::Message {
            text: true,
            payload: b"sk_live_SECRET".to_vec(),
            fragment: Some(4),
        };
        assert_eq!(format!("{event:?}"), "Text(14 bytes)");
    }
}
