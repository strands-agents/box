//! Incremental response redaction with credential-sized retained state.

use std::fmt;

use zeroize::Zeroizing;

use crate::Secret;
use crate::attach::REDACTION;

/// An owned response scrubber that withholds only a possible secret prefix between body chunks.
pub struct ResponseRedactor {
    secret: Zeroizing<String>,
    fallback: Zeroizing<Vec<usize>>,
    matched: usize,
}

impl ResponseRedactor {
    pub(crate) fn new(secret: &Secret) -> Self {
        let secret = Zeroizing::new(secret.as_str().to_owned());
        let needle = secret.as_bytes();
        let mut fallback = Zeroizing::new(vec![0; needle.len()]);
        for index in 1..needle.len() {
            let mut matched = fallback[index - 1];
            while matched > 0 && needle[index] != needle[matched] {
                matched = fallback[matched - 1];
            }
            if needle[index] == needle[matched] {
                matched += 1;
            }
            fallback[index] = matched;
        }
        Self {
            secret,
            fallback,
            matched: 0,
        }
    }

    /// Replace secret occurrences in one header value, returning `None` when it needs no edit.
    pub fn redact_header(&self, value: &str) -> Option<String> {
        value
            .contains(self.secret.as_str())
            .then(|| value.replace(self.secret.as_str(), REDACTION))
    }

    /// Consume a body chunk and return safe bytes, with allocation bounded by the chunk and credential sizes.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let needle = self.secret.as_bytes();
        let mut output = Vec::with_capacity(chunk.len());
        for &byte in chunk {
            while self.matched > 0 && byte != needle[self.matched] {
                let retained = self.fallback[self.matched - 1];
                output.extend_from_slice(&needle[..self.matched - retained]);
                self.matched = retained;
            }
            if byte == needle[self.matched] {
                self.matched += 1;
                if self.matched == needle.len() {
                    output.extend_from_slice(REDACTION.as_bytes());
                    self.matched = 0;
                }
            } else {
                output.push(byte);
            }
        }
        output
    }

    /// Release an unmatched prefix at clean body completion; drop the scrubber instead on failure.
    pub fn finish(self) -> Vec<u8> {
        self.secret.as_bytes()[..self.matched].to_vec()
    }
}

impl fmt::Debug for ResponseRedactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseRedactor").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Destination, Inbound, Redactions};

    fn secret(value: &str) -> Secret {
        Secret::new(Zeroizing::new(value.to_owned()), "test://redaction").unwrap()
    }

    fn whole_body(secret: &Secret, body: &[u8]) -> Vec<u8> {
        Redactions::scan(
            &Inbound {
                destination: Destination {
                    host: "api.example.com",
                    port: 443,
                    path: "/",
                },
                headers: &[],
                body,
            },
            secret,
        )
        .and_then(|redactions| redactions.body().map(<[u8]>::to_vec))
        .unwrap_or_else(|| body.to_vec())
    }

    #[test]
    fn unrelated_events_emit_immediately_and_only_secret_prefixes_wait() {
        let mut redactor = ResponseRedactor::new(&secret("sk_secret_abcdef"));
        let event = b"data: {\"text\":\"hello\"}\n\n";
        assert_eq!(redactor.push(event), event);
        assert_eq!(redactor.push(b"data: sk_sec"), b"data: ");
        assert!(redactor.push(b"ret_abc").is_empty());
        assert_eq!(redactor.push(b"def\n\n"), b"[REDACTED]\n\n");
        assert_eq!(redactor.push(b"last: sk_sec"), b"last: ");
        assert_eq!(redactor.finish(), b"sk_sec");
    }

    #[test]
    fn every_partition_matches_whole_body_greedy_redaction() {
        for secret_len in 1..=4 {
            for secret_bits in 0..(1 << secret_len) {
                let value: String = (0..secret_len)
                    .map(|index| {
                        if secret_bits & (1 << index) == 0 {
                            'a'
                        } else {
                            'b'
                        }
                    })
                    .collect();
                let secret = secret(&value);
                for body_len in 0..=7 {
                    for body_bits in 0..(1 << body_len) {
                        let body: Vec<u8> = (0..body_len)
                            .map(|index| {
                                if body_bits & (1 << index) == 0 {
                                    b'a'
                                } else {
                                    b'b'
                                }
                            })
                            .collect();
                        let expected = whole_body(&secret, &body);
                        for first in 0..=body.len() {
                            for second in first..=body.len() {
                                let mut redactor = ResponseRedactor::new(&secret);
                                let mut actual = redactor.push(&body[..first]);
                                actual.extend(redactor.push(&body[first..second]));
                                actual.extend(redactor.push(&body[second..]));
                                actual.extend(redactor.finish());
                                assert_eq!(
                                    actual, expected,
                                    "secret {value:?}, body {body:?}, splits {first}/{second}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn byte_boundaries_preserve_binary_data_and_redact_utf8_secrets() {
        let secret = secret("clé🔑");
        let mut body = vec![0, 255, b'c'];
        body.extend_from_slice("clé🔑clé🔑!".as_bytes());
        body.extend_from_slice(&[128, 0]);
        let mut redactor = ResponseRedactor::new(&secret);
        let mut actual = Vec::new();
        for byte in &body {
            actual.extend(redactor.push(std::slice::from_ref(byte)));
        }
        actual.extend(redactor.finish());
        assert_eq!(actual, whole_body(&secret, &body));
    }

    #[test]
    fn a_long_stream_retains_only_credential_sized_state() {
        let secret = secret(&format!("{}B", "A".repeat(127)));
        let mut redactor = ResponseRedactor::new(&secret);
        let secret_capacity = redactor.secret.capacity();
        let fallback_capacity = redactor.fallback.capacity();
        let chunk = [b'A'; 8192];
        let mut emitted = 0;
        for _ in 0..4096 {
            let output = redactor.push(&chunk);
            assert!(output.iter().all(|byte| *byte == b'A'));
            emitted += output.len();
            assert!(redactor.matched < secret.as_str().len());
            assert_eq!(redactor.secret.capacity(), secret_capacity);
            assert_eq!(redactor.fallback.capacity(), fallback_capacity);
        }
        emitted += redactor.finish().len();
        assert_eq!(emitted, chunk.len() * 4096);
    }

    #[test]
    fn header_edits_and_debug_do_not_expose_the_credential() {
        let mut redactor = ResponseRedactor::new(&secret("private-value"));
        assert_eq!(
            redactor.redact_header("echo private-value, private-value"),
            Some("echo [REDACTED], [REDACTED]".to_owned())
        );
        assert_eq!(redactor.redact_header("application/json"), None);
        assert!(redactor.push(b"private-").is_empty());
        let debug = format!("{redactor:?}");
        assert!(!debug.contains("private"));
    }
}
