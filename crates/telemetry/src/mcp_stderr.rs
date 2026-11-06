//! Bounded, redacted stderr from one admitted MCP server.

use std::sync::{Arc, Mutex};

use opentelemetry::logs::{LogRecord as _, Logger as _};
use opentelemetry_sdk::logs::SdkLogger;

const MAXIMUM_BYTES: usize = 64 * 1024;
const MAXIMUM_LINES: usize = 256;

#[derive(Default)]
pub(crate) struct Budget {
    bytes: usize,
    lines: usize,
    output_bytes: usize,
    notified: bool,
}

impl Budget {
    pub(crate) fn closed() -> Self {
        Self {
            notified: true,
            ..Self::default()
        }
    }
}

/// One server process's stderr, with a budget shared by that server's starts in this run.
pub struct McpStderr {
    logger: SdkLogger,
    server: String,
    budget: Arc<Mutex<Budget>>,
    secrets: Vec<Vec<u8>>,
    pending: Vec<u8>,
    stopped: bool,
}

impl McpStderr {
    pub(crate) fn new(
        logger: SdkLogger,
        server: &str,
        values: &[String],
        budget: Arc<Mutex<Budget>>,
    ) -> Self {
        let mut secrets = values
            .iter()
            .flat_map(|value| value.as_bytes().split(|byte| *byte == b'\n'))
            .filter(|value| !value.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        secrets.sort();
        secrets.dedup();
        Self {
            logger,
            server: server.to_string(),
            budget,
            secrets,
            pending: Vec::new(),
            stopped: false,
        }
    }

    /// Accept raw stderr bytes and return whether more bytes can be recorded.
    pub fn write(&mut self, bytes: &[u8]) -> bool {
        if self.stopped {
            return false;
        }
        let budget = Arc::clone(&self.budget);
        let Ok(mut budget) = budget.lock() else {
            self.stopped = true;
            return false;
        };
        for byte in bytes {
            if budget.notified {
                self.pending.clear();
                self.stopped = true;
                return false;
            }
            if budget.bytes >= MAXIMUM_BYTES || budget.lines >= MAXIMUM_LINES {
                if !self.pending.is_empty() {
                    self.flush(&mut budget, true);
                }
                if !budget.notified {
                    budget.notified = true;
                    self.emit("MCP stderr capture limit reached (65536 bytes or 256 lines); remaining output discarded", true);
                }
                self.stopped = true;
                return false;
            }
            budget.bytes += 1;
            if *byte == b'\n' {
                self.flush(&mut budget, false);
            } else {
                self.pending.push(*byte);
            }
        }
        true
    }

    /// Record the final unterminated line.
    pub fn finish(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let budget = Arc::clone(&self.budget);
        if let Ok(mut budget) = budget.lock() {
            if budget.notified {
                self.pending.clear();
            } else {
                self.flush(&mut budget, self.stopped);
            }
        } else {
            self.pending.clear();
        }
    }

    fn flush(&mut self, budget: &mut Budget, truncated: bool) {
        if budget.lines < MAXIMUM_LINES {
            let text = redact(&self.pending, &self.secrets, truncated);
            let remaining = MAXIMUM_BYTES.saturating_sub(budget.output_bytes);
            let mut end = remaining.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.emit(&text[..end], false);
            budget.output_bytes += end;
            budget.lines += 1;
            if end < text.len() {
                if !budget.notified {
                    budget.notified = true;
                    self.emit("MCP stderr capture limit reached (65536 bytes or 256 lines); remaining output discarded", true);
                }
                self.stopped = true;
            }
        }
        self.pending.clear();
    }

    fn emit(&self, text: &str, truncated: bool) {
        let mut record = self.logger.create_log_record();
        record.set_event_name("strands.box.mcp.stderr");
        record.set_timestamp(std::time::SystemTime::now());
        record.set_severity_number(opentelemetry::logs::Severity::Warn);
        record.set_body(text.to_string().into());
        record.add_attribute("strands.box.mcp.server", self.server.clone());
        record.add_attribute("strands.box.mcp.stderr.truncated", truncated);
        self.logger.emit(record);
    }
}

impl Drop for McpStderr {
    fn drop(&mut self) {
        self.finish();
    }
}

fn redact(bytes: &[u8], secrets: &[Vec<u8>], truncated: bool) -> String {
    let mut hidden = vec![false; bytes.len()];
    for secret in secrets {
        for start in 0..bytes.len() {
            let length = secret.len().min(bytes.len() - start);
            if bytes[start..start + length] == secret[..length]
                && (length == secret.len() || truncated)
            {
                hidden[start..start + length].fill(true);
            }
        }
    }
    let mut output = Vec::new();
    let mut masked = false;
    for (byte, hidden) in bytes.iter().zip(hidden) {
        if hidden {
            if !masked {
                output.extend_from_slice(b"[redacted]");
            }
        } else {
            output.push(*byte);
        }
        masked = hidden;
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_values_and_truncated_prefixes_are_masked() {
        let secrets = vec![b"abcd".to_vec(), b"bcde".to_vec(), b"secret".to_vec()];
        assert_eq!(
            redact(b"abcde secret", &secrets, false),
            "[redacted] [redacted]"
        );
        assert_eq!(redact(b"message sec", &secrets, true), "message [redacted]");
        assert_eq!(redact(b"message sec", &secrets, false), "message sec");
    }
}
