//! Bounded workload messages from the effect interceptor.

use std::fmt::{self, Write as _};
use std::io;

const MESSAGE_LIMIT: usize = 8192;

pub(super) fn denial_message(error: &io::Error) -> String {
    let mut message = Message(String::new());
    if write!(message, "{error}").is_err() {
        message.0.push_str("...");
    }
    message.0
}

struct Message(String);

impl fmt::Write for Message {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for character in text.chars() {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                for escaped in character.escape_default() {
                    self.push(escaped)?;
                }
            } else {
                self.push(character)?;
            }
        }
        Ok(())
    }
}

impl Message {
    fn push(&mut self, character: char) -> fmt::Result {
        if self.0.len() + character.len_utf8() > MESSAGE_LIMIT - 3 {
            return Err(fmt::Error);
        }
        self.0.push(character);
        Ok(())
    }
}
