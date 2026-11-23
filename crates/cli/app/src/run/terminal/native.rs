use alacritty_terminal::vte::{Params, Parser, Perform};

use super::emulator::Osc;

#[derive(Default)]
pub(super) struct OutputState {
    parser: Parser,
    screen: ScreenMode,
    osc: Osc,
}

impl OutputState {
    pub(super) fn process(&mut self, bytes: &[u8]) {
        self.parser
            .advance(&mut self.screen, &self.osc.process(bytes));
    }

    pub(super) fn alternate(&self) -> Option<u16> {
        self.screen.alternate
    }
}

#[derive(Default)]
struct ScreenMode {
    alternate: Option<u16>,
}

impl Perform for ScreenMode {
    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], ignore: bool, action: char) {
        if ignore || intermediates != b"?" || !matches!(action, 'h' | 'l') {
            return;
        }
        for mode in params {
            if let &[mode @ (47 | 1047 | 1049)] = mode {
                self.alternate = (action == 'h').then_some(mode);
            }
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
        if !ignore && intermediates.is_empty() && byte == b'c' {
            self.alternate = None;
        }
    }
}

#[derive(Default)]
pub(super) struct StartupOutput {
    pub(super) bytes: Vec<u8>,
    parser: Parser,
    first: FirstOutput,
    escape: usize,
}

impl StartupOutput {
    pub(super) fn ready(&self) -> bool {
        self.first.ready
    }

    pub(super) fn push(&mut self, bytes: &[u8], output: &mut Vec<u8>) {
        if self.ready() {
            self.bytes.extend_from_slice(bytes);
            return;
        }
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'\x1b' {
                self.escape = self.bytes.len();
            }
            self.bytes.push(byte);
            self.parser.advance(&mut self.first, &[byte]);
            if std::mem::take(&mut self.first.forward) {
                output.extend(self.bytes.drain(self.escape..));
            }
            if self.first.ready
                || self.bytes.len() >= 64 * 1024
                || (self.bytes.len() == self.escape + 2 && matches!(byte, b'_' | b'^' | b'X'))
            {
                self.first.ready = true;
                self.bytes.extend_from_slice(&bytes[index + 1..]);
                return;
            }
        }
    }
}

#[derive(Default)]
struct FirstOutput {
    ready: bool,
    forward: bool,
}

impl Perform for FirstOutput {
    fn print(&mut self, character: char) {
        self.ready |= !character.is_whitespace();
    }

    fn execute(&mut self, byte: u8) {
        self.ready |= byte == b'\x07';
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _: bool, action: char) {
        if matches!(action, 'h' | 'l') {
            const INPUT_MODES: &[u16] = &[
                1, 9, 66, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 2004, 2031, 2048,
            ];
            self.forward = intermediates == b"?"
                && params
                    .iter()
                    .all(|mode| matches!(mode, [value] if INPUT_MODES.contains(value)));
            let screen_mode = intermediates == b"?"
                && params
                    .iter()
                    .all(|mode| matches!(mode, [6 | 7 | 25 | 47 | 1047 | 1048 | 1049 | 2026]));
            self.ready |= !self.forward && !screen_mode;
            return;
        }
        // shortcut: queries hand off early; extend if a CLI needs replies before a slow first draw.
        self.ready |= !(intermediates.is_empty()
            && matches!(
                action,
                'm' | 'r'
                    | 'J'
                    | 'K'
                    | 'H'
                    | 'G'
                    | 'f'
                    | 'A'
                    | 'B'
                    | 'C'
                    | 'D'
                    | 'E'
                    | 'F'
                    | 'd'
                    | 'e'
                    | 'a'
                    | 's'
            ))
            && !(action == 'q' && intermediates == b" ");
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _: bool, byte: u8) {
        self.forward = intermediates.is_empty() && matches!(byte, b'=' | b'>');
        let screen_command = intermediates.is_empty()
            && matches!(byte, b'7' | b'8' | b'D' | b'E' | b'M' | b'H' | b'\\');
        self.ready |=
            !self.forward && !screen_command && !matches!(intermediates, b"(" | b")" | b"*" | b"+");
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _: bool) {
        self.ready |= params.contains(&b"?".as_slice())
            || !matches!(params.first().copied(), Some(b"0" | b"1" | b"2"));
    }

    fn hook(&mut self, _: &Params, _: &[u8], _: bool, _: char) {
        self.ready = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_state_tracks_fragmented_alternate_modes_and_reset() {
        for mode in [47, 1047, 1049] {
            let mut state = OutputState::default();
            let enter = format!("\x1b[?{mode}h");
            for byte in enter.bytes() {
                state.process(&[byte]);
            }
            assert_eq!(state.alternate(), Some(mode));
            state.process(format!("\x1b[?{mode}l").as_bytes());
            assert_eq!(state.alternate(), None);
            state.process(enter.as_bytes());
            state.process(b"\x1bc");
            assert_eq!(state.alternate(), None);
        }
    }

    #[test]
    fn startup_waits_for_text_but_does_not_hold_native_queries_or_unbounded_output() {
        let mut startup = StartupOutput::default();
        let mut output = Vec::new();
        for byte in
            b"\x1b7\x1b[r\x1b8\x1b[?25l\x1b[?1h\x1b[?2004h\x1b=\x1b]2;Claude\x07\r\n\x1b[31m"
        {
            startup.push(&[*byte], &mut output);
            assert!(!startup.ready());
        }
        assert_eq!(output, b"\x1b[?1h\x1b[?2004h\x1b=");
        startup.push(b"Claude", &mut output);
        assert!(startup.ready());
        startup.push(b"\x1b[31m", &mut output);
        startup.push(b"=", &mut output);
        assert_eq!(output, b"\x1b[?1h\x1b[?2004h\x1b=");
        assert_eq!(
            startup.bytes,
            b"\x1b7\x1b[r\x1b8\x1b[?25l\x1b]2;Claude\x07\r\n\x1b[31mClaude\x1b[31m="
        );
        for (bytes, ready) in [
            (b"\x1b]2;Claude\x1b\\".as_slice(), false),
            (b"\x1b[6n", true),
            (b"\x1b[?u", true),
            (b"\x1b]11;?\x07", true),
            (b"\x1b_G", true),
            (b"\x1b[?9999h", true),
            (b"\x1b[>4;2m", true),
            (b"\x1bc", true),
            (b"\x1b#8", true),
            (&vec![b' '; 64 * 1024], true),
        ] {
            let mut startup = StartupOutput::default();
            startup.push(bytes, &mut Vec::new());
            assert_eq!(startup.ready(), ready);
        }
    }
}
