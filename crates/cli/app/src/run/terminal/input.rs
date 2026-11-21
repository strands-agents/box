use std::time::{Duration, Instant};

use alacritty_terminal::grid::Scroll;
use ratatui::layout::Rect;

use super::super::banner::Heading;
use super::mouse::{Click, Mouse};

pub(super) struct Input {
    pub(super) minimized: bool,
    pub(super) enabled: bool,
    pub(super) navigation: usize,
    pub(super) toggle_policy: bool,
    pub(super) reload_policy: bool,
    pub(super) reload_available: bool,
    pending: Vec<u8>,
    paste: bool,
    paste_markers: bool,
    escape_at: Option<Instant>,
    pub(super) agent_paste: bool,
    pub(super) mouse: Mouse,
    pub(super) controls: Option<(u16, Heading)>,
    pub(super) files: Vec<(Rect, String)>,
    pub(super) pointer: Option<(usize, u16)>,
    pub(super) native_rows: u16,
    mouse_captured: bool,
    pub(super) selecting: bool,
    pub(super) actions: Vec<Action>,
}

pub(super) enum Action {
    Select(Click),
    ClearSelection,
    CopyPath(String),
    Scroll(Scroll),
}

impl Input {
    pub(super) fn new() -> Self {
        Self {
            minimized: true,
            enabled: true,
            navigation: 0,
            toggle_policy: false,
            reload_policy: false,
            reload_available: false,
            pending: Vec::new(),
            paste: false,
            paste_markers: false,
            escape_at: None,
            agent_paste: false,
            mouse: Mouse::default(),
            controls: None,
            files: Vec::new(),
            pointer: None,
            native_rows: 0,
            mouse_captured: false,
            selecting: false,
            actions: Vec::new(),
        }
    }

    pub(super) fn route(&mut self, bytes: &[u8], agent: &mut Vec<u8>) {
        for &byte in bytes {
            if self.paste {
                self.pasted(byte, agent);
                continue;
            }
            if self.pending.is_empty() && byte != 0x1b {
                self.key(&[byte], agent);
                continue;
            }
            if self.pending.is_empty() {
                self.escape_at = Some(Instant::now());
            }
            self.pending.push(byte);
            let complete = match self.pending.as_slice() {
                [0x1b] => false,
                [0x1b, b'[', rest @ ..] => !rest.is_empty() && (0x40..=0x7e).contains(&byte),
                [0x1b, b'O'] => false,
                [0x1b, b']', ..] => byte == 7 || self.pending.ends_with(b"\x1b\\"),
                _ => true,
            };
            if complete || self.pending.len() == 256 {
                let sequence = std::mem::take(&mut self.pending);
                self.key(&sequence, agent);
                self.escape_at = None;
            }
        }
    }

    pub(super) fn flush_escape(&mut self, agent: &mut Vec<u8>) {
        if !self.paste
            && !self.pending.is_empty()
            && self
                .escape_at
                .is_some_and(|at| at.elapsed() >= Duration::from_millis(50))
        {
            let pending = std::mem::take(&mut self.pending);
            self.escape_at = None;
            self.key(&pending, agent);
        }
    }

    fn key(&mut self, bytes: &[u8], agent: &mut Vec<u8>) {
        if let Some(click) = Click::parse(bytes) {
            self.click(click, bytes, agent);
            return;
        }
        if bytes.starts_with(b"\x1b]") || matches!(bytes, b"\x1b[I" | b"\x1b[O") {
            if bytes == b"\x1b[O" {
                self.selecting = false;
                self.actions.push(Action::ClearSelection);
            }
            agent.extend(bytes);
            return;
        }
        self.selecting = false;
        if !matches!(self.actions.last(), Some(Action::Scroll(Scroll::Bottom))) {
            self.actions.push(Action::Scroll(Scroll::Bottom));
        }
        if bytes == b"\x1b[200~" {
            self.paste = true;
            self.paste_markers = self.agent_paste;
            if self.paste_markers {
                agent.extend(bytes);
            }
            return;
        }
        let report = keyboard_report(bytes);
        // Ctrl+] minimizes or expands the banner.
        let minimize = bytes == b"\x1d"
            || report.is_some_and(|(code, modifiers, _)| code == 93 && modifiers == 5);
        if minimize && self.enabled {
            if report.is_none_or(|(_, _, event)| event == 1) {
                self.minimized = !self.minimized;
            }
            return;
        }
        // Ctrl+\ requests a policy toggle.
        let policy_toggle = bytes == b"\x1c"
            || report.is_some_and(|(code, modifiers, _)| code == 92 && modifiers == 5);
        if policy_toggle {
            if report.is_none_or(|(_, _, event)| event == 1) {
                self.toggle_policy = !self.toggle_policy;
            }
            return;
        }
        let reload = bytes == b"\x1b\x12"
            || report.is_some_and(|(code, modifiers, _)| code == 114 && modifiers == 7);
        if reload && self.reload_available {
            if report.is_none_or(|(_, _, event)| event == 1) {
                self.reload_policy = true;
            }
            return;
        }
        agent.extend(bytes);
    }

    fn click(&mut self, click: Click, bytes: &[u8], agent: &mut Vec<u8>) {
        if click.column == 0 || click.row == 0 {
            return;
        }
        self.pointer = u16::try_from(click.row)
            .ok()
            .map(|row| ((click.column - 1) as usize, row));
        if self.selecting {
            if click.left_release() {
                self.selecting = false;
                self.actions.push(Action::Select(click));
            } else if click.left_drag() {
                self.actions.push(Action::Select(click));
            }
            return;
        }
        if self.mouse_captured {
            if click.release {
                self.mouse_captured = false;
            }
            return;
        }
        if click.row > u32::from(self.native_rows) {
            self.mouse_captured = click.left_press();
            if self.mouse_captured
                && self.enabled
                && let Some((row, heading)) = &self.controls
                && click.row == u32::from(*row)
            {
                let column = (click.column - 1) as usize;
                if heading.activity.contains(&column) {
                    self.navigation += 1;
                } else if heading.minimize.contains(&column) {
                    self.minimized = !self.minimized;
                } else if heading.policy.contains(&column) {
                    self.toggle_policy = !self.toggle_policy;
                } else if self.reload_available && heading.reload.contains(&column) {
                    self.reload_policy = true;
                }
            }
            if self.mouse_captured
                && self.enabled
                && !self.minimized
                && let Some((_, path)) = self.files.iter().find(|(area, _)| {
                    click.row == u32::from(area.y)
                        && (u32::from(area.x)..u32::from(area.right()))
                            .contains(&(click.column - 1))
                })
            {
                self.actions.push(Action::CopyPath(path.clone()));
            }
        } else if self.mouse.tracking == 0 && click.left_press() {
            self.selecting = true;
            self.actions.push(Action::Select(click));
        } else if self.mouse.tracking == 0
            && let Some(lines) = click.scroll()
        {
            self.actions.push(Action::Scroll(Scroll::Delta(lines)));
        } else {
            self.mouse.forward(&click, bytes, agent);
        }
    }

    fn pasted(&mut self, byte: u8, agent: &mut Vec<u8>) {
        const END: &[u8] = b"\x1b[201~";
        self.pending.push(byte);
        while !END.starts_with(&self.pending) {
            let byte = self.pending.remove(0);
            agent.push(byte);
        }
        if self.pending == END {
            if self.paste_markers {
                agent.extend(END);
            }
            self.pending.clear();
            self.paste = false;
        }
    }
}

fn keyboard_report(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    let text = std::str::from_utf8(bytes).ok()?.strip_prefix("\x1b[")?;
    if let Some(parameters) = text.strip_suffix('u') {
        let mut fields = parameters.split(';');
        let code = fields.next()?.split(':').next()?.parse().ok()?;
        let (modifiers, event) = modifiers(fields.next().unwrap_or("1"))?;
        Some((code, modifiers, event))
    } else if let Some(parameters) = text
        .strip_prefix("27;")
        .and_then(|text| text.strip_suffix('~'))
    {
        let mut fields = parameters.split(';');
        let (modifiers, event) = modifiers(fields.next()?)?;
        Some((fields.next()?.parse().ok()?, modifiers, event))
    } else {
        None
    }
}

fn modifiers(text: &str) -> Option<(u32, u32)> {
    let mut fields = text.split(':');
    Some((
        fields.next()?.parse::<u32>().ok()? & !192,
        fields.next().unwrap_or("1").parse().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copied(input: &mut Input) -> Option<String> {
        input
            .actions
            .drain(..)
            .filter_map(|action| match action {
                Action::CopyPath(path) => Some(path),
                _ => None,
            })
            .next_back()
    }

    #[test]
    fn file_clicks_copy_the_path_without_forwarding_or_triggering_other_controls() {
        let mut input = Input::new();
        input.native_rows = 12;
        input.minimized = false;
        input.files = vec![
            (Rect::new(2, 15, 12, 1), "/profile/policy.dw".into()),
            (Rect::new(2, 18, 16, 1), "/profile/profile.toml".into()),
        ];
        let mut agent = Vec::new();
        for (column, row, path) in [
            (3, 15, "/profile/policy.dw"),
            (14, 15, "/profile/policy.dw"),
            (3, 18, "/profile/profile.toml"),
            (18, 18, "/profile/profile.toml"),
        ] {
            for byte in format!("\x1b[<0;{column};{row}M").bytes() {
                input.route(&[byte], &mut agent);
            }
            assert_eq!(copied(&mut input).as_deref(), Some(path));
            input.route(
                format!("\x1b[<32;{column};{row}M\x1b[<0;{column};{row}m").as_bytes(),
                &mut agent,
            );
            assert!(copied(&mut input).is_none());
        }
        for bytes in [
            b"\x1b[<35;3;15M".as_slice(),
            b"\x1b[<2;3;15M\x1b[<2;3;15m",
            b"\x1b[<0;2;15M\x1b[<0;2;15m",
            b"\x1b[<0;15;15M\x1b[<0;15;15m",
            b"\x1b[<0;3;14M\x1b[<0;3;14m",
            b"\x1b[<0;65539;15M\x1b[<0;65539;15m",
        ] {
            input.route(bytes, &mut agent);
            assert!(copied(&mut input).is_none(), "{bytes:?}");
        }
        let pasted = b"\x1b[<0;3;15M\x1b[<0;3;15m".as_slice();
        input.route(&[b"\x1b[200~", pasted, b"\x1b[201~"].concat(), &mut agent);
        assert!(copied(&mut input).is_none());
        assert_eq!(agent, pasted);
        assert_eq!(input.navigation, 0);
        assert!(!input.toggle_policy);
        assert!(!input.minimized);
        for (enabled, minimized) in [(true, true), (false, false)] {
            input.enabled = enabled;
            input.minimized = minimized;
            input.route(pasted, &mut agent);
            assert!(copied(&mut input).is_none());
        }
    }

    #[test]
    fn native_mouse_reports_only_reach_an_agent_that_requests_them() {
        let mut input = Input::new();
        input.native_rows = 19;
        let mut agent = Vec::new();
        let click = b"\x1b[<0;10;2M\x1b[<0;10;2m";
        input.route(click, &mut agent);
        assert!(agent.is_empty());
        input.mouse.format = 1006;
        for tracking in [1000, 1002, 1003] {
            input.mouse.tracking = tracking;
            input.route(click, &mut agent);
            assert_eq!(agent, click);
            agent.clear();
        }
        input.mouse.tracking = 0;
        input.route(click, &mut agent);
        assert!(agent.is_empty());
    }

    #[test]
    fn local_drag_captures_release_across_the_banner_and_keys_cancel_it() {
        let mut input = Input::new();
        input.native_rows = 10;
        let mut agent = Vec::new();
        input.route(b"\x1b[<0;2;1M\x1b[<32;5;12M\x1b[<0;5;12m", &mut agent);
        assert_eq!(input.actions.len(), 3);
        assert!(!input.selecting);
        assert!(agent.is_empty());
        assert!(input.minimized);
        input.actions.clear();
        input.route(b"\x1b[<0;2;1M", &mut agent);
        assert!(input.selecting);
        input.route(b"\x1b[200~pasted\x1b[201~", &mut agent);
        assert!(!input.selecting);
        assert!(matches!(
            input.actions.as_slice(),
            [Action::Select(_), Action::Scroll(Scroll::Bottom)]
        ));
        assert_eq!(agent, b"pasted");
    }

    #[test]
    fn wheel_scrolls_locally_only_when_the_agent_does_not_handle_the_mouse() {
        let mut input = Input::new();
        input.native_rows = 10;
        let wheel = b"\x1b[<64;2;3M\x1b[<65;2;3M";
        let mut agent = Vec::new();
        input.route(wheel, &mut agent);
        assert!(matches!(
            input.actions.as_slice(),
            [
                Action::Scroll(Scroll::Delta(3)),
                Action::Scroll(Scroll::Delta(-3))
            ]
        ));
        assert!(agent.is_empty());
        input.actions.clear();
        input.selecting = true;
        let reports = b"\x1b]11;rgb:0000/0000/0000\x07\x1b[O\x1b[I";
        input.route(reports, &mut agent);
        assert!(matches!(input.actions.as_slice(), [Action::ClearSelection]));
        assert!(!input.selecting);
        assert_eq!(agent, reports);
        input.actions.clear();
        agent.clear();
        input.route(b"\x1b[<64;2;12M", &mut agent);
        assert!(input.actions.is_empty(), "the banner must not scroll");
        input.mouse = Mouse {
            tracking: 1000,
            format: 1006,
        };
        input.route(wheel, &mut agent);
        assert!(input.actions.is_empty());
        assert_eq!(agent, wheel);
    }

    #[test]
    fn hover_stays_local_unless_the_native_cli_requests_motion() {
        let hover = b"\x1b[<35;10;2M";
        let drag = b"\x1b[<32;10;2M";
        for (tracking, expected) in [
            (0, Vec::new()),
            (1000, Vec::new()),
            (1002, drag.to_vec()),
            (1003, [hover.as_slice(), drag.as_slice()].concat()),
        ] {
            let mut input = Input::new();
            input.native_rows = 17;
            input.mouse.tracking = tracking;
            input.mouse.format = 1006;
            let mut agent = Vec::new();
            input.route(hover, &mut agent);
            input.route(drag, &mut agent);
            assert_eq!(agent, expected);
        }
        let mut input = Input::new();
        input.native_rows = 17;
        input.minimized = false;
        input.controls = Some((
            18,
            Heading {
                line: String::new(),
                minimize: 1..10,
                activity: 28..40,
                policy: 0..0,
                reload: 0..0,
                message: 0..0,
                policy_notice: false,
            },
        ));
        input.mouse.tracking = 1003;
        input.mouse.format = 1006;
        let mut agent = Vec::new();
        input.route(b"\x1b[<35;30;18M", &mut agent);
        assert_eq!(input.navigation, 0);
        input.route(b"\x1b[<0;2;18m", &mut agent);
        assert!(!input.minimized);
        for button in [4, 32, 64] {
            input.route(format!("\x1b[<{button};2;18M").as_bytes(), &mut agent);
            assert!(!input.minimized);
        }
        input.route(b"\x1b[<0;30;18M", &mut agent);
        assert_eq!(input.navigation, 1);
        input.route(b"\x1b[<35;1;1M\x1b[<0;1;1m", &mut agent);
        input.mouse.tracking = 1000;
        input.route(b"\x1b[<0;2;18M", &mut agent);
        assert!(input.minimized);
        input.native_rows = 24;
        input.route(b"\x1b[<35;2;18M\x1b[<0;2;18m", &mut agent);
        assert!(agent.is_empty());
        assert!(!input.mouse_captured);
    }

    #[test]
    fn minimize_shortcut_toggles_and_ignores_repeats_and_releases() {
        for key in [b"\x1d".as_slice(), b"\x1b[93;5u", b"\x1b[27;5;93~"] {
            let mut input = Input::new();
            let mut agent = Vec::new();
            for byte in key {
                input.route(&[*byte], &mut agent);
            }
            assert!(!input.minimized);
            for event in [b"\x1b[93;5:2u", b"\x1b[93;5:3u"] {
                input.route(event, &mut agent);
                assert!(!input.minimized);
            }
            input.route(key, &mut agent);
            assert!(input.minimized);
            assert!(agent.is_empty());
        }
    }

    #[test]
    fn reload_shortcut_and_click_only_apply_an_available_update() {
        for key in [b"\x1b\x12".as_slice(), b"\x1b[114;7u", b"\x1b[27;7;114~"] {
            let mut input = Input::new();
            let mut agent = Vec::new();
            input.route(key, &mut agent);
            assert_eq!(agent, key);
            assert!(!input.reload_policy);
            agent.clear();
            input.reload_available = true;
            for byte in key {
                input.route(&[*byte], &mut agent);
            }
            assert!(std::mem::take(&mut input.reload_policy));
            input.route(b"\x1b[114;7:2u\x1b[114;7:3u", &mut agent);
            assert!(!input.reload_policy);
            assert!(agent.is_empty());
        }
        let mut banner = crate::run::banner::Banner::new("test", "profile.toml", "policy.dw");
        banner.policy.pending = true;
        let (_, heading) = banner.view(120, true).heading.unwrap();
        let column = heading.reload.start + 1;
        let mut input = Input::new();
        input.controls = Some((20, heading));
        input.reload_available = true;
        let mut agent = Vec::new();
        input.route(format!("\x1b[<0;{column};20M").as_bytes(), &mut agent);
        assert!(input.reload_policy);
        assert!(!input.toggle_policy);
        assert!(agent.is_empty());
    }

    #[test]
    fn policy_shortcut_toggles_and_ignores_repeats_and_releases() {
        for key in [b"\x1c".as_slice(), b"\x1b[92;5u", b"\x1b[27;5;92~"] {
            let mut input = Input::new();
            let mut agent = Vec::new();
            for byte in key {
                input.route(&[*byte], &mut agent);
            }
            assert!(input.toggle_policy);
            for event in [b"\x1b[92;5:2u", b"\x1b[92;5:3u"] {
                input.route(event, &mut agent);
                assert!(input.toggle_policy);
            }
            input.enabled = false;
            input.route(key, &mut agent);
            assert!(!input.toggle_policy);
            input.route(&[key, key].concat(), &mut agent);
            assert!(!input.toggle_policy);
            assert!(input.minimized);
            assert!(agent.is_empty());
        }
    }

    #[test]
    fn clicking_the_policy_control_toggles_without_activating_other_footer_items() {
        for minimized in [true, false] {
            let banner =
                crate::run::banner::Banner::new("claude-8e099ce7", "box.toml", "policy.dw");
            let (_, heading) = banner.view(80, minimized).heading.unwrap();
            let policy_column = heading.policy.start + 1;
            let minimize_column = heading.minimize.start + 1;
            let mut input = Input::new();
            input.native_rows = 18;
            input.minimized = minimized;
            input.controls = Some((20, heading));
            let mut agent = Vec::new();
            input.enabled = false;
            for column in [policy_column, minimize_column] {
                input.route(
                    format!("\x1b[<0;{column};20M\x1b[<0;{column};20m").as_bytes(),
                    &mut agent,
                );
            }
            assert!(!input.toggle_policy);
            assert_eq!(input.minimized, minimized);
            input.enabled = true;
            for column in [1, 3] {
                input.route(
                    format!("\x1b[<0;{column};20M\x1b[<0;{column};20m").as_bytes(),
                    &mut agent,
                );
            }
            assert!(!input.toggle_policy);
            input.route(
                format!("\x1b[<35;{policy_column};20M\x1b[<0;{policy_column};20M").as_bytes(),
                &mut agent,
            );
            assert!(input.toggle_policy);
            input.route(
                format!("\x1b[<32;{policy_column};20M\x1b[<0;{policy_column};20m").as_bytes(),
                &mut agent,
            );
            assert!(input.toggle_policy);
            assert_eq!(input.minimized, minimized);
            input.route(
                format!("\x1b[<0;{minimize_column};20M\x1b[<0;{minimize_column};20m").as_bytes(),
                &mut agent,
            );
            assert_eq!(input.minimized, !minimized);
            assert!(input.toggle_policy);
            input.route(
                format!("\x1b[<0;{policy_column};20M\x1b[<0;{policy_column};20m").as_bytes(),
                &mut agent,
            );
            assert!(!input.toggle_policy);
            assert_eq!(input.navigation, 0);
            assert!(agent.is_empty());
        }
    }

    #[test]
    fn fragmented_paste_never_activates_controls() {
        for agent_paste in [false, true] {
            let mut input = Input::new();
            input.agent_paste = agent_paste;
            input.reload_available = true;
            input.native_rows = 17;
            input.controls = Some((
                20,
                Heading {
                    line: String::new(),
                    minimize: 0..0,
                    activity: 52..75,
                    policy: 0..6,
                    reload: 7..22,
                    message: 0..0,
                    policy_notice: false,
                },
            ));
            let mut agent = Vec::new();
            let pasted = b"\x1b[200~text\x1b\x12\x1b[114;7u\x1d\x1c\x1b[93;5u\x1b[92;5u\x1b[27;5;93~\x1b[27;5;92~\x1b[<0;60;20M\x1b[201~";
            for byte in pasted {
                input.route(&[*byte], &mut agent);
                assert!(input.minimized);
            }
            assert_eq!(input.navigation, 0);
            assert!(!input.toggle_policy);
            assert!(!input.reload_policy);
            assert_eq!(
                agent,
                if agent_paste {
                    pasted.as_slice()
                } else {
                    &pasted[6..pasted.len() - 6]
                }
            );
        }
    }

    #[test]
    fn ordinary_escape_and_control_sequences_pass_through() {
        for keys in [
            b"\x1b[A\x1b[B\x1b[C\x1b[D\x1b[5~\x1b[6~\x1b[1;1:2B\x1b[6;1:3~\x1bOP\x1bx\x03\x07\rhello\\\x1b[112u\x1b[93;1u\x1b[92;1u".as_slice(),
            b"\x1bOR\x1b[1;2R\x1b[12;34R\x1b[?12;34R\x1b[6;20;10t",
            b"\x12\x1b[114;5u",
        ] {
            let mut input = Input::new();
            input.reload_available = true;
            let mut agent = Vec::new();
            for byte in keys {
                input.route(&[*byte], &mut agent);
            }
            assert_eq!(agent, keys);
            assert!(input.minimized);
        }
    }

    #[test]
    fn disabled_banner_forwards_its_shortcut_to_the_agent() {
        let mut input = Input::new();
        input.enabled = false;
        let mut agent = Vec::new();
        let keys = b"\x1d\x1b[93;5u\x1b[93;5:2u\x1b[93;5:3u\x1b[27;5;93~";
        input.route(keys, &mut agent);
        assert_eq!(agent, keys);
    }

    #[test]
    fn a_paste_keeps_its_initial_framing_when_the_agent_changes_modes() {
        let mut input = Input::new();
        input.agent_paste = true;
        let mut agent = Vec::new();
        input.route(b"\x1b[200~first", &mut agent);
        input.agent_paste = false;
        input.route(b"second\x1b[201~", &mut agent);
        assert_eq!(agent, b"\x1b[200~firstsecond\x1b[201~");
    }

    #[test]
    fn incomplete_sequences_release_control_c_after_the_sequence_window() {
        for prefix in [
            b"\x1b".as_slice(),
            b"\x1b[",
            b"\x1b]title",
            b"\x1b[1;",
            b"\x1b[<0;",
        ] {
            let mut input = Input::new();
            let mut agent = Vec::new();
            input.route(prefix, &mut agent);
            input.escape_at = Some(Instant::now() - Duration::from_millis(100));
            input.flush_escape(&mut agent);
            assert_eq!(agent, prefix);
            input.route(b"\x03", &mut agent);
            assert_eq!(agent, [prefix, b"\x03"].concat());
        }
    }

    #[test]
    fn an_expired_paste_start_is_forwarded_as_raw_input() {
        let mut input = Input::new();
        let mut agent = Vec::new();
        input.route(b"\x1b[200", &mut agent);
        input.escape_at = Some(Instant::now() - Duration::from_millis(100));
        input.flush_escape(&mut agent);
        input.route(b"~\x1d", &mut agent);
        assert_eq!(agent, b"\x1b[200~");
        assert!(!input.minimized);
    }

    #[test]
    fn recognized_paste_does_not_expire() {
        let mut input = Input::new();
        input.agent_paste = true;
        let mut agent = Vec::new();
        input.route(b"\x1b[200", &mut agent);
        input.route(b"~first\x1b[20", &mut agent);
        std::thread::sleep(Duration::from_millis(60));
        input.flush_escape(&mut agent);
        input.route(b"1~\x1d", &mut agent);
        assert_eq!(agent, b"\x1b[200~first\x1b[201~");
        assert!(!input.minimized);
    }

    #[test]
    fn queued_and_fragmented_mouse_reports_use_the_current_agent_encoding() {
        let report = b"\x1b[<0;128;1M";
        for (before, after, expected) in [
            ((1000, 1005), (1000, 0), b"\x1b[M \xa0!".as_slice()),
            ((1000, 0), (1000, 1005), b"\x1b[M \xc2\xa0!"),
            ((1000, 1005), (0, 1005), b""),
            ((0, 1005), (1000, 1005), b"\x1b[M \xc2\xa0!"),
            ((0, 0), (1000, 1006), report),
            ((1000, 1006), (1000, 0), b"\x1b[M \xa0!"),
        ] {
            for split in 0..report.len() {
                let mut input = Input::new();
                input.native_rows = 24;
                input.mouse = Mouse {
                    tracking: before.0,
                    format: before.1,
                };
                let mut agent = Vec::new();
                input.route(&report[..split], &mut agent);
                input.mouse = Mouse {
                    tracking: after.0,
                    format: after.1,
                };
                input.route(&report[split..], &mut agent);
                input.route(b"x", &mut agent);
                assert_eq!(
                    agent,
                    [expected, b"x"].concat(),
                    "{before:?} -> {after:?}, split {split}"
                );
            }
        }
    }

    #[test]
    fn pasted_escape_sequences_cannot_swallow_the_end_marker() {
        for text in [b"text\x1b".as_slice(), b"\x1b]", b"\x1b[", b"\x1b[201"] {
            let mut input = Input::new();
            let mut agent = Vec::new();
            let pasted = [b"\x1b[200~", text, b"\x1b[201~"].concat();
            for byte in pasted {
                input.route(&[byte], &mut agent);
            }
            assert_eq!(agent, text);
            input.route(b"\x1d", &mut Vec::new());
            assert!(!input.minimized);
        }
    }
}
