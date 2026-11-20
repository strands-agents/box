use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionRange, SelectionType};
use alacritty_terminal::term::cell::{Cell, Flags, Hyperlink, LineLength};
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::{ClipboardType, Config, MIN_COLUMNS, Osc52, TermDamage, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, Processor};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::mouse::Click;

pub(super) struct Emulator {
    terminal: Term<Events>,
    parser: Processor,
    events: Receiver<Event>,
    size: Size,
    osc: Osc,
    full_redraw: bool,
    drawn_selection: Option<SelectionRange>,
}

#[derive(Clone, Copy)]
struct Size {
    rows: u16,
    columns: u16,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        usize::from(self.rows)
    }

    fn screen_lines(&self) -> usize {
        usize::from(self.rows)
    }

    fn columns(&self) -> usize {
        usize::from(self.columns)
    }
}

struct Events(Sender<Event>);

impl EventListener for Events {
    fn send_event(&self, event: Event) {
        if matches!(
            event,
            Event::PtyWrite(_)
                | Event::ColorRequest(..)
                | Event::TextAreaSizeRequest(_)
                | Event::ClipboardStore(..)
        ) {
            let _ = self.0.send(event);
        }
    }
}

impl Emulator {
    pub(super) fn new(rows: u16, columns: u16) -> Self {
        let size = Size {
            rows: rows.max(1),
            columns: columns.max(MIN_COLUMNS as u16),
        };
        let (sender, events) = mpsc::channel();
        let config = Config {
            kitty_keyboard: false,
            osc52: Osc52::OnlyCopy,
            scrolling_history: 1000,
            ..Config::default()
        };
        Self {
            terminal: Term::new(config, &size, Events(sender)),
            parser: Processor::new(),
            events,
            size,
            osc: Osc::Ground,
            full_redraw: true,
            drawn_selection: None,
        }
    }

    pub(super) fn process(&mut self, bytes: &[u8]) -> bool {
        let expired = self
            .parser
            .sync_timeout()
            .sync_timeout()
            .is_some_and(|deadline| deadline <= Instant::now());
        if expired {
            self.parser.stop_sync(&mut self.terminal);
        }
        if bytes.is_empty() && !expired {
            return false;
        }
        let bounded = self.osc.process(bytes);
        self.parser.advance(&mut self.terminal, &bounded);
        true
    }

    pub(super) fn finish_output(&mut self) -> bool {
        self.osc = Osc::Ground;
        let changed = self.parser.sync_bytes_count() != 0;
        self.parser.stop_sync(&mut self.terminal);
        changed
    }

    pub(super) fn resize(&mut self, rows: u16, columns: u16) {
        self.full_redraw = true;
        self.size = Size {
            rows: rows.max(1),
            columns: columns.max(MIN_COLUMNS as u16),
        };
        self.terminal.resize(self.size);
    }

    pub(super) fn take_replies(&mut self, output: &mut Vec<u8>) -> Vec<u8> {
        let mut replies = Vec::new();
        for event in self.events.try_iter() {
            let reply = match event {
                Event::PtyWrite(reply) => reply,
                Event::ClipboardStore(clipboard, text) => {
                    if text
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\t' | '\n'))
                    {
                        continue;
                    }
                    copy_to_clipboard(output, clipboard, &text);
                    continue;
                }
                Event::ColorRequest(index, format) => {
                    if let Some(color) = self.terminal.renderable_content().colors[index] {
                        format(color)
                    } else {
                        let query = match index {
                            0..=255 => format!("\x1b]4;{index};?\x07"),
                            256..=258 => format!("\x1b]{};?\x07", index - 246),
                            _ => continue,
                        };
                        output.extend_from_slice(query.as_bytes());
                        continue;
                    }
                }
                Event::TextAreaSizeRequest(format) => format(WindowSize {
                    num_lines: self.size.rows,
                    num_cols: self.size.columns,
                    cell_width: 0,
                    cell_height: 0,
                }),
                _ => continue,
            };
            replies.extend_from_slice(reply.as_bytes());
        }
        replies
    }

    pub(super) fn mode(&self) -> TermMode {
        *self.terminal.mode()
    }

    pub(super) fn has_content(&self) -> bool {
        self.terminal
            .renderable_content()
            .display_iter
            .any(|cell| !cell.c.is_whitespace())
    }

    pub(super) fn write_primary(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        if self.mode().contains(TermMode::ALT_SCREEN) {
            self.terminal.swap_alt();
        }
        let grid = self.terminal.grid();
        let first = -(grid.history_size() as i32);
        let Some(last) =
            (first..i32::from(self.size.rows)).rfind(|&line| grid[Line(line)].line_length().0 != 0)
        else {
            return Ok(());
        };
        output.extend_from_slice(b"\r");
        let colors = self.terminal.renderable_content().colors;
        let mut style = None;
        let mut hyperlink = None;
        for line in first..=last {
            let row = &grid[Line(line)];
            for column in 0..row.line_length().0 {
                let cell = &row[Column(column)];
                if cell
                    .flags
                    .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
                {
                    continue;
                }
                write_cell(
                    output,
                    cell,
                    Style::new(cell, colors),
                    &mut style,
                    &mut hyperlink,
                )?;
            }
            if line == last
                || !row[Column(usize::from(self.size.columns - 1))]
                    .flags
                    .contains(Flags::WRAPLINE)
            {
                output.extend_from_slice(b"\x1b]8;;\x1b\\\x1b[0m\r\n");
                style = None;
                hyperlink = None;
            }
        }
        Ok(())
    }

    pub(super) fn clear_selection(&mut self) -> bool {
        self.terminal.selection.take().is_some()
    }

    pub(super) fn scroll(&mut self, scroll: Scroll) -> bool {
        let before = self.terminal.grid().display_offset();
        self.terminal.scroll_display(scroll);
        self.terminal.grid().display_offset() != before
    }

    pub(super) fn select(&mut self, click: Click) -> Option<String> {
        let mut point = Point::new(
            Line(
                click
                    .row
                    .saturating_sub(1)
                    .min(u32::from(self.size.rows - 1)) as i32,
            ),
            Column(
                click
                    .column
                    .saturating_sub(1)
                    .min(u32::from(self.size.columns - 1)) as usize,
            ),
        );
        point.line -= self.terminal.grid().display_offset();
        if click.left_press() {
            self.terminal.selection =
                Some(Selection::new(SelectionType::Simple, point, Side::Left));
        } else if let Some(selection) = &mut self.terminal.selection {
            let started = !selection.is_empty();
            selection.update(point, Side::Left);
            if started || !selection.is_empty() {
                selection.include_all();
            }
        }
        click
            .release
            .then(|| self.terminal.selection_to_string())
            .flatten()
            .filter(|text| !text.is_empty())
    }

    pub(super) fn render(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        output.write_all(b"\x1b[?25l\x1b[?6l\x1b[r\x1b[4l\x1b[?7l\x1b(B\x1b[0m\x1b]8;;\x1b\\")?;
        let selection = self.terminal.renderable_content().selection;
        let rows: Vec<u16> = if self.full_redraw || selection != self.drawn_selection {
            (0..self.size.rows).collect()
        } else {
            match self.terminal.damage() {
                TermDamage::Full => (0..self.size.rows).collect(),
                TermDamage::Partial(rows) => rows.map(|row| row.line as u16).collect(),
            }
        };
        let content = self.terminal.renderable_content();
        let mut style = None;
        let mut hyperlink: Option<Hyperlink> = None;
        for row in rows {
            let line = Line(i32::from(row)) - content.display_offset;
            let mut position = true;
            for column in 0..self.size.columns {
                let cell = &self.terminal.grid()[line][Column(usize::from(column))];
                if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    continue;
                }
                if position {
                    write!(output, "\x1b[{};{}H", row + 1, column + 1)?;
                }
                let mut next_style = Style::new(cell, content.colors);
                if content.selection.is_some_and(|range| {
                    let point = Point::new(line, Column(usize::from(column)));
                    range.contains(point)
                        || (cell.flags.contains(Flags::WIDE_CHAR)
                            && range.contains(Point::new(point.line, point.column + 1)))
                }) {
                    next_style.flags.toggle(Flags::INVERSE);
                }
                let character = write_cell(output, cell, next_style, &mut style, &mut hyperlink)?;
                position = !character.is_ascii()
                    || cell.zerowidth().is_some_and(|chars| !chars.is_empty());
            }
        }
        output.write_all(b"\x1b]8;;\x1b\\\x1b[0m")?;
        self.restore_cursor(output)?;
        self.full_redraw = false;
        self.drawn_selection = selection;
        self.terminal.reset_damage();
        Ok(())
    }

    pub(super) fn restore_cursor(&self, output: &mut impl Write) -> io::Result<()> {
        let cursor = self.terminal.renderable_content().cursor;
        let row = cursor.point.line.0.clamp(0, i32::from(self.size.rows) - 1) + 1;
        let column = cursor
            .point
            .column
            .0
            .min(usize::from(self.size.columns) - 1)
            + 1;
        output.write_all(b"\x1b[?6l\x1b[?7h\x1b[0m")?;
        write!(output, "\x1b[{row};{column}H")?;
        if cursor.shape == CursorShape::Hidden || self.terminal.grid().display_offset() != 0 {
            return output.write_all(b"\x1b[?25l");
        }
        let blink = self.terminal.cursor_style().blinking;
        let shape = match cursor.shape {
            CursorShape::Underline => 4,
            CursorShape::Beam => 6,
            _ => 2,
        } - u8::from(blink);
        write!(output, "\x1b[{shape} q\x1b[?25h")
    }
}

fn write_cell(
    output: &mut Vec<u8>,
    cell: &Cell,
    next_style: Style,
    style: &mut Option<Style>,
    hyperlink: &mut Option<Hyperlink>,
) -> io::Result<char> {
    if *style != Some(next_style) {
        next_style.write(output)?;
        *style = Some(next_style);
    }
    let next_hyperlink = cell.hyperlink();
    if *hyperlink != next_hyperlink {
        output.extend_from_slice(b"\x1b]8;;\x1b\\");
        if let Some(link) = &next_hyperlink {
            let id: String = link.id().chars().filter(|c| !c.is_control()).collect();
            let uri: String = link.uri().chars().filter(|c| !c.is_control()).collect();
            write!(output, "\x1b]8;id={id};{uri}\x1b\\")?;
        }
        *hyperlink = next_hyperlink;
    }
    let character = if cell.c.is_control() || cell.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
        ' '
    } else {
        cell.c
    };
    write!(output, "{character}")?;
    for character in cell.zerowidth().into_iter().flatten() {
        if !character.is_control() {
            write!(output, "{character}")?;
        }
    }
    Ok(character)
}

pub(super) fn copy_to_clipboard(output: &mut Vec<u8>, clipboard: ClipboardType, text: &str) {
    let target = match clipboard {
        ClipboardType::Clipboard => 'c',
        ClipboardType::Selection => 'p',
    };
    let encoded = STANDARD.encode(text);
    output.extend_from_slice(format!("\x1b]52;{target};{encoded}\x07").as_bytes());
}

#[derive(Default)]
pub(super) enum Osc {
    #[default]
    Ground,
    Escape,
    Collect(Vec<u8>),
    Ending(Vec<u8>),
    Discard,
    DiscardEnding,
}

impl Osc {
    pub(super) fn process(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut bounded = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            self.push(byte, &mut bounded);
        }
        bounded
    }

    fn push(&mut self, byte: u8, output: &mut Vec<u8>) {
        const LIMIT: usize = 64 * 1024;
        *self = match std::mem::take(self) {
            Self::Ground if byte == 0x1b => Self::Escape,
            Self::Ground => {
                output.push(byte);
                Self::Ground
            }
            Self::Escape => Self::after_escape(byte, output),
            Self::Collect(mut bytes) => match byte {
                0x07 => {
                    bytes.push(byte);
                    output.extend(bytes);
                    Self::Ground
                }
                0x18 | 0x1a => {
                    output.push(byte);
                    Self::Ground
                }
                0x1b => Self::Ending(bytes),
                _ if bytes.len() >= LIMIT - 2 => Self::Discard,
                _ => {
                    bytes.push(byte);
                    Self::Collect(bytes)
                }
            },
            Self::Ending(mut bytes) if byte == b'\\' => {
                bytes.extend_from_slice(b"\x1b\\");
                output.extend(bytes);
                Self::Ground
            }
            Self::Ending(_) => Self::after_escape(byte, output),
            Self::Discard => match byte {
                0x07 => Self::Ground,
                0x18 | 0x1a => {
                    output.push(byte);
                    Self::Ground
                }
                0x1b => Self::DiscardEnding,
                _ => Self::Discard,
            },
            Self::DiscardEnding if byte == b'\\' => Self::Ground,
            Self::DiscardEnding => Self::after_escape(byte, output),
        };
    }

    fn after_escape(byte: u8, output: &mut Vec<u8>) -> Self {
        if byte == b']' {
            // The withheld OSC must still end any preceding control string.
            output.push(0x18);
            return Self::Collect(b"\x1b]".to_vec());
        }
        output.push(0x1b);
        if byte == 0x1b {
            Self::Escape
        } else {
            output.push(byte);
            Self::Ground
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Style {
    foreground: Color,
    background: Color,
    underline: Option<Color>,
    flags: Flags,
}

impl Style {
    fn new(cell: &Cell, colors: &Colors) -> Self {
        Self {
            foreground: resolve(colors, cell.fg),
            background: resolve(colors, cell.bg),
            underline: cell.underline_color().map(|color| resolve(colors, color)),
            flags: cell.flags
                & (Flags::BOLD
                    | Flags::DIM
                    | Flags::ITALIC
                    | Flags::ALL_UNDERLINES
                    | Flags::INVERSE
                    | Flags::HIDDEN
                    | Flags::STRIKEOUT),
        }
    }

    fn write(&self, output: &mut impl Write) -> io::Result<()> {
        output.write_all(b"\x1b[0m")?;
        write_color(output, self.foreground, 38)?;
        write_color(output, self.background, 48)?;
        for (flag, code) in [
            (Flags::BOLD, 1),
            (Flags::DIM, 2),
            (Flags::ITALIC, 3),
            (Flags::INVERSE, 7),
            (Flags::HIDDEN, 8),
            (Flags::STRIKEOUT, 9),
        ] {
            if self.flags.contains(flag) {
                write!(output, "\x1b[{code}m")?;
            }
        }
        let underline = if self.flags.contains(Flags::UNDERCURL) {
            Some("4:3")
        } else if self.flags.contains(Flags::DOTTED_UNDERLINE) {
            Some("4:4")
        } else if self.flags.contains(Flags::DASHED_UNDERLINE) {
            Some("4:5")
        } else if self.flags.contains(Flags::DOUBLE_UNDERLINE) {
            Some("4:2")
        } else if self.flags.contains(Flags::UNDERLINE) {
            Some("4")
        } else {
            None
        };
        if let Some(code) = underline {
            write!(output, "\x1b[{code}m")?;
        }
        if let Some(color) = self.underline {
            write_color(output, color, 58)?;
        }
        Ok(())
    }
}

fn resolve(colors: &Colors, color: Color) -> Color {
    let index = match color {
        Color::Spec(_) => return color,
        Color::Named(name) => name as usize,
        Color::Indexed(index) => usize::from(index),
    };
    colors[index].map_or(color, Color::Spec)
}

fn write_color(output: &mut impl Write, color: Color, prefix: u16) -> io::Result<()> {
    match color {
        Color::Spec(rgb) => {
            write!(output, "\x1b[{prefix};2;{};{};{}m", rgb.r, rgb.g, rgb.b)
        }
        Color::Indexed(index) => write!(output, "\x1b[{prefix};5;{index}m"),
        Color::Named(name) => {
            let code = match name as u16 {
                index @ 0..=7 => prefix - 8 + index,
                index @ 8..=15 => prefix + 44 + index,
                _ => prefix + 1,
            };
            write!(output, "\x1b[{code}m")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(emulator: &mut Emulator) -> (vt100::Parser, Vec<u8>) {
        let mut frame = Vec::new();
        emulator.render(&mut frame).unwrap();
        let mut terminal = vt100::Parser::new(emulator.size.rows, emulator.size.columns, 0);
        terminal.process(&frame);
        (terminal, frame)
    }

    fn text(terminal: &vt100::Parser) -> String {
        terminal
            .screen()
            .contents()
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_owned()
    }

    #[test]
    fn primary_output_survives_history_wrapping_and_an_unclosed_alternate_screen() {
        let mut emulator = Emulator::new(3, 8);
        emulator.process("first\r\n1234567界e\u{301}\r\n\x1b[31mFINAL\x1b[0m".as_bytes());
        emulator.process(b"\x1b[?1049hPRIVATE UI");
        let mut output = Vec::new();
        emulator.write_primary(&mut output).unwrap();
        let mut host = vt100::Parser::new(12, 20, 100);
        host.process(&output);
        host.process(b"$ ");
        assert_eq!(text(&host), "first\n1234567界e\u{301}\nFINAL\n$");
        assert_eq!(
            host.screen().cell(2, 0).unwrap().fgcolor(),
            vt100::Color::Idx(1)
        );
        assert_eq!(
            host.screen().cell(3, 0).unwrap().fgcolor(),
            vt100::Color::Default
        );
    }

    #[test]
    fn cleanup_resets_origin_and_margins_without_moving_the_primary_cursor() {
        for (bytes, cursor) in [
            (b"\x1b[2;6r\x1b[?6h\x1b[2;5HX".as_slice(), (2, 5)),
            (b"BEFORE\r\n\x1b[?1049h\x1b[2;6r\x1b[?6h\x1b[2;5HX", (1, 0)),
        ] {
            let mut host = Emulator::new(10, 40);
            let mut state = super::super::native::OutputState::default();
            host.process(bytes);
            state.process(bytes);
            let mut cleanup = Vec::new();
            super::super::restore_screen(&mut cleanup, state.alternate()).unwrap();
            host.process(&cleanup);
            assert_eq!(
                host.terminal.grid().cursor.point,
                alacritty_terminal::index::Point::new(Line(cursor.0), Column(cursor.1)),
            );
            assert!(
                !host
                    .mode()
                    .intersects(TermMode::ORIGIN | TermMode::ALT_SCREEN)
            );
            let history = host.terminal.grid().history_size();
            host.process(b"\x1b[10;1H\r\n");
            assert_eq!(host.terminal.grid().history_size(), history + 1);
        }
    }

    #[test]
    fn clipboard_stores_reject_controls_and_preserve_text() {
        for target in ['c', 'p'] {
            let mut emulator = Emulator::new(3, 20);
            for code in (0..=0x1f).chain(0x7f..=0x9f) {
                let character = char::from_u32(code).unwrap();
                if matches!(character, '\t' | '\n') {
                    continue;
                }
                let encoded = STANDARD.encode(format!("before{character}after"));
                for byte in format!("\x1b]52;{target};{encoded}\x07").bytes() {
                    emulator.process(&[byte]);
                }
                let mut output = Vec::new();
                assert!(emulator.take_replies(&mut output).is_empty());
                assert!(output.is_empty(), "clipboard {target}, U+{code:04X}");
            }
            for text in ["", "hello", "界 café 👋\n\tsecond line"] {
                let encoded = STANDARD.encode(text);
                let request = format!("\x1b]52;{target};{encoded}\x07");
                emulator.process(request.as_bytes());
                let mut output = Vec::new();
                assert!(emulator.take_replies(&mut output).is_empty());
                assert_eq!(output, request.as_bytes());
            }
        }
    }

    #[test]
    fn startup_ignores_clear_queries_and_buffered_output() {
        let mut emulator = Emulator::new(3, 20);
        emulator.process(b"\x1b[2J\x1b[6n\x1b[?25l   ");
        assert!(!emulator.has_content());
        emulator.process(b"\x1b[?2026hREADY");
        assert!(!emulator.has_content());
        emulator.process(b"\x1b[?2026l");
        assert!(emulator.has_content());
    }

    #[test]
    fn drag_highlights_and_copies_wrapped_unicode_in_either_direction() {
        for (start, end) in [((2, 1), (1, 2)), ((1, 2), (2, 1))] {
            let mut emulator = Emulator::new(3, 8);
            emulator.process("abc界e\u{301}fgh".as_bytes());
            for (button, (column, row)) in [(0, start), (32, end)] {
                emulator.select(
                    Click::parse(format!("\x1b[<{button};{column};{row}M").as_bytes()).unwrap(),
                );
            }
            let (host, _) = rendered(&mut emulator);
            assert!(host.screen().cell(0, 3).unwrap().inverse());
            let (column, row) = end;
            assert_eq!(
                emulator
                    .select(Click::parse(format!("\x1b[<0;{column};{row}m").as_bytes()).unwrap())
                    .as_deref(),
                Some("bc界e\u{301}fgh"),
            );
        }
    }

    #[test]
    fn adjacent_drag_endpoints_match_the_copied_text() {
        let mut emulator = Emulator::new(2, 8);
        emulator.process(b"abc");
        emulator.select(Click::parse(b"\x1b[<0;2;1M").unwrap());
        for end in [1, 3, 1] {
            emulator.select(Click::parse(format!("\x1b[<32;{end};1M").as_bytes()).unwrap());
            let (host, _) = rendered(&mut emulator);
            for column in 0..3 {
                assert_eq!(
                    host.screen().cell(0, column).unwrap().inverse(),
                    (end.min(2)..=end.max(2)).contains(&(column + 1)),
                    "drag from b to column {end}, cell {column}",
                );
            }
            assert_eq!(
                emulator.terminal.selection_to_string().as_deref(),
                Some(if end == 1 { "ab" } else { "bc" }),
            );
        }
        assert_eq!(
            emulator
                .select(Click::parse(b"\x1b[<0;1;1m").unwrap())
                .as_deref(),
            Some("ab"),
        );
        emulator.select(Click::parse(b"\x1b[<0;2;1M").unwrap());
        emulator.select(Click::parse(b"\x1b[<32;2;1M").unwrap());
        assert!(
            emulator
                .select(Click::parse(b"\x1b[<0;2;1m").unwrap())
                .is_none()
        );
        emulator.select(Click::parse(b"\x1b[<0;2;1M").unwrap());
        assert_eq!(
            emulator
                .select(Click::parse(b"\x1b[<0;1;1m").unwrap())
                .as_deref(),
            Some("ab"),
        );
    }

    #[test]
    fn clearing_a_selected_line_removes_the_whole_highlight() {
        let mut emulator = Emulator::new(5, 8);
        emulator.process(b"one\r\ntwo\r\nthree\r\nfour\r\nfive");
        emulator.select(Click::parse(b"\x1b[<0;1;1M").unwrap());
        emulator.select(Click::parse(b"\x1b[<0;4;5m").unwrap());
        let (mut host, _) = rendered(&mut emulator);
        for row in 0..5 {
            assert!(host.screen().cell(row, 0).unwrap().inverse());
        }
        emulator.process(b"\x1b[3;1H\x1b[2K");
        assert!(emulator.terminal.selection.is_none());
        let mut frame = Vec::new();
        emulator.render(&mut frame).unwrap();
        host.process(&frame);
        for row in 0..5 {
            for column in 0..8 {
                assert!(
                    !host.screen().cell(row, column).unwrap().inverse(),
                    "cell {row},{column}"
                );
            }
        }
    }

    #[test]
    fn scrolled_output_stays_visible_and_selectable_until_returning_to_the_bottom() {
        let mut emulator = Emulator::new(4, 20);
        for line in 1..=12 {
            emulator.process(format!("line {line:02} café\r\n").as_bytes());
        }
        assert!(emulator.scroll(Scroll::Delta(6)));
        let (mut host, _) = rendered(&mut emulator);
        let history = text(&host);
        assert!(history.starts_with("line 04 café"), "{history}");
        assert!(host.screen().hide_cursor());
        emulator.process("line 13 café\r\n".as_bytes());
        let mut frame = Vec::new();
        emulator.render(&mut frame).unwrap();
        host.process(&frame);
        assert_eq!(text(&host), history, "new output moved the scrolled view");
        emulator.select(Click::parse(b"\x1b[<0;1;1M").unwrap());
        assert_eq!(
            emulator
                .select(Click::parse(b"\x1b[<0;12;1m").unwrap())
                .as_deref(),
            Some("line 04 café")
        );
        let (host, _) = rendered(&mut emulator);
        assert!(host.screen().cell(0, 0).unwrap().inverse());
        assert!(emulator.scroll(Scroll::Bottom));
        let (host, _) = rendered(&mut emulator);
        assert!(text(&host).contains("line 13 café"));
        assert!(!host.screen().hide_cursor());
    }

    #[test]
    fn default_colors_follow_the_host_and_explicit_colors_survive() {
        let mut emulator = Emulator::new(2, 20);
        emulator.process(
            b"A\x1b[38;2;1;2;3;48;2;4;5;6mB\x1b[0mC\x1b[31;104mD\
              \x1b[38;5;123;48;5;234mE",
        );
        let (terminal, _) = rendered(&mut emulator);
        for column in [0, 2, 19] {
            let cell = terminal.screen().cell(0, column).unwrap();
            assert_eq!(cell.fgcolor(), vt100::Color::Default);
            assert_eq!(cell.bgcolor(), vt100::Color::Default);
        }
        let explicit = terminal.screen().cell(0, 1).unwrap();
        assert_eq!(explicit.fgcolor(), vt100::Color::Rgb(1, 2, 3));
        assert_eq!(explicit.bgcolor(), vt100::Color::Rgb(4, 5, 6));
        let named = terminal.screen().cell(0, 3).unwrap();
        assert_eq!(named.fgcolor(), vt100::Color::Idx(1));
        assert_eq!(named.bgcolor(), vt100::Color::Idx(12));
        let indexed = terminal.screen().cell(0, 4).unwrap();
        assert_eq!(indexed.fgcolor(), vt100::Color::Idx(123));
        assert_eq!(indexed.bgcolor(), vt100::Color::Idx(234));

        emulator.process(
            b"\x1b]10;rgb:12/34/56\x07\x1b]11;rgb:65/43/21\x07\
              \x1b]4;1;rgb:ab/cd/ef\x07",
        );
        let (overridden, _) = rendered(&mut emulator);
        let cell = overridden.screen().cell(0, 0).unwrap();
        assert_eq!(cell.fgcolor(), vt100::Color::Rgb(0x12, 0x34, 0x56));
        assert_eq!(cell.bgcolor(), vt100::Color::Rgb(0x65, 0x43, 0x21));
        assert_eq!(
            overridden.screen().cell(0, 3).unwrap().fgcolor(),
            vt100::Color::Rgb(0xab, 0xcd, 0xef),
        );

        emulator.process(b"\x1b]110\x07\x1b]111\x07\x1b]104;1\x07");
        let (reset, _) = rendered(&mut emulator);
        let cell = reset.screen().cell(0, 0).unwrap();
        assert_eq!(cell.fgcolor(), vt100::Color::Default);
        assert_eq!(cell.bgcolor(), vt100::Color::Default);
        assert_eq!(
            reset.screen().cell(0, 3).unwrap().fgcolor(),
            vt100::Color::Idx(1),
        );
    }

    #[test]
    fn color_queries_use_the_host_unless_the_agent_overrides_them() {
        let mut emulator = Emulator::new(2, 20);
        let mut output = Vec::new();
        emulator.process(b"\x1b]4;1;?\x07\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07");
        assert!(emulator.take_replies(&mut output).is_empty());
        assert_eq!(
            output,
            b"\x1b]4;1;?\x07\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07"
        );

        output.clear();
        emulator.process(b"\x1b]11;rgb:12/34/56\x07\x1b]11;?\x07\x1b[6n");
        assert_eq!(
            emulator.take_replies(&mut output),
            b"\x1b]11;rgb:1212/3434/5656\x07\x1b[1;1R",
        );
        assert!(output.is_empty());

        emulator.process(b"\x1b]111\x07\x1b]11;?\x1b\\");
        assert!(emulator.take_replies(&mut output).is_empty());
        assert_eq!(output, b"\x1b]11;?\x07");
    }

    #[test]
    fn fragmented_controls_and_utf8_keep_the_same_cells_and_replies() {
        let bytes = "ab\x1b7\x1b[2;3H界e\u{301}\x1b8Z\x1b[6n".as_bytes();
        for split in 0..=bytes.len() {
            let mut emulator = Emulator::new(3, 20);
            emulator.process(&bytes[..split]);
            emulator.process(&bytes[split..]);
            assert_eq!(emulator.take_replies(&mut Vec::new()), b"\x1b[1;4R");
            let (terminal, frame) = rendered(&mut emulator);
            assert_eq!(text(&terminal), "abZ\n  界e\u{301}");
            assert_eq!(terminal.screen().cursor_position(), (0, 3));
            assert!(!frame.windows(4).any(|bytes| bytes == b"\x1b[6n"));
        }
    }

    #[test]
    fn alternate_screen_exit_restores_all_primary_rows() {
        let mut emulator = Emulator::new(12, 40);
        emulator.process(b"hello\x1b[7;20HX\x1b[H\x1b[?1049halt");
        let (alternate, _) = rendered(&mut emulator);
        assert_eq!(text(&alternate), "alt");
        emulator.process(b"\x1b[?1049l");
        let (primary, _) = rendered(&mut emulator);
        assert!(primary.screen().contents().starts_with("hello"));
        assert_eq!(primary.screen().cell(6, 19).unwrap().contents(), "X");
    }

    #[test]
    fn resize_updates_window_reports_and_preserves_output() {
        let mut emulator = Emulator::new(12, 40);
        emulator.process(b"first\r\nsecond");
        emulator.resize(3, 8);
        emulator.process(b"\x1b[18t");
        assert_eq!(emulator.take_replies(&mut Vec::new()), b"\x1b[8;3;8t");
        let (terminal, _) = rendered(&mut emulator);
        assert_eq!(text(&terminal), "first\nsecond");
    }

    #[test]
    fn a_one_column_host_keeps_wide_output_safe() {
        let mut emulator = Emulator::new(1, 1);
        emulator.process("界".as_bytes());
        emulator.process(b"\x1b[18t");
        assert_eq!(emulator.take_replies(&mut Vec::new()), b"\x1b[8;1;2t");
        let (terminal, _) = rendered(&mut emulator);
        assert_eq!(terminal.screen().cell(0, 0).unwrap().contents(), "界");
    }

    #[test]
    fn split_osc_terminators_do_not_consume_visible_output() {
        let mut emulator = Emulator::new(3, 20);
        for bytes in [
            b"\x1b]8;id=test;https://example.com\x1b".as_slice(),
            b"\\link\x1b]8;;",
            b"\x1b",
            b"\\",
        ] {
            emulator.process(bytes);
        }
        let (terminal, _) = rendered(&mut emulator);
        assert_eq!(text(&terminal), "link");
    }

    #[test]
    fn oversized_osc_is_discarded_through_its_terminator() {
        for (prefix, terminator) in [
            (b"".as_slice(), b"\x07".as_slice()),
            (b"", b"\x1b\\"),
            (b"\x1bPignored", b"\x07"),
        ] {
            let mut emulator = Emulator::new(3, 20);
            emulator.process(b"before");
            emulator.process(prefix);
            emulator.process(b"\x1b]2;");
            for _ in 0..80 {
                emulator.process(&[b'x'; 1024]);
            }
            emulator.process(terminator);
            emulator.process(b"AFTER");
            let (terminal, _) = rendered(&mut emulator);
            assert_eq!(text(&terminal), "beforeAFTER");
        }
    }

    #[test]
    fn cancelled_and_abandoned_osc_resume_normal_output() {
        for cancellation in [b"\x18".as_slice(), b"\x1a", b"\x1b[1;1H"] {
            let mut emulator = Emulator::new(3, 20);
            emulator.process(b"\x1b]2;unfinished");
            emulator.process(cancellation);
            emulator.process(b"OK");
            let (terminal, _) = rendered(&mut emulator);
            assert_eq!(text(&terminal), "OK");
        }
    }

    #[test]
    fn idle_insert_polls_only_redraw_when_synchronized_output_expires() {
        let mut emulator = Emulator::new(3, 20);
        emulator.process(b"\x1b[4hREADY");
        rendered(&mut emulator);
        assert!(!emulator.process(&[]));
        emulator.process(b"\x1b[?2026hbuffered");
        let (before, _) = rendered(&mut emulator);
        assert_eq!(text(&before), "READY");
        let deadline = emulator.parser.sync_timeout().sync_timeout().unwrap();
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        assert!(emulator.process(&[]));
        let (after, _) = rendered(&mut emulator);
        assert_eq!(text(&after), "READYbuffered");
        assert!(!emulator.process(&[]));
    }

    #[test]
    fn a_late_combining_mark_redraws_after_an_unchanged_frame() {
        for trigger in [b"".as_slice(), b"\x1b[6n"] {
            let mut emulator = Emulator::new(3, 20);
            emulator.process(b"unchanged\r\ne");
            let (mut terminal, _) = rendered(&mut emulator);
            emulator.process(trigger);
            let (_, frame) = rendered(&mut emulator);
            terminal.process(&frame);
            assert!(emulator.process("\u{301}".as_bytes()));
            let (_, frame) = rendered(&mut emulator);
            terminal.process(&frame);
            assert_eq!(text(&terminal), "unchanged\ne\u{301}");
        }
    }

    #[test]
    fn cursor_visibility_comes_from_the_model() {
        let mut emulator = Emulator::new(3, 20);
        emulator.process(b"\x1b[?25l");
        let (hidden, _) = rendered(&mut emulator);
        assert!(hidden.screen().hide_cursor());
        emulator.process(b"\x1b[?25h");
        let (visible, _) = rendered(&mut emulator);
        assert!(!visible.screen().hide_cursor());
    }
}
