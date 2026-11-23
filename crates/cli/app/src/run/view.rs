use std::borrow::Cow;
use std::io::{self, Write};
use std::time::Duration;

use ratatui::backend::Backend;
use ratatui::buffer::{Buffer, CellWidth};
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Widget};
use ratatui_termion::TermionBackend;

use super::banner::{BANNER_ROWS, Banner, Heading, display_width, fit};
use super::history::{ActivityEntry, ActivityView};
use unicode_segmentation::UnicodeSegmentation;

const TEXT: Color = Color::Rgb(228, 232, 235);
const MUTED: Color = Color::Rgb(144, 158, 169);
const BORDER: Color = Color::Rgb(102, 113, 121);
const ACCENT: Color = Color::Rgb(74, 222, 128);
const HOVER: Color = Color::Rgb(255, 255, 255);
const DENIAL: Color = Color::Rgb(104, 52, 46);
const POLICY_ON: Color = Color::Rgb(37, 75, 56);
const POLICY_ON_BADGE: Color = Color::Rgb(47, 115, 74);
const POLICY_RELOADED: Color = Color::Rgb(92, 64, 16);
const POLICY_RELOADED_BADGE: Color = Color::Rgb(245, 183, 45);
const POLICY_OFF: Color = Color::Rgb(128, 45, 37);
const POLICY_OFF_BADGE: Color = Color::Rgb(190, 48, 35);

pub(super) struct Panel {
    pub(super) buffer: Buffer,
    pub(super) heading: Option<(u16, Heading)>,
    pub(super) files: Vec<(Rect, String)>,
}

impl Panel {
    fn new(width: usize, height: u16) -> Self {
        let mut buffer =
            Buffer::empty(Rect::new(0, 0, width.min(u16::MAX as usize) as u16, height));
        if height > 1 {
            Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER))
                .render(
                    Rect {
                        height: buffer.area.height - 1,
                        ..buffer.area
                    },
                    &mut buffer,
                );
        }
        Self {
            buffer,
            heading: None,
            files: Vec::new(),
        }
    }

    fn status(&mut self, banner: &Banner, minimized: bool) {
        let width = self.buffer.area.width;
        if width == 0 {
            return;
        }
        let row = self.buffer.area.height - 1;
        let activity_start =
            (!minimized).then(|| usize::from(section_areas(self.buffer.area)[1].x));
        let heading = banner.heading(usize::from(width), activity_start, minimized);
        let policy_restored =
            heading.policy_notice && banner.policy.enabled && !banner.policy.failed;
        let policy_reloaded = policy_restored && (banner.policy.reloaded || banner.policy.pending);
        let footer_color = if !banner.policy.enabled {
            Some(POLICY_OFF)
        } else if policy_reloaded {
            Some(POLICY_RELOADED)
        } else {
            policy_restored.then_some(POLICY_ON)
        };
        let mut style = Style::default().fg(MUTED);
        if let Some(background) = footer_color {
            style = style.fg(TEXT).bg(background);
        }
        Paragraph::new(heading.line.as_str())
            .style(style)
            .render(Rect::new(0, row, width, 1), &mut self.buffer);
        if !heading.message.is_empty() {
            self.buffer.set_style(
                Rect::new(
                    heading.message.start as u16,
                    row,
                    heading.message.len() as u16,
                    1,
                ),
                Style::default()
                    .fg(if policy_reloaded { Color::Black } else { TEXT })
                    .bg(if policy_reloaded {
                        POLICY_RELOADED_BADGE
                    } else if policy_restored {
                        POLICY_ON_BADGE
                    } else if heading.policy_notice && !banner.policy.enabled {
                        POLICY_OFF_BADGE
                    } else {
                        DENIAL
                    })
                    .add_modifier(if heading.policy_notice {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            );
        }
        if !heading.policy_notice && !heading.reload.is_empty() {
            self.buffer.set_style(
                Rect::new(
                    heading.reload.start as u16,
                    row,
                    heading.reload.len() as u16,
                    1,
                ),
                Style::default().fg(POLICY_RELOADED_BADGE),
            );
        }
        if heading.line.starts_with('●') || heading.line.starts_with('○') {
            self.buffer[(0, row)].set_fg(if footer_color.is_some() {
                TEXT
            } else {
                Color::Indexed(29)
            });
            self.heading = Some((row, heading));
        }
    }

    fn file_paths(&mut self, banner: &Banner, area: Rect) {
        let mut lines = Vec::new();
        for (label, display, path) in [
            ("Config File", &banner.box_label, &banner.box_file),
            ("Policy File", &banner.policy_label, &banner.policy_file),
        ] {
            if !lines.is_empty() {
                lines.push(Line::default());
            }
            let (label, color) =
                if banner.copied.as_ref().is_some_and(|(copied, at)| {
                    copied == path && at.elapsed() < Duration::from_secs(2)
                }) {
                    ("Copied path", ACCENT)
                } else {
                    (label, TEXT)
                };
            lines.push(Line::styled(
                label,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
            let display = tail(display, usize::from(area.width));
            let target = Rect::new(
                area.x,
                area.y + lines.len() as u16,
                display_width(&display) as u16,
                1,
            )
            .intersection(area);
            if !target.is_empty() {
                self.files.push((target, path.clone()));
            }
            lines.push(Line::styled(display, Style::default().fg(MUTED)));
        }
        Paragraph::new(lines).render(area, &mut self.buffer);
    }

    /// Put the `box runs history` command for the current view in the bottom border, at the
    /// right, as a copy target, since the table cuts reasons and keeps only the latest rows. A
    /// command that does not fit whole is left out.
    fn history(&mut self, banner: &Banner) {
        if banner.history.is_empty() || self.buffer.area.height < 3 {
            return;
        }
        let command = if banner.activity == ActivityView::AllOperations {
            banner.history.clone()
        } else {
            format!("{} --deny", banner.history)
        };
        let copied = banner.copied.as_ref().is_some_and(|(copied, at)| {
            *copied == command && at.elapsed() < Duration::from_secs(2)
        });
        let label = if copied { "Copied" } else { "Full list" };
        let room = usize::from(self.buffer.area.width).saturating_sub(4);
        let width = display_width(&command);
        let Some(label) = [format!(" {label}: "), " ".to_string()]
            .into_iter()
            .find(|prefix| display_width(prefix) + width + 1 <= room)
        else {
            return;
        };
        let text = format!("{label}{command} ");
        let row = self.buffer.area.height - 2;
        // Line the label up with the activity table's left edge, which is what it lists, and
        // move it left only as far as it needs to fit.
        let table = section_areas(self.buffer.area)[1].x.saturating_sub(1);
        let start = table.min(self.buffer.area.width - 2 - display_width(&text) as u16);
        let command_start = start + display_width(&label) as u16;
        // The terminal's own foreground, so the line reads on a light or a dark background.
        self.buffer.set_string(
            start,
            row,
            &label,
            if copied {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Reset)
            },
        );
        self.buffer.set_string(
            command_start,
            row,
            format!("{command} "),
            Style::default()
                .fg(Color::Reset)
                .add_modifier(Modifier::BOLD),
        );
        self.files
            .push((Rect::new(command_start, row, width as u16, 1), command));
    }

    pub(super) fn hover(&mut self, position: Option<(usize, u16)>) {
        let Some((column, row)) = position else {
            return;
        };
        if let Some((heading_row, heading)) = &self.heading
            && row == *heading_row
        {
            for range in [
                &heading.policy,
                &heading.reload,
                &heading.minimize,
                &heading.activity,
            ] {
                if range.contains(&column) {
                    self.buffer.set_style(
                        Rect::new(range.start as u16, row, range.len() as u16, 1),
                        Style::default().fg(HOVER),
                    );
                }
            }
        }
        if let Ok(column) = u16::try_from(column) {
            for (area, _) in &self.files {
                if area.contains((column, row).into()) {
                    self.buffer.set_style(*area, Style::default().fg(HOVER));
                }
            }
        }
    }

    pub(super) fn write(
        &self,
        output: &mut impl Write,
        first: u16,
        available: u16,
        color: bool,
    ) -> io::Result<()> {
        let padding = available.saturating_sub(self.buffer.area.height);
        let skipped = self.buffer.area.height.saturating_sub(available);
        output.write_all(b"\x1b[?6l\x1b[0m")?;
        for offset in 0..available {
            write!(output, "\x1b[{};1H\x1b[2K", first + offset)?;
        }
        let mut buffer = Cow::Borrowed(&self.buffer);
        if !color {
            buffer.to_mut().set_style(self.buffer.area, Style::reset());
        }
        let baseline = Buffer::empty(buffer.area);
        TermionBackend::new(output).draw(
            baseline
                .diff_iter(&buffer)
                .filter(|(_, y, _)| *y >= skipped)
                .map(|(x, y, cell)| (x, first + padding + (y - skipped) - 1, cell)),
        )
    }
}

impl Banner {
    pub(super) fn view(&self, width: usize, minimized: bool) -> Panel {
        let mut panel = Panel::new(width, if minimized { 1 } else { BANNER_ROWS });
        panel.status(self, minimized);
        if minimized {
            return panel;
        }
        let [policy, activity] = sections(&mut panel.buffer);
        let entries = self.entries();
        panel.file_paths(self, policy);
        panel.history(self);
        activity_table(
            &entries,
            self.activity,
            self.recent_denial().map(|operation| operation.id),
            activity,
            &mut panel.buffer,
        );
        panel
    }
}

fn sections(buffer: &mut Buffer) -> [Rect; 2] {
    let [policy, activity] = section_areas(buffer.area);
    let divider = policy.right().saturating_add(1);
    if divider < buffer.area.right().saturating_sub(1) {
        for y in policy.y..policy.bottom() {
            buffer[(divider, y)].set_symbol("│").set_fg(BORDER);
        }
    }
    [policy, activity]
}

fn section_areas(area: Rect) -> [Rect; 2] {
    let body = Rect::new(
        u16::from(area.width > 0),
        u16::from(area.height > 0),
        area.width.saturating_sub(2),
        area.height.saturating_sub(3),
    );
    let sidebar = (body.width / 3).max(18).min(body.width.saturating_sub(1));
    let divider = body.x + sidebar;
    let policy = Rect::new(
        body.x + u16::from(sidebar > 0),
        body.y,
        sidebar.saturating_sub(2),
        body.height,
    );
    let start = (divider + 2).min(body.right());
    let activity = Rect::new(
        start,
        body.y,
        body.right().saturating_sub(start + 1),
        body.height,
    );
    [policy, activity]
}

fn activity_table(
    entries: &[ActivityEntry<'_>],
    view: ActivityView,
    highlighted: Option<u64>,
    area: Rect,
    buffer: &mut Buffer,
) {
    let available = usize::from(area.width);
    let show_operation = available >= 68;
    let show_reason = available >= 36;
    let show_decision = available >= 44;
    let show_count = view == ActivityView::TopDenials && available >= 18;
    let show_time = view != ActivityView::TopDenials && available >= 80;
    let count_width = 5;
    let prefix_width = if show_count {
        count_width
    } else if show_time {
        8
    } else {
        0
    };
    let operation_width = if show_operation { 16 } else { 0 };
    let result_width = if show_decision { 8 } else { 1 };
    let spacing = if show_operation { 2 } else { 1 };
    let gaps = spacing
        * (1 + usize::from(show_operation)
            + usize::from(show_reason)
            + usize::from(prefix_width > 0));
    let flexible = available.saturating_sub(prefix_width + operation_width + result_width + gaps);
    let reason_width = if show_reason {
        flexible.div_ceil(2).min(36)
    } else {
        0
    };
    let target_width = flexible - reason_width;
    let mut widths = Vec::new();
    let mut labels = Vec::new();
    if show_count {
        widths.push(Constraint::Length(count_width as u16));
        labels.push("COUNT");
    }
    if show_time {
        widths.push(Constraint::Length(8));
        labels.push("TIME");
    }
    if show_operation {
        widths.push(Constraint::Length(operation_width as u16));
        labels.push("OPERATION");
    }
    widths.push(Constraint::Min(1));
    labels.push("TARGET");
    if show_reason {
        widths.push(Constraint::Length(reason_width as u16));
        labels.push("REASON");
    }
    widths.push(Constraint::Length(result_width as u16));
    labels.push(if show_decision { "DECISION" } else { "" });
    let header = Row::new(labels).style(Style::default().fg(MUTED));
    let rows = entries
        .iter()
        .take(usize::from(area.height.saturating_sub(1)))
        .map(|entry| {
            let operation = entry.operation;
            let mut cells = Vec::new();
            if show_count {
                cells.push(
                    Cell::from(entry.count.to_string())
                        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
                );
            }
            if show_time {
                cells.push(Cell::from(operation.time.as_str()).style(Style::default().fg(MUTED)));
            }
            if show_operation {
                cells.push(Cell::from(fit(&operation.action, operation_width)));
            }
            cells.push(Cell::from(fit(&operation.resource, target_width)));
            if show_reason {
                cells.push(
                    Cell::from(if operation.permitted {
                        String::new()
                    } else {
                        fit(&operation.reason, reason_width)
                    })
                    .style(Style::default().fg(MUTED)),
                );
            }
            cells.push(
                Cell::from(if show_decision {
                    if operation.permitted { "ALLOW" } else { "DENY" }
                } else if operation.permitted {
                    "✓"
                } else {
                    "×"
                })
                .style(Style::default().fg(if operation.permitted {
                    Color::Indexed(29)
                } else {
                    Color::Red
                })),
            );
            let row = Row::new(cells);
            if Some(operation.id) == highlighted {
                row.style(Style::default().bg(DENIAL))
            } else {
                row
            }
        });
    Table::new(rows, widths)
        .header(header)
        .column_spacing(spacing as u16)
        .style(Style::default().fg(TEXT))
        .render(area, buffer);
}

fn tail(text: &str, width: usize) -> String {
    if display_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut remaining = width - 1;
    let mut graphemes: Vec<_> = text
        .graphemes(true)
        .rev()
        .take_while(|grapheme| {
            let width = usize::from(grapheme.cell_width());
            if width > remaining {
                return false;
            }
            remaining -= width;
            true
        })
        .collect();
    graphemes.reverse();
    format!("…{}", graphemes.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::run::banner::PolicyStatus;

    fn sample(count: usize) -> Banner {
        let mut banner = Banner::new(
            "claude",
            "/home/.strands/box/r/example/box.toml",
            "/home/.strands/box/r/example/policy.dw",
        );
        for index in 0..count {
            banner.record(
                false,
                "http:request",
                &format!("host-{index}.example"),
                Some("no permit matched"),
                "<default-deny>",
            );
        }
        banner
    }

    fn text(panel: &Panel) -> String {
        panel
            .buffer
            .content
            .chunks(usize::from(panel.buffer.area.width).max(1))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn file_targets_keep_full_paths_and_highlight_only_the_visible_text() {
        let config = "/home/operator/a long folder/界/profiles/claude/profile.toml";
        let policy = "/home/operator/a long folder/界/profiles/claude/policy.dw";
        let banner = Banner::new("claude", config, policy);
        for width in [20, 79, 120, 240] {
            assert!(banner.view(width, true).files.is_empty());
            let mut panel = banner.view(width, false);
            assert_eq!(panel.files.len(), 2);
            for ((area, path), expected) in panel.files.clone().into_iter().zip([config, policy]) {
                assert_eq!(path, expected);
                assert_eq!(area.height, 1);
                let after = panel.buffer[(area.right(), area.y)].clone();
                assert_eq!(
                    panel.buffer[(area.right() - 1, area.y)].symbol(),
                    &expected[expected.len() - 1..]
                );
                panel.hover(Some((usize::from(area.x), area.y)));
                for column in area.x..area.right() {
                    let cell = &panel.buffer[(column, area.y)];
                    assert_eq!(cell.fg, HOVER);
                    assert!(!cell.modifier.contains(Modifier::UNDERLINED));
                }
                assert_eq!(panel.buffer[(area.right(), area.y)], after);
            }
        }
        for width in 0..5 {
            assert!(banner.view(width, false).files.is_empty());
        }
    }

    #[test]
    fn copied_file_notice_keeps_the_path_and_expires_without_color() {
        let config = "/profiles/claude/profile.toml";
        let policy = "/profiles/claude/policy.dw";
        let mut banner = Banner::new("claude", config, policy);
        for width in [20, 79, 120, 240] {
            banner.copied = None;
            let original = banner.view(width, false);
            for copied in [config, policy] {
                for age in [0, 1, 2, 3] {
                    banner.copied =
                        Some((copied.into(), Instant::now() - Duration::from_secs(age)));
                    let panel = banner.view(width, false);
                    assert_eq!(panel.files, original.files);
                    assert!(!text(&banner.view(width, true)).contains("Copied path"));
                    for color in [true, false] {
                        let mut bytes = Vec::new();
                        panel.write(&mut bytes, 1, BANNER_ROWS, color).unwrap();
                        let mut terminal = vt100::Parser::new(BANNER_ROWS, width as u16, 0);
                        terminal.process(&bytes);
                        for ((area, path), label) in
                            panel.files.iter().zip(["Config File", "Policy File"])
                        {
                            let row = terminal
                                .screen()
                                .rows(0, width as u16)
                                .nth(usize::from(area.y - 1))
                                .unwrap();
                            let (expected, expected_color) = if path == copied && age < 2 {
                                ("Copied path", ACCENT)
                            } else {
                                (label, TEXT)
                            };
                            assert!(row.contains(expected), "{row:?}: expected {expected}");
                            assert_eq!(row.contains("Copied path"), path == copied && age < 2);
                            assert_eq!(panel.buffer[(area.x, area.y - 1)].fg, expected_color);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tiny_panels_and_untrusted_text_stay_in_their_buffer() {
        let mut banner = sample(0);
        let target = "界界\x1b[2J\n\u{202e}";
        banner.record(false, "fs:read", target, Some("refused\r"), "secret");
        let entries = banner.entries();
        let cleaned = &entries[0].operation.resource;
        assert!(!cleaned.chars().any(char::is_control));
        assert!(cleaned.contains("\\u{1b}[2J\\n\\u{202e}"));
        for width in [0, 1, 2, 12, 24, 40, 80, 120, 200] {
            for minimized in [false, true] {
                let panel = banner.view(width, minimized);
                assert!(!text(&panel).replace('\n', "").chars().any(char::is_control));
                for available in 0..25 {
                    let mut bytes = Vec::new();
                    panel.write(&mut bytes, 1, available, true).unwrap();
                }
            }
        }
    }

    #[test]
    fn writer_preserves_agent_output_and_clears_banner_rows() {
        let mut banner = sample(0);
        banner.record(false, "fs:read", "界界/document", Some("refused"), "secret");
        let panel = banner.view(79, false);
        for color in [true, false] {
            let mut bytes = b"PROMPT> \x1b7\x1b[5;1Hstale\x1b[13;80HX\x1b8\x1b[4m".to_vec();
            panel.write(&mut bytes, 5, BANNER_ROWS + 1, color).unwrap();
            let mut terminal = vt100::Parser::new(24, 80, 0);
            terminal.process(&bytes);
            let screen = terminal.screen();
            assert!(screen.contents().contains("PROMPT> "));
            assert!(screen.contents().contains("界界/document"));
            assert!(screen.rows(0, 80).nth(4).unwrap().trim().is_empty());
            assert!(!screen.cell(12, 79).unwrap().has_contents());
        }
    }

    #[test]
    fn policy_notice_precedes_profile_with_padding_and_confirmed_state_colors() {
        let mut banner = sample(1);
        let before = text(&banner.view(200, true));
        for (enabled, failed, message, background) in [
            (true, false, "POLICY ON", POLICY_ON_BADGE),
            (false, false, "POLICY OFF", POLICY_OFF_BADGE),
            (false, true, "POLICY OFF (update failed)", POLICY_OFF_BADGE),
            (true, true, "POLICY ON (update failed)", DENIAL),
        ] {
            banner.policy = PolicyStatus {
                enabled,
                failed,
                changed_at: Some(Instant::now()),
                ..PolicyStatus::default()
            };
            for minimized in [true, false] {
                let panel = banner.view(200, minimized);
                let row = panel.buffer.area.height - 1;
                let footer_color = match (enabled, failed) {
                    (false, _) => POLICY_OFF,
                    (true, false) => POLICY_ON,
                    (true, true) => Color::Reset,
                };
                assert_eq!(panel.buffer[(0, row)].bg, footer_color);
                assert_eq!(panel.buffer[(199, row)].bg, footer_color);
                let rendered = text(&panel);
                let footer = rendered.lines().last().unwrap();
                assert!(footer.contains(&format!("box •  {message}  • claude")));
                assert!(footer.contains("1 operation denied") || footer.contains("1 denied"));
                assert!(!footer.contains("BLOCKED"));
                let start = display_width(footer.split_once(message).unwrap().0) as u16;
                for column in start - 1..=start + display_width(message) as u16 {
                    let cell = &panel.buffer[(column, row)];
                    assert_eq!(cell.fg, TEXT);
                    assert_eq!(cell.bg, background);
                    assert!(cell.modifier.contains(Modifier::BOLD));
                }
                assert_eq!(
                    panel.buffer[(0, row)].symbol(),
                    if enabled { "●" } else { "○" }
                );
                assert_eq!(panel.heading.as_ref().unwrap().1.minimize.end, 199);
                assert_eq!(
                    panel.buffer[(0, row)].fg,
                    if enabled && failed {
                        Color::Indexed(29)
                    } else {
                        TEXT
                    }
                );
            }
        }
        banner.policy.enabled = true;
        banner.policy.changed_at = Some(Instant::now() - Duration::from_secs(4));
        assert!(text(&banner.view(200, true)).contains("POLICY ON"));
        banner.policy.changed_at = Some(Instant::now() - Duration::from_secs(6));
        let panel = banner.view(200, true);
        assert_eq!(text(&panel), before);
        assert_eq!(panel.buffer[(0, 0)].fg, Color::Indexed(29));
        assert_eq!(panel.buffer[(199, 0)].bg, Color::Reset);
    }

    #[test]
    fn pending_reload_notice_becomes_a_quiet_hint_and_keeps_off_visible() {
        let mut banner = sample(0);
        banner.policy.pending = true;
        for seconds in [0, 6] {
            banner.policy.changed_at = Some(Instant::now() - Duration::from_secs(seconds));
            for minimized in [true, false] {
                for width in [60, 120] {
                    let panel = banner.view(width, minimized);
                    let (row, heading) = panel.heading.as_ref().unwrap();
                    let notice = seconds == 0;
                    assert_eq!(heading.line.contains("UPDATE READY"), notice);
                    assert!(!heading.reload.is_empty());
                    assert_eq!(
                        panel.buffer[(0, *row)].bg,
                        if notice {
                            POLICY_RELOADED
                        } else {
                            Color::Reset
                        }
                    );
                    if !notice {
                        assert!(heading.line.contains("Ctrl+Alt+R to reload policy"));
                        assert!(heading.reload.end < heading.policy.start);
                        assert!(heading.activity.end <= heading.reload.start);
                        let cell = &panel.buffer[(heading.reload.start as u16, *row)];
                        assert_eq!(cell.fg, POLICY_RELOADED_BADGE);
                    }
                }
            }
        }
        banner.policy.enabled = false;
        let panel = banner.view(120, true);
        assert!(text(&panel).contains("POLICY OFF (update ready)"));
        assert!(panel.heading.unwrap().1.reload.is_empty());
        assert_eq!(panel.buffer[(0, 0)].bg, POLICY_OFF);
    }

    #[test]
    fn policy_notice_clips_before_activity_and_controls() {
        let mut banner = Banner::new("claude-bedrock-8e099ce7", "/run/box.toml", "/run/policy.dw");
        let layouts = [36, 50, 60, 79, 160]
            .map(|width| (width, banner.view(width, false).heading.unwrap().1));
        banner.policy.changed_at = Some(Instant::now());
        for (enabled, failed, message) in [
            (true, false, "POLICY ON"),
            (false, false, "POLICY OFF"),
            (true, true, "POLICY ON (update failed)"),
            (false, true, "POLICY OFF (update failed)"),
        ] {
            banner.policy.enabled = enabled;
            banner.policy.failed = failed;
            for minimized in [true, false] {
                let rendered = text(&banner.view(160, minimized));
                assert!(rendered.contains(&format!("box •  {message} ")));
                assert!(rendered.contains(r"Ctrl+\ policy on/off"));
                let narrow = text(&banner.view(79, minimized));
                assert!(narrow.contains(if enabled { "POLICY ON" } else { "POLICY OFF" }));
                assert!(narrow.contains(r"Ctrl+\"));
                if minimized {
                    assert!(rendered.contains("claude-bedrock-8e099ce7"));
                    assert!(narrow.contains(&format!("box •  {message} ")));
                    assert!(narrow.contains("0 operations denied") || narrow.contains("0 denied"));
                } else {
                    assert!(narrow.contains("Top Denials"));
                }
            }
            for (width, before) in &layouts {
                let after = banner.view(*width, false).heading.unwrap().1;
                assert_eq!(
                    (&after.activity, &after.policy, &after.minimize),
                    (&before.activity, &before.policy, &before.minimize),
                    "{width}: {}",
                    after.line
                );
                assert!(
                    after
                        .line
                        .contains(if enabled { "POLICY ON" } else { "POLICY OFF" })
                );
            }
        }
        for width in [0, 1, 2, 12, 24, 40, 80, 120] {
            let panel = banner.view(width, false);
            if let Some((row, heading)) = &panel.heading {
                if !heading.activity.is_empty() {
                    assert!(heading.message.end + 2 <= heading.activity.start);
                }
                if !heading.policy.is_empty() {
                    assert!(heading.message.end < heading.policy.start);
                    assert!(heading.policy.end < heading.minimize.start);
                    assert!(heading.minimize.end <= width);
                }
                assert_eq!(panel.buffer[(0, *row)].fg, TEXT);
            }
        }
        banner.policy.enabled = true;
        banner.policy.changed_at = Some(Instant::now() - Duration::from_secs(6));
        assert!(text(&banner.view(79, false)).contains("Top Denials"));
    }

    #[test]
    fn policy_off_notice_persists_without_color_while_policy_on_expires() {
        let mut banner = sample(0);
        banner.policy.changed_at = Some(Instant::now() - Duration::from_secs(6));
        for (enabled, dot) in [(true, "●"), (false, "○")] {
            banner.policy.enabled = enabled;
            for minimized in [true, false] {
                let panel = banner.view(79, minimized);
                let rows = panel.buffer.area.height;
                assert_eq!(
                    panel.buffer[(78, rows - 1)].bg,
                    if enabled { Color::Reset } else { POLICY_OFF }
                );
                let mut bytes = Vec::new();
                panel.write(&mut bytes, 1, rows, false).unwrap();
                let mut terminal = vt100::Parser::new(rows, 80, 0);
                terminal.process(&bytes);
                let footer = terminal.screen().rows(0, 80).last().unwrap();
                assert!(footer.starts_with(&format!("{dot} box")));
                assert_eq!(footer.contains("POLICY OFF"), !enabled);
                assert!(!footer.contains("POLICY ON"));
                assert_eq!(
                    terminal.screen().cell(rows - 1, 0).unwrap().fgcolor(),
                    vt100::Color::Default
                );
                assert_eq!(
                    terminal.screen().cell(rows - 1, 78).unwrap().bgcolor(),
                    vt100::Color::Default
                );
            }
        }
    }

    #[test]
    fn policy_and_size_controls_stay_separate_at_the_right() {
        let mut banner = sample(10_000);
        banner.activity = ActivityView::LatestDenials;
        for width in [79, 120, 200] {
            for minimized in [true, false] {
                let mut panel = banner.view(width, minimized);
                let (row, heading) = panel.heading.as_ref().unwrap();
                let control: String = heading
                    .policy
                    .clone()
                    .map(|column| panel.buffer[(column as u16, *row)].symbol())
                    .collect();
                assert_eq!(control, r"Ctrl+\ policy on/off");
                assert!(heading.policy.start > width / 2);
                assert!(heading.policy.end < heading.minimize.start);
                assert_eq!(heading.minimize.end, width - 1);
                let (row, policy) = (*row, heading.policy.clone());
                for column in [policy.start, policy.end - 1] {
                    panel.hover(Some((column, row)));
                    assert!(
                        policy
                            .clone()
                            .all(|column| panel.buffer[(column as u16, row)].fg == HOVER)
                    );
                }
                panel.hover(Some((3, row)));
                assert_eq!(panel.buffer[(0, row)].fg, Color::Indexed(29));
                assert_eq!(panel.buffer[(3, row)].fg, MUTED);
            }
        }
    }

    #[test]
    fn capped_counts_show_their_window_when_it_fits() {
        let banner = sample(1001);
        let compact = banner.view(90, false);
        assert!(text(&compact).contains("1001 denied"));
        let wide = banner.view(200, false);
        let rendered = text(&wide);
        assert!(rendered.contains("Latest 1000 of 1001"));
    }

    #[test]
    fn all_operations_show_outcomes_and_denial_reasons() {
        let mut banner = sample(1);
        banner.record(
            true,
            "http:request",
            "approved.example",
            None,
            "model_request",
        );
        banner.activity = ActivityView::AllOperations;
        let panel = banner.view(120, false);
        let rendered = text(&panel);
        let rows: Vec<_> = rendered.lines().collect();
        let reason = rows[1].find("REASON").unwrap();
        let decision = rows[1].find("DECISION").unwrap();
        assert!(rows[2].contains("approved.example"));
        assert_eq!(rows[2][decision..].split_whitespace().next(), Some("ALLOW"));
        assert!(rows[2][reason..decision].trim().is_empty());
        assert!(rows[3].contains("host-0.example"));
        assert_eq!(rows[3][decision..].split_whitespace().next(), Some("DENY"));
        assert_eq!(rows[3][reason..decision].trim(), "no permit matched");
    }

    #[test]
    fn the_full_view_offers_the_history_command_for_its_view_in_the_bottom_border() {
        let mut banner = sample(1);
        banner.history = "box runs history b-0123".into();
        let border = |panel: &Panel| {
            text(panel)
                .lines()
                .nth(usize::from(BANNER_ROWS) - 2)
                .unwrap()
                .to_string()
        };
        for (view, command) in [
            (ActivityView::TopDenials, "box runs history b-0123 --deny"),
            (
                ActivityView::LatestDenials,
                "box runs history b-0123 --deny",
            ),
            (ActivityView::AllOperations, "box runs history b-0123"),
        ] {
            banner.activity = view;
            let panel = banner.view(120, false);
            let row = border(&panel);
            assert!(row.starts_with('╰') && row.ends_with("─╯"), "{row}");
            assert!(row.contains(&format!("─ Full list: {command} ─")), "{row}");
            let table = section_areas(panel.buffer.area)[1].x;
            let label = row.chars().position(|c| c == 'F').unwrap() as u16;
            assert_eq!(label, table, "{row}");
            let (area, _) = panel.files.last().unwrap();
            assert_eq!(panel.buffer[(area.x, area.y)].fg, Color::Reset);
            assert!(
                panel.buffer[(area.x, area.y)]
                    .modifier
                    .contains(Modifier::BOLD)
            );
            let (area, target) = panel.files.last().unwrap();
            assert_eq!(target, command);
            assert_eq!(area.y, BANNER_ROWS - 2);
            assert_eq!(usize::from(area.width), command.len());
            let shown: String = (area.x..area.right())
                .map(|x| panel.buffer[(x, area.y)].symbol())
                .collect();
            assert_eq!(shown, command);
        }

        banner.activity = ActivityView::TopDenials;
        banner.copied = Some(("box runs history b-0123 --deny".into(), Instant::now()));
        assert!(border(&banner.view(120, false)).contains(" Copied: box runs history"));
        banner.copied = None;

        let narrow = banner.view(36, false);
        assert!(border(&narrow).contains(" box runs history b-0123 --deny ─╯"));
        assert!(!border(&narrow).contains("Full list"));
        let tiny = banner.view(30, false);
        assert!(!text(&tiny).contains("box runs history"));
        assert_eq!(tiny.files.len(), 2);
        assert!(banner.view(120, true).files.is_empty());
        assert!(!text(&banner.view(120, true)).contains("box runs history"));
    }
}
