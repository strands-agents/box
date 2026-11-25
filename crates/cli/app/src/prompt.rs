use std::io::{self, BufRead};
use std::path::Path;

use nix::{
    libc,
    sys::termios::{self, SetArg, SpecialCharacterIndices, Termios},
};
use ratatui::text::Span;
use unicode_segmentation::UnicodeSegmentation;

use crate::error::Error;
use crate::files::io_error;
use crate::starter::Terminal;

/// The sections of the inline view, by stage.
pub(crate) const SECTIONS: [&str; 4] = ["Agent", "Setup", "Policy", "Review"];
const BOLD_ACCENT: &str = "1;38;2;74;222;128";
pub(crate) const AGENT: usize = 0;
pub(crate) const SETUP: usize = 1;
pub(crate) const POLICY: usize = 2;
pub(crate) const REVIEW: usize = 3;

#[derive(Default)]
pub(crate) struct Session {
    pub(crate) name: String,
    pub(crate) stage: usize,
    pub(crate) sections: [Option<usize>; 4],
    /// Whether the operator picks the agent, so the Agent section shows.
    pub(crate) agent: bool,
    pub(crate) details: String,
    pub(crate) feedback: String,
    pub(crate) readings: Option<(String, Vec<crate::detect::Reading>)>,
    pub(crate) editing: Option<crate::Profile>,
    /// The workspace, when the profile runs after it is saved.
    pub(crate) run: Option<std::path::PathBuf>,
    pub(crate) reviewing: bool,
    answers: Vec<(String, String)>,
    cursor: usize,
    active: usize,
    pending_question: Option<String>,
    pub(crate) navigating: bool,
    drawn: Vec<String>,
    dimensions: Option<(usize, usize)>,
}

impl Session {
    pub(crate) fn edit(&mut self, profile: crate::Profile) {
        if self
            .editing
            .as_ref()
            .is_none_or(|saved| saved.path != profile.path)
        {
            self.clear_setup();
        }
        self.editing = Some(profile);
    }

    pub(crate) fn clear_setup(&mut self) {
        self.answers.truncate(self.cursor);
        self.active = self.cursor;
        self.sections[SETUP..].fill(None);
        self.reviewing = false;
        self.readings = None;
    }

    /// Ask every answer again from the first Setup question.
    pub(crate) fn edit_setup(&mut self) {
        self.active = self.sections[SETUP].unwrap_or(0);
        self.reviewing = true;
    }

    pub(crate) fn section(&mut self) {
        self.sections[self.stage] = Some(self.cursor);
    }

    pub(crate) fn restart(&mut self) {
        self.cursor = 0;
        self.stage = 0;
        self.pending_question = None;
        self.navigating = false;
    }

    /// The saved answer to `question`. Saved answers before it that no question asks now drop.
    fn saved(&mut self, question: &str) -> Option<String> {
        let start = self.cursor.min(self.answers.len());
        let offset = self.answers[start..]
            .iter()
            .position(|(key, _)| key == question)?;
        self.answers.drain(start..start + offset);
        Some(self.answers[start].1.clone())
    }

    pub(crate) fn accept(&mut self, value: String) {
        let Some(question) = self.pending_question.take() else {
            return;
        };
        let answer = (question, value);
        let slot = self.answers.get(self.cursor);
        if slot != Some(&answer) {
            if slot.is_some_and(|(key, _)| *key == answer.0) {
                self.answers[self.cursor] = answer;
            } else {
                self.answers.insert(self.cursor, answer);
            }
            for section in self.sections.iter_mut().skip(self.stage + 1) {
                *section = None;
            }
        }
        self.cursor += 1;
        self.active = self.active.max(self.cursor);
    }

    /// Go to the previous question, or to the next one that has an answer.
    fn step(&mut self, direction: isize) -> bool {
        let destination = if direction < 0 {
            self.cursor.checked_sub(1)
        } else {
            (self.cursor < self.answers.len()).then_some(self.cursor + 1)
        };
        self.go(destination)
    }

    /// Go to the start of the previous section, or of the next one that has an answer.
    fn navigate(&mut self, direction: isize) -> bool {
        let destination = if direction < 0 {
            self.sections[..self.stage]
                .iter()
                .rev()
                .flatten()
                .copied()
                .find(|index| *index < self.cursor)
        } else {
            self.sections[self.stage + 1..]
                .iter()
                .flatten()
                .copied()
                .find(|index| *index > self.cursor && *index <= self.answers.len())
        };
        self.go(destination)
    }

    fn go(&mut self, destination: Option<usize>) -> bool {
        if let Some(destination) = destination {
            self.active = destination;
            self.navigating = true;
            true
        } else {
            false
        }
    }
}

fn detail_lines(session: &Session, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = format!("{}{}", session.details, session.feedback)
        .trim_end()
        .lines()
        .flat_map(|line| {
            if line.is_empty() {
                vec![String::new()]
            } else if session.stage == AGENT && line.starts_with("    ") {
                wrap_line(line.trim(), 4, width.min(96))
            } else if let Some(warning) = line.trim().strip_prefix("! ") {
                let mut lines = wrap_line(warning, 4, width.min(86));
                if let Some(first) = lines.first_mut() {
                    first.replace_range(..4, "  ! ");
                }
                lines
            } else if session.stage == REVIEW
                && width >= 12
                && let Some((label, value)) = line.trim().split_once("  ")
            {
                let width = width.min(96);
                let value = value.trim_start();
                let prefix = &line.trim()[..line.trim().len() - value.len()];
                let column = (2 + Span::raw(prefix).width()).min(width / 2);
                let labels = wrap_line(label, 2, column - 1);
                let values = wrap_line(value, column, width);
                (0..labels.len().max(values.len()))
                    .map(|index| {
                        let label = labels.get(index).map_or("", String::as_str);
                        let value = values.get(index).map_or("", |line| &line[column..]);
                        format!(
                            "{label}{}{value}",
                            " ".repeat(column - Span::raw(label).width())
                        )
                    })
                    .collect()
            } else {
                wrap_line(line.trim(), 2, width.min(96))
            }
        })
        .collect();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// Which blank rows a guided question's header has.
#[derive(Clone, Copy)]
struct Blanks {
    top: bool,
    middle: bool,
    bottom: bool,
}

/// The blank rows at a `base` of header rows, with the top one kept in every layout.
fn blank_rows(base: usize, compact: bool) -> Blanks {
    Blanks {
        top: base >= 7,
        middle: base >= 7 && !compact,
        bottom: base >= 6 && !compact,
    }
}

/// A guided question's header rows and how many of its detail rows show at once.
struct Section {
    lines: Vec<String>,
    room: usize,
    cut: bool,
}

/// The header of a guided question, with at most `budget` rows before its blank bottom row.
fn section_lines(
    session: &Session,
    width: usize,
    budget: usize,
    scroll: usize,
    blanks: Blanks,
) -> Section {
    let tabs = if width < 48 {
        fit_line(&format!("  [ {} ]", SECTIONS[session.stage]), width)
    } else {
        fit_line(
            &format!(
                "  {}",
                SECTIONS
                    .iter()
                    .enumerate()
                    .skip(usize::from(!session.agent))
                    .map(|(index, label)| {
                        if index == session.stage {
                            format!("[ {label} ]")
                        } else {
                            format!("  {label}  ")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" │ ")
            ),
            width,
        )
    };
    let title = if session.editing.is_some() && session.stage != AGENT {
        format!("Edit profile / {}", session.name)
    } else if session.run.is_some() {
        if session.name.is_empty() {
            "Create a profile to run".to_string()
        } else {
            format!("Create profile / {}", session.name)
        }
    } else {
        "Create a new profile".to_string()
    };
    let mut lines = Vec::new();
    if blanks.top {
        lines.push(String::new());
    }
    lines.push(fit_line(&format!("  {title}"), width));
    if let Some(workspace) = session.run.as_ref().filter(|_| session.stage != REVIEW) {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let shown = match home
            .as_deref()
            .and_then(|home| workspace.strip_prefix(home).ok())
        {
            Some(rest) => format!("~/{}", rest.display()),
            None => workspace.display().to_string(),
        };
        lines.push(fit_line(
            &format!("  Set up this profile, then run it in {shown}."),
            width,
        ));
    }
    if blanks.middle {
        lines.push(String::new());
    }
    lines.push(tabs);
    if blanks.middle {
        lines.push(String::new());
    }
    let details = detail_lines(session, width);
    let room = budget.saturating_sub(lines.len()).max(1);
    let cut = details.len() > room;
    let first = scroll.min(details.len().saturating_sub(room));
    lines.extend(details.into_iter().skip(first).take(room));
    if blanks.bottom {
        lines.push(String::new());
    }
    Section { lines, room, cut }
}

/// The choices of one question, as the menu draws them.
struct Choices<'a> {
    labels: &'a [&'a str],
    descriptions: &'a [&'a str],
    selected: Option<usize>,
    default: Option<usize>,
    typed: &'a str,
    name_entry: bool,
}

/// The menu rows for `height` rows and whether some choices are scrolled out of view.
fn choice_rows(ask: &Choices<'_>, width: usize, height: usize, density: u8) -> (Vec<String>, bool) {
    if ask.name_entry {
        if ask.labels.is_empty() {
            return (Vec::new(), false);
        }
        // The name entry rows below the choices take the last 2 rows.
        return menu_view(
            ask.labels,
            ask.descriptions,
            ask.selected,
            ask.default,
            "",
            width,
            height.saturating_sub(2),
            density,
        );
    }
    menu_view(
        ask.labels,
        ask.descriptions,
        ask.selected,
        ask.default,
        ask.typed,
        width,
        height,
        density,
    )
}

/// The rows of a guided question for a terminal of this size.
#[derive(Debug)]
struct Layout {
    section: Vec<String>,
    menu: Vec<String>,
    room: usize,
    cut: bool,
}

/// Lay out a guided question in the least dense of four layouts that shows every choice and every
/// detail row, else the one that shows every choice and the most details.
fn guided_layout(
    session: &Session,
    ask: &Choices<'_>,
    width: usize,
    height: usize,
    scroll: usize,
) -> Layout {
    let base = height.saturating_sub(5).min(height * 2 / 3).max(3);
    let mut candidates = Vec::new();
    for level in 0..=3u8 {
        let compact = level > 0;
        let density = if level >= 2 { level } else { 0 };
        let blanks = blank_rows(base, compact);
        let full = choice_rows(ask, width, usize::MAX / 4, density).0.len();
        let needed = full + 1 + if ask.name_entry { 2 } else { 0 };
        let spare = height
            .saturating_sub(1 + needed)
            .saturating_sub(usize::from(blanks.bottom));
        // A compact header keeps the detail rows that its dropped blank rows would have had.
        let floor = base.saturating_sub(2 * usize::from(compact && blank_rows(base, false).middle));
        let section = section_lines(session, width, spare.max(floor), scroll, blanks);
        // The densest layout also uses the spare bottom row, rather than hide a choice.
        let menu_height = height.saturating_sub(section.lines.len() + 1 - usize::from(level == 3));
        let (menu, hidden) = choice_rows(ask, width, menu_height, density);
        candidates.push((
            Layout {
                section: section.lines,
                menu,
                room: section.room,
                cut: section.cut,
            },
            hidden,
        ));
    }
    let index = candidates
        .iter()
        .position(|(layout, hidden)| !hidden && !layout.cut)
        .or_else(|| {
            // The details scroll anyway, so show the most of them without losing descriptions.
            (0..3)
                .filter(|&level| !candidates[level].1)
                .reduce(|best, level| {
                    if candidates[level].0.room > candidates[best].0.room {
                        level
                    } else {
                        best
                    }
                })
        })
        .or_else(|| candidates.iter().position(|(_, hidden)| !hidden))
        .unwrap_or(3);
    candidates.swap_remove(index).0
}

fn key_hint(width: usize, sections: bool, scrollable: bool, choices: bool, back: bool) -> String {
    let mut text = if width >= 72 {
        if sections {
            "  ↑↓ choose  ←→ questions  Tab sections  Enter  Esc ACTION  Ctrl+C exit".to_string()
        } else {
            "  ↑↓ choose   Enter confirm   Esc ACTION   Ctrl+C exit".to_string()
        }
    } else if width >= 48 {
        if sections {
            "  ↑↓ ←→ Tab  Enter  Esc ACTION  Ctrl+C exit"
        } else {
            "  ↑↓ choose  Enter  Esc ACTION  Ctrl+C exit"
        }
        .to_string()
    } else {
        if sections {
            "  ↑↓ ←→ Tab Enter Esc ^C"
        } else {
            "  ↑↓ Enter Esc ^C"
        }
        .to_string()
    };
    if scrollable {
        text.push_str(if width >= 72 {
            "   PgUp/Dn scroll"
        } else if width >= 28 {
            "  PgUp/Dn"
        } else {
            " Pg↕"
        });
    }
    if !choices {
        text = text
            .replace("↑↓ choose   ", "")
            .replace("↑↓ choose  ", "")
            .replace("↑↓ ", "");
    }
    let mut text = text.replace("ACTION", if back { "back" } else { "exit" });
    if Span::raw(&text).width() >= width {
        text = text
            .replace("↑↓ choose", "↑↓")
            .replace("Enter confirm", "Enter")
            .replace("Ctrl+C exit", "^C exit");
    }
    fit_line(&text, width)
}

fn paint_line(line: &str, stage: usize) -> String {
    if SECTIONS
        .iter()
        .any(|label| line.contains(&format!("[ {label} ]")))
    {
        let mut text = format!("\x1b[90m{line}\x1b[0m");
        for label in SECTIONS {
            let active = format!("[ {label} ]");
            text = text.replace(
                &active,
                &format!("\x1b[0;1;{}m{active}\x1b[0;90m", crate::Report::ACCENT),
            );
        }
        text
    } else if let Some(warning) = line.strip_prefix("  ! ") {
        format!("  \x1b[33m!\x1b[0m {warning}")
    } else if stage == AGENT
        && let Some(name) = line
            .strip_prefix("  ✓ ")
            .or_else(|| line.strip_prefix("    ✓ "))
    {
        let indent = if line.starts_with("    ") {
            "    "
        } else {
            "  "
        };
        format!("{indent}\x1b[32m✓\x1b[0m \x1b[{BOLD_ACCENT}m{name}\x1b[0m")
    } else {
        let code = if line.starts_with("  > [")
            || line.starts_with("  > ✓ ")
            || line.starts_with("    › ")
            || (stage == REVIEW
                && matches!(
                    line,
                    "  PROFILE"
                        | "  POLICY"
                        | "  FILES"
                        | "  DETECTED OPTIONS"
                        | "  SELECTED OPTIONS"
                        | "  REVIEWED OPTIONS"
                )) {
            BOLD_ACCENT
        } else if line.starts_with("  Create a new profile")
            || line.starts_with("  Edit profile /")
            || line.starts_with("  Create profile /")
            || line.starts_with("  Create a profile to run")
        {
            "1"
        } else if line.starts_with("  ↑↓")
            || line.starts_with("  ←→")
            || line.starts_with("  Enter")
            || (stage == AGENT && (line.starts_with("  EXISTING ") || line.starts_with("    ")))
        {
            "90"
        } else {
            "0"
        };
        if code == "0"
            && stage == REVIEW
            && let Some((label, value)) = line
                .strip_prefix("  ")
                .filter(|text| !text.starts_with(' '))
                .and_then(|text| text.split_once("  "))
        {
            return format!("  \x1b[90m{label}\x1b[0m  {value}");
        }
        format!("\x1b[{code}m{line}\x1b[0m")
    }
}

fn draw_section(
    terminal: &mut Terminal<'_>,
    mut lines: Vec<String>,
    dimensions: (usize, usize),
) -> io::Result<()> {
    let session = terminal.session.as_mut().unwrap();
    if session.dimensions.is_some_and(|old| old != dimensions) {
        writeln!(terminal.output)?;
        session.drawn.clear();
    }
    session.dimensions = Some(dimensions);
    let question = wrap_line(
        session.details.lines().next().unwrap_or_default(),
        2,
        dimensions.0.min(96),
    );
    lines.resize(lines.len().max(session.drawn.len()), String::new());
    write!(terminal.output, "\r")?;
    if session.drawn.len() > 1 {
        write!(terminal.output, "\x1b[{}A", session.drawn.len() - 1)?;
    }
    for (index, line) in lines.iter().enumerate() {
        if session.drawn.get(index) != Some(line) {
            write!(terminal.output, "\r\x1b[2K")?;
            if terminal.choice_color {
                if question.contains(line) {
                    write!(terminal.output, "\x1b[1m{line}\x1b[0m")?;
                } else {
                    write!(terminal.output, "{}", paint_line(line, session.stage))?;
                }
            } else {
                write!(terminal.output, "{line}")?;
            }
        }
        if index + 1 < lines.len() {
            if index + 1 < session.drawn.len() {
                write!(terminal.output, "\x1b[B\r")?;
            } else {
                writeln!(terminal.output)?;
            }
        }
    }
    session.drawn = lines;
    Ok(())
}

pub(crate) fn finish(terminal: &mut Terminal<'_>) -> Result<(), Error> {
    let rows = terminal
        .session
        .as_ref()
        .map_or(0, |session| session.drawn.len());
    let write_error = |source| io_error("write", Path::new("stderr"), source);
    clear_menu(terminal, rows).map_err(write_error)?;
    if terminal.choice_controls {
        write!(terminal.output, "\x1b[?25h")
            .and_then(|()| terminal.output.flush())
            .map_err(write_error)?;
    }
    Ok(())
}

fn fit_line(text: &str, columns: usize) -> String {
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut width = 0;
    text.graphemes(true)
        .take_while(|grapheme| {
            width += Span::raw(*grapheme).width();
            width < columns
        })
        .collect()
}

pub(crate) fn size() -> io::Result<(usize, usize)> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one winsize to the valid pointer.
    if unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ as _, &mut size) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        usize::from(size.ws_col).max(2),
        usize::from(size.ws_row).max(4),
    ))
}

pub(crate) fn choose(
    terminal: &mut Terminal<'_>,
    choices: &[&str],
    default: Option<usize>,
) -> Result<Option<String>, Error> {
    select(terminal, choices, &[], default, true, Mode::Pick)
}

/// Pick one of `actions`, the first selected, with no `(default)` label.
pub(crate) fn act(
    terminal: &mut Terminal<'_>,
    actions: &[&str],
    descriptions: &[&str],
    selected: usize,
) -> Result<Option<String>, Error> {
    select(
        terminal,
        actions,
        descriptions,
        Some(selected),
        false,
        Mode::Pick,
    )
}

pub(crate) fn described(
    terminal: &mut Terminal<'_>,
    choices: &[&str],
    descriptions: &[&str],
    default: Option<usize>,
) -> Result<Option<String>, Error> {
    select(terminal, choices, descriptions, default, true, Mode::Pick)
}

pub(crate) fn text(terminal: &mut Terminal<'_>) -> Result<Option<String>, Error> {
    select(terminal, &[], &[], None, true, Mode::Pick)
}

/// An existing selection has a NUL prefix, which the keyboard cannot enter.
pub(crate) fn profile_name(
    terminal: &mut Terminal<'_>,
    names: &[&str],
    descriptions: &[&str],
) -> Result<Option<String>, Error> {
    select(terminal, names, descriptions, None, false, Mode::Name)
}

/// The regions that serve Amazon Bedrock (bedrock-runtime), from AWS's "Regional availability by
/// endpoints" page, checked 2026-11-25. The region prompt offers them in this order: the pack's
/// default and the other large US regions first, then the busiest outside the US, then the rest
/// by geography. Any other region that passes the input's pattern still works.
pub(crate) const BEDROCK_REGIONS: &[&str] = &[
    "us-west-2",
    "us-east-1",
    "us-east-2",
    "eu-central-1",
    "eu-west-1",
    "ap-northeast-1",
    "us-west-1",
    "ca-central-1",
    "ca-west-1",
    "mx-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-west-2",
    "eu-west-3",
    "ap-east-2",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-6",
    "ap-southeast-7",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "af-south-1",
    "sa-east-1",
    "us-gov-east-1",
    "us-gov-west-1",
];

/// Type a value, with `suggestions` that narrow to the ones holding the typed text. Enter answers
/// the selected suggestion, or the typed text when none is selected.
pub(crate) fn suggest(
    terminal: &mut Terminal<'_>,
    suggestions: &[&str],
    default: Option<usize>,
) -> Result<Option<String>, Error> {
    select(terminal, suggestions, &[], default, true, Mode::Filter)
}

/// The most matches that a filter shows at once.
const FILTER_ROWS: usize = 4;

/// How a menu takes its answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Pick a choice by number or arrows, or type an answer.
    Pick,
    /// Pick an existing name, or type a new one.
    Name,
    /// Type an answer, and pick from the choices that hold it.
    Filter,
}

/// The indices of the `choices` that hold `typed`, ignoring case.
fn matching(choices: &[&str], typed: &str) -> Vec<usize> {
    let typed = typed.trim().to_lowercase();
    (0..choices.len())
        .filter(|index| choices[*index].to_lowercase().contains(&typed))
        .collect()
}

pub(crate) fn wrap_line(text: &str, indent: usize, width: usize) -> Vec<String> {
    let mut rest: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut lines = Vec::new();
    let available = width.saturating_sub(indent).max(2);
    while !rest.is_empty() {
        let fitting = fit_line(&rest, available);
        if fitting.is_empty() {
            break;
        }
        let take = if fitting.len() < rest.len() {
            fitting
                .rfind(' ')
                .filter(|index| *index > 0)
                .unwrap_or(fitting.len())
        } else {
            fitting.len()
        };
        lines.push(format!(
            "{}{text}",
            " ".repeat(indent),
            text = &rest[..take]
        ));
        rest = rest[take..].trim_start().to_string();
    }
    lines
}

fn content_lines(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let width = width.saturating_sub(1).max(1);
    let mut style = String::new();
    for source in text.lines() {
        let mut line = style.clone();
        let mut columns = 0;
        let mut rest = source;
        while !rest.is_empty() {
            if let Some(escape) = rest.strip_prefix("\x1b[")
                && let Some(end) = escape.find('m')
                && escape[..end]
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ch == ';')
            {
                let code = &rest[..end + 3];
                if code == "\x1b[0m" {
                    style.clear();
                } else {
                    style.push_str(code);
                }
                line.push_str(code);
                rest = &rest[code.len()..];
                continue;
            }
            let grapheme = rest.graphemes(true).next().unwrap();
            rest = &rest[grapheme.len()..];
            if grapheme.chars().any(char::is_control) {
                continue;
            }
            let size = Span::raw(grapheme).width();
            if columns > 0 && columns + size > width {
                lines.push(if style.is_empty() {
                    line
                } else {
                    format!("{line}\x1b[0m")
                });
                line = style.clone();
                columns = 0;
            }
            line.push_str(grapheme);
            columns += size;
        }
        lines.push(if style.is_empty() {
            line
        } else {
            format!("{line}\x1b[0m")
        });
    }
    lines
}

#[cfg(test)]
fn menu_lines(
    choices: &[&str],
    descriptions: &[&str],
    selected: Option<usize>,
    default: Option<usize>,
    typed: &str,
    width: usize,
    height: usize,
) -> Vec<String> {
    menu_view(
        choices,
        descriptions,
        selected,
        default,
        typed,
        width,
        height,
        0,
    )
    .0
}

/// The menu rows, and whether some choices are scrolled out of view, at a `density` that is 2 to
/// drop the blank row after each choice and 3 to also keep only the selected description.
#[allow(clippy::too_many_arguments)]
fn menu_view(
    choices: &[&str],
    descriptions: &[&str],
    selected: Option<usize>,
    default: Option<usize>,
    typed: &str,
    width: usize,
    height: usize,
    density: u8,
) -> (Vec<String>, bool) {
    let build = |budget: usize| -> Vec<Vec<String>> {
        choices
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let marker = if selected == Some(index) { ">" } else { " " };
                let suffix = if default == Some(index) {
                    " (default)"
                } else {
                    ""
                };
                let mut block = wrap_line(&format!("{marker} {label}{suffix}"), 2, width);
                if let Some(description) = descriptions
                    .get(index)
                    .filter(|text| !text.is_empty() && (density < 3 || selected == Some(index)))
                {
                    block.extend(wrap_line(description, 6, width));
                }
                if density < 2 {
                    block.push(String::new());
                }
                if block.len() > budget {
                    block.truncate(budget);
                    if budget > 1 {
                        block[budget - 1] = "      …".to_string();
                    }
                }
                block
            })
            .collect()
    };
    // When every choice fits, the rows kept for the `1-2 of 3` line are not needed.
    let typed_rows = if choices.is_empty() || !typed.is_empty() {
        2
    } else {
        0
    };
    let everything = height.saturating_sub(1 + typed_rows);
    let mut blocks = build(usize::MAX);
    let fits = blocks.iter().map(Vec::len).sum::<usize>() <= everything;
    if height < 5 && !fits {
        let mut lines = Vec::new();
        if !choices.is_empty() {
            let index = selected.unwrap_or(0);
            let marker = if selected.is_some() { ">" } else { " " };
            let suffix = if default == Some(index) {
                " (default)"
            } else {
                ""
            };
            lines.push(format!("  {marker} {}{suffix}", choices[index]));
        }
        if choices.is_empty() || !typed.is_empty() {
            lines.push(format!("  > {typed}"));
        }
        let lines = lines
            .into_iter()
            .map(|line| fit_line(&line, width))
            .collect();
        return (lines, choices.len() > 1);
    }
    let budget = if fits {
        everything
    } else {
        let budget = height.saturating_sub(2 + typed_rows).max(1);
        blocks = build(budget);
        budget
    };
    let mut first = selected.unwrap_or(0);
    let mut last = (first + 1).min(blocks.len());
    let mut used = blocks.get(first).map_or(0, Vec::len);
    while first > 0 && used + blocks[first - 1].len() <= budget {
        first -= 1;
        used += blocks[first].len();
    }
    while last < blocks.len() && used + blocks[last].len() <= budget {
        used += blocks[last].len();
        last += 1;
    }
    let mut lines: Vec<String> = blocks[first..last].iter().flatten().cloned().collect();
    let windowed = first > 0 || last < blocks.len();
    if windowed {
        lines.push(format!("  {}-{} of {}", first + 1, last, choices.len()));
    }
    if choices.is_empty() || !typed.is_empty() {
        lines.push(format!("  > {typed}"));
        lines.push(String::new());
    }
    let lines = lines
        .into_iter()
        .map(|line| fit_line(&line, width))
        .collect();
    (lines, windowed)
}

fn clear_menu(terminal: &mut Terminal<'_>, rows: usize) -> io::Result<()> {
    if rows > 0 {
        write!(terminal.output, "\r")?;
        if rows > 1 {
            write!(terminal.output, "\x1b[{}A", rows - 1)?;
        }
        for index in 0..rows {
            write!(terminal.output, "\x1b[2K")?;
            if index + 1 < rows {
                writeln!(terminal.output)?;
            }
        }
        if rows > 1 {
            write!(terminal.output, "\x1b[{}A", rows - 1)?;
        }
        write!(terminal.output, "\r")?;
    }
    Ok(())
}

fn entry_text(text: &str, columns: usize) -> &str {
    let mut start = text.len();
    let mut used = 0;
    for (index, grapheme) in text.grapheme_indices(true).rev() {
        used += Span::raw(grapheme).width();
        if used > columns {
            break;
        }
        start = index;
    }
    &text[start..]
}

fn entry_cursor(lines: &[String]) -> Option<(usize, usize)> {
    lines
        .iter()
        .rposition(|line| line.starts_with("  > "))
        .map(|row| (row, Span::raw(&lines[row]).width()))
}

fn select(
    terminal: &mut Terminal<'_>,
    choices: &[&str],
    descriptions: &[&str],
    default: Option<usize>,
    labeled: bool,
    mode: Mode,
) -> Result<Option<String>, Error> {
    let result = select_choice(terminal, choices, descriptions, default, labeled, mode);
    // A guided session shows the cursor again in `finish`, so it stays hidden between questions.
    if terminal.choice_controls && terminal.session.is_none() {
        let _ = write!(terminal.output, "\x1b[?25h").and_then(|()| terminal.output.flush());
    }
    result
}

fn select_choice(
    terminal: &mut Terminal<'_>,
    choices: &[&str],
    descriptions: &[&str],
    default: Option<usize>,
    labeled: bool,
    mode: Mode,
) -> Result<Option<String>, Error> {
    let name_entry = mode == Mode::Name;
    let filter = mode == Mode::Filter;
    let saved = if let Some(session) = &mut terminal.session {
        let question = format!(
            "{:?}|{choices:?}|{descriptions:?}|{default:?}",
            session.details
        );
        let saved = session.saved(&question);
        session.pending_question = Some(question);
        if session.cursor < session.active
            && let Some(answer) = saved
        {
            return Ok(Some(answer));
        }
        saved
    } else {
        None
    };
    let mut raw = terminal
        .choice_controls
        .then(RawInput::new)
        .transpose()
        .map_err(|source| io_error("configure", Path::new("stdin"), source))?;
    let write_error = |source| io_error("write", Path::new("stderr"), source);
    let saved_index = saved.as_deref().and_then(|answer| {
        if name_entry {
            answer
                .strip_prefix('\0')
                .and_then(|name| choices.iter().position(|choice| *choice == name))
        } else if filter {
            choices.iter().position(|choice| *choice == answer)
        } else {
            answer
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1))
                .filter(|index| *index < choices.len())
        }
    });
    let mut selected = saved_index
        .or(default)
        .or_else(|| (!name_entry && !choices.is_empty()).then_some(0));
    let mut moved = saved_index.is_some();
    let revisited = saved.is_some();
    let mut typed = saved
        .filter(|answer| !answer.is_empty() && saved_index.is_none())
        .unwrap_or_default()
        .into_bytes();
    let mut drawn = 0;
    let mut previous_size = None;
    let mut scroll = 0usize;
    let mut notice = String::new();
    let labels: Vec<String> = choices
        .iter()
        .enumerate()
        .map(|(index, label)| {
            if name_entry {
                format!("✓ {label}")
            } else if filter {
                label.to_string()
            } else if terminal.session.is_some() || labeled {
                format!("[{}] {label}", index + 1)
            } else {
                label.to_string()
            }
        })
        .collect();
    let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
    // In a filter, `selected` indexes the choices that hold the typed text.
    // A saved answer that is no suggestion comes back as typed text, with nothing selected.
    // A revisited filter shows the answer it took as the typed text, the default included.
    if filter
        && revisited
        && typed.is_empty()
        && let Some(index) = selected
    {
        typed = choices[index].as_bytes().to_vec();
    }
    let mut refilter = filter && !typed.is_empty();
    let top = std::cell::Cell::new(selected.unwrap_or(0));
    loop {
        let shown: Vec<usize> = if filter {
            matching(choices, std::str::from_utf8(&typed).unwrap_or_default())
        } else {
            (0..choices.len()).collect()
        };
        if refilter {
            selected = if typed.is_empty() {
                default.or(Some(0))
            } else {
                (!shown.is_empty()).then_some(0)
            };
            top.set(selected.unwrap_or(0));
            refilter = false;
        }
        let shown_labels: Vec<&str> = shown.iter().map(|index| labels[*index]).collect();
        let shown_default = default.and_then(|default| shown.iter().position(|i| *i == default));
        let (width, height) = if terminal.choice_controls {
            size().map_err(|source| io_error("read size", Path::new("stderr"), source))?
        } else {
            (80, 40)
        };
        if terminal.session.is_none()
            && terminal.content.is_none()
            && previous_size.is_some_and(|size| size != (width, height))
        {
            writeln!(terminal.output).map_err(write_error)?;
            drawn = 0;
        }
        previous_size = Some((width, height));
        if terminal.content.is_some() {
            write!(terminal.output, "\x1b[H\x1b[J").map_err(write_error)?;
        } else if terminal.session.is_none() {
            clear_menu(terminal, drawn).map_err(write_error)?;
        }
        let content = terminal
            .content
            .as_ref()
            .map(|text| content_lines(text, width));
        let content_room = content.as_ref().map_or(0, |lines| {
            let descriptions = descriptions
                .iter()
                .map(|text| wrap_line(text, 6, width).len())
                .sum::<usize>();
            height
                .saturating_sub(
                    (choices.len() * 2 + descriptions + 3)
                        .min(height.saturating_sub(3))
                        .max(3),
                )
                .min(lines.len())
        });
        if let Some(content) = &content {
            scroll = scroll.min(content.len().saturating_sub(content_room));
        }
        let input_text = std::str::from_utf8(&typed).unwrap_or_else(|error| {
            std::str::from_utf8(&typed[..error.valid_up_to()]).expect("valid UTF-8 prefix")
        });
        let text = entry_text(input_text, width.saturating_sub(5));
        let entering = if filter {
            true
        } else if name_entry {
            selected.is_none()
        } else {
            choices.is_empty() || !typed.is_empty()
        };
        let mut cursor = None;
        // A filter lays out only the rows it draws, so the header keeps its blank rows.
        let ask = Choices {
            labels: if filter {
                &labels[..labels.len().min(FILTER_ROWS)]
            } else {
                &labels
            },
            descriptions,
            selected: if filter { None } else { selected },
            default: if name_entry {
                None
            } else {
                default.filter(|_| labeled)
            },
            typed: if name_entry || filter { "" } else { text },
            name_entry: name_entry || filter,
        };
        // A filter draws its entry first, then as many matches as the rows that the full list gets
        // in this terminal, so the rows stay put while the list narrows.
        let filtered = |room: usize| {
            let room = room.clamp(1, FILTER_ROWS);
            let mut rows = vec![fit_line(&format!("  > {text}"), width)];
            if shown.is_empty() {
                rows.push(fit_line("      No match", width));
            } else {
                // The list opens at the selected match and scrolls only when it leaves view.
                let at = selected.unwrap_or(0);
                let mut first = top.get().min(at);
                if at >= first + room {
                    first = at + 1 - room;
                }
                let first = first.min(shown.len().saturating_sub(room));
                top.set(first);
                for (offset, label) in shown_labels.iter().enumerate().skip(first).take(room) {
                    let marker = if selected == Some(offset) { "›" } else { " " };
                    let suffix = if shown_default == Some(offset) {
                        " (default)"
                    } else {
                        ""
                    };
                    rows.push(fit_line(&format!("    {marker} {label}{suffix}"), width));
                }
            }
            rows.resize(room + 2, String::new());
            rows
        };
        let (section, mut lines, room, scrollable) = if let Some(session) = &terminal.session {
            let layout = guided_layout(session, &ask, width, height, scroll);
            let menu = if filter {
                filtered(layout.menu.len())
            } else {
                layout.menu
            };
            (Some(layout.section), menu, layout.room, layout.cut)
        } else {
            let rows = height.saturating_sub(content_room + usize::from(content.is_some()));
            let menu = choice_rows(&ask, width, rows, 0).0;
            let menu = if filter { filtered(menu.len()) } else { menu };
            (None, menu, 0, false)
        };
        if name_entry {
            let marker = if selected.is_none() { ">" } else { " " };
            lines.push(fit_line(&format!("  {marker} {text}"), width));
            lines.push(String::new());
        }
        if let Some(mut section) = section {
            let mut lines = lines;
            if height < 7 {
                section.remove(0);
                section.truncate(2);
                let row = if entering {
                    entry_cursor(&lines).map_or(0, |(row, _)| row)
                } else {
                    0
                };
                lines = vec![lines.get(row).cloned().unwrap_or_default()];
            }
            section.append(&mut lines);
            let feedback = &terminal.session.as_ref().unwrap().feedback;
            let back = terminal.can_go_back || terminal.session.as_ref().unwrap().cursor > 0;
            let hint = if filter && width >= 72 {
                format!(
                    "  Type to filter  ↑↓ choose  Tab/Enter pick  Esc {}  Ctrl+C exit",
                    if back { "back" } else { "exit" }
                )
            } else if name_entry && !choices.is_empty() {
                if width >= 72 {
                    format!(
                        "  ↑↓ edit existing  Type a new name  Enter  Esc {}  Ctrl+C exit",
                        if back { "back" } else { "exit" }
                    )
                } else {
                    key_hint(width, false, scrollable, true, back)
                }
            } else {
                key_hint(width, true, scrollable, !choices.is_empty(), back)
            };
            section.push(fit_line(
                if !feedback.is_empty() {
                    feedback.lines().next().unwrap_or_default()
                } else if notice.is_empty() {
                    &hint
                } else {
                    &notice
                },
                width,
            ));
            section.truncate(height);
            if entering {
                cursor = entry_cursor(&section);
            }
            draw_section(terminal, section, (width, height)).map_err(write_error)?;
        } else {
            let mut lines = lines;
            lines.push(key_hint(
                width,
                false,
                content
                    .as_ref()
                    .is_some_and(|lines| lines.len() > content_room),
                !choices.is_empty(),
                terminal.can_go_back,
            ));
            if let Some(content) = &content {
                lines.splice(
                    0..0,
                    content
                        .iter()
                        .skip(scroll)
                        .take(content_room)
                        .cloned()
                        .chain(std::iter::once(String::new())),
                );
            }
            lines.truncate(height);
            drawn = lines.len();
            if entering {
                cursor = entry_cursor(&lines);
            }
            for (index, line) in lines.iter().enumerate() {
                let code = if line.starts_with("  > ") {
                    BOLD_ACCENT
                } else {
                    "2"
                };
                if index < content_room {
                    write!(terminal.output, "{line}").map_err(write_error)?;
                } else if terminal.choice_color
                    && (line.starts_with("  > ") || !line.contains("] "))
                {
                    write!(terminal.output, "\x1b[{code}m{line}\x1b[0m").map_err(write_error)?;
                } else {
                    write!(terminal.output, "{line}").map_err(write_error)?;
                }
                if index + 1 < drawn {
                    writeln!(terminal.output).map_err(write_error)?;
                }
            }
        }
        write!(terminal.output, "\x1b7").map_err(write_error)?;
        if let Some((row, column)) = cursor {
            let rows = terminal
                .session
                .as_ref()
                .map_or(drawn, |session| session.drawn.len());
            let up = rows - row - 1;
            if up > 0 {
                write!(terminal.output, "\x1b[{up}A").map_err(write_error)?;
            }
            write!(terminal.output, "\r\x1b[{column}C\x1b[?25h").map_err(write_error)?;
        } else {
            write!(terminal.output, "\x1b[?25l").map_err(write_error)?;
        }
        terminal.output.flush().map_err(write_error)?;
        let key = key(terminal.input, raw.as_mut());
        // Keep the cursor hidden while the next frame is drawn. It is shown again only for typed
        // entries, or when the prompt ends.
        write!(terminal.output, "\x1b8\x1b[?25l").map_err(write_error)?;
        let key = key.map_err(|source| io_error("read", Path::new("stdin"), source))?;
        match key {
            Key::Cancel => {
                if let Some(session) = &mut terminal.session {
                    session.step(-1);
                }
                if terminal.session.is_none() {
                    clear_menu(terminal, drawn).map_err(write_error)?;
                }
                return Ok(None);
            }
            Key::Exit => {
                if terminal.session.is_none() {
                    clear_menu(terminal, drawn).map_err(write_error)?;
                }
                return Err(Error::Interrupted);
            }
            key @ (Key::Enter | Key::Tab) if filter || matches!(key, Key::Enter) => {
                let line = if name_entry && let Some(index) = selected {
                    format!("\0{}", choices[index])
                } else if filter {
                    let Some(index) = selected else {
                        notice = "  No match. Pick one from the list.".to_string();
                        continue;
                    };
                    choices[shown[index]].to_string()
                } else if !typed.is_empty() {
                    String::from_utf8(typed)
                        .map_err(|source| {
                            io_error(
                                "read",
                                Path::new("stdin"),
                                io::Error::new(io::ErrorKind::InvalidData, source),
                            )
                        })?
                        .trim()
                        .to_string()
                } else if moved || default.is_none() {
                    selected
                        .map(|index| (index + 1).to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                if terminal.session.is_some() {
                    return Ok(Some(line));
                }
                let chosen = if line.is_empty() {
                    default
                } else if filter {
                    None
                } else {
                    line.parse::<usize>()
                        .ok()
                        .and_then(|number| number.checked_sub(1))
                }
                .and_then(|index| choices.get(index))
                .copied()
                .unwrap_or(&line);
                clear_menu(terminal, drawn).map_err(write_error)?;
                let chosen = fit_line(&format!("  › {chosen}"), width);
                if terminal.choice_color {
                    writeln!(
                        terminal.output,
                        "\x1b[{}m{chosen}\x1b[0m\n",
                        crate::Report::ACCENT
                    )
                    .map_err(write_error)?;
                } else {
                    writeln!(terminal.output, "{chosen}\n").map_err(write_error)?;
                }
                return Ok(Some(line));
            }
            Key::Left | Key::Right | Key::Tab | Key::BackTab if terminal.session.is_some() => {
                let session = terminal.session.as_mut().unwrap();
                let back = matches!(key, Key::Left | Key::BackTab);
                let direction = if back { -1 } else { 1 };
                let moved = if matches!(key, Key::Tab | Key::BackTab) {
                    session.navigate(direction)
                } else {
                    session.step(direction)
                };
                if moved {
                    return Ok(None);
                }
                notice = if back {
                    "  Already at the first question."
                } else if session.stage == REVIEW {
                    "  Choose an action, then Enter."
                } else {
                    "  Enter confirms this answer first."
                }
                .to_string();
            }
            Key::PageUp | Key::PageDown if terminal.session.is_some() => {
                let last = detail_lines(terminal.session.as_ref().unwrap(), width)
                    .len()
                    .saturating_sub(room);
                let step = room.min(3);
                scroll = if matches!(key, Key::PageUp) {
                    scroll.saturating_sub(step)
                } else {
                    scroll.saturating_add(step).min(last)
                };
                notice.clear();
            }
            Key::PageUp | Key::PageDown if content.is_some() => {
                let last = content.as_ref().unwrap().len().saturating_sub(content_room);
                let step = content_room.saturating_sub(1).max(1);
                scroll = if matches!(key, Key::PageUp) {
                    scroll.saturating_sub(step)
                } else {
                    scroll.saturating_add(step).min(last)
                };
            }
            Key::Up | Key::Down if filter => {
                let count = shown.len();
                if count > 0 {
                    let at = selected.unwrap_or(0);
                    selected = Some(if matches!(key, Key::Up) {
                        (at + count - 1) % count
                    } else {
                        (at + 1) % count
                    });
                }
            }
            Key::Up | Key::Down if !choices.is_empty() => {
                if name_entry {
                    selected = match (selected, key) {
                        (Some(0), Key::Up) => None,
                        (Some(index), Key::Up) => Some(index - 1),
                        (Some(index), _) if index + 1 == choices.len() => None,
                        (Some(index), _) => Some(index + 1),
                        (None, Key::Up) => Some(choices.len() - 1),
                        (None, _) => Some(0),
                    };
                    continue;
                }
                selected = Some(match (selected, key) {
                    (Some(index), Key::Up) => (index + choices.len() - 1) % choices.len(),
                    (Some(index), _) => (index + 1) % choices.len(),
                    (None, Key::Up) => choices.len() - 1,
                    (None, _) => 0,
                });
                typed.clear();
                moved = true;
            }
            Key::Backspace => {
                if name_entry {
                    selected = None;
                }
                refilter = filter;
                notice.clear();
                while typed.pop().is_some_and(|byte| byte & 0xc0 == 0x80) {}
            }
            Key::Byte(byte) => {
                if name_entry {
                    selected = None;
                }
                refilter = filter;
                notice.clear();
                typed.push(byte);
            }
            Key::Enter
            | Key::Ignore
            | Key::Left
            | Key::Right
            | Key::Tab
            | Key::BackTab
            | Key::Up
            | Key::Down
            | Key::PageUp
            | Key::PageDown => {}
        }
    }
}

enum Key {
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    PageUp,
    PageDown,
    Enter,
    Backspace,
    Cancel,
    Exit,
    Byte(u8),
    Ignore,
}

fn byte(input: &mut dyn BufRead) -> io::Result<Option<u8>> {
    let mut buffer = [0];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(buffer[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn key(input: &mut dyn BufRead, mut raw: Option<&mut RawInput>) -> io::Result<Key> {
    Ok(match byte(input)? {
        None | Some(3 | 4) => Key::Exit,
        Some(b'\r' | b'\n') => Key::Enter,
        Some(8 | 127) => Key::Backspace,
        Some(b'\t') => Key::Tab,
        Some(27) => {
            if let Some(raw) = raw.as_deref_mut() {
                raw.timeout(true)?;
            }
            let result = escape(input);
            if let Some(raw) = raw {
                raw.timeout(false)?;
            }
            result?
        }
        Some(0..=31) => Key::Ignore,
        Some(byte) => Key::Byte(byte),
    })
}

fn escape(input: &mut dyn BufRead) -> io::Result<Key> {
    if !matches!(byte(input)?, Some(b'[' | b'O')) {
        return Ok(Key::Cancel);
    }
    let mut parameter = Vec::new();
    for _ in 0..16 {
        match byte(input)? {
            Some(b'A') => return Ok(Key::Up),
            Some(b'B') => return Ok(Key::Down),
            Some(b'C') => return Ok(Key::Right),
            Some(b'D') => return Ok(Key::Left),
            Some(b'Z') => return Ok(Key::BackTab),
            Some(b'~') if parameter == b"5" => return Ok(Key::PageUp),
            Some(b'~') if parameter == b"6" => return Ok(Key::PageDown),
            Some(0x40..=0x7e) => return Ok(Key::Ignore),
            None => return Ok(Key::Cancel),
            Some(byte) => parameter.push(byte),
        }
    }
    Ok(Key::Cancel)
}

struct RawInput {
    saved: Termios,
    current: Termios,
}

impl RawInput {
    fn new() -> io::Result<Self> {
        let saved = termios::tcgetattr(io::stdin())?;
        let mut current = saved.clone();
        termios::cfmakeraw(&mut current);
        current.input_flags = saved.input_flags;
        current.output_flags = saved.output_flags;
        current.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        current.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &current)?;
        Ok(Self { saved, current })
    }

    fn timeout(&mut self, enabled: bool) -> io::Result<()> {
        self.current.control_chars[SpecialCharacterIndices::VMIN as usize] = u8::from(!enabled);
        self.current.control_chars[SpecialCharacterIndices::VTIME as usize] = u8::from(enabled);
        termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.current)?;
        Ok(())
    }
}

impl Drop for RawInput {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_cursor_tracks_the_input_and_restores_after_choice_navigation() {
        for names in [&[][..], &["existing"][..]] {
            let typed = format!("{}東京e\u{301}", "a".repeat(90));
            let keys = format!("{typed}\x1b[A\x1b[B\x7f\x1b");
            let mut input = keys.as_bytes();
            let mut output = Vec::new();
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.session = Some(Session {
                details: "Choose a name\n\n".to_string(),
                ..Session::default()
            });
            if names.is_empty() {
                assert!(text(&mut terminal).unwrap().is_none());
            } else {
                assert!(profile_name(&mut terminal, names, &[]).unwrap().is_none());
            }
            let output = String::from_utf8(output).unwrap();
            let mut parser = vt100::Parser::new(40, 80, 0);
            let mut seen = false;
            for frame in output
                .split("\x1b8")
                .filter(|frame| frame.contains("\x1b7"))
            {
                parser.process(frame.replace('\n', "\r\n").as_bytes());
                let screen = parser.screen();
                if !screen.hide_cursor() {
                    let (row, column) = screen.cursor_position();
                    let line = screen.contents_between(row, 0, row, 79);
                    assert!(line.starts_with("  > "), "{row},{column}: {line:?}");
                    assert_eq!(
                        usize::from(column),
                        Span::raw(&line).width().max(4),
                        "{line:?}: {frame:?}"
                    );
                    assert!(column < 80);
                    seen = true;
                }
                parser.process(b"\x1b8");
            }
            assert!(seen);
        }
    }

    #[test]
    fn panel_content_scrolls_without_hiding_actions() {
        let content = (0..100)
            .map(|index| format!("profile-{index:03}\n"))
            .collect::<String>();
        let keys = format!("{}\x1b[B\r", "\x1b[6~".repeat(5));
        let mut input = keys.as_bytes();
        let mut output = Vec::new();
        let mut terminal = Terminal::new(&mut input, &mut output);
        terminal.content = Some(content);
        assert_eq!(
            act(&mut terminal, &["Back", "Exit"], &[], 0)
                .unwrap()
                .as_deref(),
            Some("2")
        );
        let output = String::from_utf8(output).unwrap();
        let mut reached_end = false;
        for frame in output.split("\x1b[H\x1b[J").skip(1).take(5) {
            let mut parser = vt100::Parser::new(40, 80, 0);
            parser.process(frame.replace('\n', "\r\n").as_bytes());
            let screen = parser.screen();
            let text = screen.contents();
            assert!(text.contains("> Back") && text.contains("Exit"), "{text}");
            reached_end |= text.contains("profile-099");
        }
        assert!(reached_end, "all content must remain reachable");
    }

    #[test]
    fn escape_revisits_the_previous_answer_but_interrupt_and_eof_exit() {
        for keys in [b"\x1b".as_slice(), b"\x03", b"\x04", b""] {
            let mut input = keys;
            let mut output = Vec::new();
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.session = Some(Session {
                answers: vec![("Agent".into(), "2".into())],
                cursor: 1,
                active: 1,
                ..Session::default()
            });
            let result = choose(&mut terminal, &["Open", "Project"], None);
            let session = terminal.session.as_ref().unwrap();
            if keys == b"\x1b" {
                assert_eq!(result.unwrap(), None);
                assert!(session.navigating, "Esc must revisit the previous answer");
                assert_eq!(session.active, 0);
            } else {
                assert!(result.is_err(), "Interrupt and EOF must exit: {keys:?}");
                assert!(!session.navigating);
            }
            assert_eq!(session.answers, [("Agent".into(), "2".into())]);
        }
    }

    #[test]
    fn name_entry_selects_existing_profiles_without_losing_typed_names() {
        for (keys, expected) in [
            ("\x1b[A\r", Some("\0work")),
            ("\x1b[A\x1b[A\r", Some("\0personal")),
            ("new\x1b[A\x1b[B\r", Some("new")),
            ("2\r", Some("2")),
            ("/work\r", Some("/work")),
            ("\x1b[Aother\r", Some("other")),
            ("\x1b[A\x1b", None),
        ] {
            let mut input = keys.as_bytes();
            let mut output = Vec::new();
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.session = Some(Session::default());
            assert_eq!(
                profile_name(&mut terminal, &["personal", "work"], &[])
                    .unwrap()
                    .as_deref(),
                expected
            );
        }
    }

    #[test]
    fn review_wraps_labels_and_values_in_separate_columns() {
        for width in [24, 80, 120] {
            for (label, value, column) in [
                (
                    "Packs",
                    "@box/claude, @box/bedrock, @box/cargo, @box/git, @box/node, @box/npm, @box/pnpm, @box/yarn",
                    14,
                ),
                (
                    "claude.instructions",
                    "A long instruction with 東京 and e\u{301} that continues on another line.",
                    23,
                ),
            ] {
                let session = Session {
                    stage: REVIEW,
                    details: format!("  {label:<padding$}  {value}", padding = column - 4),
                    ..Session::default()
                };
                let lines = detail_lines(&session, width);
                let value_column = column.min(width / 2);
                let mut actual_labels = String::new();
                let mut actual_values = String::new();
                for line in lines {
                    assert!(Span::raw(&line).width() < width, "{line:?}");
                    actual_labels.push_str(line[..value_column].trim());
                    actual_values.push_str(&line[value_column..]);
                }
                assert_eq!(actual_labels, label);
                let compact = |s: &str| s.split_whitespace().collect::<String>();
                assert_eq!(compact(&actual_values), compact(value));
            }
        }
    }

    #[test]
    fn navigation_keys_do_not_confirm_answers_and_replays_do_not_consume_input() {
        fn ask(terminal: &mut Terminal<'_>, stage: usize) -> Option<String> {
            terminal.stage("demo", stage + SETUP);
            terminal.question(["Provider", "Policy", "Save?"][stage]);
            let (choices, default): (&[&str], _) = match stage {
                0 => (&["First", "Second"], None),
                1 => (&["Open", "Project"], Some(1)),
                _ => (&["Save"], Some(0)),
            };
            let answer = choose(terminal, choices, default).unwrap();
            if let Some(answer) = &answer {
                terminal.session.as_mut().unwrap().accept(answer.clone());
            }
            answer
        }
        let mut input = b"\t2\r\r\x1b[Z\t\x1b[Z\r\t\x1b".as_slice();
        let mut output = Vec::new();
        let mut terminal = Terminal::new(&mut input, &mut output);
        terminal.session = Some(Session::default());
        assert_eq!(ask(&mut terminal, 0).as_deref(), Some("2"));
        assert_eq!(ask(&mut terminal, 1).as_deref(), Some(""));
        assert_eq!(ask(&mut terminal, 2), None);
        assert!(terminal.session.as_ref().unwrap().navigating);
        terminal.session.as_mut().unwrap().restart();
        assert_eq!(ask(&mut terminal, 0).as_deref(), Some("2"));
        assert_eq!(ask(&mut terminal, 1), None);
        assert!(
            terminal.session.as_ref().unwrap().navigating,
            "Tab returns to visited Review"
        );
        terminal.session.as_mut().unwrap().restart();
        assert_eq!(ask(&mut terminal, 0).as_deref(), Some("2"));
        assert_eq!(ask(&mut terminal, 1).as_deref(), Some(""));
        assert_eq!(ask(&mut terminal, 2), None);
        terminal.session.as_mut().unwrap().restart();
        assert_eq!(ask(&mut terminal, 0).as_deref(), Some("2"));
        assert_eq!(ask(&mut terminal, 1).as_deref(), Some(""));
        assert_eq!(ask(&mut terminal, 2), None);
        assert!(
            terminal.session.as_ref().unwrap().navigating,
            "Esc at Review goes back to Policy"
        );
        assert_eq!(terminal.session.as_ref().unwrap().active, 1);
        assert_eq!(terminal.session.as_ref().unwrap().answers.len(), 2);
        let mut resume = b"\r".as_slice();
        terminal.input = &mut resume;
        terminal.session.as_mut().unwrap().edit_setup();
        terminal.session.as_mut().unwrap().restart();
        assert_eq!(ask(&mut terminal, 0).as_deref(), Some("2"));
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("  > [2] Second")
        );
    }

    #[test]
    fn inline_sections_only_rewrite_changed_rows_and_scroll_all_details() {
        let mut output = Vec::new();
        let mut input = b"".as_slice();
        {
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.session = Some(Session::default());
            draw_section(
                &mut terminal,
                vec!["title".into(), "old choice".into()],
                (80, 24),
            )
            .unwrap();
            draw_section(
                &mut terminal,
                vec!["title".into(), "new choice".into()],
                (80, 24),
            )
            .unwrap();
            draw_section(
                &mut terminal,
                vec!["title".into(), "new choice".into()],
                (80, 24),
            )
            .unwrap();
        }
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("\x1b[2K").count(), 3);
        assert_eq!(output.matches("title").count(), 1);
        assert_eq!(output.matches("\x1b[1A").count(), 2);
        assert!(!output.contains("\x1b[2J"));
        let mut output = Vec::new();
        {
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.session = Some(Session::default());
            draw_section(
                &mut terminal,
                vec!["title".into(), "choice".into()],
                (24, 8),
            )
            .unwrap();
            draw_section(
                &mut terminal,
                vec!["title".into(), "choice".into()],
                (80, 24),
            )
            .unwrap();
        }
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("title").count(), 2);
        assert!(
            !output.contains("\x1b[1A"),
            "resize must not erase rows whose position changed during reflow"
        );
        let session = Session {
            details: "First warning\nSecond warning\nLast warning".into(),
            ..Session::default()
        };
        for width in [24, 40, 80] {
            let first = section_lines(&session, width, 3, 0, blank_rows(3, false)).lines;
            let last = section_lines(&session, width, 3, usize::MAX, blank_rows(3, false)).lines;
            assert!(first.iter().any(|line| line.contains("First warning")));
            assert!(last.iter().any(|line| line.contains("Last warning")));
            assert!(
                first
                    .iter()
                    .chain(&last)
                    .all(|line| Span::raw(line).width() < width)
            );
            assert!(first.len() <= 3 && last.len() <= 3);
        }
        let keys = format!("{}{}\x1b", "\x1b[6~".repeat(30), "\x1b[5~".repeat(30));
        let mut input = keys.as_bytes();
        let mut output = Vec::new();
        let mut terminal = Terminal::new(&mut input, &mut output);
        terminal.session = Some(Session {
            details: (0..50).map(|index| format!("Warning {index}\n")).collect(),
            ..Session::default()
        });
        assert_eq!(
            choose(&mut terminal, &["Yes", "No"], Some(1)).unwrap(),
            None
        );
        assert!(
            terminal
                .session
                .as_ref()
                .unwrap()
                .drawn
                .iter()
                .any(|line| line.contains("Warning 0"))
        );
        assert!(String::from_utf8(output).unwrap().contains("Warning 49"));
    }

    #[test]
    fn section_navigation_replays_confirmed_answers_and_invalidates_changed_dependents() {
        let mut session = Session::default();
        session.sections[0] = Some(0);
        session.pending_question = Some("provider".into());
        session.accept("1".into());
        session.pending_question = Some("region".into());
        session.accept("us-east-1".into());
        session.stage = 1;
        session.sections[1] = Some(2);
        assert!(
            !session.navigate(1),
            "Right cannot bypass an unanswered policy"
        );
        assert!(session.navigate(-1));
        session.restart();
        assert_eq!(session.cursor, 0);
        assert_eq!(session.active, 0);
        assert_eq!(session.saved("provider").as_deref(), Some("1"));
        session.pending_question = Some("provider".into());
        session.accept("1".into());
        assert_eq!(
            session.answers.len(),
            2,
            "unchanged answers retain later inputs"
        );
        session.cursor = 0;
        session.pending_question = Some("provider".into());
        session.accept("2".into());
        assert_eq!(session.sections[1], None, "a change reopens later sections");
    }

    #[test]
    fn guided_menus_fit_small_terminals_and_keep_the_selected_choice_visible() {
        for height in [4, 5, 8, 9] {
            let lines = menu_lines(
                &["Keep", "Remove"],
                &["Cancel without changes.", "Delete the items listed above."],
                Some(0),
                Some(0),
                "y",
                80,
                height,
            );
            assert!(
                lines.len() < height,
                "input and keyboard help must fit: {height}: {lines:?}"
            );
        }
        let choices = [
            "[1] First",
            "[2] Second",
            "[3] Third",
            "[4] Fourth",
            "[5] Fifth",
            "[6] Sixth",
            "[7] Last",
        ];
        let unselected = menu_lines(&choices, &[], None, None, "", 24, 8);
        assert!(unselected.iter().any(|line| line.contains("[1] First")));
        assert!(!unselected.iter().any(|line| line.contains("> [1]")));
        assert!(
            menu_lines(&["Yes", "No"], &[], Some(1), Some(1), "", 24, 8)
                .iter()
                .any(|line| line.contains("No (default)"))
        );
        for (width, height) in [(24, 4), (24, 10), (50, 14), (80, 24), (120, 40)] {
            let lines = menu_lines(
                &choices,
                &["A description"; 7],
                Some(6),
                Some(0),
                "",
                width,
                height,
            );
            assert!(lines.len() <= height, "{width}x{height}: {lines:?}");
            assert!(
                lines.iter().any(|line| line.contains("> [7] Last")),
                "{lines:?}"
            );
            assert!(lines.iter().all(|line| Span::raw(line).width() < width));
        }
    }

    #[test]
    fn text_answers_support_editing_and_cancel_without_selecting_a_choice() {
        for (keys, answer) in [
            (b"us-east-2\x7f1\r".as_slice(), Some("us-east-1")),
            (b"\x1b[B\r", Some("")),
            (b"\x1b", None),
            (b"\x03", None),
        ] {
            let mut input = keys;
            let mut output = Vec::new();
            let result = text(&mut Terminal::new(&mut input, &mut output));
            if keys == b"\x03" {
                assert!(matches!(result, Err(Error::Interrupted)));
            } else {
                assert_eq!(result.unwrap().as_deref(), answer);
            }
        }
    }

    #[test]
    fn the_cursor_stays_hidden_while_a_guided_question_redraws() {
        let mut input = b"\x1b[B\x1b[A\x1b[B\r".as_slice();
        let mut output = Vec::new();
        let mut terminal = Terminal::new(&mut input, &mut output);
        terminal.session = Some(Session::default());
        let answer = choose(&mut terminal, &["One", "Two", "Three"], Some(0)).unwrap();
        assert_eq!(answer.as_deref(), Some("2"));
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("\x1b[?25h"), "{output:?}");
        assert_eq!(output.matches("\x1b8\x1b[?25l").count(), 4, "{output:?}");
    }

    const LABELS: [&str; 3] = ["[1] Open", "[2] Scoped", "[3] Locked"];
    const DESCRIPTIONS: [&str; 3] = [
        "Any command, any host.",
        "Only what the packs allow.",
        "Read the project, change nothing.",
    ];

    fn question(stage: usize, warnings: usize) -> Session {
        let mut details = String::from("Which policy should the agent start with?\n\n");
        for index in 0..warnings {
            details.push_str(&format!(
                "! Warning {index} is long enough to take a second row on a narrow terminal.\n"
            ));
        }
        Session {
            stage,
            details,
            ..Session::default()
        }
    }

    fn layout(session: &Session, width: usize, height: usize) -> Layout {
        let ask = Choices {
            labels: &LABELS,
            descriptions: &DESCRIPTIONS,
            selected: Some(0),
            default: Some(0),
            typed: "",
            name_entry: false,
        };
        guided_layout(session, &ask, width, height, 0)
    }

    #[test]
    fn a_guided_question_shows_every_choice_and_fits_the_terminal() {
        for width in [60, 80, 120] {
            for height in 10..=40 {
                let mut title_rows = Vec::new();
                for (stage, warnings) in [(POLICY, 0), (SETUP, 4), (REVIEW, 9)] {
                    let layout = layout(&question(stage, warnings), width, height);
                    let case = format!("{width}x{height} stage {stage}: {layout:?}");
                    for label in LABELS {
                        assert!(
                            layout.menu.iter().any(|line| line.contains(label)),
                            "{label} is hidden at {case}"
                        );
                    }
                    assert!(!layout.menu.iter().any(|line| line.contains(" of 3")));
                    assert!(
                        layout.section.len() + layout.menu.len() < height,
                        "the frame and its key hint are taller than the terminal at {case}"
                    );
                    title_rows.push(
                        layout
                            .section
                            .iter()
                            .position(|line| line.contains("Create a new profile")),
                    );
                }
                // The title is on one row for every question, below a blank row when it fits.
                assert!(
                    title_rows.iter().all(|row| *row == title_rows[0]),
                    "{width}x{height}: {title_rows:?}"
                );
                assert_eq!(title_rows[0], Some(usize::from(height >= 12)));
            }
        }
    }

    #[test]
    fn a_guided_question_keeps_its_descriptions_when_the_warnings_overflow_anyway() {
        let layout = layout(&question(SETUP, 30), 80, 24);
        assert!(layout.cut);
        for description in DESCRIPTIONS {
            assert!(
                layout.menu.iter().any(|line| line.contains(description)),
                "{layout:?}"
            );
        }
    }

    #[test]
    fn a_guided_question_shows_every_warning_when_the_choices_leave_room() {
        let session = question(SETUP, 8);
        let tall = layout(&session, 100, 40);
        assert!(!tall.cut, "{tall:?}");
        let short = layout(&session, 100, 14);
        assert!(short.cut, "{short:?}");
        assert!(short.room < tall.room, "{short:?}");
    }

    #[test]
    fn a_guided_question_saves_blank_rows_before_it_hides_choices() {
        let choices = ["[1] Open", "[2] Scoped", "[3] Locked"];
        let descriptions = ["Any command.", "Only what packs allow.", "Read only."];
        let view = |height, density| {
            menu_view(
                &choices,
                &descriptions,
                Some(0),
                None,
                "",
                80,
                height,
                density,
            )
        };
        // Each choice takes 3 rows with its blank row, so 3 choices need 9 rows plus 1 spare row.
        assert!(view(9, 0).1);
        let (lines, hidden) = view(10, 0);
        assert!(!hidden, "{lines:?}");
        assert!(view(6, 2).1);
        let (lines, hidden) = view(7, 2);
        assert!(!hidden, "{lines:?}");
        // Keeping only the selected description needs 4 rows plus 1 spare row.
        let (lines, hidden) = view(5, 3);
        assert!(!hidden, "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("Any command.")));
        assert!(!lines.iter().any(|line| line.contains("Read only.")));
        let session = Session::default();
        let padded = section_lines(&session, 80, 16, 0, blank_rows(16, false)).lines;
        let compact = section_lines(&session, 80, 14, 0, blank_rows(16, true)).lines;
        assert!(compact.len() < padded.len());
        // The title stays on the same row in both layouts.
        let title = |lines: &[String]| lines.iter().position(|line| line.contains("Create a new"));
        assert_eq!(title(&compact), title(&padded));
        assert_eq!(title(&compact), Some(1));
    }

    #[test]
    fn a_boolean_selector_shows_both_answers_and_keeps_the_default_contract() {
        for (keys, expected) in [
            (b"\r".as_slice(), Some("")),
            (b"\x1b[A\r", Some("1")),
            (b"\x1b[B\r", Some("1")),
            (b"2\r", Some("2")),
            (b"yes\r", Some("yes")),
        ] {
            let mut input = keys;
            let mut output = Vec::new();
            let result = choose(
                &mut Terminal::new(&mut input, &mut output),
                &["Yes", "No"],
                Some(1),
            );
            assert_eq!(result.unwrap().as_deref(), expected, "{keys:?}");
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.contains("    [1] Yes") && output.contains("  > [2] No (default)"),
                "{output}"
            );
            assert!(!output.contains("1. true"), "{output}");
        }
    }

    fn answer(input: &[u8], default: Option<usize>) -> Option<String> {
        let mut input = input;
        let mut output = Vec::new();
        choose(
            &mut Terminal::new(&mut input, &mut output),
            &["first", "second", "third"],
            default,
        )
        .expect("a choice")
    }

    #[test]
    fn enter_accepts_the_initial_selection_and_arrows_move_from_it() {
        assert_eq!(answer(b"\n", None).as_deref(), Some("1"));
        assert_eq!(answer(b"\n", Some(1)).as_deref(), Some(""));
        assert_eq!(answer(b"\x1b[B\r", None).as_deref(), Some("2"));
        assert_eq!(answer(b"\x1b[A\r", None).as_deref(), Some("3"));
        assert_eq!(answer(b"\x1b[B\r", Some(1)).as_deref(), Some("3"));
        assert_eq!(answer(b"\x1bOA\r", Some(0)).as_deref(), Some("3"));
    }

    fn suggested(input: &[u8], default: Option<usize>) -> Option<String> {
        let mut input = input;
        let mut output = Vec::new();
        suggest(
            &mut Terminal::new(&mut input, &mut output),
            &["us-east-1", "us-west-2", "eu-west-1", "eu-west-3"],
            default,
        )
        .expect("an answer")
    }

    #[test]
    fn typing_narrows_the_suggestions_and_tab_or_enter_picks_the_highlighted_one() {
        // Enter with nothing typed keeps the default, as other prompts do.
        assert_eq!(suggested(b"\r", Some(1)).as_deref(), Some("us-west-2"));
        assert_eq!(suggested(b"EU\r", Some(1)).as_deref(), Some("eu-west-1"));
        assert_eq!(suggested(b"eu\t", Some(1)).as_deref(), Some("eu-west-1"));
        assert_eq!(
            suggested(b"eu\x1b[B\r", Some(1)).as_deref(),
            Some("eu-west-3")
        );
        assert_eq!(
            suggested(b"west-\x1b[A\r", None).as_deref(),
            Some("eu-west-3")
        );
        assert_eq!(
            suggested(b"eu-wx\x7f\r", None).as_deref(),
            Some("eu-west-1")
        );
        // An unlisted saved value that the caller lists first is what Enter keeps.
        let mut input = b"\r".as_slice();
        let mut output = Vec::new();
        let kept = suggest(
            &mut Terminal::new(&mut input, &mut output),
            &["us-west-9", "us-west-2"],
            Some(0),
        )
        .expect("an answer");
        assert_eq!(kept.as_deref(), Some("us-west-9"));
    }

    #[test]
    fn a_value_that_matches_no_suggestion_is_refused() {
        // Enter with no match keeps asking, so the corrected text answers.
        assert_eq!(
            suggested(b"us-west-9\r\x7f2\r", None).as_deref(),
            Some("us-west-2")
        );
        let mut input = b"us-west-9\r".as_slice();
        let mut output = Vec::new();
        let result = suggest(
            &mut Terminal::new(&mut input, &mut output),
            &["us-west-2"],
            None,
        );
        assert!(matches!(result, Err(Error::Interrupted)));
    }

    #[test]
    fn the_matches_draw_under_the_typed_text() {
        let mut input = b"eu".as_slice();
        let mut output = Vec::new();
        let _ = suggest(
            &mut Terminal::new(&mut input, &mut output),
            &["us-west-2", "eu-west-1", "eu-west-3"],
            None,
        );
        let output = String::from_utf8_lossy(&output);
        let last = output.rsplit("  > eu").next().expect("the typed text");
        assert!(
            last.contains("› eu-west-1") && last.contains("  eu-west-3"),
            "{last}"
        );
        assert!(!last.contains("us-west-2"), "{last}");
    }

    #[test]
    fn typed_choices_can_be_corrected_and_unknown_keys_do_not_choose() {
        assert_eq!(answer(b"12\x7f\r", None).as_deref(), Some("1"));
        assert_eq!(answer(b"second\r", None).as_deref(), Some("second"));
        assert_eq!(answer(b"\x1b[C\r", None).as_deref(), Some("1"));
        assert_eq!(answer(b"\x1b[1;5B\r", None).as_deref(), Some("2"));
    }

    #[test]
    fn escape_returns_but_eof_and_interrupt_exit_the_choice() {
        for input in [
            b"".as_slice(),
            b"\x1b",
            b"\x1b[",
            b"\x1b1\r",
            b"\x031\r",
            b"\x041\r",
        ] {
            let mut keys = input;
            let mut output = Vec::new();
            let result = choose(
                &mut Terminal::new(&mut keys, &mut output),
                &["first"],
                Some(0),
            );
            if input.starts_with(b"\x1b") {
                assert_eq!(result.unwrap(), None, "{input:?}");
            } else {
                assert!(matches!(result, Err(Error::Interrupted)), "{input:?}");
            }
        }
    }

    #[test]
    fn a_choice_stops_when_output_fails() {
        struct FailedOutput;
        impl std::io::Write for FailedOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("output failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = choose(
            &mut Terminal::new(&mut b"\n".as_slice(), &mut FailedOutput),
            &["first"],
            Some(0),
        )
        .expect_err("output failure stops the prompt");
        assert!(error.to_string().contains("output failed"));
    }

    #[test]
    fn the_active_choice_shows_its_label_and_color_is_optional() {
        for color in [false, true] {
            let mut input = b"\x03".as_slice();
            let mut output = Vec::new();
            let mut terminal = Terminal::new(&mut input, &mut output);
            terminal.choice_color = color;
            assert!(matches!(
                choose(&mut terminal, &["Amazon Bedrock"], None),
                Err(Error::Interrupted)
            ));
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("> [1] Amazon Bedrock"));
            assert_eq!(output.contains(&format!("\x1b[{BOLD_ACCENT}m")), color);
        }
    }

    #[test]
    fn an_active_line_fits_unicode_labels_and_keeps_the_last_column_clear() {
        use ratatui::text::Span;
        for columns in [1, 2, 3, 10, 40] {
            let line = fit_line("> [1] 東京 e\u{301} long label\nnew line", columns);
            assert!(Span::raw(&line).width() < columns, "{columns}: {line:?}");
            assert!(!line.contains('\n'));
        }
    }
}
