use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use crate::create::{CreatedProfile, Resolution, Route};
use crate::credential::Credential;

/// The column a report line wraps at.
const WIDTH: usize = 100;

/// The width of a label in the list of files.
const LABEL: usize = 10;

/// The widest name column in the list of what discovery found.
pub(crate) const NAME_COLUMN: usize = 24;

/// ANSI styling, or none.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    guided: bool,
    color: bool,
}

impl Report {
    /// The Strands green that accents commands, choices, and headings.
    pub const ACCENT: &'static str = "38;2;74;222;128";

    /// Select the layout and whether text uses ANSI color.
    pub fn new(guided: bool, color: bool) -> Self {
        Self { guided, color }
    }

    /// The terminal width, or 80 columns when no size is available.
    pub fn columns(self) -> usize {
        crate::prompt::size().map(|(width, _)| width).unwrap_or(80)
    }

    /// Text wrapped to the terminal, with room for a prefix on its first line.
    pub fn wrap(self, message: &str, first_indent: usize) -> String {
        let width = self.columns().min(WIDTH);
        message
            .split('\n')
            .enumerate()
            .map(|(index, line)| {
                let indent = if index == 0 {
                    first_indent
                } else {
                    line.len() - line.trim_start().len()
                };
                let wrapped = crate::prompt::wrap_line(line.trim_start(), indent, width).join("\n");
                if index == 0 {
                    wrapped.trim_start().to_string()
                } else {
                    wrapped
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A command title.
    pub fn heading(self, title: &str) -> String {
        let title = format!("{} {}\n", self.accent("box:"), self.bold(title));
        if self.guided {
            format!("\n  {title}\n")
        } else {
            format!("{title}\n")
        }
    }

    /// A section title, separated from its contents.
    pub fn section(self, title: &str) -> String {
        if self.guided {
            format!(
                "  {}\n",
                self.paint("1;38;2;74;222;128", &title.to_uppercase())
            )
        } else {
            self.bold(title)
        }
    }

    /// Text styling without a background fill.
    pub fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn green(self, text: &str) -> String {
        self.paint("32", text)
    }

    fn yellow(self, text: &str) -> String {
        self.paint("33", text)
    }

    fn accent(self, text: &str) -> String {
        self.paint(Self::ACCENT, text)
    }
}

/// Where the operator puts a credential that the routes name.
enum CredentialSource<'a> {
    /// A variable, and the hosts of each route that reads it.
    Variable(String, Vec<&'a str>),
    /// An AWS profile, and the route that signs with it.
    AwsProfile(&'a str, String),
    /// The host's ambient AWS identity, and the route that signs with it.
    AwsDefaultChain(&'a str),
    /// The hosts of a route that reads from a declared source, its scheme, and its plugin.
    Source(Vec<&'a str>, String, Option<String>),
}

/// The steps that tell the operator where the routes' credentials come from, in route order. Each
/// variable has one, and so does each route that signs with an AWS profile or the default chain or
/// reads from a source of `declared`.
fn credential_steps(routes: &[Route], declared: &BTreeMap<String, Option<String>>) -> Vec<String> {
    let mut sources: Vec<CredentialSource> = Vec::new();
    for route in routes {
        let Some(credential) = route
            .secret
            .as_deref()
            .and_then(|reference| Credential::from_reference(reference, declared))
        else {
            continue;
        };
        match credential {
            Credential::Environment(name) => {
                let hosts = route.destinations.iter().map(String::as_str);
                let known = sources.iter_mut().find_map(|source| match source {
                    CredentialSource::Variable(variable, known_hosts) if *variable == name => {
                        Some(known_hosts)
                    }
                    _ => None,
                });
                match known {
                    Some(known_hosts) => known_hosts.extend(hosts),
                    None => sources.push(CredentialSource::Variable(name, hosts.collect())),
                }
            }
            Credential::AwsProfile(profile) => {
                sources.push(CredentialSource::AwsProfile(&route.name, profile));
            }
            Credential::AwsDefaultChain => {
                sources.push(CredentialSource::AwsDefaultChain(&route.name));
            }
            Credential::Source(scheme, plugin) => {
                let hosts = route.destinations.iter().map(String::as_str).collect();
                sources.push(CredentialSource::Source(hosts, scheme, plugin));
            }
        }
    }
    sources
        .into_iter()
        .map(|source| match source {
            CredentialSource::Variable(name, hosts) => {
                format!("Put the key for {} in {name}.", hosts.join(" and "))
            }
            CredentialSource::AwsProfile(route, profile) => format!(
                "The {route} route signs with the AWS profile {profile}. Box Core signs with that \
                 profile's static keys, credential_process, assume-role, or web identity, not an \
                 AWS SSO or aws login profile."
            ),
            CredentialSource::AwsDefaultChain(route) => format!(
                "The {route} route signs with your default AWS identity. Box Core warns on each \
                 request."
            ),
            CredentialSource::Source(hosts, scheme, plugin) => {
                let program = match plugin {
                    Some(plugin) => format!("the program of {plugin}"),
                    None => format!("the program of your `[secret-source.{scheme}]`"),
                };
                format!(
                    "When the box starts, it reads the key for {} with {program}, so you set no \
                     variable for it.",
                    hosts.join(" and ")
                )
            }
        })
        .collect()
}

/// What discovery found on the host, as the report lists it.
struct Found<'a> {
    home: &'a Path,
    agent_label: &'a str,
    agent: &'a Path,
    agent_pack: &'a str,
    resolutions: &'a [Resolution],
    skipped: &'a [(String, String)],
}

impl Found<'_> {
    fn write(&self, paint: Report, out: &mut String) {
        let label = if self
            .resolutions
            .iter()
            .any(|tool| tool.name == self.agent_label)
        {
            format!("{} (agent)", self.agent_label)
        } else {
            self.agent_label.to_string()
        };
        let width = std::iter::once(label.len())
            .chain(self.resolutions.iter().map(|tool| tool.name.len()))
            .chain(self.skipped.iter().map(|(name, _)| name.len()))
            .max()
            .unwrap_or_default()
            .min(NAME_COLUMN);
        let _ = writeln!(out, "{}", paint.section("Programs"));
        let mut row = |mark: String, name: &str, what: String, details: Vec<String>| {
            let _ = writeln!(
                out,
                "  {mark} {}  {what}",
                paint.bold(&format!("{name:<width$}"))
            );
            for detail in details {
                for line in wrap(&detail, WIDTH - 6 - width) {
                    let _ = writeln!(out, "    {:<width$}  {}", "", paint.dim(&line));
                }
            }
        };
        row(
            paint.green("✓"),
            &label,
            paint.dim(self.agent_pack),
            vec![shown(self.home, self.agent)],
        );
        for tool in self.resolutions {
            let path = if tool.spelling == tool.identity {
                shown(self.home, &tool.identity)
            } else {
                format!(
                    "{} → {}",
                    shown(self.home, &tool.spelling),
                    shown(self.home, &tool.identity)
                )
            };
            row(
                paint.green("✓"),
                &tool.name,
                paint.dim(&tool.pack),
                vec![path],
            );
        }
        for (name, why) in self.skipped {
            row(
                paint.yellow("!"),
                name,
                paint.yellow(&format!("skipped: {}", shown_text(self.home, why))),
                Vec::new(),
            );
        }
        out.push('\n');
    }
}

/// `path` for reading, with the operator home as `~`.
fn shown(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    }
}

/// `text` for reading, with every path under the operator home written with `~`.
fn shown_text(home: &Path, text: &str) -> String {
    text.replace(&format!("{}/", home.display()), "~/")
}

/// One numbered step, wrapped under its number.
fn step(out: &mut String, number: usize, text: &str) {
    let mut lines = wrap(text, WIDTH - 5).into_iter();
    let _ = writeln!(out, "  {number}. {}", lines.next().unwrap_or_default());
    for rest in lines {
        let _ = writeln!(out, "     {rest}");
    }
}

/// `text` broken into lines of at most `width` characters, at spaces.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split(' ') {
        let current = lines.last_mut().expect("one line");
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(word.to_string());
        }
    }
    lines
}

impl CreatedProfile {
    /// A compact saved-profile summary for the Run, Edit, and Exit menu.
    pub fn guided_summary(&self, color: bool) -> String {
        let paint = Report::new(true, color);
        let mut out = paint.heading("Profile saved");
        let _ = writeln!(out, "{}", paint.section("Profile"));
        for (label, value) in [
            ("Name", self.name.clone()),
            ("Agent", self.label()),
            ("Packs", self.short_packs()),
        ] {
            let _ = writeln!(
                out,
                "  {}  {}",
                paint.dim(&format!("{label:<7}")),
                paint.wrap(&value, 11)
            );
        }
        let _ = writeln!(out, "\n{}", paint.section("Policy"));
        let _ = writeln!(out, "  {}", paint.wrap(self.policy_summary().trim(), 2));
        let mut notes = Vec::new();
        if let Some((program, _)) = self.missing() {
            notes.push(format!(
                "{program} is not on this host. Install it before running."
            ));
        }
        if !self.discovery.tools.skipped.is_empty() {
            notes.push(format!(
                "Skipped tools: {}.",
                self.discovery
                    .tools
                    .skipped
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for (pack, _) in &self.shadowing {
            notes.push(format!(
                "Using your local {pack} pack instead of {}{pack}.",
                crate::lang::VENDORED
            ));
        }
        notes.extend(credential_steps(&self.routes, &self.sources));
        if !notes.is_empty() {
            let _ = writeln!(out, "\n{}", paint.section("Before running"));
            for note in notes {
                let _ = writeln!(out, "  • {}", paint.wrap(&note, 4));
            }
        }
        let _ = writeln!(
            out,
            "\n  Details: {}",
            paint.accent(&format!("box profile show {}", self.name))
        );
        out
    }

    fn short_packs(&self) -> String {
        self.profile
            .packs()
            .iter()
            .map(|pack| pack.strip_prefix(crate::lang::VENDORED).unwrap_or(pack))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// What was found and where the profile is, in ANSI color when `color`.
    pub fn summary(&self, color: bool) -> String {
        let paint = Report::new(false, color);
        let mut out = paint.heading(&format!("Profile {}", self.name));
        let resolutions = self.resolutions();
        if let Some((program, missing)) = self.missing() {
            let _ = writeln!(out, "{}", paint.section("Programs"));
            for line in wrap(
                &format!(
                    "{program} is not on this host now: {}. `box run` looks again each time.",
                    shown_text(&self.home, missing)
                ),
                WIDTH - 4,
            ) {
                let _ = writeln!(out, "  {}", paint.yellow(&line));
            }
            out.push('\n');
        }
        if let Some(agent) = &self.discovery.agent {
            Found {
                home: &self.home,
                agent_label: &self.label(),
                agent,
                agent_pack: &self.agent_pack,
                resolutions: &resolutions,
                skipped: &self.discovery.tools.skipped,
            }
            .write(paint, &mut out);
        }
        if !self.detected.is_empty() {
            let _ = writeln!(out, "{}", paint.section("Detected"));
            let width = paint.columns().min(WIDTH);
            for line in &self.detected {
                let answer = match &line.answer {
                    Some(value) => format!("{}: {value}", line.label),
                    None => line.label.clone(),
                };
                for text in crate::prompt::wrap_line(&answer, 2, width) {
                    let _ = writeln!(out, "{text}");
                }
                for text in crate::prompt::wrap_line(&line.text, 4, width) {
                    let _ = writeln!(out, "{}", paint.dim(&text));
                }
            }
            out.push('\n');
        }
        if let (Some(policy), Some(copy)) = (&self.policy, self.policy_path()) {
            let _ = writeln!(out, "{}", paint.section("Policy"));
            let from = match &self.policy_from {
                Some(starter) => format!(", from the {starter} starter"),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "  {} ({}){from}, copied to {}\n",
                policy.label,
                policy.name,
                shown(&self.home, &copy)
            );
        }
        let _ = writeln!(out, "{}", paint.section("Files"));
        let _ = writeln!(
            out,
            "  {} {}",
            paint.dim(&format!("{:<LABEL$}", "profile")),
            shown(&self.home, &self.path())
        );
        if let Some(copy) = self.policy_path() {
            let _ = writeln!(
                out,
                "  {} {}",
                paint.dim(&format!("{:<LABEL$}", "policy")),
                shown(&self.home, &copy)
            );
        }
        for (pack, path) in &self.shadowing {
            let _ = writeln!(
                out,
                "  {} {}, used instead of {}{pack}",
                paint.dim(&format!("{:<LABEL$}", "pack")),
                shown(&self.home, path),
                crate::lang::VENDORED
            );
        }
        out.push('\n');
        out
    }

    /// The commands that start the profile, in ANSI color when `color`.
    pub fn next_steps(&self, color: bool) -> String {
        let paint = Report::new(false, color);
        let mut out = String::new();
        let _ = writeln!(out, "{} Wrote profile {}.\n", paint.green("✓"), self.name);
        let _ = writeln!(out, "{}", paint.section("Next"));
        let mut number = 0;
        for text in credential_steps(&self.routes, &self.sources) {
            number += 1;
            step(&mut out, number, &text);
        }
        let label = self.label();
        step(
            &mut out,
            number + 1,
            &format!("Start {label} in the box, from the project directory:"),
        );
        let run = format!("box run {}", self.name);
        let _ = writeln!(out, "     {}", paint.accent(&run));
        let _ = writeln!(
            out,
            "     {}",
            paint.dim(&format!(
                "Arguments after -- go to {label}: {run} -- <args>"
            ))
        );
        let _ = writeln!(
            out,
            "\n{}",
            paint.dim(&format!(
                "Full configuration: box profile show {} --full",
                self.name
            ))
        );
        let _ = writeln!(
            out,
            "{}",
            paint.dim(&format!(
                "To change it with a coding agent, tell the agent: Run box help agent and follow it to update profile {}.",
                self.name
            ))
        );
        out
    }

    fn policy_summary(&self) -> String {
        let mut text = String::new();
        if let Some(policy) = &self.policy {
            let _ = writeln!(text, "  {}\n  {}", policy.label, policy.description);
        } else {
            let _ = writeln!(text, "  Rules from the selected packs.");
            if !self.profile.policies().is_empty() {
                let _ = writeln!(
                    text,
                    "  Keep current rules in {}.",
                    self.profile.policies().join(", ")
                );
            }
        }
        text
    }

    /// Review a profile before writing; false returns to Setup.
    pub(crate) fn review(&self, terminal: &mut crate::Terminal<'_>) -> Result<bool, crate::Error> {
        terminal.stage(&self.name, crate::prompt::REVIEW);
        let session = terminal.session.as_ref();
        let workspace = session.and_then(|session| session.run.clone());
        let reviewing = session.is_some_and(|session| session.reviewing);
        let mut text = "  PROFILE\n\n".to_string();
        let mut rows = vec![("Name", self.name.clone()), ("Agent", self.label())];
        if let Some(workspace) = &workspace {
            rows.push(("Workspace", shown(&self.home, workspace)));
        }
        for (label, value) in rows {
            let _ = writeln!(text, "  {label:<10}  {value}");
        }
        let _ = write!(text, "\n  POLICY\n\n{}", self.policy_summary());
        let _ = writeln!(text, "\n  FILES\n");
        let mut rows = vec![
            ("Packs", self.short_packs()),
            ("Folder", shown(&self.home, &self.folder)),
            ("Settings", shown(&self.home, &self.path())),
        ];
        for file in self.profile.policies() {
            rows.push(("Policy", shown(&self.home, &self.folder.join(file))));
        }
        for (label, value) in rows {
            let _ = writeln!(text, "  {label:<10}  {value}");
        }
        let detected: Vec<(&crate::detect::Line, String)> = self
            .detected
            .iter()
            .map(|line| {
                let source = match &line.answer {
                    Some(answer) if reviewing => {
                        format!("{answer}  your answer")
                    }
                    Some(answer) => format!("{answer}  from {}", line.text),
                    None => line.text.clone(),
                };
                (line, source)
            })
            .collect();
        if !detected.is_empty() {
            let heading = if reviewing {
                "REVIEWED OPTIONS"
            } else {
                "DETECTED OPTIONS"
            };
            let _ = writeln!(text, "\n  {heading}\n");
            let width = detected
                .iter()
                .map(|(line, _)| line.label.len())
                .max()
                .unwrap_or(0);
            for (line, source) in &detected {
                let _ = writeln!(text, "  {:<width$}  {source}", line.label);
            }
        }
        if let Some(options) = self
            .profile
            .table
            .get("options")
            .and_then(toml::Value::as_table)
        {
            let _ = writeln!(text, "\n  SELECTED OPTIONS\n");
            let mut values = std::collections::BTreeMap::new();
            crate::lang::collect_values(
                &toml::Value::Table(options.clone()),
                &mut Vec::new(),
                &mut values,
            )
            .expect("validated profile options");
            let width = values.keys().map(|name| name.len()).max().unwrap_or(0);
            for (name, value) in values {
                let _ = writeln!(text, "  {name:<width$}  {value}");
            }
        }
        let _ = writeln!(
            text,
            "\n  Other inputs use their pack or environment defaults."
        );
        let (question, save, saves) = match &workspace {
            Some(_) => (
                "Save this profile and run it?",
                "Save and run",
                format!("Save these settings, then start {} here.", self.label()),
            ),
            None => (
                if self.editing.is_some() {
                    "Save changes to this profile?"
                } else {
                    "Save this profile?"
                },
                "Save profile",
                "Save these settings.".to_string(),
            ),
        };
        terminal.question(question);
        terminal.detail(&text);
        loop {
            match crate::prompt::act(
                terminal,
                &[save, "Review or change settings", "Cancel"],
                &[
                    &saves,
                    "Review all settings, including detected values.",
                    "Leave without writing a profile.",
                ],
                0,
            )?
            .as_deref()
            {
                Some("" | "1") => return Ok(true),
                Some("2") => {
                    terminal
                        .session
                        .as_mut()
                        .map(crate::prompt::Session::edit_setup);
                    return Ok(false);
                }
                None | Some("3") => {
                    return Err(crate::Error::StarterAborted {
                        question: question.to_string(),
                    });
                }
                _ => {
                    terminal.feedback("  Choose 1, 2 or 3.\n");
                }
            }
        }
    }

    /// The program that the host lacks, as `(its name, why)`: the agent, or the program of a
    /// declared secret source.
    fn missing(&self) -> Option<(String, &str)> {
        match (
            &self.discovery.missing_agent,
            &self.discovery.missing_source,
        ) {
            (Some(reason), _) => Some((self.label(), reason)),
            (None, Some((program, reason))) => Some((program.clone(), reason)),
            (None, None) => None,
        }
    }

    /// The agent's name as a person reads it.
    pub(crate) fn label(&self) -> String {
        self.agent_label.clone()
    }
}
