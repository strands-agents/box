//! `box`: configure a Strands Box from the host, keep it as a profile, and run a workload in it.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime};

use chrono::{DateTime, Utc};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use strands_box_cli::{
    CreatedProfile, Error, HeldBoxes, Launch, Launcher, NewProfile, OutputFormat, Preparation,
    RecordsOptions, Report, Terminal, is_profile_path, json_line, validate_name,
};
use strands_box_cli_telemetry::{
    COMPLETION_BUDGET, ExitOutcome, Invocation, LaunchOutcome, Session,
};

mod panel;
use panel::Panel;

#[derive(Debug, Parser)]
#[command(
    name = "box",
    version,
    about = "Configure a Strands Box from the toolchains on this host, and run a workload in it",
    before_help = "Coding agents: run `box help agent` before you create or change a profile.",
    after_help = "Help topics:
  box help agent            What a coding agent reads to create or change a profile

Examples:
  box run claude            Start the claude profile in this folder
  box profile create        Pick an agent and set up a profile
  box profile list          See your profiles and starters
  box runs list             See saved box runs
  box explain B0102         Explain a code in a Box message"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start an agent with a profile in the current folder.
    #[command(after_help = format!("Examples:
  box run claude                        Start the claude profile here
  box run claude --no-banner            Run without the activity banner
  box run                               Choose a profile, or create one
  box run claude -- --continue          Pass arguments to the agent
  box run claude --box-id <BOX_ID>      Keep a saved run's policy history

Tip: Create a new profile with {}.", styled(true, Report::ACCENT, "box profile create")))]
    Run {
        /// Profile to use: a name in `~/.strands/box/profiles/<profile>/`, or the path of a profile file,
        /// such as `../box/profile.toml`. Omit to choose or create one.
        profile: Option<String>,
        /// Reuse a saved run's policy history. Find IDs with `box runs list`.
        /// Without this, start with fresh history. Does not resume an agent conversation.
        #[arg(long, value_name = "BOX_ID")]
        box_id: Option<String>,
        /// Show the activity banner, even when the profile or `~/.strands/box/config.toml` turns it off.
        #[arg(long, overrides_with = "no_banner")]
        banner: bool,
        /// Use the full terminal without the banner.
        #[arg(long, overrides_with = "banner")]
        no_banner: bool,
        /// Arguments for the agent, after `--`.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Inspect saved box runs.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Create, edit, list, and show profiles, and remove their boxes, storage, or the profiles.
    #[command(after_help = "Examples:
  box profile create        Pick an agent and set up a profile
  box profile edit claude   Change the claude profile's answers
  box profile list          See your profiles and starters

To change a profile with a coding agent, tell the agent: Run box help agent and follow it.")]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Turn usage telemetry on or off, or show whether it is on.
    #[command(
        after_help = "BOX_TELEMETRY=0 or DO_NOT_TRACK=1 turns telemetry off for one shell.

Examples:
  box telemetry status   Show whether telemetry is on, and why
  box telemetry off      Stop sending usage telemetry
  box telemetry on       Send usage telemetry again"
    )]
    Telemetry {
        #[command(subcommand)]
        command: TelemetryCommand,
    },
    /// Show what a Box message code means and what to do about it.
    #[command(after_help = "Examples:
  box explain B0102                 Explain strands-box: error[B0102]
  box explain P0201 --format json   Print the explanation as JSON")]
    Explain {
        /// The code in a message such as `policy: warning[P0201]: ...`.
        #[arg(value_parser = parse_code)]
        code: String,
        /// Print text or one JSON object.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum TelemetryCommand {
    /// Send usage telemetry, and save that choice.
    On,
    /// Stop sending usage telemetry, and save that choice.
    Off,
    /// Show whether telemetry is on, and what decided it.
    Status,
}

#[derive(Debug, Subcommand)]
enum RunsCommand {
    /// List saved runs, most recently updated first.
    #[command(
        after_help = "Use box runs history <BOX_ID> to inspect one run. Updated is the last configuration write, not proof of startup. Listed runs may be active or completed.

Examples:
  box runs list                 List saved runs
  box runs list claude          List the claude profile's runs
  box runs list --format json   List them as JSON"
    )]
    List {
        /// Only the runs of this profile. Omit to list every saved run.
        #[arg(value_parser = parse_runs_profile)]
        profile: Option<String>,
        /// Print a text table or a JSON array of saved runs.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Read a run's recorded policy decisions.
    #[command(after_help = "Examples:
  box runs history <BOX_ID>             Every recorded decision
  box runs history <BOX_ID> --deny      Only denials
  box runs history <BOX_ID> --tail 20   The last 20 decisions")]
    History {
        /// The saved run ID from `$BOX_HOME/r/` (`~/.strands/box/r/` by default).
        box_id: String,
        /// Show recorded denials, excluding explicit would-denies.
        #[arg(long, conflicts_with = "would_deny")]
        deny: bool,
        /// Show recorded denials explicitly marked as not enforced.
        #[arg(long)]
        would_deny: bool,
        /// Print a text table or a JSON array of decisions.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Match this action exactly, such as fs:read (case-sensitive).
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        action: Option<String>,
        /// Keep resources containing this text (case-sensitive, not a glob).
        #[arg(long, value_name = "TEXT", value_parser = clap::builder::NonEmptyStringValueParser::new())]
        resource: Option<String>,
        /// Keep decisions at or after this RFC3339 time, including its timezone.
        #[arg(long, value_name = "TIMESTAMP", value_parser = parse_records_since)]
        since: Option<DateTime<Utc>>,
        /// Keep the last N matching decisions in their recorded order.
        #[arg(long, value_name = "N")]
        tail: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Create a profile from a starter, or from the packs you name.
    #[command(after_help = "Examples:
  box profile create                                Pick an agent and set it up
  box profile create claude                         Set up a Claude Code profile
  box profile create claude-project --with claude   Give the profile a custom name
  box profile create claude --policy scoped         Start from the scoped policy")]
    Create {
        /// The profile name [default: the first pack in `--with`]. When it is the name of a
        /// starter (`box profile list` lists them), that starter asks what the profile needs.
        name: Option<String>,
        /// Packs to use, comma-separated, such as `--with <agent>,bedrock`. A starter in the list
        /// selects that starter, and a pack that one of its choices adds answers that question.
        /// A short name is the operator's pack in `~/.strands/box/packs/` when it exists, else
        /// `@box/<pack>`.
        #[arg(long, value_delimiter = ',')]
        with: Vec<String>,
        /// Set an input in the profile's `[options]`, as `name=value`. Repeat for more.
        #[arg(long = "option", value_name = "NAME=VALUE")]
        options: Vec<String>,
        /// The policy the profile starts with, such as `open` or `scoped`. Without it, `box` asks at a
        /// terminal and stops without one.
        #[arg(long, value_name = "POLICY")]
        policy: Option<String>,
        #[command(flatten)]
        host: HostArgs,
        /// Replace an existing profile.
        #[arg(long)]
        force: bool,
    },
    /// Reopen a profile's answers at a terminal, and save the changes.
    #[command(after_help = "Examples:
  box profile edit claude   Change the claude profile's answers")]
    Edit {
        /// The profile.
        name: String,
    },
    /// List the profiles.
    #[command(after_help = "Examples:
  box profile list   See your profiles and starters")]
    List,
    /// Resolve a profile for the current directory, and print the packs and options a run uses.
    #[command(after_help = "Examples:
  box profile show claude                        What the claude profile uses here
  box profile show claude --full                 Also print box.toml and policy.dw
  box profile show claude --format json --full   Print all of it as one JSON document")]
    Show {
        /// The profile: a name, or the path of a profile file.
        name: String,
        /// Also print the `box.toml` and `policy.dw` the run gets.
        #[arg(long)]
        full: bool,
        /// Print the text report, or the same report as one JSON document.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Remove the boxes that profiles own, and their records. The profiles and their storage stay.
    #[command(after_help = "Examples:
  box profile clean claude                     Remove the boxes that claude owns
  box profile clean claude --box-id <BOX_ID>   Remove one box of claude
  box profile clean --all                      Remove every box, of every profile

A box that is still running stops the command, and nothing is removed.")]
    #[command(group = clap::ArgGroup::new("target").required(true).args(["names", "all"]))]
    Clean {
        /// The profiles whose boxes to remove.
        names: Vec<String>,
        /// Remove every box, of every profile.
        #[arg(long)]
        all: bool,
        /// Remove only this box, from `box runs list <name>`. It must belong to the one profile named.
        #[arg(
            long,
            value_name = "BOX_ID",
            requires = "names",
            conflicts_with = "all"
        )]
        box_id: Option<String>,
        /// Remove without asking first.
        #[arg(long)]
        no_ask: bool,
    },
    /// Delete profiles, with the boxes they own and their storage.
    #[command(after_help = "Examples:
  box profile delete claude   Delete the claude profile, its boxes, and its storage
  box profile delete --all    Delete every profile, every box, and all storage

A box that is still running stops the command, and nothing is deleted.")]
    #[command(group = clap::ArgGroup::new("target").required(true).args(["names", "all"]))]
    Delete {
        /// The profiles to delete.
        names: Vec<String>,
        /// Delete every profile.
        #[arg(long)]
        all: bool,
        /// Delete without asking first.
        #[arg(long)]
        no_ask: bool,
    },
    /// Delete the storage of profiles: the agent's settings and sessions. The profiles and their
    /// boxes stay, and the next run starts the agent fresh.
    #[command(after_help = "Examples:
  box profile reset claude   Delete the claude profile's storage
  box profile reset --all    Delete the storage of every profile

A box that is still running stops the command, and nothing is deleted.")]
    #[command(group = clap::ArgGroup::new("target").required(true).args(["names", "all"]))]
    Reset {
        /// The profiles whose storage to delete.
        names: Vec<String>,
        /// Delete the storage of every profile.
        #[arg(long)]
        all: bool,
        /// Delete without asking first.
        #[arg(long)]
        no_ask: bool,
    },
}

#[derive(Debug, Args)]
struct HostArgs {
    /// Comma-separated tools to detect [default: `[tools] defaults` in the shipped config.toml].
    #[arg(long, value_delimiter = ',')]
    tools: Option<Vec<String>>,
}

/// `name=value` pairs, in the order given.
fn pairs(options: &[String]) -> Result<Vec<(String, String)>, Error> {
    options
        .iter()
        .map(|option| {
            option
                .split_once('=')
                .map(|(name, value)| (name.trim().to_string(), value.to_string()))
                .ok_or_else(|| Error::OptionSyntax {
                    option: option.clone(),
                })
        })
        .collect()
}

/// The topics that `box help` takes beside a command.
const HELP_TOPICS: [&str; 1] = ["agent"];

/// The commands of `box`, with a `help` command at each level that has commands.
fn cli() -> clap::Command {
    let topics = "Help topics:
  box help agent            What a coding agent reads to create or change a profile

Tell a coding agent on this host:
  Run box help agent and follow it to create a profile.
  Run box help agent and follow it to update profile <name>.";
    help_commands(
        Cli::command().disable_help_subcommand(true),
        "Print this message, the help of a command, or a help topic",
        "A command, or a help topic",
    )
    .mut_subcommand("help", |help| help.after_help(topics))
}

fn help_commands(
    command: clap::Command,
    about: &'static str,
    argument: &'static str,
) -> clap::Command {
    if !command.has_subcommands() {
        return command;
    }
    command
        .mut_subcommands(|command| {
            help_commands(
                command,
                "Print this message or the help of the given subcommand(s)",
                "Print help for the subcommand(s)",
            )
        })
        .subcommand(
            clap::Command::new("help").about(about).arg(
                clap::Arg::new("command")
                    .action(clap::ArgAction::Append)
                    .num_args(..)
                    .value_name("COMMAND")
                    .help(argument),
            ),
        )
}

/// The command path or the topic that a `help` command names, when `matches` end in one.
fn help_path(matches: &clap::ArgMatches) -> Option<Vec<String>> {
    let (name, selected) = matches.subcommand()?;
    if name == "help" {
        return Some(
            selected
                .get_many::<String>("command")
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
        );
    }
    help_path(selected).map(|path| std::iter::once(name.to_string()).chain(path).collect())
}

/// Print the topic `path`, or the help that `box <path> --help` prints.
fn help(command: &mut clap::Command, path: &[String]) -> ExitCode {
    if path == HELP_TOPICS {
        return finish(
            strands_box_cli::check_box_home()
                .and_then(|()| agent_help())
                .map(|()| ExitCode::SUCCESS),
            command.find_subcommand_mut("help").expect("help command"),
        );
    }
    let mut named = &*command;
    for name in path {
        let Some(found) = named.find_subcommand(name) else {
            let commands: Vec<&str> = named
                .get_subcommands()
                .map(clap::Command::get_name)
                .collect();
            let message = format!(
                "`{}` is not a command or a help topic

Commands: {}
Help topics: {}",
                path.join(" "),
                commands.join(", "),
                HELP_TOPICS.join(", ")
            );
            let error = command
                .find_subcommand_mut("help")
                .expect("help command")
                .error(clap::error::ErrorKind::InvalidSubcommand, message);
            print_diagnostic(&error, None);
            return ExitCode::from(error.exit_code() as u8);
        };
        named = found;
    }
    let arguments = std::env::args_os()
        .take(1)
        .chain(path.iter().map(OsString::from))
        .chain([OsString::from("--help")]);
    match command.try_get_matches_from_mut(arguments) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            print_diagnostic(&error, None);
            ExitCode::from(error.exit_code() as u8)
        }
    }
}

fn agent_help() -> Result<(), Error> {
    let text = Launcher::from_host().agent_help()?;
    write!(std::io::stdout(), "{text}")
        .or_else(|error| match error.kind() {
            std::io::ErrorKind::BrokenPipe => Ok(()),
            _ => Err(error),
        })
        .map_err(|source| Error::Io {
            action: "write",
            path: "standard output".into(),
            source,
        })
}

fn main() -> ExitCode {
    let mut command = command_style(cli());
    command.build();
    let parse_error = |error: clap::Error| {
        print_diagnostic(&error, examples(std::env::args_os()).as_deref());
        ExitCode::from(error.exit_code() as u8)
    };
    let matches = match command.try_get_matches_from_mut(std::env::args_os()) {
        Ok(matches) => matches,
        Err(error) => return parse_error(error),
    };
    if let Some(path) = help_path(&matches) {
        return help(&mut command, &path);
    }
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => return parse_error(error),
    };
    let mut context = &mut command;
    let mut selected = &matches;
    while let Some((name, matches)) = selected.subcommand() {
        context = context
            .find_subcommand_mut(name)
            .expect("parsed subcommand belongs to the command");
        selected = matches;
    }
    if let Command::Explain { code, format } = &cli.command {
        let explained = strands_box_cli::explain(code, *format, &mut std::io::stdout().lock());
        return finish(
            match explained {
                Err(Error::ExplainOutput { source })
                    if source.kind() == std::io::ErrorKind::BrokenPipe =>
                {
                    Ok(ExitCode::SUCCESS)
                }
                result => result.map(|()| ExitCode::SUCCESS),
            },
            context,
        );
    }
    if let Err(error) = strands_box_cli::check_box_home() {
        return finish(Err(error), context);
    }
    let result = match cli.command {
        Command::Explain { .. } => unreachable!("explained above"),
        Command::Run {
            profile,
            box_id,
            args,
            banner,
            no_banner,
        } => {
            let banner = flag(banner, no_banner);
            return finish(
                profile
                    .map_or_else(|| choose_profile(box_id.as_deref(), context), Ok)
                    .and_then(|profile| run(&profile, box_id.as_deref(), &args, banner)),
                context,
            );
        }
        Command::Runs {
            command: RunsCommand::List { profile, format },
        } => list_runs(profile.as_deref(), format).map(|()| None),
        Command::Runs {
            command:
                RunsCommand::History {
                    box_id,
                    deny,
                    would_deny,
                    format,
                    action,
                    resource,
                    since,
                    tail,
                },
        } => records(
            &box_id,
            RecordsOptions {
                format,
                deny,
                would_deny,
                action,
                resource,
                since,
                tail,
            },
        )
        .map(|()| None),
        Command::Profile { command } => profile_action(command, context),
        Command::Telemetry { command } => telemetry(match command {
            TelemetryCommand::On => Some(true),
            TelemetryCommand::Off => Some(false),
            TelemetryCommand::Status => None,
        })
        .map(|()| None),
    };
    match result {
        Ok(Some(name)) => finish(
            run(&name, None, &[], None),
            command.find_subcommand_mut("run").expect("run command"),
        ),
        result => finish(result.map(|_| ExitCode::SUCCESS), context),
    }
}

fn finish(result: Result<ExitCode, Error>, command: &mut clap::Command) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(Error::ExitRequested) => ExitCode::SUCCESS,
        Err(Error::Interrupted) => {
            eprintln!("Cancelled.");
            ExitCode::from(130)
        }
        Err(error @ (Error::StarterAborted { .. } | Error::Kept)) if interactive() => {
            let message = match error {
                Error::Kept => "Cancelled. Nothing was removed.",
                _ if command.get_name() == "run" => "Cancelled.",
                _ if command.get_name() == "edit" => "Cancelled. The profile is unchanged.",
                _ => "Cancelled. No profile saved.",
            };
            eprintln!("{message}");
            ExitCode::FAILURE
        }
        Err(error) => {
            let examples = command.get_after_help().map(ToString::to_string);
            let message = Report::new(false, false).wrap(&error.to_string(), "box: error: ".len());
            print_diagnostic(
                &command.error(clap::error::ErrorKind::ValueValidation, message),
                examples.as_deref(),
            );
            ExitCode::FAILURE
        }
    }
}

fn command_style(command: clap::Command) -> clap::Command {
    let accent = clap::builder::styling::Style::new()
        .fg_color(Some(clap::builder::styling::RgbColor(74, 222, 128).into()));
    let styles = clap::builder::Styles::styled()
        .header(accent.bold())
        .usage(accent.bold())
        .literal(accent)
        .placeholder(clap::builder::styling::AnsiColor::White.on_default())
        .error(clap::builder::styling::AnsiColor::Red.on_default().bold());
    command
        .styles(styles)
        .max_term_width(100)
        .mut_subcommands(command_style)
}

/// The examples of the command that `args` name, for a parse error.
fn examples(args: impl Iterator<Item = OsString>) -> Option<String> {
    let mut command = cli();
    for arg in args.skip(1) {
        match arg.to_str().and_then(|arg| command.find_subcommand(arg)) {
            Some(subcommand) => command = subcommand.clone(),
            None => break,
        }
    }
    command.get_after_help().map(ToString::to_string)
}

fn print_diagnostic(error: &clap::Error, examples: Option<&str>) {
    if !error.use_stderr() {
        let _ = error.print();
        return;
    }
    let _ = write!(std::io::stderr(), "{}", diagnostic(error, examples));
}

fn diagnostic(error: &clap::Error, examples: Option<&str>) -> String {
    let rendered = error.render();
    let text = if colored(&std::io::stderr()) {
        rendered.ansi().to_string()
    } else {
        rendered.to_string()
    };
    let examples = examples
        .and_then(|text| text.rfind("Examples:").map(|at| &text[at..]))
        .filter(|_| {
            text.contains("Usage:")
                && error.kind() != clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        });
    let text = match examples {
        Some(examples) => {
            let examples = Report::new(false, false).wrap(examples.trim_end(), 0);
            match text.find("\nFor more information") {
                Some(at) => format!("{}\n{examples}\n{}", &text[..at], &text[at..]),
                None => format!("{}\n{examples}\n", text.trim_end()),
            }
        }
        None => text,
    };
    format!("box: {text}")
}

fn telemetry(choice: Option<bool>) -> Result<(), Error> {
    Launcher::from_host().telemetry(choice, &mut std::io::stdout().lock())
}

fn list_runs(profile: Option<&str>, format: OutputFormat) -> Result<(), Error> {
    match Launcher::from_host().list_runs(profile, format, &mut std::io::stdout().lock()) {
        Err(Error::RunListOutput { source }) if source.kind() == std::io::ErrorKind::BrokenPipe => {
            Ok(())
        }
        result => result,
    }
}

fn parse_code(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    if bytes.len() == 5
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..].iter().all(u8::is_ascii_digit)
    {
        Ok(value.to_ascii_uppercase())
    } else {
        Err("a code is a letter and four digits, such as P0201".to_owned())
    }
}

fn parse_runs_profile(value: &str) -> Result<String, String> {
    if is_profile_path(value) {
        return Err(
            "a run records the profile's name, not its file; pass the `[profile] name` in that file"
                .to_owned(),
        );
    }
    validate_name(value)
        .map(|()| value.to_owned())
        .map_err(|error| error.to_string())
}

fn parse_records_since(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| {
            "use an RFC3339 timestamp with a timezone, such as 2026-11-11T12:00:00Z".to_owned()
        })
}

fn records(id: &str, options: RecordsOptions) -> Result<(), Error> {
    match Launcher::from_host().records(
        id,
        &options,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ) {
        Err(Error::RecordsOutput {
            stream: "stdout",
            source,
        }) if source.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

fn current_dir() -> Result<PathBuf, Error> {
    std::env::current_dir().map_err(|source| Error::Io {
        action: "read",
        path: PathBuf::from("."),
        source,
    })
}

fn show(name: &str, full: bool, format: OutputFormat, output: &mut dyn Write) -> Result<(), Error> {
    let json = matches!(format, OutputFormat::Json);
    let launcher = Launcher::from_host();
    let color = colored(&std::io::stdout());
    let preview = match launcher.preview(name, &current_dir()?) {
        Ok(preview) => preview,
        Err(error) => {
            if !json && let Ok(Some((profile, _))) = launcher.profiles().load(name) {
                profile_heading(output, &format!("Profile {name}"), color);
                section(output, "Saved settings", color);
                let _ = writeln!(output, "\n{}\n", profile.source().trim_end());
                let _ = writeln!(
                    output,
                    "{}\n",
                    styled(color, "33", "Run preview unavailable for this directory.")
                );
            }
            return Err(error);
        }
    };
    if json {
        return json_line(output, &preview.json(name, full)?).map_err(|source| Error::Io {
            action: "write to",
            path: PathBuf::from("stdout"),
            source,
        });
    }
    profile_heading(output, &format!("Profile {name}"), color);
    let guided = guided(&std::io::stdout());
    if guided {
        section(output, "Overview", color);
    }
    let _ = writeln!(
        output,
        "{}",
        styled(color, "32", "✓ Resolves for this directory")
    );
    let overview = preview.overview();
    let width = overview
        .iter()
        .map(|(label, _)| label.len())
        .fold(8, usize::max);
    for (label, text) in overview {
        let _ = writeln!(
            output,
            "  {}  {text}",
            styled(color, "2", &format!("{label:<width$}"))
        );
    }
    if !preview.inputs.is_empty() {
        if guided {
            section(output, "Options", color);
        } else {
            let _ = writeln!(output, "\n{}", styled(color, "1", "Options"));
        }
    }
    let width = preview
        .inputs
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or_default();
    for (input, value, source) in &preview.inputs {
        let _ = writeln!(
            output,
            "  {}  {value:?}  {}",
            styled(color, Report::ACCENT, &format!("{input:<width$}")),
            styled(color, "2", &format!("({source})"))
        );
    }
    let note = |output: &mut dyn Write, message: String| {
        let _ = writeln!(output, "  {} {message}", styled(color, "33", "!"));
    };
    if guided
        && (!preview.skipped.is_empty()
            || !preview.dropped.is_empty()
            || !preview.open_routes.is_empty())
    {
        section(output, "Access notes", color);
    }
    for (tool, why) in &preview.skipped {
        note(output, format!("skipped tool {tool}: {why}"));
    }
    for (tool, path) in &preview.dropped {
        note(
            output,
            format!("dropped {path} from tool {tool}: not on this host"),
        );
    }
    for (route, hosts) in &preview.open_routes {
        note(
            output,
            format!(
                "route {route}: {} (no credential, open to every program in the box)",
                hosts.join(", ")
            ),
        );
    }
    if guided
        && (!preview.copies.is_empty() || !preview.links.is_empty() || !preview.parts.is_empty())
    {
        section(output, "Files and storage", color);
    }
    for (source, target, what) in &preview.copies {
        let _ = writeln!(
            output,
            "  {} {source} -> {target} {}",
            styled(color, "2", "copy"),
            styled(color, "2", &format!("({what})"))
        );
    }
    for (link, what) in &preview.links {
        let _ = writeln!(output, "  link     {link} {what}");
    }
    for (what, target, names) in preview.part_lines() {
        let _ = writeln!(output, "  {what:<8} {names} in {target}");
    }
    if guided
        && (!preview.mcp_unstarted.is_empty()
            || !preview.mcp_unread.is_empty()
            || !preview.mcp_servers.is_empty()
            || !preview.mcp_dropped.is_empty()
            || !preview.mcp_unchecked.is_empty()
            || !preview.mcp_path_dropped.is_empty()
            || !preview.mcp_skipped.is_empty())
    {
        section(output, "MCP servers", color);
    }
    for (server, why) in &preview.mcp_unstarted {
        note(
            output,
            format!("no permit to start MCP server {server}: {why}"),
        );
    }
    for (file, why) in &preview.mcp_unread {
        note(output, format!("did not read {file}: {why}"));
    }
    for (server, file, detail) in &preview.mcp_servers {
        let _ = writeln!(output, "  mcp      {server} declared from {file}{detail}");
    }
    for (variable, server, file, why) in &preview.mcp_dropped {
        note(
            output,
            format!("dropped {variable} from MCP server {server} (from {file}): {why}"),
        );
    }
    for line in preview.mcp_unchecked_lines() {
        note(output, line);
    }
    for line in &preview.mcp_path_dropped {
        note(output, format!("dropped {line}"));
    }
    for (server, file, why) in &preview.mcp_skipped {
        note(
            output,
            format!("no automatic MCP declaration for {server} (from {file}): {why}"),
        );
    }
    if guided && !preview.warnings.is_empty() {
        section(output, "Policy notes", color);
    }
    for warning in &preview.warnings {
        note(output, format!("warning {warning}"));
    }
    if guided {
        let _ = writeln!(
            output,
            "\n  {}",
            styled(color, "2", "Preview only. No box started.")
        );
    }
    if full {
        let _ = writeln!(
            output,
            "\n# box.toml\n{}\n# policy.dw\n{}",
            preview.box_toml, preview.policy
        );
    } else {
        let _ = writeln!(
            output,
            "\n{}",
            styled(
                color,
                "2",
                &format!("Full configuration: box profile show {name} --full")
            )
        );
    }
    if guided {
        let _ = writeln!(
            output,
            "  {}  start",
            styled(color, Report::ACCENT, &format!("box run {name}"))
        );
    }
    Ok(())
}

/// What a pair of `--<name>` and `--no-<name>` flags sets: `None` when neither is given.
fn flag(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// The launcher of `box run`, with the banner choice of its flags.
fn run_launcher(banner: Option<bool>) -> Launcher {
    Launcher::from_host().banner(banner)
}

fn run(
    name: &str,
    box_id: Option<&str>,
    args: &[OsString],
    banner: Option<bool>,
) -> Result<ExitCode, Error> {
    let started = Instant::now();
    let launcher = run_launcher(banner);
    let (launch, session) = prepare_run(
        name,
        box_id,
        &launcher,
        current_dir(),
        started,
        create_from_starter,
        Session::delivering,
    )?;
    launch.run_with_telemetry(args, session)
}

fn capture_preparation(
    prepare: impl FnOnce() -> Preparation,
    started: Instant,
    capture: impl FnOnce(Invocation, LaunchOutcome) -> Option<Session>,
) -> Result<(Launch, Option<Session>), Error> {
    let startup_started_at = SystemTime::now();
    let prepared = prepare();
    let prepared_at = Instant::now();
    let outcome = prepared.result.as_ref().map_or_else(
        |error| LaunchOutcome::PreparationFailed(error.telemetry_failure()),
        |_| LaunchOutcome::Unknown,
    );
    let session = prepared.installation_id.and_then(|installation_id| {
        capture(
            Invocation::new(
                installation_id,
                prepared.context,
                started,
                startup_started_at,
            )?,
            outcome,
        )
    });
    match prepared.result {
        Ok(launch) => Ok((launch, session)),
        Err(error) => {
            if let Some(session) = session {
                session.finish_with_timeout(prepared_at, ExitOutcome::Nonzero, COMPLETION_BUDGET);
            }
            Err(error)
        }
    }
}

fn prepare_run(
    name: &str,
    box_id: Option<&str>,
    launcher: &Launcher,
    workspace: Result<PathBuf, Error>,
    started: Instant,
    create_profile: impl FnOnce(&str) -> Result<(), Error>,
    capture: impl FnOnce(Invocation, LaunchOutcome) -> Option<Session>,
) -> Result<(Launch, Option<Session>), Error> {
    let workspace = (|| {
        let workspace = workspace?;
        launcher.refuse_home_workspace(&workspace)?;
        if !is_profile_path(name)
            && box_id.is_none_or(|id| launcher.reusable(name, id))
            && !launcher.profiles().contains(name)?
            && launcher.is_starter(name)?
        {
            if !interactive() {
                eprintln!("box: no profile named {name}. Creating one from the {name} starter.");
            }
            create_profile(name)?;
        }
        Ok(workspace)
    })();
    capture_preparation(
        || {
            workspace
                .map(|workspace| launcher.prepare_with_context(name, &workspace, box_id))
                .unwrap_or_else(|error| launcher.failed_preparation(error))
        },
        started,
        capture,
    )
}

fn create_from_starter(name: &str) -> Result<(), Error> {
    create(
        Vec::new(),
        &[],
        None,
        Some(name.to_string()),
        HostArgs { tools: None },
        false,
        true,
    )
    .map(|_| ())
}

/// The saved profile the operator picks for `box run`, or a new one from a starter. With
/// `box_id`, only a profile that can reuse that box.
fn choose_profile(box_id: Option<&str>, context: &mut clap::Command) -> Result<String, Error> {
    let launcher = Launcher::from_host();
    launcher.refuse_home_workspace(&current_dir()?)?;
    if !interactive() {
        return Err(Error::RunUnnamed);
    }
    let names: Vec<String> = launcher
        .profiles()
        .list()?
        .into_iter()
        .map(|entry| entry.name)
        .filter(|name| box_id.is_none_or(|id| launcher.reusable(name, id)))
        .collect();
    if box_id.is_some() && names.is_empty() {
        return Err(Error::RunUnnamed);
    }
    let panel = Panel::enter()?;
    loop {
        panel.clear()?;
        let mut choices: Vec<&str> = names.iter().map(String::as_str).collect();
        if box_id.is_none() {
            choices.push("Create a new profile");
        }
        let picked = Terminal::stdio(&mut std::io::stdin().lock(), &mut std::io::stderr())
            .with_content(String::new())
            .menu("Run or create a profile", "box run --help", &choices);
        let picked = match picked {
            Err(Error::StarterAborted { .. }) => return Err(Error::ExitRequested),
            result => result?,
        };
        if let Some(name) = names.get(picked) {
            return Ok(name.clone());
        }
        panel.clear()?;
        match save_profile(NewProfile::from_host(), false, true, true) {
            Err(Error::StarterAborted { .. }) => continue,
            Err(error) => menu_result(Err(error), context, Vec::new())?,
            Ok(created) => return Ok(created.name().to_string()),
        }
    }
}

fn menu_error(error: Error, context: &mut clap::Command, report: &mut Vec<u8>) {
    let examples = context.get_after_help().map(ToString::to_string);
    let message = Report::new(false, false).wrap(&error.to_string(), "box: error: ".len());
    let _ = write!(
        report,
        "{}",
        diagnostic(
            &context.error(clap::error::ErrorKind::ValueValidation, message),
            examples.as_deref(),
        )
    );
}

fn menu_result(
    result: Result<(), Error>,
    context: &mut clap::Command,
    mut report: Vec<u8>,
) -> Result<(), Error> {
    match result {
        Err(error @ (Error::Interrupted | Error::ExitRequested)) => return Err(error),
        Err(Error::StarterAborted { .. } | Error::Kept) => return Ok(()),
        Err(error) => menu_error(error, context, &mut report),
        Ok(()) => {}
    }
    let result = Terminal::stdio(&mut std::io::stdin().lock(), &mut std::io::stderr())
        .with_back()
        .with_content(String::from_utf8_lossy(&report).into_owned())
        .pick_choice("Back or exit", &["Back", "Exit"]);
    match result {
        Ok(0) | Err(Error::StarterAborted { .. }) => Ok(()),
        Ok(_) => Err(Error::ExitRequested),
        Err(error) => Err(error),
    }
}

fn profile_action(
    command: ProfileCommand,
    context: &mut clap::Command,
) -> Result<Option<String>, Error> {
    match command {
        ProfileCommand::Create {
            with,
            options,
            policy,
            name,
            host,
            force,
        } => {
            let panel = Panel::enter()?;
            let created = create(with, &options, policy, name, host, force, false)?;
            if interactive() {
                saved_profile_menu(created, &panel, context)
            } else {
                Ok(None)
            }
        }
        ProfileCommand::Edit { name } => {
            let profile = NewProfile::from_host().edit(&name)?;
            if !interactive() {
                return Err(Error::EditNeedsTerminal {
                    path: Launcher::from_host().profiles().path(&name),
                });
            }
            let panel = Panel::enter()?;
            let created = save_profile(profile, false, false, false)?;
            saved_profile_menu(created, &panel, context)
        }
        ProfileCommand::List => list(&mut std::io::stdout()).map(|()| None),
        ProfileCommand::Show { name, full, format } => {
            show(&name, full, format, &mut std::io::stdout()).map(|()| None)
        }
        ProfileCommand::Clean {
            names,
            all,
            box_id: Some(id),
            no_ask,
        } if !all => {
            if names.len() != 1 {
                let examples = context.get_after_help().map(ToString::to_string);
                let usage = context.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    Error::CleanBoxIdOneProfile.to_string(),
                );
                print_diagnostic(&usage, examples.as_deref());
                std::process::exit(usage.exit_code());
            }
            profile_clean_box(&names, &id, no_ask).map(|()| None)
        }
        ProfileCommand::Clean {
            names, all, no_ask, ..
        } => profile_clean(&names, all, no_ask).map(|()| None),
        ProfileCommand::Delete { names, all, no_ask } => {
            profile_delete(&names, all, no_ask).map(|()| None)
        }
        ProfileCommand::Reset { names, all, no_ask } => {
            profile_reset(&names, all, no_ask).map(|()| None)
        }
    }
}

fn edit_profile(name: &str, context: &mut clap::Command) -> Result<Option<CreatedProfile>, Error> {
    match NewProfile::from_host()
        .edit(name)
        .and_then(|profile| save_profile(profile, false, false, true))
    {
        Ok(created) => Ok(Some(created)),
        Err(error) => {
            menu_result(Err(error), context, Vec::new())?;
            Ok(None)
        }
    }
}

fn saved_profile_menu(
    mut created: CreatedProfile,
    panel: &Panel,
    context: &mut clap::Command,
) -> Result<Option<String>, Error> {
    loop {
        panel.clear()?;
        let action = Terminal::stdio(&mut std::io::stdin().lock(), &mut std::io::stderr())
            .with_content(created.guided_summary(colored(&std::io::stderr())))
            .pick_choice("Profile actions", &["Run", "Edit", "Exit"]);
        match action {
            Ok(0) => return Ok(Some(created.name().to_string())),
            Ok(1) => {
                panel.clear()?;
                if let Some(edited) = edit_profile(created.name(), context)? {
                    created = edited;
                }
            }
            Err(Error::StarterAborted { .. }) => return Ok(None),
            Ok(_) => return Err(Error::ExitRequested),
            Err(error) => return Err(error),
        }
    }
}

/// Create a profile. With `run`, review it as one that runs here next.
fn create(
    with: Vec<String>,
    options: &[String],
    policy: Option<String>,
    name: Option<String>,
    host: HostArgs,
    force: bool,
    run: bool,
) -> Result<CreatedProfile, Error> {
    let mut profile = NewProfile::from_host();
    for pack in with {
        profile = profile.with(pack);
    }
    for (option, value) in pairs(options)? {
        profile = profile.option(option, value);
    }
    if let Some(name) = name {
        profile = profile.name(name);
    }
    if let Some(policy) = policy {
        profile = profile.policy(policy);
    }
    if let Some(tools) = host.tools {
        profile = profile.tools(tools);
    }
    let created = save_profile(profile, force, run, false)?;
    let mut output = std::io::stdout();
    let color = colored(&output);
    if interactive() {
        if run {
            let _ = writeln!(
                output,
                "{} Saved profile {}",
                styled(color, "32", "✓"),
                created.name()
            );
        }
    } else {
        let _ = write!(output, "{}", created.summary(color));
        if !run {
            let _ = write!(output, "{}", created.next_steps(color));
        }
    }
    Ok(created)
}

fn save_profile(
    profile: NewProfile,
    force: bool,
    run: bool,
    back: bool,
) -> Result<CreatedProfile, Error> {
    let mut input = std::io::stdin().lock();
    let mut prompts = std::io::stderr();
    let mut request = profile.force(force);
    if run {
        request = request.run_in(current_dir()?);
    }
    let created = if interactive() {
        let mut terminal = Terminal::stdio(&mut input, &mut prompts);
        if back {
            terminal = terminal.with_back();
        }
        request.guided(&mut terminal)?
    } else {
        request.answer(None)?.create()?
    };
    created.write(force)?;
    Ok(created)
}

fn list(output: &mut dyn Write) -> Result<(), Error> {
    let profiles = Launcher::from_host().profiles();
    let listed = profiles.list()?;
    let color = colored(&std::io::stdout());
    profile_heading(output, "Profiles", color);
    if listed.is_empty() {
        let _ = writeln!(
            output,
            "No profiles in {}. Create one from a starter: `box profile create <starter>`.",
            profiles.root().display()
        );
    }
    let guided = guided(&std::io::stdout());
    let report = Report::new(guided, color);
    for entry in listed {
        let (name_style, status, detail) = match entry.profile {
            Ok(profile) => {
                let packs = profile.packs().join(", ");
                let detail = if guided {
                    format!("Packs  {}", report.wrap(&packs, 11))
                } else {
                    format!("packs {packs}")
                };
                (
                    "1;38;2;74;222;128",
                    styled(color, "32", "✓ Readable"),
                    styled(color, "2", &detail),
                )
            }
            Err(error) => (
                "1",
                styled(color, "31", "! Invalid"),
                if guided {
                    report.wrap(&error.to_string(), 4)
                } else {
                    format!("{} {error}", styled(color, "31", "! invalid:"))
                },
            ),
        };
        let status = if guided {
            format!("  {status}")
        } else {
            String::new()
        };
        let _ = writeln!(
            output,
            "  {}{status}\n    {detail}\n",
            styled(color, name_style, &entry.name)
        );
    }
    let starters = match Launcher::from_host().starters() {
        Ok(starters) => starters,
        Err(error) => {
            let _ = writeln!(output, "\nStarters: invalid: {error}");
            return Ok(());
        }
    };
    if !starters.is_empty() {
        if guided {
            section(output, "Starters", color);
        } else {
            let _ = writeln!(output, "{}", styled(color, "1", "Starters:"));
        }
        let width = starters
            .iter()
            .map(|starter| starter.name.len())
            .max()
            .unwrap_or_default();
        for starter in starters {
            match starter.label {
                Ok(description) => {
                    let _ = writeln!(
                        output,
                        "  {}  {description}",
                        styled(color, Report::ACCENT, &format!("{:<width$}", starter.name))
                    );
                }
                Err(reason) => {
                    let _ = writeln!(
                        output,
                        "  {:<width$}  {} {reason}",
                        starter.name,
                        styled(color, "31", "! invalid:")
                    );
                }
            }
        }
    }
    if guided {
        let _ = writeln!(
            output,
            "\n  {}",
            styled(
                color,
                "2",
                "Listed from profile files. Use show to check packs and policies."
            )
        );
        let _ = writeln!(
            output,
            "\n  {}  inspect\n  {}  create",
            styled(color, Report::ACCENT, "box profile show <name>"),
            styled(color, Report::ACCENT, "box profile create <name>")
        );
    }
    Ok(())
}

fn profile_clean_box(names: &[String], id: &str, no_ask: bool) -> Result<(), Error> {
    let [name] = names else {
        return Err(Error::CleanBoxIdOneProfile);
    };
    let launcher = Launcher::from_host();
    launcher.profile_box(name, id)?;
    let held = launcher.hold_boxes(&[id.to_string()], "clean")?;
    ask(
        no_ask,
        &format!("Remove box {id} of profile {name}, and its records?"),
    )?;
    let mut removed = 0;
    held.remove(&mut removed)?;
    if removed == 0 {
        return Err(Error::BoxIdUnknown {
            id: id.to_string(),
            root: launcher.runs_root(),
        });
    }
    eprintln!("box: removed box {id} of profile {name}");
    Ok(())
}

fn profile_clean(names: &[String], all: bool, no_ask: bool) -> Result<(), Error> {
    let launcher = Launcher::from_host();
    let ids = launcher.profile_boxes((!all).then_some(names))?;
    let mut owners = Vec::new();
    if !all {
        for name in names {
            if launcher
                .profile_boxes(Some(std::slice::from_ref(name)))?
                .is_empty()
            {
                if names.len() > 1 {
                    eprintln!("box: no boxes found for profile {name}");
                }
            } else {
                owners.push(name.clone());
            }
        }
    }
    let whose = named_profiles(if owners.is_empty() { names } else { &owners });
    if ids.is_empty() {
        if all {
            eprintln!("box: no boxes found");
        } else {
            eprintln!("box: no boxes found for {whose}");
        }
        return Ok(());
    }
    let held = launcher.hold_boxes(&ids, "clean")?;
    let found = held.len();
    let records = if found == 1 { "its" } else { "their" };
    let (question, done) = if all {
        let every = if found == 1 {
            "the only box".to_string()
        } else {
            format!("all {found} boxes")
        };
        (format!("Remove {every}, and {records} records?"), every)
    } else {
        (
            format!("Remove {} of {whose}, and {records} records?", boxes(found)),
            format!("{} of {whose}", boxes(found)),
        )
    };
    ask(no_ask, &question)?;
    let mut removed = 0;
    let result = held.remove(&mut removed);
    if removed == found {
        eprintln!("box: removed {done}");
    } else {
        let whole = if all {
            format!("{found} boxes")
        } else {
            format!("{found} boxes of {whose}")
        };
        eprintln!("box: removed {removed} of {whole}");
    }
    result
}

/// `names` for the operator: `profile claude`, or `profiles claude, codex`.
fn named_profiles(names: &[String]) -> String {
    format!(
        "{} {}",
        if names.len() == 1 {
            "profile"
        } else {
            "profiles"
        },
        names.join(", ")
    )
}

/// `items` joined for the operator: `a`, `a and b`, or `a, b, and c`.
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [first, second] => format!("{first} and {second}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// The names to act on: the names given, each a valid profile name, or with `--all` the profiles
/// and the storage folders that `box` holds.
fn profile_targets(launcher: &Launcher, names: &[String], all: bool) -> Result<Vec<String>, Error> {
    if !all {
        for name in names {
            validate_name(name)?;
        }
        return Ok(names.to_vec());
    }
    let mut targets: Vec<String> = launcher
        .profiles()
        .list()?
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    for name in launcher.stored_profiles()? {
        if !targets.contains(&name) {
            targets.push(name);
        }
    }
    targets.sort();
    Ok(targets)
}

/// Hold each box of `profiles` (every box when `None`) that started after `held` was listed, while
/// the operator answered. Refuse when one of them is running.
fn hold_late_boxes(
    launcher: &Launcher,
    profiles: Option<&Vec<String>>,
    held: &[String],
    command: &'static str,
) -> Result<HeldBoxes, Error> {
    let late: Vec<String> = launcher
        .profile_boxes(profiles.map(Vec::as_slice))?
        .into_iter()
        .filter(|id| !held.contains(id))
        .collect();
    launcher.hold_boxes(&late, command)
}

fn profile_delete(names: &[String], all: bool, no_ask: bool) -> Result<(), Error> {
    let launcher = Launcher::from_host();
    let profiles = launcher.profiles();
    let targets = profile_targets(&launcher, names, all)?;
    let mut present = Vec::new();
    let mut stored = Vec::new();
    for name in &targets {
        if profiles.contains(name)? {
            present.push(name.clone());
        }
        if launcher.storage_folder(name).symlink_metadata().is_ok() {
            stored.push(name.clone());
        }
    }
    let ids = launcher.profile_boxes((!all).then_some(&targets))?;
    let any_profile_entry =
        all && std::fs::read_dir(profiles.root()).is_ok_and(|mut entries| entries.next().is_some());
    if !all && names.len() > 1 {
        for name in &targets {
            if !present.contains(name)
                && !stored.contains(name)
                && launcher
                    .profile_boxes(Some(std::slice::from_ref(name)))?
                    .is_empty()
            {
                eprintln!("box: no profile {name} found");
            }
        }
    }
    if present.is_empty() && !any_profile_entry && stored.is_empty() && ids.is_empty() {
        if all {
            eprintln!("box: no profiles found");
        } else {
            eprintln!("box: no {} found", named_profiles(names));
        }
        return Ok(());
    }
    let held = launcher.hold_boxes(&ids, "delete")?;
    let whose = if all && (any_profile_entry || !present.is_empty()) {
        "every profile".to_string()
    } else if all {
        "what is left of every profile".to_string()
    } else if present.is_empty() {
        format!("what is left of {}", named_profiles(&targets))
    } else {
        named_profiles(&present)
    };
    let mut with = Vec::new();
    if !ids.is_empty() {
        with.push(boxes(ids.len()));
    }
    if !stored.is_empty() {
        with.push(if all {
            "all storage".to_string()
        } else if stored.len() > 1 {
            "their storage".to_string()
        } else {
            "its storage".to_string()
        });
    }
    let what = if with.is_empty() {
        whose
    } else {
        format!("{whose}, with {}", and_list(&with))
    };
    ask(no_ask, &format!("Delete {what}?"))?;
    let late = hold_late_boxes(&launcher, (!all).then_some(&targets), &ids, "delete")?;
    let mut removed = 0;
    if let Err(error) = held
        .remove(&mut removed)
        .and_then(|()| late.remove(&mut removed))
    {
        eprintln!(
            "box: deleted {} of {} before the error; the profiles and their storage are kept",
            removed,
            boxes(ids.len())
        );
        return Err(error);
    }
    for name in &stored {
        launcher.remove_storage(name)?;
    }
    if all {
        profiles.reset()?;
    } else {
        for name in &present {
            profiles.remove(name)?;
        }
    }
    eprintln!("box: deleted {what}");
    Ok(())
}

fn profile_reset(names: &[String], all: bool, no_ask: bool) -> Result<(), Error> {
    let launcher = Launcher::from_host();
    let targets = profile_targets(&launcher, names, all)?;
    let mut stored = Vec::new();
    for name in &targets {
        if launcher.has_storage(name)? {
            stored.push(name.clone());
        } else if !all && names.len() > 1 {
            eprintln!("box: no storage found for profile {name}");
        }
    }
    if stored.is_empty() {
        if all {
            eprintln!("box: no storage found");
        } else {
            eprintln!("box: no storage found for {}", named_profiles(names));
        }
        return Ok(());
    }
    let ids = launcher.profile_boxes(Some(&stored))?;
    let held = launcher.hold_boxes(&ids, "reset")?;
    let whose = if all {
        "every profile".to_string()
    } else {
        named_profiles(&stored)
    };
    let keeps = if all || stored.len() > 1 {
        "Each agent loses its settings and sessions. The profiles and their boxes stay."
    } else {
        "The agent loses its settings and sessions. The profile and its boxes stay."
    };
    ask(no_ask, &format!("Delete the storage of {whose}? {keeps}"))?;
    let late = hold_late_boxes(&launcher, Some(&stored), &ids, "reset")?;
    for name in &stored {
        launcher.reset_storage(name)?;
    }
    drop((held, late));
    eprintln!("box: deleted the storage of {whose}");
    Ok(())
}

/// Ask `question` on the terminal, unless `--no-ask` is given.
fn ask(no_ask: bool, question: &str) -> Result<(), Error> {
    if no_ask {
        return Ok(());
    }
    if !interactive() {
        return Err(Error::Unconfirmed);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stderr();
    Terminal::stdio(&mut input, &mut output).confirm(question)
}

/// Whether `box` can ask: stdin and stderr are terminals.
fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// `count` run folders, counted for the operator.
fn boxes(count: usize) -> String {
    if count == 1 {
        "1 box".to_string()
    } else {
        format!("{count} boxes")
    }
}

/// Whether `stream` is a terminal that accepts ANSI color.
fn colored(stream: &impl IsTerminal) -> bool {
    stream.is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

fn styled(color: bool, code: &str, text: &str) -> String {
    Report::new(false, color).paint(code, text)
}

fn guided(stream: &impl IsTerminal) -> bool {
    stream.is_terminal()
        && std::env::var_os("TERM").is_some_and(|term| term != "dumb" && !term.is_empty())
}

fn section(output: &mut dyn Write, title: &str, color: bool) {
    let _ = writeln!(
        output,
        "\n{}",
        Report::new(guided(&std::io::stdout()), color).section(title)
    );
}

fn profile_heading(output: &mut dyn Write, title: &str, color: bool) {
    let _ = write!(
        output,
        "{}",
        Report::new(guided(&std::io::stdout()), color).heading(title)
    );
}

#[cfg(all(test, feature = "test-support"))]
#[path = "main_tests.rs"]
mod tests;
