//! The errors that `box` reports, from a profile to a run.
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

/// Why `box` could not produce, write, or run a configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An `--option` is not `name=value`.
    #[error("--option {option:?} is not `name=value`")]
    OptionSyntax {
        /// The option as given.
        option: String,
    },

    /// An `--option` names no input, or names one twice.
    #[error("--option {option:?} {reason}")]
    OptionFlag {
        /// The input name as given.
        option: String,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// The host is not one `box` supports yet.
    #[error("box supports macOS and Linux")]
    UnsupportedPlatform,

    /// `HOME` is unset or does not resolve.
    #[error("HOME is unset or does not resolve; box needs the operator home")]
    NoHome,

    /// `BOX_HOME` is not a full path.
    #[error("BOX_HOME must be a full path, not {}", path.display())]
    BoxHomeRelative {
        /// The value of `BOX_HOME`.
        path: PathBuf,
    },

    /// The project is missing or is not a directory.
    #[error("project {path} is not a directory")]
    Project {
        /// The project as given.
        path: PathBuf,
    },

    /// The project is the operator home or holds it.
    #[error(
        "{path} is your home folder (or holds it), and box won't hand an agent your whole home. \
         cd into a project folder, such as ~/src/my-app, and run the command again"
    )]
    ProjectHoldsHome {
        /// The canonical project.
        path: PathBuf,
    },

    /// The project holds the directory the configuration or the box state goes in.
    #[error("project {path} holds {holds}; choose a project outside it")]
    ProjectHoldsBox {
        /// The canonical project.
        path: PathBuf,
        /// The directory it holds.
        holds: PathBuf,
    },

    /// The configuration directory is a symbolic link.
    #[error("{path} is a symbolic link; box writes only into a real directory")]
    Symlink {
        /// The link.
        path: PathBuf,
    },

    /// A `[[storage.files]]` row cannot be copied into storage.
    #[error("cannot copy {path} into storage: {reason}")]
    Copy {
        /// The row's source.
        path: PathBuf,
        /// Why.
        reason: String,
    },

    /// A `[[storage.files.set]]` row cannot rewrite the copy in storage.
    #[error("`{at}`: {reason}")]
    Set {
        /// The row, such as `storage.files[0]`.
        at: String,
        /// Why.
        reason: String,
    },

    /// A requested tool is not one `box` knows.
    #[error("unknown tool {name:?}; known tools: {known}")]
    UnknownTool {
        /// The requested name.
        name: String,
        /// The names `box` detects.
        known: String,
    },

    /// A path cannot be written into a configuration because it is not UTF-8.
    #[error("{path} is not UTF-8")]
    NotUtf8 {
        /// The path.
        path: PathBuf,
    },

    /// A file would be overwritten without `--force`.
    #[error("{path} exists; pass --force to overwrite")]
    Exists {
        /// The existing file.
        path: PathBuf,
    },

    /// A profile name is not one `box` accepts.
    #[error("invalid profile name {name:?}: {reason}")]
    ProfileName {
        /// The name as given.
        name: String,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A profile file that `box run` names by its path cannot be read.
    #[error("cannot read the profile {path}: {source}")]
    ProfilePath {
        /// The path as given.
        path: PathBuf,
        /// Why it cannot be read.
        source: std::io::Error,
    },

    /// A profile file that `box run` names by its path declares no name.
    #[error("{path} names no profile: add `[profile] name = \"<name>\"` to it")]
    ProfileFileUnnamed {
        /// The profile file.
        path: PathBuf,
    },

    /// Another profile already has the name that a profile file declares.
    #[error(
        "the profile name {name:?} in {path} belongs to {owner}; give this profile another \
         `[profile] name`"
    )]
    ProfileNameTaken {
        /// The declared name.
        name: String,
        /// The profile file that declares it.
        path: PathBuf,
        /// The profile that owns the name.
        owner: PathBuf,
    },

    /// A profile file owns the name that a profile in `~/.strands/box/profiles/` or a new profile uses.
    #[error(
        "the profile name {name:?} belongs to the profile file {owner}; run that file by its path, \
         or choose another name"
    )]
    ProfileNameOwned {
        /// The name.
        name: String,
        /// The profile file that owns the name.
        owner: PathBuf,
    },

    /// The profile file that a name's record holds no longer exists, or no longer declares it.
    #[error(
        "the profile name {name:?} was recorded for {owner}, which no longer exists or no longer \
         declares it; if you moved, renamed, or deleted that profile, remove {record}, and run \
         again"
    )]
    ProfileNameOwnerGone {
        /// The name.
        name: String,
        /// The path that the record holds.
        owner: PathBuf,
        /// The record of the owner.
        record: PathBuf,
    },

    /// A profile file or policy file that another name or another user can change.
    #[error(
        "{path} cannot be a profile or policy file: {reason}; run `chmod go-w {path}`, or use a \
         copy with one name that only you own"
    )]
    ProfileFileShared {
        /// The file.
        path: PathBuf,
        /// Why another name or user can change it.
        reason: &'static str,
    },

    /// The project holds a profile file that an earlier run loaded, outside the project's `.box`.
    #[error(
        "project {workspace} holds the profile file {profile}, which a box in this project could \
         change before that profile's next run; run in a folder that does not hold it, or move \
         the profile file outside the project or into its `.box` folder"
    )]
    WorkspaceHoldsProfile {
        /// The project.
        workspace: PathBuf,
        /// The profile file an earlier run loaded.
        profile: PathBuf,
    },

    /// A profile file, or one of its policy files, is in the project that the agent can write.
    #[error(
        "{path} is in the project {workspace}, which the agent can write; keep the profile and \
         its policy files outside the project, or in its `.box` folder"
    )]
    ProfileInWorkspace {
        /// The profile file or policy file.
        path: PathBuf,
        /// The project.
        workspace: PathBuf,
    },

    /// `box profile create` got neither a name nor a pack.
    #[error(
        "provide a profile name or --with <PACK>\n\n  \
         tip: list starters with 'box profile list'"
    )]
    ProfileUnnamed,

    /// `box run` got no profile, and there is no terminal to choose one on.
    #[error(
        "name a profile to run: box run <PROFILE>\n\n  \
         tip: list profiles with 'box profile list'"
    )]
    RunUnnamed,

    /// `box profile edit` has no terminal to ask on.
    #[error("box profile edit needs a terminal. Edit {} in your editor.", path.display())]
    EditNeedsTerminal {
        /// The profile's `profile.toml`.
        path: PathBuf,
    },

    /// No profile of this name exists.
    #[error("no profile named {name} at {path}. {hint}")]
    ProfileMissing {
        /// The profile name.
        name: String,
        /// Where the profile would be.
        path: PathBuf,
        /// How to create it.
        hint: String,
    },

    /// `config.toml` is not valid.
    #[error("{path}: {reason}")]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },

    /// A starter needs an answer, and there is no terminal to ask on.
    #[error("{command} needs an answer to {question:?}\n{flags}")]
    StarterUnanswered {
        /// The command that answers it.
        command: String,
        /// The question or the input.
        question: String,
        /// One line for each flag that answers it.
        flags: String,
    },

    /// The operator ended the input before a starter question had an answer.
    #[error("no answer to {question:?}; nothing was written")]
    StarterAborted {
        /// The question or the input.
        question: String,
    },

    /// The operator interrupted a prompt or closed its input.
    #[error("cancelled")]
    Interrupted,

    /// The operator chose to leave the interactive menu.
    #[error("exit requested")]
    ExitRequested,

    /// A profile or a pack is not valid.
    #[error("{}: {reason}", located(path, *line))]
    Profile {
        /// The file.
        path: PathBuf,
        /// The line in the file, when one line is wrong.
        line: Option<usize>,
        /// What is wrong with it.
        reason: String,
    },

    /// Box Core refuses the compiled policy.
    #[error("{}", described(findings))]
    Policy {
        /// Each problem in the combined policy.
        findings: Vec<PolicyFinding>,
    },

    /// Box Core cannot check the compiled policy.
    #[error("Box Core cannot check the policy: {reason}")]
    PolicyCheck {
        /// Why.
        reason: String,
    },

    /// A file or a program that a profile reads is not on this host.
    #[error("{path}: {reason}")]
    NotOnHost {
        /// The profile.
        path: PathBuf,
        /// What is missing.
        reason: String,
    },

    /// A program lies under a write grant, where the workload can replace it.
    #[error(
        "{program} lies under the write grant {grant} of `[{writer}]`, so the workload can replace it; to keep it, list {folder} in your profile's `[filesystem] deny_write`"
    )]
    ProgramUnderWrite {
        /// The program, `exec` entry, or search-path directory.
        program: PathBuf,
        /// The folder to list: the program when it is a directory, else its parent.
        folder: PathBuf,
        /// The write grant.
        grant: PathBuf,
        /// The table whose write grant reaches the program, as `agent`, `tool.<name>`, or
        /// `mcp.<name>`.
        writer: String,
    },
    /// The program of a secret source, its `#!` interpreter, or a path in its `command`, lies under
    /// a write grant, where the workload can replace it, or holds one, where the workload can change
    /// what is in it. The path can be a file, a folder, or absent. A `deny_write` does not keep it,
    /// because the program runs outside every sandbox.
    #[error(
        "{program} {} the write grant {grant} of `[{writer}]`, so the workload can {}; keep the program of each secret source, its `#!` interpreter, and each path in its `command`, outside every write grant",
        if *.holds { "holds" } else { "lies under" },
        if *.holds { "change what is in it" } else { "replace it" }
    )]
    SourceProgramUnderWrite {
        /// The program or the path.
        program: PathBuf,
        /// The write grant.
        grant: PathBuf,
        /// The table whose write grant reaches it.
        writer: String,
        /// Whether the path is a folder that holds the grant, and does not lie under it.
        holds: bool,
    },
    /// An `exec` folder holds a write grant, where the workload can write a program and run it.
    #[error(
        "the `exec` folder {exec} holds the write grant {grant}, so the workload can run a file it writes"
    )]
    WriteUnderExec {
        /// The `exec` entry.
        exec: PathBuf,
        /// The write grant inside it.
        grant: PathBuf,
    },

    /// A write grant reaches a directory that later runs trust.
    #[error(
        "the agent could change files that box trusts\n\n  \
         Writable: {grant}\n  \
         Protected: {protected}\n\n  \
         Run box from a project folder that does not contain its install or build folder.\n  \
         If a profile grants this access, remove or narrow that write entry."
    )]
    WriteOverProtected {
        /// The write grant.
        grant: PathBuf,
        /// The protected directory.
        protected: PathBuf,
    },

    /// The project configuration directory is a symbolic link or a file.
    #[error("{path} is not a directory; box refuses a `.box` that is a link or a file")]
    ProjectConfiguration {
        /// The `.box` entry.
        path: PathBuf,
    },

    /// No directory holds the packs that `box` ships.
    #[error(
        "no box resources found; looked at {looked}. Set BOX_RESOURCES to the resources directory"
    )]
    Resources {
        /// Every directory that was tried.
        looked: String,
    },

    /// The resource directory holds the packs and not the profile guide.
    #[error(
        "the profile guide is missing: {path} does not exist. This resources folder is from a box \
         without the guide; use the resources folder of this box"
    )]
    GuideMissing {
        /// Where the guide must be.
        path: PathBuf,
    },

    /// `--box-id` names no run of this operator.
    #[error("no run {id:?} in {root}; pass a box ID from `box runs list`")]
    BoxIdUnknown {
        /// The box ID.
        id: String,
        /// The runs directory.
        root: PathBuf,
    },

    /// `--box-id` names an identity that Box Core generated, which no run of `box` holds.
    #[error(
        "{id:?} is an ID that Box Core generated, and no `box run` makes one; pass a box ID from `box runs list`"
    )]
    BoxIdCore {
        /// The identity that Box Core generated.
        id: String,
    },

    /// `--box-id` names a run of another profile.
    #[error(
        "run {id:?} is not a run of profile {profile}; pass a box ID for that profile from `box runs list`, or run without --box-id to start fresh"
    )]
    BoxIdProfile {
        /// The box ID.
        id: String,
        /// The profile of this run.
        profile: String,
    },

    /// `--box-id` names a run that is still running.
    #[error(
        "run {id:?} is still running; wait for it to exit, or run without --box-id to start fresh"
    )]
    BoxIdRunning {
        /// The box ID.
        id: String,
    },

    /// `box profile clean --box-id` names a box that the named profile does not own.
    #[error(
        "box {id} is not a box of profile {profile}; pass a box ID that `box runs list {profile}` shows"
    )]
    CleanBoxNotOwned {
        /// The box ID.
        id: String,
        /// The named profile.
        profile: String,
    },

    /// `box profile clean --box-id` names other than one profile.
    #[error(
        "--box-id removes one box of one profile, so name exactly one profile, such as `box profile clean claude --box-id <BOX_ID>`"
    )]
    CleanBoxIdOneProfile,

    /// `box profile clean` cannot hold every box at once under the open-file limit.
    #[error(
        "cannot remove {count} boxes at once, because this process may open only {limit} files; raise the limit with `ulimit -n`, then run box profile {command} again"
    )]
    TooManyBoxes {
        /// The `box profile` command that would remove the boxes.
        command: &'static str,
        /// The boxes to remove.
        count: usize,
        /// The open-file limit.
        limit: u64,
    },

    /// A `box profile` command would remove a box, or the storage of a box, that is still running.
    #[error(
        "{id} is still running, so nothing was removed; exit that box, then run box profile {command} again"
    )]
    CleanBoxRunning {
        /// The `box profile` command.
        command: &'static str,
        /// The running box ID.
        id: String,
    },

    /// A `box profile` command would remove boxes, or the storage of boxes, that are still running.
    #[error(
        "these boxes are still running, so nothing was removed: {ids}; exit them, then run box profile {command} again"
    )]
    BoxesRunning {
        /// The `box profile` command.
        command: &'static str,
        /// The running box IDs, comma-separated.
        ids: String,
    },

    /// The operator did not answer yes to a removal.
    #[error("nothing was removed")]
    Kept,

    /// A removal needs a yes, and there is no terminal to ask on.
    #[error("box asks before it removes anything; pass --no-ask to remove without a terminal")]
    Unconfirmed,

    /// The generated `box.toml` could not be rendered.
    #[error("cannot render box.toml: {0}")]
    Render(#[from] toml::ser::Error),

    /// `box` cannot parse the generated `box.toml` again.
    #[error("cannot read back the generated box.toml: {0}")]
    Reread(#[source] toml_edit::TomlError),

    /// The records command needs a literal run directory name.
    #[error("invalid box ID {id:?}; pass a box ID from `box runs list`")]
    RecordsId {
        /// The box ID as given.
        id: String,
    },

    /// A saved records file could not be opened or read.
    #[error("cannot read records at {path:?}: {source}")]
    RecordsRead {
        /// The expected records file.
        path: PathBuf,
        /// The read failure.
        #[source]
        source: std::io::Error,
    },

    /// One or more lines were skipped after a read or parse failure.
    #[error("records at {path:?} contain unreadable lines; output is incomplete")]
    RecordsIncomplete {
        /// The records file with skipped lines.
        path: PathBuf,
    },

    /// The saved-run list could not be written.
    #[error("cannot write run list to stdout: {source}")]
    RunListOutput {
        /// The write failure.
        #[source]
        source: std::io::Error,
    },

    /// Decision output or its warnings could not be written.
    #[error("cannot write records to {stream}: {source}")]
    RecordsOutput {
        /// The output stream.
        stream: &'static str,
        /// The write failure.
        #[source]
        source: std::io::Error,
    },

    /// A filesystem operation failed.
    #[error("cannot {action} {path}: {source}")]
    Io {
        /// What was being done.
        action: &'static str,
        /// The path it was done to.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// The preparation failure category, with diagnostic text excluded.
    pub fn telemetry_failure(&self) -> strands_box_cli_telemetry::FailureReason {
        use strands_box_cli_telemetry::FailureReason;
        match self {
            Self::ProfileMissing { .. } => FailureReason::ProfileMissing,
            Self::ProfilePath { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                FailureReason::ProfileMissing
            }
            Self::Profile { .. }
            | Self::ProfileName { .. }
            | Self::ProfilePath { .. }
            | Self::ProfileFileUnnamed { .. }
            | Self::ProfileNameTaken { .. }
            | Self::ProfileNameOwned { .. }
            | Self::ProfileNameOwnerGone { .. }
            | Self::ProfileFileShared { .. }
            | Self::ProfileInWorkspace { .. } => FailureReason::ProfileInvalid,
            Self::Policy { .. } => FailureReason::PolicyRejected,
            _ => FailureReason::Unknown,
        }
    }
}

/// One problem that Box Core finds in a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFinding {
    /// The combined `policy.dw` that Box Core checks.
    pub path: PathBuf,
    /// The line in the file, when Box Core or the rule's `@id` places it.
    pub line: Option<usize>,
    /// Box Core's message, and its hint.
    pub reason: String,
}

impl std::fmt::Display for PolicyFinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {}",
            located(&self.path, self.line),
            self.reason
        )
    }
}

/// One finding on its line, or each finding on a line of its own.
fn described(findings: &[PolicyFinding]) -> String {
    match findings {
        [finding] => finding.to_string(),
        _ => {
            let lines: Vec<String> = findings
                .iter()
                .map(|finding| format!("\n  {finding}"))
                .collect();
            format!("Box Core refuses the policy:{}", lines.concat())
        }
    }
}

/// `path`, and `:line` when there is one.
fn located(path: &Path, line: Option<usize>) -> String {
    match line {
        Some(line) => format!("{}:{line}", path.display()),
        None => path.display().to_string(),
    }
}
