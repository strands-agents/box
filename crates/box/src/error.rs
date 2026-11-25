//! Why a box refused to run, or stopped running.

use std::path::PathBuf;

use crate::run::events::RefusalKind;

/// Why a box refused to run or reload, or stopped running.
#[derive(Debug)]
pub(crate) struct BoxError(Internal);

impl BoxError {
    /// Whether no box is open for reload in this process.
    pub(crate) fn is_not_running(&self) -> bool {
        matches!(self.0, Internal::Daemon(DaemonError::NotRunning))
    }

    /// Mark this failure as the agent's program not being installed, so its kind is
    /// `AgentNotFound`. The message stays as it was.
    pub(crate) fn agent_not_found(self) -> Self {
        Self(Internal::AgentNotFound(Box::new(self.0)))
    }

    /// The kind of this failure, without its diagnostic text. The match names every group, so a
    /// new group must choose its kind before it compiles.
    pub(crate) fn kind(&self) -> RefusalKind {
        match &self.0 {
            Internal::Config(_) => RefusalKind::Config,
            Internal::Layout(_) => RefusalKind::Layout,
            Internal::Daemon(_) => RefusalKind::Daemon,
            Internal::AgentNotFound(_) => RefusalKind::AgentNotFound,
            Internal::Executable(_) => RefusalKind::Executable,
            Internal::Trampoline(TrampolineError::SetupFailed { stage, .. }) => {
                RefusalKind::ContainmentSetup(stage.public())
            }
            Internal::Trampoline(_) => RefusalKind::Trampoline,
            Internal::Installation(_) => RefusalKind::Installation,
            // The run's failure names the kind, as it names the code.
            Internal::Supervise(SuperviseError::AlsoShutdown { outcome, .. }) => outcome.kind(),
            Internal::Supervise(_) => RefusalKind::Supervise,
            Internal::Shell(_) => RefusalKind::Shell,
            Internal::McpSchema(_) => RefusalKind::McpSchema,
            Internal::Policy(_) => RefusalKind::Policy,
            Internal::PolicyStaging(_) => RefusalKind::PolicyStaging,
            Internal::GrammarBinding(_) => RefusalKind::GrammarBinding,
            Internal::HistoryDisagreesWithRecord { .. } => RefusalKind::HistoryMismatch,
            Internal::HistoryFlush(_) => RefusalKind::HistoryFlush,
            Internal::Credential(_) | Internal::CredentialProjection(_) => RefusalKind::Credential,
            Internal::Proxy(_) => RefusalKind::Proxy,
            Internal::Containment(_) => RefusalKind::Containment,
            Internal::Telemetry(_) => RefusalKind::Telemetry,
            #[cfg(target_os = "linux")]
            Internal::Relay(_) => RefusalKind::Relay,
            Internal::McpDiscovery(_) => RefusalKind::McpDiscovery,
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            Internal::NativeFilesystem(_) => RefusalKind::NativeFilesystem,
        }
    }

    /// The message code of this refusal (docs/user/message-codes.md), or an uncoded error for a
    /// Box defect the reader can only report.
    pub(crate) fn code(&self) -> ::diagnostics::Kind {
        self.0.code()
    }
}

/// An uncoded error: a Box defect, not a cause the reader can fix.
const DEFECT: ::diagnostics::Kind = ::diagnostics::Kind::Uncoded(::diagnostics::Severity::Error);

impl Internal {
    /// One exhaustive match, so a new variant does not compile until it has a code.
    fn code(&self) -> ::diagnostics::Kind {
        use ::diagnostics::Code;
        match self {
            Self::Config(error) => error.code(),
            Self::Layout(error) => match error {
                LayoutError::NoOperatorHome
                | LayoutError::UnsafeDirectory { .. }
                | LayoutError::Remove { .. }
                | LayoutError::ReadDirectory { .. }
                | LayoutError::Create { .. }
                | LayoutError::NotADirectory { .. } => Code::B0105.into(),
            },
            Self::Daemon(error) => match error {
                DaemonError::NotRunning
                | DaemonError::Busy
                | DaemonError::AlreadyRunning { .. }
                | DaemonError::Lock { .. } => Code::B0106.into(),
                DaemonError::LiveParse { .. } => Code::B0105.into(),
                // Its one use refuses a directory grant that reaches the gateway's CA key.
                DaemonError::Refused { .. } => Code::B0102.into(),
                DaemonError::NoProxyPort => Code::B0110.into(),
            },
            // The mark changes the kind, not the message, so the code is the marked error's.
            Self::AgentNotFound(inner) => inner.code(),
            Self::Executable(error) => match error {
                ExecutableError::NotExecutable { .. }
                | ExecutableError::NotOnPath { .. }
                | ExecutableError::RelativeProgram { .. }
                | ExecutableError::NotUtf8 { .. } => Code::B0107.into(),
            },
            Self::Trampoline(error) => match error {
                TrampolineError::Missing { .. }
                | TrampolineError::NotExecutable { .. }
                | TrampolineError::Open { .. }
                | TrampolineError::Invalid { .. }
                | TrampolineError::Materialize { .. } => Code::B0107.into(),
                TrampolineError::UnsupportedPlatform { .. }
                | TrampolineError::StatusPipe { .. }
                | TrampolineError::StatusRead { .. }
                | TrampolineError::SetupIncomplete
                | TrampolineError::SetupFailed { .. } => Code::B0108.into(),
                TrampolineError::StatusProtocol { .. }
                | TrampolineError::Environment { .. }
                | TrampolineError::WorkloadPath { .. } => DEFECT,
            },
            Self::Installation(error) => match error {
                InstallationError::Locate { .. }
                | InstallationError::Invalid { .. }
                | InstallationError::Changed { .. } => Code::B0107.into(),
            },
            Self::Supervise(error) => match error {
                SuperviseError::Spawn { .. } | SuperviseError::Native { .. } => Code::B0108.into(),
                SuperviseError::NativeDuringRun { .. } => Code::B1003.into(),
                SuperviseError::Callback { .. } => Code::B0112.into(),
                SuperviseError::Ingress { .. } => Code::B0704.into(),
                SuperviseError::AlsoShutdown { outcome, .. } => outcome.code(),
                SuperviseError::NoProcessId
                | SuperviseError::Wait { .. }
                | SuperviseError::Signal { .. }
                | SuperviseError::Diagnostics { .. }
                | SuperviseError::Control { .. } => DEFECT,
            },
            Self::Shell(error) => match error {
                ShellError::Missing { .. }
                | ShellError::NotExecutable { .. }
                | ShellError::Materialize { .. } => Code::B0107.into(),
                ShellError::Bind { .. } | ShellError::Serve { .. } => Code::B0111.into(),
            },
            Self::McpSchema(error) => match error {
                McpSchemaError::WorkingDirectory { .. }
                | McpSchemaError::Discover { .. }
                | McpSchemaError::Credential { .. }
                | McpSchemaError::UnsupportedPlacement { .. }
                | McpSchemaError::Policy(_)
                | McpSchemaError::Write { .. } => Code::B0109.into(),
            },
            Self::Policy(_) | Self::PolicyStaging(_) | Self::GrammarBinding(_) => {
                Code::B0103.into()
            }
            Self::HistoryDisagreesWithRecord { .. } => Code::B0105.into(),
            Self::HistoryFlush(_) => Code::P0303.into(),
            Self::Credential(_) | Self::CredentialProjection(_) => Code::B0104.into(),
            Self::Proxy(_) => Code::B0110.into(),
            Self::Containment(_) => Code::B0108.into(),
            Self::Telemetry(_) => Code::T0103.into(),
            #[cfg(target_os = "linux")]
            Self::Relay(error) => match error {
                RelayError::ControlPair { .. }
                | RelayError::Receive { .. }
                | RelayError::NoDescriptor
                | RelayError::Accept { .. } => Code::B0110.into(),
                RelayError::Ingress(_) => Code::B0704.into(),
            },
            Self::McpDiscovery(error) => match error {
                McpDiscoveryError::Thread { .. } | McpDiscoveryError::NoOutcome => {
                    Code::B0109.into()
                }
            },
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            Self::NativeFilesystem(error) => match error {
                NativeFilesystemError::Runtime
                | NativeFilesystemError::Sdk
                | NativeFilesystemError::Allocation
                | NativeFilesystemError::Deadlines
                | NativeFilesystemError::Subscriptions
                | NativeFilesystemError::ExistingChildren
                | NativeFilesystemError::Muting
                | NativeFilesystemError::Client { .. }
                | NativeFilesystemError::Paths { .. }
                | NativeFilesystemError::BootstrapIdentity { .. } => Code::B0108.into(),
                NativeFilesystemError::Shutdown { .. }
                | NativeFilesystemError::Reply
                | NativeFilesystemError::Sequence
                | NativeFilesystemError::Outcome { .. }
                | NativeFilesystemError::Panic
                | NativeFilesystemError::Tracking => Code::B1003.into(),
            },
        }
    }
}

impl ConfigError {
    /// The message code of this refusal; one exhaustive match.
    pub(crate) fn code(&self) -> ::diagnostics::Kind {
        use ::diagnostics::Code;
        match self {
            Self::ExperimentalFeatureUnavailable { .. }
            | Self::Contract { .. }
            | Self::Process { .. }
            | Self::ToolGrammar { .. }
            | Self::ToolSelection { .. }
            | Self::Mcp { .. }
            | Self::Telemetry { .. }
            | Self::Workspace { .. }
            | Self::Read { .. }
            | Self::Parse { .. }
            | Self::BoxName { .. }
            | Self::EmptyWorkload
            | Self::SuppliedIdentity { .. }
            | Self::RemovedKey { .. }
            | Self::NotUtf8 { .. } => Code::B0101.into(),
            Self::AuthorityRead { .. }
            | Self::AuthorityChanged { .. }
            | Self::Filesystem { .. } => Code::B0102.into(),
            Self::PolicyRead { .. } | Self::PolicyInvalid { .. } => Code::B0103.into(),
            Self::Credential { .. }
            | Self::SecretSource { .. }
            | Self::SecretFetch { .. }
            | Self::Locator { .. } => Code::B0104.into(),
            Self::RecordVersion { .. }
            | Self::RecordIdentity { .. }
            | Self::IdentityMismatch { .. } => Code::B0105.into(),
            Self::Disclosure { .. } | Self::RecordWrite { .. } => DEFECT,
        }
    }
}

impl std::fmt::Display for BoxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for BoxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl<E: Into<Internal>> From<E> for BoxError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

/// Anything that stops a box from running, one variant per owning phase or mechanism.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Internal {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Layout(#[from] LayoutError),

    #[error(transparent)]
    Daemon(#[from] DaemonError),

    /// The agent's own program is not installed, which [`BoxError::agent_not_found`] marks.
    #[error(transparent)]
    AgentNotFound(Box<Internal>),

    #[error(transparent)]
    Executable(#[from] ExecutableError),

    #[error(transparent)]
    Trampoline(#[from] TrampolineError),

    #[error(transparent)]
    Installation(#[from] InstallationError),

    #[error(transparent)]
    Supervise(#[from] SuperviseError),

    #[error(transparent)]
    Shell(#[from] ShellError),

    #[error(transparent)]
    McpSchema(#[from] McpSchemaError),

    #[error("policy load failed: {0}")]
    Policy(#[from] policy::PolicyError),

    #[error("policy staging failed: {0}")]
    PolicyStaging(#[from] policy::PolicyStagingError),

    #[error("tool grammar binding refused: {0}")]
    GrammarBinding(#[from] policy::BindingRefusal),

    /// The committed record and the durable history disagree about whether this box has run.
    #[error(
        "policy staging failed: the box record is {}, but the history {history} {found}. \
         Wipe the box directory to start again.",
        if *.committed { "committed" } else { "not committed" }
    )]
    HistoryDisagreesWithRecord {
        committed: bool,
        history: PathBuf,
        found: HistoryFound,
    },

    /// The policy history could not be flushed when the box stopped.
    #[error("{0}")]
    HistoryFlush(policy::PolicyError),

    #[error("credential setup failed: {0}")]
    Credential(#[from] credentials::CredentialError),

    /// A declared credential did not resolve, or resolved to the wrong shape.
    #[error("credential setup failed: {0}")]
    CredentialProjection(String),

    #[error("egress proxy failed: {0}")]
    Proxy(#[from] egress_gateway::ProxyError),

    #[error("containment config failed: {0}")]
    Containment(#[from] containment::ContainmentError),

    #[error("telemetry setup failed: {0}")]
    Telemetry(#[from] telemetry::TelemetryError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Relay(#[from] RelayError),

    #[error(transparent)]
    McpDiscovery(#[from] McpDiscoveryError),

    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    #[error(transparent)]
    NativeFilesystem(#[from] NativeFilesystemError),
}

#[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeFilesystemError {
    #[error("native filesystem policy requires macOS 27 or later")]
    Runtime,
    #[error("native filesystem policy requires a build with the macOS 27 SDK or later")]
    Sdk,
    #[error("native filesystem policy could not allocate its client")]
    Allocation,
    #[error("native filesystem policy could not confirm kernel deadline handling")]
    Deadlines,
    #[error("native filesystem policy could not confirm its event subscriptions")]
    Subscriptions,
    #[error("native filesystem policy requires startup before any child process exists")]
    ExistingChildren,
    #[error("native filesystem policy could not confirm its event mute settings")]
    Muting,
    #[error(
        "native filesystem policy client creation failed (Endpoint Security code {code}); verify the binary's signature and entitlement"
    )]
    Client { code: i32 },
    #[error("native filesystem policy path setup failed: {source}")]
    Paths { source: policy::PathRefusal },
    #[error(
        "native filesystem policy shutdown failed (bridge code {code}); callback memory remains retained"
    )]
    Shutdown { code: i32 },
    #[error("native filesystem policy could not identify its trusted executable: {source}")]
    BootstrapIdentity { source: std::io::Error },
    #[error("native filesystem policy authorization reply failed or missed its deadline")]
    Reply,
    #[error("native filesystem policy dropped or reordered messages")]
    Sequence,
    #[error("native filesystem policy could not record its authorization outcome: {source}")]
    Outcome { source: policy::PolicyError },
    #[error("native filesystem policy callback panicked")]
    Panic,
    #[error("native filesystem policy event queue, bootstrap, or process tracking failed")]
    Tracking,
}

/// Runtime MCP discovery could not preserve its lifecycle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum McpDiscoveryError {
    #[error("cannot start the MCP discovery thread: {source}")]
    Thread { source: std::io::Error },

    #[error("the MCP discovery thread stopped without reporting an outcome")]
    NoOutcome,
}

/// An MCP server's Cedar schema could not be generated or written.
#[derive(Debug, thiserror::Error)]
pub(crate) enum McpSchemaError {
    #[error("cannot read the working directory: {source}")]
    WorkingDirectory { source: std::io::Error },

    #[error("cannot discover MCP server {server:?}: {source}")]
    Discover {
        server: String,
        source: std::io::Error,
    },

    #[error("cannot resolve the credential for MCP server {server:?}: {reason}")]
    Credential { server: String, reason: String },

    #[error(
        "MCP server {server:?} uses credential placement {placement:?}, which schema discovery does not support"
    )]
    UnsupportedPlacement { server: String, placement: String },

    #[error(transparent)]
    Policy(#[from] policy::McpSchemaError),

    #[error("cannot write policy schema artifact {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// The Linux egress relay could not be established.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum RelayError {
    #[error("creating the relay control socket: {source}")]
    ControlPair { source: std::io::Error },

    #[error("receiving the workload's listening socket: {source}")]
    Receive { source: std::io::Error },

    #[error(
        "the containment trampoline sent no listening descriptor, so the workload \
         has no route to the egress gateway"
    )]
    NoDescriptor,

    #[error("accepting on the workload's listening socket: {source}")]
    Accept { source: std::io::Error },

    #[error(transparent)]
    Ingress(#[from] ingress::IngressError),
}

/// The four inputs could not be read, parsed, or validated.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error(
        "experimental feature `{feature}` requires a supported macOS or Linux ARM64 build with `native-filesystem-policy`"
    )]
    ExperimentalFeatureUnavailable { feature: &'static str },

    #[error("invalid Box configuration: {reason}")]
    Contract { reason: String },

    #[error("cannot read {kind} source {path}: {source}")]
    AuthorityRead {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{kind} source {path} changed identity while Box prepared the run")]
    AuthorityChanged { kind: &'static str, path: PathBuf },

    #[error("`{table}` filesystem entry {entry:?} is refused: {reason}")]
    Filesystem {
        table: String,
        entry: String,
        reason: String,
    },

    #[error("invalid `{table}` table: {reason}")]
    Process { table: String, reason: String },

    #[error("tool grammar refused: {source}")]
    ToolGrammar { source: policy::ToolGrammarError },

    /// The hosted Shell was asked to start a program no `[tool.<name>]` names.
    #[error("no tool runs {program}: {reason}")]
    ToolSelection { program: String, reason: String },

    #[error("invalid MCP server {name:?}: {reason}")]
    Mcp { name: String, reason: String },

    /// Refused before anything is written, and before the box starts. A telemetry lane that
    /// silently drops records is worse than one an operator knows is absent.
    #[error("invalid `[telemetry.{name}]` target: {reason}")]
    Telemetry { name: String, reason: String },

    #[error("cannot settle the project this box belongs to: {reason}")]
    Workspace { reason: String },

    #[error("cannot write the startup disclosure to stderr: {source}")]
    Disclosure { source: std::io::Error },

    #[error("cannot read policy file {path}: {source}")]
    PolicyRead {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Refused before anything is written. Otherwise the refusal arrives at the next `run`, from
    /// inside the daemon, as "the box's daemon exited during startup".
    #[error("policy file {path} will not load: {source}")]
    PolicyInvalid {
        path: PathBuf,
        source: policy::PolicyError,
    },

    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("invalid credential entry for host {host:?}: {reason}")]
    Credential { host: String, reason: String },

    #[error("invalid `[secret-source.{scheme}]` table: {reason}")]
    SecretSource { scheme: String, reason: String },

    /// A declared secret source read no secret for one entry; the reason went to stderr alone.
    #[error(
        "`{entry}` names a secret that the secret source `{scheme}` ({program}) did not return, \
         so the box does not start"
    )]
    SecretFetch {
        entry: String,
        scheme: String,
        program: String,
    },

    #[error("credential locator {locator:?} is invalid: {source}")]
    Locator {
        locator: String,
        source: credentials::CredentialError,
    },

    #[error(
        "box name {name:?} is invalid: {reason}; use one component of letters, digits, '.', '_', or '-'"
    )]
    BoxName { name: String, reason: String },

    #[error(
        "no workload to run: the configuration has no `[agent]` table, and a trailing argv appends \
         to `[agent] command` rather than replacing it"
    )]
    EmptyWorkload,

    /// The remedy must name a verb that exists; `no_error_message_names_a_removed_verb` sweeps it.
    #[error(
        "box record is version {found}, but this build understands {expected}; \
         select an empty `box_dir`, or remove the stale box state before the next run"
    )]
    RecordVersion { found: u32, expected: u32 },

    #[error(
        "box record identity {found:?} is invalid; select an empty `box_dir`, or remove the stale box state before the next run"
    )]
    RecordIdentity { found: String },

    #[error(
        "box ID {found:?} is invalid; a box ID is a prefix of 1 to {max} letters, digits, `.`, `_`, \
         or `-` that does not start with `.` or `-`, then `-` and 16 lowercase hexadecimal digits",
        max = crate::record::config::MAXIMUM_BOX_IDENTITY_PREFIX
    )]
    SuppliedIdentity { found: String },

    #[error(
        "box ID {supplied:?} does not match this box, whose ID is {stored:?}; pass {stored:?}, or \
         select an empty `box_dir` for a new box"
    )]
    IdentityMismatch { stored: String, supplied: String },

    #[error(
        "{path} carries `{key}`, which this build does not read; write {replacement} instead. Edit \
         the configuration, or select an empty `box_dir` to rebuild a stored record"
    )]
    RemovedKey {
        path: PathBuf,
        key: &'static str,
        replacement: &'static str,
    },

    #[error("cannot serialize box record: {source}")]
    RecordWrite { source: toml::ser::Error },

    #[error("{description} {value} is not valid UTF-8")]
    NotUtf8 {
        description: &'static str,
        value: String,
    },
}

/// The box's own filesystem could not be created.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LayoutError {
    #[error("HOME is not set")]
    NoOperatorHome,

    #[error("unsafe box directory {path}: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: String },

    #[error("cannot remove {path}: {source}")]
    Remove {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot read {path}: {source}")]
    ReadDirectory {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot create box directory {path}: {source}")]
    Create {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("box path is not a directory: {path}")]
    NotADirectory { path: PathBuf },
}

/// What a run found where this box's durable history belongs.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HistoryFound {
    Absent,
    Empty,
    Present { bytes: u64 },
}

impl std::fmt::Display for HistoryFound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str("is absent"),
            Self::Empty => formatter.write_str("is empty"),
            Self::Present { bytes } => write!(formatter, "holds {bytes} bytes"),
        }
    }
}

/// A trusted Box operation could not start, run, or stop.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DaemonError {
    #[error("no box is running in this process")]
    NotRunning,

    #[error("cannot parse the box's live record: {source}")]
    LiveParse { source: serde_json::Error },

    #[error("cannot take the box lock {path}: {source}")]
    Lock {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("another strands-box operation is in progress for this box; retry shortly")]
    Busy,

    /// A second `run` of a box one already owns. Apart from [`Busy`](Self::Busy)
    /// because a busy operation clears by itself and a running box does not.
    #[error(
        "box {name} is already running, and one run owns a box at a time; \
         wait for that run to exit, or start a configuration with a different `box_dir`"
    )]
    AlreadyRunning { name: String },

    /// A trusted Box component understood the request and refused it.
    #[error("the trusted Box operation refused: {reason}")]
    Refused { reason: String },

    #[error("the egress proxy did not bind a port")]
    NoProxyPort,
}

/// The workload executable could not be resolved to one exec literal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutableError {
    #[error("executable is not an executable regular file: {path}")]
    NotExecutable { path: PathBuf },

    #[error("cannot resolve bare executable {program} on the declared PATH")]
    NotOnPath { program: PathBuf },

    #[error(
        "executable {program} is a relative path with a separator; write an absolute path, or a \
         bare name that `env.PATH` resolves"
    )]
    RelativeProgram { program: PathBuf },

    #[error("{description} {value} is not valid UTF-8")]
    NotUtf8 {
        description: &'static str,
        value: String,
    },
}

/// The installed trusted executables could not retain their identities.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallationError {
    #[error("cannot locate the trusted Box executable: {source}")]
    Locate { source: std::io::Error },

    #[error("trusted Box executable {path} {reason}")]
    Invalid { path: PathBuf, reason: String },

    #[error(
        "trusted Box executable {path} changed after this run loaded it. Stop Box before updating its installation"
    )]
    Changed { path: PathBuf },
}

/// The containment trampoline could not be prepared or launched.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TrampolineError {
    #[error(
        "strands-box-contain-trampoline must be installed next to strands-box ({path}): {source}"
    )]
    Missing {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("strands-box-contain-trampoline is not an executable regular file: {path}")]
    NotExecutable { path: PathBuf },

    #[error("cannot securely open containment executable {path}: {reason}")]
    Open { path: PathBuf, reason: String },

    /// The opened bytes are not the trampoline the box expects.
    #[error("invalid containment executable {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },

    #[cfg_attr(
        all(not(target_os = "macos"), not(test)),
        expect(
            dead_code,
            reason = "constructed only on macOS, which copies the image"
        )
    )]
    #[error("cannot materialize containment executable {path}: {reason}")]
    Materialize { path: PathBuf, reason: String },

    /// The platform has no way to bind an exec to an opened identity.
    #[cfg_attr(
        any(target_os = "macos", target_os = "linux"),
        expect(dead_code, reason = "constructed only on other targets")
    )]
    #[error("identity-bound containment execution is unsupported on {os}")]
    UnsupportedPlatform { os: &'static str },

    #[error("create containment setup status pipe: {source}")]
    StatusPipe { source: std::io::Error },

    #[error("read containment setup status: {source}")]
    StatusRead { source: std::io::Error },

    #[error("containment setup channel closed before completion")]
    SetupIncomplete,

    #[error("invalid containment setup status protocol: {reason}")]
    StatusProtocol { reason: String },

    /// Containment failed before the workload ever ran, at a named stage, with the trampoline's own
    /// message when the box captured it.
    #[error("containment setup failed during {stage}{}", .detail.as_deref().map_or(String::new(), |detail| format!(": {detail}")))]
    SetupFailed {
        stage: SetupStage,
        detail: Option<String>,
    },

    #[error("serialize workload environment: {source}")]
    Environment { source: serde_json::Error },

    #[error("construct workload PATH: {source}")]
    WorkloadPath { source: std::env::JoinPathsError },
}

/// The Strands Shell could not be prepared, bound, or served.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ShellError {
    #[error("strands-box-sock-alias must be installed next to strands-box ({path}): {source}")]
    Missing {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("strands-box-sock-alias is not an executable regular file: {path}")]
    NotExecutable { path: PathBuf },

    #[error("cannot materialize the Shell image {path}: {reason}")]
    Materialize { path: PathBuf, reason: String },

    /// Nothing was ever published, so no client can have connected. Apart from [`Self::Serve`].
    #[error("bind the broker socket: {source}")]
    Bind { source: std::io::Error },

    /// Terminal for the daemon: with no broker, nothing stands behind any alias.
    #[error("serve the broker: {source}")]
    Serve { source: std::io::Error },
}

/// The child could not be spawned, supervised, or reaped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SuperviseError {
    #[error("workload diagnostics failed: {source}")]
    Diagnostics { source: std::io::Error },

    #[error("spawn contained workload: {source}")]
    Spawn { source: std::io::Error },

    #[error("workload has no process id")]
    NoProcessId,

    #[error("workload wait failed: {source}")]
    Wait { source: std::io::Error },

    #[error("signal handling failed: {source}")]
    Signal { source: std::io::Error },

    #[error("workload process control failed: {reason}")]
    Control { reason: String },

    /// A library caller's `on_ready` callback refused the run.
    #[error("workload process control failed: on_ready callback failed: {source}")]
    Callback { source: std::io::Error },

    /// An `[[agent.ingress]]` listener could not be bound or relayed.
    #[error("workload process control failed: {reason}")]
    Ingress { reason: String },

    /// Native filesystem policy could not be set up or kept running.
    #[cfg_attr(not(feature = "native-filesystem-policy"), allow(dead_code))]
    #[error("workload process control failed: {reason}")]
    Native { reason: String },

    /// Native filesystem policy failed after the workload started, or did not stop cleanly.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "native-filesystem-policy")),
        allow(dead_code)
    )]
    #[error("workload process control failed: {reason}")]
    NativeDuringRun { reason: String },

    /// The run failed, and its shutdown failed too; the run's failure names the code.
    #[error("workload process control failed: {outcome}; shutdown also failed: {shutdown}")]
    AlsoShutdown {
        outcome: Box<BoxError>,
        shutdown: Box<BoxError>,
    },
}

/// How far containment got before it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetupStage {
    ConfigRead,
    ConfigValidation,
    Apply,
    TargetEnvironment,
    Exec,
}

impl SetupStage {
    /// The stage as stable text. `&'static str` rather than the enum, so the façade leaks no
    /// variant set and a new stage breaks no caller.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::ConfigRead => "config read",
            Self::ConfigValidation => "config validation",
            Self::Apply => "containment apply",
            Self::TargetEnvironment => "target environment",
            Self::Exec => "target exec",
        }
    }

    /// The stage as the public kind a library caller matches on.
    pub(crate) fn public(self) -> crate::run::events::ContainmentStage {
        use crate::run::events::ContainmentStage;
        match self {
            Self::ConfigRead => ContainmentStage::ConfigRead,
            Self::ConfigValidation => ContainmentStage::ConfigValidation,
            Self::Apply => ContainmentStage::Apply,
            Self::TargetEnvironment => ContainmentStage::TargetEnvironment,
            Self::Exec => ContainmentStage::Exec,
        }
    }

    /// Decode the byte the trampoline wrote.
    pub(crate) fn decode(byte: u8) -> Result<Self, TrampolineError> {
        match byte {
            1 => Ok(Self::ConfigRead),
            2 => Ok(Self::ConfigValidation),
            3 => Ok(Self::Apply),
            4 => Ok(Self::TargetEnvironment),
            5 => Ok(Self::Exec),
            other => Err(TrampolineError::StatusProtocol {
                reason: format!("unknown setup stage byte {other}"),
            }),
        }
    }
}

impl std::fmt::Display for SetupStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_group_names_its_kind_and_a_marked_agent_is_agent_not_found() {
        let missing = || -> BoxError {
            ExecutableError::NotOnPath {
                program: "private".into(),
            }
            .into()
        };
        let cases: [(BoxError, RefusalKind); 7] = [
            (
                SuperviseError::AlsoShutdown {
                    outcome: Box::new(DaemonError::NoProxyPort.into()),
                    shutdown: Box::new(
                        Internal::HistoryFlush(policy::PolicyError::Evaluation("full".into()))
                            .into(),
                    ),
                }
                .into(),
                RefusalKind::Daemon,
            ),
            (ConfigError::EmptyWorkload.into(), RefusalKind::Config),
            (DaemonError::Busy.into(), RefusalKind::Daemon),
            (missing(), RefusalKind::Executable),
            (missing().agent_not_found(), RefusalKind::AgentNotFound),
            (
                ExecutableError::NotExecutable {
                    path: "private".into(),
                }
                .into(),
                RefusalKind::Executable,
            ),
            (
                TrampolineError::SetupFailed {
                    stage: SetupStage::Apply,
                    detail: Some("private".into()),
                }
                .into(),
                RefusalKind::ContainmentSetup(crate::run::events::ContainmentStage::Apply),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.kind(), expected, "{error}");
        }
        assert_eq!(
            missing().agent_not_found().to_string(),
            missing().to_string(),
            "the mark leaves the message as it was"
        );
    }

    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    #[test]
    fn native_outcome_failure_preserves_the_policy_error() {
        use std::error::Error;
        let error = NativeFilesystemError::Outcome {
            source: policy::PolicyError::Evaluation("record failed".into()),
        };
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<policy::PolicyError>()
                .is_some()
        );
    }

    #[test]
    fn setup_stage_bytes_round_trip_and_reject_the_unknown() {
        for (byte, stage) in [
            (1, SetupStage::ConfigRead),
            (2, SetupStage::ConfigValidation),
            (3, SetupStage::Apply),
            (4, SetupStage::TargetEnvironment),
            (5, SetupStage::Exec),
        ] {
            assert_eq!(SetupStage::decode(byte).unwrap(), stage);
        }
        for byte in [0, 6, 255] {
            assert!(
                SetupStage::decode(byte).is_err(),
                "byte {byte} must not decode to a stage"
            );
        }
    }

    /// The strings the end-to-end suites match on.
    #[test]
    fn refusals_name_their_cause() {
        let cases: [(BoxError, &str); 4] = [
            (
                LayoutError::NotADirectory {
                    path: PathBuf::from("/box/home"),
                }
                .into(),
                "not a directory",
            ),
            (LayoutError::NoOperatorHome.into(), "HOME is not set"),
            (
                ExecutableError::NotExecutable {
                    path: PathBuf::from("/box/home/data"),
                }
                .into(),
                "not an executable regular file",
            ),
            (
                TrampolineError::NotExecutable {
                    path: PathBuf::from("/bin/strands-box-contain-trampoline"),
                }
                .into(),
                "not an executable regular file",
            ),
        ];
        for (error, expected) in cases {
            assert!(
                error.to_string().contains(expected),
                "{error} must mention {expected:?}"
            );
        }
    }

    /// Each refusal names the code of its cause, and a Box defect names none.
    #[test]
    fn refusals_name_their_code() {
        use ::diagnostics::{Code, Kind, Severity};
        let cases: [(BoxError, Kind); 23] = [
            (
                SuperviseError::NativeDuringRun {
                    reason: "native request deadline exceeded".into(),
                }
                .into(),
                Code::B1003.into(),
            ),
            (
                SuperviseError::Diagnostics {
                    source: std::io::Error::other("replay"),
                }
                .into(),
                Kind::Uncoded(Severity::Error),
            ),
            (ConfigError::EmptyWorkload.into(), Code::B0101.into()),
            (
                SuperviseError::Callback {
                    source: std::io::Error::other("refused"),
                }
                .into(),
                Code::B0112.into(),
            ),
            (
                SuperviseError::Ingress {
                    reason: "binding the ingress 127.0.0.1:8080: in use".into(),
                }
                .into(),
                Code::B0704.into(),
            ),
            (
                SuperviseError::AlsoShutdown {
                    outcome: Box::new(DaemonError::NoProxyPort.into()),
                    shutdown: Box::new(
                        Internal::HistoryFlush(policy::PolicyError::Evaluation("full".into()))
                            .into(),
                    ),
                }
                .into(),
                Code::B0110.into(),
            ),
            (
                Internal::HistoryFlush(policy::PolicyError::Evaluation("full".into())).into(),
                Code::P0303.into(),
            ),
            (
                SuperviseError::Wait {
                    source: std::io::Error::other("gone"),
                }
                .into(),
                Kind::Uncoded(Severity::Error),
            ),
            (
                ConfigError::PolicyRead {
                    path: "policy.dw".into(),
                    source: std::io::Error::other("gone"),
                }
                .into(),
                Code::B0103.into(),
            ),
            (
                Internal::Policy(policy::PolicyError::UnknownAction("x".into())).into(),
                Code::B0103.into(),
            ),
            (
                ConfigError::Credential {
                    host: "api.example.com".into(),
                    reason: "no locator".into(),
                }
                .into(),
                Code::B0104.into(),
            ),
            (
                Internal::CredentialProjection("unset".into()).into(),
                Code::B0104.into(),
            ),
            (
                Internal::HistoryDisagreesWithRecord {
                    committed: true,
                    history: "history".into(),
                    found: HistoryFound::Absent,
                }
                .into(),
                Code::B0105.into(),
            ),
            (
                ExecutableError::NotOnPath {
                    program: "claude".into(),
                }
                .into(),
                Code::B0107.into(),
            ),
            (McpDiscoveryError::NoOutcome.into(), Code::B0109.into()),
            (DaemonError::NoProxyPort.into(), Code::B0110.into()),
            (
                Internal::Telemetry(telemetry::TelemetryError::Config {
                    reason: "no target".into(),
                })
                .into(),
                Code::T0103.into(),
            ),
            (
                ConfigError::Filesystem {
                    table: "[agent]".into(),
                    entry: "~/.ssh".into(),
                    reason: "a credential store".into(),
                }
                .into(),
                Code::B0102.into(),
            ),
            (
                ConfigError::RecordVersion {
                    found: 9,
                    expected: 1,
                }
                .into(),
                Code::B0105.into(),
            ),
            (
                DaemonError::AlreadyRunning { name: "b".into() }.into(),
                Code::B0106.into(),
            ),
            (
                TrampolineError::SetupFailed {
                    stage: SetupStage::Apply,
                    detail: None,
                }
                .into(),
                Code::B0108.into(),
            ),
            (
                ShellError::Bind {
                    source: std::io::Error::other("in use"),
                }
                .into(),
                Code::B0111.into(),
            ),
            (
                TrampolineError::StatusProtocol {
                    reason: "byte 9".into(),
                }
                .into(),
                Kind::Uncoded(Severity::Error),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.code(), expected, "{error}");
        }
        #[cfg(target_os = "linux")]
        {
            let relay: BoxError = RelayError::Ingress(ingress::IngressError::NotReady).into();
            assert_eq!(relay.code(), Code::B0704.into(), "{relay}");
        }
    }

    #[test]
    fn a_setup_failure_names_its_stage() {
        let error: BoxError = TrampolineError::SetupFailed {
            stage: SetupStage::Apply,
            detail: None,
        }
        .into();

        assert!(error.to_string().contains("containment apply"), "{error}");
    }
}
