//! Why a box refused to run, or stopped running.

use std::path::PathBuf;

/// Why a box refused to run, or stopped running.
#[derive(Debug)]
pub(crate) struct BoxError(Internal);

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

    #[error(transparent)]
    Executable(#[from] ExecutableError),

    #[error(transparent)]
    Trampoline(#[from] TrampolineError),

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
}

/// The four inputs could not be read, parsed, or validated.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
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
