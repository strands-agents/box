//! `box.toml`'s `[telemetry.<label>]` declarations: where a box's records go.
//!
//! A declared target REPLACES the box's default destination, so this module owns both halves — what
//! an operator may write, and the collector request a run builds from what was stored.
//!
//! An absent `include` means every signal, so a target receives the harness's own spans, logs and
//! metrics without naming one. The five words below are how an operator NARROWS that.
//!
//! The `telemetry` crate's own items are imported by name rather than qualified, because this module
//! shares its spelling and `telemetry::Signal` would read as `self::Signal`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use telemetry::{Payload, Signal, Target, TargetKind, TargetSecret, TelemetryConfig};

use crate::error::{BoxError, ConfigError};
// The `[[egress]]` vocabulary owns these: a telemetry target's secret is a credential,
// and it follows the same header convention.
use super::{BEARER_PREFIX, DEFAULT_HEADER, ENV_SCHEME};

/// Refuse a file destination the workload could truncate.
///
/// The test is `box_directory` itself, because a caller selects that path and no directory above it
/// belongs to Box. Both spellings of each side are compared, because a symlink laundering the
/// authored path resolves only through its deepest existing ancestor.
fn refuse_a_workload_reachable_destination(
    expanded: &str,
    box_directory: &Path,
) -> Result<(), String> {
    let path = Path::new(expanded);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{expanded:?} carries a `..` component; write the path it names, so the destination \
             this box opens is the one you read"
        ));
    }
    let roots = [
        box_directory.to_path_buf(),
        crate::record::layout::canonical(box_directory),
    ];
    let spellings = [
        path.to_path_buf(),
        crate::record::layout::resolved_to_its_deepest_existing_ancestor(path),
    ];
    for root in &roots {
        let private = root.join(crate::record::layout::PRIVATE_DIRECTORY);
        for spelling in &spellings {
            if crate::record::layout::lies_within(spelling, root)
                && !crate::record::layout::lies_within(spelling, &private)
            {
                return Err(format!(
                    "{expanded:?} is inside the box directory {} but outside its private tree, \
                     where a process could truncate it; name a destination under `private/`, or \
                     outside the box, or declare no target and take the default",
                    root.display()
                ));
            }
        }
    }
    Ok(())
}

/// A destination with a leading `~/` replaced by the operator's home.
fn expanded_home_path(destination: &str, operator_home: Option<&Path>) -> Option<String> {
    let Some(relative) = destination
        .strip_prefix("~/")
        .or_else(|| destination.strip_prefix("~").filter(|rest| rest.is_empty()))
    else {
        return Some(destination.to_string());
    };
    let home = operator_home?;
    Some(home.join(relative).to_string_lossy().into_owned())
}

/// The spelling an operator may use beside the credential vocabulary's own.
const TELEMETRY_ALIAS_SCHEME: &str = "secret://";

/// The schemes a telemetry credential may name, beside `env://` and its alias.
const VAULT_SCHEMES: [&str; 5] = [
    "file://",
    "op://",
    "aws://",
    "credsd://",
    "aws-secretsmanager://",
];

/// The schemes whose credential signs the request instead of sitting in one header.
const SIGNING_SCHEMES: [&str; 2] = ["aws://", "credsd://"];

/// The `secret.placement` that sends the credential as HTTP Basic auth.
const BASIC_AUTH_PLACEMENT: &str = "basic_auth";

/// The `secret.placement` that sends the credential in one header.
const HEADER_PLACEMENT: &str = "header";

/// The user half a Basic-auth phantom is presented under. The vault reads only the password half.
const PHANTOM_USER: &str = "strands-box";

/// The header prefix a signed request owns.
const SIGNING_HEADER_PREFIX: &str = "x-amz-";

/// One word an operator writes in `include`, and the signals it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignalGroup {
    /// Every effective denial.
    Deny,
    /// Every effective permit.
    Permit,
    /// The agent's own spans, and this box's control-plane operations.
    Trace,
    /// The agent's own log records.
    Logs,
    /// The agent's own metrics.
    Metrics,
}

impl SignalGroup {
    /// The signals this word names.
    fn signals(self) -> Vec<Signal> {
        match self {
            Self::Deny => vec![Signal::PolicyDenied],
            Self::Permit => vec![Signal::PolicyPermitted],
            Self::Trace => vec![Signal::AgentTrace, Signal::ControlPlane],
            Self::Logs => vec![Signal::AgentLogs],
            Self::Metrics => vec![Signal::AgentMetrics],
        }
    }

    /// Every word an operator may write, for a refusal that lists them.
    fn every() -> [Self; 5] {
        [
            Self::Deny,
            Self::Permit,
            Self::Trace,
            Self::Logs,
            Self::Metrics,
        ]
    }

    /// The `box.toml` spelling.
    fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Permit => "permit",
            Self::Trace => "trace",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }
}

/// The signals an `include` list names, in a deterministic order.
///
/// No two words share a signal, so `checked` refusing a repeated word is what keeps this free of
/// duplicates.
fn signals_for(include: &[SignalGroup]) -> Vec<Signal> {
    let mut signals: Vec<Signal> = include.iter().flat_map(|group| group.signals()).collect();
    signals.sort_unstable();
    signals
}

/// What a target is: one of the two exporters, or a vendor whose settings the box knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TelemetryKind {
    /// One OTLP-JSON request per line, appended to a file.
    File,
    /// OTLP over HTTP, with every setting written out.
    Otlp,
    /// Langfuse's OTLP endpoint.
    Langfuse,
    /// LangSmith's OTLP endpoint.
    Langsmith,
    /// CloudWatch Logs' OTLP endpoint.
    CloudwatchLogs,
    /// X-Ray's OTLP endpoint, which writes spans to Transaction Search.
    CloudwatchTraces,
}

impl TelemetryKind {
    /// The exporter this kind runs on.
    fn exporter(self) -> TargetKind {
        match self {
            Self::File => TargetKind::File,
            _ => TargetKind::Otlp,
        }
    }

    /// The spelling an operator writes.
    fn spelling(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Otlp => "otlp",
            Self::Langfuse => "langfuse",
            Self::Langsmith => "langsmith",
            Self::CloudwatchLogs => "cloudwatch_logs",
            Self::CloudwatchTraces => "cloudwatch_traces",
        }
    }
}

/// One `[telemetry.<label>]`: where records go, and how much of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetryEntry {
    /// Which exporter or vendor this target selects. Serde refuses a spelling that is not one.
    pub(crate) kind: TelemetryKind,

    /// Where this target sends records. A vendor kind has a default, and CloudWatch takes `region`.
    #[serde(default)]
    pub(crate) destination: String,

    /// Which records reach this target. Serde refuses a spelling that is not one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) include: Option<Vec<SignalGroup>>,

    /// The secret the box attaches on the way out, and the header carrying it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<TelemetrySecret>,

    /// Which OTLP payloads the destination takes. Absent means every one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) accepts: Option<Vec<Payload>>,

    /// Fixed, non-secret headers sent on every request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) headers: Option<BTreeMap<String, String>>,

    /// The CloudWatch Logs group a target writes to, sent as `x-aws-log-group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) log_group: Option<String>,

    /// The CloudWatch Logs stream a target writes to, sent as `x-aws-log-stream`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) log_stream: Option<String>,

    /// The LangSmith project a `langsmith` target writes to, sent as `Langsmith-Project`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project: Option<String>,

    /// The AWS region a CloudWatch target sends to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) region: Option<String>,
}

/// Which secret a telemetry target attaches, and under which header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetrySecret {
    /// The secret to attach, as a URI: `env://NAME` or `secret://NAME`.
    #[serde(rename = "ref")]
    pub(crate) reference: String,

    /// The header to attach it under. Defaults to `Authorization` with a `Bearer ` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<String>,

    /// The literal text before the secret. Defaults to `Bearer ` on `Authorization` and to empty
    /// elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prefix: Option<String>,

    /// Where the secret lands: `header` or `basic_auth`. Defaults to `header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) placement: Option<String>,
}

/// How a telemetry credential reaches the request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialShape {
    /// `name: <prefix><secret>`.
    Header { name: String, prefix: String },
    /// `Authorization: Basic <base64 of the secret>`, the secret being `user:password`.
    BasicAuth,
    /// SigV4, signed by the vault for the destination's service and region.
    Signed,
}

impl CredentialShape {
    /// The shape a secret declares, refusing a field its scheme or placement cannot use.
    fn of(secret: &TelemetrySecret) -> Result<Self, String> {
        let reference = secret.reference.trim();
        if SIGNING_SCHEMES
            .iter()
            .any(|scheme| reference.starts_with(scheme))
        {
            if secret.header.is_some() || secret.prefix.is_some() || secret.placement.is_some() {
                return Err(
                    "an `aws://` or `credsd://` credential signs the whole request, so it takes \
                     no `header`, `prefix` or `placement`"
                        .to_string(),
                );
            }
            return Ok(Self::Signed);
        }
        match secret.placement.as_deref() {
            None | Some(HEADER_PLACEMENT) => {
                let name = secret
                    .header
                    .as_deref()
                    .unwrap_or(DEFAULT_HEADER)
                    .to_string();
                let prefix = secret.prefix.clone().unwrap_or_else(|| {
                    if name.eq_ignore_ascii_case(DEFAULT_HEADER) {
                        BEARER_PREFIX.to_string()
                    } else {
                        String::new()
                    }
                });
                Ok(Self::Header { name, prefix })
            }
            Some(BASIC_AUTH_PLACEMENT) => {
                if secret.header.is_some() || secret.prefix.is_some() {
                    return Err(
                        "a `basic_auth` credential is sent as `Authorization: Basic …`, so it \
                         takes no `header` or `prefix`"
                            .to_string(),
                    );
                }
                Ok(Self::BasicAuth)
            }
            Some(other) => Err(format!(
                "`secret.placement = {other:?}` is not a placement a telemetry target takes; write \
                 `{HEADER_PLACEMENT}` or `{BASIC_AUTH_PLACEMENT}`"
            )),
        }
    }

    /// The header the credential occupies, or `None` when it signs several.
    fn header(&self) -> Option<&str> {
        match self {
            Self::Header { name, .. } => Some(name),
            Self::BasicAuth => Some(DEFAULT_HEADER),
            Self::Signed => None,
        }
    }

    /// The vault's placement for this shape, or `None` for a signed credential.
    fn inject_mode(&self) -> Result<Option<credentials::InjectMode>, String> {
        match self {
            Self::Header { name, prefix } => credentials::InjectMode::header(
                format!("{prefix}{{}}"),
                (!name.eq_ignore_ascii_case(DEFAULT_HEADER)).then(|| name.clone()),
            )
            .map(Some)
            .map_err(|error| error.to_string()),
            Self::BasicAuth => Ok(Some(credentials::InjectMode::basic_auth())),
            Self::Signed => Ok(None),
        }
    }

    /// The header that presents `phantom` where the vault looks for it.
    fn presented(&self, phantom: &str) -> Option<(String, String)> {
        match self {
            Self::Header { name, prefix } => Some((name.clone(), format!("{prefix}{phantom}"))),
            Self::BasicAuth => {
                let pair = format!("{PHANTOM_USER}:{phantom}");
                Some((
                    DEFAULT_HEADER.to_string(),
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(pair)
                    ),
                ))
            }
            Self::Signed => None,
        }
    }
}

/// A telemetry secret reference, as the credential vocabulary spells it.
fn telemetry_secret_uri(reference: &str) -> Result<String, String> {
    let reference = reference.trim();
    if let Some(name) = reference.strip_prefix(TELEMETRY_ALIAS_SCHEME) {
        if name.is_empty() {
            return Err(format!(
                "the {TELEMETRY_ALIAS_SCHEME} reference names no variable"
            ));
        }
        return Ok(format!("{ENV_SCHEME}{name}"));
    }
    if reference.starts_with(ENV_SCHEME)
        || VAULT_SCHEMES
            .iter()
            .any(|scheme| reference.starts_with(scheme))
    {
        return Ok(reference.to_string());
    }
    Err(format!(
        "`secret.ref` names no scheme this box reads; write `{ENV_SCHEME}NAME`, \
         `{TELEMETRY_ALIAS_SCHEME}NAME`, `file:///path`, `op://…`, `aws://profile` or \
         `credsd://environment` or `aws-secretsmanager://secret#field`, never the value itself. The value is deliberately not echoed \
         here, in case it is one"
    ))
}

/// The refusal a declared target carries, naming the target the operator keyed it under.
fn refuse(name: &str, reason: String) -> ConfigError {
    ConfigError::Telemetry {
        name: name.to_string(),
        reason,
    }
}

/// One declared target as the collector's own value.
fn target_for(
    entry: &TelemetryEntry,
    home: Option<&Path>,
    box_directory: &Path,
    secret: Option<TargetSecret>,
) -> Result<Target, String> {
    // `~/…` is expanded here and nowhere else, so one answer decides which file a relative-looking
    // destination names. Absolute after this, which is what the collector requires of a file target.
    let destination = match entry.kind {
        TelemetryKind::File => {
            let expanded = expanded_home_path(entry.destination.trim(), home).ok_or_else(|| {
                "a `~/`-relative destination needs the operator's home, which this box cannot \
                 resolve"
                    .to_string()
            })?;
            refuse_a_workload_reachable_destination(&expanded, box_directory)?;
            expanded
        }
        _ => entry.destination.trim().to_string(),
    };

    let mut target = Target::new(entry.kind.exporter(), destination);
    if let Some(include) = &entry.include {
        target = target.receiving(signals_for(include));
    }
    if let Some(accepts) = &entry.accepts {
        target = target.accepting(accepts.clone());
    }
    for (name, value) in entry.headers.iter().flatten() {
        target = target.with_header(name, value);
    }
    if let Some(secret) = secret {
        target = target.with_secret(secret);
    }
    Ok(target)
}

/// The header CloudWatch Logs reads the log group from.
const LOG_GROUP_HEADER: &str = "x-aws-log-group";

/// The header CloudWatch Logs reads the log stream from.
const LOG_STREAM_HEADER: &str = "x-aws-log-stream";

/// The longest log group or log stream name CloudWatch Logs accepts.
const MAXIMUM_LOG_NAME: usize = 512;

/// The default Langfuse endpoint, its OTLP path, and the ingestion version it is sent.
const LANGFUSE: (&str, &str) = ("https://cloud.langfuse.com", "/api/public/otel");

/// The header Langfuse reads the ingestion version from, and the version the box sends.
const LANGFUSE_INGESTION_VERSION: (&str, &str) = ("x-langfuse-ingestion-version", "4");

/// The default LangSmith endpoint and its OTLP path.
const LANGSMITH: (&str, &str) = ("https://api.smith.langchain.com", "/otel");

/// The header LangSmith reads the project from.
const LANGSMITH_PROJECT_HEADER: &str = "Langsmith-Project";

/// The header LangSmith reads the API key from.
const LANGSMITH_KEY_HEADER: &str = "x-api-key";

/// The longest AWS region name the box accepts.
const MAXIMUM_REGION: usize = 32;

/// A vendor target as the plain target it stands for: the endpoint, the payloads, the headers and
/// the credential placement the vendor needs. A `file` or `otlp` target comes back unchanged.
fn expanded(entry: &TelemetryEntry) -> Result<TelemetryEntry, String> {
    let kind = entry.kind;
    let not_here = |key: &str, set: bool| -> Result<(), String> {
        if set {
            Err(format!(
                "`{key}` does not apply to a `{}` target",
                kind.spelling()
            ))
        } else {
            Ok(())
        }
    };
    let set_by_box = |key: &str, set: bool| -> Result<(), String> {
        if set {
            Err(format!(
                "a `{}` target sets `{key}` itself, so leave it out",
                kind.spelling()
            ))
        } else {
            Ok(())
        }
    };
    match kind {
        TelemetryKind::File | TelemetryKind::Otlp => {
            for (key, set) in [
                ("project", entry.project.is_some()),
                ("region", entry.region.is_some()),
                ("log_group", entry.log_group.is_some()),
                ("log_stream", entry.log_stream.is_some()),
            ] {
                not_here(key, set)?;
            }
            if entry.destination.trim().is_empty() {
                return Err("the target names no destination".to_string());
            }
            Ok(entry.clone())
        }
        TelemetryKind::Langfuse | TelemetryKind::Langsmith => {
            set_by_box("headers", entry.headers.is_some())?;
            set_by_box("accepts", entry.accepts.is_some())?;
            not_here("region", entry.region.is_some())?;
            not_here("log_group", entry.log_group.is_some())?;
            not_here("log_stream", entry.log_stream.is_some())?;
            let langfuse = kind == TelemetryKind::Langfuse;
            if langfuse {
                not_here("project", entry.project.is_some())?;
            }
            let reference = vendor_secret(entry)?;
            let (default_base, path) = if langfuse { LANGFUSE } else { LANGSMITH };
            let base = match entry.destination.trim() {
                "" => default_base,
                written => written,
            }
            .trim_end_matches('/');
            let destination = if base.ends_with(path) {
                base.to_string()
            } else {
                format!("{base}{path}")
            };
            let mut headers = BTreeMap::new();
            if langfuse {
                let (name, version) = LANGFUSE_INGESTION_VERSION;
                headers.insert(name.to_string(), version.to_string());
            } else if let Some(project) = &entry.project {
                let project = project.trim();
                if project.is_empty() || project.chars().any(char::is_control) {
                    return Err(format!(
                        "`project` {project:?} is not a LangSmith project name: it is empty or \
                         holds a control character"
                    ));
                }
                headers.insert(LANGSMITH_PROJECT_HEADER.to_string(), project.to_string());
            }
            let secret = TelemetrySecret {
                reference,
                header: (!langfuse).then(|| LANGSMITH_KEY_HEADER.to_string()),
                prefix: None,
                placement: langfuse.then(|| BASIC_AUTH_PLACEMENT.to_string()),
            };
            Ok(vendor_target(
                entry,
                destination,
                Payload::Traces,
                headers,
                secret,
            ))
        }
        TelemetryKind::CloudwatchLogs | TelemetryKind::CloudwatchTraces => {
            set_by_box("headers", entry.headers.is_some())?;
            set_by_box("accepts", entry.accepts.is_some())?;
            not_here("project", entry.project.is_some())?;
            if !entry.destination.trim().is_empty() {
                return Err(format!(
                    "a `{}` target takes `region` and names its own endpoint, so leave out \
                     `destination`",
                    kind.spelling()
                ));
            }
            let logs = kind == TelemetryKind::CloudwatchLogs;
            if !logs {
                not_here("log_group", entry.log_group.is_some())?;
                not_here("log_stream", entry.log_stream.is_some())?;
            }
            let region = entry.region.as_deref().map(str::trim).unwrap_or_default();
            let region_is_valid = (1..=MAXIMUM_REGION).contains(&region.len())
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            if !region_is_valid {
                return Err(format!(
                    "a `{}` target needs `region`, an AWS region such as `us-west-2`",
                    kind.spelling()
                ));
            }
            let reference = vendor_secret(entry)?;
            if !SIGNING_SCHEMES
                .iter()
                .any(|scheme| reference.trim().starts_with(scheme))
            {
                return Err(format!(
                    "a `{}` target is signed with SigV4, so `secret.ref` names `aws://profile` or \
                     `credsd://environment`",
                    kind.spelling()
                ));
            }
            let mut headers = BTreeMap::new();
            let (service, payload) = if logs {
                let (group, stream) = log_names(entry)?;
                headers.insert(LOG_GROUP_HEADER.to_string(), group);
                headers.insert(LOG_STREAM_HEADER.to_string(), stream);
                ("logs", Payload::Logs)
            } else {
                ("xray", Payload::Traces)
            };
            let secret = TelemetrySecret {
                reference,
                header: None,
                prefix: None,
                placement: None,
            };
            Ok(vendor_target(
                entry,
                format!("https://{service}.{region}.amazonaws.com"),
                payload,
                headers,
                secret,
            ))
        }
    }
}

/// A vendor target's secret reference, refusing a placement the vendor fixes.
fn vendor_secret(entry: &TelemetryEntry) -> Result<String, String> {
    let kind = entry.kind.spelling();
    let secret = entry
        .secret
        .as_ref()
        .ok_or_else(|| format!("a `{kind}` target needs `secret.ref`"))?;
    for (key, set) in [
        ("secret.header", secret.header.is_some()),
        ("secret.prefix", secret.prefix.is_some()),
        ("secret.placement", secret.placement.is_some()),
    ] {
        if set {
            return Err(format!(
                "a `{kind}` target sets `{key}` itself, so leave it out"
            ));
        }
    }
    Ok(secret.reference.clone())
}

/// The plain OTLP target a vendor target stands for.
fn vendor_target(
    entry: &TelemetryEntry,
    destination: String,
    payload: Payload,
    headers: BTreeMap<String, String>,
    secret: TelemetrySecret,
) -> TelemetryEntry {
    TelemetryEntry {
        kind: TelemetryKind::Otlp,
        destination,
        include: entry.include.clone(),
        secret: Some(secret),
        accepts: Some(vec![payload]),
        headers: (!headers.is_empty()).then_some(headers),
        log_group: None,
        log_stream: None,
        project: None,
        region: None,
    }
}

/// A `cloudwatch_logs` target's group and stream, checked against CloudWatch Logs' naming rules.
fn log_names(entry: &TelemetryEntry) -> Result<(String, String), String> {
    let (Some(group), Some(stream)) = (entry.log_group.as_deref(), entry.log_stream.as_deref())
    else {
        return Err("a `cloudwatch_logs` target needs `log_group` and `log_stream`".to_string());
    };
    let (group, stream) = (group.trim(), stream.trim());
    let group_is_valid = (1..=MAXIMUM_LOG_NAME).contains(&group.len())
        && group
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/#".contains(&byte));
    if !group_is_valid {
        return Err(format!(
            "`log_group` {group:?} is not a CloudWatch Logs group name: 1 to {MAXIMUM_LOG_NAME} \
             letters, digits, `.`, `_`, `-`, `/` or `#`"
        ));
    }
    let stream_is_valid = (1..=MAXIMUM_LOG_NAME).contains(&stream.len())
        && !stream
            .chars()
            .any(|character| character == ':' || character == '*' || character.is_control());
    if !stream_is_valid {
        return Err(format!(
            "`log_stream` {stream:?} is not a CloudWatch Logs stream name: 1 to \
             {MAXIMUM_LOG_NAME} characters, with no `:`, `*` or control character"
        ));
    }
    Ok((group.to_string(), stream.to_string()))
}

/// Refuse a fixed header that would stand where the credential or a signature goes.
fn refuse_a_credential_header(
    headers: &BTreeMap<String, String>,
    shape: Option<&CredentialShape>,
) -> Result<(), String> {
    for name in headers.keys() {
        let lowered = name.to_ascii_lowercase();
        if lowered == DEFAULT_HEADER.to_ascii_lowercase()
            || lowered.starts_with(SIGNING_HEADER_PREFIX)
            || shape
                .and_then(CredentialShape::header)
                .is_some_and(|credential| credential.eq_ignore_ascii_case(name))
        {
            return Err(format!(
                "the {name} header carries a credential or a signature, so it is set through \
                 `secret` and never as a fixed header"
            ));
        }
    }
    Ok(())
}

/// The host and port a destination's credential is bound to.
fn credential_destination(destination: &str) -> Result<String, String> {
    let dialed = if destination.contains("://") {
        destination.to_string()
    } else {
        format!("http://{destination}")
    };
    let url = url::Url::parse(&dialed)
        .map_err(|_| "the destination is not a URL a credential can be bound to".to_string())?;
    let host = match url.host() {
        Some(url::Host::Domain(name)) => name.to_string(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        _ => {
            return Err(
                "a credential is bound to a host name or an IPv4 address, and this destination \
                 names neither"
                    .to_string(),
            );
        }
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "the destination names no port".to_string())?;
    Ok(format!("{host}:{port}"))
}

/// One target's vault, and the header that presents its phantom when the credential has one.
type ResolvedCredential = (Arc<credentials::Vault>, Option<(String, String)>);

/// The vault holding one target's credential, and the header presenting its phantom.
///
/// Each target gets its own vault, apart from the egress gateway's, so no request the workload
/// sends can carry this credential.
fn resolved_secret(
    label: &str,
    destination: &str,
    secret: &TelemetrySecret,
) -> Result<ResolvedCredential, BoxError> {
    let refused = |reason: String| -> BoxError { refuse(label, reason).into() };
    let uri = telemetry_secret_uri(&secret.reference).map_err(refused)?;
    let locator = credentials::Locator::parse_uri(&uri).map_err(|source| ConfigError::Locator {
        locator: "<telemetry secret>".to_string(),
        source,
    })?;
    let shape = CredentialShape::of(secret).map_err(refused)?;
    let pattern = credentials::DestinationPattern::parse(
        &credential_destination(destination).map_err(refused)?,
    )
    .map_err(|error| refused(error.to_string()))?;
    let route = match shape.inject_mode().map_err(refused)? {
        Some(mode) => credentials::RouteSpec::opaque(pattern, locator, mode),
        None => credentials::RouteSpec::signed_aws(pattern, locator),
    };
    let opened = credentials::Vault::open(
        credentials::VaultConfig::new(
            credentials::Backend::local(),
            format!("strands-box-telemetry-{label}"),
        )
        .route(route)
        .require_every_route(),
    )
    .map_err(|source| ConfigError::Locator {
        locator: "<telemetry secret>".to_string(),
        source,
    })?;
    let presented = match (shape.presented(""), opened.phantoms()) {
        (None, []) => None,
        (Some(_), [phantom]) => shape.presented(phantom.token()),
        (_, phantoms) => {
            return Err(refused(format!(
                "the credential minted {} phantoms, and this shape presents {}",
                phantoms.len(),
                usize::from(shape.presented("").is_some())
            )));
        }
    };
    Ok((Arc::new(opened.into_vault()), presented))
}

/// The stored telemetry entries as one collector request.
pub(crate) fn config_for(
    box_name: &str,
    entries: &BTreeMap<String, TelemetryEntry>,
    layout: &crate::record::layout::BoxRoot,
) -> Result<TelemetryConfig, BoxError> {
    let mut request = TelemetryConfig::for_box(box_name);
    if entries.is_empty() {
        let destination = layout.telemetry_file();
        let file = layout.open_telemetry_file()?;
        return Ok(request.with_target(Target::opened_file(destination.to_string_lossy(), file)));
    }

    for (name, entry) in entries {
        let entry = &expanded(entry).map_err(|reason| refuse(name, reason))?;
        let mut target = target_for(entry, layout.operator_home(), layout.root(), None)
            .map_err(|reason| refuse(name, reason))?;
        if let Some(secret) = &entry.secret {
            let (vault, presented) = resolved_secret(name, entry.destination.trim(), secret)?;
            target = target.with_vault(vault);
            if let Some((header, value)) = presented {
                target = target.with_header(header, value);
            }
        }
        request = request.with_target(target);
    }
    Ok(request)
}

/// The declared telemetry targets, refusing every spelling the collector cannot honour.
pub(crate) fn checked(
    entries: &BTreeMap<String, TelemetryEntry>,
    box_directory: &Path,
) -> Result<BTreeMap<String, TelemetryEntry>, ConfigError> {
    let home = crate::record::layout::operator_home_directory().ok();

    let mut accepted = BTreeMap::new();
    for (name, authored) in entries {
        // A vendor target is stored as the plain target it stands for, so `run` reads one shape.
        let entry = &expanded(authored).map_err(|reason| refuse(name, reason))?;
        {
            // **A file target names an absolute path**, judged on the AUTHORED spelling. A relative
            // one opens against whatever working directory the box's trusted process holds, so two
            if entry.kind == TelemetryKind::File {
                let destination = entry.destination.trim();
                // Exactly the tilde forms `expanded_home_path` rewrites, and no other:
                let home_relative = destination == "~" || destination.starts_with("~/");
                if !home_relative && !Path::new(destination).is_absolute() {
                    return Err(refuse(
                        name,
                        format!(
                            "a file destination must be absolute or begin with `~/`; \
                             {destination:?} would open against the box's working directory"
                        ),
                    ));
                }
            }
            // **Both `include` refusals are stated here**, because the collector's own messages name
            // the record spellings, and `include` accepts none of them.
            if let Some(include) = &entry.include {
                if include.is_empty() {
                    let every: Vec<&str> = SignalGroup::every()
                        .iter()
                        .map(|group| group.as_str())
                        .collect();
                    return Err(refuse(
                        name,
                        format!(
                            "the target names no signal, so nothing would reach it; write one or \
                             more of: {}",
                            every.join(", ")
                        ),
                    ));
                }
                for (index, group) in include.iter().enumerate() {
                    if include[..index].contains(group) {
                        return Err(refuse(
                            name,
                            format!("the target names {} twice", group.as_str()),
                        ));
                    }
                }
            }
            let shape = match &entry.secret {
                Some(secret) => {
                    telemetry_secret_uri(&secret.reference)
                        .map_err(|reason| refuse(name, reason))?;
                    let shape =
                        CredentialShape::of(secret).map_err(|reason| refuse(name, reason))?;
                    shape.inject_mode().map_err(|reason| refuse(name, reason))?;
                    credential_destination(entry.destination.trim())
                        .map_err(|reason| refuse(name, reason))?;
                    Some(shape)
                }
                None => None,
            };
            if let Some(headers) = &entry.headers {
                refuse_a_credential_header(headers, shape.as_ref())
                    .map_err(|reason| refuse(name, reason))?;
            }

            // **Every remaining rule belongs to the collector, so ask it rather than restate it.**
            // Two copies disagreed on `HTTPS://`, so `configure` refused what `run` accepted. The
            let probe = target_for(
                entry,
                home.as_deref(),
                box_directory,
                entry
                    .secret
                    .as_ref()
                    .map(|_| TargetSecret::new("probe", "")),
            )
            .map_err(|reason| refuse(name, reason))?;
            TelemetryConfig::for_box("probe")
                .with_target(probe)
                .validate()
                .map_err(|error| refuse(name, error.to_string()))?;
        }
        accepted.insert(name.clone(), entry.clone());
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A destination inside the box directory but outside `private/` is refused**, because a
    /// process a spec grants reach there could truncate the record of its own denials.
    ///
    /// Two positives pair with the refusals. Without them a check that refuses everything passes,
    /// and the guard is one `starts_with` against a directory a caller now chooses — so an
    /// anchor pointing at nothing would look identical to an anchor working.
    #[test]
    fn a_destination_inside_the_box_directory_outside_private_is_refused() {
        let box_directory = Path::new("/var/lib/boxes/codex");

        let refusal = refuse_a_workload_reachable_destination(
            box_directory.join("trust/records.jsonl").to_str().unwrap(),
            box_directory,
        )
        .expect_err("a path beside `private/` is reachable by a grant, so it must be refused");
        assert!(
            refusal.contains("outside its private tree"),
            "the refusal must name why: {refusal}"
        );

        let refusal = refuse_a_workload_reachable_destination(
            box_directory
                .join("private/../trust/records.jsonl")
                .to_str()
                .unwrap(),
            box_directory,
        )
        .expect_err("a `..` component must be refused rather than resolved");
        assert!(refusal.contains("`..`"), "{refusal}");

        refuse_a_workload_reachable_destination(
            box_directory
                .join("private/telemetry/records.jsonl")
                .to_str()
                .unwrap(),
            box_directory,
        )
        .expect("the private tree is the one destination inside the box that is allowed");

        refuse_a_workload_reachable_destination("/var/log/box.jsonl", box_directory)
            .expect("a destination outside the box directory is allowed");
    }

    /// **A destination in the macOS data-volume spelling of the box directory is refused** outside
    /// its private tree, and accepted inside it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_data_volume_destination_outside_private_is_refused() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let box_directory = scratch
            .path()
            .canonicalize()
            .expect("resolves")
            .join("codex");
        std::fs::create_dir_all(box_directory.join("private")).expect("the box directory");
        let data_volume =
            Path::new("/System/Volumes/Data").join(box_directory.strip_prefix("/").unwrap());

        refuse_a_workload_reachable_destination(
            data_volume
                .join("bin/records.jsonl")
                .to_str()
                .expect("UTF-8"),
            &box_directory,
        )
        .expect_err("a destination outside private/ is refused in either spelling");
        refuse_a_workload_reachable_destination(
            data_volume
                .join("private/records.jsonl")
                .to_str()
                .expect("UTF-8"),
            &box_directory,
        )
        .expect("a destination under private/ is accepted in either spelling");
    }

    /// A sibling whose path merely *starts with* the box directory's spelling is not inside it.
    #[test]
    fn a_sibling_sharing_the_box_directorys_prefix_is_not_inside_it() {
        refuse_a_workload_reachable_destination(
            "/var/lib/boxes/codex-notes/records.jsonl",
            Path::new("/var/lib/boxes/codex"),
        )
        .expect("a sibling directory is outside the box, whatever its name begins with");
    }

    /// **A secret reference is a reference.** `secret://NAME` means `env://NAME`, and a bare value is
    /// refused without being echoed, in case it is one.
    #[test]
    fn a_secret_reference_is_normalized_and_a_literal_is_refused() {
        assert_eq!(
            telemetry_secret_uri("secret://HONEYCOMB_KEY").expect("the alias is accepted"),
            format!("{ENV_SCHEME}HONEYCOMB_KEY")
        );
        assert_eq!(
            telemetry_secret_uri("env://HONEYCOMB_KEY").expect("the canonical form is accepted"),
            "env://HONEYCOMB_KEY"
        );
        assert!(
            telemetry_secret_uri("secret://").is_err(),
            "an empty name names no variable"
        );

        let refusal = telemetry_secret_uri("hcaik_live_abcdef")
            .expect_err("a literal value is not a reference");
        assert!(
            !refusal.contains("hcaik_live_abcdef"),
            "the refusal must not echo the value, in case it is a secret: {refusal}"
        );
    }

    /// A file destination must be absolute or `~/`-relative, judged on the AUTHORED spelling.
    #[test]
    fn a_relative_file_destination_is_refused() {
        let entry = TelemetryEntry {
            kind: TelemetryKind::File,
            destination: "records.jsonl".to_string(),
            include: None,
            secret: None,
            accepts: None,
            headers: None,
            log_group: None,
            log_stream: None,
            project: None,
            region: None,
        };
        let entries = BTreeMap::from([("decisions".to_string(), entry)]);
        let refusal = checked(&entries, Path::new("/var/lib/boxes/codex"))
            .expect_err("a relative file destination must be refused");
        assert!(refusal.to_string().contains("absolute"), "{refusal}");
        // The refusal names the target the operator keyed it under, not a position in an array.
        assert!(refusal.to_string().contains("decisions"), "{refusal}");
    }

    /// **`trace` names both the agent's spans and the control plane**, so neither is selectable on
    /// its own, and the five words together name every signal the box files.
    ///
    /// `logs` and `metrics` are separate words rather than part of `trace`, because a harness log is
    /// not a span and an operator narrowing to spans must not silently also take metrics.
    #[test]
    fn the_five_words_expand_through_the_production_path() {
        assert_eq!(
            signals_for(&[SignalGroup::Deny]),
            vec![Signal::PolicyDenied]
        );
        assert_eq!(
            signals_for(&[SignalGroup::Permit]),
            vec![Signal::PolicyPermitted]
        );
        assert_eq!(
            signals_for(&[SignalGroup::Trace]),
            vec![Signal::AgentTrace, Signal::ControlPlane]
        );
        assert_eq!(signals_for(&[SignalGroup::Logs]), vec![Signal::AgentLogs]);
        assert_eq!(
            signals_for(&[SignalGroup::Metrics]),
            vec![Signal::AgentMetrics]
        );

        // Counted against the crate's own set, so a seventh signal no word reaches fails here.
        let every = signals_for(&SignalGroup::every());
        assert_eq!(every.len(), Signal::every().len(), "{every:?}");
    }

    /// **An absent `include` takes every signal**, so an operator who names nothing still receives
    /// the harness's own logs and metrics.
    ///
    /// Read through `target_for`, which is the one path a run takes, rather than through
    /// `Signal::default_signals` — the box could otherwise call `receiving` with a narrower set and
    /// this assertion would still pass.
    #[test]
    fn an_absent_include_takes_every_signal() {
        let entry = TelemetryEntry {
            kind: TelemetryKind::File,
            destination: "/tmp/records.jsonl".to_string(),
            include: None,
            secret: None,
            accepts: None,
            headers: None,
            log_group: None,
            log_stream: None,
            project: None,
            region: None,
        };
        let target = target_for(&entry, None, Path::new("/var/lib/boxes/codex"), None)
            .expect("the entry is well formed");
        assert_eq!(
            target.signals().len(),
            Signal::every().len(),
            "an absent include must reach every signal: {:?}",
            target.signals()
        );
        for expected in [Signal::AgentLogs, Signal::AgentMetrics, Signal::AgentTrace] {
            assert!(
                target.signals().contains(&expected),
                "{} must arrive with no include written",
                expected.as_str()
            );
        }
    }

    /// **An empty `include` and a repeated word are both refused in the operator's own vocabulary**,
    /// because the collector's own messages name the record spellings instead.
    #[test]
    fn an_empty_or_repeated_include_is_refused_naming_the_five_words() {
        let entry = |include: Vec<SignalGroup>| TelemetryEntry {
            kind: TelemetryKind::File,
            destination: "/tmp/records.jsonl".to_string(),
            include: Some(include),
            secret: None,
            accepts: None,
            headers: None,
            log_group: None,
            log_stream: None,
            project: None,
            region: None,
        };

        let empty = checked(
            &BTreeMap::from([("decisions".to_string(), entry(vec![]))]),
            Path::new("/var/lib/boxes/codex"),
        )
        .expect_err("an empty include names no signal")
        .to_string();
        assert!(empty.contains("no signal"), "{empty}");
        for word in ["deny", "permit", "trace", "logs", "metrics"] {
            assert!(
                empty.contains(word),
                "the refusal must list {word}, which an operator may write: {empty}"
            );
        }

        let repeated = checked(
            &BTreeMap::from([(
                "decisions".to_string(),
                entry(vec![SignalGroup::Deny, SignalGroup::Deny]),
            )]),
            Path::new("/var/lib/boxes/codex"),
        )
        .expect_err("a repeated word is refused rather than deduplicated in silence")
        .to_string();
        assert!(repeated.contains("deny twice"), "{repeated}");
    }

    /// Parse `[telemetry.<label>]` tables the way `box.toml` delivers them.
    fn parsed(text: &str) -> BTreeMap<String, TelemetryEntry> {
        #[derive(Deserialize)]
        struct File {
            telemetry: BTreeMap<String, TelemetryEntry>,
        }
        toml::from_str::<File>(text)
            .expect("the table parses")
            .telemetry
    }

    /// **The three vendor shapes are what an operator writes**, and each passes the checks.
    #[test]
    fn langfuse_langsmith_and_cloudwatch_targets_are_accepted() {
        let entries = parsed(
            r#"
[telemetry.langfuse]
kind = "otlp"
destination = "https://cloud.langfuse.com/api/public/otel"
accepts = ["traces"]
headers = { "x-langfuse-ingestion-version" = "4" }
secret = { ref = "env://LANGFUSE_AUTH", placement = "basic_auth" }

[telemetry.langsmith]
kind = "otlp"
destination = "https://api.smith.langchain.com/otel"
accepts = ["traces"]
headers = { "Langsmith-Project" = "strands-box" }
secret = { ref = "env://LANGSMITH_API_KEY", header = "x-api-key" }

[telemetry.cloudwatch_logs]
kind = "otlp"
destination = "https://logs.us-west-2.amazonaws.com"
accepts = ["logs"]
headers = { "x-aws-log-group" = "/strands-box/demo", "x-aws-log-stream" = "box" }
secret.ref = "aws://default"

[telemetry.xray]
kind = "otlp"
destination = "https://xray.us-west-2.amazonaws.com"
accepts = ["traces"]
secret.ref = "credsd://default"
"#,
        );
        let checked = checked(&entries, Path::new("/var/lib/boxes/codex")).expect("accepted");
        assert_eq!(checked.len(), 4);
        assert_eq!(
            checked["langfuse"].accepts.as_deref(),
            Some(&[Payload::Traces][..])
        );
    }

    /// **A Secrets Manager secret is an opaque credential**, so it takes a placement like `env://`.
    #[test]
    fn a_secrets_manager_secret_is_accepted_with_a_placement() {
        let entries = parsed(
            r#"
[telemetry.langfuse]
kind = "otlp"
destination = "https://us.cloud.langfuse.com/api/public/otel"
accepts = ["traces"]
secret = { ref = "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH", placement = "basic_auth" }

[telemetry.langsmith]
kind = "otlp"
destination = "https://api.smith.langchain.com/otel"
secret = { ref = "aws-secretsmanager://strands-box/telemetry#LANGSMITH_API_KEY", header = "x-api-key" }
"#,
        );
        let checked = checked(&entries, Path::new("/var/lib/boxes/codex")).expect("accepted");
        assert_eq!(checked.len(), 2);
    }

    /// **A vendor kind is stored as the plain OTLP target it stands for**: the endpoint, the
    /// payloads, the headers and the credential placement are the box's, and the operator writes
    /// only what is theirs.
    #[test]
    fn a_vendor_kind_expands_to_its_otlp_target() {
        let entries = parsed(
            r#"
[telemetry.langfuse]
kind = "langfuse"
destination = "https://us.cloud.langfuse.com"
secret.ref = "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH"

[telemetry.langsmith]
kind = "langsmith"
project = "strands-box-agentcore"
secret.ref = "aws-secretsmanager://strands-box/telemetry#LANGSMITH_API_KEY"

[telemetry.cloudwatch_logs]
kind = "cloudwatch_logs"
region = "us-west-2"
log_group = "strandsbox"
log_stream = "agentcore-runtime"
secret.ref = "aws://runtime"

[telemetry.cloudwatch_traces]
kind = "cloudwatch_traces"
region = "us-west-2"
secret.ref = "aws://runtime"
"#,
        );
        let stored = checked(&entries, Path::new("/var/lib/boxes/codex")).expect("accepted");
        let header = |label: &str, name: &str| {
            stored[label]
                .headers
                .as_ref()
                .and_then(|headers| headers.get(name))
                .cloned()
        };
        for label in [
            "langfuse",
            "langsmith",
            "cloudwatch_logs",
            "cloudwatch_traces",
        ] {
            assert_eq!(stored[label].kind, TelemetryKind::Otlp, "{label}");
        }

        let langfuse = &stored["langfuse"];
        assert_eq!(
            langfuse.destination,
            "https://us.cloud.langfuse.com/api/public/otel"
        );
        assert_eq!(langfuse.accepts.as_deref(), Some(&[Payload::Traces][..]));
        assert_eq!(
            header("langfuse", "x-langfuse-ingestion-version").as_deref(),
            Some("4")
        );
        let secret = langfuse.secret.as_ref().expect("a secret");
        assert_eq!(secret.placement.as_deref(), Some("basic_auth"));

        let langsmith = &stored["langsmith"];
        assert_eq!(
            langsmith.destination,
            "https://api.smith.langchain.com/otel"
        );
        assert_eq!(
            header("langsmith", "Langsmith-Project").as_deref(),
            Some("strands-box-agentcore")
        );
        assert_eq!(
            langsmith.secret.as_ref().and_then(|s| s.header.as_deref()),
            Some("x-api-key")
        );

        let logs = &stored["cloudwatch_logs"];
        assert_eq!(logs.destination, "https://logs.us-west-2.amazonaws.com");
        assert_eq!(logs.accepts.as_deref(), Some(&[Payload::Logs][..]));
        assert_eq!(
            header("cloudwatch_logs", "x-aws-log-group").as_deref(),
            Some("strandsbox")
        );
        assert_eq!(
            header("cloudwatch_logs", "x-aws-log-stream").as_deref(),
            Some("agentcore-runtime")
        );

        let traces = &stored["cloudwatch_traces"];
        assert_eq!(traces.destination, "https://xray.us-west-2.amazonaws.com");
        assert_eq!(traces.accepts.as_deref(), Some(&[Payload::Traces][..]));
        assert!(traces.headers.is_none());

        // The stored form is itself accepted unchanged, so `run` reads what `checked` wrote.
        assert_eq!(
            checked(&stored, Path::new("/var/lib/boxes/codex")).expect("accepted"),
            stored
        );
    }

    /// **A vendor kind refuses every field it sets, and every field it lacks**, naming the field.
    #[test]
    fn a_vendor_kind_refuses_what_it_sets_or_lacks() {
        let cases = [
            (
                "kind = \"langfuse\"\nheaders = { \"x\" = \"y\" }\nsecret.ref = \"env://K\"\n",
                "sets `headers` itself",
            ),
            (
                "kind = \"langfuse\"\naccepts = [\"traces\"]\nsecret.ref = \"env://K\"\n",
                "sets `accepts` itself",
            ),
            (
                "kind = \"langfuse\"\nproject = \"p\"\nsecret.ref = \"env://K\"\n",
                "`project` does not apply",
            ),
            (
                "kind = \"langsmith\"\nsecret = { ref = \"env://K\", header = \"x-api-key\" }\n",
                "sets `secret.header` itself",
            ),
            ("kind = \"langsmith\"\n", "needs `secret.ref`"),
            (
                "kind = \"cloudwatch_logs\"\nlog_group = \"g\"\nlog_stream = \"s\"\nsecret.ref = \"aws://p\"\n",
                "needs `region`",
            ),
            (
                "kind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\nlog_group = \"g\"\nsecret.ref = \"aws://p\"\n",
                "needs `log_group` and `log_stream`",
            ),
            (
                "kind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\nlog_group = \"a b\"\nlog_stream = \"s\"\nsecret.ref = \"aws://p\"\n",
                "not a CloudWatch Logs group name",
            ),
            (
                "kind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\nlog_group = \"g\"\nlog_stream = \"a:b\"\nsecret.ref = \"aws://p\"\n",
                "not a CloudWatch Logs stream name",
            ),
            (
                "kind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\nlog_group = \"g\"\nlog_stream = \"s\"\nsecret.ref = \"env://K\"\n",
                "signed with SigV4",
            ),
            (
                "kind = \"cloudwatch_logs\"\ndestination = \"https://logs.us-west-2.amazonaws.com\"\nregion = \"us-west-2\"\nlog_group = \"g\"\nlog_stream = \"s\"\nsecret.ref = \"aws://p\"\n",
                "leave out `destination`",
            ),
            (
                "kind = \"cloudwatch_traces\"\nregion = \"us-west-2\"\nlog_group = \"g\"\nsecret.ref = \"aws://p\"\n",
                "`log_group` does not apply",
            ),
            (
                "kind = \"otlp\"\ndestination = \"https://example.com\"\nregion = \"us-west-2\"\n",
                "`region` does not apply",
            ),
            ("kind = \"otlp\"\n", "names no destination"),
        ];
        for (body, expected) in cases {
            let refused = refusal(&format!("[telemetry.x]\n{body}"));
            assert!(
                refused.contains(expected),
                "{body:?} gave {refused:?}, expected {expected:?}"
            );
        }
    }

    /// One entry's refusal, as the operator reads it.
    fn refusal(text: &str) -> String {
        checked(&parsed(text), Path::new("/var/lib/boxes/codex"))
            .expect_err("refused")
            .to_string()
    }

    /// **A signed credential takes no header, and Basic auth takes no prefix**, because neither
    /// would be the request that is sent.
    #[test]
    fn a_credential_field_its_shape_cannot_use_is_refused() {
        let signed = refusal(
            "[telemetry.x]\nkind = \"otlp\"\ndestination = \"https://logs.us-west-2.amazonaws.com\"\n\
             secret = { ref = \"aws://default\", header = \"x-api-key\" }\n",
        );
        assert!(signed.contains("signs the whole request"), "{signed}");

        let basic = refusal(
            "[telemetry.x]\nkind = \"otlp\"\ndestination = \"https://cloud.langfuse.com\"\n\
             secret = { ref = \"env://K\", placement = \"basic_auth\", prefix = \"Basic \" }\n",
        );
        assert!(basic.contains("no `header` or `prefix`"), "{basic}");

        let unknown = refusal(
            "[telemetry.x]\nkind = \"otlp\"\ndestination = \"https://vendor.example\"\n\
             secret = { ref = \"env://K\", placement = \"query_param\" }\n",
        );
        assert!(unknown.contains("not a placement"), "{unknown}");
    }

    /// **A fixed header never stands where the credential or a signature goes.**
    #[test]
    fn a_fixed_header_cannot_carry_a_credential_or_a_signature() {
        for header in ["Authorization", "x-amz-date", "X-Api-Key"] {
            let text = format!(
                "[telemetry.x]\nkind = \"otlp\"\ndestination = \"https://vendor.example\"\n\
                 headers = {{ \"{header}\" = \"v\" }}\n\
                 secret = {{ ref = \"env://K\", header = \"x-api-key\" }}\n"
            );
            let refused = refusal(&text);
            assert!(refused.contains("through `secret`"), "{header}: {refused}");
        }
    }

    /// **A file target takes no `accepts` and no header**, asked of the collector.
    #[test]
    fn a_file_target_takes_no_endpoint_keys() {
        let refused = refusal(
            "[telemetry.x]\nkind = \"file\"\ndestination = \"/tmp/records.jsonl\"\naccepts = [\"logs\"]\n",
        );
        assert!(refused.contains("no accepts"), "{refused}");
    }

    /// **A credential destination is a host name or an IPv4 address with a port.**
    #[test]
    fn a_credential_destination_carries_its_port() {
        assert_eq!(
            credential_destination("https://cloud.langfuse.com/api/public/otel").as_deref(),
            Ok("cloud.langfuse.com:443")
        );
        assert_eq!(
            credential_destination("127.0.0.1:4318").as_deref(),
            Ok("127.0.0.1:4318")
        );
        assert!(credential_destination("http://[::1]:4318").is_err());
    }

    /// **The vault holds the secret and the target holds only the phantom**, presented where the
    /// vault looks for it.
    #[test]
    fn the_target_presents_a_phantom_and_never_the_secret() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("key");
        std::fs::write(&path, "pk-lf-1:sk-lf-2").expect("write");
        let reference = format!("file://{}", path.display());

        let secret = |placement: Option<&str>, header: Option<&str>| TelemetrySecret {
            reference: reference.clone(),
            header: header.map(str::to_string),
            prefix: None,
            placement: placement.map(str::to_string),
        };

        let (vault, presented) = resolved_secret(
            "langfuse",
            "https://cloud.langfuse.com/api/public/otel",
            &secret(Some(BASIC_AUTH_PLACEMENT), None),
        )
        .expect("resolves");
        let (header, value) = presented.expect("a Basic phantom");
        assert_eq!(header, DEFAULT_HEADER);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.strip_prefix("Basic ").expect("Basic"))
            .expect("base64");
        let decoded = String::from_utf8(decoded).expect("utf-8");
        assert!(decoded.starts_with("strands-box:strands_box_"), "{decoded}");
        assert!(
            !format!("{vault:?}").contains("sk-lf-2"),
            "the vault prints no secret"
        );

        let (_, presented) = resolved_secret(
            "langsmith",
            "https://api.smith.langchain.com/otel",
            &secret(None, Some("x-api-key")),
        )
        .expect("resolves");
        let (header, value) = presented.expect("a header phantom");
        assert_eq!(header, "x-api-key");
        assert!(
            value.starts_with("strands_box_"),
            "no prefix on a named header: {value}"
        );

        let (_, presented) =
            resolved_secret("bearer", "https://vendor.example", &secret(None, None))
                .expect("resolves");
        let (header, value) = presented.expect("a bearer phantom");
        assert_eq!(header, DEFAULT_HEADER);
        assert!(value.starts_with("Bearer strands_box_"), "{value}");

        let (_, presented) = resolved_secret(
            "cloudwatch",
            "https://logs.us-west-2.amazonaws.com",
            &TelemetrySecret {
                reference: "aws://default".to_string(),
                header: None,
                prefix: None,
                placement: None,
            },
        )
        .expect("a signed route resolves per request, not at open");
        assert!(
            presented.is_none(),
            "a signed credential presents no phantom"
        );
    }

    /// **An empty declaration is unrepresentable**, now that a name holds one target rather than an
    /// array. `[[telemetry.file]]` with no entries was a kind naming no target, and `checked` had to
    /// refuse it; `[telemetry.<name>]` cannot be written that way.
    #[test]
    fn no_declaration_can_name_a_kind_without_a_target() {
        assert!(
            checked(&BTreeMap::new(), Path::new("/var/lib/boxes/codex"))
                .expect("no targets is not an error")
                .is_empty()
        );
    }
}
