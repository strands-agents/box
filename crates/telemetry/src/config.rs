//! What an operator declares: where records go, and how much of them.

use zeroize::Zeroizing;

use crate::error::{Result, TelemetryError};
use crate::record::Signal;

/// Which exporter a target selects.
///
/// `Deserialize` is what parses the `box.toml` spelling, so no caller hand-matches a string.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// One OTLP-JSON request per line, appended.
    File,
    /// OTLP over HTTP, protobuf.
    Otlp,
}

impl TargetKind {
    /// The `box.toml` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Otlp => "otlp",
        }
    }

    /// Every spelling, for a refusal that lists what an operator may write.
    #[must_use]
    pub fn every() -> Vec<&'static str> {
        Self::EVERY.iter().map(|k| k.as_str()).collect()
    }

    const EVERY: [Self; 2] = [Self::File, Self::Otlp];
}

/// One OTLP payload a destination accepts, named after its route.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// `/v1/traces`.
    Traces,
    /// `/v1/logs`.
    Logs,
    /// `/v1/metrics`.
    Metrics,
}

impl Payload {
    /// The `box.toml` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }

    /// Every payload, in route order.
    #[must_use]
    pub fn every() -> Vec<Self> {
        vec![Self::Traces, Self::Logs, Self::Metrics]
    }

    /// The OTLP/HTTP route this payload posts to.
    pub(crate) fn route(self) -> &'static str {
        match self {
            Self::Traces => "/v1/traces",
            Self::Logs => "/v1/logs",
            Self::Metrics => "/v1/metrics",
        }
    }
}

/// Header names the exporter writes itself, so a target may not set one.
const TRANSPORT_HEADERS: [&str; 5] = [
    "content-type",
    "content-length",
    "host",
    "transfer-encoding",
    "connection",
];

/// The header a target's credential is sent in, and its resolved value.
#[derive(Clone)]
pub struct TargetSecret {
    header: String,
    value: Zeroizing<String>,
}

impl TargetSecret {
    /// Take a resolved value. The caller resolved the reference; this never reads the environment.
    #[must_use]
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            value: Zeroizing::new(value.into()),
        }
    }

    pub(crate) fn header(&self) -> &str {
        &self.header
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// Whether a secret may cross to `destination`: TLS, or a host that never leaves this machine.
    fn may_cross_to(destination: &str) -> bool {
        parsed(destination).is_some_and(|url| url.scheme() == "https")
            || reaches_only_this_host(destination)
    }
}

impl std::fmt::Debug for TargetSecret {
    /// Names the header and never the value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetSecret")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// One declared destination.
#[derive(Debug, Clone)]
pub struct Target {
    kind: TargetKind,
    destination: String,
    signals: Vec<Signal>,
    secret: Option<TargetSecret>,
    file: Option<std::sync::Arc<std::fs::File>>,
    accepts: Option<Vec<Payload>>,
    headers: Vec<(String, String)>,
    vault: Option<std::sync::Arc<credentials::Vault>>,
}

impl Target {
    /// A target of `kind` at `destination`, receiving every decision signal until told otherwise.
    #[must_use]
    pub fn new(kind: TargetKind, destination: impl Into<String>) -> Self {
        Self {
            kind,
            destination: destination.into(),
            signals: Signal::default_signals(),
            secret: None,
            file: None,
            accepts: None,
            headers: Vec::new(),
            vault: None,
        }
    }

    /// Use an already-open file for this file target.
    #[must_use]
    pub fn opened_file(destination: impl Into<String>, file: std::fs::File) -> Self {
        Self {
            kind: TargetKind::File,
            destination: destination.into(),
            signals: Signal::default_signals(),
            secret: None,
            file: Some(std::sync::Arc::new(file)),
            accepts: None,
            headers: Vec::new(),
            vault: None,
        }
    }

    /// State exactly what this target receives. An empty or repeated set is refused by `validate`.
    #[must_use]
    pub fn receiving(mut self, signals: Vec<Signal>) -> Self {
        self.signals = signals;
        self
    }

    /// Attach the credential this destination needs.
    #[must_use]
    pub fn with_secret(mut self, secret: TargetSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    /// State which OTLP payloads this destination takes. An empty or repeated set is refused by
    /// `validate`.
    #[must_use]
    pub fn accepting(mut self, payloads: Vec<Payload>) -> Self {
        self.accepts = Some(payloads);
        self
    }

    /// Send one fixed, non-secret header on every request.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Attach this destination's credential through `vault` on every request.
    #[must_use]
    pub fn with_vault(mut self, vault: std::sync::Arc<credentials::Vault>) -> Self {
        self.vault = Some(vault);
        self
    }

    pub(crate) fn kind(&self) -> TargetKind {
        self.kind
    }

    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }

    /// What this target receives, so a caller can assert its own default rather than restate it.
    #[must_use]
    pub fn signals(&self) -> &[Signal] {
        &self.signals
    }

    pub(crate) fn secret(&self) -> Option<&TargetSecret> {
        self.secret.as_ref()
    }

    pub(crate) fn file(&self) -> Option<&std::fs::File> {
        self.file.as_deref()
    }

    /// The payloads this destination takes; every one when the caller stated none.
    pub(crate) fn accepts(&self) -> Vec<Payload> {
        self.accepts.clone().unwrap_or_else(Payload::every)
    }

    pub(crate) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub(crate) fn vault(&self) -> Option<&std::sync::Arc<credentials::Vault>> {
        self.vault.as_ref()
    }
}

/// Every target one box declares.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    box_name: String,
    targets: Vec<Target>,
    reports_failures: bool,
}

impl TelemetryConfig {
    /// A config for the box named `box_name`, with no target yet.
    #[must_use]
    pub fn for_box(box_name: impl Into<String>) -> Self {
        Self {
            box_name: box_name.into(),
            targets: Vec::new(),
            reports_failures: false,
        }
    }

    /// Print each failed batch to stderr with its full cause. Without this, a failed batch is only
    /// counted.
    #[must_use]
    pub fn reporting_failures(mut self) -> Self {
        self.reports_failures = true;
        self
    }

    /// Add a declared target.
    #[must_use]
    pub fn with_target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    pub(crate) fn box_name(&self) -> &str {
        &self.box_name
    }

    pub(crate) fn targets(&self) -> &[Target] {
        &self.targets
    }

    pub(crate) fn reports_failures(&self) -> bool {
        self.reports_failures
    }

    /// Refuse a config no run could honour. The one owner of every rule about a target.
    pub fn validate(&self) -> Result<()> {
        if self.box_name.is_empty() {
            return Err(TelemetryError::Config {
                reason: "the box name is empty".to_string(),
            });
        }
        for target in &self.targets {
            if target.destination.is_empty() {
                return Err(TelemetryError::Config {
                    reason: format!("the {} target names no destination", target.kind.as_str()),
                });
            }
            if target.signals.is_empty() {
                return Err(TelemetryError::Config {
                    reason: format!(
                        "the {} target names no signal, so nothing would reach it; write one or \
                         more of: {}",
                        target.kind.as_str(),
                        Signal::every().join(", ")
                    ),
                });
            }
            for (index, signal) in target.signals.iter().enumerate() {
                if target.signals[..index].contains(signal) {
                    return Err(TelemetryError::Config {
                        reason: format!(
                            "the {} target names {} twice",
                            target.kind.as_str(),
                            signal.as_str()
                        ),
                    });
                }
            }
            // Absolute here, whichever writer supplied it.
            if target.kind == TargetKind::File
                && !std::path::Path::new(&target.destination).is_absolute()
            {
                return Err(TelemetryError::Config {
                    reason: format!(
                        "the file target's destination {:?} is relative; a destination is absolute \
                         after any ~ expansion",
                        target.destination
                    ),
                });
            }
            if target.secret.is_some() && target.kind == TargetKind::File {
                return Err(TelemetryError::Config {
                    reason: "a file target attaches no secret, so naming one would read as \
                             protection the file does not have"
                        .to_string(),
                });
            }
            // A secret needs TLS, or a `secret.ref` ships a vendor key in the clear. Loopback is
            // exempt because the bytes never leave the host.
            if target.secret.is_some() && !TargetSecret::may_cross_to(&target.destination) {
                return Err(TelemetryError::Config {
                    reason: format!(
                        "the {} target carries a secret and its destination is neither https nor \
                         loopback",
                        target.kind.as_str()
                    ),
                });
            }
            Self::validate_otlp_shape(target)?;
        }
        Ok(())
    }

    /// Refuse an `accepts`, a header, or a vault the target's kind cannot honour.
    fn validate_otlp_shape(target: &Target) -> Result<()> {
        let refuse = |reason: String| Err(TelemetryError::Config { reason });
        if target.kind == TargetKind::File {
            if target.accepts.is_some() || !target.headers.is_empty() || target.vault.is_some() {
                return refuse(
                    "a file target writes every payload to one file, so it takes no accepts, no \
                     header and no credential"
                        .to_string(),
                );
            }
            return Ok(());
        }
        if let Some(accepts) = &target.accepts {
            if accepts.is_empty() {
                return refuse(format!(
                    "the {} target accepts no payload, so nothing would reach it; write one or \
                     more of: traces, logs, metrics",
                    target.kind.as_str()
                ));
            }
            for (index, payload) in accepts.iter().enumerate() {
                if accepts[..index].contains(payload) {
                    return refuse(format!(
                        "the {} target accepts {} twice",
                        target.kind.as_str(),
                        payload.as_str()
                    ));
                }
            }
        }
        for (name, value) in &target.headers {
            if name.is_empty() || !name.bytes().all(is_header_name_byte) {
                return refuse(format!("the header name {name:?} is not an RFC 7230 token"));
            }
            if TRANSPORT_HEADERS
                .iter()
                .any(|owned| owned.eq_ignore_ascii_case(name))
            {
                return refuse(format!(
                    "the exporter writes the {name} header itself, so a target may not set it"
                ));
            }
            if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                return refuse(format!(
                    "the {name} header value carries a control character"
                ));
            }
        }
        if target.vault.is_some() && !TargetSecret::may_cross_to(&target.destination) {
            return refuse(format!(
                "the {} target carries a credential and its destination is neither https nor \
                 loopback",
                target.kind.as_str()
            ));
        }
        if target.vault.is_some() && target.secret.is_some() {
            return refuse(
                "a target attaches one credential, through its vault or as a secret, not both"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Whether `byte` is legal in an RFC 7230 token.
fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A destination as `reqwest` will dial it, with a scheme supplied when the operator wrote none.
///
/// The one rule, so the loopback exemption cannot judge a different URL from the one the exporter
/// dials.
pub(crate) fn dialed(destination: &str) -> String {
    if destination.contains("://") {
        destination.to_string()
    } else {
        format!("http://{destination}")
    }
}

fn parsed(destination: &str) -> Option<url::Url> {
    url::Url::parse(&dialed(destination)).ok()
}

/// Whether a destination names the host this process runs on.
fn reaches_only_this_host(destination: &str) -> bool {
    match parsed(destination).as_ref().and_then(url::Url::host) {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **`as_str` and the serde spelling agree**, and nothing outside the vocabulary parses.
    ///
    /// Serde owns the parsing now, so this is the seam that matters: a `rename_all` that disagreed
    /// with `as_str` would store `"file"` and read back a different kind, silently.
    #[test]
    fn every_kind_spelling_round_trips_through_serde() {
        for spelling in TargetKind::every() {
            let parsed: TargetKind = serde_json::from_str(&format!("\"{spelling}\""))
                .unwrap_or_else(|error| panic!("{spelling} must deserialize: {error}"));
            assert_eq!(parsed.as_str(), spelling);
        }
        for absent in ["splunk", "kafka", "datadog", "awsemf"] {
            assert!(
                serde_json::from_str::<TargetKind>(&format!("\"{absent}\"")).is_err(),
                "{absent} names no built exporter"
            );
        }
    }

    /// A file target may not name a secret, because the file has no transport to protect.
    #[test]
    fn a_file_target_attaches_no_secret() {
        let refusal = TelemetryConfig::for_box("b")
            .with_target(
                Target::new(TargetKind::File, "/tmp/records.jsonl")
                    .with_secret(TargetSecret::new("x-key", "s3cret")),
            )
            .validate()
            .expect_err("a file target takes no secret");
        assert!(refusal.to_string().contains("no secret"));
    }

    /// A secret over plaintext is refused, because it would ship a vendor key in the clear.
    #[test]
    fn a_secret_without_tls_is_refused() {
        let refusal = TelemetryConfig::for_box("b")
            .with_target(
                Target::new(TargetKind::Otlp, "http://vendor.example")
                    .with_secret(TargetSecret::new("x-key", "s3cret")),
            )
            .validate()
            .expect_err("a secret needs TLS");
        assert!(refusal.to_string().contains("https"));
    }

    /// Loopback is exempt, because those bytes never leave the host.
    #[test]
    fn a_secret_to_loopback_is_accepted() {
        for destination in [
            "http://127.0.0.1:4318",
            "http://localhost:4318",
            "http://[::1]:4318",
        ] {
            TelemetryConfig::for_box("b")
                .with_target(
                    Target::new(TargetKind::Otlp, destination)
                        .with_secret(TargetSecret::new("x-key", "s3cret")),
                )
                .validate()
                .unwrap_or_else(|error| panic!("{destination} must be accepted: {error}"));
        }
    }

    /// A host that merely starts with a loopback name is not loopback.
    #[test]
    fn a_lookalike_host_is_not_loopback() {
        let refusal = TelemetryConfig::for_box("b")
            .with_target(
                Target::new(TargetKind::Otlp, "http://localhost.vendor.example")
                    .with_secret(TargetSecret::new("x-key", "s3cret")),
            )
            .validate()
            .expect_err("a suffixed host is a remote host");
        assert!(refusal.to_string().contains("https"));
    }

    /// No spelling makes a remote host loopback.
    ///
    /// Each of these defeated a hand-rolled authority split. The backslash is the sharpest: `url`
    /// and `reqwest` end the authority at `\` for a special scheme, so the host is `evil.com`
    /// while a `rsplit('@')` read `127.0.0.1`.
    #[test]
    fn userinfo_cannot_forge_a_loopback_destination() {
        for spelling in [
            "http://localhost:4318@evil.com/",
            "http://127.0.0.1:4318@attacker.example/v1/logs",
            "http://user:localhost@evil.com",
            "http://[::1]@evil.com",
            r"http://evil.com\@127.0.0.1/v1/logs",
            r"http://evil.com\@localhost",
        ] {
            assert!(
                !reaches_only_this_host(spelling),
                "{spelling} is not this host, whatever its userinfo says"
            );
            let refusal = TelemetryConfig::for_box("b")
                .with_target(
                    Target::new(TargetKind::Otlp, spelling)
                        .with_secret(TargetSecret::new("x-key", "s3cret")),
                )
                .validate()
                .expect_err("a secret must not cross plaintext to a remote host");
            assert!(refusal.to_string().contains("https"), "{spelling}");
        }
    }

    /// A real loopback destination still carries a secret, which is what the exemption is for.
    ///
    /// The last four were refused by the hand-rolled split: every `127.0.0.0/8` address is
    /// loopback, the host is case-insensitive, an integer literal is a valid IPv4 spelling, and a
    /// bare authority has no scheme to split on.
    #[test]
    fn a_plain_loopback_destination_still_takes_a_secret() {
        for spelling in [
            "http://127.0.0.1:4318",
            "http://localhost:4318/v1/logs",
            "http://[::1]:4318",
            "http://127.0.0.2:4318",
            "http://LOCALHOST:4318",
            "http://2130706433:4318",
            // Scheme-less, which the README documents as the ordinary `otlp` spelling. `localhost`
            // is the one that broke: `Url::parse("localhost:4318")` succeeds with the SCHEME
            // `localhost` and no host, so a first-parse-then-fall-back rule refused it while the
            // exporter dialed a real loopback address.
            "127.0.0.1:4318",
            "localhost:4318",
            "LOCALHOST:4318",
            "[::1]:4318",
        ] {
            assert!(reaches_only_this_host(spelling), "{spelling}");
        }
    }

    /// **One rule decides the URL, so validation cannot judge a URL the exporter will not dial.**
    #[test]
    fn the_dialed_url_is_the_one_that_was_judged() {
        for (authored, dialed_as) in [
            ("127.0.0.1:4318", "http://127.0.0.1:4318"),
            ("localhost:4318", "http://localhost:4318"),
            ("https://vendor.example", "https://vendor.example"),
        ] {
            assert_eq!(dialed(authored), dialed_as);
            assert_eq!(
                parsed(authored).map(|url| url.to_string()),
                url::Url::parse(dialed_as).ok().map(|url| url.to_string()),
                "{authored}: the judged URL must be the dialed one"
            );
        }
    }

    /// **`accepts`, a header and a credential each belong to an endpoint**, so a file target
    /// refuses all three, and an endpoint refuses an empty or repeated `accepts`.
    #[test]
    fn the_otlp_shape_is_refused_where_it_cannot_apply() {
        let file = |target: Target| {
            TelemetryConfig::for_box("b")
                .with_target(target)
                .validate()
                .expect_err("a file target takes none of these")
                .to_string()
        };
        let base = || Target::new(TargetKind::File, "/tmp/records.jsonl");
        assert!(file(base().accepting(vec![Payload::Traces])).contains("no accepts"));
        assert!(file(base().with_header("x-a", "1")).contains("no header"));

        let otlp = |target: Target| {
            TelemetryConfig::for_box("b")
                .with_target(target)
                .validate()
                .map_err(|error| error.to_string())
        };
        let endpoint = || Target::new(TargetKind::Otlp, "https://vendor.example");
        assert!(
            otlp(endpoint().accepting(vec![]))
                .expect_err("empty")
                .contains("accepts no payload")
        );
        assert!(
            otlp(endpoint().accepting(vec![Payload::Logs, Payload::Logs]))
                .expect_err("repeated")
                .contains("logs twice")
        );
        otlp(endpoint().accepting(vec![Payload::Traces])).expect("one payload is accepted");
    }

    /// **The exporter owns the transport headers**, so a target cannot replace the body's type or
    /// forge a second header line.
    #[test]
    fn a_header_the_exporter_owns_or_a_forged_line_is_refused() {
        let refusal = |name: &str, value: &str| {
            TelemetryConfig::for_box("b")
                .with_target(
                    Target::new(TargetKind::Otlp, "https://vendor.example")
                        .with_header(name, value),
                )
                .validate()
                .expect_err("refused")
                .to_string()
        };
        assert!(refusal("Content-Type", "application/json").contains("itself"));
        assert!(refusal("x-project", "a\r\nx-injected: 1").contains("control character"));
        assert!(refusal("bad header", "1").contains("RFC 7230"));
    }

    /// **A credential needs TLS or loopback**, the same rule a secret meets.
    #[test]
    fn a_vault_without_tls_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("key");
        std::fs::write(&path, "real").expect("write");
        let opened = credentials::Vault::open(
            credentials::VaultConfig::new(credentials::Backend::local(), "t").route(
                credentials::RouteSpec::opaque(
                    credentials::DestinationPattern::parse("vendor.example").expect("pattern"),
                    credentials::Locator::parse_uri(&format!("file://{}", path.display()))
                        .expect("locator"),
                    credentials::InjectMode::header("Bearer {}", None).expect("mode"),
                ),
            ),
        )
        .expect("open");
        let refusal = TelemetryConfig::for_box("b")
            .with_target(
                Target::new(TargetKind::Otlp, "http://vendor.example")
                    .with_vault(std::sync::Arc::new(opened.into_vault())),
            )
            .validate()
            .expect_err("a credential over plaintext is refused");
        assert!(refusal.to_string().contains("https"), "{refusal}");
    }

    /// No rendering of a secret carries its value.
    #[test]
    fn a_secret_never_prints_its_value() {
        let secret = TargetSecret::new("x-honeycomb-team", "vendor-key");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("vendor-key"), "{rendered}");
        assert!(rendered.contains("x-honeycomb-team"));
    }
}
