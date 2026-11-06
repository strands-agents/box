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
}

/// Every target one box declares.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    box_name: String,
    targets: Vec<Target>,
    resource_attributes: String,
}

impl TelemetryConfig {
    /// A config for the box named `box_name`, with no target yet.
    #[must_use]
    pub fn for_box(box_name: impl Into<String>) -> Self {
        Self {
            box_name: box_name.into(),
            targets: Vec::new(),
            resource_attributes: String::new(),
        }
    }

    /// Add a declared target.
    #[must_use]
    pub fn with_target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    /// Add the operator's resource attributes, in `OTEL_RESOURCE_ATTRIBUTES` syntax.
    #[must_use]
    pub fn with_resource_attributes(mut self, text: impl Into<String>) -> Self {
        self.resource_attributes = text.into();
        self
    }

    pub(crate) fn box_name(&self) -> &str {
        &self.box_name
    }

    pub(crate) fn targets(&self) -> &[Target] {
        &self.targets
    }

    pub(crate) fn resource_attributes(&self) -> Result<Vec<(String, String)>> {
        parsed_resource_attributes(&self.resource_attributes)
    }

    /// Refuse a config no run could honour. The one owner of every rule about a target.
    pub fn validate(&self) -> Result<()> {
        if self.box_name.is_empty() {
            return Err(TelemetryError::Config {
                reason: "the box name is empty".to_string(),
            });
        }
        self.resource_attributes()?;
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
        }
        Ok(())
    }
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

/// The most bytes `OTEL_RESOURCE_ATTRIBUTES` may hold, because every relayed resource carries it.
const RESOURCE_ATTRIBUTES_LIMIT: usize = 1024;

/// The operator's resource attributes, in order, or the refusal for the first bad entry.
fn parsed_resource_attributes(text: &str) -> Result<Vec<(String, String)>> {
    let refuse = |entry: &str, why: &str| TelemetryError::Config {
        reason: format!("OTEL_RESOURCE_ATTRIBUTES entry {entry:?} {why}"),
    };
    if text.len() > RESOURCE_ATTRIBUTES_LIMIT {
        return Err(TelemetryError::Config {
            reason: format!(
                "OTEL_RESOURCE_ATTRIBUTES is {} bytes; write at most {RESOURCE_ATTRIBUTES_LIMIT}",
                text.len()
            ),
        });
    }
    let mut parsed: Vec<(String, String)> = Vec::new();
    for entry in text
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(refuse(entry, "has no `=`; write key=value"));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(refuse(entry, "has an empty key"));
        }
        if key == "service.name" || key.starts_with(crate::export::RESERVED_PREFIX) {
            return Err(refuse(
                entry,
                "names a reserved key; the box writes `service.name` and every `strands.box.` key itself",
            ));
        }
        if parsed.iter().any(|(seen, _)| seen == key) {
            return Err(TelemetryError::Config {
                reason: format!("OTEL_RESOURCE_ATTRIBUTES names the key {key:?} twice"),
            });
        }
        let Some(value) = percent_decoded(value.trim()) else {
            return Err(refuse(
                entry,
                "has an invalid percent escape or a value that is not UTF-8",
            ));
        };
        parsed.push((key.to_string(), value));
    }
    Ok(parsed)
}

/// `text` with each `%XX` decoded, or `None` for a bad escape or bytes that are not UTF-8.
fn percent_decoded(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let hex = std::str::from_utf8(hex).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
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

    /// No rendering of a secret carries its value.
    #[test]
    fn a_secret_never_prints_its_value() {
        let secret = TargetSecret::new("x-honeycomb-team", "vendor-key");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("vendor-key"), "{rendered}");
        assert!(rendered.contains("x-honeycomb-team"));
    }

    fn attributes(text: &str) -> Result<Vec<(String, String)>> {
        TelemetryConfig::for_box("b")
            .with_resource_attributes(text)
            .resource_attributes()
    }

    fn refusal(text: &str) -> String {
        let refused = TelemetryConfig::for_box("b")
            .with_resource_attributes(text)
            .validate()
            .expect_err("this value must refuse");
        refused.to_string()
    }

    #[test]
    fn operator_resource_attributes_parse_and_percent_decode() {
        let parsed = attributes(" tenant.id = acme ,conversation.id=c%2C42,token=a=b").unwrap();
        assert_eq!(
            parsed,
            vec![
                ("tenant.id".to_string(), "acme".to_string()),
                ("conversation.id".to_string(), "c,42".to_string()),
                ("token".to_string(), "a=b".to_string()),
            ]
        );
    }

    #[test]
    fn an_unset_or_empty_value_adds_no_attribute() {
        assert!(
            TelemetryConfig::for_box("b")
                .resource_attributes()
                .unwrap()
                .is_empty()
        );
        assert!(attributes("").unwrap().is_empty());
        assert!(attributes("   ").unwrap().is_empty());
    }

    #[test]
    fn a_blank_segment_is_ignored() {
        assert_eq!(
            attributes("a=1,,b=2,").unwrap(),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
    }

    #[test]
    fn a_malformed_operator_attribute_refuses() {
        for (text, entry) in [("tenant", "tenant"), ("a=1,=2", "=2")] {
            let reason = refusal(text);
            assert!(reason.contains("OTEL_RESOURCE_ATTRIBUTES"), "{reason}");
            assert!(reason.contains(&format!("{entry:?}")), "{reason}");
        }
    }

    #[test]
    fn a_repeated_operator_attribute_refuses() {
        let reason = refusal("a=1,a=2");
        assert!(
            reason.contains("\"a\"") && reason.contains("twice"),
            "{reason}"
        );
    }

    #[test]
    fn a_reserved_operator_attribute_refuses() {
        for text in [
            "service.name=x",
            "strands.box.name=x",
            "strands.box.policy.verdict=permit",
        ] {
            let reason = refusal(text);
            assert!(reason.contains(&format!("{text:?}")), "{reason}");
            assert!(reason.contains("reserved"), "{reason}");
        }
    }

    #[test]
    fn an_invalid_percent_escape_refuses() {
        for text in ["a=%", "a=%4", "a=%zz", "a=%ff", "a=%+f"] {
            let reason = refusal(text);
            assert!(reason.contains("percent"), "{text}: {reason}");
        }
    }

    #[test]
    fn an_operator_attribute_value_over_the_bound_refuses() {
        let at_the_bound = format!("a={}", "x".repeat(RESOURCE_ATTRIBUTES_LIMIT - 2));
        assert_eq!(attributes(&at_the_bound).unwrap().len(), 1);
        let reason = refusal(&format!("{at_the_bound}y"));
        assert!(reason.contains("OTEL_RESOURCE_ATTRIBUTES"), "{reason}");
        assert!(reason.contains("1024"), "{reason}");
    }
}
