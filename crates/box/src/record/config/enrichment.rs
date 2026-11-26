//! `[enrichment.<name>]`: the outside classification sources Box asks about each DNS name the
//! workload connects to.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use policy::EnrichmentNames;
use serde::{Deserialize, Serialize};

use super::secret_source::DeclaredSources;
use crate::error::ConfigError;
use crate::run::enrichment::Confidence;

/// The most labels one source may give.
const MAXIMUM_OUTPUTS: usize = 64;

/// One classification source, as `[enrichment.<name>]` declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrichmentEntry {
    /// The source kind, which must be one this build implements.
    pub(crate) kind: String,
    /// Where the source answers, as its kind reads it.
    pub(crate) endpoint: String,
    /// The secret the source needs, named as an `[egress.<name>]` `secret.ref` names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<EnrichmentSecret>,
    /// The labels the source may give; no other label reaches policy.
    pub(crate) outputs: Vec<String>,
    /// The least confidence of a label that reaches policy.
    pub(crate) min_confidence: Confidence,
    /// How long Box waits for an answer.
    #[serde(default)]
    pub(crate) timeout: Timeout,
    /// How long Box keeps an answer at most.
    #[serde(default)]
    pub(crate) max_age: MaxAge,
}

/// The secret one classification source reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrichmentSecret {
    /// The secret's reference, such as `env://NAME`.
    #[serde(rename = "ref")]
    pub(crate) reference: String,
}

/// How long Box waits for a source's answer: `"500ms"` unless the table says, from 1ms to 10s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeout(pub(crate) Duration);

/// How long Box keeps a source's answer at most: `"300s"` unless the table says, from 1s to 24h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaxAge(pub(crate) Duration);

impl Default for Timeout {
    fn default() -> Self {
        Self(Duration::from_millis(500))
    }
}

impl Default for MaxAge {
    fn default() -> Self {
        Self(Duration::from_secs(300))
    }
}

/// The key, bounds, and example of one duration key.
struct Span {
    key: &'static str,
    least: Duration,
    most: Duration,
    example: &'static str,
}

static TIMEOUT: Span = Span {
    key: "timeout",
    least: Duration::from_millis(1),
    most: Duration::from_secs(10),
    example: "500ms",
};

static MAX_AGE: Span = Span {
    key: "max_age",
    least: Duration::from_secs(1),
    most: Duration::from_secs(24 * 3600),
    example: "300s",
};

impl Span {
    /// `text` as a duration within these bounds, or the refusal that names the key.
    fn parse(&self, text: &str) -> Result<Duration, String> {
        let digits = text.trim_end_matches(|character: char| character.is_ascii_alphabetic());
        let unit = &text[digits.len()..];
        let count = (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| digits.parse::<u64>().ok())
            .flatten();
        let spelled = count.and_then(|count| match unit {
            "ms" => Some(Duration::from_millis(count)),
            "s" => Some(Duration::from_secs(count)),
            "m" => count.checked_mul(60).map(Duration::from_secs),
            "h" => count.checked_mul(3600).map(Duration::from_secs),
            _ => None,
        });
        match spelled {
            Some(duration) if duration >= self.least && duration <= self.most => Ok(duration),
            _ => Err(self.refusal(&format!("{text:?}"))),
        }
    }

    fn refusal(&self, found: &str) -> String {
        format!(
            "{} must be a whole number followed by ms, s, m, or h, from {} to {}, such as {:?}; \
             found {found}",
            self.key,
            spelled(self.least),
            spelled(self.most),
            self.example
        )
    }

    fn deserialize<'de, D: serde::Deserializer<'de>>(
        &'static self,
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        struct Visitor(&'static Span);
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Duration;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "{} as a whole number and a unit", self.0.key)
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Duration, E> {
                self.0.parse(text).map_err(E::custom)
            }

            fn visit_i64<E: serde::de::Error>(self, number: i64) -> Result<Duration, E> {
                Err(E::custom(
                    self.0.refusal(&format!("the bare number {number}")),
                ))
            }

            fn visit_u64<E: serde::de::Error>(self, number: u64) -> Result<Duration, E> {
                Err(E::custom(
                    self.0.refusal(&format!("the bare number {number}")),
                ))
            }

            fn visit_f64<E: serde::de::Error>(self, number: f64) -> Result<Duration, E> {
                Err(E::custom(
                    self.0.refusal(&format!("the bare number {number}")),
                ))
            }
        }
        deserializer.deserialize_any(Visitor(self))
    }
}

/// `duration` in the largest unit that spells it whole.
fn spelled(duration: Duration) -> String {
    let milliseconds = duration.as_millis();
    if milliseconds.is_multiple_of(3_600_000) {
        format!("{}h", milliseconds / 3_600_000)
    } else if milliseconds.is_multiple_of(60_000) {
        format!("{}m", milliseconds / 60_000)
    } else if milliseconds.is_multiple_of(1_000) {
        format!("{}s", milliseconds / 1_000)
    } else {
        format!("{milliseconds}ms")
    }
}

impl<'de> Deserialize<'de> for Timeout {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        TIMEOUT.deserialize(deserializer).map(Self)
    }
}

impl<'de> Deserialize<'de> for MaxAge {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        MAX_AGE.deserialize(deserializer).map(Self)
    }
}

impl Serialize for Timeout {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&spelled(self.0))
    }
}

impl Serialize for MaxAge {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&spelled(self.0))
    }
}

/// The validated names of `entries`.
pub(crate) fn names(
    entries: &BTreeMap<String, EnrichmentEntry>,
) -> Result<EnrichmentNames, ConfigError> {
    EnrichmentNames::new(entries.keys().cloned()).map_err(|error| ConfigError::Enrichment {
        name: error.name().to_string(),
        reason: error.to_string(),
    })
}

/// Refuse an entry no run could honor, and return the validated names.
pub(super) fn validate(
    entries: &BTreeMap<String, EnrichmentEntry>,
    sources: &DeclaredSources,
) -> Result<EnrichmentNames, ConfigError> {
    let names = names(entries)?;
    for (name, entry) in entries {
        let refuse = |reason: String| ConfigError::Enrichment {
            name: name.clone(),
            reason,
        };
        crate::run::enrichment::kinds::check(&entry.kind, &entry.endpoint).map_err(refuse)?;
        if let Some(secret) = &entry.secret {
            super::egress::validate_reference(
                &secret.reference,
                &format!("[enrichment.{name}]"),
                sources,
            )
            .map_err(|error| match error {
                ConfigError::Credential { reason, .. } => refuse(format!("secret.ref: {reason}")),
                other => other,
            })?;
        }
        if entry.outputs.is_empty() || entry.outputs.len() > MAXIMUM_OUTPUTS {
            return Err(refuse(format!(
                "outputs names {} labels; name from 1 to {MAXIMUM_OUTPUTS}, the labels a rule \
                 reads",
                entry.outputs.len()
            )));
        }
        let mut seen = BTreeSet::new();
        if let Some(label) = entry
            .outputs
            .iter()
            .find(|label| label.is_empty() || !seen.insert(label.as_str()))
        {
            return Err(refuse(format!(
                "outputs names {label:?} more than once or names an empty label"
            )));
        }
    }
    Ok(names)
}

/// Each test that loads `kind = "in-memory"` needs a `test-support` build, which implements it.
#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::ConfigFile;
    use crate::error::ConfigError;

    const TABLE: &str = "[enrichment.threat]\nkind = \"in-memory\"\n\
                         endpoint = \"file:///srv/fixture.json\"\noutputs = [\"malware\"]\n\
                         min_confidence = \"HIGH\"\n";

    fn parsed(extra: &str) -> Result<ConfigFile, ConfigError> {
        ConfigFile::parse(
            &format!("name = \"test\"\nbox_dir = \"/var/lib/box\"\n{extra}"),
            Path::new("box.toml"),
        )
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn an_unknown_key_in_the_table_or_its_secret_is_refused() {
        parsed(TABLE).expect("the table loads");
        for extra in [
            format!("{TABLE}colour = \"red\"\n"),
            format!("{TABLE}secret.ref = \"env://TOKEN\"\nsecret.env = \"TOKEN\"\n"),
        ] {
            assert!(
                matches!(parsed(&extra), Err(ConfigError::Parse { .. })),
                "{extra}"
            );
        }
    }

    /// A duration is a whole number and a unit within its key's bounds; anything else is refused
    /// by the key's name.
    #[cfg(feature = "test-support")]
    #[test]
    fn a_duration_is_a_whole_number_and_a_unit_within_its_bounds() {
        let entry = |extra: &str| -> Result<super::EnrichmentEntry, ConfigError> {
            parsed(&format!("{TABLE}{extra}")).map(|config| config.enrichment["threat"].clone())
        };
        let defaults = entry("").expect("the defaults load");
        assert_eq!(defaults.timeout.0, std::time::Duration::from_millis(500));
        assert_eq!(defaults.max_age.0, std::time::Duration::from_secs(300));
        let spelled = entry("timeout = \"10s\"\nmax_age = \"24h\"\n").expect("the bounds load");
        assert_eq!(spelled.timeout.0, std::time::Duration::from_secs(10));
        assert_eq!(spelled.max_age.0, std::time::Duration::from_secs(86_400));
        assert_eq!(
            entry("timeout = \"1ms\"\nmax_age = \"2m\"\n")
                .map(|entry| (entry.timeout.0, entry.max_age.0))
                .ok(),
            Some((
                std::time::Duration::from_millis(1),
                std::time::Duration::from_secs(120)
            ))
        );
        for (extra, key) in [
            ("timeout = \"1.5s\"\n", "timeout"),
            ("timeout = \"0ms\"\n", "timeout"),
            ("timeout = \"500\"\n", "timeout"),
            ("timeout = 500\n", "timeout"),
            ("timeout = \"5d\"\n", "timeout"),
            ("timeout = \"11s\"\n", "timeout"),
            ("max_age = \"500ms\"\n", "max_age"),
            ("max_age = \"25h\"\n", "max_age"),
            ("max_age = \"-5s\"\n", "max_age"),
        ] {
            let error = entry(extra).expect_err("the duration is refused");
            assert!(
                error.to_string().contains(&format!(
                    "{key} must be a whole number followed by ms, s, m, or h"
                )),
                "{extra}: {error}"
            );
        }
    }

    /// The least confidence is spelled in uppercase.
    #[cfg(feature = "test-support")]
    #[test]
    fn min_confidence_is_uppercase() {
        assert!(parsed(&TABLE.replace("\"HIGH\"", "\"LOW\"")).is_ok());
        assert!(matches!(
            parsed(&TABLE.replace("\"HIGH\"", "\"high\"")),
            Err(ConfigError::Parse { .. })
        ));
    }

    /// A release build implements no kind, so it refuses the test kind like any other.
    #[cfg(not(feature = "test-support"))]
    #[test]
    fn a_release_build_refuses_the_in_memory_kind() {
        let error = parsed(TABLE).expect_err("kind in-memory is refused");
        assert_eq!(
            error.to_string(),
            "`[enrichment.threat]` names kind \"in-memory\", which this build of Box does not \
             implement; this build implements no enrichment kind"
        );
    }

    #[test]
    fn a_kind_this_build_does_not_implement_is_refused_by_name() {
        let error = parsed(&TABLE.replace("in-memory", "x")).expect_err("kind x is refused");
        assert!(
            error.to_string().starts_with(
                "`[enrichment.threat]` names kind \"x\", which this build of Box does not \
                 implement; this build implements"
            ),
            "{error}"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn a_table_no_run_could_honor_is_refused() {
        let outputs = |count: usize| {
            let labels: Vec<String> = (0..count).map(|label| format!("\"l{label}\"")).collect();
            TABLE.replace("[\"malware\"]", &format!("[{}]", labels.join(", ")))
        };
        parsed(&outputs(super::MAXIMUM_OUTPUTS)).expect("64 outputs load");
        for (extra, says) in [
            (TABLE.replace("threat", "Threat"), "[enrichment.Threat]"),
            (TABLE.replace("[\"malware\"]", "[]"), "outputs"),
            (
                outputs(super::MAXIMUM_OUTPUTS + 1),
                "outputs names 65 labels",
            ),
            (
                TABLE.replace("[\"malware\"]", "[\"malware\", \"malware\"]"),
                "more than once",
            ),
            (TABLE.replace("[\"malware\"]", "[\"\"]"), "an empty label"),
            (
                TABLE.replace("file:///srv/fixture.json", "https://example.invalid/"),
                "file:// URL",
            ),
            (format!("{TABLE}secret.ref = \"plain\"\n"), "secret.ref"),
        ] {
            let error = parsed(&extra).expect_err("the table is refused");
            assert!(
                matches!(error, ConfigError::Enrichment { .. }) && error.to_string().contains(says),
                "{extra}: {error}"
            );
        }
    }

    /// Configure refuses, as `B0103`, a policy that reads an entry's labels and no answer.
    #[cfg(feature = "test-support")]
    #[test]
    fn configure_refuses_labels_read_without_the_answer() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("policy.dw");
        std::fs::write(
            &path,
            r#"permit (principal, action == Box::Action::"net:connect", resource);
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.labels.contains("malware") };"#,
        )
        .expect("the policy writes");
        let config = parsed(TABLE).expect("the table loads");

        let error = super::super::read_authored_policy(
            Some(&path),
            true,
            &policy::Operator::unanchored(),
            &policy::ToolGrammars::default(),
            &super::names(&config.enrichment).expect("the names are valid"),
        )
        .expect_err("the policy is refused");
        assert_eq!(error.code(), ::diagnostics::Code::B0103.into());
        assert!(
            error
                .to_string()
                .contains("no rule reads context.input.enrichment.threat.answered"),
            "{error}"
        );
    }
}
