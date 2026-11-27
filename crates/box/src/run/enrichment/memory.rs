//! The `in-memory` classification source, which answers from a table and counts each question.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use serde::Deserialize;

use super::{Classification, Confidence, Source};

/// How long an answer holds when a fixture names no `ttl`, in seconds.
const DEFAULT_TTL: u64 = 300;

/// The longest a stalled name holds its question before the source answers it anyway.
const STALL_LIMIT: Duration = Duration::from_secs(10);

/// A source that answers from a table: a listed name with its labels, a listed name with no
/// answer, and any other name with no label.
pub(crate) struct InMemorySource {
    answers: BTreeMap<String, Option<Vec<(String, Confidence)>>>,
    ttl: Duration,
    calls: AtomicUsize,
    /// The names whose question waits until the source is released, for at most [`STALL_LIMIT`].
    stalled: BTreeSet<String>,
    released: (Mutex<bool>, Condvar),
}

impl InMemorySource {
    /// A source that answers every name with no label, each answer holding for `ttl`.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            answers: BTreeMap::new(),
            ttl,
            calls: AtomicUsize::new(0),
            stalled: BTreeSet::new(),
            released: (Mutex::new(false), Condvar::new()),
        }
    }

    /// This source, answering `host` with `label` at `confidence` too.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn labelling(mut self, host: &str, label: &str, confidence: Confidence) -> Self {
        if let Some(labels) = self
            .answers
            .entry(host.to_string())
            .or_insert_with(|| Some(Vec::new()))
        {
            labels.push((label.to_string(), confidence));
        }
        self
    }

    /// This source, giving no answer about `host`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn unanswering(mut self, host: &str) -> Self {
        self.answers.insert(host.to_string(), None);
        self
    }

    /// This source, holding each question about `host` until [`Self::release`].
    #[cfg(test)]
    #[must_use]
    pub(crate) fn stalling(mut self, host: &str) -> Self {
        self.stalled.insert(host.to_string());
        self
    }

    /// Let every held question go.
    #[cfg(test)]
    pub(crate) fn release(&self) {
        let (released, wake) = &self.released;
        if let Ok(mut released) = released.lock() {
            *released = true;
        }
        wake.notify_all();
    }

    /// How many times Box asked this source.
    #[cfg(test)]
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The source a fixture describes, such as
    /// `{"ttl": 300, "hosts": {"evil.example": {"malware": "high"}, "slow.invalid": null}}`.
    pub(crate) fn from_json(text: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fixture {
            #[serde(default = "default_ttl")]
            ttl: u64,
            #[serde(default)]
            hosts: BTreeMap<String, Option<BTreeMap<String, Sureness>>>,
        }
        /// A label's confidence as a fixture spells it, in lowercase.
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Sureness {
            Low,
            Medium,
            High,
        }
        impl From<Sureness> for Confidence {
            fn from(sureness: Sureness) -> Self {
                match sureness {
                    Sureness::Low => Self::Low,
                    Sureness::Medium => Self::Medium,
                    Sureness::High => Self::High,
                }
            }
        }
        fn default_ttl() -> u64 {
            DEFAULT_TTL
        }
        let fixture: Fixture = serde_json::from_str(text)
            .map_err(|error| format!("its in-memory fixture is not valid: {error}"))?;
        let mut source = Self::new(Duration::from_secs(fixture.ttl));
        for (host, labels) in fixture.hosts {
            let name = super::dns_name(&host).unwrap_or(host);
            source.answers.insert(
                name,
                labels.map(|labels| {
                    labels
                        .into_iter()
                        .map(|(label, sureness)| (label, sureness.into()))
                        .collect()
                }),
            );
        }
        Ok(source)
    }
}

impl Source for InMemorySource {
    fn classify(
        &self,
        host: &str,
        _outputs: &[String],
        _timeout: Duration,
    ) -> Option<Classification> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stalled.contains(host) {
            let (released, wake) = &self.released;
            if let Ok(held) = released.lock() {
                let _ = wake.wait_timeout_while(held, STALL_LIMIT, |released| !*released);
            }
        }
        let labels = match self.answers.get(host) {
            Some(None) => return None,
            Some(Some(labels)) => labels.clone(),
            None => Vec::new(),
        };
        Some(Classification {
            labels,
            ttl: self.ttl,
        })
    }
}

/// The absolute path a `file://` endpoint names.
pub(crate) fn fixture_path(endpoint: &str) -> Result<PathBuf, String> {
    const REFUSAL: &str = "endpoint must be a file:// URL to an absolute path holding the \
                           in-memory fixture, such as file:///srv/fixture.json";
    let url = url::Url::parse(endpoint).map_err(|_| REFUSAL.to_string())?;
    if url.scheme() != "file" || url.query().is_some() || url.fragment().is_some() {
        return Err(REFUSAL.to_string());
    }
    url.to_file_path().map_err(|()| REFUSAL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixture_lists_labels_and_missing_answers() {
        let source = InMemorySource::from_json(
            r#"{"hosts": {"Evil.Example.": {"malware": "high"}, "slow.invalid": null}}"#,
        )
        .expect("the fixture parses");
        let evil = source
            .classify("evil.example", &[], Duration::ZERO)
            .expect("an answer");
        assert_eq!(evil.labels, [("malware".to_string(), Confidence::High)]);
        assert_eq!(evil.ttl, Duration::from_secs(DEFAULT_TTL));
        assert!(
            source
                .classify("slow.invalid", &[], Duration::ZERO)
                .is_none()
        );
        assert!(
            source
                .classify("clean.example", &[], Duration::ZERO)
                .is_some_and(|answer| answer.labels.is_empty())
        );
        assert!(fixture_path("https://example.invalid/fixture.json").is_err());
        // A non-special scheme with an absolute path names a file path too, so only the scheme
        // check refuses it.
        assert!(fixture_path("x-fixture:///srv/fixture.json").is_err());
        assert!(fixture_path("file:///srv/fixture.json?token=x").is_err());
        assert_eq!(
            fixture_path("file:///srv/fixture.json").ok(),
            Some(PathBuf::from("/srv/fixture.json"))
        );
    }
}
