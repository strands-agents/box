//! DNS-name enrichment: the classification sources a box asks, the cache in front of each, and
//! the enricher the egress adapter reads before policy decides a `net:connect`.
//!
//! | Module | Owns |
//! |---|---|
//! | [`kinds`] | the source kinds this build implements, and how each checks and opens its endpoint |
//! | `memory` | the `in-memory` test source, which only a `test-support` build implements |

pub(crate) mod kinds;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod memory;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use policy::{EnrichmentAnswer, EnrichmentFacts, HostEnricher};
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::record::config::enrichment::EnrichmentEntry;

/// How sure a source is of one label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

/// What a source answered about one DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classification {
    /// Each label the source gave, with how sure it is.
    pub(crate) labels: Vec<(String, Confidence)>,
    /// How long the source says its answer holds.
    pub(crate) ttl: Duration,
}

/// An outside classification source that Box asks about one DNS name.
pub(crate) trait Source: Send + Sync {
    /// What the source says about `host` among `outputs`, or `None` for no answer in `timeout`.
    fn classify(&self, host: &str, outputs: &[String], timeout: Duration)
    -> Option<Classification>;
}

/// How many names one entry keeps, because the workload chooses the names.
const CACHE_CAPACITY: usize = 4096;

/// How many questions to one entry's source may wait at once, so a stalled source holds at most
/// this many threads.
const IN_FLIGHT_CAPACITY: usize = 64;

/// The enricher of one box: each declared entry, in name order.
pub(crate) struct Enricher {
    entries: Vec<Entry>,
}

impl Enricher {
    /// Open the source of each entry in `declared` that a rule names in `read`.
    pub(crate) fn open(
        declared: &BTreeMap<String, EnrichmentEntry>,
        read: &BTreeSet<String>,
    ) -> Result<Self, ConfigError> {
        Self::opening(declared, read, |entry| {
            kinds::open(&entry.kind, &entry.endpoint)
        })
    }

    /// [`Self::open`], with `open` opening each read entry's source.
    pub(crate) fn opening(
        declared: &BTreeMap<String, EnrichmentEntry>,
        read: &BTreeSet<String>,
        open: impl Fn(&EnrichmentEntry) -> Result<Arc<dyn Source>, String>,
    ) -> Result<Self, ConfigError> {
        let entries = declared
            .iter()
            .map(|(name, entry)| {
                let source = if read.contains(name) {
                    Some(open(entry).map_err(|reason| ConfigError::Enrichment {
                        name: name.clone(),
                        reason,
                    })?)
                } else {
                    None
                };
                Ok(Entry::new(name, entry, source))
            })
            .collect::<Result<_, ConfigError>>()?;
        Ok(Self { entries })
    }
}

impl HostEnricher for Enricher {
    /// Each entry's answer about `host`, asking its source on a cache miss.
    fn enrich(&self, host: &str) -> EnrichmentFacts {
        let name = dns_name(host);
        let now = Instant::now();
        returned(
            self.entries
                .iter()
                .map(|entry| (entry.name.clone(), entry.answer(name.as_deref(), now)))
                .collect(),
        )
    }
}

/// One declared entry, with its source when a rule reads it.
struct Entry {
    name: String,
    source: Option<Arc<dyn Source>>,
    outputs: Vec<String>,
    min_confidence: Confidence,
    timeout: Duration,
    max_age: Duration,
    cache: Mutex<Cache>,
    /// How many questions to the source wait for an answer now.
    in_flight: Arc<AtomicUsize>,
}

impl Entry {
    fn new(name: &str, entry: &EnrichmentEntry, source: Option<Arc<dyn Source>>) -> Self {
        Self {
            name: name.to_string(),
            source,
            outputs: entry.outputs.clone(),
            min_confidence: entry.min_confidence,
            timeout: entry.timeout,
            max_age: entry.max_age,
            cache: Mutex::new(Cache::new(CACHE_CAPACITY)),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// This entry's answer about the DNS name `name`: the cached one while it holds, else the
    /// source's. A missing answer is not kept, so the next host decision asks again.
    fn answer(&self, name: Option<&str>, now: Instant) -> EnrichmentAnswer {
        let (Some(source), Some(name)) = (&self.source, name) else {
            return EnrichmentAnswer::unanswered();
        };
        if let Some(answer) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(name, now))
        {
            return answer;
        }
        let Some(classification) = self.classify(source, name) else {
            return EnrichmentAnswer::unanswered();
        };
        let answer = EnrichmentAnswer::answered(self.kept(classification.labels));
        if let Ok(mut cache) = self.cache.lock() {
            let expires = now + classification.ttl.min(self.max_age);
            cache.insert(name, answer.clone(), expires, now);
        }
        answer
    }

    /// What `source` says about `name` within `timeout`, asked on a thread of its own so a stalled
    /// source holds no decision longer, and not asked while [`IN_FLIGHT_CAPACITY`] questions wait.
    fn classify(&self, source: &Arc<dyn Source>, name: &str) -> Option<Classification> {
        let slot = Slot::claim(&self.in_flight)?;
        let (answered, answer) = mpsc::sync_channel(1);
        let source = Arc::clone(source);
        let (name, outputs, timeout) = (name.to_string(), self.outputs.clone(), self.timeout);
        std::thread::Builder::new()
            .name(format!("enrichment-{}", self.name))
            .spawn(move || {
                let _slot = slot;
                let _ = answered.send(source.classify(&name, &outputs, timeout));
            })
            .ok()?;
        answer.recv_timeout(self.timeout).ok().flatten()
    }

    /// The labels that reach policy: those in `outputs` at `min_confidence` or above.
    fn kept(&self, labels: Vec<(String, Confidence)>) -> BTreeSet<String> {
        labels
            .into_iter()
            .filter(|(label, confidence)| {
                *confidence >= self.min_confidence && self.outputs.contains(label)
            })
            .map(|(label, _)| label)
            .collect()
    }
}

/// One question waiting on a source, counted against [`IN_FLIGHT_CAPACITY`] until it drops.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// A slot of `in_flight`, or none when [`IN_FLIGHT_CAPACITY`] questions already wait.
    fn claim(in_flight: &Arc<AtomicUsize>) -> Option<Self> {
        in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiting| {
                (waiting < IN_FLIGHT_CAPACITY).then_some(waiting + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(in_flight)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The answers of one entry by DNS name, each with when it expires.
struct Cache {
    capacity: usize,
    answers: BTreeMap<String, (EnrichmentAnswer, Instant)>,
}

impl Cache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            answers: BTreeMap::new(),
        }
    }

    fn get(&self, name: &str, now: Instant) -> Option<EnrichmentAnswer> {
        self.answers
            .get(name)
            .filter(|(_, expires)| *expires > now)
            .map(|(answer, _)| answer.clone())
    }

    /// Keep `answer` until `expires`; when full, drop the expired names, then the one that
    /// expires first.
    fn insert(&mut self, name: &str, answer: EnrichmentAnswer, expires: Instant, now: Instant) {
        if !self.answers.contains_key(name) && self.answers.len() >= self.capacity {
            self.answers.retain(|_, (_, at)| *at > now);
            if self.answers.len() >= self.capacity
                && let Some(first) = self
                    .answers
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(kept, _)| kept.clone())
            {
                self.answers.remove(&first);
            }
        }
        self.answers.insert(name.to_string(), (answer, expires));
    }
}

/// The DNS name Box asks about for `host`: ASCII lowercase with one trailing `.` removed, or
/// `None` for an address, which is not a DNS name.
pub(crate) fn dns_name(host: &str) -> Option<String> {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return None;
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    (!name.is_empty() && !crate::record::config::ends_in_a_number(&name)).then_some(name)
}

thread_local! {
    /// The facts this thread's enricher last returned, while a [`FactsCapture`] is open.
    static RETURNED: RefCell<Option<EnrichmentFacts>> = const { RefCell::new(None) };
}

/// Keep `facts` for this thread's open [`FactsCapture`], and return them.
fn returned(facts: EnrichmentFacts) -> EnrichmentFacts {
    RETURNED.with(|returned| {
        if let Some(slot) = returned.borrow_mut().as_mut() {
            slot.clone_from(&facts);
        }
    });
    facts
}

/// Keep the facts the enricher returns on this thread until they are read.
pub(crate) struct FactsCapture(());

impl FactsCapture {
    pub(crate) fn begin() -> Self {
        RETURNED.with(|returned| *returned.borrow_mut() = Some(EnrichmentFacts::NONE));
        Self(())
    }

    /// The facts the enricher last returned since `begin`, or none.
    pub(crate) fn finish(self) -> EnrichmentFacts {
        RETURNED.with(|returned| returned.borrow_mut().take().unwrap_or_default())
    }
}

impl Drop for FactsCapture {
    fn drop(&mut self) {
        RETURNED.with(|returned| *returned.borrow_mut() = None);
    }
}

#[cfg(test)]
mod tests {
    use super::memory::InMemorySource;
    use super::*;
    use crate::test_support::{enrichment_entry as entry, enrichment_interceptor as interceptor};

    /// An enricher whose one `threat` entry asks `source` when `read`.
    fn enricher(declared: EnrichmentEntry, source: &Arc<InMemorySource>, read: bool) -> Enricher {
        let declared = BTreeMap::from([("threat".to_string(), declared)]);
        let read = if read {
            BTreeSet::from(["threat".to_string()])
        } else {
            BTreeSet::new()
        };
        Enricher::opening(&declared, &read, |_| {
            Ok(Arc::clone(source) as Arc<dyn Source>)
        })
        .expect("the enricher opens")
    }

    fn threat(enricher: &Enricher, host: &str) -> EnrichmentAnswer {
        entry_of(&enricher.enrich(host))
    }

    fn entry_of(facts: &EnrichmentFacts) -> EnrichmentAnswer {
        facts
            .iter()
            .find(|(name, _)| *name == "threat")
            .map(|(_, answer)| answer.clone())
            .expect("the threat entry answers")
    }

    /// Only a label in `outputs` at `min_confidence` or above reaches policy, whatever spelling of
    /// the name the workload dials, and a second connection to one name asks the source once.
    #[test]
    fn the_source_is_asked_once_per_name_and_only_declared_confident_labels_pass() {
        let source = Arc::new(
            InMemorySource::new(Duration::from_secs(300))
                .labelling("evil.example", "malware", Confidence::High)
                .labelling("evil.example", "phishing", Confidence::Low)
                .labelling("evil.example", "undeclared", Confidence::High),
        );
        let enricher = enricher(
            entry(&["malware", "phishing"], Confidence::Medium),
            &source,
            true,
        );

        let answer = threat(&enricher, "evil.example");
        assert!(answer.is_answered());
        assert_eq!(
            answer.labels().iter().collect::<Vec<_>>(),
            ["malware"],
            "a low-confidence and an undeclared label are dropped"
        );
        for spelling in ["EVIL.example", "evil.example."] {
            assert_eq!(threat(&enricher, spelling), answer, "{spelling}");
        }
        assert_eq!(source.calls(), 1, "every spelling is one cached name");
    }

    /// A missing answer is not kept, so the next host decision asks again.
    #[test]
    fn a_missing_answer_is_asked_again() {
        let source =
            Arc::new(InMemorySource::new(Duration::from_secs(300)).unanswering("slow.invalid"));
        let enricher = enricher(entry(&["malware"], Confidence::Low), &source, true);

        assert!(!threat(&enricher, "slow.invalid").is_answered());
        assert_eq!(source.calls(), 1);
        assert!(!threat(&enricher, "slow.invalid").is_answered());
        assert_eq!(source.calls(), 2, "the next host decision asks again");
    }

    /// An entry no rule reads opens no source, so Box sends it no name and its fact is unanswered.
    #[test]
    fn an_unread_entry_asks_nothing() {
        let source = Arc::new(InMemorySource::new(Duration::from_secs(300)).labelling(
            "evil.example",
            "malware",
            Confidence::High,
        ));
        let enricher = enricher(entry(&["malware"], Confidence::Low), &source, false);

        assert!(!threat(&enricher, "evil.example").is_answered());
        assert_eq!(source.calls(), 0);
    }

    /// An IP-literal host is not a DNS name: through the egress adapter no source is asked, the
    /// entry reads unanswered, and only a rule that names the address lets it through.
    #[test]
    fn an_address_is_never_asked_and_only_a_named_one_passes() {
        let source = Arc::new(InMemorySource::new(Duration::from_secs(300)));
        let (interceptor, _history) = interceptor(
            r#"
permit (principal, action == Box::Action::"net:connect", resource);
forbid (principal, action == Box::Action::"net:connect", resource)
unless { context.input.enrichment.threat.answered || context.input.host == "203.0.113.7" };
"#,
            &source,
        );
        let resolve = |host| egress_gateway::EffectAttempt::Resolve { host, port: 443 };

        interceptor
            .intercept(&resolve("203.0.113.7"))
            .expect("the address a rule names goes ahead");
        interceptor
            .intercept(&egress_gateway::EffectAttempt::Connect {
                host: "203.0.113.7",
                port: 443,
                address: "203.0.113.7:443".parse().expect("an address"),
                http_visibility: false,
            })
            .expect("and so does its pinned address");
        // `127.1` and `2130706433` end in a number, which a resolver can read as an address.
        for refused in [
            "198.51.100.9",
            "2001:db8::1",
            "[2001:db8::1]",
            "127.1",
            "2130706433",
        ] {
            assert!(
                interceptor.intercept(&resolve(refused)).is_err(),
                "{refused} reads unanswered and is refused"
            );
        }
        assert_eq!(source.calls(), 0, "no source is asked about an address");
    }

    /// An entry whose questions wait `timeout` on `source`.
    fn waiting(timeout: Duration, source: &Arc<InMemorySource>) -> Enricher {
        let mut declared = entry(&["malware"], Confidence::Low);
        declared.timeout = timeout;
        enricher(declared, source, true)
    }

    /// Box waits for an answer that arrives within an entry's `timeout`, and at most that long for
    /// one that does not, which then reads unanswered.
    #[test]
    fn a_decision_waits_for_its_source_at_most_the_timeout() {
        let late = Arc::new(InMemorySource::new(Duration::from_secs(300)).stalling("late.example"));
        let enricher = waiting(Duration::from_secs(5), &late);
        let releasing = Arc::clone(&late);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            releasing.release();
        });
        assert!(
            threat(&enricher, "late.example").is_answered(),
            "an answer within the timeout counts"
        );
        release.join().expect("the release runs");

        let stalled =
            Arc::new(InMemorySource::new(Duration::from_secs(300)).stalling("slow.example"));
        let enricher = waiting(Duration::from_millis(20), &stalled);
        let started = Instant::now();
        assert!(!threat(&enricher, "slow.example").is_answered());
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "the decision waited {waited:?}"
        );
        stalled.release();
    }

    /// A stalled source holds at most `IN_FLIGHT_CAPACITY` questions; past them Box asks nothing
    /// and the entry reads unanswered.
    #[test]
    fn a_stalled_source_holds_at_most_its_in_flight_questions() {
        let source =
            Arc::new(InMemorySource::new(Duration::from_secs(300)).stalling("slow.example"));
        let enricher = waiting(Duration::from_millis(20), &source);

        for _ in 0..IN_FLIGHT_CAPACITY {
            assert!(!threat(&enricher, "slow.example").is_answered());
        }
        let reached = Instant::now() + Duration::from_secs(5);
        while source.calls() < IN_FLIGHT_CAPACITY && Instant::now() < reached {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(source.calls(), IN_FLIGHT_CAPACITY);

        assert!(!threat(&enricher, "slow.example").is_answered());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            source.calls(),
            IN_FLIGHT_CAPACITY,
            "with every slot held, Box asks nothing"
        );
        source.release();
    }

    /// An answer holds for the source's ttl, capped at `max_age`; after that the next host
    /// decision asks again.
    #[test]
    fn max_age_caps_how_long_an_answer_holds() {
        let source = Arc::new(InMemorySource::new(Duration::from_secs(300)));
        let mut declared = entry(&["malware"], Confidence::Low);
        declared.max_age = Duration::from_secs(1);
        let enricher = enricher(declared, &source, true);
        let [only] = enricher.entries.as_slice() else {
            panic!("one entry");
        };
        let now = Instant::now();

        assert!(only.answer(Some("clean.example"), now).is_answered());
        assert!(
            only.answer(Some("clean.example"), now + Duration::from_millis(999))
                .is_answered()
        );
        assert_eq!(source.calls(), 1, "the answer holds within max_age");
        assert!(
            only.answer(Some("clean.example"), now + Duration::from_secs(1))
                .is_answered()
        );
        assert_eq!(source.calls(), 2, "max_age caps the source's ttl of 300s");
    }

    /// After more distinct names than it holds, a cache holds at most its capacity and still serves
    /// the newest answer.
    #[test]
    fn a_full_cache_stays_within_its_capacity_and_keeps_the_newest_answer() {
        let now = Instant::now();
        let mut cache = Cache::new(4);
        let answer = EnrichmentAnswer::answered([]);
        for (seconds, lasts) in (0..).zip([9, 1, 5, 1, 7, 3, 8, 2, 6, 4]) {
            let later = now + Duration::from_secs(seconds);
            let name = format!("host{seconds}.example");
            cache.insert(
                &name,
                answer.clone(),
                later + Duration::from_secs(lasts),
                later,
            );
            assert!(cache.answers.len() <= 4, "after {name}");
            assert_eq!(cache.get(&name, later), Some(answer.clone()), "{name}");
        }
    }
}
