//! DNS-name enrichment on `net:connect`, through the openers, checks, and adapter a box uses.

use std::fs::File;
use std::path::{Path, PathBuf};

use policy::{
    EnrichmentAnswer, EnrichmentFacts, EnrichmentNames, GovernedBox, Operator, Policy,
    PolicyEngine, PolicyError, Principal, Request, ToolGrammars,
};

/// A box that refuses a labelled host and a host its source did not answer about.
const THREAT_POLICY: &str = r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("block_malware")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.labels.contains("malware") };
@id("require_answer")
forbid (principal, action == Box::Action::"net:connect", resource)
unless { context.input.enrichment.threat.answered };
"#;

/// A box that reads the labels and forgets the answer.
const LABELS_ONLY: &str = r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("block_malware")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.labels.contains("malware") };
"#;

fn source(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }]
}

fn names(declared: &[&str]) -> EnrichmentNames {
    EnrichmentNames::new(declared.iter().map(|name| (*name).to_string()))
        .expect("the names are valid")
}

fn history(directory: &Path) -> (File, PathBuf) {
    let path = directory.join("dogwood.redb");
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("the history file opens");
    (file, path)
}

fn open(
    text: &str,
    enrichment: &EnrichmentNames,
    directory: &Path,
) -> Result<PolicyEngine, policy::PolicyStagingError> {
    let (file, path) = history(directory);
    PolicyEngine::open_staged_file_with_grammars(
        &Operator::unanchored(),
        source(text),
        ToolGrammars::default(),
        enrichment,
        file,
        path,
    )
}

fn threat(answer: EnrichmentAnswer) -> EnrichmentFacts {
    [("threat".to_string(), answer)].into_iter().collect()
}

fn decide(engine: &PolicyEngine, host: &str, facts: &EnrichmentFacts) -> policy::Decision {
    engine
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::Connect {
                host,
                ip: None,
                port: 443,
                enrichment: facts,
            },
        )
        .0
}

#[test]
fn a_name_a_rule_cannot_read_unquoted_is_refused() {
    for refused in [
        "Threat",
        "1threat",
        "",
        "if",
        "has",
        &"a".repeat(33),
        "two-words",
    ] {
        let error = EnrichmentNames::new([refused.to_string()]).expect_err("the name is refused");
        assert_eq!(error.name(), refused);
    }
    assert!(EnrichmentNames::new(["threat_2".to_string(), "a".repeat(32)]).is_ok());
}

/// Reading an entry's labels with no rule on its answer is refused the same way by the check, by
/// configure's validation, and by the opener, and the finding names the rule.
#[test]
fn reading_labels_without_the_answer_is_refused_everywhere_a_box_loads_policy() {
    let declared = names(&["threat"]);
    let operator = Operator::unanchored();

    let validated = PolicyEngine::validate_with_grammars(
        &operator,
        &source(LABELS_ONLY),
        &ToolGrammars::default(),
        &declared,
    )
    .expect_err("validation refuses labels without the answer");
    assert!(matches!(validated, PolicyError::Schema(_)), "{validated}");
    let text = validated.to_string();
    assert!(
        text.contains(
            r#"rule @id("block_malware") (rule 2) reads context.input.enrichment.threat.labels"#
        ) && text.contains("no rule reads context.input.enrichment.threat.answered")
            && text.contains("unless { context.input.enrichment.threat.answered };"),
        "{text}"
    );

    for complete in [true, false] {
        let check = PolicyEngine::check_with_grammars(
            &operator,
            &source(LABELS_ONLY),
            complete,
            &ToolGrammars::default(),
            &declared,
        );
        let finding = check
            .errors()
            .iter()
            .find(|finding| finding.message().contains("threat.labels"))
            .unwrap_or_else(|| panic!("the check finds the unread answer: {check:?}"));
        assert_eq!(
            finding
                .rules()
                .iter()
                .map(|rule| rule.id().map(str::to_string))
                .collect::<Vec<_>>(),
            [Some("block_malware".to_string())]
        );
    }

    let staged = PolicyEngine::validate_staged_with_grammars(
        &source(LABELS_ONLY),
        &ToolGrammars::default(),
        &declared,
    )
    .expect_err("staged validation refuses labels without the answer");
    assert!(
        staged
            .to_string()
            .contains("no rule reads context.input.enrichment.threat.answered"),
        "{staged}"
    );

    let directory = tempfile::tempdir().expect("a temporary directory");
    let opened = open(LABELS_ONLY, &declared, directory.path())
        .expect_err("the opener refuses labels without the answer");
    assert!(opened.to_string().contains("threat.answered"), "{opened}");

    // The same text loads once a rule reads the answer, here only from history.
    let answered_in_history = format!(
        r#"{LABELS_ONLY}
@id("one_unanswered_ends_egress")
forbid (principal, action == Box::Action::"net:connect", resource)
when temporal {{ formerly within 3600s (Box::Action::"net:connect"::request{{ input.enrichment.threat.answered: false }}) }};"#
    );
    PolicyEngine::validate_with_grammars(
        &operator,
        &source(&answered_in_history),
        &ToolGrammars::default(),
        &declared,
    )
    .expect("a history read of the answer pairs the labels read");
}

/// A rule that reads an entry no table declares does not load, with no table or with another one.
#[test]
fn a_rule_reading_an_undeclared_entry_is_refused() {
    let reads_threat = r#"
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.answered };
"#;
    for declared in [names(&[]), names(&["reputation"])] {
        let error = PolicyEngine::validate_with_grammars(
            &Operator::unanchored(),
            &source(reads_threat),
            &ToolGrammars::default(),
            &declared,
        )
        .expect_err("the undeclared entry is refused");
        assert!(
            matches!(error, PolicyError::Schema(_)),
            "{declared:?}: {error}"
        );
        let staged = PolicyEngine::validate_staged_with_grammars(
            &source(reads_threat),
            &ToolGrammars::default(),
            &declared,
        )
        .expect_err("staged validation refuses the undeclared entry");
        assert!(
            staged.to_string().contains(
                "reads context.input.enrichment.threat, but the box declares no \
                 [enrichment.threat] table"
            ),
            "{declared:?}: {staged}"
        );
        let directory = tempfile::tempdir().expect("a temporary directory");
        assert!(
            open(reads_threat, &declared, directory.path()).is_err(),
            "{declared:?}: the opener refuses it too"
        );
    }
}

/// A `has` test reads no value, so testing for the record or the entry stands in for no rule on
/// the answer.
#[test]
fn a_has_test_is_not_a_read_of_the_answer() {
    for guard in [
        "context.input has enrichment",
        "context.input.enrichment has threat",
    ] {
        let text = format!(
            r#"
permit (principal, action == Box::Action::"net:connect", resource);
@id("block_malware")
forbid (principal, action == Box::Action::"net:connect", resource)
when {{ {guard} && context.input.enrichment.threat.labels.contains("malware") }};
"#
        );
        let error = PolicyEngine::validate_with_grammars(
            &Operator::unanchored(),
            &source(&text),
            &ToolGrammars::default(),
            &names(&["threat"]),
        )
        .expect_err("a has test does not read the answer");
        assert!(
            error
                .to_string()
                .contains("no rule reads context.input.enrichment.threat.answered"),
            "{guard}: {error}"
        );
    }
}

#[test]
fn the_engine_reads_only_the_entries_a_rule_names() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = open(
        THREAT_POLICY,
        &names(&["threat", "unused"]),
        directory.path(),
    )
    .expect("the policy opens");

    assert_eq!(
        engine.read_enrichment().iter().collect::<Vec<_>>(),
        ["threat"]
    );
}

/// A reload keeps which entries the rules read, since the box asks only those entries' sources and
/// disclosed them at startup, and a reload still refuses labels read without the answer.
#[test]
fn a_reload_cannot_change_which_entries_a_rule_reads() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = open(
        THREAT_POLICY,
        &names(&["threat", "reputation"]),
        directory.path(),
    )
    .expect("the policy opens");
    let reads_reputation = r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("require_reputation")
forbid (principal, action == Box::Action::"net:connect", resource)
unless { context.input.enrichment.reputation.answered };
"#;
    let changed = "a reload cannot change which [enrichment.<name>] tables a rule reads: the \
                   running policy reads [enrichment.threat], and this one reads";

    for (text, refusal) in [
        (
            reads_reputation,
            format!("{changed} [enrichment.reputation]; restart the box to apply it"),
        ),
        (
            r#"permit (principal, action == Box::Action::"net:connect", resource);"#,
            format!("{changed} none; restart the box to apply it"),
        ),
        (
            LABELS_ONLY,
            "no rule reads context.input.enrichment.threat.answered".to_string(),
        ),
    ] {
        let error = engine
            .reload(&source(text))
            .expect_err("the reload is refused");
        assert!(error.to_string().contains(&refusal), "{error}");
    }

    engine
        .reload(&source(&THREAT_POLICY.replace("malware", "phishing")))
        .expect("a reload that reads the same entries installs");
    assert_eq!(
        engine.read_enrichment().iter().collect::<Vec<_>>(),
        ["threat"]
    );
}

/// The answer reaches both the stateless rules and the recorded history a temporal rule reads.
#[test]
fn an_unanswered_connect_is_recorded_for_a_temporal_rule() {
    let policy = r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("one_unanswered_ends_egress")
forbid (principal, action == Box::Action::"net:connect", resource)
when temporal { formerly within 3600s (Box::Action::"net:connect"::request{ input.enrichment.threat.answered: false }) };
"#;
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = open(policy, &names(&["threat"]), directory.path()).expect("the policy opens");
    let clean = threat(EnrichmentAnswer::answered([]));

    assert!(decide(&engine, "first.example", &clean).is_allow());
    decide(
        &engine,
        "slow.invalid",
        &threat(EnrichmentAnswer::unanswered()),
    );
    let after = decide(&engine, "first.example", &clean);
    assert!(
        after.to_string().contains("one_unanswered_ends_egress"),
        "the recorded unanswered request ends egress: {after}"
    );
}

/// A box that declares no entry keeps the shipped schema, so its stored history is unchanged.
#[test]
fn a_box_with_no_entry_composes_the_shipped_schema() {
    assert_eq!(
        policy::compose_action_schema(&[]).expect("the schema composes"),
        include_str!("../schema/actions.cedarschema")
    );
}

#[cfg(feature = "egress-adapter")]
mod adapter {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use egress_gateway::{EffectAttempt, EffectInterceptor, EffectOutcome};
    use policy::{
        EgressPolicyInterceptor, EnrichmentAnswer, EnrichmentFacts, GovernedBox, HostEnricher,
        McpServerKind, PolicyEngine, Principal, ToolCatalogs,
    };

    use super::{THREAT_POLICY, names, open, threat};

    /// An enricher that answers from a fixed table, counts how often it may ask a source, and,
    /// as Box's does, recalls only what its latest `enrich` returned about the same host.
    struct Table {
        answers: BTreeMap<&'static str, EnrichmentAnswer>,
        asked: AtomicUsize,
        latest: Mutex<Option<(String, EnrichmentFacts)>>,
    }

    impl Table {
        fn new(answers: BTreeMap<&'static str, EnrichmentAnswer>) -> Self {
            Self {
                answers,
                asked: AtomicUsize::new(0),
                latest: Mutex::new(None),
            }
        }
    }

    impl HostEnricher for Table {
        fn enrich(&self, host: &str) -> EnrichmentFacts {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let facts = threat(
                self.answers
                    .get(host)
                    .cloned()
                    .unwrap_or_else(EnrichmentAnswer::unanswered),
            );
            *self.latest.lock().expect("the table is not poisoned") =
                Some((host.to_string(), facts.clone()));
            facts
        }

        fn recall(&self, host: &str) -> EnrichmentFacts {
            self.latest
                .lock()
                .expect("the table is not poisoned")
                .as_ref()
                .filter(|(decided, _)| decided == host)
                .map_or_else(
                    || threat(EnrichmentAnswer::unanswered()),
                    |(_, facts)| facts.clone(),
                )
        }
    }

    /// The egress interceptor of a box whose policy is `policy` and whose entries `enricher` answers.
    fn interceptor(
        policy: &Arc<PolicyEngine>,
        enricher: Arc<dyn HostEnricher>,
    ) -> Arc<dyn EffectInterceptor> {
        EgressPolicyInterceptor::into_handle_with_discovery(
            Arc::clone(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
            Vec::new(),
            Arc::new(ToolCatalogs::new(
                Arc::clone(policy),
                Vec::<(String, McpServerKind)>::new(),
            )),
            Arc::new(|| {}),
            enricher,
        )
    }

    fn refusal(interceptor: &dyn EffectInterceptor, attempt: &EffectAttempt<'_>) -> String {
        match interceptor.intercept(attempt) {
            Ok(_) => panic!("{attempt:?} was admitted"),
            Err(error) => error.to_string(),
        }
    }

    /// A labelled host is refused at resolution, before any DNS query, and again at each pinned
    /// address, which recalls the answer rather than asking again; a clean host goes ahead; a host
    /// the source did not answer about is refused.
    #[test]
    fn the_adapter_decides_each_connect_on_what_the_source_answered() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(THREAT_POLICY, &names(&["threat"]), directory.path()).expect("the policy opens"),
        );
        let enricher = Arc::new(Table::new(BTreeMap::from([
            (
                "evil.example",
                EnrichmentAnswer::answered(["malware".to_string()]),
            ),
            ("clean.example", EnrichmentAnswer::answered([])),
        ])));
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);
        let resolve = |host| EffectAttempt::Resolve { host, port: 443 };

        let labelled = refusal(interceptor.as_ref(), &resolve("evil.example"));
        assert!(labelled.contains("block_malware"), "{labelled}");
        let pinned = refusal(
            interceptor.as_ref(),
            &EffectAttempt::Connect {
                host: "evil.example",
                port: 443,
                address: "192.0.2.10:443".parse().expect("an address"),
                http_visibility: false,
            },
        );
        assert!(pinned.contains("block_malware"), "{pinned}");
        assert_eq!(
            enricher.asked.load(Ordering::SeqCst),
            1,
            "only the host decision may ask a source"
        );
        interceptor
            .intercept(&resolve("clean.example"))
            .expect("a clean host is admitted");
        let unanswered = refusal(interceptor.as_ref(), &resolve("slow.invalid"));
        assert!(unanswered.contains("require_answer"), "{unanswered}");
    }

    /// A `net:connect` outcome carries the facts its decision read, so a temporal rule on its
    /// `::response`, or on its `::error` when the socket did not open, matches.
    #[test]
    fn a_connect_outcome_carries_the_facts_its_decision_read() {
        let address = "192.0.2.10:443".parse().expect("an address");
        for (kind, outcome) in [
            ("response", EffectOutcome::Connected(address)),
            (
                "error",
                EffectOutcome::ConnectFailed(std::io::ErrorKind::ConnectionRefused),
            ),
        ] {
            let text = format!(
                r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("after_an_answered_connect")
forbid (principal, action == Box::Action::"net:connect", resource)
when temporal {{ formerly within 3600s (Box::Action::"net:connect"::{kind}{{ input.enrichment.threat.answered: true }}) }};
"#
            );
            let directory = tempfile::tempdir().expect("a temporary directory");
            let policy = Arc::new(
                open(&text, &names(&["threat"]), directory.path()).expect("the policy opens"),
            );
            let interceptor = interceptor(
                &policy,
                Arc::new(Table::new(BTreeMap::from([(
                    "clean.example",
                    EnrichmentAnswer::answered([]),
                )]))),
            );
            let resolve = EffectAttempt::Resolve {
                host: "clean.example",
                port: 443,
            };
            let connect = EffectAttempt::Connect {
                host: "clean.example",
                port: 443,
                address,
                http_visibility: false,
            };

            interceptor
                .intercept(&resolve)
                .expect("the first answered host is admitted");
            interceptor
                .intercept(&connect)
                .expect("and so is its address")
                .record_outcome(outcome)
                .expect("the outcome records");
            let after = refusal(interceptor.as_ref(), &connect);
            assert!(
                after.contains("after_an_answered_connect"),
                "the recorded {kind} carries the answer: {after}"
            );
        }
    }
}
