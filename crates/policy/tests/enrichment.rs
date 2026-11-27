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
            && text.contains("the load does not check what that rule does with it")
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

/// The load asks only that some rule reads the answer, not that a missing answer is refused: a
/// `forbid` on a label that it guards with `answered` loads, and lets an unanswered host through.
/// Whether a source outage refuses a host is the operator's rule to write.
#[test]
fn a_label_rule_guarded_by_the_answer_lets_an_unanswered_host_through() {
    let guarded = r#"
@id("allow_connect")
permit (principal, action == Box::Action::"net:connect", resource);
@id("block_malware")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.answered && context.input.enrichment.threat.labels.contains("malware") };
"#;
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = open(guarded, &names(&["threat"]), directory.path()).expect("the policy opens");

    assert!(
        decide(
            &engine,
            "slow.invalid",
            &threat(EnrichmentAnswer::unanswered())
        )
        .is_allow(),
        "an unanswered host is let through"
    );
    let labelled = decide(
        &engine,
        "evil.example",
        &threat(EnrichmentAnswer::answered(["malware".to_string()])),
    );
    assert!(labelled.to_string().contains("block_malware"), "{labelled}");
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use egress_gateway::{EffectAttempt, EffectInterceptor, EffectOutcome};
    use policy::{
        EgressPolicyInterceptor, EnrichmentAnswer, EnrichmentFacts, GovernedBox, HostEnricher,
        McpServerKind, PolicyEngine, Principal, ToolCatalogs,
    };

    use super::{THREAT_POLICY, names, open, threat};

    /// An enricher that answers from a fixed table, and counts how often it is asked, which is how
    /// often a source would learn a name.
    struct Table {
        answers: BTreeMap<&'static str, EnrichmentAnswer>,
        asked: AtomicUsize,
        /// Whether it answers only its first question, as a source whose answer expires at once.
        once: bool,
    }

    impl Table {
        fn new(answers: BTreeMap<&'static str, EnrichmentAnswer>) -> Self {
            Self {
                answers,
                asked: AtomicUsize::new(0),
                once: false,
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    impl HostEnricher for Table {
        fn enrich(&self, host: &str) -> EnrichmentFacts {
            let earlier = self.asked.fetch_add(1, Ordering::SeqCst);
            threat(
                self.answers
                    .get(host)
                    .filter(|_| !self.once || earlier == 0)
                    .cloned()
                    .unwrap_or_else(EnrichmentAnswer::unanswered),
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

    fn resolve(host: &str) -> EffectAttempt<'_> {
        EffectAttempt::Resolve { host, port: 443 }
    }

    fn connect(host: &str) -> EffectAttempt<'_> {
        connect_to(host, "192.0.2.10:443")
    }

    fn connect_to<'a>(host: &'a str, address: &str) -> EffectAttempt<'a> {
        EffectAttempt::Connect {
            host,
            port: 443,
            address: address.parse().expect("an address"),
            http_visibility: false,
        }
    }

    /// A box that admits two hosts by name, refuses one domain by name, and reads its source's
    /// answer.
    const SCREENED: &str = r#"
@id("allow_named")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "api.example" || context.input.host == "c2vjcmv0.exfil.example" };
@id("no_exfil")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.host like "*.exfil.example" };
@id("no_sinkhole")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input has ip4 && context.input.ip4 == "192.0.2.66" };
@id("block_malware")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.labels.contains("malware") };
@id("require_answer")
forbid (principal, action == Box::Action::"net:connect", resource)
unless { context.input.enrichment.threat.answered };
"#;

    /// No source learns a name that policy refuses whatever the source says: one a rule that reads
    /// no answer forbids, by name or by address, or one no permit could admit, on an address
    /// decision and on the host decision alike. The refusal is still the policy's, and a host the
    /// policy could admit is asked about.
    #[test]
    fn a_host_refused_whatever_the_source_says_is_never_asked_about() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(SCREENED, &names(&["threat"]), directory.path()).expect("the policy opens"),
        );
        let enricher = Arc::new(Table::new(BTreeMap::from([(
            "api.example",
            EnrichmentAnswer::answered([]),
        )])));
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);

        for (attempt, rule) in [
            (connect("c2vjcmv0.exfil.example"), "no_exfil"),
            (resolve("c2vjcmv0.exfil.example"), "no_exfil"),
            (connect_to("api.example", "192.0.2.66:443"), "no_sinkhole"),
        ] {
            let forbidden = refusal(interceptor.as_ref(), &attempt);
            assert!(forbidden.contains(rule), "{forbidden}");
        }
        for attempt in [connect("unlisted.example"), resolve("unlisted.example")] {
            let unmatched = refusal(interceptor.as_ref(), &attempt);
            assert!(!unmatched.contains("allow_named"), "{unmatched}");
        }
        assert_eq!(enricher.asked(), 0, "no refused name reaches the source");

        interceptor
            .intercept(&resolve("api.example"))
            .expect("a host the policy admits is asked about and admitted");
        assert_eq!(enricher.asked(), 1);
    }

    /// A reload changes which hosts are refused whatever the source says along with the rules.
    #[test]
    fn a_reload_changes_which_hosts_are_asked_about() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(SCREENED, &names(&["threat"]), directory.path()).expect("the policy opens"),
        );
        let enricher = Arc::new(Table::new(BTreeMap::from([(
            "c2vjcmv0.exfil.example",
            EnrichmentAnswer::answered([]),
        )])));
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);

        refusal(interceptor.as_ref(), &resolve("c2vjcmv0.exfil.example"));
        assert_eq!(enricher.asked(), 0);
        policy
            .reload(&super::source(&SCREENED.replace(
                r#"when { context.input.host like "*.exfil.example" };"#,
                r#"when { context.input.host like "*.elsewhere.example" };"#,
            )))
            .expect("a reload that reads the same entries installs");
        interceptor
            .intercept(&resolve("c2vjcmv0.exfil.example"))
            .expect("the reloaded policy admits the host on its answer");
        assert_eq!(enricher.asked(), 1);
    }

    /// The source is asked whenever its answer could change the decision: a host that only a rule
    /// on the answer could admit, and a host a rule could refuse for the absence of the record,
    /// which no screen without the record can judge.
    #[test]
    fn a_host_whose_answer_could_change_the_decision_is_asked_about() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(
                &format!(
                    r#"{SCREENED}
@id("allow_trusted")
permit (principal, action == Box::Action::"net:connect", resource)
when {{ context.input.enrichment.threat.labels.contains("trusted") }};
@id("without_the_record")
forbid (principal, action == Box::Action::"net:connect", resource)
when {{ !(context.input has enrichment) || context.input.host == "blocked.example" }};
"#
                ),
                &names(&["threat"]),
                directory.path(),
            )
            .expect("the policy opens"),
        );
        let enricher = Arc::new(Table::new(BTreeMap::from([
            (
                "trusted.example",
                EnrichmentAnswer::answered(["trusted".to_string()]),
            ),
            ("api.example", EnrichmentAnswer::answered([])),
        ])));
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);

        interceptor
            .intercept(&resolve("trusted.example"))
            .expect("the label admits a host no other permit names");
        interceptor
            .intercept(&resolve("api.example"))
            .expect("a rule on the record's absence does not hide the answer");
        assert_eq!(enricher.asked(), 2);
    }

    /// In log-only mode a host that policy refuses whatever the source says is still not asked
    /// about, and the denial is recorded and let through, so the screen enforces nothing.
    #[test]
    fn log_only_mode_lets_an_unasked_refusal_through() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(SCREENED, &names(&["threat"]), directory.path())
                .expect("the policy opens")
                .log_only(),
        );
        let enricher = Arc::new(Table::new(BTreeMap::new()));
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);

        for attempt in [
            resolve("c2vjcmv0.exfil.example"),
            connect("c2vjcmv0.exfil.example"),
        ] {
            interceptor
                .intercept(&attempt)
                .expect("log-only mode lets the denial through");
        }
        assert_eq!(enricher.asked(), 0);
    }

    /// Each address decision of a connection reads what its host decision read, even when the
    /// source would answer differently by then, and asks nothing more.
    #[test]
    fn each_address_decision_reads_the_answer_its_host_decision_read() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(THREAT_POLICY, &names(&["threat"]), directory.path()).expect("the policy opens"),
        );
        let enricher = Arc::new(Table {
            once: true,
            ..Table::new(BTreeMap::from([(
                "clean.example",
                EnrichmentAnswer::answered([]),
            )]))
        });
        let interceptor = interceptor(&policy, Arc::clone(&enricher) as Arc<dyn HostEnricher>);

        interceptor
            .intercept(&resolve("clean.example"))
            .expect("the answered host is admitted");
        for address in ["192.0.2.1:443", "[2001:db8::1]:443"] {
            interceptor
                .intercept(&EffectAttempt::Connect {
                    host: "clean.example",
                    port: 443,
                    address: address.parse().expect("an address"),
                    http_visibility: false,
                })
                .expect("each address reads the answer the host decision read");
        }
        assert_eq!(enricher.asked(), 1, "only the host decision asks");
    }

    /// An enricher whose source gives no answer to its first question and answers every later one.
    #[derive(Default)]
    struct Recovering(AtomicUsize);

    impl HostEnricher for Recovering {
        fn enrich(&self, _host: &str) -> EnrichmentFacts {
            threat(if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                EnrichmentAnswer::unanswered()
            } else {
                EnrichmentAnswer::answered([])
            })
        }
    }

    /// An address decision reads the answer of its own connection's host decision, not the answer
    /// a later connection to the same host and port got in between.
    #[test]
    fn an_address_decision_reads_its_own_connections_answer() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let policy = Arc::new(
            open(
                r#"
permit (principal, action == Box::Action::"net:connect", resource);
@id("address_needs_answer")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input has ip4 && !context.input.enrichment.threat.answered };
"#,
                &names(&["threat"]),
                directory.path(),
            )
            .expect("the policy opens"),
        );
        let interceptor = interceptor(&policy, Arc::new(Recovering::default()));
        let (resolved, first_resolved) = std::sync::mpsc::channel();
        let (go, second_resolved) = std::sync::mpsc::channel();

        let refused = std::thread::scope(|scope| {
            let interceptor = &interceptor;
            let first = scope.spawn(move || {
                interceptor
                    .intercept(&resolve("flaky.example"))
                    .expect("the first host decision, unanswered, is admitted");
                resolved.send(()).expect("the test waits");
                second_resolved
                    .recv()
                    .expect("the second host decision runs");
                refusal(interceptor.as_ref(), &connect("flaky.example"))
            });
            first_resolved.recv().expect("the first host decision runs");
            interceptor
                .intercept(&resolve("flaky.example"))
                .expect("the second host decision, answered, is admitted");
            go.send(()).expect("the first connection waits");
            first.join().expect("the first connection finishes")
        });
        assert!(refused.contains("address_needs_answer"), "{refused}");
    }

    /// An address decision with no host decision before it asks, and decides on that answer.
    #[test]
    fn an_address_decision_with_no_host_decision_asks() {
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

        interceptor
            .intercept(&connect("clean.example"))
            .expect("the clean answer admits the address");
        let labelled = refusal(interceptor.as_ref(), &connect("evil.example"));
        assert!(labelled.contains("block_malware"), "{labelled}");
        assert_eq!(enricher.asked(), 2);
    }

    /// A labelled host is refused at resolution, before any DNS query, and again at each pinned
    /// address, which reads the answer its host decision read rather than asking again; a clean
    /// host goes ahead; a host the source did not answer about is refused.
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

        let labelled = refusal(interceptor.as_ref(), &resolve("evil.example"));
        assert!(labelled.contains("block_malware"), "{labelled}");
        let pinned = refusal(interceptor.as_ref(), &connect("evil.example"));
        assert!(pinned.contains("block_malware"), "{pinned}");
        assert_eq!(
            enricher.asked(),
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
