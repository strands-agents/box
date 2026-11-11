//! Request identifiers make completed HTTP operations visible to temporal limits.

#[path = "support/history.rs"]
mod history;
mod support;

use history::{events as stored_events, identifier};

use std::collections::BTreeSet;
use std::path::PathBuf;

use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Record};

use policy::{
    Decision, Delivery, DenyReason, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request,
    RequestId, compose_action_schema, event_schema_source,
};

fn tripwire(predicate: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("request-id-tripwire.dw"),
        text: format!(
            r#"
permit (principal, action == Box::Action::"http:request", resource);
@id("tripwire")
forbid (principal, action == Box::Action::"http:request", resource)
when temporal {{ {predicate} }};
"#,
        ),
    }])
    .expect("the temporal tripwire loads")
}

fn request() -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/upload",
        body_bytes: 5,
        intercepted: true,
    }
}

fn response() -> Outcome<'static> {
    Outcome::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/upload",
        delivery: Delivery::Completed { bytes: 5 },
        status: Some(200),
        intercepted: true,
    }
}

fn assert_second_request_is_forbidden(predicate: &str) {
    let engine = tripwire(predicate);
    let request_id = admitted(&engine);
    completed(&engine, &request_id);
    assert_forbidden_by(&decide(&engine).0, "tripwire");
}

#[test]
fn a_request_id_variable_tripwire_forbids_the_second_http_request() {
    assert_second_request_is_forbidden(
        r#"exists (r: String). (
            formerly within 3600s (
                Box::Action::"http:request"::response{ requestId: r }
            )
        )"#,
    );
}

#[test]
fn a_request_id_wildcard_tripwire_forbids_the_second_http_request() {
    assert_second_request_is_forbidden(
        r#"formerly within 3600s (
            Box::Action::"http:request"::response{ requestId: _ }
        )"#,
    );
}

#[test]
fn an_input_host_control_forbids_the_second_http_request() {
    assert_second_request_is_forbidden(
        r#"formerly within 3600s (
            Box::Action::"http:request"::response{ input.host: _ }
        )"#,
    );
}

#[test]
fn an_unrecorded_operation_does_not_trip_a_response_limit() {
    let engine = tripwire(
        r#"formerly within 3600s (
            Box::Action::"http:request"::response{ requestId: _ }
        )"#,
    );
    let governed = GovernedBox::assigned("request-id-test");
    let principal = Principal::agent();
    for _ in 0..5 {
        let decision = engine.decide(&governed, &principal, &request()).0;
        assert!(
            decision.is_allow(),
            "a request without a response must not trip this limit: {decision:?}"
        );
    }
}

#[test]
fn durable_http_history_preserves_one_identifier_for_each_operation() {
    let history = tempfile::tempdir().expect("the history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open(permit(), &path).expect("the HTTP policy opens");
    for _ in 0..2 {
        let request_id = admitted(&engine);
        completed(&engine, &request_id);
    }
    drop(engine);

    let events = stored_events(&path);
    assert_eq!(
        events.len(),
        4,
        "two operations produce two requests and two responses"
    );
    let identifiers: Vec<_> = events
        .iter()
        .map(|event| {
            assert_eq!(event.action(), "http:request");
            identifier(event)
        })
        .collect();
    assert_eq!(
        events.iter().map(|event| event.kind()).collect::<Vec<_>>(),
        ["request", "response", "request", "response"]
    );
    assert_eq!(
        identifiers[0], identifiers[1],
        "the first response must identify its request"
    );
    assert_eq!(
        identifiers[2], identifiers[3],
        "the second response must identify its request"
    );
    assert_ne!(
        identifiers[0], identifiers[2],
        "identical operations must have separate identifiers"
    );
}

fn permit() -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("http-permit.dw"),
        text: r#"permit(principal, action == Box::Action::"http:request", resource);"#.to_string(),
    }]
}

fn decide(engine: &PolicyEngine) -> (Decision, Option<RequestId>) {
    engine.decide(
        &GovernedBox::assigned("request-id-test"),
        &Principal::agent(),
        &request(),
    )
}

fn admitted(engine: &PolicyEngine) -> RequestId {
    let (decision, request_id) = decide(engine);
    assert!(
        decision.is_allow(),
        "the operation must be admitted: {decision:?}"
    );
    request_id.expect("a submitted request has a token")
}

fn completed(engine: &PolicyEngine, request_id: &RequestId) {
    engine
        .record(
            &GovernedBox::assigned("request-id-test"),
            &Principal::agent(),
            request_id,
            &response(),
        )
        .expect("the matching outcome records");
}

fn assert_forbidden_by(decision: &Decision, annotation: &str) {
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ),
        "{annotation} must deny through policy, not an internal fault: {decision:?}"
    );
    assert!(
        decision
            .attribution()
            .iter()
            .any(|policy| policy.annotation_id.as_deref() == Some(annotation)),
        "the expected {annotation} monitor must cause the denial: {decision:?}"
    );
}

#[test]
fn identical_interleaved_requests_keep_their_ids_when_responses_finish_in_reverse_order() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open(permit(), &path).expect("authority opens");
    let first = admitted(&engine);
    let second = admitted(&engine);
    let unfinished = admitted(&engine);
    assert_ne!(first.as_str(), second.as_str());
    assert_ne!(first.as_str(), unfinished.as_str());
    assert_ne!(second.as_str(), unfinished.as_str());
    completed(&engine, &second);
    completed(&engine, &first);
    drop(engine);
    let events = stored_events(&path);
    assert_eq!(
        events.iter().map(|event| event.kind()).collect::<Vec<_>>(),
        ["request", "request", "request", "response", "response"]
    );
    assert_eq!(
        events.iter().map(identifier).collect::<Vec<_>>(),
        [
            first.as_str(),
            second.as_str(),
            unfinished.as_str(),
            second.as_str(),
            first.as_str()
        ]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() != "request")
            .filter(|event| identifier(event) == unfinished.as_str())
            .count(),
        0,
        "the unfinished request must not acquire another request's response"
    );
}

#[test]
fn a_literal_request_id_predicate_observes_the_matching_response() {
    let history = tempfile::tempdir().expect("history directory");
    let engine = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        permit(),
        &history.path().join("dogwood.redb"),
    )
    .expect("authority opens");
    let request_id = admitted(&engine);
    completed(&engine, &request_id);
    // A new statement starts its temporal history at installation, so install the literal
    // predicate before its matching event. Retain the already-submitted operation across reload.
    let pending = admitted(&engine);
    let literal =
        serde_json::to_string(pending.as_str()).expect("the identifier is a string literal");
    let mut rules = permit();
    rules.push(Policy {
        origin: PathBuf::from("literal.dw"),
        text: format!(
            r#"
        @id("literal")
        forbid(principal, action == Box::Action::"http:request", resource)
        when temporal {{ formerly within 3600s (
            Box::Action::"http:request"::response{{ requestId: {literal} }}
        ) }};"#,
        ),
    });
    engine.reload(&rules).expect("literal predicate installs");
    assert!(decide(&engine).0.is_allow());
    completed(&engine, &pending);
    let (decision, _) = decide(&engine);
    assert!(
        !decision.is_allow(),
        "the response must match its literal requestId: {decision:?}"
    );
    assert!(
        decision
            .attribution()
            .iter()
            .any(|policy| policy.annotation_id.as_deref() == Some("literal"))
    );
}

#[test]
fn a_correlated_request_response_predicate_trips_only_after_a_completed_pair() {
    assert_second_request_is_forbidden(
        r#"exists (r: String). (
        formerly within 3600s (
            Box::Action::"http:request"::response{ requestId: r }
            && formerly within 3600s (
                Box::Action::"http:request"::request{ requestId: r }
            )
        )
    )"#,
    );
}

#[test]
fn failed_http_outcomes_trip_identifier_error_predicates_and_leave_response_predicates_open() {
    for (kind, allowed_after_failure) in [("error", false), ("response", true)] {
        let engine = tripwire(&format!(
            r#"formerly within 3600s (
            Box::Action::"http:request"::{kind}{{ requestId: _ }}
        )"#
        ));
        let request_id = admitted(&engine);
        engine
            .record(
                &GovernedBox::assigned("request-id-test"),
                &Principal::agent(),
                &request_id,
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/upload",
                    delivery: Delivery::Failed,
                    status: None,
                    intercepted: true,
                },
            )
            .expect("the failed operation records");
        assert_eq!(
            decide(&engine).0.is_allow(),
            allowed_after_failure,
            "a failed operation must enter only the error monitor"
        );
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_refusal_before_submission_returns_no_token_and_records_no_event() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open(permit(), &path).expect("authority opens");
    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("request-id-test"),
        &Principal::agent(),
        &Request::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/upload",
            body_bytes: usize::MAX,
            intercepted: true,
        },
    );
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::InternalFault,
                ..
            }
        ),
        "an input that cannot fit a Cedar Long must fail the request gate: {decision:?}"
    );
    assert!(
        request_id.is_none(),
        "an unsubmitted request must not return a correlation token"
    );
    drop(engine);
    assert!(
        stored_events(&path).is_empty(),
        "the request gate must run before appending history"
    );
}

#[test]
fn a_denied_request_records_an_id_without_fabricating_an_outcome() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("denied.dw"),
            text: r#"forbid(principal, action == Box::Action::"http:request", resource);"#
                .to_string(),
        }],
        &path,
    )
    .expect("authority opens");
    let (decision, request_id) = decide(&engine);
    assert!(matches!(
        decision,
        Decision::Deny {
            reason: DenyReason::Forbidden,
            ..
        }
    ));
    let request_id = request_id.expect("a policy denial follows a submitted request");
    drop(engine);
    let events = stored_events(&path);
    assert_eq!(
        events.len(),
        1,
        "the denial must not invent a completed operation"
    );
    assert_eq!(events[0].kind(), "request");
    assert_eq!(identifier(&events[0]), request_id.as_str());
}

#[test]
fn reload_keeps_in_flight_tokens_and_reopen_never_reuses_a_recorded_identifier() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let engine = PolicyEngine::open_staged(&policy::Operator::unanchored(), permit(), &path)
        .expect("authority opens");
    let before_reload = admitted(&engine);
    engine.reload(&permit()).expect("unchanged policy reloads");
    let after_reload = admitted(&engine);
    completed(&engine, &before_reload);
    completed(&engine, &after_reload);
    drop(engine);
    let before_reopen = stored_events(&path);
    let engine = PolicyEngine::open_staged(&policy::Operator::unanchored(), permit(), &path)
        .expect("existing history reopens");
    let after_reopen = admitted(&engine);
    assert_ne!(before_reload.as_str(), after_reopen.as_str());
    assert_ne!(after_reload.as_str(), after_reopen.as_str());
    assert!(
        engine
            .record(
                &GovernedBox::assigned("request-id-test"),
                &Principal::agent(),
                &before_reload,
                &response()
            )
            .is_err(),
        "a token from a closed authority cannot append to a reopened one"
    );
    completed(&engine, &after_reopen);
    drop(engine);
    let events = stored_events(&path);
    assert_eq!(
        &events[..before_reopen.len()],
        &before_reopen,
        "reopening and rejected old tokens must preserve prior facts"
    );
    assert_eq!(
        events.len(),
        before_reopen.len() + 2,
        "a rejected token appends no outcome"
    );
    assert_eq!(identifier(&events[events.len() - 1]), after_reopen.as_str());
}

#[test]
fn a_token_from_another_open_history_cannot_record_an_outcome() {
    let first = support::open_policy(permit()).expect("first authority opens");
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let second = PolicyEngine::open(permit(), &path).expect("second authority opens");
    let foreign = admitted(&first);
    let own = admitted(&second);
    assert!(
        second
            .record(
                &GovernedBox::assigned("request-id-test"),
                &Principal::agent(),
                &foreign,
                &response()
            )
            .is_err(),
        "correlation tokens cannot cross durable histories"
    );
    completed(&second, &own);
    drop(second);
    let events = stored_events(&path);
    assert_eq!(
        events.len(),
        2,
        "foreign token rejection must append no event"
    );
    assert_eq!(identifier(&events[0]), identifier(&events[1]));
}

const LEGACY_GUARDS: &str = r#"
permit(principal, action == Box::Action::"http:request", resource);
@id("legacy-host")
forbid(principal, action == Box::Action::"http:request", resource)
when { context.input.path == "/host-probe" }
when temporal { formerly within 3600s (
    Box::Action::"http:request"::response{ input.host: "api.example.com" }
) };
@id("request-id")
forbid(principal, action == Box::Action::"http:request", resource)
when { context.input.path == "/id-probe" }
when temporal { formerly within 3600s (
    Box::Action::"http:request"::response{ requestId: _ }
) };
"#;

#[test]
fn captured_legacy_events_reopen_without_erasing_facts_or_inventing_identifiers() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let actions = compose_action_schema(&[]).expect("fixed schema composes");
    let mut old = DurableTemporalEngine::open(&path, 10_000).expect("legacy store opens");
    old.install(LEGACY_GUARDS, &actions, Some(event_schema_source()), None)
        .expect("guards install");
    // These are exact pre-fix Record bytes from the sbox-72 HTTP reproduction. Submit assigns
    // fresh timestamps so finite-window assertions remain valid on future test runs. Every
    // captured field and missing field remains unchanged; no request IDs are synthesized.
    let captured: Vec<_> = include_str!("fixtures/legacy_http_history.jsonl")
        .lines()
        .map(|line| {
            let Record::Event(event) =
                Record::decode(line.as_bytes()).expect("captured record decodes")
            else {
                panic!("fixture contains only events")
            };
            assert!(event.field_path(&["requestId".to_string()]).is_none());
            old.submit(event.clone().into_builder())
                .expect("legacy event records");
            event
        })
        .collect();
    drop(old);
    let before = stored_events(&path);
    assert_eq!(before.len(), captured.len());
    for (captured, stored) in captured.iter().zip(&before) {
        assert_eq!(
            dogwood_local_engine::event_to_json(captured),
            dogwood_local_engine::event_to_json(stored),
            "restamping must preserve every captured field"
        );
    }
    let sources = || {
        vec![Policy {
            origin: PathBuf::from("legacy-guards.dw"),
            text: LEGACY_GUARDS.to_string(),
        }]
    };
    let engine =
        PolicyEngine::open(sources(), &path).expect("the old history opens without migration");
    let probe = |path| Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path,
        body_bytes: 5,
        intercepted: true,
    };
    let (host_decision, _) = engine.decide(
        &GovernedBox::assigned("request-id-test"),
        &Principal::agent(),
        &probe("/host-probe"),
    );
    assert_forbidden_by(&host_decision, "legacy-host");
    assert!(
        engine
            .decide(
                &GovernedBox::assigned("request-id-test"),
                &Principal::agent(),
                &probe("/id-probe")
            )
            .0
            .is_allow(),
        "a missing old identifier cannot become a fabricated match"
    );
    let new_request = admitted(&engine);
    completed(&engine, &new_request);
    let (id_decision, _) = engine.decide(
        &GovernedBox::assigned("request-id-test"),
        &Principal::agent(),
        &probe("/id-probe"),
    );
    assert_forbidden_by(&id_decision, "request-id");
    drop(engine);
    let after = stored_events(&path);
    assert_eq!(
        &after[..before.len()],
        &before,
        "opening and adding correlated events never rewrite old facts"
    );
    let engine = PolicyEngine::open(sources(), &path).expect("mixed old/new history reopens");
    for (path, annotation) in [("/host-probe", "legacy-host"), ("/id-probe", "request-id")] {
        let (decision, _) = engine.decide(
            &GovernedBox::assigned("request-id-test"),
            &Principal::agent(),
            &probe(path),
        );
        assert_forbidden_by(&decision, annotation);
    }
}

#[test]
#[ignore = "twenty thousand durable submissions cross two checkpoints; run explicitly with --ignored"]
fn an_identifier_guard_stays_closed_across_checkpoints_and_reopen() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let sources = || {
        vec![Policy {
            origin: PathBuf::from("long-request-id.dw"),
            text: r#"permit(principal, action == Box::Action::"http:request", resource);
            @id("long-request-id")
            forbid(principal, action == Box::Action::"http:request", resource)
            when temporal { formerly within 3600s (
                Box::Action::"http:request"::response{ requestId: _ }
            ) };"#
                .to_string(),
        }]
    };
    let engine = PolicyEngine::open(sources(), &path).expect("authority opens");
    let first = admitted(&engine);
    let mut identifiers = BTreeSet::from([first.as_str().to_string()]);
    completed(&engine, &first);
    for iteration in 0..20_050 {
        let (decision, request_id) = decide(&engine);
        assert!(
            !decision.is_allow(),
            "the guard must stay closed at submission {iteration}"
        );
        assert!(
            decision
                .attribution()
                .iter()
                .any(|policy| policy.annotation_id.as_deref() == Some("long-request-id")),
            "a policy guard, not an internal error, must deny submission {iteration}"
        );
        assert!(
            identifiers.insert(
                request_id
                    .expect("denied request records")
                    .as_str()
                    .to_string()
            ),
            "checkpoint activity must not reuse a request identifier"
        );
    }
    drop(engine);
    {
        let log = DurableLog::open(&path).expect("history opens");
        let snapshot = log
            .get_snapshot()
            .expect("snapshot slot reads")
            .expect("the workload creates a checkpoint");
        assert!(
            snapshot.up_to_offset >= 20_000,
            "the persisted checkpoint must include the second ten-thousand-event interval"
        );
    }
    let engine = PolicyEngine::open(sources(), &path).expect("checkpointed history reopens");
    let (decision, request_id) = decide(&engine);
    assert!(
        !decision.is_allow(),
        "the identifier monitor must survive checkpoint replay"
    );
    assert!(
        decision
            .attribution()
            .iter()
            .any(|policy| policy.annotation_id.as_deref() == Some("long-request-id"))
    );
    assert!(
        identifiers.insert(
            request_id
                .expect("reopened request records")
                .as_str()
                .to_string()
        ),
        "pruned history must not reset the request identifier counter"
    );
}
