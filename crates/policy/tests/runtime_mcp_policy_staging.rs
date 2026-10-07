//! Runtime MCP policy staging through the public policy facade.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dogwood_language::{Event, Value};
use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Record};
use policy::{
    Decision, DecisionObserver, Delivery, DenyReason, GovernedBox, Outcome, Policy, PolicyEngine,
    Principal, Request, RuleId, SchemaStage, generate_mcp_schema,
};
use serde_json::json;

const BUDGET: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    exists (total: Long). (
        (sum b for (b: Long), (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b } && tp(t)
            )
        )) == total
        && total < 100
    )
};
"#;

fn source(name: &str, text: &str) -> Policy {
    Policy {
        origin: PathBuf::from(name),
        text: text.to_string(),
    }
}

fn generated(server: &str, tool: &str, field: &str, field_type: &str) -> String {
    generate_mcp_schema(
        server,
        &format!(
            r#"{{
                "result": {{
                    "tools": [{{
                        "name": "{tool}",
                        "inputSchema": {{
                            "type": "object",
                            "properties": {{"{field}": {{"type": "{field_type}"}}}},
                            "required": ["{field}"]
                        }}
                    }}]
                }}
            }}"#
        ),
    )
    .expect("the MCP schema generates")
}

fn shell_request() -> Request<'static> {
    Request::ShellExec {
        command: "printf ready",
        program: "printf",
        args: &[],
        cwd: "/work",
    }
}

fn http_request() -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1",
        body_bytes: 10,
        intercepted: true,
    }
}

fn staged(sources: Vec<Policy>, history: &Path) -> PolicyEngine {
    PolicyEngine::open_staged(&policy::Operator::unanchored(), sources, history)
        .expect("the staged policy opens")
}

#[test]
fn a_canonical_bundle_is_ready_without_an_mcp_schema() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let authority = staged(
        vec![source(
            "canonical.dw",
            r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
        )],
        &path,
    );

    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "the canonical fast path must install before discovery"
    );
    authority
        .finish_mcp_discovery()
        .expect("a ready bundle has no finish diagnostics");
    drop(authority);

    let log = DurableLog::open(&path).expect("the canonical log opens");
    let mut management_timestamps = std::collections::BTreeSet::new();
    log.scan_from(0, |_, bytes| {
        let record = Record::decode(bytes).expect("the canonical record decodes");
        if !matches!(record, Record::Event(_)) {
            management_timestamps.insert(record.timestamp());
        }
    })
    .expect("the canonical records scan");
    assert_eq!(
        management_timestamps.len(),
        1,
        "the canonical fast path must install in one durable transaction"
    );
}

#[test]
fn an_empty_authored_bundle_is_ready_and_denies_by_default() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(Vec::new(), &history.path().join("dogwood.redb"));

    assert!(
        !authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow()
    );
    authority
        .finish_mcp_discovery()
        .expect("the source-free authority is ready");
}

#[derive(Default)]
struct RecordingObserver {
    decisions: Mutex<Vec<Decision>>,
}

impl DecisionObserver for RecordingObserver {
    fn observed(&self, _action: &str, _resource: &str, decision: &Decision) {
        if let Ok(mut decisions) = self.decisions.lock() {
            decisions.push(decision.clone());
        }
    }
}

#[test]
fn a_discovering_pending_tool_is_policy_pending_and_is_observed() {
    // While a server's schema is still staging, the box opens `Discovering` and serves the
    // schema-independent subset. Only a `tools/call` naming a still-pending typed tool is held with
    // a transient `PolicyPending`; discovery frames and non-typed requests are decided normally. A
    // coarse `mcp:call` permit keeps `tools/list` allowed so no `tools/list` contradiction arises.
    let history = tempfile::tempdir().expect("history directory");
    let observer = Arc::new(RecordingObserver::default());
    let authority = staged(
        vec![source(
            "pending.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
permit(principal, action == alpha::Action::"read", resource);
permit(principal, action == alpha::Action::"write", resource);
"#,
        )],
        &history.path().join("dogwood.redb"),
    )
    .observed_by(observer.clone());

    let arguments = json!({"path": "/workspace/input"});
    let pending_tool = authority.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::McpCall {
            server: "alpha",
            method: "tools/call",
            tool: Some("read"),
            prompt: None,
            uri: None,
            arguments: Some(&arguments),
        },
    );
    assert!(
        matches!(
            pending_tool,
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ref rule,
                ref attribution,
                ..
            } if rule.as_str() == RuleId::POLICY_PENDING && attribution.is_empty()
        ),
        "a tool call whose typed action is still pending is held transiently"
    );
    assert!(
        observer
            .decisions
            .lock()
            .expect("observer recording")
            .contains(&pending_tool),
        "the observer must receive the pending denial"
    );

    // A discovery frame for the same server is decided against the committed subset, not held.
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "alpha",
                    method: "tools/list",
                    tool: None,
                    prompt: None,
                    uri: None,
                    arguments: None,
                },
            )
            .is_allow(),
        "tools/list is decided by the schema-independent subset while discovering"
    );

    // The typed rules never staged (alpha's `tools/list` is not permitted), so completion
    // degrades that one server rather than fataling. The degraded set names it, and its tool calls
    // are denied fail-closed below.
    let degraded = authority
        .finish_mcp_discovery()
        .expect("discovery completion degrades the server rather than fataling");
    assert_eq!(
        degraded,
        vec!["alpha".to_string()],
        "the server whose typed rules never staged is degraded"
    );
    assert!(
        !authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "alpha",
                    method: "tools/call",
                    tool: Some("read"),
                    prompt: None,
                    uri: None,
                    arguments: Some(&json!({})),
                },
            )
            .is_allow(),
        "a degraded server's tool call is denied fail-closed after completion"
    );
}

#[test]
fn a_held_pending_tool_decision_appends_no_durable_event() {
    // A `tools/call` held because its typed action is still staging returns a transient
    // `PolicyPending` without evaluating the engine, so it records no event. The subset commit at
    // open writes management records (schema/adds), never an event, so the invariant is "no event".
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let authority = staged(
        vec![source(
            "pending.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
permit(principal, action == alpha::Action::"read", resource);
"#,
        )],
        &path,
    );

    let arguments = json!({"path": "/workspace/input"});
    assert!(matches!(
        authority.decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::McpCall {
                server: "alpha",
                method: "tools/call",
                tool: Some("read"),
                prompt: None,
                uri: None,
                arguments: Some(&arguments),
            },
        ),
        Decision::Deny {
            reason: DenyReason::PolicyPending,
            ..
        }
    ));
    drop(authority);

    let log = DurableLog::open(&path).expect("the durable log opens");
    let mut events = 0usize;
    log.scan_from(0, |_, bytes| {
        if matches!(
            Record::decode(bytes).expect("the record decodes"),
            Record::Event(_)
        ) {
            events += 1;
        }
    })
    .expect("the records scan");
    assert_eq!(
        events, 0,
        "a held pending-tool decision must append no durable event"
    );
}

#[test]
fn cumulative_schemas_hold_each_pending_tool_until_it_stages() {
    // Schema-independent rules (canonical shell:exec, the coarse mcp:call permits) serve
    // during discovery; only a `tools/call` to a not-yet-staged typed tool is held. As each server
    // stages, its tool flips from held to enforced; the authority reaches Ready when all stage.
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![
            source(
                "canonical.dw",
                r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
            ),
            source(
                "alpha-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "alpha" };"#,
            ),
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "beta-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "beta" };"#,
            ),
            source(
                "beta.dw",
                r#"permit(principal, action == beta::Action::"write", resource);"#,
            ),
        ],
        &history.path().join("dogwood.redb"),
    );

    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("Alpha stages"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "a schema-independent request is served by the subset while discovering"
    );
    let beta_arguments = json!({"value": 7});
    assert!(
        matches!(
            authority.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "beta",
                    method: "tools/call",
                    tool: Some("write"),
                    prompt: None,
                    uri: None,
                    arguments: Some(&beta_arguments),
                },
            ),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "Beta's tool is held while its typed action is still pending"
    );
    let alpha_arguments = json!({"path": "/workspace/input"});
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "alpha",
                    method: "tools/call",
                    tool: Some("read"),
                    prompt: None,
                    uri: None,
                    arguments: Some(&alpha_arguments),
                },
            )
            .is_allow(),
        "the staged Alpha tool is enforced during discovery"
    );

    assert_eq!(
        authority
            .stage_mcp_schema("beta", generated("beta", "write", "value", "integer"))
            .expect("Beta stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "beta",
                    method: "tools/call",
                    tool: Some("write"),
                    prompt: None,
                    uri: None,
                    arguments: Some(&beta_arguments),
                },
            )
            .is_allow(),
        "the Beta tool is enforced once its schema stages"
    );
}

#[test]
fn a_fragment_staged_under_another_server_is_rejected_without_state_change() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "alpha-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "alpha" };"#,
            ),
        ],
        &history.path().join("dogwood.redb"),
    );

    assert!(matches!(
        authority
            .stage_mcp_schema("alpha", generated("beta", "read", "path", "string"))
            .expect("the mismatch is proposal-specific"),
        SchemaStage::Rejected { .. }
    ));
    // The mismatched fragment left alpha's typed rule pending, observable as its `tools/call`
    // being held transiently (there is no read-only `finish` anymore — it degrades and completes).
    assert!(
        matches!(
            authority.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::McpCall {
                    server: "alpha",
                    method: "tools/call",
                    tool: Some("read"),
                    prompt: None,
                    uri: None,
                    arguments: Some(&json!({ "path": "/x" })),
                },
            ),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "alpha's typed rule is still pending after the mismatched fragment"
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the correct fragment stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
}

#[test]
fn candidate_diagnostics_follow_cumulative_ordinary_macro_and_temporal_references() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![
            source(
                "canonical.dw",
                r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
            ),
            source(
                "alpha-head.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "alpha-condition.dw",
                r#"permit(principal, action, resource)
                   when { action == alpha::Action::"read" };"#,
            ),
            // A forbid, because `alpha-head.dw` permits the action with no condition and a temporal
            // permit beside it would refuse the load as an inert cap.
            source(
                "alpha-beta-temporal.dw",
                r#"forbid(principal, action == alpha::Action::"read", resource)
                   when temporal {
                       formerly within 60s (
                           beta::Action::"write"::request{ input.value: _ }
                       )
                   };"#,
            ),
            source(
                "alpha-macro.dw",
                r#"def cedar is_alpha(?candidate) {
                       ?candidate == alpha::Action::"read"
                   };
                   permit(principal, action, resource)
                   when { is_alpha(action) };"#,
            ),
            source(
                "beta-head.dw",
                r#"permit(principal, action == beta::Action::"write", resource);"#,
            ),
            source(
                "missing.dw",
                r#"permit(principal, action == missing::Action::"never", resource);"#,
            ),
            // Coarse permits keep tools/list allowed for every server named by a typed rule, so
            // nothing contradicts. Appended last, so the ordinals above are unchanged.
            source(
                "coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { ["alpha", "beta", "missing"].contains(context.input.server) };"#,
            ),
        ],
        &history.path().join("dogwood.redb"),
    );

    // `finish_mcp_discovery` now degrades (and completes) rather than reporting pending
    // ordinals read-only, so the cumulative classification is observed through the STAGE outcomes
    // below plus the FINAL degraded set. Staging alpha then beta must resolve every ordinary, macro,
    // and temporal reference to `alpha`/`beta`; only `missing` (whose server never stages) is left,
    // so completion degrades exactly that one server.
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "value", "string"))
            .expect("Alpha stages"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    assert_eq!(
        authority
            .stage_mcp_schema("beta", generated("beta", "write", "value", "string"))
            .expect("Beta stages"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling"),
        vec!["missing".to_string()],
        "staging alpha and beta resolves every ordinary, macro, and temporal reference to them; \
         only the never-staged `missing` server is degraded"
    );
}

#[test]
fn macro_expansion_precedes_candidate_classification() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![
            source(
                "macro.dw",
                r#"
def cedar is_alpha(?candidate) {
    ?candidate == alpha::Action::"read"
};
permit(principal, action, resource)
when { is_alpha(action) };
"#,
            ),
            source(
                "alpha-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "alpha" };"#,
            ),
        ],
        &history.path().join("dogwood.redb"),
    );

    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the expanded candidate stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
}

#[test]
fn staged_validation_checks_parse_macro_and_provider_without_weakening_strict_validation() {
    let unknown_action = source(
        "mcp.dw",
        r#"
def cedar is_alpha(?candidate) {
    ?candidate == alpha::Action::"read"
};
permit(principal, action, resource)
when { is_alpha(action) };
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
"#,
    );
    PolicyEngine::validate_staged(std::slice::from_ref(&unknown_action))
        .expect("an MCP action can remain unresolved before discovery");
    assert!(
        matches!(
            PolicyEngine::validate(
                &policy::Operator::unanchored(),
                std::slice::from_ref(&unknown_action)
            ),
            Err(policy::PolicyError::UnknownAction(_))
        ),
        "strict validation must continue to reject an unresolved action"
    );

    for invalid in [
        r#"permit(principal, action, resource"#,
        r#"permit(principal, action, resource) when { missing_macro(action) };"#,
        r#"permit(principal, action, resource)
           when { Risk::Elevated("host").high == false };"#,
    ] {
        assert!(
            PolicyEngine::validate_staged(&[source("invalid.dw", invalid)]).is_err(),
            "staged validation must reject syntax, macro, and provider faults: {invalid}"
        );
    }
}

#[test]
fn an_incompatible_schema_cannot_change_a_ready_authority_or_later_staging() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let sources = vec![
        source(
            "canonical.dw",
            r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
        ),
        source(
            "path.dw",
            r#"permit(principal, action, resource)
               when {
                   context has input
                   && context.input has path
                   && context.input.path like "*/secret"
               };"#,
        ),
    ];
    {
        let authority = staged(sources.clone(), &path);
        assert!(
            authority
                .decide(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent(),
                    &shell_request(),
                )
                .is_allow()
        );
    }
    let before = {
        let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
        (
            durable.list(),
            durable.policy_source(),
            durable.action_schema(),
            durable.event_schema(),
            durable.log_offset(),
        )
    };

    let authority = staged(sources.clone(), &path);
    assert!(matches!(
        authority
            .stage_mcp_schema("bad", generated("bad", "read", "path", "integer"))
            .expect("schema rejection is not terminal"),
        SchemaStage::Rejected { .. }
    ));
    let rejected_arguments = json!({"path": 7});
    assert!(matches!(
        authority.decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::McpCall {
                server: "bad",
                method: "tools/call",
                tool: Some("read"),
                prompt: None,
                uri: None,
                arguments: Some(&rejected_arguments),
            },
        ),
        Decision::Deny {
            reason: DenyReason::InternalFault,
            ..
        }
    ));
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "the same ready authority must remain operational after rejection"
    );
    authority
        .finish_mcp_discovery()
        .expect("rejection must not move the ready authority back to blocked");
    drop(authority);

    let after_rejection = {
        let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
        (
            durable.list(),
            durable.policy_source(),
            durable.action_schema(),
            durable.event_schema(),
            durable.log_offset(),
        )
    };
    assert_eq!(&after_rejection.0, &before.0);
    assert_eq!(&after_rejection.1, &before.1);
    assert_eq!(&after_rejection.2, &before.2);
    assert_eq!(&after_rejection.3, &before.3);
    let log = DurableLog::open(&path).expect("the durable log opens");
    let mut appended = Vec::new();
    log.scan_from(before.4, |_, bytes| {
        appended.push(Record::decode(bytes).expect("the request record decodes"));
    })
    .expect("the request record scans");
    assert_eq!(
        appended.len(),
        1,
        "schema rejection and its rejected action must append no durable record"
    );
    assert!(
        matches!(appended[0], Record::Event(_)),
        "the same-instance decision must be the only durable change after rejection"
    );
    drop(log);

    let authority = staged(sources, &path);
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "the prior authority must remain operational"
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "query", "string"))
            .expect("a later compatible schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        },
        "the rejected fragment must not remain in the cumulative schema map"
    );
    drop(authority);

    let after = {
        let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
        (
            durable.list(),
            durable.policy_source(),
            durable.action_schema(),
            durable.event_schema(),
            durable.log_offset(),
        )
    };
    assert_ne!(
        after.2, before.2,
        "the later accepted schema must change the durable action schema"
    );
}

#[test]
fn discovering_staging_revalidates_every_ready_candidate() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![
            source(
                "alpha.dw",
                r#"permit(principal, action, resource)
                   when {
                       context has input
                       && context.input has path
                       && context.input.path like "*/secret"
                       && alpha::Action::"read" == alpha::Action::"read"
                   };"#,
            ),
            source(
                "missing.dw",
                r#"permit(principal, action == missing::Action::"never", resource);"#,
            ),
            source(
                "coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { ["alpha", "missing"].contains(context.input.server) };"#,
            ),
        ],
        &history.path().join("dogwood.redb"),
    );

    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("Alpha stages"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    assert!(matches!(
        authority
            .stage_mcp_schema("beta", generated("beta", "read", "path", "integer"))
            .expect("candidate rejection is not terminal"),
        SchemaStage::Rejected { .. }
    ));
    assert_eq!(
        authority
            .stage_mcp_schema("missing", generated("missing", "never", "query", "string"))
            .expect("the rejected schema was not retained"),
        SchemaStage::Accepted {
            authority_ready: true,
        },
        "each proposal must preserve every ready candidate"
    );
}

#[test]
fn discovering_installs_the_subset_and_holds_pending_typed_rules() {
    // This replaces the old "a partial set installs no durable authority": open now commits the
    // schema-independent subset durably (so the box serves during discovery), and the still-pending
    // typed rules stay out of the durable authority until their schema stages.
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let authority = staged(
        vec![
            source(
                "alpha-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "alpha" };"#,
            ),
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "beta-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "beta" };"#,
            ),
            source(
                "beta.dw",
                r#"permit(principal, action == beta::Action::"write", resource);"#,
            ),
        ],
        &path,
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("Alpha stages in memory"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    drop(authority);

    let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
    assert!(
        durable.has_policy(),
        "the schema-independent subset installs durably during discovery"
    );
    let installed = durable.list();
    assert!(
        installed
            .iter()
            .any(|entry| entry.statement.contains(r#"alpha::Action::"read""#)),
        "the staged Alpha tool is installed"
    );
    assert!(
        installed
            .iter()
            .all(|entry| !entry.statement.contains(r#"beta::Action::"write""#)),
        "the still-pending Beta tool is not installed until its schema stages"
    );
}

#[test]
fn partial_staging_retains_the_unchanged_authority_and_adds_the_staged_tool() {
    // This replaces "partial staging writes nothing durable": a partial stage now installs the
    // newly-ready typed rule. The surviving invariant is that an UNCHANGED policy keeps its
    // durable identity (token) and its recorded temporal history is not replayed. The coarse permit
    // lives in the existing store too, so the open-time subset commit reconciles to a no-op.
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let canonical = r#"permit(principal, action == Box::Action::"http:request", resource);"#;
    let coarse = r#"permit(principal, action == Box::Action::"mcp:call", resource)
                    when { context.input.server == "alpha" };"#;
    let governed = GovernedBox::assigned("test-box");
    let principal = Principal::agent();
    {
        let authority = PolicyEngine::open(
            vec![
                source("canonical.dw", canonical),
                source("coarse.dw", coarse),
            ],
            &path,
        )
        .expect("the existing authority installs");
        assert!(
            authority
                .decide(&governed, &principal, &http_request())
                .is_allow()
        );
        authority
            .record(
                &governed,
                &principal,
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1",
                    delivery: Delivery::Completed { bytes: 10 },
                    status: Some(200),
                },
            )
            .expect("the existing authority records history");
    }

    let canonical_statement = |durable: &DurableTemporalEngine| {
        durable
            .list()
            .into_iter()
            .find(|entry| entry.statement.contains(r#"Box::Action::"http:request""#))
            .expect("the canonical policy is installed")
    };
    let event_count = |path: &Path| {
        let log = DurableLog::open(path).expect("the durable log opens");
        let mut events = 0usize;
        log.scan_from(0, |_, bytes| {
            if matches!(
                Record::decode(bytes).expect("the record decodes"),
                Record::Event(_)
            ) {
                events += 1;
            }
        })
        .expect("the records scan");
        events
    };

    let (canonical_before, events_before) = {
        let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
        let token = canonical_statement(&durable).token;
        drop(durable);
        (token, event_count(&path))
    };

    let authority = staged(
        vec![
            source("canonical.dw", canonical),
            source("coarse.dw", coarse),
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "beta-coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "beta" };"#,
            ),
            source(
                "beta.dw",
                r#"permit(principal, action == beta::Action::"write", resource);"#,
            ),
        ],
        &path,
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("Alpha stages in memory"),
        SchemaStage::Accepted {
            authority_ready: false,
        }
    );
    drop(authority);

    let durable = DurableTemporalEngine::open(&path, 10_000).expect("the store reopens");
    assert_eq!(
        canonical_statement(&durable).token,
        canonical_before,
        "the unchanged canonical policy must keep its durable identity across staging"
    );
    assert!(
        durable
            .list()
            .iter()
            .any(|entry| entry.statement.contains(r#"alpha::Action::"read""#)),
        "the staged Alpha tool is now installed"
    );
    assert!(
        durable
            .list()
            .iter()
            .all(|entry| !entry.statement.contains(r#"beta::Action::"write""#)),
        "the still-pending Beta tool is not installed"
    );
    drop(durable);
    assert_eq!(
        event_count(&path),
        events_before,
        "partial staging must not replay or drop the recorded temporal history"
    );
}

#[test]
fn discovering_record_observes_an_outcome() {
    // This replaces "a blocked authority refuses an outcome": the box serves decisions while
    // Discovering (the schema-independent subset is committed at open), so `record` observes an
    // outcome there rather than erroring. The coarse permit is in the existing store too, so the
    // open-time subset commit reconciles to a no-op.
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let canonical = r#"permit(principal, action == Box::Action::"http:request", resource);"#;
    let coarse = r#"permit(principal, action == Box::Action::"mcp:call", resource)
                    when { context.input.server == "alpha" };"#;
    {
        PolicyEngine::open(
            vec![
                source("canonical.dw", canonical),
                source("coarse.dw", coarse),
            ],
            &path,
        )
        .expect("the existing authority installs");
    }
    let before_events = {
        let log = DurableLog::open(&path).expect("the durable log opens");
        let mut events = 0usize;
        log.scan_from(0, |_, bytes| {
            if matches!(
                Record::decode(bytes).expect("the record decodes"),
                Record::Event(_)
            ) {
                events += 1;
            }
        })
        .expect("the records scan");
        events
    };

    let authority = staged(
        vec![
            source("canonical.dw", canonical),
            source("coarse.dw", coarse),
            source(
                "pending.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
        ],
        &path,
    );
    authority
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Outcome::Http {
                host: "api.example.com",
                port: 443,
                method: "POST",
                path: "/v1",
                delivery: Delivery::Completed { bytes: 10 },
                status: Some(200),
            },
        )
        .expect("record observes an outcome while discovering");
    drop(authority);

    let log = DurableLog::open(&path).expect("the durable log opens");
    let mut after_events = 0usize;
    log.scan_from(0, |_, bytes| {
        if matches!(
            Record::decode(bytes).expect("the record decodes"),
            Record::Event(_)
        ) {
            after_events += 1;
        }
    })
    .expect("the records scan");
    assert_eq!(
        after_events,
        before_events + 1,
        "the outcome recorded while discovering must append to durable history"
    );
}

#[test]
fn schema_arrival_order_produces_the_same_durable_authority() {
    let sources = || {
        vec![
            source(
                "coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { ["alpha", "beta"].contains(context.input.server) };"#,
            ),
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "beta.dw",
                r#"permit(principal, action == beta::Action::"write", resource);"#,
            ),
        ]
    };
    let alpha = generated("alpha", "read", "path", "string");
    let beta = generated("beta", "write", "value", "integer");
    let first = tempfile::tempdir().expect("first history");
    let second = tempfile::tempdir().expect("second history");
    let first_path = first.path().join("dogwood.redb");
    let second_path = second.path().join("dogwood.redb");

    let alpha_first = staged(sources(), &first_path);
    alpha_first
        .stage_mcp_schema("alpha", alpha.clone())
        .expect("Alpha stages");
    alpha_first
        .stage_mcp_schema("beta", beta.clone())
        .expect("Beta stages");
    drop(alpha_first);

    let beta_first = staged(sources(), &second_path);
    beta_first
        .stage_mcp_schema("beta", beta)
        .expect("Beta stages");
    beta_first
        .stage_mcp_schema("alpha", alpha)
        .expect("Alpha stages");
    drop(beta_first);

    let first_store =
        DurableTemporalEngine::open(&first_path, 10_000).expect("first store reopens");
    let second_store =
        DurableTemporalEngine::open(&second_path, 10_000).expect("second store reopens");
    assert_eq!(first_store.action_schema(), second_store.action_schema());
    // Each typed rule is added as it stages, so the serialized policy ORDER now follows arrival
    // order. The invariant that survives is that both stores hold the SAME SET of policies (Cedar
    // is order-independent under deny-overrides), so compare the sorted statements.
    let mut first_statements: Vec<_> = first_store
        .list()
        .into_iter()
        .map(|entry| entry.statement)
        .collect();
    let mut second_statements: Vec<_> = second_store
        .list()
        .into_iter()
        .map(|entry| entry.statement)
        .collect();
    first_statements.sort();
    second_statements.sort();
    assert_eq!(
        first_statements, second_statements,
        "schema arrival order must produce the same set of durable policies"
    );
}

#[test]
fn restart_recovers_a_namespaced_event_with_an_escaped_tool_id() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let tool = "read.\"wiki\":item";
    let tools = serde_json::json!({
        "result": {
            "tools": [{
                "name": tool,
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            }]
        }
    });
    let fragment =
        generate_mcp_schema("issues-mcp", &tools.to_string()).expect("the schema generates");
    let policy = source(
        "escaped.dw",
        r#"
permit(principal, action == issues_mcp::Action::"read.\"wiki\":item", resource);
permit(principal, action == Box::Action::"shell:exec", resource);
forbid(principal, action == Box::Action::"shell:exec", resource)
when temporal {
    formerly within 60s (
        issues_mcp::Action::"read.\"wiki\":item"::request{
            input.path: "/workspace/secret"
        }
    )
};
"#,
    );
    let arguments = json!({"path": "/workspace/secret"});

    {
        let authority = PolicyEngine::open_with_mcp_schemas(
            vec![policy.clone()],
            std::slice::from_ref(&fragment),
            &path,
        )
        .expect("the namespaced policy opens");
        assert!(
            authority
                .refine_tool_call(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent(),
                    "issues-mcp",
                    tool,
                    &arguments,
                )
                .is_allow()
        );
    }

    let recovered = PolicyEngine::open_with_mcp_schemas(vec![policy], &[fragment], &path)
        .expect("the namespaced history recovers");
    assert!(
        !recovered
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "the recovered namespaced request must satisfy the temporal forbid"
    );
}

#[test]
fn upgrading_retires_global_identities_without_moving_their_temporal_state() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let old_fragment = r#"
namespace Mcp::alpha {
    type readInput = { path: String };
}
action "alpha___read" appliesTo {
    principal: [Agent],
    resource: [Resource],
    context: { input: Mcp::alpha::readInput }
};
"#;
    let mut old_canonical =
        policy::compose_action_schema(&[]).expect("the canonical schema composes");
    old_canonical = old_canonical.replacen("namespace Box {\n", "", 1);
    let closing_brace = old_canonical
        .rfind('}')
        .expect("the Box namespace has a closing brace");
    old_canonical.remove(closing_brace);
    let old_schema = format!("{old_canonical}\n{old_fragment}");
    let old_policy = r#"
permit(principal, action == Action::"fs:read", resource);
permit(principal, action == Action::"fs:write", resource);
permit(principal, action == Action::"shell:exec", resource);
permit(principal, action == Action::"alpha___read", resource);
forbid(principal, action == Action::"shell:exec", resource)
when temporal {
    formerly within 60s (
        Action::"fs:read"::request{
            input.path: "/fixed",
            input.operation: FsReadOperation::"read_content"
        }
    )
};
forbid(principal, action == Action::"fs:write", resource)
when temporal {
    formerly within 60s (
        Action::"alpha___read"::request{ input.path: "/tool" }
    )
};
"#;
    {
        let mut durable = DurableTemporalEngine::open(&path, 10_000).expect("the old store opens");
        durable
            .install(
                old_policy,
                &old_schema,
                Some(policy::event_schema_source()),
                None,
            )
            .expect("the old authority installs");
        let fixed_input = Value::Object(std::collections::BTreeMap::from([
            ("path".to_string(), Value::String("/fixed".to_string())),
            (
                "operation".to_string(),
                Value::Entity {
                    ty: "FsReadOperation".to_string(),
                    id: "read_content".to_string(),
                },
            ),
        ]));
        durable
            .submit(
                Event::builder_for(&["Action"], "fs:read", "request")
                    .principal_for("Agent", "self")
                    .resource_for("Resource", "unused")
                    .logged_field("input", fixed_input.clone())
                    .request_context_field("input", fixed_input),
            )
            .expect("the fixed event records");
        let tool_input = Value::Object(std::collections::BTreeMap::from([(
            "path".to_string(),
            Value::String("/tool".to_string()),
        )]));
        durable
            .submit(
                Event::builder_for(&["Action"], "alpha___read", "request")
                    .principal_for("Agent", "self")
                    .resource_for("Resource", "unused")
                    .logged_field("input", tool_input.clone())
                    .request_context_field("input", tool_input),
            )
            .expect("the old tool event records");
    }

    let new_policy = r#"
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == alpha::Action::"read", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
forbid(principal, action == Box::Action::"shell:exec", resource)
when temporal {
    formerly within 60s (
        Box::Action::"fs:read"::request{
            input.path: "/fixed",
            input.operation: Box::FsReadOperation::"read_content"
        }
    )
};
forbid(principal, action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 60s (
        alpha::Action::"read"::request{ input.path: "/tool" }
    )
};
"#;
    let authority = staged(vec![source("upgrade.dw", new_policy)], &path);
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the namespaced schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "the Box action identity must start with empty temporal state"
    );
    let resolver =
        policy::PathResolver::over([PathBuf::from("/")]).expect("the root resolver opens");
    let fixed_path = resolver
        .approve_virtual(Path::new("/fixed"))
        .expect("the fixed path resolves");
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &fixed_path,
                    operation: policy::FsOperation::ReadContent,
                },
            )
            .is_allow(),
        "the new fixed request records under Box"
    );
    assert!(
        !authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &shell_request(),
            )
            .is_allow(),
        "new Box temporal state must govern later requests"
    );
    let write_path = resolver
        .approve_virtual(Path::new("/after-upgrade"))
        .expect("the write path resolves");
    assert!(
        authority
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &write_path,
                    operation: policy::FsOperation::WriteContent,
                },
            )
            .is_allow(),
        "the namespaced temporal identity must start empty"
    );
    drop(authority);

    let durable = DurableTemporalEngine::open(&path, 10_000).expect("the upgraded store opens");
    assert!(
        durable
            .list()
            .iter()
            .all(|entry| !entry.statement.contains("alpha___read")),
        "the upgraded authority must contain no global per-tool identity"
    );
}

#[test]
fn an_existing_store_uses_one_batch_and_retains_temporal_state() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let governed = GovernedBox::assigned("test-box");
    let principal = Principal::agent();

    // The coarse permit lives in the existing store AND the staged bundle, so the open-time subset
    // commit reconciles to a no-op and the only durable transition is the staged tool's one batch.
    let coarse = r#"permit(principal, action == Box::Action::"mcp:call", resource)
                    when { context.input.server == "alpha" };"#;
    {
        let authority = PolicyEngine::open(
            vec![source("budget.dw", BUDGET), source("coarse.dw", coarse)],
            &path,
        )
        .expect("budget opens");
        assert!(
            authority
                .decide(&governed, &principal, &http_request())
                .is_allow()
        );
        authority
            .record(
                &governed,
                &principal,
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1",
                    delivery: Delivery::Completed { bytes: 150 },
                    status: Some(200),
                },
            )
            .expect("the delivery records");
    }

    let (before_offset, retained_before) = {
        let durable =
            DurableTemporalEngine::open(&path, 10_000).expect("the original store reopens");
        let retained = durable
            .list()
            .into_iter()
            .find(|entry| entry.statement.contains("total < 100"))
            .expect("the budget policy is installed");
        (durable.log_offset(), retained)
    };

    let authority = staged(
        vec![
            source("budget.dw", BUDGET),
            source("coarse.dw", coarse),
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
        ],
        &path,
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the complete bundle commits"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        !authority
            .decide(&governed, &principal, &http_request())
            .is_allow(),
        "the unchanged temporal policy must retain its exhausted budget"
    );
    drop(authority);

    let durable = DurableTemporalEngine::open(&path, 10_000).expect("the staged store reopens");
    let retained_after = durable
        .list()
        .into_iter()
        .find(|entry| entry.statement == retained_before.statement)
        .expect("the unchanged budget policy remains installed");
    assert_eq!(
        retained_after.token, retained_before.token,
        "targeted reconciliation must retain the policy identity"
    );
    drop(durable);

    let log = DurableLog::open(&path).expect("the durable log opens");
    let mut transition = Vec::new();
    log.scan_from(before_offset, |_, bytes| {
        transition.push(Record::decode(bytes).expect("the transition record decodes"));
    })
    .expect("the transition records scan");
    assert_eq!(
        transition.len(),
        3,
        "the log must contain the two-record transition and the later verification request"
    );
    assert!(matches!(transition[0], Record::SetActionSchema { .. }));
    assert!(matches!(transition[1], Record::Add { .. }));
    assert!(matches!(transition[2], Record::Event(_)));
    assert_eq!(
        transition[0].timestamp(),
        transition[1].timestamp(),
        "all targeted changes must commit in one durable batch"
    );
}

#[test]
fn an_existing_store_deletes_obsolete_policies_before_replacing_the_schema() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let obsolete = generated("obsolete", "read", "path", "string");
    {
        PolicyEngine::open_with_mcp_schemas(
            vec![source(
                "obsolete.dw",
                r#"permit(principal, action == obsolete::Action::"read", resource);"#,
            )],
            &[obsolete],
            &path,
        )
        .expect("the obsolete authority installs");
    }
    let before_offset = DurableTemporalEngine::open(&path, 10_000)
        .expect("the existing store reopens")
        .log_offset();

    let authority = staged(
        vec![
            source(
                "alpha.dw",
                r#"permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            source(
                "coarse.dw",
                r#"permit(principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "alpha" };"#,
            ),
        ],
        &path,
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the replacement authority commits"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    drop(authority);

    let durable = DurableTemporalEngine::open(&path, 10_000).expect("the staged store reopens");
    let installed = durable.list();
    assert!(
        installed
            .iter()
            .any(|entry| entry.statement.contains(r#"alpha::Action::"read""#))
    );
    assert!(
        installed
            .iter()
            .all(|entry| !entry.statement.contains(r#"obsolete::Action::"read""#)),
        "the obsolete per-tool policy must be durably deleted, not shadowed"
    );
    drop(durable);

    // Obsolete removal now happens at the open-time subset commit (its target no longer
    // names `obsolete`), and the staged tool is added at the stage commit. Each commit is one
    // atomic batch; the invariant that survives is that obsolete is DELETED (before the alpha add)
    // and every record in a batch shares one timestamp.
    let log = DurableLog::open(&path).expect("the durable log opens");
    let mut transition = Vec::new();
    log.scan_from(before_offset, |_, bytes| {
        transition.push(Record::decode(bytes).expect("the transition record decodes"));
    })
    .expect("the transition records scan");
    let delete_index = transition
        .iter()
        .position(|record| matches!(record, Record::Delete { .. }))
        .expect("the obsolete policy is durably deleted");
    let alpha_add_index = transition
        .iter()
        .rposition(|record| matches!(record, Record::Add { .. }))
        .expect("the replacement policy is durably added");
    assert!(
        delete_index < alpha_add_index,
        "the obsolete delete must precede the replacement add"
    );
    // Each batch commits atomically: records sharing a timestamp form one durable transaction.
    let batches: std::collections::BTreeSet<_> =
        transition.iter().map(|record| record.timestamp()).collect();
    assert!(
        !batches.is_empty(),
        "the transition must contain at least one durable batch"
    );
}
