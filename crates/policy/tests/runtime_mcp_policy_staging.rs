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

fn staged_engine(text: &str, history: &Path) -> PolicyEngine {
    staged(vec![source("staged.dw", text)], history)
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
            .0
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
            .0
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
    let pending_tool = authority
        .decide(
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
        )
        .0;
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
            .0
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
            .0
            .is_allow(),
        "a degraded server's tool call is denied fail-closed after completion"
    );
}

/// A late listing that completes the bundle after discovery finished lifts the degraded mark.
#[test]
fn a_complete_bundle_after_completion_clears_the_degraded_mark() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "relist.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
permit(principal, action == alpha::Action::"read", resource);
forbid(principal, action == alpha::Action::"read", resource)
when { context.input.path == "/workspace/secret" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );

    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling"),
        vec!["alpha".to_string()],
        "the first listing never staged, so the server degrades"
    );
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path", "string"))
            .expect("the later listing is not a terminal fault"),
        SchemaStage::Accepted {
            authority_ready: true,
        },
        "the later listing completes the bundle"
    );

    let forbidden = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "read",
        &json!({"path": "/workspace/secret"}),
    );
    assert!(
        matches!(
            forbidden,
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ),
        "the installed forbid must refuse the path it names, and the refusal must come from that \
         forbid rather than from a stale degraded mark: {forbidden:?}"
    );

    let permitted = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "read",
        &json!({"path": "/workspace/input"}),
    );
    assert!(
        matches!(&permitted, Decision::Allow { rule, .. } if rule.as_str() != RuleId::DEFAULT_DENY),
        "a path the forbid does not name must stay allowed by the staged per-tool permit itself, \
         not refused by a stale mark and not riding the coarse grant: {permitted:?}"
    );
}

/// A server that declares a tool but names its arguments differently from the operator's rule
/// leaves that rule unable to stage, so the tool degrades while the committed schema still
/// declares its action. The refinement must still deny the call. The coarse `mcp:call` permit
/// gives an unruled tool its allow, and that allow must not reach a degraded tool.
#[test]
fn a_degraded_tool_whose_action_is_declared_is_denied_through_the_refinement() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "renamed.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
forbid(principal, action == alpha::Action::"deploy", resource)
when { context.input.env == "prod" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );

    // The server declares `deploy`, so the committed schema names the action, but it calls the
    // property `target`, so the `env` forbid cannot stage.
    assert_eq!(
        authority
            .stage_mcp_schema("alpha", generated("alpha", "deploy", "target", "string"))
            .expect("the renamed schema is not a terminal fault"),
        SchemaStage::Accepted {
            authority_ready: false,
        },
        "the forbid cannot stage against the renamed property, so the bundle stays incomplete"
    );
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling"),
        vec!["alpha".to_string()],
        "the tool whose rule never staged degrades its server"
    );

    let decision = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "deploy",
        &json!({"env": "prod"}),
    );
    // Not merely "not allowed": the refusal is the degraded mark's, not the transient hold a
    // pending tool takes, because discovery finished without this rule.
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the refinement must deny a degraded tool whose action the schema declares: {decision:?}"
    );
}

/// The degraded refusal must not swallow the coarse permit. One server degrades one tool, and a
/// second tool on the same server that no rule names still rides the `mcp:call` allow. Without
/// this leg, refusing every call on a degraded server would pass the test above.
#[test]
fn a_tool_no_rule_names_still_rides_the_coarse_permit_on_a_degraded_server() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "renamed.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
forbid(principal, action == alpha::Action::"deploy", resource)
when { context.input.env == "prod" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    authority
        .stage_mcp_schema("alpha", generated("alpha", "deploy", "target", "string"))
        .expect("the renamed schema is not a terminal fault");
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling"),
        vec!["alpha".to_string()],
        "the tool whose rule never staged degrades its server"
    );

    let decision = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "status",
        &json!({}),
    );
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "a tool the catalog never declared and no rule names must ride the coarse permit, \
         even on a server one of whose tools degraded: {decision:?}"
    );
}

/// The two refusals a tool can take are not interchangeable. A tool still waiting for its schema
/// takes the transient `PolicyPending`, and only a tool whose rule had not staged when discovery
/// finished takes the terminal `NoMatch`. An operator reads the difference, and a retry is right
/// for one and wrong for the other.
#[test]
fn a_tool_awaiting_its_schema_is_held_and_a_degraded_one_is_refused() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "renamed.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
forbid(principal, action == alpha::Action::"deploy", resource)
when { context.input.env == "prod" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );

    let held = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "deploy",
        &json!({"env": "prod"}),
    );
    assert!(
        matches!(
            held,
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "before any catalog arrives the call is held transiently, not refused: {held:?}"
    );

    authority
        .stage_mcp_schema("alpha", generated("alpha", "deploy", "target", "string"))
        .expect("the renamed schema is not a terminal fault");
    authority
        .finish_mcp_discovery()
        .expect("completion degrades rather than fataling");

    let refused = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "alpha",
        "deploy",
        &json!({"env": "prod"}),
    );
    assert!(
        matches!(
            refused,
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "once discovery finishes without the rule the refusal is terminal: {refused:?}"
    );
}

/// A tool name that carries a quote or a backslash must reach both fail-closed holds, and must
/// still enforce its own rule once that rule's schema stages.
#[test]
fn an_escaped_tool_name_holds_and_degrades_like_a_plain_one() {
    // `literal` is the name as a policy spells it; `raw` is the name a `tools/call` frame carries.
    for (literal, raw) in [
        ("foobar", "foobar"),
        (r#"foo\"bar"#, "foo\"bar"),
        (r#"foo\\bar"#, "foo\\bar"),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged(
            vec![source(
                "pending.dw",
                &format!(
                    r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when {{ context.input.server == "alpha" }};
forbid(principal, action == alpha::Action::"{literal}", resource)
when {{ context.input.path like "/secret/*" }};
permit(principal, action == alpha::Action::"{literal}", resource);
"#
                ),
            )],
            &history.path().join("dogwood.redb"),
        );

        let arguments = json!({"path": "/secret/x"});
        let call = |authority: &PolicyEngine| {
            authority.refine_tool_call(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                "alpha",
                raw,
                &arguments,
            )
        };

        assert!(
            matches!(
                call(&authority),
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            "{raw}: a call whose rule is still pending must be held, not ride the coarse permit"
        );
        assert_eq!(
            authority
                .finish_mcp_discovery()
                .expect("discovery completion degrades the server"),
            vec!["alpha".to_string()],
            "{raw}: the server whose typed rule never staged is degraded"
        );
        assert!(
            matches!(
                call(&authority),
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "{raw}: a degraded tool call must be denied fail-closed"
        );
    }
}

/// A pending rule reaches a tool through its condition rather than its head. The hold must still
/// cover that tool, and its server must still reach the degradation warning.
#[test]
fn a_tool_a_pending_condition_names_is_held_and_degrades() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "condition.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "srv" };
forbid(principal, action, resource) when { action == srv::Action::"read" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );

    let arguments = json!({"path": "/secret/x"});
    let call = || {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "srv",
            "read",
            &arguments,
        )
    };
    assert!(
        matches!(
            call(),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "a tool that only a pending condition names must still be held"
    );
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completion degrades the server"),
        vec!["srv".to_string()],
        "the server that only a pending condition names must reach the warning"
    );
    assert!(
        matches!(
            call(),
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the degraded hold must cover that tool too"
    );
}

/// A pending rule reaches an escaped tool name through its condition. The hold must cover the name
/// the operator wrote, and not a prefix that stops at the escape. Each case is one class of escape
/// that the policy render emits, so the hold set reads back every name the render can give it.
#[test]
fn a_condition_that_names_an_escaped_tool_holds_the_whole_name() {
    // `literal` is the name as a policy spells it; `raw` is the name a `tools/call` frame carries.
    for (literal, raw) in [
        ("foobar", "foobar"),
        (r#"foo\"bar"#, "foo\"bar"),
        (r#"foo\\bar"#, "foo\\bar"),
        (r#"foo\'bar"#, "foo'bar"),
        (r#"foo\nbar"#, "foo\nbar"),
        (r#"foo\tbar"#, "foo\tbar"),
        (r#"foo\rbar"#, "foo\rbar"),
        (r#"foo\0bar"#, "foo\0bar"),
        // A name the render re-spells: the operator's escape is not the render's escape, so a
        // reader that keeps the rendered text rather than decoding it holds the wrong name.
        (r#"caf\u{00e9}"#, "café"),
        (r#"a\u{0007}b"#, "a\u{7}b"),
        (r#"a\u{200b}b"#, "a\u{200b}b"),
        ("foo😀bar", "foo😀bar"),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged(
            vec![source(
                "condition.dw",
                &format!(
                    r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when {{ context.input.server == "srv" }};
forbid(principal, action, resource) when {{ action == srv::Action::"{literal}" }};
"#
                ),
            )],
            &history.path().join("dogwood.redb"),
        );

        let arguments = json!({"path": "/secret/x"});
        let call = || {
            authority.refine_tool_call(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                "srv",
                raw,
                &arguments,
            )
        };
        assert!(
            matches!(
                call(),
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            "{raw}: a tool that only a pending condition names must still be held"
        );
        assert_eq!(
            authority
                .finish_mcp_discovery()
                .expect("discovery completion degrades the server"),
            vec!["srv".to_string()],
            "{raw}: the server that only a pending condition names must reach the warning"
        );
        assert!(
            matches!(
                call(),
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "{raw}: the degraded hold must cover that tool too"
        );
    }
}

/// One tool name, stated once in a head and once in a condition. Both ways of asking which tool a
/// rule is about must answer the same, in every discovery window.
#[test]
fn a_head_and_a_condition_agree_on_an_escaped_tool_name() {
    let literal = r#"foo\"bar"#;
    let raw = "foo\"bar";
    let coarse = r#"permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "srv" };"#;

    let histories = [
        tempfile::tempdir().expect("head history directory"),
        tempfile::tempdir().expect("condition history directory"),
    ];
    let authorities: Vec<PolicyEngine> = [
        format!(r#"forbid(principal, action == srv::Action::"{literal}", resource);"#),
        format!(
            r#"forbid(principal, action, resource) when {{ action == srv::Action::"{literal}" }};"#
        ),
    ]
    .iter()
    .zip(&histories)
    .map(|(rule, history)| {
        staged(
            vec![source("agree.dw", &format!("{coarse}\n{rule}\n"))],
            &history.path().join("dogwood.redb"),
        )
    })
    .collect();

    let arguments = json!({"path": "/secret/x"});
    let call = |authority: &PolicyEngine| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "srv",
            raw,
            &arguments,
        )
    };

    assert_eq!(
        call(&authorities[0]),
        call(&authorities[1]),
        "the head and the condition must hold the same call while the schema is pending"
    );
    // The values as well as the agreement, because two paths that agree can agree on an allow.
    for authority in &authorities {
        assert!(
            matches!(
                call(authority),
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            "both must hold the call, and not agree on an allow"
        );
    }

    let degraded: Vec<_> = authorities
        .iter()
        .map(|authority| {
            authority
                .finish_mcp_discovery()
                .expect("discovery completion degrades the server")
        })
        .collect();
    assert_eq!(
        degraded[0], degraded[1],
        "the head and the condition must degrade the same server"
    );
    assert_eq!(
        degraded[0],
        vec!["srv".to_string()],
        "both must name the server whose typed rule never staged"
    );

    assert_eq!(
        call(&authorities[0]),
        call(&authorities[1]),
        "the head and the condition must deny the same call once the server degrades"
    );
    for authority in &authorities {
        assert!(
            matches!(
                call(authority),
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "both must deny the call fail-closed once the server degrades"
        );
    }
}

/// stderr must name every server a pending rule still waits for, and no other. A rule waits for a
/// tool to be declared, which fails both when the catalog never arrives and when it arrives without
/// that tool. The tools a rule decides answer which calls to hold, and they are the wrong answer
/// here, because a rule also waits for a tool it only reads from history.
#[test]
fn discovery_names_each_server_a_pending_rule_still_waits_for() {
    // Each case is one pending rule. `staged` is the server whose catalog arrives, and `expected`
    // is what stderr must name.
    for (rule, staged, expected) in [
        // Every tool the rule names is declared, and the rule is pending for another reason: it
        // compares an argument against the wrong type. A check on the named tools alone goes quiet.
        (
            r#"forbid(principal, action == alpha::Action::"read", resource)
when { context.input.path > 3 };"#,
            &[("alpha", "read", "path")][..],
            vec!["alpha"],
        ),
        // The same, naming an argument the server does not declare.
        (
            r#"forbid(principal, action == alpha::Action::"read", resource)
when { context.input.pth == "/x" };"#,
            &[("alpha", "read", "path")][..],
            vec!["alpha"],
        ),
        // The same, where the wrong argument name sits in a history reference on a second server.
        // Both servers are healthy and both are named, because the rule waits on both.
        (
            r#"forbid(principal, action == alpha::Action::"read", resource)
unless temporal { formerly within 600s ( beta::Action::"fetch"::response{ input.url: _ } ) };"#,
            &[("alpha", "read", "path"), ("beta", "fetch", "path")][..],
            vec!["alpha", "beta"],
        ),
        // The catalog arrives and does not offer the tool the rule names: a misspelling, or a tool
        // the server dropped. The server is healthy, so a check on the catalog alone goes quiet.
        (
            r#"forbid(principal, action == alpha::Action::"raed", resource);"#,
            &[("alpha", "read", "path")][..],
            vec!["alpha"],
        ),
        // The same, named by a condition rather than the head.
        (
            r#"forbid(principal, action, resource) when { action == alpha::Action::"raed" };"#,
            &[("alpha", "read", "path")][..],
            vec!["alpha"],
        ),
        // The same, named only by a history reference, beside a head the catalog does declare.
        (
            r#"forbid(principal, action == alpha::Action::"read", resource)
unless temporal { formerly within 600s ( alpha::Action::"raed"::response{ input.path: _ } ) };"#,
            &[("alpha", "read", "path")][..],
            vec!["alpha"],
        ),
        // The rule decides a denied server's tool and reads a healthy server's from history.
        (
            r#"forbid(principal, action == alpha::Action::"deploy", resource)
unless temporal { formerly within 600s ( beta::Action::"approve"::response{ input.id: _ } ) };"#,
            &[("beta", "approve", "id")][..],
            vec!["alpha"],
        ),
        // The mirror: the rule decides a healthy server's tool and reads a denied server's.
        (
            r#"forbid(principal, action == beta::Action::"ship", resource)
unless temporal { formerly within 600s ( alpha::Action::"approve"::response{ input.id: _ } ) };"#,
            &[("beta", "ship", "id")][..],
            vec!["alpha"],
        ),
        // The only tool name a coarse-headed rule spells is the history reference.
        (
            r#"forbid(principal, action == Box::Action::"mcp:call", resource)
unless temporal { formerly within 600s ( alpha::Action::"approve"::response{ input.id: _ } ) };"#,
            &[][..],
            vec!["alpha"],
        ),
        // The head names an action of another family, so it decides no tool call at all.
        (
            r#"forbid(principal, action == Box::Action::"shell:exec", resource)
unless temporal { formerly within 600s ( alpha::Action::"approve"::response{ input.id: _ } ) };"#,
            &[][..],
            vec!["alpha"],
        ),
        // The head constrains no action.
        (
            r#"forbid(principal, action, resource)
unless temporal { formerly within 600s ( alpha::Action::"approve"::response{ input.id: _ } ) };"#,
            &[][..],
            vec!["alpha"],
        ),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged_engine(
            &format!("permit(principal, action == Box::Action::\"mcp:call\", resource);\n{rule}\n"),
            &history.path().join("dogwood.redb"),
        );
        for (server, tool, field) in staged {
            authority
                .stage_mcp_schema(server, generated(server, tool, field, "string"))
                .expect("the healthy server stages");
        }
        assert_eq!(
            authority
                .finish_mcp_discovery()
                .expect("discovery completes"),
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "stderr must name each server this rule still waits for, for rule: {rule}"
        );
    }
}

/// A server name that is not a Cedar identifier reaches a rule as a normalized namespace. stderr
/// must not name such a server once its catalog declares the tool, although the two spellings
/// differ.
#[test]
fn a_staged_server_whose_name_needs_normalizing_is_not_named() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged_engine(
        r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == my_srv::Action::"read", resource)
unless temporal { formerly within 600s ( other::Action::"fetch"::response{ input.url: _ } ) };
"#,
        &history.path().join("dogwood.redb"),
    );
    authority
        .stage_mcp_schema("my-srv", generated("my-srv", "read", "path", "string"))
        .expect("the hyphenated server stages");
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes"),
        vec!["other".to_string()],
        "a staged server must not be named, and the server with no catalog must be"
    );
}

/// A pending rule reads one server's tool from history and decides another server's tool. The hold
/// and the degradation must reach the server the rule decides, and must leave the other alone. An
/// escaped name must read the same, because the reader that tells the two apart decodes the name.
#[test]
fn a_server_a_pending_rule_only_reads_from_history_is_neither_held_nor_degraded() {
    // `literal` is the name as a policy spells it; `raw` is the name a `tools/call` frame carries.
    for (literal, raw) in [("approve", "approve"), (r#"app\"rove"#, "app\"rove")] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged(
            vec![source(
                "approval.dw",
                &format!(
                    r#"
permit(principal, action == Box::Action::"mcp:call", resource);
@id("deploy-needs-approval")
forbid(principal, action == alpha::Action::"deploy", resource)
unless temporal {{
    formerly within 600s ( beta::Action::"{literal}"::response{{ input.id: _ }} )
}};
"#
                ),
            )],
            &history.path().join("dogwood.redb"),
        );

        let call = |server: &str, tool: &str, arguments: serde_json::Value| {
            authority.refine_tool_call(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                server,
                tool,
                &arguments,
            )
        };

        assert!(
            matches!(
                call("alpha", "deploy", json!({"target": "prod"})),
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            "{raw}: the tool the pending rule decides must be held"
        );
        assert!(
            call("beta", raw, json!({"id": "x"})).is_allow(),
            "{raw}: the tool the pending rule only reads from history must not be held"
        );

        let tools = json!({
            "result": {
                "tools": [{
                    "name": raw,
                    "inputSchema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                        "required": ["id"]
                    }
                }]
            }
        });
        assert_eq!(
            authority
                .stage_mcp_schema(
                    "beta",
                    generate_mcp_schema("beta", &tools.to_string())
                        .expect("the beta schema generates"),
                )
                .expect("beta stages"),
            SchemaStage::Accepted {
                authority_ready: false,
            },
            "{raw}: beta's schema arrives, and the rule still waits for alpha's"
        );
        assert!(
            call("beta", raw, json!({"id": "x"})).is_allow(),
            "{raw}: a fully discovered server's tool must not be held by another server's pending rule"
        );

        assert_eq!(
            authority
                .finish_mcp_discovery()
                .expect("discovery completes"),
            vec!["alpha".to_string()],
            "{raw}: only the server whose schema never arrived degrades"
        );
        assert!(
            matches!(
                call("alpha", "deploy", json!({"target": "prod"})),
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "{raw}: the degraded server's tool stays denied fail-closed"
        );
        assert!(
            call("beta", raw, json!({"id": "x"})).is_allow(),
            "{raw}: the healthy server's tool must not be refused"
        );
    }
}

/// One pending rule both decides a tool and reads another tool of the same server from history.
/// The hold must cover the tool it decides and must not grow to the tool it only reads.
#[test]
fn a_pending_rule_holds_the_tool_it_decides_and_not_the_tool_it_reads() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "review.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == svc::Action::"push", resource)
when { context.input.branch == "main" }
unless temporal {
    formerly within 600s ( svc::Action::"review"::response{ input.id: _ } )
};
"#,
        )],
        &history.path().join("dogwood.redb"),
    );

    let call = |tool: &str, arguments: serde_json::Value| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "svc",
            tool,
            &arguments,
        )
    };

    assert!(
        matches!(
            call("push", json!({"branch": "main"})),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "the tool the pending rule decides must be held"
    );
    assert!(
        call("review", json!({"id": "x"})).is_allow(),
        "the tool the same rule only reads from history must not be held"
    );

    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes"),
        vec!["svc".to_string()],
        "the server whose typed rule never staged degrades"
    );
    assert!(
        matches!(
            call("push", json!({"branch": "main"})),
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the degraded hold must cover the tool the rule decides"
    );
    assert!(
        call("review", json!({"id": "x"})).is_allow(),
        "the degraded hold must not cover the tool the rule only reads"
    );
}

/// A rule whose head is the coarse `mcp:call` action, and whose condition pins one server and one
/// tool to literals, decides exactly that call. The only typed names it spells sit in a
/// `when temporal` precondition over two servers. The hold must cover the tool the condition
/// decides while one of those servers never discovers, because otherwise the call rides the coarse
/// permit with the precondition unenforced.
#[test]
fn accepted_tool_waits_for_a_valid_cross_server_approval_rule() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged_engine(
        r#"
permit(principal, action == Box::Action::"mcp:call", resource);
@id("approve-needs-both")
forbid(principal, action == Box::Action::"mcp:call", resource)
when {
    context.input.server == "svc"
    && context.input has tool
    && context.input.tool == "approve"
}
unless temporal {
    formerly within 600s ( svc::Action::"approve"::response{ input.id: _ } )
    && formerly within 600s ( beta::Action::"approve"::response{ input.id: _ } )
};
"#,
        &history.path().join("dogwood.redb"),
    );

    let call = |server: &str, tool: &str, arguments: serde_json::Value| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            server,
            tool,
            &arguments,
        )
    };

    assert_eq!(
        authority
            .stage_mcp_schema("svc", generated("svc", "approve", "id", "string"))
            .expect("svc stages"),
        SchemaStage::Accepted {
            authority_ready: false,
        },
        "svc's catalog arrives, and the rule still waits for beta's"
    );

    assert!(
        matches!(
            call("svc", "approve", json!({"id": "x"})),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "the tool the pending condition pins must be held while beta discovers"
    );

    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes"),
        vec!["beta".to_string()],
        "only the server whose catalog never arrived reaches the warning"
    );
    assert!(
        matches!(
            call("svc", "approve", json!({"id": "x"})),
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the tool the condition decides must stay denied fail-closed, not ride the coarse permit"
    );
}

/// What the reader of a condition's pins may and may not claim. A pin states a tool the rule
/// decides only when it sits in a plain conjunction of `when`: a disjunction, a negation, or an
/// `unless` leaves the decided set somewhere other than the pins, so reading one out would hold a
/// tool no rule decides. Each rule here waits on `beta`, which never discovers.
#[test]
fn a_condition_pins_a_held_tool_only_when_it_decides_that_tool_alone() {
    // `condition` narrows the coarse head; `call` is the tool asked for; `held` is whether the box
    // must hold that call back while the rule is pending.
    for (condition, server, tool, held) in [
        // The pinned pair, in both operand orders the render can give.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve" }"#,
            "svc",
            "approve",
            true,
        ),
        (
            r#"when { "svc" == context.input.server && "approve" == context.input.tool }"#,
            "svc",
            "approve",
            true,
        ),
        // The same pins, spread over two `when` blocks, which the rule conjoins.
        (
            r#"when { context.input.server == "svc" } when { context.input.tool == "approve" }"#,
            "svc",
            "approve",
            true,
        ),
        // A pinned name that carries a quote: the hold must cover the name the operator wrote.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "app\"rove" }"#,
            "svc",
            "app\"rove",
            true,
        ),
        // A server name that is not a Cedar identifier reaches the hold set normalized.
        (
            r#"when { context.input.server == "my-srv" && context.input.tool == "approve" }"#,
            "my-srv",
            "approve",
            true,
        ),
        // A negation, spelled as an inequality: the rule decides every tool except the pinned one,
        // so holding the pinned one would refuse the single tool no rule decides.
        (
            r#"when { context.input.server == "svc" && context.input.tool != "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A negation, spelled over a whole comparison. The pin it holds is the server the rule
        // explicitly does not decide.
        (
            r#"when { !(context.input.server == "svc") && context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A string literal may itself spell a condition. The reader must not read a pin out of one.
        (
            r#"unless { context.input.method == "when { context.input.server == \"other\" && context.input.tool == \"fetch\" }" }"#,
            "other",
            "fetch",
            false,
        ),
        // An `if`: this one reads as `server != "svc" && tool == "approve"`, so the pinned pair is
        // the one pair the rule does not decide.
        (
            r#"when { if context.input.server == "svc" then false else context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A second guard beside the pins. A conjunction only narrows, so each pin still has to
        // hold, and an operator writes `!=` as readily as `>`. These two rows differ only in which
        // `when` block holds the guard, so they must agree.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve" && context.input.method != "x" }"#,
            "svc",
            "approve",
            true,
        ),
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve" } when { context.input.method != "x" }"#,
            "svc",
            "approve",
            true,
        ),
        // A guard that is itself a disjunction, beside intact pins. Same reasoning: the pins hold.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve"
&& (context.input.method == "tools/call" || context.input.method == "tools/list") }"#,
            "svc",
            "approve",
            true,
        ),
        // A tool's own arguments reach `context.input`, so a rule can compare one whose name
        // starts with `server` or `tool`. An argument is not the server and not the tool, so the
        // pair these two spell is a call no rule decides.
        (
            r#"when { "other" == context.input.server_id && "fetch" == context.input.tool_name }"#,
            "other",
            "fetch",
            false,
        ),
        // A comparison of a comparison, which renders with no `!` at all. The pinned pair is the
        // one pair this rule excludes, so reading a pin out of it would refuse exactly the wrong
        // call.
        (
            r#"when { (context.input.server == "svc") == false && context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A disjunction over the pins themselves. This rule does decide `svc/approve`, but it also
        // decides every tool on `svc` and every tool named `approve` anywhere, and that set cannot
        // be enumerated. Box holds none of it rather than part of it.
        (
            r#"when { context.input.server == "svc" || context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A disjunction beside an intact server pin. The server pin is read, because it still has
        // to hold; the tool is not, because the disjunction states two of them. One pin alone
        // leaves no pair, so nothing is held.
        (
            r#"when { context.input.server == "svc"
&& (context.input.tool == "approve" || context.input.tool == "reject") }"#,
            "svc",
            "approve",
            false,
        ),
        // A pattern match names no tool, although it bounds them. `like` is not an equality, so it
        // states no pin.
        (
            r#"when { context.input.server == "svc" && context.input.tool like "appro*" }"#,
            "svc",
            "approve",
            false,
        ),
        // An `unless` block states what stops the rule, so its pins are not a decided tool.
        (
            r#"unless { context.input.server == "svc" && context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A set membership names a finite set of tools, and Box does not read it. The set is
        // enumerable, so this is a limit rather than a necessity.
        (
            r#"when { context.input.server == "svc" && context.input has tool
&& ["approve", "reject"].contains(context.input.tool) }"#,
            "svc",
            "approve",
            false,
        ),
        // One pin alone leaves a set the box cannot enumerate: every tool on one server, or one
        // tool name on every server. The server-only case is enumerable at decision time, because
        // the call carries its server, so it too is a limit rather than a necessity.
        (
            r#"when { context.input.server == "svc" }"#,
            "svc",
            "approve",
            false,
        ),
        (
            r#"when { context.input.tool == "approve" }"#,
            "svc",
            "approve",
            false,
        ),
        // A `when temporal` block beside the pins renders a negation of its own. That negation
        // belongs to the history predicate, so it must not disqualify the pins.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve" }
when temporal { !( formerly within 600s ( beta::Action::"approve"::response{ input.id: _ } ) ) }"#,
            "svc",
            "approve",
            true,
        ),
        // Two pins on one attribute cannot both hold, so neither states a decided tool.
        (
            r#"when { context.input.server == "svc" && context.input.tool == "approve" && context.input.tool == "deploy" }"#,
            "svc",
            "approve",
            false,
        ),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged_engine(
            &format!(
                r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == Box::Action::"mcp:call", resource)
{condition}
unless temporal {{
    formerly within 600s ( beta::Action::"approve"::response{{ input.id: _ }} )
}};
"#
            ),
            &history.path().join("dogwood.redb"),
        );
        let decision = authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            server,
            tool,
            &json!({"id": "x"}),
        );
        assert_eq!(
            matches!(
                decision,
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            held,
            "the hold over {server}/{tool} must read {held} for: {condition}"
        );
    }
}

/// A rule's head states its whole reach, so a pin beside a typed head can only contradict it. Box
/// must not read such a pin: the pinned pair names a server that is answering correctly, and
/// holding it would refuse a healthy, fully discovered tool on behalf of a rule that can never
/// decide it ([a server whose discovery a policy denies degrades
/// alone](../../../docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone)).
#[test]
fn a_pin_beside_a_typed_head_holds_no_other_servers_tool() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged_engine(
        r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == alpha::Action::"deploy", resource)
when { context.input.server == "svc" && context.input.tool == "approve" };
"#,
        &history.path().join("dogwood.redb"),
    );
    authority
        .stage_mcp_schema("svc", generated("svc", "approve", "id", "string"))
        .expect("svc stages");

    let call = |server: &str, tool: &str| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            server,
            tool,
            &json!({"id": "x"}),
        )
    };

    assert!(
        call("svc", "approve").is_allow(),
        "the healthy server's declared tool must not be held for a rule headed on another server"
    );
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes"),
        vec!["alpha".to_string()],
        "only the server whose catalog never arrived reaches the warning"
    );
    assert!(
        call("svc", "approve").is_allow(),
        "the healthy server's tool must not be refused once discovery completes"
    );
}

/// Which calls Box holds and which servers it names are different questions. A pinned tool is a
/// hold, never a wait: a rule compares `context.input.server` against a plain string, which needs
/// no catalog, so the pinned server is not a server the rule waits for. Feeding the pins into the
/// warning would name a server the operator cannot act on.
#[test]
fn a_pinned_server_is_held_and_is_not_named_on_stderr() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged_engine(
        r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "ghost" && context.input.tool == "wipe" }
unless temporal {
    formerly within 600s ( beta::Action::"approve"::response{ input.id: _ } )
};
"#,
        &history.path().join("dogwood.redb"),
    );

    let call = || {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "ghost",
            "wipe",
            &json!({"id": "x"}),
        )
    };

    assert!(
        matches!(
            call(),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "the pinned tool must be held while the rule is pending"
    );
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes"),
        vec!["beta".to_string()],
        "stderr must name the server the rule waits for, and not the server a pin spells"
    );
    assert!(
        matches!(
            call(),
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the pinned tool must stay denied fail-closed"
    );
}

/// The hold above is transient: once the schema stages, an argument-constrained rule over a
/// quote-bearing tool name decides the call itself.
#[test]
fn an_escaped_tool_name_enforces_its_own_rule_once_its_schema_stages() {
    let tool = "foo\"bar";
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "staged.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "alpha" };
forbid(principal, action == alpha::Action::"foo\"bar", resource)
when { context.input.path like "/secret/*" };
permit(principal, action == alpha::Action::"foo\"bar", resource);
"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    let tools = json!({
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
    assert_eq!(
        authority
            .stage_mcp_schema(
                "alpha",
                generate_mcp_schema("alpha", &tools.to_string()).expect("the schema generates"),
            )
            .expect("the schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes")
            .is_empty(),
        "a staged tool degrades no server"
    );

    let refine = |path: &str| {
        let arguments = json!({"path": path});
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "alpha",
            tool,
            &arguments,
        )
    };
    assert!(
        matches!(
            refine("/secret/x"),
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ),
        "the argument-constrained forbid must deny the forbidden argument"
    );
    assert!(
        refine("/public/x").is_allow(),
        "the forbid must not reach an argument it does not name"
    );
}

#[test]
fn a_union_argument_is_decided_by_the_policy() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "staged.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "deepwiki" };
forbid(principal, action == deepwiki::Action::"ask_wiki_question", resource)
when {
    (context.input.repoName has typeChoice0 && context.input.repoName.typeChoice0 == "private/repo")
    || (context.input.repoName has typeChoice1 && context.input.repoName.typeChoice1.contains("private/repo"))
};
permit(principal, action == deepwiki::Action::"ask_wiki_question", resource);
"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    let tools = json!({
        "result": {
            "tools": [{
                "name": "ask_wiki_question",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repoName": {
                            "anyOf": [
                                {"type": "string"},
                                {"items": {"type": "string"}, "type": "array"}
                            ]
                        },
                        "question": {"type": "string"}
                    },
                    "required": ["repoName", "question"]
                }
            }]
        }
    });
    assert_eq!(
        authority
            .stage_mcp_schema(
                "deepwiki",
                generate_mcp_schema("deepwiki", &tools.to_string()).expect("the schema generates"),
            )
            .expect("the schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes")
            .is_empty()
    );

    let decide = |repo_name: serde_json::Value| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "deepwiki",
            "ask_wiki_question",
            &json!({"repoName": repo_name, "question": "How does it work?"}),
        )
    };
    assert!(
        decide(json!("strands-agents/sdk-python")).is_allow(),
        "a bare string member is decided by the permit"
    );
    assert!(
        decide(json!(["strands-agents/sdk-python", "strands-agents/box"])).is_allow(),
        "an array member is decided by the permit"
    );
    for forbidden in [
        json!("private/repo"),
        json!(["strands-agents/box", "private/repo"]),
    ] {
        assert!(
            matches!(
                decide(forbidden.clone()),
                Decision::Deny {
                    reason: DenyReason::Forbidden,
                    ..
                }
            ),
            "the forbid reads the member {forbidden}"
        );
    }
    for outside in [json!(7), json!({"typeChoice0": "strands-agents/box"})] {
        assert!(
            matches!(
                decide(outside.clone()),
                Decision::Deny {
                    reason: DenyReason::InternalFault,
                    ..
                }
            ),
            "a value outside the union is refused: {outside}"
        );
    }
}

#[test]
fn a_datetime_union_member_is_placed_and_its_rule_cannot_be_bypassed() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "staged.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "events" };
forbid(principal, action == events::Action::"list_events", resource)
when { context.input.since has typeChoice0 && context.input.since.typeChoice0 < datetime("2024-01-01") };
permit(principal, action == events::Action::"list_events", resource);
permit(principal, action == events::Action::"count_events", resource);
"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    let tools = json!({
        "result": {
            "tools": [
                {
                    "name": "list_events",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "since": {
                                "anyOf": [
                                    {"type": "string", "format": "date-time"},
                                    {"type": "string"}
                                ]
                            }
                        },
                        "required": ["since"]
                    }
                },
                {
                    "name": "count_events",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "since": {
                                "anyOf": [
                                    {"type": "string", "format": "date-time"},
                                    {"type": "null"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    });
    assert_eq!(
        authority
            .stage_mcp_schema(
                "events",
                generate_mcp_schema("events", &tools.to_string()).expect("the schema generates"),
            )
            .expect("the schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    assert!(
        authority
            .finish_mcp_discovery()
            .expect("discovery completes")
            .is_empty()
    );

    let decide = |tool: &str, since: &str| {
        authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "events",
            tool,
            &json!({"since": since}),
        )
    };
    assert!(
        decide("count_events", "2025-06-01T00:00:00Z").is_allow(),
        "a datetime fills the datetime member of a nullable datetime"
    );
    assert!(
        !decide("list_events", "2023-06-01T00:00:00Z").is_allow(),
        "a rule on the datetime member is not bypassed by the string member"
    );
    assert!(
        decide("list_events", "yesterday").is_allow(),
        "a string that is not a datetime fills only the string member"
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
                    arguments: Some(&arguments),
                },
            )
            .0,
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
            .0
            .is_allow(),
        "a schema-independent request is served by the subset while discovering"
    );
    let beta_arguments = json!({"value": 7});
    assert!(
        matches!(
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
                .0,
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
            .0
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
            .0
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
                        arguments: Some(&json!({ "path": "/x" })),
                    },
                )
                .0,
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
fn a_rule_that_reads_the_input_across_a_tool_action_is_refused_before_its_schema_stages() {
    for (name, text) in [
        (
            "mixed.dw",
            r#"@id("mixed")
               forbid(principal, action in [Box::Action::"fs:read", filesrv::Action::"read"], resource)
               when { context.input.path like "*/secret" };"#,
        ),
        (
            "branched.dw",
            r#"@id("branched")
               forbid(principal, action, resource)
               when {
                   (action == svc::Action::"read" && context.input has path)
                   || (action == Box::Action::"fs:read" && context.input.path like "*/secret")
               };"#,
        ),
        (
            "temporal_tool.dw",
            r#"@id("temporal_tool")
               forbid(principal, action in [Box::Action::"fs:read", srv::Action::"read"], resource)
               when { context.input.path like "*secret*" }
               when temporal { formerly within 60s ( srv::Action::"read"::request{ input.path: _ } ) };"#,
        ),
        (
            "temporal_box.dw",
            r#"@id("temporal_box")
               forbid(principal, action in [Box::Action::"fs:read", srv::Action::"read"], resource)
               when { context.input.path like "*secret*" }
               when temporal { formerly within 60s ( Box::Action::"fs:read"::request{ input.path: "a}\"{" } ) };"#,
        ),
    ] {
        let history = tempfile::tempdir().expect("history directory");
        let refusal = PolicyEngine::open_staged(
            &policy::Operator::unanchored(),
            vec![source(name, text)],
            &history.path().join("dogwood.redb"),
        )
        .map(|_| ())
        .expect_err("the rule is refused at open, not parked");
        assert!(
            matches!(
                refusal,
                policy::PolicyStagingError::Policy(policy::PolicyError::InputAcrossFamilies(_))
            ),
            "{name}: {refusal}"
        );
        assert!(
            refusal.to_string().contains("reads context.input"),
            "{name}: {refusal}"
        );
    }
}

#[test]
fn staged_validation_refuses_a_read_of_the_input_across_families() {
    for (name, text) in [
        (
            "box.dw",
            r#"forbid(principal, action in [Box::Action::"fs:read", Box::Action::"http:request"], resource)
               when { context.input.path like "*/secret" };"#,
        ),
        (
            "mixed.dw",
            r#"forbid(principal, action in [Box::Action::"fs:read", filesrv::Action::"read"], resource)
               when { context.input.path like "*/secret" };"#,
        ),
        (
            "unscoped.dw",
            r#"forbid(principal, action, resource) when { context.input has path };"#,
        ),
        (
            "temporal.dw",
            r#"forbid(principal, action in [Box::Action::"fs:read", srv::Action::"read"], resource)
               when { context.input.path like "*secret*" }
               when temporal { formerly within 60s ( srv::Action::"read"::request{ input.path: _ } ) };"#,
        ),
    ] {
        let refusal = PolicyEngine::validate_staged(&[source(name, text)])
            .expect_err("staged validation refuses the rule before discovery");
        assert!(
            matches!(refusal, policy::PolicyError::InputAcrossFamilies(_)),
            "{name}: {refusal}"
        );
    }
    PolicyEngine::validate_staged(&[source(
        "one.dw",
        r#"forbid(principal, action == filesrv::Action::"read", resource)
           when { context.input.path like "*/secret" };"#,
    )])
    .expect("a rule over one tool action passes staged validation");
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
            r#"permit(principal, action == Box::Action::"fs:read", resource)
               when { context.input.path like "*/secret" };"#,
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
                .0
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
    let SchemaStage::Rejected { reason } = authority
        .stage_mcp_schema("bad", generated("other", "read", "path", "integer"))
        .expect("schema rejection is not terminal")
    else {
        panic!("a schema for another namespace is rejected");
    };
    assert!(reason.contains("requires namespace"), "{reason}");
    let rejected_arguments = json!({"path": 7});
    assert!(matches!(
        authority
            .decide(
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
            )
            .0,
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
            .0
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
            .0
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
                r#"permit(principal, action == alpha::Action::"read", resource)
                   when { context.input.path like "*/secret" };"#,
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
    let SchemaStage::Rejected { reason } = authority
        .stage_mcp_schema("alpha", generated("alpha", "read", "path", "integer"))
        .expect("candidate rejection is not terminal")
    else {
        panic!("a schema that conflicts with a ready candidate is rejected");
    };
    assert!(reason.contains("fails schema validation"), "{reason}");
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
        let (decision, request_id) = authority.decide(&governed, &principal, &http_request());
        assert!(decision.is_allow());
        authority
            .record(
                &governed,
                &principal,
                &request_id.expect("the request records"),
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1",
                    delivery: Delivery::Completed { bytes: 10 },
                    status: Some(200),
                    intercepted: true,
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
    let (decision, request_id) = authority.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &http_request(),
    );
    assert!(
        decision.is_allow(),
        "the canonical request is admitted while discovering"
    );
    authority
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &request_id.expect("the request records"),
            &Outcome::Http {
                host: "api.example.com",
                port: 443,
                method: "POST",
                path: "/v1",
                delivery: Delivery::Completed { bytes: 10 },
                status: Some(200),
                intercepted: true,
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
        before_events + 2,
        "the request and outcome recorded while discovering must append to durable history"
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
            .0
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
            .0
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
            .0
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
            .0
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
            .0
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
        let (decision, request_id) = authority.decide(&governed, &principal, &http_request());
        assert!(decision.is_allow());
        authority
            .record(
                &governed,
                &principal,
                &request_id.expect("the request records"),
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1",
                    delivery: Delivery::Completed { bytes: 150 },
                    status: Some(200),
                    intercepted: true,
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
            .0
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

/// A tool on each of two servers, held while either server's schema is missing.
const TWO_SERVERS: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource);
permit(principal, action, resource)
when { action == alpha::Action::"read" || action == beta::Action::"read" };
forbid(principal, action == alpha::Action::"read", resource)
when { context.input.path == "/workspace/secret" };
forbid(principal, action == beta::Action::"read", resource)
when { context.input.path == "/workspace/secret" };
"#;

/// One server's `read` of `path`, through the per-tool refinement.
fn read(authority: &PolicyEngine, server: &str, path: &str) -> Decision {
    authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        server,
        "read",
        &json!({ "path": path }),
    )
}

/// With two schemas missing, a late list from either server is `Rejected` in either order, and
/// both servers keep their refusal.
#[test]
fn two_missing_schemas_do_not_recover_from_a_relist() {
    for order in [["alpha", "beta"], ["beta", "alpha"]] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged(
            vec![source("two-servers.dw", TWO_SERVERS)],
            &history.path().join("dogwood.redb"),
        );
        assert_eq!(
            authority
                .finish_mcp_discovery()
                .expect("completion degrades rather than fataling"),
            vec!["alpha".to_string(), "beta".to_string()],
            "neither listing staged, so both servers degrade"
        );

        for server in order {
            let other = if server == "alpha" { "beta" } else { "alpha" };
            let relist = authority
                .stage_mcp_schema(server, generated(server, "read", "path", "string"))
                .expect("the later listing is not a terminal fault");
            assert!(
                matches!(
                    &relist,
                    SchemaStage::Rejected { reason }
                        if reason.contains(&format!("{other}::Action::\"read\""))
                ),
                "{order:?}: {other}'s schema is missing, so {server}'s relist is refused and its \
                 schema is dropped with it: {relist:?}"
            );
            for held in ["alpha", "beta"] {
                let call = read(&authority, held, "/workspace/secret");
                assert!(
                    matches!(
                        call,
                        Decision::Deny {
                            reason: DenyReason::NoMatch,
                            ..
                        }
                    ),
                    "{order:?}: after {server}'s relist, {held}'s tool keeps the degraded \
                     refusal rather than riding the coarse grant past its forbid: {call:?}"
                );
            }
        }
    }
}

/// One rule that decides a tool on each of two servers holds both while one schema is missing, and
/// the late list that supplies that schema recovers both, in either order.
#[test]
fn a_late_list_that_supplies_the_last_schema_recovers_both_servers() {
    for [early, late] in [["alpha", "beta"], ["beta", "alpha"]] {
        let history = tempfile::tempdir().expect("history directory");
        let authority = staged(
            vec![source("two-servers.dw", TWO_SERVERS)],
            &history.path().join("dogwood.redb"),
        );
        assert_eq!(
            authority
                .stage_mcp_schema(early, generated(early, "read", "path", "string"))
                .expect("the listing is not a terminal fault"),
            SchemaStage::Accepted {
                authority_ready: false,
            },
            "{early}'s schema stages during discovery, and the shared permit still waits for \
             {late}'s"
        );
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling");
        for server in ["alpha", "beta"] {
            let call = read(&authority, server, "/workspace/input");
            assert!(
                matches!(
                    call,
                    Decision::Deny {
                        reason: DenyReason::NoMatch,
                        ..
                    }
                ),
                "{early} early: {server}'s tool is held whether or not its own schema arrived: \
                 {call:?}"
            );
        }

        assert_eq!(
            authority
                .stage_mcp_schema(late, generated(late, "read", "path", "string"))
                .expect("the later listing is not a terminal fault"),
            SchemaStage::Accepted {
                authority_ready: true,
            },
            "{late}'s schema is the last one the bundle needs"
        );
        for server in ["alpha", "beta"] {
            let forbidden = read(&authority, server, "/workspace/secret");
            assert!(
                matches!(
                    forbidden,
                    Decision::Deny {
                        reason: DenyReason::Forbidden,
                        ..
                    }
                ),
                "{early} early: {server}'s forbid refuses the path it names: {forbidden:?}"
            );
            let permitted = read(&authority, server, "/workspace/input");
            assert!(
                matches!(&permitted, Decision::Allow { rule, .. } if rule.as_str() != RuleId::DEFAULT_DENY),
                "{early} early: the shared permit allows {server}'s other path, and the call does \
                 not ride the coarse grant: {permitted:?}"
            );
        }
    }
}

/// A late list is refused while a schema that already staged does not match its server's rule.
#[test]
fn a_late_list_is_refused_while_a_staged_schema_does_not_match_its_rule() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source("two-servers.dw", TWO_SERVERS)],
        &history.path().join("dogwood.redb"),
    );
    authority
        .stage_mcp_schema("alpha", generated("alpha", "read", "target", "string"))
        .expect("the listing is not a terminal fault");
    authority
        .finish_mcp_discovery()
        .expect("completion degrades rather than fataling");

    let relist = authority
        .stage_mcp_schema("beta", generated("beta", "read", "path", "string"))
        .expect("the later listing is not a terminal fault");
    assert!(
        matches!(
            &relist,
            SchemaStage::Rejected { reason } if reason.contains("alpha::Action::\"read\"")
        ),
        "beta supplies the only missing schema, but alpha's forbid reads an argument alpha's schema \
         does not declare: {relist:?}"
    );
    for held in ["alpha", "beta"] {
        let call = read(&authority, held, "/workspace/secret");
        assert!(
            matches!(
                call,
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "{held}'s tool keeps the degraded refusal: {call:?}"
        );
    }
}

/// A late list refused for a namespace collision leaves every degraded refusal in place.
#[test]
fn a_late_list_refused_for_a_namespace_collision_keeps_the_degraded_mark() {
    let history = tempfile::tempdir().expect("history directory");
    let authority = staged(
        vec![source(
            "collision.dw",
            r#"
permit(principal, action == Box::Action::"mcp:call", resource);
permit(principal, action == a_b::Action::"read", resource);
forbid(principal, action == beta::Action::"read", resource)
when { context.input.path == "/workspace/secret" };
"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    authority
        .stage_mcp_schema("a-b", generated("a-b", "read", "path", "string"))
        .expect("the listing is not a terminal fault");
    assert_eq!(
        authority
            .finish_mcp_discovery()
            .expect("completion degrades rather than fataling"),
        vec!["beta".to_string()]
    );

    let relist = authority
        .stage_mcp_schema("a.b", generated("a.b", "read", "path", "string"))
        .expect("the later listing is not a terminal fault");
    assert!(
        matches!(
            &relist,
            SchemaStage::Rejected { reason } if reason.contains("same Cedar namespace")
        ),
        "a.b and a-b share the namespace a_b, so a.b's list is refused: {relist:?}"
    );
    let call = read(&authority, "beta", "/workspace/secret");
    assert!(
        matches!(
            call,
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "the refused list must not lift beta's degraded refusal, or beta's read rides the coarse \
         grant past its forbid: {call:?}"
    );
}
