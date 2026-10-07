//! The two decisions an MCP server meets: may it run, and may this request be made.

use std::io;

use egress_gateway::McpTarget;
use policy::{Decision, GovernedBox, PolicyEngine, Principal, Request};
use serde_json::Value;

use crate::record::config::mcp::McpServer;
use crate::run::telemetry::{EffectiveDecision, capture_policy_action};

/// Resolve this alias to the server the operator declared, and answer with what to start.
pub(crate) fn admit_server<'a>(
    declared: &'a [McpServer],
    alias: &str,
) -> io::Result<&'a McpServer> {
    crate::record::config::mcp::for_alias(declared, alias).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "no MCP server declares the program {alias:?} in box.toml, so the box placed no \
                 alias for it"
            ),
        )
    })
}

/// Decide one frame, if it asks the server to do anything.
pub(super) fn admit_tool_call(
    policy: &PolicyEngine,
    governed: &GovernedBox,
    principal: &Principal,
    server: &str,
    frame: &str,
) -> io::Result<McpRequestAdmission> {
    let correlation = telemetry::Correlation::from_mcp(frame);
    correlation.during(|| {
        let Some(target) = McpTarget::of_stdio_request(frame.as_bytes())? else {
            return Ok(McpRequestAdmission::Undecided);
        };

        let decision = policy.decide(
            governed,
            principal,
            &Request::McpCall {
                server,
                method: target.method(),
                tool: target.tool(),
                prompt: target.prompt(),
                uri: target.uri(),
                // Gate one: the coarse `mcp:call`. The per-tool refinement is gate two, below.
                arguments: None,
            },
        );
        let reported = target.reported();
        let resource = format!("{server}/{reported}");
        let coarse =
            EffectiveDecision::from_policy(r#"Box::Action::"mcp:call""#, &resource, &decision);
        match &decision {
            Decision::Allow { .. } => {}
            Decision::Deny {
                reason: policy::DenyReason::PolicyPending,
                ..
            } => {
                return Ok(McpRequestAdmission::PolicyPending(
                    coarse,
                    io::Error::new(io::ErrorKind::PermissionDenied, decision.to_string()),
                ));
            }
            refused => {
                return Ok(McpRequestAdmission::Denied {
                    decision: coarse,
                    refusal: request_refusal(refused, target.method()),
                });
            }
        }

        // Gate two: the server-namespaced per-tool refinement for a `tools/call`.
        // It rides the coarse allow unless a `forbid` on the tool or its arguments matches; an
        // undeclared tool is unaffected. The arguments are typed against the composed schema.
        if let Some(tool) = target.tool() {
            let arguments: Value = serde_json::from_str(&target.arguments).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("MCP tool arguments are not valid JSON: {error}"),
                )
            })?;
            let (refined, refined_action) = capture_policy_action(|| {
                policy.refine_tool_call(governed, principal, server, tool, &arguments)
            });
            match &refined {
                Decision::Deny { .. } => {
                    return Ok(McpRequestAdmission::Denied {
                        decision: EffectiveDecision::from_policy(
                            refined_action
                                .unwrap_or_else(|| r#"Box::Action::"mcp:call""#.to_string()),
                            &resource,
                            &refined,
                        ),
                        refusal: request_refusal(&refined, target.method()),
                    });
                }
                Decision::Allow { rule, .. } if rule.as_str() != policy::RuleId::DEFAULT_DENY => {
                    return Ok(McpRequestAdmission::Allowed(
                        EffectiveDecision::from_policy(
                            refined_action
                                .unwrap_or_else(|| r#"Box::Action::"mcp:call""#.to_string()),
                            resource,
                            &refined,
                        ),
                    ));
                }
                Decision::Allow { .. } => {}
            }
        }
        Ok(McpRequestAdmission::Allowed(coarse))
    })
}

pub(super) fn request_refusal(decision: &Decision, method: &str) -> io::Error {
    const CONTEXT_LIMIT: usize = 128;
    let truncated = if method.chars().nth(CONTEXT_LIMIT).is_some() {
        "..."
    } else {
        ""
    };
    let method = method
        .chars()
        .take(CONTEXT_LIMIT)
        .flat_map(char::escape_debug)
        .collect::<String>();
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{decision} ({method}{truncated})"),
    )
}

pub(super) enum McpRequestAdmission {
    Undecided,
    Allowed(EffectiveDecision),
    PolicyPending(EffectiveDecision, io::Error),
    Denied {
        decision: EffectiveDecision,
        refusal: io::Error,
    },
}

/// Make the JSON-RPC response for a policy-denied request.
pub(crate) fn policy_denial_response(frame: &str, message: &str) -> Option<String> {
    egress_gateway::mcp_denial_response(frame.as_bytes(), message)
        .map(|response| format!("{response}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use policy::Outcome;
    use serde_json::json;

    use crate::test_support::{open_policy, open_policy_with_mcp_schemas};

    /// The declared set, as `box.toml`'s `[[mcp]]` array reaches the broker.
    fn declared() -> Vec<McpServer> {
        let servers = vec![
            McpServer {
                name: "issues-mcp".to_string(),
                command: vec!["issues-mcp".to_string()],
            },
            McpServer {
                name: "aws-mcp".to_string(),
                command: vec!["uvx".to_string(), "mcp-proxy-for-aws@latest".to_string()],
            },
        ];
        crate::record::config::mcp::validate_authored(&servers)
            .expect("the fixture is a valid authored array");
        servers
    }

    fn policy(text: &str) -> PolicyEngine {
        open_policy(vec![policy::Policy {
            origin: PathBuf::from("mcp.dw"),
            text: text.to_string(),
        }])
    }

    fn tool_policy(text: &str) -> PolicyEngine {
        let schema =
            policy::generate_mcp_schema("issues-mcp", TOOLS).expect("the MCP schema generates");
        open_policy_with_mcp_schemas(
            vec![policy::Policy {
                origin: PathBuf::from("mcp.dw"),
                text: text.to_string(),
            }],
            &[schema],
        )
        .observed_by(Arc::new(crate::run::telemetry::PolicyDecisionObserver))
    }

    /// Admit through an **alias**, which is named for the declared `program`.
    fn admit(alias: &str) -> io::Result<McpServer> {
        admit_server(&declared(), alias).cloned()
    }

    const TOOLS: &str = r#"
    {
        "result": {
            "tools": [
                {
                    "name": "SearchIssues",
                    "description": "Search issues",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    }
                },
                {
                    "name": "AddComment",
                    "description": "Add a comment",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }
            ]
        }
    }
    "#;

    /// A declared server resolves to the argv the file fixed.
    #[test]
    fn a_declared_server_resolves_to_the_files_own_argv() {
        // Through `uvx`, because that is the alias the harness executes for this server.
        let admitted = admit("uvx").expect("uvx is declared");
        assert_eq!(admitted.program(), "uvx");
        assert_eq!(
            admitted.name, "aws-mcp",
            "the reported identity is the server's name, which is what a rule reads"
        );
        assert_eq!(
            admitted.arguments(),
            ["mcp-proxy-for-aws@latest"],
            "the argv comes from box.toml, never from the agent"
        );
    }

    /// **An undeclared program is refused, and that refusal is the whole floor.**
    ///
    /// The box places one alias per declared server, so an undeclared program names nothing the box
    #[test]
    fn an_undeclared_program_is_refused() {
        for undeclared in ["not-in-the-file", "aws-mcp"] {
            let refusal = admit(undeclared)
                .expect_err("a program the file does not declare must be refused")
                .to_string();
            assert!(
                refusal.contains("no MCP server declares the program"),
                "{undeclared:?} must be refused as undeclared: {refusal}"
            );
        }
    }

    fn call(policy: &PolicyEngine, frame: &str) -> io::Result<Option<String>> {
        let reported = McpTarget::of_stdio_request(frame.as_bytes())?
            .map(|target| target.reported().to_string());
        match admit_tool_call(
            policy,
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            frame,
        )? {
            McpRequestAdmission::Undecided => Ok(None),
            McpRequestAdmission::Allowed(_) => Ok(reported),
            McpRequestAdmission::PolicyPending(_, refusal) => Err(refusal),
            McpRequestAdmission::Denied { refusal, .. } => Err(refusal),
        }
    }

    const SEARCH: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"SearchIssues","arguments":{"query":"x"}}}"#;
    const COMMENT: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"AddComment","arguments":{}}}"#;

    /// A coarse permit admits a tool when the per-tool refinement has no matching rule.
    #[test]
    fn a_permitted_tool_call_is_admitted() {
        let policy = policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };"#,
        );
        assert_eq!(
            call(&policy, SEARCH).expect("permitted"),
            Some("SearchIssues".to_string())
        );
    }

    /// A `count(mcp:call::response) >= 2` cap fires, because the reply records the response leg
    /// via `Outcome::Mcp`. Two recorded responses mean the 3rd call is denied. This drives the exact
    /// loop `forward_server_frame` runs, decide (`admit_tool_call`) plus `record(Outcome::Mcp)`, so
    /// removing the record leaves the count at 0 and this test fails.
    #[test]
    fn a_temporal_response_cap_on_mcp_call_fires() {
        let engine = policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };
               forbid (principal, action == Box::Action::"mcp:call", resource)
               when temporal {
                   exists (n: Long). (
                       (count for (t: Timepoint). where (
                           formerly within 3600s (
                               Box::Action::"mcp:call"::response{ input.server: _ } && tp(t)
                           )
                       )) == n
                       && n >= 2
                   )
               };"#,
        );
        let governed = GovernedBox::assigned("test-box");
        let record_response = || {
            engine
                .record(
                    &governed,
                    &Principal::agent(),
                    &Outcome::Mcp {
                        server: "issues-mcp",
                        method: "tools/call",
                        tool: Some("SearchIssues"),
                        prompt: None,
                        uri: None,
                    },
                )
                .expect("record the response leg");
        };

        // Two calls under the cap: each admitted, each records a `mcp:call::response`.
        for _ in 0..2 {
            assert!(
                matches!(
                    admit_tool_call(
                        &engine,
                        &governed,
                        &Principal::agent(),
                        "issues-mcp",
                        SEARCH
                    )
                    .expect("admit"),
                    McpRequestAdmission::Allowed(_)
                ),
                "a call under the cap must be admitted"
            );
            record_response();
        }

        // The third: count(mcp:call::response) == 2, so the temporal forbid fires.
        assert!(
            matches!(
                admit_tool_call(
                    &engine,
                    &governed,
                    &Principal::agent(),
                    "issues-mcp",
                    SEARCH
                )
                .expect("admit"),
                McpRequestAdmission::Denied { .. }
            ),
            "the 3rd mcp:call must be denied by count(::response) >= 2 — the response leg is counted"
        );
    }

    #[test]
    fn a_no_match_refinement_records_the_coarse_permit_as_the_final_decision() {
        use crate::run::telemetry::{EffectiveRule, EffectiveVerdict};

        let policy = policy(
            r#"@id("coarse") @description("coarse permit")
               permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };"#,
        );
        let admission = admit_tool_call(
            &policy,
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            SEARCH,
        )
        .expect("the tool call is valid");
        let McpRequestAdmission::Allowed(decision) = admission else {
            panic!("the coarse permit must be the final permit");
        };
        let (action, resource, rule, verdict, reason) = decision.parts();
        assert_eq!(action, r#"Box::Action::"mcp:call""#);
        assert_eq!(resource, "issues-mcp/SearchIssues");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(reason, None);
        let [attribution] = decision.attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(attribution.annotation_id.as_deref(), Some("coarse"));
        assert_eq!(attribution.description.as_deref(), Some("coarse permit"));
    }

    /// **A forbid on one tool refuses that tool and leaves the rest working.**
    #[test]
    fn one_tool_is_refused_while_the_rest_still_work() {
        let policy = policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };
               forbid (principal, action == Box::Action::"mcp:call", resource)
               when { context.input has tool && context.input.tool == "AddComment" };"#,
        );

        assert!(call(&policy, SEARCH).is_ok(), "the other tools still work");
        let refusal = call(&policy, COMMENT)
            .expect_err("the forbidden tool must be refused")
            .to_string();
        assert!(
            refusal.contains("AddComment"),
            "the refusal must name the tool: {refusal}"
        );
    }

    /// A tool call with nothing permitting it is refused, not forwarded.
    #[test]
    fn an_unpermitted_tool_call_is_refused() {
        let policy = tool_policy("");
        let refusal = call(&policy, SEARCH).expect_err("the coarse gate has no permit");
        assert!(refusal.to_string().contains("[default-deny]"));
    }

    #[test]
    fn a_policy_denial_bounds_the_reported_tool_name() {
        let policy = policy("forbid (principal, action, resource);");
        let frame = json!({
            "jsonrpc": "2.0",
            "id": 19,
            "method": "tools/call",
            "params": {"name": "x".repeat(20_000), "arguments": {}},
        })
        .to_string();
        let refusal = call(&policy, &frame).expect_err("the coarse forbid denies");
        let message = refusal.to_string();
        assert!(message.len() < 2048, "{message}");
        assert_eq!(message.matches('x').count(), 1024 - "issues-mcp/".len());
        assert!(message.contains("xxx...' [policy: "), "{message}");
        assert!(message.ends_with(" (tools/call)"), "{message}");
        let response: Value = serde_json::from_str(
            &policy_denial_response(&frame, &refusal.to_string()).expect("the request has an ID"),
        )
        .expect("the response is JSON");
        assert_eq!(response["id"], 19);
        assert_eq!(response["error"]["code"], -32001);
    }

    #[test]
    fn a_policy_denial_escapes_request_context_in_the_response() {
        let policy = policy("forbid (principal, action, resource);");
        let unsafe_text = "name\n\u{1b}[31m\u{202e}\\suffix";
        for (method, tool) in [("tools/call", unsafe_text), (unsafe_text, "tool")] {
            let frame = json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": method,
                "params": {"name": tool, "arguments": {}},
            })
            .to_string();
            let refusal = call(&policy, &frame).expect_err("the coarse forbid denies");
            let response: Value = serde_json::from_str(
                &policy_denial_response(&frame, &refusal.to_string())
                    .expect("the request has an ID"),
            )
            .expect("the response is JSON");
            let message = response["error"]["message"]
                .as_str()
                .expect("the denial has a message");
            assert!(
                message.contains(r"name\n\u{1b}[31m\u{202e}\\suffix"),
                "{message:?}"
            );
            assert!(!message.chars().any(char::is_control));
            assert!(!message.contains('\u{202e}'));
            assert_eq!(response["id"], 20);
            assert_eq!(response["error"]["code"], -32001);
        }
    }

    /// **A per-tool ARGUMENT forbid refines the coarse `mcp:call` allow (hybrid B).** stdio raises
    /// the typed server-namespaced gate as a refinement, so a `forbid` on an argument value
    /// refuses one call while the coarse permit still covers the tool for other arguments.
    #[test]
    fn a_per_tool_argument_forbid_refines_the_coarse_allow() {
        let policy = tool_policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };
               forbid (principal, action == issues_mcp::Action::"SearchIssues", resource)
               when { context.input.query == "x" };"#,
        );

        // `query == "x"` hits the per-tool forbid at gate two, though gate one (`mcp:call`) allows.
        assert!(
            call(&policy, SEARCH).is_err(),
            "the arg-level forbid must refuse this call"
        );
        // A different `query` rides the coarse allow — the per-tool forbid does not match.
        let other = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call",
            "params":{"name":"SearchIssues","arguments":{"query":"y"}}}"#;
        assert!(
            call(&policy, other).is_ok(),
            "a non-matching argument still rides the coarse allow"
        );
    }

    #[test]
    fn a_per_tool_permit_keeps_its_attribution() {
        let policy = tool_policy(
            r#"@id("coarse")
               permit(principal, action == Box::Action::"mcp:call", resource);
               @id("tool") @description("tool permit")
               permit(principal, action == issues_mcp::Action::"SearchIssues", resource);"#,
        );
        let McpRequestAdmission::Allowed(decision) = admit_tool_call(
            &policy,
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            SEARCH,
        )
        .expect("valid tool call") else {
            panic!("the tool permit admits the call");
        };
        assert_eq!(decision.parts().0, r#"issues_mcp::Action::"SearchIssues""#);
        let [attribution] = decision.attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(attribution.annotation_id.as_deref(), Some("tool"));
        assert_eq!(attribution.description.as_deref(), Some("tool permit"));
    }

    #[test]
    fn a_per_tool_forbid_records_the_refined_denial_as_the_final_decision() {
        use crate::run::telemetry::{EffectiveRule, EffectiveVerdict};

        let policy = tool_policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };
               @id("refusal") @description("tool forbid")
               forbid (principal, action == issues_mcp::Action::"SearchIssues", resource)
               when { context.input.query == "x" };"#,
        );
        let admission = admit_tool_call(
            &policy,
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            SEARCH,
        )
        .expect("the tool call is valid");
        let McpRequestAdmission::Denied { decision, refusal } = admission else {
            panic!("the per-tool forbid must be the final denial");
        };
        let (action, resource, rule, verdict, reason) = decision.parts();
        assert_eq!(action, r#"issues_mcp::Action::"SearchIssues""#);
        assert_eq!(resource, "issues-mcp/SearchIssues");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert!(reason.is_some_and(|reason| reason.contains("forbid")));
        let [attribution] = decision.attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(attribution.annotation_id.as_deref(), Some("refusal"));
        let response: Value = serde_json::from_str(
            &policy_denial_response(SEARCH, &refusal.to_string()).expect("the request has an ID"),
        )
        .expect("the refusal response is JSON");
        assert_eq!(response["id"], 1);
        assert_eq!(response["error"]["code"], -32001);
        assert_eq!(
            response["error"]["message"],
            "policy denied this operation on 'issues-mcp/SearchIssues' [policy: refusal]: tool forbid. (tools/call)"
        );
        assert_eq!(attribution.description.as_deref(), Some("tool forbid"));
    }

    /// A denied request receives a JSON-RPC error with its original request id.
    #[test]
    fn a_policy_denial_has_a_json_rpc_response() {
        let message =
            r#"policy denied this operation [policy: private-search]: Use "PublicSearch"."#;
        for (frame, id) in [
            (
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"SearchIssues","arguments":{"query":"x"}}}"#,
                json!(7),
            ),
            (
                r#"{"jsonrpc":"2.0","id":"request-8","method":"tools/call","params":{"name":"SearchIssues","arguments":{"query":"x"}}}"#,
                json!("request-8"),
            ),
        ] {
            let response: Value = serde_json::from_str(
                &policy_denial_response(frame, message)
                    .expect("an id-bearing request has a response"),
            )
            .expect("the response is JSON");
            assert_eq!(response["jsonrpc"], "2.0");
            assert_eq!(response["id"], id);
            assert_eq!(response["error"]["code"], -32001);
            assert_eq!(response["error"]["message"], message);
        }
    }

    /// Notifications and malformed frames have no request id the broker can answer.
    #[test]
    fn a_policy_denial_response_requires_an_id_bearing_json_rpc_request() {
        for frame in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","id":false,"method":"tools/call"}"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"tools/call"}"#,
            "not json",
        ] {
            assert!(
                policy_denial_response(frame, "policy denied this operation.").is_none(),
                "{frame} has no valid JSON-RPC response target"
            );
        }
    }

    /// A tool input that does not match the generated type is refused.
    #[test]
    fn a_mistyped_tool_input_is_refused() {
        let policy = tool_policy(
            r#"permit (
                principal,
                action == issues_mcp::Action::"SearchIssues",
                resource
            );"#,
        );
        let wrong = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"SearchIssues","arguments":{"query":7}}}"#;

        assert!(
            call(&policy, wrong).is_err(),
            "a request that fails the generated Cedar input type must not be forwarded"
        );
    }

    /// The handshake frames ask the server for nothing, so they raise no decision.
    #[test]
    fn a_frame_that_calls_no_tool_raises_no_decision() {
        let deny_everything = open_policy(Vec::new());
        for frame in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"server/discover"}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"subscriptions/listen"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "",
        ] {
            assert_eq!(
                call(&deny_everything, frame).expect("a frame asking nothing is not a decision"),
                None,
                "{frame} must raise no decision"
            );
        }
    }

    /// **The `*/list` discovery methods are decided, so a rule can gate discovery.** They were
    /// undecided; promoting them matches the remote door and lets a policy hide a server's catalog.
    #[test]
    fn the_list_methods_are_decided() {
        let deny_everything = open_policy(Vec::new());
        for method in ["tools/list", "prompts/list", "resources/list"] {
            let frame = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
            let refusal = call(&deny_everything, &frame)
                .expect_err("a list method is now decided, so absent policy denies it")
                .to_string();
            assert!(
                refusal.contains(method),
                "the refusal must name the list method it decided: {refusal}"
            );
        }
    }

    /// **A client-sent JSON-RPC response is refused, not forwarded undecided.**
    ///
    /// The client MUST NOT write responses under the 2026-07-28 stdio binding, so a frame carrying
    #[test]
    fn a_client_sent_response_is_refused() {
        let permit_everything = open_policy(vec![policy::Policy {
            origin: std::path::PathBuf::from("permissive.dw"),
            text: "permit (principal, action, resource);".to_string(),
        }]);

        for frame in [
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
            r#"{"jsonrpc":"2.0","id":9,"error":{"code":-1,"message":"no"}}"#,
        ] {
            let error = call(&permit_everything, frame)
                .expect_err("a client-sent response must be refused");
            assert!(
                error.to_string().contains("client-sent JSON-RPC response"),
                "the refusal must say what shape it refused: {error}"
            );
        }
    }

    /// **Each of these methods raises a decision, not only `tools/call`.**
    ///
    /// `resources/read` reads a file the server can reach, and `prompts/get` expands a template;
    #[test]
    fn a_method_other_than_tools_call_still_raises_a_decision() {
        let deny_everything = open_policy(Vec::new());
        // A method with no per-item identity (`*/list`, subscribe, a later method): decided by the
        // method alone, so the denial names it.
        for method in [
            "resources/subscribe",
            "resources/unsubscribe",
            "completion/complete",
            "logging/setLevel",
            "a/method/from/a/later/specification",
        ] {
            let frame = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
            let refusal = call(&deny_everything, &frame)
                .expect_err("absent policy denies, so this must be refused")
                .to_string();
            assert!(
                refusal.contains(method),
                "the refusal must name the method it decided: {refusal}"
            );
        }
        // A method carrying a per-item identity: the denial names the method too.
        for frame in [
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"review"}}"#,
        ] {
            let refusal = call(&deny_everything, frame)
                .expect_err("absent policy denies, so this must be refused")
                .to_string();
            assert!(
                refusal.contains("resources/read") || refusal.contains("prompts/get"),
                "the refusal must name the method it decided: {refusal}"
            );
        }
    }

    /// A decided method reports itself as the target, so a rule can permit exactly one.
    #[test]
    fn a_rule_may_permit_one_method_without_permitting_the_rest() {
        let reads_only = policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.method == "resources/read" };"#,
        );
        let read =
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}"#;
        let write = r#"{"jsonrpc":"2.0","id":2,"method":"resources/subscribe","params":{}}"#;

        // The reported item for a `resources/read` is its URI, the per-item identity it carries.
        assert_eq!(
            call(&reads_only, read).expect("permitted"),
            Some("file:///x".to_string())
        );
        assert!(
            call(&reads_only, write).is_err(),
            "a rule naming one method must not admit another"
        );
    }

    /// A re-spelled `resources/read` `uri` that RESOLVES to a
    /// forbidden path is denied, because the decision canonicalizes it to the form the server resolves
    /// (`McpTarget::of_stdio_request`). As reported, each re-spelling dodged a byte-exact `forbid`; here every class
    /// is denied. Guards the canonicalize-before-decide wiring — remove it and the re-spellings are
    /// admitted again (the exact regression). The permitted case also proves the reported target is
    /// canonical, so a denial/telemetry record names the resolved identity.
    #[test]
    fn a_respelled_resource_uri_cannot_dodge_a_uri_forbid() {
        let guards_etc = policy(
            r#"permit (principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "issues-mcp" };
               forbid (principal, action == Box::Action::"mcp:call", resource)
               when { context.input has uri && context.input.uri like "file:///etc/*" };"#,
        );
        let read = |uri: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{{"uri":"{uri}"}}}}"#
            )
        };
        // The literal spelling is denied (the control) ...
        assert!(
            call(&guards_etc, &read("file:///etc/passwd")).is_err(),
            "the literal forbidden uri must be denied"
        );
        // ... and so is every re-spelling the finding used, because each canonicalizes to it.
        for respelling in [
            "file:/etc/passwd",            // no authority
            "file:///%65tc/passwd",        // percent-encoding (%65 = 'e')
            "file:///tmp/../etc/passwd",   // dot-segments
            "file://localhost/etc/passwd", // RFC 8089 localhost authority
        ] {
            assert!(
                call(&guards_etc, &read(respelling)).is_err(),
                "a uri resolving to /etc must be denied however it is spelled: {respelling}"
            );
        }
        // A resource outside the forbid still reads, reported in canonical form.
        assert_eq!(
            call(&guards_etc, &read("file:///%74mp/ok")).expect("permitted"),
            Some("file:///tmp/ok".to_string()),
            "a permitted uri is admitted and reported canonically (%74 = 't')"
        );
    }

    /// **A `notifications/` frame carrying an `id` is decided, not waved through.**
    ///
    /// The prefix is admitted undecided because a notification gets no reply, so the client learns
    #[test]
    fn a_notification_carrying_an_id_is_decided() {
        let deny_everything = open_policy(Vec::new());

        // A real notification: no `id`, so no decision and no reply.
        assert_eq!(
            call(
                &deny_everything,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .expect("a notification asks nothing"),
            None
        );

        // The same prefix with an `id` is a request wearing a notification's name.
        let refusal = call(
            &deny_everything,
            r#"{"jsonrpc":"2.0","id":7,"method":"notifications/tools/call",
                "params":{"name":"run_command","arguments":{}}}"#,
        )
        .expect_err("an id-bearing notification must be decided, and absent policy denies")
        .to_string();
        assert!(
            refusal.contains("notifications/tools/call"),
            "the refusal must name the method it decided: {refusal}"
        );
    }

    /// **A JSON-RPC batch is refused.** It carried every method past the check.
    #[test]
    fn a_batch_frame_cannot_smuggle_a_call_past_the_decision() {
        let permissive = policy(r#"permit (principal, action, resource);"#);
        let batch = format!("[{SEARCH}]");
        let refusal = call(&permissive, &batch)
            .expect_err("a batch must be refused even under a permissive policy")
            .to_string();
        assert!(
            refusal.contains("not a JSON object"),
            "the refusal must say why a batch is not decidable: {refusal}"
        );
    }

    /// **A frame the box cannot parse is refused rather than forwarded.**
    ///
    /// This is what lets the declaration stay coarse. Without it, one malformed frame would leave
    #[test]
    fn an_unparseable_frame_is_refused_rather_than_forwarded() {
        let permissive = policy(r#"permit (principal, action, resource);"#);
        for frame in [
            "not json at all",
            "{\"jsonrpc\":\"2.0\",",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}"#,
        ] {
            assert!(
                call(&permissive, frame).is_err(),
                "{frame} must be refused even under a permissive policy"
            );
        }
    }
}
