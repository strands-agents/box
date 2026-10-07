//! E2E coverage for the policy interceptor consumed by egress-proxy.

#![cfg(feature = "egress-adapter")]

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use egress_gateway::{EffectAttempt, EffectInterceptor, EffectOutcome, McpFrame};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, Principal, generate_mcp_schema};

/// The demo server's `tools/list`, which declares the typed `demo::Action::"add"` action.
const DEMO_TOOLS: &str = r#"{"result":{"tools":[
  {"name":"add","description":"add","inputSchema":{"type":"object",
    "properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}},
  {"name":"echo","description":"echo","inputSchema":{"type":"object",
    "properties":{"text":{"type":"string"}},"required":["text"]}}
]}}"#;

fn egress_interceptor(src: &str) -> Arc<dyn EffectInterceptor> {
    interceptor_from(support::open_policy(sources(src)).expect("egress effect policy opens"))
}

/// An interceptor whose engine includes the generated `demo` per-tool actions.
fn egress_interceptor_with_demo_tools(src: &str) -> Arc<dyn EffectInterceptor> {
    let fragment = generate_mcp_schema("demo", DEMO_TOOLS).expect("the demo MCP schema generates");
    let policy = support::open_policy_with_mcp_schemas(sources(src), &[fragment])
        .expect("egress effect policy and demo schema open");
    interceptor_from(policy)
}

fn sources(src: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("policy-egress-effect-e2e"),
        text: src.to_owned(),
    }]
}

fn interceptor_from(policy: policy::PolicyEngine) -> Arc<dyn EffectInterceptor> {
    EgressPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    )
}

#[test]
fn interceptor_maps_connect_request_and_the_response_phase() {
    let interceptor = egress_interceptor(
        r#"
        permit(principal, action == Box::Action::"net:connect", resource)
        when {
            context.input.host == "api.github.com" &&
            context.input.port == 443
        };
        permit(principal, action == Box::Action::"http:request", resource)
        when {
            context.input.host == "api.github.com" &&
            context.input.port == 443 &&
            context.input.method == "POST" &&
            context.input.path == "/v1/messages" &&
            context.input.body_bytes == 42 &&
            context.input.intercepted
        };
        "#,
    );
    let peer: SocketAddr = "192.0.2.1:443".parse().unwrap();

    interceptor
        .intercept(&EffectAttempt::Connect {
            host: "api.github.com",
            port: 443,
            address: peer,
            http_visibility: true,
        })
        .expect("connect is allowed")
        .record_outcome(EffectOutcome::Connected(peer))
        .expect("local outcome recording succeeds");
    interceptor
        .intercept(&request_attempt(443, 42))
        .expect("request is allowed")
        .record_outcome(EffectOutcome::Completed(100))
        .expect("local outcome recording succeeds");
    interceptor
        .intercept(&response_attempt(443, 84))
        .expect("response release is allowed")
        .record_outcome(EffectOutcome::Completed(120))
        .expect("local outcome recording succeeds");
}

/// The request leg projects `port` and `body_bytes` into its decision.
///
/// The response half is gone with the response decision: no rule runs on that leg, so a rule
/// cannot read a response's `port` or `body_bytes`.
#[test]
fn the_request_leg_projects_port_and_body_bytes() {
    let interceptor = egress_interceptor(
        r#"
        permit(principal, action == Box::Action::"http:request", resource)
        when {
            context.input.host == "api.github.com" &&
            context.input.port == 443 &&
            context.input.body_bytes == 42
        };
        "#,
    );

    interceptor
        .intercept(&request_attempt(443, 42))
        .expect("matching request metadata is allowed")
        .mark_indeterminate();
    assert!(interceptor.intercept(&request_attempt(8443, 42)).is_err());
    assert!(interceptor.intercept(&request_attempt(443, 43)).is_err());
}

/// The request is decided; the release of a reply is not.
///
/// An unpermitted request is refused, and the release is admitted whatever policy says, because
/// no rule can name it. The reply itself reaches history on the request permit, which
/// `adapters/egress.rs::the_request_is_decided_and_the_reply_is_recorded_once` pins.
#[test]
fn the_request_is_decided_and_the_release_is_not() {
    let request_only = egress_interceptor(
        r#"permit(principal, action == Box::Action::"http:request", resource)
           when { context.input.host == "api.github.com" };"#,
    );
    request_only
        .intercept(&request_attempt(443, 0))
        .expect("http:request allows the request")
        .mark_indeterminate();
    request_only
        .intercept(&response_attempt(443, 0))
        .expect("the release takes no decision, so it is admitted")
        .mark_indeterminate();

    let nothing =
        egress_interceptor(r#"permit(principal, action == Box::Action::"net:connect", resource);"#);
    assert!(
        nothing.intercept(&request_attempt(443, 0)).is_err(),
        "an unpermitted request must be refused"
    );
    nothing
        .intercept(&response_attempt(443, 0))
        .expect("the release is admitted whatever policy says")
        .mark_indeterminate();
}

#[test]
fn connect_authorizes_the_exact_host_and_port() {
    // Connect authorization discriminates on host and port.
    let interceptor = egress_interceptor(
        r#"
        permit(principal, action == Box::Action::"net:connect", resource)
        when {
            context.input.host == "api.github.com" && context.input.port == 443
        };
        "#,
    );
    let address: SocketAddr = "192.0.2.1:443".parse().unwrap();

    interceptor
        .intercept(&EffectAttempt::Connect {
            host: "api.github.com",
            port: 443,
            address,
            http_visibility: true,
        })
        .expect("the permitted host and port are allowed")
        .mark_indeterminate();

    assert!(
        interceptor
            .intercept(&EffectAttempt::Connect {
                host: "api.github.com",
                port: 8443,
                address: "192.0.2.1:8443".parse().unwrap(),
                http_visibility: true,
            })
            .is_err(),
        "an unlisted port must be denied"
    );

    assert!(
        interceptor
            .intercept(&EffectAttempt::Connect {
                host: "evil.example.com",
                port: 443,
                address,
                http_visibility: true,
            })
            .is_err(),
        "an unlisted host must be denied"
    );
}

fn request_attempt(port: u16, body_bytes: usize) -> EffectAttempt<'static> {
    EffectAttempt::HttpRequest {
        host: "api.github.com",
        port,
        method: "POST",
        path: "/v1/messages",
        body_bytes,
        intercepted: true,
        mcp: None,
    }
}

fn response_attempt(port: u16, body_bytes: usize) -> EffectAttempt<'static> {
    EffectAttempt::ResponseRelease {
        host: "api.github.com",
        port,
        method: "POST",
        path: "/v1/messages",
        status: 201,
        body_bytes,
    }
}

/// A remote MCP request leg carrying a classified tool call, as the gateway builds it for a
/// `protocol = "mcp"` destination. `server` is config-assigned; `tool` is what the frame named.
fn mcp_request_attempt(
    server: &'static str,
    tool: &'static str,
    arguments: &'static str,
) -> EffectAttempt<'static> {
    EffectAttempt::HttpRequest {
        host: "mcp-fixture.demo",
        port: 8931,
        method: "POST",
        path: "/mcp",
        body_bytes: 64,
        intercepted: false,
        mcp: Some(McpFrame::ToolCall {
            server,
            tool,
            arguments,
        }),
    }
}

/// A remote MCP tool call is gated per tool, under one broad `mcp:call` permit.
///
/// The request leg runs two gates in order — `http:request`, then `mcp:call` — with deny-overrides.
/// A `forbid` on one tool name refuses that tool at the second gate while every other tool on the
/// same server still passes. This is the automated form of the live check (`echo` → 403, `add` ok).
#[test]
fn a_remote_mcp_tool_call_is_gated_by_name() {
    let interceptor = egress_interceptor_with_demo_tools(
        r#"
        permit(principal, action == Box::Action::"http:request", resource)
        when { context.input.host == "mcp-fixture.demo" };

        permit(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" };

        forbid(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" &&
               context.input has tool && context.input.tool == "echo" };
        "#,
    );

    // `add` clears `http:request` and the broad `mcp:call` permit, with no forbid against it. Its
    // per-tool action is declared but unauthored, so the refinement gate passes it.
    interceptor
        .intercept(&mcp_request_attempt("demo", "add", r#"{"a":2,"b":3}"#))
        .expect("a permitted tool passes http:request then mcp:call")
        .mark_indeterminate();

    // `echo` clears `http:request` but the forbid denies it at the `mcp:call` gate.
    let denied = interceptor
        .intercept(&mcp_request_attempt("demo", "echo", r#"{"text":"hi"}"#))
        .err()
        .expect("a forbidden tool must be denied at the mcp:call gate");
    // The deny reason names the tool gate and the server and method, so the durable audit tells
    // this apart from a host-level block. The workload-controlled tool name is NOT in the line
    // (it could carry a secret); the durable decision record names it through the context.
    let reason = denied.to_string();
    assert!(
        reason.contains("mcp:call gate")
            && reason.contains("\"demo\"")
            && reason.contains("\"tools/call\""),
        "the tool-gate denial must name the layer, server, and method: {reason}"
    );
}

/// The typed tool gate refines the `mcp:call` allow by an argument value.
#[test]
fn a_per_tool_forbid_refines_the_mcp_call_allow_by_argument() {
    let interceptor = egress_interceptor_with_demo_tools(
        r#"
        permit(principal, action == Box::Action::"http:request", resource)
        when { context.input.host == "mcp-fixture.demo" };

        permit(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" };

        forbid(principal, action == demo::Action::"add", resource)
        when { context.input.a > 100 };
        "#,
    );

    // Under the cap: `mcp:call` allows it, and the per-tool gate has no matching forbid and no
    // permit — so the refinement passes it (it does not default-deny).
    interceptor
        .intercept(&mcp_request_attempt("demo", "add", r#"{"a":2,"b":3}"#))
        .expect("a=2 is under the cap, so mcp:call allows and the per-tool gate does not forbid")
        .mark_indeterminate();

    // Over the cap: `mcp:call` still allows, but the per-tool `forbid` matches on `a`, so the
    // refinement denies. The denial names the per-tool action.
    let reason = interceptor
        .intercept(&mcp_request_attempt("demo", "add", r#"{"a":200,"b":1}"#))
        .err()
        .expect("a=200 exceeds the cap, so the per-tool forbid denies")
        .to_string();
    assert!(
        reason.contains("per-tool gate") && reason.contains(r#"demo::Action::"add""#),
        "the arg-level denial must name the per-tool gate and action: {reason}"
    );
}

/// A host-level denial names the `http:request` gate, not the tool gate, so an operator reading
/// the audit can tell a host block from a tool block.
#[test]
fn a_host_level_denial_names_the_http_request_gate() {
    let interceptor = egress_interceptor(
        r#"
        permit(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" };
        "#,
    );

    let reason = interceptor
        .intercept(&mcp_request_attempt("demo", "add", r#"{"a":2,"b":3}"#))
        .err()
        .expect("with no http:request permit, the host gate denies")
        .to_string();
    assert!(
        reason.contains("http:request gate") && !reason.contains("mcp:call gate"),
        "a host-level denial must name the http:request gate and not the tool gate: {reason}"
    );
}

/// The `http:request` gate runs first: a frame whose host is not permitted is refused before its
/// `mcp:call` is even asked, so a tool the `mcp:call` rules would allow still cannot reach the
/// server. This pins the ordering, not just the pair.
#[test]
fn the_mcp_call_gate_is_reached_only_after_http_request_passes() {
    let interceptor = egress_interceptor(
        r#"
        permit(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" };
        "#,
    );

    assert!(
        interceptor
            .intercept(&mcp_request_attempt("demo", "add", r#"{"a":2,"b":3}"#,))
            .is_err(),
        "with no http:request permit, the first gate denies before mcp:call is asked"
    );
}

#[test]
fn an_unmapped_attempt_is_denied_rather_than_admitted() {
    // Both crates' `EffectAttempt` is `#[non_exhaustive]`, so upstream can add a variant
    // this adapter cannot map. The catch-all must DENY: an attempt nobody can authorize
    // must not reach the network because the mapping fell through.
    //
    // The variant cannot be constructed here (that is what `#[non_exhaustive]` means), so
    // this asserts the property the arm implements — a denial carries
    // `PermissionDenied` — over the mapped variants, and the arm itself is read as the
    // same construction. See `src/adapters/egress.rs`.
    let interceptor = egress_interceptor(r#"forbid(principal, action, resource);"#);
    let attempt = EffectAttempt::Connect {
        host: "api.github.com",
        port: 443,
        address: "192.0.2.1:443".parse().unwrap(),
        http_visibility: true,
    };
    let error = interceptor
        .intercept(&attempt)
        .err()
        .expect("a forbid denies");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "a denial must be PermissionDenied so the proxy answers 403 rather than 502"
    );
}

/// A tool with the full range of argument shapes — an **enum**, a **`number`**, an array (`Set`), an
/// integer, and a nested object — must conform and be gate-able by value. `generate_mcp_schema`
/// lowers the enum to `String` and the `number` to `Long`, so the bare values a tool call carries
/// conform and a rule reads them directly. Before that lowering the enum/number became Cedar
/// entities and the request was denied (a 403) even with no authored rule.
///
/// Mirrors a github filter tool: `state` (enum), `perPage` (number), `labels` (array), `limit`
/// (integer), `range` (nested object).
#[test]
fn a_tool_call_with_enum_and_number_and_nested_args_is_gated_by_value() {
    let fragment = generate_mcp_schema(
        "demo",
        r#"{"result":{"tools":[
            {"name":"filter","description":"filter","inputSchema":{"type":"object",
              "properties":{
                "state":{"type":"string","enum":["open","closed","all"]},
                "perPage":{"type":"number"},
                "labels":{"type":"array","items":{"type":"string"}},
                "limit":{"type":"integer"},
                "range":{"type":"object","properties":{"min":{"type":"integer"},"max":{"type":"integer"}}}},
              "required":["state"]}}
        ]}}"#,
    )
    .expect("the filter tool schema generates");
    let interceptor = interceptor_from(
        support::open_policy_with_mcp_schemas(
            sources(
                r#"permit (principal, action == Box::Action::"http:request", resource)
                   when { context.input.host == "mcp-fixture.demo" };
                   permit (principal, action == Box::Action::"mcp:call", resource)
                   when { context.input.server == "demo" };
                   // Gate on the (lowered-to-String) enum value.
                   forbid (principal, action == demo::Action::"filter", resource)
                   when { context.input.state == "open" };"#,
            ),
            &[fragment],
        )
        .expect("the policy and filter schema open"),
    );

    // Every arg shape present and `state != "open"`: conforms and rides the `mcp:call` allow.
    interceptor
        .intercept(&mcp_request_attempt(
            "demo",
            "filter",
            r#"{"state":"closed","perPage":30,"labels":["bug","p1"],"limit":5,"range":{"min":1,"max":9}}"#,
        ))
        .expect("enum + number + array + nested args conform and are allowed")
        .mark_indeterminate();

    // The enum value is gate-able as a plain string: `state == "open"` is refused.
    assert!(
        interceptor
            .intercept(&mcp_request_attempt(
                "demo",
                "filter",
                r#"{"state":"open","perPage":30,"labels":["bug"],"limit":5,"range":{"min":1,"max":9}}"#,
            ))
            .is_err(),
        "a forbid on the enum value must refuse the call"
    );
}

/// Outside a temporal clause `context.output` is absent at decision time.
#[test]
fn a_rule_that_reads_context_output_outside_a_temporal_clause_is_refused_or_never_matches() {
    let bare = support::open_policy(sources(
        r#"permit(principal, action == Box::Action::"http:request", resource)
        when { context.output.status == 200 };"#,
    ));
    let Err(policy::PolicyError::Schema(reason)) = bare else {
        panic!("the bare spelling is refused at load, got {bare:?}");
    };
    assert!(reason.contains("optional attribute `output`"), "{reason}");

    let interceptor = egress_interceptor(
        r#"permit(principal, action == Box::Action::"http:request", resource)
        when { context has output && context.output.status == 200 };"#,
    );
    let error = interceptor
        .intercept(&request_attempt(443, 0))
        .err()
        .expect("no permit matches, so the request is default-denied");
    assert_eq!(
        error.to_string(),
        "http:request gate: policy denied this operation on 'api.github.com:443/v1/messages' \
         [default-deny]: No permit policy matched this request."
    );
}

fn request_to_host(host: &'static str) -> EffectAttempt<'static> {
    EffectAttempt::HttpRequest {
        host,
        port: 443,
        method: "GET",
        path: "/",
        body_bytes: 0,
        intercepted: true,
        mcp: None,
    }
}

fn assert_default_denied(interceptor: &Arc<dyn EffectInterceptor>, host: &'static str) {
    let denied = interceptor
        .intercept(&request_to_host(host))
        .err()
        .unwrap_or_else(|| panic!("{host} must not match the host rule"));
    assert_eq!(
        denied.to_string(),
        format!(
            "http:request gate: policy denied this operation on '{host}:443/' \
             [default-deny]: No permit policy matched this request."
        )
    );
}

/// `like "*.example.com"` admits the subdomain and refuses the apex until a second clause names it.
#[test]
fn a_host_wildcard_admits_the_subdomain_and_refuses_the_apex_until_a_clause_names_it() {
    let wildcard_only = egress_interceptor(
        r#"permit(principal, action == Box::Action::"http:request", resource)
           when { context.input.host like "*.example.com" };"#,
    );
    wildcard_only
        .intercept(&request_to_host("www.example.com"))
        .expect("the subdomain matches the wildcard")
        .mark_indeterminate();
    for host in [
        "example.com",
        "example.net",
        "example.com.evil.net",
        "wwwexample.com",
    ] {
        assert_default_denied(&wildcard_only, host);
    }

    let apex_named_too = egress_interceptor(
        r#"permit(principal, action == Box::Action::"http:request", resource)
           when { context.input.host like "*.example.com" || context.input.host == "example.com" };"#,
    );
    for host in ["www.example.com", "example.com"] {
        apex_named_too
            .intercept(&request_to_host(host))
            .unwrap_or_else(|error| panic!("{host} is named by one of the two clauses: {error}"))
            .mark_indeterminate();
    }
    for host in ["example.net", "example.com.evil.net"] {
        assert_default_denied(&apex_named_too, host);
    }
}
