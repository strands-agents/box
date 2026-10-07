//! `mcp:call`: one action with a typed context, and the two rule shapes an operator needs.
//!
//! **A group action is deliberately not available**, and these tests are what make that a
//! trade rather than a gap. Commit `cbd983e` removed Cedar action groups from this schema
//! because a group action is never raised, so a temporal rule against one counts nothing and
//! silently enforces nothing. The Lifecycle design writes `action in [Box::Action::"mcp:<server>"]`
//! and calls it a group; a typed context expresses both shapes it was wanted for, with rules
//! that actually fire.

mod support;

use std::path::PathBuf;

use policy::{GovernedBox, Policy, PolicyEngine, Principal, Request};

fn loaded(text: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("mcp.dw"),
        text: text.to_string(),
    }])
    .expect("the policy loads")
}

fn allows(policy: &PolicyEngine, server: &str, tool: &str) -> bool {
    policy
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::McpCall {
                server,
                method: "tools/call",
                tool: Some(tool),
                prompt: None,
                uri: None,
                arguments: None,
            },
        )
        .is_allow()
}

fn allows_read(policy: &PolicyEngine, server: &str, uri: &str) -> bool {
    policy
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::McpCall {
                server,
                method: "resources/read",
                tool: None,
                prompt: None,
                uri: Some(uri),
                arguments: None,
            },
        )
        .is_allow()
}

fn allows_list(policy: &PolicyEngine, server: &str) -> bool {
    policy
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::McpCall {
                server,
                method: "tools/list",
                tool: None,
                prompt: None,
                uri: None,
                arguments: None,
            },
        )
        .is_allow()
}

/// **Every tool on one server, in one rule.** This is what a group was wanted for.
#[test]
fn a_server_scoped_permit_reaches_every_tool_on_that_server() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.server == "issues-mcp" };"#,
    );

    assert!(allows(&policy, "issues-mcp", "SearchIssues"));
    assert!(allows(&policy, "issues-mcp", "ListComments"));
    assert!(
        !allows(&policy, "aws-mcp", "SearchIssues"),
        "a rule naming one server must not reach another"
    );
}

/// **One tool refused by name, and the rest still work.** The other half of the group's job.
///
/// A `forbid` survives a widening, which is the property an operator relies on: the permit
/// above may be broadened later and this refusal still holds.
#[test]
fn a_tool_scoped_forbid_refuses_one_tool_and_leaves_the_rest() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.server == "issues-mcp" };
           forbid (principal, action == Box::Action::"mcp:call", resource)
           when { context.input has tool && context.input.tool == "AddComment" };"#,
    );

    assert!(
        !allows(&policy, "issues-mcp", "AddComment"),
        "a forbid on one tool must refuse that tool"
    );
    assert!(
        allows(&policy, "issues-mcp", "SearchIssues"),
        "and must leave every other tool on the server working"
    );
}

/// **The coarse action gates every MCP method, not just `tools/call`.** A server-scoped permit
/// reaches a `resources/read` and a `tools/list` the same way it reaches a tool call, so an
/// operator writes one rule for a whole server.
#[test]
fn a_server_scoped_permit_reaches_every_method() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.server == "issues-mcp" };"#,
    );

    assert!(allows(&policy, "issues-mcp", "SearchIssues"));
    assert!(allows_read(&policy, "issues-mcp", "file:///demo/notes.txt"));
    assert!(allows_list(&policy, "issues-mcp"));
}

/// **A method and a per-item identity refuse one resource by URI.** A `resources/read` carries a
/// `uri` and no `tool`, so the rule guards `context.input has uri`; the same permit still allows a
/// tool call, which carries no `uri`.
#[test]
fn a_method_and_uri_scoped_forbid_refuses_one_resource() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.server == "issues-mcp" };
           forbid (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.method == "resources/read" &&
                  context.input has uri && context.input.uri like "file:///etc/*" };"#,
    );

    assert!(
        !allows_read(&policy, "issues-mcp", "file:///etc/passwd"),
        "a forbid on one resource URI must refuse that read"
    );
    assert!(
        allows_read(&policy, "issues-mcp", "file:///demo/notes.txt"),
        "and must leave another resource readable"
    );
    assert!(
        allows(&policy, "issues-mcp", "SearchIssues"),
        "a tool call carries no uri, so the resource forbid never reaches it"
    );
}

/// Absent policy denies a tool call, like every other action.
#[test]
fn an_unpermitted_tool_call_is_denied() {
    let policy = support::open_policy(Vec::new()).expect("an empty policy set loads");
    assert!(!allows(&policy, "issues-mcp", "SearchIssues"));
}

/// **Naming a server reaches nothing on its own.**
///
/// Running a server is `shell:spawn`; calling its tools is `mcp:call`. A rule permitting the
/// first must not permit the second, or an operator who allowed a server to start would have
/// allowed everything it can do.
#[test]
fn permitting_a_server_to_run_does_not_permit_its_tools() {
    let policy = loaded(
        r#"permit (principal, action == Box::Action::"shell:spawn", resource)
           when { context.input.program == "issues-mcp" };"#,
    );

    assert!(
        !allows(&policy, "issues-mcp", "SearchIssues"),
        "shell:spawn authorizes starting the server, never calling its tools"
    );
}
