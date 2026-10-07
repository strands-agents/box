//! Adapters from the policy facade to egress effect interception.

use std::collections::BTreeSet;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use egress_gateway::{
    EffectAttempt as EgressEffectAttempt, EffectInterceptor as EgressEffectInterceptor,
    EffectOutcome as EgressEffectOutcome, EffectPermit as EgressEffectPermit, McpFrame,
    McpListReply,
};

use crate::GovernedBox;
use crate::{
    CatalogRefusal, CatalogStage, DiscoveryFailure, ListPage, McpServerKind, ToolCatalogs,
};
use crate::{Decision, Delivery, DenyReason, Outcome, PolicyEngine, Principal, Request};

/// Binds one policy and egress principal to outbound effect interception.
pub struct EgressPolicyInterceptor {
    policy: Arc<PolicyEngine>,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    /// The hosts of the configured remote MCP servers, which the pending-verdict arms below admit.
    /// Those arms cannot fire, because a pending verdict is raised only for an MCP tool call
    /// (docs/design/decisions.md#a-pending-authority-bootstraps-a-handshake-and-never-an-act).
    mcp_hosts: BTreeSet<String>,
    /// The box's tool catalogs, which hold each remote server's accepted `tools/list`.
    catalogs: Arc<ToolCatalogs>,
    /// Reports the egress door finished to the box's discovery coordinator
    /// (docs/design/decisions.md#the-box-coordinates-discovery-completion).
    on_remote_finished: Arc<dyn Fn() + Send + Sync>,
}

impl EgressPolicyInterceptor {
    /// Construct the egress effect-interceptor handle, with no remote MCP servers to track.
    pub fn into_handle(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
    ) -> Arc<dyn EgressEffectInterceptor> {
        let catalogs = Arc::new(ToolCatalogs::new(Arc::clone(&policy), Vec::new()));
        Self::into_handle_with_discovery(
            policy,
            principal,
            governed,
            Vec::new(),
            catalogs,
            Arc::new(|| {}),
        )
    }

    /// Construct the handle and track lazy remote MCP discovery in `catalogs`, calling
    /// `on_remote_finished` once every HTTP server there is terminal.
    pub fn into_handle_with_discovery(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
        remote_servers: Vec<(String, String)>,
        catalogs: Arc<ToolCatalogs>,
        on_remote_finished: Arc<dyn Fn() + Send + Sync>,
    ) -> Arc<dyn EgressEffectInterceptor> {
        let mcp_hosts: BTreeSet<String> = remote_servers
            .iter()
            .map(|(host, _)| host.clone())
            .collect();
        Arc::new(Self {
            policy,
            principal,
            governed,
            mcp_hosts,
            catalogs,
            on_remote_finished,
        })
    }

    /// Refuse a call to a tracked server unless its accepted `tools/list` names `tool` exactly.
    fn require_accepted_tool(&self, server: &str, tool: &str) -> Result<(), String> {
        match self.catalogs.require_listed(server, tool) {
            Ok(()) | Err(CatalogRefusal::Undeclared) => Ok(()),
            Err(refusal @ CatalogRefusal::NotListed) => Err(format!(
                "mcp-catalog (server {:?} tool {:?}): {refusal}",
                diagnostic_context(server),
                diagnostic_context(tool)
            )),
            Err(refusal @ CatalogRefusal::NotAccepted) => Err(format!(
                "mcp-catalog (server {:?}): {refusal}",
                diagnostic_context(server)
            )),
        }
    }

    /// Report the egress door finished once every remote server is terminal.
    fn report_if_remote_finished(&self) {
        if self.catalogs.kind_done(McpServerKind::Http) {
            (self.on_remote_finished)();
        }
    }

    /// The two MCP gates on an allowed `http:request`: `mcp:call` identity, then the per-tool typed
    /// refinement. A non-MCP request carries no frame and passes.
    fn mcp_gates(&self, mcp: &Option<McpFrame<'_>>) -> Result<(), String> {
        let Some(frame) = mcp else { return Ok(()) };
        // Gate one: `mcp:call` (identity). `{:?}` quotes the server and method, so a hostile
        // identity cannot forge a log line; identity and args are omitted from it.
        let request = mcp_request(frame);
        if let Err(reason) = authorize(&self.policy, &self.governed, &self.principal, &request) {
            // A denied `tools/list` produces no reply, so the server is marked terminal here, and
            // discovery can finish with that one server degraded.
            if let McpFrame::List { server, method } = *frame
                && method == "tools/list"
            {
                self.catalogs.list_denied(server);
                self.report_if_remote_finished();
            }
            return Err(format!(
                "mcp:call gate (server {:?} method {:?}): {reason}",
                diagnostic_context(frame.server()),
                diagnostic_context(frame.method())
            ));
        }
        // Gate two: the namespaced per-tool action, a refinement of the `mcp:call` allow. A tracked
        // server's tool must first be named exactly by its accepted `tools/list`. The refinement then
        // blocks only on an explicit `forbid`, and an unruled tool rides the coarse allow. `McpFrame`
        // is `Copy`.
        if let McpFrame::ToolCall {
            server,
            tool,
            arguments,
        } = *frame
        {
            self.require_accepted_tool(server, tool)?;
            let identity = crate::schema::ActionIdentity::mcp_tool(server, tool);
            let action = identity.observer_action();
            // The raw `params.arguments` JSON, typed against the tool's generated schema. A parse
            // failure is fail-closed.
            let arguments: serde_json::Value =
                serde_json::from_str(arguments).map_err(|error| {
                    format!(
                        "per-tool gate ({}): invalid arguments JSON: {error}",
                        diagnostic_context(&action)
                    )
                })?;
            if let decision @ Decision::Deny { .. } = self.policy.refine_tool_call(
                &self.governed,
                &self.principal,
                server,
                tool,
                &arguments,
            ) {
                return Err(format!(
                    "per-tool gate ({}): {decision}",
                    diagnostic_context(&action)
                ));
            }
        }
        Ok(())
    }
}

impl EgressEffectInterceptor for EgressPolicyInterceptor {
    fn intercept(
        &self,
        effect: &EgressEffectAttempt<'_>,
    ) -> io::Result<Box<dyn EgressEffectPermit>> {
        let decision = match effect {
            // The host, decided before it is resolved. No address exists yet, so an address rule does
            // not apply here; it applies to the per-address `Connect` that follows.
            EgressEffectAttempt::Resolve { host, port } => match self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::Connect {
                    host,
                    ip: None,
                    port: *port,
                },
            ) {
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                } if self.mcp_hosts.contains(*host) => Ok(()),
                decision @ Decision::Deny { .. } => Err(decision.to_string()),
                Decision::Allow { .. } => Ok(()),
            },
            EgressEffectAttempt::Connect {
                host,
                port,
                address,
                ..
            } => match self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::Connect {
                    host,
                    ip: Some(address.ip()),
                    port: *port,
                },
            ) {
                // Unreachable: a `Connect` never carries `PolicyPending`, so this arm never fires.
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                } if self.mcp_hosts.contains(*host) => Ok(()),
                decision @ Decision::Deny { .. } => Err(decision.to_string()),
                Decision::Allow { .. } => Ok(()),
            },
            EgressEffectAttempt::HttpRequest {
                host,
                port,
                method,
                path,
                body_bytes,
                intercepted,
                mcp,
            } => {
                // The `http:request` gate. `decide` records to history, so it is called exactly
                // once here; the `mcp:call` gate below is the second recorded decision.
                match self.policy.decide(
                    &self.governed,
                    &self.principal,
                    &Request::Http {
                        host,
                        port: *port,
                        method,
                        path,
                        body_bytes: *body_bytes,
                        intercepted: *intercepted,
                    },
                ) {
                    // Unreachable: an `Http` request never carries `PolicyPending`, so this arm never
                    // fires.
                    Decision::Deny {
                        reason: DenyReason::PolicyPending,
                        ..
                    } if self.mcp_hosts.contains(*host)
                        && !matches!(
                            mcp,
                            Some(
                                McpFrame::ToolCall { .. }
                                    | McpFrame::PromptGet { .. }
                                    | McpFrame::ResourceRead { .. }
                            )
                        ) =>
                    {
                        Ok(())
                    }
                    decision @ Decision::Deny { .. } => {
                        Err(format!("http:request gate: {decision}"))
                    }
                    // Allowed; the `mcp:call` gate and per-tool refinement run on the Ready authority.
                    Decision::Allow { .. } => self.mcp_gates(mcp),
                }
            }
            // The release of a reply to the workload decides nothing and records nothing. The
            // reply reaches history once, on the `HttpRequest` permit, as `output.status`.
            EgressEffectAttempt::ResponseRelease { .. } => Ok(()),
            _ => Err("policy does not support this egress effect".to_string()),
        };

        decision
            .map(|()| {
                Box::new(LocalPolicyEffectPermit {
                    policy: Arc::clone(&self.policy),
                    principal: self.principal.clone(),
                    governed: self.governed.clone(),
                    attempt: AttemptIdentity::capture(effect),
                }) as Box<dyn EgressEffectPermit>
            })
            .map_err(permission_denied)
    }

    fn stage_mcp_catalog(&self, server: &str, reply: McpListReply<'_>) -> io::Result<()> {
        let staged = self.observe_list_reply(server, reply);
        self.report_if_remote_finished();
        staged
    }
}

impl EgressPolicyInterceptor {
    /// Observe one `tools/list` reply, and stage the catalog once its last page arrives
    /// (docs/design/decisions.md#remote-tool-schemas-are-discovered-at-runtime-in-memory).
    fn observe_list_reply(&self, server: &str, reply: McpListReply<'_>) -> io::Result<()> {
        let connection = reply.session.unwrap_or_default();
        let message = std::str::from_utf8(reply.body)
            .ok()
            .and_then(tools_list_json)
            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok());
        let Some(message) = message else {
            self.catalogs
                .list_failed(server, connection, DiscoveryFailure::CatalogCapture);
            return Err(io::Error::other(format!(
                "no tools/list JSON in the {server:?} response"
            )));
        };
        let page = self
            .catalogs
            .observe_page(server, connection, reply.cursor, &message, reply.body.len())
            .map_err(|failure| {
                io::Error::other(format!("{server:?} tools/list failed during {failure}"))
            })?;
        let ListPage::Complete(catalog) = page else {
            return Ok(());
        };
        match self.catalogs.stage(catalog) {
            Ok(CatalogStage::Accepted { .. } | CatalogStage::Unchanged) => Ok(()),
            Ok(CatalogStage::Rejected { reason, .. }) => Err(io::Error::other(format!(
                "schema for {server:?} rejected: {reason}"
            ))),
            Err(error) => Err(io::Error::other(format!(
                "stage schema for {server:?}: {error}"
            ))),
        }
    }
}

/// The tools/list JSON from a captured response body. A plain-JSON body is returned as-is; an MCP
/// Streamable-HTTP body is Server-Sent Events, so the `data:` payload carrying `result.tools` is
/// unwrapped. Returns `None` when no such payload is present.
fn tools_list_json(body: &str) -> Option<String> {
    if body.trim_start().starts_with('{') {
        return Some(body.to_string());
    }
    // Walk the SSE stream: `data:` lines within one event join with `\n`, and a blank line ends the
    // event. Pick the first event whose JSON is a JSON-RPC message carrying `result.tools`.
    let mut data = String::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        } else if line.trim().is_empty() {
            if let Some(found) = tools_list_event(&data) {
                return Some(found);
            }
            data.clear();
        }
    }
    tools_list_event(&data)
}

/// One SSE event's data, when it is a JSON-RPC message carrying `result.tools`.
fn tools_list_event(data: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    value
        .get("result")
        .and_then(|result| result.get("tools"))
        .is_some()
        .then(|| data.to_string())
}

/// What the permit must remember to build a history event.
/// The MCP identity of an `http:request` that carried an `mcp:call`, kept so the delivery outcome
/// can record the `mcp:call::response` leg for a remote (http) MCP server. Owned,
/// because the source `McpFrame` is borrowed for the request only.
struct McpCallIdentity {
    server: String,
    method: String,
    tool: Option<String>,
    prompt: Option<String>,
    uri: Option<String>,
}

enum AttemptIdentity {
    Connect {
        host: String,
        port: u16,
        address: SocketAddr,
    },
    Http {
        host: String,
        port: u16,
        method: String,
        path: String,
        /// Present when this request carried an `mcp:call`; drives the response-leg recording.
        mcp: Option<McpCallIdentity>,
    },
    /// An attempt kind this adapter does not map, and the release of a reply. Each is admitted
    /// only if the authorization arm above allowed it, and it records nothing.
    Unmapped,
}

impl AttemptIdentity {
    fn capture(effect: &EgressEffectAttempt<'_>) -> Self {
        match effect {
            EgressEffectAttempt::Connect {
                host,
                port,
                address,
                ..
            } => Self::Connect {
                host: (*host).to_string(),
                port: *port,
                address: *address,
            },
            EgressEffectAttempt::HttpRequest {
                host,
                port,
                method,
                path,
                mcp,
                ..
            } => Self::Http {
                host: (*host).to_string(),
                port: *port,
                method: (*method).to_string(),
                path: (*path).to_string(),
                // Record a response leg only for an actual tool/resource/prompt CALL — never for
                // `List`/enumeration (tools/list, resources/list, prompts/list). Discovery drives
                // those `List` frames through the gateway at startup; counting them would inflate a
                // temporal usage cap so it fires before the first real call.
                mcp: mcp.as_ref().and_then(|frame| match frame {
                    McpFrame::List { .. } => None,
                    McpFrame::ToolCall { server, tool, .. } => Some(McpCallIdentity {
                        server: (*server).to_string(),
                        method: frame.method().to_string(),
                        tool: Some((*tool).to_string()),
                        prompt: None,
                        uri: None,
                    }),
                    McpFrame::PromptGet { server, prompt, .. } => Some(McpCallIdentity {
                        server: (*server).to_string(),
                        method: frame.method().to_string(),
                        tool: None,
                        prompt: Some((*prompt).to_string()),
                        uri: None,
                    }),
                    McpFrame::ResourceRead { server, uri, .. } => Some(McpCallIdentity {
                        server: (*server).to_string(),
                        method: frame.method().to_string(),
                        tool: None,
                        prompt: None,
                        uri: Some((*uri).to_string()),
                    }),
                }),
            },
            _ => Self::Unmapped,
        }
    }
}

struct LocalPolicyEffectPermit {
    policy: Arc<PolicyEngine>,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    attempt: AttemptIdentity,
}

impl LocalPolicyEffectPermit {
    /// Submit this effect's history, translating the proxy's outcome into the policy
    /// vocabulary.
    fn submit(&self, outcome: EgressEffectOutcome) -> io::Result<()> {
        let delivery = delivery_of(outcome);
        let recorded = match (&self.attempt, delivery) {
            (
                AttemptIdentity::Connect {
                    host,
                    port,
                    address,
                },
                _,
            ) => self.policy.record(
                &self.governed,
                &self.principal,
                &Outcome::Connect {
                    host,
                    port: *port,
                    address: *address,
                    // False only for a connect that definitely failed. An
                    // indeterminate outcome may have opened the socket, so it stays
                    // a `response` and a rule capping connects still counts it.
                    connected: !matches!(outcome, EgressEffectOutcome::ConnectFailed(_)),
                },
            ),
            (
                AttemptIdentity::Http {
                    host,
                    port,
                    method,
                    path,
                    mcp,
                },
                Some(delivery),
            ) => {
                let http = self.policy.record(
                    &self.governed,
                    &self.principal,
                    &Outcome::Http {
                        host,
                        port: *port,
                        method,
                        path,
                        delivery,
                        status: reply_status_of(outcome),
                    },
                );
                // Record the `mcp:call::response` leg for a remote (http) MCP call, so temporal caps
                // over `mcp:call::response` fire for http-transport servers too — the gateway twin of
                // the stdio broker's `forward_server_frame` recording. Record for every
                // delivery EXCEPT a definite `Failed`, exactly matching `outcome_kind(Outcome::Http)`:
                // a `Partial` or `Indeterminate` delivery counts as a `::response` too. This is the
                // soundness rule — an attacker who forces an uncertain outcome (e.g. a TLS reset after
                // flush) must not be able to slip a call past an `mcp:call` cap when the same trick
                // would not slip it past the `http:request` cap on the identical request. A completed
                // call is a `response` whatever the server then replies (a JSON-RPC error is still
                // `::response`, like a delivered `Http` request with a 500); only a definite `Failed`
                // — the effect provably did not occur — records nothing.
                match mcp {
                    Some(mcp) if !matches!(delivery, Delivery::Failed) => {
                        http.and(self.policy.record(
                            &self.governed,
                            &self.principal,
                            &Outcome::Mcp {
                                server: &mcp.server,
                                method: &mcp.method,
                                tool: mcp.tool.as_deref(),
                                prompt: mcp.prompt.as_deref(),
                                uri: mcp.uri.as_deref(),
                            },
                        ))
                    }
                    _ => http,
                }
            }
            // A message attempt whose outcome carries no delivery, or an unmapped
            // attempt: nothing truthful to record.
            _ => Ok(()),
        };

        if recorded.is_err() {
            let _ = writeln!(
                io::stderr().lock(),
                "strands-box: warning: policy outcome recording was not confirmed"
            );
        }
        Ok(())
    }
}

impl EgressEffectPermit for LocalPolicyEffectPermit {
    fn record_outcome(self: Box<Self>, outcome: EgressEffectOutcome) -> io::Result<()> {
        self.submit(outcome)
    }

    fn mark_indeterminate(self: Box<Self>) {
        // An admitted effect that ended with no terminal outcome. Record it as an
        // indeterminate delivery of zero known bytes rather than silently dropping it:
        // a rule that counts attempts must still see that one happened.
        let _ = self.submit(EgressEffectOutcome::Indeterminate { accepted_bytes: 0 });
    }
}

/// Translate the proxy's outcome into the policy's delivery vocabulary.
fn delivery_of(outcome: EgressEffectOutcome) -> Option<Delivery> {
    match outcome {
        EgressEffectOutcome::Completed(bytes)
        | EgressEffectOutcome::Replied {
            accepted_bytes: bytes,
            ..
        } => Some(Delivery::Completed { bytes }),
        EgressEffectOutcome::Partial { accepted_bytes, .. } => {
            Some(Delivery::Partial { accepted_bytes })
        }
        EgressEffectOutcome::Failed { .. } => Some(Delivery::Failed),
        EgressEffectOutcome::Indeterminate { accepted_bytes } => {
            Some(Delivery::Indeterminate { accepted_bytes })
        }
        EgressEffectOutcome::Connected(_) | EgressEffectOutcome::ConnectFailed(_) => None,
        // An outcome variant added upstream is recorded as an INDETERMINATE delivery,
        // not dropped. Returning `None` here would silently omit the effect from
        // history, so a rule looking back for it would conclude it never happened —
        // history that is quietly incomplete is worse than history that says "unknown".
        _ => Some(Delivery::Indeterminate { accepted_bytes: 0 }),
    }
}

/// The upstream's reply status, when the exchange got one.
fn reply_status_of(outcome: EgressEffectOutcome) -> Option<u16> {
    match outcome {
        EgressEffectOutcome::Replied { status, .. } => Some(status),
        _ => None,
    }
}

/// Map a classified MCP frame onto the `mcp:call` request. `server` and `method` are on every
/// frame; the per-item identity is set only for the method that carries it.
fn mcp_request<'a>(frame: &McpFrame<'a>) -> Request<'a> {
    let server = frame.server();
    let method = frame.method();
    match frame {
        McpFrame::ToolCall { tool, .. } => Request::McpCall {
            server,
            method,
            tool: Some(*tool),
            prompt: None,
            uri: None,
            arguments: None,
        },
        McpFrame::PromptGet { prompt, .. } => Request::McpCall {
            server,
            method,
            tool: None,
            prompt: Some(*prompt),
            uri: None,
            arguments: None,
        },
        McpFrame::ResourceRead { uri, .. } => Request::McpCall {
            server,
            method,
            tool: None,
            prompt: None,
            uri: Some(*uri),
            arguments: None,
        },
        McpFrame::List { .. } => Request::McpCall {
            server,
            method,
            tool: None,
            prompt: None,
            uri: None,
            arguments: None,
        },
    }
}

fn authorize(
    policy: &PolicyEngine,
    governed: &GovernedBox,
    principal: &Principal,
    request: &Request<'_>,
) -> Result<(), String> {
    match policy.decide(governed, principal, request) {
        Decision::Allow { .. } => Ok(()),
        decision @ Decision::Deny { .. } => Err(decision.to_string()),
    }
}

fn diagnostic_context(value: &str) -> String {
    const LIMIT: usize = 128;
    let mut text: String = value.chars().take(LIMIT).collect();
    if value.chars().nth(LIMIT).is_some() {
        text.push_str("...");
    }
    text
}

fn permission_denied(reason: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::ops::Deref;
    use std::path::PathBuf;

    use super::*;

    fn demo_catalogs(policy: &Arc<PolicyEngine>) -> Arc<ToolCatalogs> {
        Arc::new(ToolCatalogs::new(
            Arc::clone(policy),
            [("demo".to_string(), McpServerKind::Http)],
        ))
    }

    fn root_reply(body: &[u8]) -> McpListReply<'_> {
        McpListReply {
            session: None,
            cursor: None,
            body,
        }
    }

    fn page_reply<'a>(cursor: &'a str, body: &'a [u8]) -> McpListReply<'a> {
        McpListReply {
            session: None,
            cursor: Some(cursor),
            body,
        }
    }
    use crate::Policy;

    struct InterceptorFixture {
        interceptor: Arc<dyn EgressEffectInterceptor>,
        _history: tempfile::TempDir,
    }

    impl Deref for InterceptorFixture {
        type Target = dyn EgressEffectInterceptor;

        fn deref(&self) -> &Self::Target {
            self.interceptor.as_ref()
        }
    }

    fn interceptor(source: &str) -> InterceptorFixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("adapter-test.cedar"),
                text: source.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let interceptor = EgressPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        InterceptorFixture {
            interceptor,
            _history: history,
        }
    }

    /// The demo server's `tools/list`, which generates the typed `demo::Action::"add"` action.
    const DEMO_TOOLS: &str = r#"{"result":{"tools":[
      {"name":"add","description":"add","inputSchema":{"type":"object",
        "properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}}
    ]}}"#;

    /// An interceptor whose authority is blocked until the demo schema stages.
    fn blocked_interceptor() -> InterceptorFixture {
        tracked_interceptor(&format!(
            r#"{DEMO_PERMITS}
            forbid(principal, action == demo::Action::"add", resource)
            when {{ context.input has a && context.input.a > 5 }};"#
        ))
    }

    /// A `*/list` discovery frame to the demo MCP server.
    fn mcp_list_attempt(
        server: &'static str,
        method: &'static str,
    ) -> EgressEffectAttempt<'static> {
        EgressEffectAttempt::HttpRequest {
            host: "mcp-fixture.demo",
            port: 8931,
            method: "POST",
            path: "/mcp",
            body_bytes: 32,
            intercepted: false,
            mcp: Some(McpFrame::List { server, method }),
        }
    }

    /// A `tools/call` act frame to the demo MCP server.
    fn mcp_call_attempt(
        server: &'static str,
        tool: &'static str,
        arguments: &'static str,
    ) -> EgressEffectAttempt<'static> {
        EgressEffectAttempt::HttpRequest {
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

    /// A handshake and a `tools/list` to a configured MCP server are admitted while discovery runs.
    #[test]
    fn a_pending_authority_bootstraps_a_discovery_list() {
        let fixture = blocked_interceptor();
        fixture
            .intercept(&mcp_list_attempt("demo", "initialize"))
            .expect("initialize bootstraps while the authority is pending");
        fixture
            .intercept(&mcp_list_attempt("demo", "tools/list"))
            .expect("a tools/list bootstraps while the authority is pending");
    }

    /// The bootstrap is scoped to discovery frames: a `tools/call` never rides it, so no tool
    /// argument escapes the per-tool gate while the schema is still pending.
    #[test]
    fn a_pending_authority_never_bootstraps_a_tool_call() {
        let fixture = blocked_interceptor();
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":9,"b":2}"#))
                .is_err(),
            "a tools/call must be denied while pending, not bootstrapped"
        );
    }

    /// Remote leg: a remote (http) MCP tool call records `mcp:call::response` on
    /// delivery, so a temporal cap over `mcp:call::response` fires for http-transport servers too —
    /// the gateway twin of the stdio broker's recording. Two delivered calls → the 3rd is denied by
    /// the cap. Before this change the gateway recorded no response leg, so the count stayed 0 and
    /// the documented cap was inert. Guards the `submit`-records-`Outcome::Mcp` wiring — remove that
    /// and the 3rd call is admitted.
    #[test]
    fn a_remote_mcp_call_records_a_response_leg_a_temporal_cap_counts() {
        let source = r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.host == "mcp-fixture.demo" };
            permit(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" };
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" && context.input.method == "tools/call" }
            when temporal {
              exists (n: Long). (
                (count for (t: Timepoint). where (
                  formerly within 3600s (
                    Box::Action::"mcp:call"::response{ input.server: "demo" } && tp(t)
                  )
                )) == n
                && n >= 2
              )
            };
        "#;
        let fixture = interceptor(source);
        // Two calls under the cap: each admitted, each records a response leg on delivery.
        for _ in 0..2 {
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
                .expect("a call under the cap is admitted")
                .record_outcome(EgressEffectOutcome::Completed(4))
                .expect("the delivered call records its response leg");
        }
        // The third: count(mcp:call::response for demo) == 2 → the temporal forbid fires.
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
                .is_err(),
            "the 3rd remote mcp:call must be denied — the response leg now counts http calls"
        );
    }

    /// Remote leg: a DEFINITE `Failed` delivery — the write provably never reached the
    /// server — records NO `mcp:call::response` leg. Only `Failed` is excluded (matching
    /// `outcome_kind(Outcome::Http)`, which maps `Failed` to `::error` and everything else to
    /// `::response`); uncertain deliveries still count (see the two tests below). Here two FAILED
    /// deliveries record nothing, so the count stays 0 and a later call is still admitted.
    #[test]
    fn a_remote_mcp_call_that_failed_to_deliver_records_no_response_leg() {
        let source = r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.host == "mcp-fixture.demo" };
            permit(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" };
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" && context.input.method == "tools/call" }
            when temporal {
              exists (n: Long). (
                (count for (t: Timepoint). where (
                  formerly within 3600s (
                    Box::Action::"mcp:call"::response{ input.server: "demo" } && tp(t)
                  )
                )) == n
                && n >= 2
              )
            };
        "#;
        let fixture = interceptor(source);
        // Two calls that FAIL to deliver: each admitted at the gate, but the write never reaches the
        // server, so neither records a response leg.
        for _ in 0..2 {
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
                .expect("a call under the cap is admitted")
                .record_outcome(EgressEffectOutcome::Failed {
                    accepted_bytes: 0,
                    error_kind: std::io::ErrorKind::ConnectionReset,
                })
                .expect("a failed delivery records no response leg");
        }
        // The count is still 0 (no response legs recorded), so a further call is admitted.
        fixture
            .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
            .expect("a call must be admitted — failed deliveries never counted toward the cap");
    }

    /// An UNCERTAIN delivery counts toward an `mcp:call::response` cap, exactly
    /// as it counts toward the `http:request::response` cap (`outcome_kind(Outcome::Http)` maps
    /// everything but `Failed` to `::response`). This is the soundness rule: an attacker who forces an
    /// uncertain outcome must not slip a call past an `mcp:call` cap when the same trick would not slip
    /// it past the http cap. Two uncertain deliveries trip a `count(::response) >= 2` cap on the 3rd.
    fn an_uncertain_delivery_counts_toward_the_mcp_cap(outcome: EgressEffectOutcome) {
        let source = r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.host == "mcp-fixture.demo" };
            permit(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" };
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" && context.input.method == "tools/call" }
            when temporal {
              exists (n: Long). (
                (count for (t: Timepoint). where (
                  formerly within 3600s (
                    Box::Action::"mcp:call"::response{ input.server: "demo" } && tp(t)
                  )
                )) == n
                && n >= 2
              )
            };
        "#;
        let fixture = interceptor(source);
        for _ in 0..2 {
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
                .expect("a call under the cap is admitted")
                .record_outcome(outcome)
                .expect("an uncertain delivery records a response leg");
        }
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":1}"#))
                .is_err(),
            "the 3rd remote mcp:call must be denied — uncertain deliveries count, matching the http cap"
        );
    }

    #[test]
    fn a_partial_remote_mcp_delivery_counts_toward_the_cap() {
        an_uncertain_delivery_counts_toward_the_mcp_cap(EgressEffectOutcome::Partial {
            accepted_bytes: 8,
            error_kind: std::io::ErrorKind::ConnectionReset,
        });
    }

    #[test]
    fn an_indeterminate_remote_mcp_delivery_counts_toward_the_cap() {
        an_uncertain_delivery_counts_toward_the_mcp_cap(EgressEffectOutcome::Indeterminate {
            accepted_bytes: 8,
        });
    }

    /// A denied `tools/list` for a configured MCP server marks that server terminal, so the
    /// egress door can report finished and the box degrades the one server instead of hanging in
    /// `Discovering`. The denial happens at the `mcp:call` gate (the `http:request` gate allowed the
    /// host), which is where the terminal mark now fires. Without it `on_remote_finished` never runs.
    #[test]
    fn a_denied_tools_list_marks_the_remote_terminal_so_discovery_finishes() {
        let source = r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.host == "mcp-fixture.demo" };
            permit(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.server == "demo" };
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when { context.input.method == "tools/list" };
            forbid(principal, action == demo::Action::"add", resource)
            when { context.input has a && context.input.a > 5 };
        "#;
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open_staged(
            &crate::Operator::unanchored(),
            vec![Policy {
                origin: PathBuf::from("adapter-test.cedar"),
                text: source.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged policy opens Discovering");
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        let policy = Arc::new(policy);
        let interceptor = EgressPolicyInterceptor::into_handle_with_discovery(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
            vec![("mcp-fixture.demo".to_string(), "demo".to_string())],
            demo_catalogs(&policy),
            Arc::new(move || flag.store(true, std::sync::atomic::Ordering::SeqCst)),
        );
        assert!(
            interceptor
                .intercept(&mcp_list_attempt("demo", "tools/list"))
                .is_err(),
            "a forbidden tools/list must be denied, not bootstrapped"
        );
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "the denied tools/list must mark demo terminal and finish discovery"
        );
    }

    /// Staging a catalog declares the per-tool action, so the complete bundle validates, the
    /// authority becomes Ready, and the per-tool `forbid` takes effect.
    #[test]
    fn staging_a_catalog_flips_readiness_and_arms_the_per_tool_rule() {
        let fixture = blocked_interceptor();
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        fixture
            .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
            .expect("an add within the limit passes once the authority is Ready");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":9,"b":2}"#))
                .is_err(),
            "the per-tool forbid is armed once the schema is staged"
        );
    }

    /// A real remote catalog arrives as MCP Streamable-HTTP Server-Sent Events, not raw JSON. The
    /// `data:` payload is unwrapped before generation, so staging an SSE body flips readiness too.
    #[test]
    fn staging_an_sse_framed_catalog_succeeds() {
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[\
            {\"name\":\"add\",\"inputSchema\":{\"type\":\"object\",\
            \"properties\":{\"a\":{\"type\":\"integer\"},\"b\":{\"type\":\"integer\"}},\
            \"required\":[\"a\",\"b\"]}}]}}\n\n";
        let fixture = blocked_interceptor();
        fixture
            .stage_mcp_catalog("demo", root_reply(sse.as_bytes()))
            .expect("an SSE-framed catalog stages");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":9,"b":2}"#))
                .is_err(),
            "the per-tool forbid is armed after staging the SSE catalog"
        );
    }

    /// A `tools/list` page carrying a `nextCursor` accumulates but does not stage — the catalog is
    /// incomplete — so the authority stays blocked. The final page, with no cursor, stages the merged
    /// catalog and arms the per-tool rule.
    #[test]
    fn a_paginated_catalog_stages_only_on_the_final_page() {
        // Page one: a `search` tool and a `nextCursor`. Nothing about `add` yet.
        const PAGE_ONE: &str = r#"{"result":{"tools":[
            {"name":"search","inputSchema":{"type":"object",
              "properties":{"q":{"type":"string"}}}}
        ],"nextCursor":"page-2"}}"#;
        // Page two: the `add` tool and no cursor, so the merged catalog is complete.
        const PAGE_TWO: &str = r#"{"result":{"tools":[
            {"name":"add","description":"add","inputSchema":{"type":"object",
              "properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}}
        ]}}"#;
        let fixture = blocked_interceptor();

        fixture
            .stage_mcp_catalog("demo", root_reply(PAGE_ONE.as_bytes()))
            .expect("a page with a nextCursor accumulates");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
                .is_err(),
            "the authority stays blocked while the catalog is still paginating"
        );

        fixture
            .stage_mcp_catalog("demo", page_reply("page-2", PAGE_TWO.as_bytes()))
            .expect("the final page stages the merged catalog");
        fixture
            .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
            .expect("an in-limit add passes once the merged catalog is Ready");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":9,"b":2}"#))
                .is_err(),
            "the per-tool forbid is armed after the final page merges add"
        );
    }

    /// An interceptor under `source` that tracks the demo server, so its host is a bootstrap target
    /// while pending.
    fn tracked_interceptor(source: &str) -> InterceptorFixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open_staged(
            &crate::Operator::unanchored(),
            vec![Policy {
                origin: PathBuf::from("adapter-test.cedar"),
                text: source.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged policy opens");
        let policy = Arc::new(policy);
        let interceptor = EgressPolicyInterceptor::into_handle_with_discovery(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
            vec![("mcp-fixture.demo".to_string(), "demo".to_string())],
            demo_catalogs(&policy),
            Arc::new(|| {}),
        );
        InterceptorFixture {
            interceptor,
            _history: history,
        }
    }

    const DEMO_PERMITS: &str = r#"
        permit(principal, action == Box::Action::"http:request", resource)
        when { context.input.host == "mcp-fixture.demo" };
        permit(principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "demo" };
    "#;

    fn refusal(fixture: &InterceptorFixture, attempt: &EgressEffectAttempt<'_>) -> String {
        match fixture.intercept(attempt) {
            Ok(_) => panic!("the call must be refused"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_tool_call_before_any_accepted_catalog_is_refused() {
        let fixture = tracked_interceptor(DEMO_PERMITS);
        let reason = refusal(
            &fixture,
            &mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#),
        );
        assert!(
            reason.contains("the MCP tool catalog is not accepted"),
            "{reason}"
        );
    }

    #[test]
    fn a_tool_the_catalog_does_not_list_is_refused() {
        let fixture = tracked_interceptor(DEMO_PERMITS);
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        fixture
            .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
            .expect("a listed tool passes");
        let reason = refusal(&fixture, &mcp_call_attempt("demo", "hidden", "{}"));
        assert!(
            reason.contains("the tool is not in the accepted MCP catalog"),
            "{reason}"
        );
    }

    #[test]
    fn a_respelled_tool_name_is_refused() {
        let fixture = tracked_interceptor(DEMO_PERMITS);
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        for spelling in ["add ", "add\t", "add\n", "add\u{200b}", "Add", " add"] {
            let reason = refusal(
                &fixture,
                &mcp_call_attempt("demo", spelling, r#"{"a":9,"b":2}"#),
            );
            assert!(
                reason.contains("the tool is not in the accepted MCP catalog"),
                "{spelling:?}: {reason}"
            );
        }
    }

    #[test]
    fn a_respelled_tool_name_cannot_escape_a_per_tool_forbid() {
        let fixture = blocked_interceptor();
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add ", r#"{"a":9,"b":2}"#))
                .is_err(),
            "a trailing space must not reach the coarse allow past the per-tool forbid"
        );
    }

    #[test]
    fn a_respelled_tool_name_cannot_escape_a_tool_name_forbid() {
        let source = format!(
            r#"{DEMO_PERMITS}
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input has tool && context.input.tool == "add" }};"#
        );
        let fixture = tracked_interceptor(&source);
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add ", r#"{"a":1,"b":2}"#))
                .is_err(),
            "a trailing space must not miss a forbid on the tool name"
        );
    }

    #[test]
    fn a_fresh_tools_list_replaces_the_accepted_names() {
        const ECHO_ONLY: &str = r#"{"result":{"tools":[
            {"name":"echo","inputSchema":{"type":"object",
              "properties":{"text":{"type":"string"}}}}
        ]}}"#;
        let fixture = tracked_interceptor(DEMO_PERMITS);
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        fixture
            .stage_mcp_catalog("demo", root_reply(ECHO_ONLY.as_bytes()))
            .expect("the fresh catalog stages");
        fixture
            .intercept(&mcp_call_attempt("demo", "echo", r#"{"text":"x"}"#))
            .expect("a tool of the fresh list passes");
        assert!(
            fixture
                .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
                .is_err(),
            "a tool only the earlier list named is refused"
        );
    }

    #[test]
    fn a_failed_catalog_withdraws_the_accepted_names() {
        let fixture = tracked_interceptor(DEMO_PERMITS);
        fixture
            .stage_mcp_catalog("demo", root_reply(DEMO_TOOLS.as_bytes()))
            .expect("the demo catalog stages");
        assert!(
            fixture
                .stage_mcp_catalog("demo", root_reply(br#"{"result":{"tools":"not a list"}}"#))
                .is_err()
        );
        let reason = refusal(
            &fixture,
            &mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#),
        );
        assert!(
            reason.contains("the MCP tool catalog is not accepted"),
            "{reason}"
        );
    }

    #[test]
    fn an_untracked_server_is_not_held_to_a_catalog() {
        let fixture = interceptor(DEMO_PERMITS);
        fixture
            .intercept(&mcp_call_attempt("demo", "add", r#"{"a":1,"b":2}"#))
            .expect("a server the box does not track has no catalog to match");
    }

    #[test]
    fn tools_list_json_unwraps_plain_json_and_sse() {
        // Plain JSON passes through.
        assert!(tools_list_json(r#"{"result":{"tools":[]}}"#).is_some());
        // SSE with a `result.tools` event is unwrapped to its data payload.
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]}}\n\n";
        assert_eq!(
            tools_list_json(sse).as_deref(),
            Some(r#"{"jsonrpc":"2.0","result":{"tools":[]}}"#)
        );
        // An SSE stream with no tools/list event yields nothing.
        assert!(tools_list_json("event: ping\ndata: {\"jsonrpc\":\"2.0\"}\n\n").is_none());
    }

    /// The bootstrap keys on `PolicyPending`, not on a frame being a list: a Ready authority that
    /// does not permit the host denies a `tools/list` (a `NoMatch`) rather than bootstrapping it.
    #[test]
    fn a_ready_no_match_is_not_bootstrapped() {
        let fixture = interceptor(
            r#"permit(principal, action == Box::Action::"net:connect", resource)
               when { context.input.port == 443 };"#,
        );
        assert!(
            fixture
                .intercept(&mcp_list_attempt("demo", "tools/list"))
                .is_err(),
            "a tools/list on a Ready authority with no matching permit is denied"
        );
    }

    fn resolve_attempt(host: &'static str) -> EgressEffectAttempt<'static> {
        EgressEffectAttempt::Resolve { host, port: 443 }
    }

    /// A host forbid refuses the name before it is resolved, so no DNS query is made for it.
    #[test]
    fn a_host_forbid_refuses_resolution() {
        let fixture = interceptor(
            r#"permit(principal, action == Box::Action::"net:connect", resource);
               forbid(principal, action == Box::Action::"net:connect", resource)
               when { context.input.host == "exfil.attacker.test" };"#,
        );
        assert!(
            fixture
                .intercept(&resolve_attempt("exfil.attacker.test"))
                .is_err()
        );
        assert!(
            fixture
                .intercept(&resolve_attempt("api.github.com"))
                .is_ok()
        );
    }

    /// With no `net:connect` permit, every name is refused before it is resolved.
    #[test]
    fn default_deny_refuses_resolution() {
        let fixture =
            interceptor(r#"permit(principal, action == Box::Action::"http:request", resource);"#);
        assert!(
            fixture
                .intercept(&resolve_attempt("api.github.com"))
                .is_err()
        );
    }

    /// An address rule does not decide resolution, because no address exists yet; it decides the
    /// per-address `Connect` that follows.
    #[test]
    fn an_address_forbid_decides_the_connect_not_the_resolution() {
        let fixture = interceptor(
            r#"permit(principal, action == Box::Action::"net:connect", resource);
               forbid(principal, action == Box::Action::"net:connect", resource)
               when { context.input has ip && context.input.ip like "10.*" };"#,
        );
        assert!(
            fixture
                .intercept(&resolve_attempt("api.github.com"))
                .is_ok()
        );
        assert!(
            fixture
                .intercept(&connect_attempt("10.1.2.3:443".parse().unwrap()))
                .is_err()
        );
    }

    fn connect_attempt(address: SocketAddr) -> EgressEffectAttempt<'static> {
        EgressEffectAttempt::Connect {
            host: "api.github.com",
            port: 443,
            address,
            http_visibility: true,
        }
    }

    /// Every attempt the gateway raises reaches the adapter, and the response phase is
    /// admitted without a rule naming it — there is no response action to name.
    #[test]
    fn effect_interceptor_maps_every_attempt() {
        let interceptor = interceptor(
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
            .intercept(&connect_attempt(peer))
            .expect("connect is allowed")
            .record_outcome(EgressEffectOutcome::Connected(peer))
            .expect("local outcome recording succeeds");
        interceptor
            .intercept(&EgressEffectAttempt::HttpRequest {
                host: "api.github.com",
                port: 443,
                method: "POST",
                path: "/v1/messages",
                body_bytes: 42,
                intercepted: true,
                mcp: None,
            })
            .expect("request is allowed")
            .record_outcome(EgressEffectOutcome::Completed(100))
            .expect("local outcome recording succeeds");
        interceptor
            .intercept(&EgressEffectAttempt::ResponseRelease {
                host: "api.github.com",
                port: 443,
                method: "POST",
                path: "/v1/messages",
                status: 201,
                body_bytes: 84,
            })
            .expect("response release is allowed")
            .record_outcome(EgressEffectOutcome::Completed(120))
            .expect("local outcome recording succeeds");
    }

    /// The request is decided; the release of a reply is not, and the reply is recorded once, on
    /// the request permit, as `output.status`.
    #[test]
    fn the_request_is_decided_and_the_reply_is_recorded_once() {
        let request = EgressEffectAttempt::HttpRequest {
            host: "api.github.com",
            port: 443,
            method: "GET",
            path: "/",
            body_bytes: 0,
            intercepted: true,
            mcp: None,
        };
        let response = EgressEffectAttempt::ResponseRelease {
            host: "api.github.com",
            port: 443,
            method: "GET",
            path: "/",
            status: 200,
            body_bytes: 0,
        };

        // A cap of two `::response` records within the window. One exchange must leave it unfired.
        let request_only = interceptor(
            r#"permit(principal, action == Box::Action::"http:request", resource)
               when { context.input.host == "api.github.com" };
               forbid(principal, action == Box::Action::"http:request", resource)
               when temporal {
                 exists (n: Long). (
                   (count for (t: Timepoint). where (
                     formerly within 3600s (
                       Box::Action::"http:request"::response{ input.host: "api.github.com" } && tp(t)
                     )
                   )) == n
                   && n >= 2
                 )
               };"#,
        );
        request_only
            .intercept(&request)
            .expect("http:request allows the request")
            .record_outcome(EgressEffectOutcome::Replied {
                accepted_bytes: 10,
                status: 200,
            })
            .expect("the reply records");
        request_only
            .intercept(&response)
            .expect("the release takes no decision, so it is admitted")
            .record_outcome(EgressEffectOutcome::Completed(64))
            .expect("the release records nothing");
        request_only
            .intercept(&request)
            .expect("one exchange is one ::response, so a cap of two does not fire")
            .record_outcome(EgressEffectOutcome::Replied {
                accepted_bytes: 10,
                status: 200,
            })
            .expect("the reply records");
        assert!(
            request_only.intercept(&request).is_err(),
            "two exchanges are two ::response records, so the cap fires on the third request"
        );

        let nothing =
            interceptor(r#"permit(principal, action == Box::Action::"net:connect", resource);"#);
        let denied = match nothing.intercept(&request) {
            Ok(_) => panic!("an unpermitted request must be refused"),
            Err(error) => error,
        };
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        nothing
            .intercept(&response)
            .expect("the release is admitted whatever policy says")
            .mark_indeterminate();
    }

    /// The forbid a reply status arms: three 500s within the window refuse the fourth request,
    /// and 200s never do.
    fn three_replies_then_a_fourth_request(status: u16) -> bool {
        let fixture = interceptor(
            r#"permit(principal, action == Box::Action::"http:request", resource)
               when { context.input.host == "api.github.com" };
               forbid(principal, action == Box::Action::"http:request", resource)
               when temporal {
                 exists (n: Long). (
                   (count for (t: Timepoint). where (
                     formerly within 3600s (
                       Box::Action::"http:request"::response{ input.host: "api.github.com", output.status: 500 } && tp(t)
                     )
                   )) == n
                   && n >= 3
                 )
               };"#,
        );
        let request = EgressEffectAttempt::HttpRequest {
            host: "api.github.com",
            port: 443,
            method: "GET",
            path: "/",
            body_bytes: 0,
            intercepted: true,
            mcp: None,
        };
        for _ in 0..3 {
            fixture
                .intercept(&request)
                .expect("a request under the cap is admitted")
                .record_outcome(EgressEffectOutcome::Replied {
                    accepted_bytes: 10,
                    status,
                })
                .expect("the reply records");
        }
        fixture.intercept(&request).is_ok()
    }

    #[test]
    fn three_server_errors_refuse_the_fourth_request() {
        assert!(
            !three_replies_then_a_fourth_request(500),
            "three 500 replies must arm the forbid"
        );
    }

    #[test]
    fn three_successes_admit_the_fourth_request() {
        assert!(
            three_replies_then_a_fourth_request(200),
            "200 replies must not match a rule on output.status: 500"
        );
    }

    /// A request that got no reply still records its one `::response`, with no `output`, so an
    /// outbound count still sees it and a rule on `output.status` does not match it.
    #[test]
    fn a_request_with_no_reply_records_a_response_without_a_status() {
        let count_all = r#"permit(principal, action == Box::Action::"http:request", resource)
               when { context.input.host == "api.github.com" };
               forbid(principal, action == Box::Action::"http:request", resource)
               when temporal {
                 exists (n: Long). (
                   (count for (t: Timepoint). where (
                     formerly within 3600s (
                       Box::Action::"http:request"::response{ input.host: "api.github.com" } && tp(t)
                     )
                   )) == n
                   && n >= 1
                 )
               };"#;
        let count_errors = r#"permit(principal, action == Box::Action::"http:request", resource)
               when { context.input.host == "api.github.com" };
               forbid(principal, action == Box::Action::"http:request", resource)
               when temporal {
                 exists (n: Long). (
                   (count for (t: Timepoint). where (
                     formerly within 3600s (
                       Box::Action::"http:request"::response{ input.host: "api.github.com", output.status: 500 } && tp(t)
                     )
                   )) == n
                   && n >= 1
                 )
               };"#;
        let request = EgressEffectAttempt::HttpRequest {
            host: "api.github.com",
            port: 443,
            method: "GET",
            path: "/",
            body_bytes: 0,
            intercepted: true,
            mcp: None,
        };
        for (source, admitted_after) in [(count_all, false), (count_errors, true)] {
            let fixture = interceptor(source);
            fixture
                .intercept(&request)
                .expect("the first request is admitted")
                .record_outcome(EgressEffectOutcome::Completed(10))
                .expect("a delivery with no reply records");
            assert_eq!(
                fixture.intercept(&request).is_ok(),
                admitted_after,
                "a reply-less exchange is one ::response with no output"
            );
        }
    }

    /// A forbid on `ip` refuses the pinned address and leaves every other address to the permit.
    #[test]
    fn an_address_forbid_refuses_only_its_addresses() {
        let fixture = interceptor(
            r#"permit(principal, action == Box::Action::"net:connect", resource);
               forbid(principal, action == Box::Action::"net:connect", resource)
               when { context.input has ip && (context.input.ip like "169.254.*"
                      || context.input.ip == "fd00:ec2::254") };"#,
        );
        for refused in [
            "169.254.169.254:80",
            "169.254.170.2:80",
            "[fd00:ec2::254]:80",
            "[::ffff:169.254.169.254]:80",
            "[2002:a9fe:a9fe::]:80",
        ] {
            assert!(
                fixture
                    .intercept(&connect_attempt(refused.parse().unwrap()))
                    .is_err(),
                "{refused} is refused"
            );
        }
        for admitted in [
            "93.184.216.34:443",
            "169.253.0.1:80",
            "[fd00:ec2::253]:80",
            "[2606:2800:220:1::1]:443",
        ] {
            fixture
                .intercept(&connect_attempt(admitted.parse().unwrap()))
                .unwrap_or_else(|error| panic!("{admitted} is admitted: {error}"));
        }
    }

    /// `ip` is a string, so the Cedar `ipaddr` form fails when the policy loads.
    #[test]
    fn an_ipaddr_rule_is_refused_when_the_policy_loads() {
        let history = tempfile::tempdir().expect("history directory");
        let Err(refusal) = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("adapter-test.cedar"),
                text: r#"forbid(principal, action == Box::Action::"net:connect", resource)
                    when { context.input has ip && context.input.ip.isInRange(ip("10.0.0.0/8")) };"#
                    .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        ) else {
            panic!("an ipaddr comparison does not load");
        };
        let refusal = refusal.to_string();
        assert!(refusal.contains("schema validation"), "{refusal}");
    }

    /// The request leg projects `port` and `body_bytes` into its decision. No rule runs on the
    /// release of a reply, so a reply's `port` or `body_bytes` is not read;
    /// `the_request_is_decided_and_the_reply_is_recorded_once` pins the admission, and
    /// `tests/temporal_egress_budget.rs::a_reply_adds_nothing_to_an_outbound_budget` the history.
    #[test]
    fn the_request_leg_projects_port_and_body_bytes() {
        let interceptor = interceptor(
            r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when {
                context.input.host == "api.github.com" &&
                context.input.port == 443 &&
                context.input.body_bytes == 42
            };
            "#,
        );

        let request = |port, body_bytes| EgressEffectAttempt::HttpRequest {
            host: "api.github.com",
            port,
            method: "POST",
            path: "/v1/messages",
            body_bytes,
            intercepted: true,
            mcp: None,
        };

        interceptor
            .intercept(&request(443, 42))
            .expect("matching request metadata is allowed")
            .mark_indeterminate();
        assert!(interceptor.intercept(&request(8443, 42)).is_err());
        assert!(interceptor.intercept(&request(443, 43)).is_err());
    }

    /// A rule keyed on `context.input.intercepted` distinguishes a TLS-terminated request from a
    /// plain-HTTP one. The transport is threaded through the attempt, so a TLS route reports
    /// `intercepted == true` and a plain-HTTP route `false`. Before that, the adapter hardcoded
    /// `true`, and a "TLS-only" rule silently admitted plaintext.
    #[test]
    fn the_request_leg_projects_the_intercepted_transport() {
        let interceptor = interceptor(
            r#"
            permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.intercepted };
            "#,
        );

        let request = |intercepted| EgressEffectAttempt::HttpRequest {
            host: "api.github.com",
            port: 443,
            method: "POST",
            path: "/v1/messages",
            body_bytes: 0,
            intercepted,
            mcp: None,
        };

        // TLS-terminated (intercepted == true) satisfies the rule.
        interceptor
            .intercept(&request(true))
            .expect("a TLS-intercepted request satisfies an intercepted rule")
            .mark_indeterminate();
        // Plain HTTP (intercepted == false) is refused by the same TLS-only rule.
        assert!(
            interceptor.intercept(&request(false)).is_err(),
            "a plain-HTTP request must not satisfy a rule that requires intercepted"
        );
    }
}
