//! Domain-neutral interception of outbound effects.

use std::io;
use std::net::SocketAddr;

/// The MCP call on an `HttpRequest` whose destination is a configured remote MCP server.
///
/// `server` is **config-assigned** (the name of the matched destination, keyed by the host the
/// connection reached); it is never read from the frame, so an agent cannot borrow another server's
/// identity. `method` is the JSON-RPC method, available on every variant (derived, or stored on the
/// `List`/other catch-all). The per-item identity (`tool`/`prompt`/`uri`) and `args` are workload-
/// controlled; `args` is present only where the method carries them (`tools/call`, `prompts/get`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum McpFrame<'a> {
    /// `tools/call` — `context.input.tool` + the raw arguments JSON for the per-tool typed gate.
    ToolCall {
        /// Config-assigned server name.
        server: &'a str,
        /// The tool the call names (`params.name`).
        tool: &'a str,
        /// The tool's `params.arguments` as JSON text (`{}` when none). Kept whole so the policy's
        /// schema-bound parse types enums, sets, and nested objects — not only scalars.
        arguments: &'a str,
    },
    /// `prompts/get` — `context.input.prompt`. Prompt args ride the coarse `mcp:call` gate by name,
    /// so they are not carried here.
    PromptGet {
        /// Config-assigned server name.
        server: &'a str,
        /// The prompt the call names (`params.name`).
        prompt: &'a str,
    },
    /// `resources/read` — `context.input.uri`, no args.
    ResourceRead {
        /// Config-assigned server name.
        server: &'a str,
        /// The resource URI (`params.uri`).
        uri: &'a str,
    },
    /// `*/list` and other decided methods with no per-item identity — `context.input.method` only.
    List {
        /// Config-assigned server name.
        server: &'a str,
        /// The JSON-RPC method (`tools/list`, `prompts/list`, `resources/list`, …).
        method: &'a str,
    },
}

impl<'a> McpFrame<'a> {
    /// The config-assigned server name — `context.input.server`.
    pub fn server(&self) -> &'a str {
        match self {
            Self::ToolCall { server, .. }
            | Self::PromptGet { server, .. }
            | Self::ResourceRead { server, .. }
            | Self::List { server, .. } => server,
        }
    }

    /// The JSON-RPC method — `context.input.method`, present on every frame. Derived for the named
    /// variants (the variant is the method), carried explicitly for the `List`/other catch-all.
    pub fn method(&self) -> &'a str {
        match self {
            Self::ToolCall { .. } => "tools/call",
            Self::PromptGet { .. } => "prompts/get",
            Self::ResourceRead { .. } => "resources/read",
            Self::List { method, .. } => method,
        }
    }
}

impl std::fmt::Debug for McpFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `server` and `method` are safe (config-assigned / a bounded protocol verb). The per-item
        // identity and args are workload-controlled (`params.*`), so they are redacted rather than
        // printed: an attempt's Debug must stay secret-free. The audit names them through the
        // decision record.
        f.debug_struct("McpFrame")
            .field("server", &self.server())
            .field("method", &self.method())
            .field("identity", &"<redacted>")
            .field("args", &"<redacted>")
            .finish()
    }
}

/// An outbound operation presented immediately before its external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectAttempt<'a> {
    /// Resolving a destination host, decided before any DNS query leaves the box. A decision only: its
    /// permit receives no outcome.
    Resolve {
        /// The logical destination host from the CONNECT request.
        host: &'a str,
        /// The logical destination port.
        port: u16,
    },
    /// Opening one upstream socket after resolution and hard controls.
    Connect {
        /// The logical destination host from the CONNECT request.
        host: &'a str,
        /// The logical destination port.
        port: u16,
        /// The exact pinned address this socket attempt will use.
        address: SocketAddr,
        /// Whether this connection will expose HTTP request and response effects.
        http_visibility: bool,
    },
    /// Sending one serialized HTTP request to the upstream.
    HttpRequest {
        /// The logical destination host.
        host: &'a str,
        /// The logical destination port.
        port: u16,
        /// The request method after request controls have run.
        method: &'a str,
        /// The request path after request controls have run, without its query.
        path: &'a str,
        /// The request body length, without exposing body content.
        body_bytes: usize,
        /// Whether the plaintext was seen through TLS interception. A CONNECT/TLS route terminates
        /// TLS to inspect the request, so it is `true`; a plain-HTTP route was never encrypted, so it
        /// is `false`. Feeds the policy's `intercepted` input, so a rule can distinguish the two.
        intercepted: bool,
        /// The MCP frame this request carries, when its destination is a configured remote MCP
        /// server; `None` otherwise. Present drives the `mcp:call` gate alongside `http:request`.
        mcp: Option<McpFrame<'a>>,
    },
    /// Returning one serialized, governed HTTP response to the workload.
    ResponseRelease {
        /// The logical destination host of the originating request.
        host: &'a str,
        /// The logical destination port of the originating request.
        port: u16,
        /// The originating request method.
        method: &'a str,
        /// The originating request path, without its query.
        path: &'a str,
        /// The governed response status.
        status: u16,
        /// The governed response body length, without exposing body content.
        body_bytes: usize,
    },
}

/// The observed result of an admitted outbound effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectOutcome {
    /// The upstream socket opened and connected to this actual peer.
    Connected(SocketAddr),
    /// No upstream socket opened.
    ConnectFailed(io::ErrorKind),
    /// The complete prepared message was accepted and flushed.
    Completed(usize),
    /// The complete prepared request was accepted and flushed, and the upstream replied.
    Replied {
        /// Bytes of the request the operating system accepted.
        accepted_bytes: usize,
        /// The upstream's reply status.
        status: u16,
    },
    /// A message write failed before any bytes were accepted.
    Failed {
        /// Bytes accepted before the failure. This is zero for this variant.
        accepted_bytes: usize,
        /// The write failure category.
        error_kind: io::ErrorKind,
    },
    /// A message write failed after accepting a non-zero prefix.
    Partial {
        /// Bytes accepted before the failure.
        accepted_bytes: usize,
        /// The write failure category.
        error_kind: io::ErrorKind,
    },
    /// Delivery became uncertain after this many bytes were accepted.
    Indeterminate {
        /// Bytes accepted before delivery became uncertain.
        accepted_bytes: usize,
    },
}

/// One `tools/list` reply from a remote MCP server, with the request it answers.
#[derive(Clone, Copy)]
pub struct McpListReply<'a> {
    /// The `Mcp-Session-Id` the request carried.
    pub session: Option<&'a str>,
    /// The `params.cursor` the request carried.
    pub cursor: Option<&'a str>,
    /// The reply body, as plain JSON or as Server-Sent Events.
    pub body: &'a [u8],
}

/// Intercepts an outbound effect immediately before the proxy performs it.
pub trait EffectInterceptor: Send + Sync {
    /// Obtain the permit that must receive the effect's terminal outcome.
    fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>>;

    /// Observe one `tools/list` reply from a remote MCP server, before the workload receives it.
    fn stage_mcp_catalog(&self, _server: &str, _reply: McpListReply<'_>) -> io::Result<()> {
        Ok(())
    }
}

/// Correlates one admitted outbound effect with its eventual outcome.
pub trait EffectPermit: Send {
    /// Record the observed result after the proxy attempted the admitted effect.
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()>;

    /// Mark a claimed effect that ended without a terminal outcome.
    fn mark_indeterminate(self: Box<Self>);
}

/// Makes the permit's indeterminate transition automatic on every early exit.
#[cfg(feature = "tls-intercept")]
pub(crate) struct ClaimedEffectPermit {
    permit: Option<Box<dyn EffectPermit>>,
}

#[cfg(feature = "tls-intercept")]
impl ClaimedEffectPermit {
    pub(crate) fn new(permit: Box<dyn EffectPermit>) -> Self {
        Self {
            permit: Some(permit),
        }
    }

    pub(crate) fn record_outcome(mut self, outcome: EffectOutcome) -> io::Result<()> {
        self.permit
            .take()
            .expect("claimed effect permit is present")
            .record_outcome(outcome)
    }
}

#[cfg(feature = "tls-intercept")]
impl Drop for ClaimedEffectPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            permit.mark_indeterminate();
        }
    }
}

#[cfg(all(test, feature = "tls-intercept"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingPermit {
        recorded: Arc<AtomicUsize>,
        indeterminate: Arc<AtomicUsize>,
    }

    impl EffectPermit for CountingPermit {
        fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
            self.recorded.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn mark_indeterminate(self: Box<Self>) {
            self.indeterminate.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn permit(
        recorded: &Arc<AtomicUsize>,
        indeterminate: &Arc<AtomicUsize>,
    ) -> ClaimedEffectPermit {
        ClaimedEffectPermit::new(Box::new(CountingPermit {
            recorded: recorded.clone(),
            indeterminate: indeterminate.clone(),
        }))
    }

    #[test]
    fn recording_is_the_only_terminal_transition() {
        let recorded = Arc::new(AtomicUsize::new(0));
        let indeterminate = Arc::new(AtomicUsize::new(0));

        permit(&recorded, &indeterminate)
            .record_outcome(EffectOutcome::Completed(4))
            .unwrap();

        assert_eq!(recorded.load(Ordering::SeqCst), 1);
        assert_eq!(indeterminate.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_a_claim_marks_it_indeterminate_once() {
        let recorded = Arc::new(AtomicUsize::new(0));
        let indeterminate = Arc::new(AtomicUsize::new(0));

        drop(permit(&recorded, &indeterminate));

        assert_eq!(recorded.load(Ordering::SeqCst), 0);
        assert_eq!(indeterminate.load(Ordering::SeqCst), 1);
    }
}
