# Egress Gateway

`strands-box-egress-gateway` is the outbound boundary of the Strands box. Its
default adapter listens locally, forwards authorized
traffic, applies credential mutations, and emits secret-free audit records.

Authorization is supplied by the caller as an `EffectInterceptor` — the policy
engine's seam. This crate holds no allow/deny authority: it cannot widen what
policy permits. `CapabilityOutcome` has no `Allow` variant, so the most a
capability can return is a list of edits or a fault. `AuditDecision` does carry
`Allow` and `Deny`; it records a decision made elsewhere and authorizes nothing.

Audience: Rust developers composing the Strands box outbound boundary and
operators inspecting egress decisions.

## Public Interface

The crate root is the complete public API — 44 names, 40 unconditional and 4
behind the `tls-intercept` feature:

| Area | Items |
|---|---|
| Audit values | `AuditDecision`, `EgressDecision`, `NetworkAuditEvent`, `RequestId`, `SharedAuditLog` |
| Boundary values | `BodyRef`, `DenyReason`, `HeaderMap`, `InterceptedRequest`, `InterceptedResponse`, `Mutation`, `MutationTarget`, `Target`, `Verdict` |
| Credential mutators | `CapabilityContext`, `CapabilityFault`, `CapabilityOutcome`, `CapabilitySet`, `CapabilitySetBuilder`, `CredentialCapability` |
| Host spelling | `is_bindable_host`, `normalize_host` |
| Effect lifecycle | `EffectAttempt`, `EffectInterceptor`, `EffectOutcome`, `EffectPermit` |
| Remote MCP | `McpFrame`, `McpListReply`, `McpTarget`, `McpTargetIdentity`, `canonicalize_mcp_frame`, `mcp_denial_response`, `refuse_duplicate_mcp_keys` |
| Interception port | `Interceptor` |
| Audit seam | `Emitter`, `StubEmitter` |
| Errors | `ProxyError`, `Result`, `PROXY_ORIGIN_HEADER`, `PROXY_ORIGIN_VALUE` |
| Default adapter | `MitmConfig`, `MitmHandle`, `MitmInterceptor`, `ResponseLimits` |

`AuditDecision` is the one renamed export: the item is `audit::Decision`.
`SharedAuditLog` keeps the newest 1,024 events. A push to a full log drops the
oldest event.

The default adapter items are available with the default-on `tls-intercept`
feature.

## Authorization

Domain authorization is supplied as an `EffectInterceptor`:

```rust
pub trait EffectInterceptor: Send + Sync {
    fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>>;
    fn stage_mcp_catalog(&self, _server: &str, _reply: McpListReply<'_>) -> io::Result<()> {
        Ok(())
    }
}

pub trait EffectPermit: Send {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()>;
    fn mark_indeterminate(self: Box<Self>);
}
```

The seam speaks `std::io::Result`, not `ProxyError`. There are four attempt
kinds, and the proxy presents each one immediately before its effect:

| Attempt | Fields | Reported when |
|---|---|---|
| `EffectAttempt::Resolve` | `host`, `port` | before the host is resolved, once per connection |
| `EffectAttempt::Connect` | `host`, `port`, `address`, `http_visibility` | before one upstream socket opens, once per pinned address |
| `EffectAttempt::HttpRequest` | `host`, `port`, `method`, `path`, `body_bytes`, `intercepted`, `mcp` | after the request is serialized, before it is written |
| `EffectAttempt::ResponseRelease` | `host`, `port`, `method`, `path`, `status`, `body_bytes` | after response mutators run, before the workload receives bytes |

No attempt carries a header or credential material. The only body content in an
attempt is `mcp`, the MCP frame of a request to a configured remote MCP server.
`path` excludes the query string and is the path the workload sent, captured
before any credential edit. `body_bytes` is a length. `intercepted` is `true`
when the request came through TLS interception. A WebSocket handshake is an
ordinary `HttpRequest` with `method` `GET` and `body_bytes` 0, and the messages
of its session raise no attempt.

A `Resolve` permit is a decision only, and it receives no outcome. Both
`EffectPermit` methods consume `self: Box<Self>`, so a permit of the other three
kinds reaches exactly one terminal transition. The proxy reports
`EffectOutcome::Connected`, `ConnectFailed`, `Completed`, `Replied`, `Failed`,
`Partial`, or `Indeterminate`. A dropped permit of those kinds becomes
`mark_indeterminate`, so an early return or a panic still reports.

`stage_mcp_catalog` receives each `tools/list` reply from a remote MCP server
before the workload receives it. Its default does nothing.

An `io::ErrorKind::PermissionDenied` from `intercept` blocks the effect. For a
connect, that happens before any upstream socket opens. Each adapter constructor
takes an `Arc<dyn EffectInterceptor>`, so an adapter with no authorization is
unconstructible.

## Destination Decisions

Every connection is decided twice through `EffectInterceptor`: on the host before resolution, and
on each resolved, pinned address before its socket opens. The gateway holds no destination deny
list of its own. A metadata or link-local address is refused by a policy `forbid` on
`context.input.ip`.

## Credential Mutators

`CapabilitySet::builder()` returns a `CapabilitySetBuilder`. `add_credential`
registers one `CredentialCapability` per destination pattern, and `build` freezes
the set. A capability returns either `CapabilityOutcome::Applied(mutations)` —
empty when it does not apply to the exchange — or
`CapabilityOutcome::Unavailable(fault)` on a credential integrity failure such as
a phantom mismatch, an ambiguous binding, or a signer error. It cannot authorize.

Any fault denies the exchange. The interceptor applies the mutations only when
the fold allows. Two set-like mutations on one header, path, or query parameter
fail closed as `DenyReason::MutationCollision`; one capability's own
strip-then-set swap is not a collision.

`CapabilitySet::validate` enforces one capability per destination pattern, and
nothing else. A duplicate is a `ProxyError::Config` before the adapter starts.
There is no visibility check: every connection is terminated and inspected
([no connection is opaque](../../docs/design/decisions.md#no-connection-is-opaque-to-the-boundary)),
so plaintext is always available to a capability.

The proxy answers a refusal with a static, secret-free diagnostic. Such a
diagnostic is trusted boundary output and does not enter `ResponseRelease`, so a
denied effect needs no authorization to report. Upstream response bytes always
enter `ResponseRelease` before workload delivery. The release of a `101` admits
the server messages of its WebSocket session, and the gateway scrubs each one.

## Destination Matching

A capability governs the requests its `credentials::DestinationPattern` matches.
This crate adds no matcher of its own: `Target::as_destination()` borrows a
`Target` as a `credentials::Destination` (`host`, `port`, `path`), and
`CapabilitySet` prefilters both legs by `pattern().matches(..)`. On the response
leg the target comes from `CapabilityContext::target`, because a response has no
target of its own.

`DestinationPattern::parse` reads `host[:port][/path]`:

| Written | Matches |
|---|---|
| `api.stripe.com` | that host only, case-insensitively |
| `*.openai.com` | any strict sub-domain, never the apex `openai.com` |
| `*` | every host |
| `api.stripe.com:8443` | port `8443` exactly |
| `api.stripe.com` | port `443` or `80`, and no other |
| `api.stripe.com/v1/` | any path under the prefix `/v1/` |
| `api.stripe.com/v1/chat` | `/v1/chat`, `/v1/chat/completions`, `/v1/chat?x=1`; not `/v1/chatbot` |
| `api.stripe.com/*.json` | any path ending `.json` |

`matches` ANDs the host, the port, and the path, so each component only narrows.
A wildcard host does not widen the port: `*` alone still refuses port `8080`. Host
matching is case-insensitive; path matching is case-sensitive. `parse` rejects an
empty host, a bare `*.`, a second `*`, a `*` outside the leading `*.` form, and a
port that is not a `u16`.

## Default Adapter

Three constructors start the adapter, and each requires the authorization seam:

```text
MitmInterceptor::start(MitmConfig, CapabilitySet, Arc<dyn EffectInterceptor>)
    -> Result<MitmHandle>

MitmInterceptor::start_with_emitter(MitmConfig, CapabilitySet,
                                    Arc<dyn EffectInterceptor>, Box<dyn Emitter>)
    -> Result<MitmHandle>

MitmInterceptor::start_with_emitter_and_opened_ca(MitmConfig, CapabilitySet,
                                                  Arc<dyn EffectInterceptor>,
                                                  Box<dyn Emitter>, &File)
    -> Result<MitmHandle>
```

`start` installs a `StubEmitter`, which buffers the durable records in memory.
When `intercept_ca_dir` is set, `start_with_emitter_and_opened_ca` writes the
public CA certificate to a file that the caller opened. Each validates the
`CapabilitySet`, refuses the two unsupported `MitmConfig` values below,
generates the ephemeral CA, builds the additive upstream trust bundle, binds
exactly one transport, and spawns the accept loop:

```rust
use std::io;
use std::sync::Arc;

use egress_gateway::{
    CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, MitmConfig,
    MitmHandle, MitmInterceptor,
};

/// Denies every connect and records nothing for the legs it admits.
struct DenyConnect;

struct DiscardPermit;

impl EffectPermit for DiscardPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

impl EffectInterceptor for DenyConnect {
    fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        match effect {
            EffectAttempt::Connect { host, port, .. } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("no rule permits {host}:{port}"),
            )),
            _ => Ok(Box::new(DiscardPermit)),
        }
    }
}

fn start() -> egress_gateway::Result<MitmHandle> {
    MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        Arc::new(DenyConnect),
    )
}
```

`EffectAttempt` is `#[non_exhaustive]`, so an implementation needs a wildcard arm.

`MitmConfig` has thirteen fields:

| Field | Type | Default |
|---|---|---|
| `bind_addr` | `SocketAddr` | `127.0.0.1:0` |
| `unix_socket_path` | `Option<PathBuf>` | `None` |
| `external_proxy` | `Option<SocketAddr>` | `None` |
| `intercept_ca_dir` | `Option<PathBuf>` | `None` |
| `enable_h2` | `bool` | `false` |
| `response_limits` | `ResponseLimits` | `max_body_bytes: 16 MiB` |
| `expected_token` | `Option<String>` | `None` |
| `credential_env` | `Vec<(String, String)>` | empty |
| `upstream_ca_pems` | `Vec<String>` | empty |
| `dns_overrides` | `Vec<(String, IpAddr)>` | empty |
| `upstream_read_deadline` | `Duration` | 300 s |
| `max_connections` | `usize` | `256` |
| `mcp_servers` | `Vec<(String, String)>` | empty |

Start refuses `enable_h2 = true` and `external_proxy = Some(..)` with
`ProxyError::Config`, before it makes the CA or binds a transport. The gateway
serves only HTTP/1.1, and it connects only to the pinned address.

`unix_socket_path` selects the transport. `None` binds a localhost `TcpListener`
at `bind_addr`; `Some(path)` binds only a `UnixListener`, at mode `0600`, and
never a TCP port. Every admitted connection is terminated and inspected, so TLS
interception is not selective. The adapter runs on its own tokio runtime, on a
thread that it starts, and `max_connections` bounds the connections that it
serves at once. `upstream_read_deadline` bounds each read and each
write on an upstream socket by the time with no byte in either direction, so an upstream that never
drains the request or never replies ends the exchange with one `http:request::response` that has no
`output`. A byte that leaves or arrives restarts the bound, so the wait for a reply counts from the
last byte of the request. There is no total bound: a request or a reply that keeps moving goes
through, whatever its length; `box.toml` exposes no key for it.

Each read and each write on a client socket waits at most 60 s, and the gateway closes the
connection at the first read or write that moves no byte in that time. One write can copy a part of
the reply and then wait, so a client that stops reading its reply frees its slot in at most 120 s.
The first head of a connection, which is the `CONNECT` head or the head of a plain-HTTP request,
must be complete 60 s after the connection takes its slot. The gateway checks this time at the end
of each read of the head, and closes a late connection with no reply. So a client that sends nothing
frees its slot in 60 s, and a client that sends its head slowly frees it in at most 120 s. The head
of the request inside a tunnel must be complete 60 s after the gateway starts to read it; a late
head closes the connection with no reply. A request body, the TLS handshake with the client, and the
reply to the client have no total bound, so a slow upload that keeps sending bytes goes through.
While the gateway waits for the upstream reply, the client's silence does not count against the
bound, so a slow reply reaches a client that waits for it. A plain-HTTP request whose body stops for
60 s gets a `400` before any decision. No `MitmConfig` field and no `box.toml` key sets these
bounds.

`MitmHandle` exposes `port()`, `unix_socket_path()`, `intercept_ca_path()`,
`env_vars()`, `credential_env_vars()`, `drain_audit_events()`, and `shutdown()`.
`env_vars()` returns the four `HTTP_PROXY`/`HTTPS_PROXY` spellings on the TCP
transport and no proxy variable on AF_UNIX. It adds `SSL_CERT_FILE` on both
transports when a CA directory is configured. `shutdown()` and `Drop` stop the
accept loop with no connection to the listener. `Drop` returns when the loop has
closed the listener, also when every connection slot is held. Open connections
run to their end on the gateway thread.

## Errors

`ProxyError::http_status` maps proxy failures to workload-facing status codes:

| Status | Variants |
|---|---|
| `403` | `HostDenied`, `IpDenied`, `ControlDenied`, `Credential`, `NotAuthorized` |
| `407` | `InvalidToken` |
| `502` | `UpstreamConnect`, `Intercept`, `ResponseLimit`, `Io` |
| `503` | `Config`, `Bind` |

`ProxyError` is `#[non_exhaustive]`. `From<DenyReason>` converts every deny
reason into one of these variants, with `MutationCollision` becoming
`ProxyError::Config`. `Result<T>` is the crate alias for
`std::result::Result<T, ProxyError>`.
