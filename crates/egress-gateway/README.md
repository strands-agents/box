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

The crate root is the complete public API — 33 names, 29 unconditional and 4
behind the `tls-intercept` feature:

| Area | Items |
|---|---|
| Audit values | `AuditDecision`, `EgressDecision`, `NetworkAuditEvent`, `RequestId`, `SharedAuditLog` |
| Boundary values | `BodyRef`, `DenyReason`, `HeaderMap`, `InterceptedRequest`, `InterceptedResponse`, `Mutation`, `MutationTarget`, `Target`, `Verdict` |
| Credential mutators | `CapabilityContext`, `CapabilityFault`, `CapabilityOutcome`, `CapabilitySet`, `CapabilitySetBuilder`, `CredentialCapability` |
| Effect lifecycle | `EffectAttempt`, `EffectInterceptor`, `EffectOutcome`, `EffectPermit` |
| Interception port | `Interceptor` |
| Audit seam | `Emitter`, `StubEmitter` |
| Errors | `ProxyError`, `Result` |
| Default adapter | `MitmConfig`, `MitmHandle`, `MitmInterceptor`, `ResponseLimits` |

`AuditDecision` is the one renamed export: the item is `audit::Decision`.

The default adapter items are available with the default-on `tls-intercept`
feature.

## Authorization

Domain authorization is supplied as an `EffectInterceptor`:

```rust
pub trait EffectInterceptor: Send + Sync {
    fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>>;
}

pub trait EffectPermit: Send {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()>;
    fn mark_indeterminate(self: Box<Self>);
}
```

The seam speaks `std::io::Result`, not `ProxyError`. There are three attempt
kinds, and the proxy presents each one immediately before its effect:

| Attempt | Fields | Reported when |
|---|---|---|
| `EffectAttempt::Connect` | `host`, `port`, `address`, `http_visibility` | before one upstream socket opens, once per pinned address |
| `EffectAttempt::HttpRequest` | `host`, `port`, `method`, `path`, `body_bytes` | after the request is serialized, before it is written |
| `EffectAttempt::ResponseRelease` | `host`, `port`, `method`, `path`, `status`, `body_bytes` | after response mutators run, before the workload receives bytes |

No attempt carries a header, a body, or credential material. `path` excludes the
query string and is the path the workload sent, captured before any credential
edit. `body_bytes` is a length.

Both `EffectPermit` methods consume `self: Box<Self>`, so one permit reaches
exactly one terminal transition. The proxy reports `EffectOutcome::Connected`,
`ConnectFailed`, `Completed`, `Failed`, `Partial`, or `Indeterminate`. A dropped
permit becomes `mark_indeterminate`, so an early return or a panic still reports.

An `io::ErrorKind::PermissionDenied` from `intercept` blocks the effect. For a
connect, that happens before any upstream socket opens. Both adapter constructors
take an `Arc<dyn EffectInterceptor>`, so an adapter with no authorization is
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
enter `ResponseRelease` before workload delivery.

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

Two constructors start the adapter, and both require the authorization seam:

```text
MitmInterceptor::start(MitmConfig, CapabilitySet, Arc<dyn EffectInterceptor>)
    -> Result<MitmHandle>

MitmInterceptor::start_with_emitter(MitmConfig, CapabilitySet,
                                    Arc<dyn EffectInterceptor>, Box<dyn Emitter>)
    -> Result<MitmHandle>
```

`start` installs a `StubEmitter`, which buffers the durable records in memory.
Both validate the `CapabilitySet`, generate the ephemeral CA, build the additive
upstream trust bundle, bind exactly one transport, and spawn the accept loop:

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

`MitmConfig` has eleven fields:

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

`unix_socket_path` selects the transport. `None` binds a localhost `TcpListener`
at `bind_addr`; `Some(path)` binds only a `UnixListener`, at mode `0600`, and
never a TCP port. Every admitted connection is terminated and inspected, so TLS
interception is not selective. The adapter is thread-per-connection, and
`max_connections` bounds the thread count. `upstream_read_deadline` bounds each read and each
write on an upstream socket and one exchange's upstream reads and writes as a whole, so an
upstream that never drains or sips the request, or never replies or drips its reply, ends the
exchange with one `http:request::response` that has no `output`. The same bound ends a legitimate
exchange whose request and reply together take longer than the deadline, with no reply to the
workload; `box.toml` exposes no key for it.

`MitmHandle` exposes `port()`, `unix_socket_path()`, `intercept_ca_path()`,
`env_vars()`, `credential_env_vars()`, `drain_audit_events()`, and `shutdown()`.
`env_vars()` returns the four `HTTP_PROXY`/`HTTPS_PROXY` spellings on the TCP
transport and no proxy variable on AF_UNIX. It adds `SSL_CERT_FILE` on both
transports when a CA directory is configured. `Drop` shuts the adapter down and
joins the accept thread.

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
