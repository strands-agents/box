# Credentials

`strands-box-credentials` resolves credential references to real secrets at a
trusted boundary, so the workload never holds one. It resolves destination-scoped
declarations at startup, mints a non-secret phantom to stand in for each real
secret, and answers two questions on the request path: what must be edited on this
request, and did this response echo a secret back?

Audience: Rust developers composing credential-aware network boundaries, and
operators reading credential-loading behavior.

## Startup

`Vault::open(config)` takes a `VaultConfig` and returns an `Opened`:

| Accessor | Returns |
|---|---|
| `phantoms()` | `&[Phantom]`, in declaration order — one per resolved opaque route. Each carries `destination()` and `token()`: the destination it covers and the non-secret token standing in for its secret. Seed these into the workload's environment. |
| `skipped()` | `&[Skipped]`, one per route whose secret was absent or unreadable. Each carries `destination()`, `code()`, `message()`, and `hint()`. A non-empty list does not mean the open failed. Always empty under `require_every_route`. |
| `into_vault()` | The vault, for the request path. It consumes the `Opened`. |

A signed AWS route mints no phantom, so it never appears in `phantoms()`.

Build the config with a backend, a tenant, and one route per destination:

```rust
use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};

let opened = Vault::open(
    VaultConfig::new(Backend::local(), "tenant-a")
        .route(RouteSpec::opaque(
            DestinationPattern::parse("api.github.com")?,
            Locator::parse_uri("env://GITHUB_TOKEN")?,
            InjectMode::header("Bearer {}", None)?,
        ))
        .require_every_route(),
)?;
```

The library name is `credentials`; the package name is `strands-box-credentials`.
`VaultConfig` is a consuming builder, so each method returns the config. `routes(iter)`
adds many at once. `require_scoped_aws_profile()` denies the ambient AWS identity: a signed
route that names no profile then fails at signing time, per request, rather than at `open`.

`require_every_route` makes an absent secret abort the open instead of appearing in
`skipped()`. Use it when a destination left reachable and uncredentialed is worse
than not starting: the request goes upstream bare, and the upstream's `401` reads
like the boundary denying the call.

A route is either **opaque** (`RouteSpec::opaque`) — one secret attached
at one location, standing behind a phantom — or **signed AWS**
(`RouteSpec::signed_aws`), SigV4-signed across several headers. A signed
route takes no inject location and mints no phantom, because nothing is placed for
the vault to recognize. Add `harness_location(mode)` to an opaque route when the
workload presents the phantom somewhere other than where the real secret attaches. It returns
`Result<RouteSpec>`, and it refuses a `mode` of a different *kind* from the inject mode. The two
may differ in details: a phantom in `x-phantom` with the secret into `Authorization` is legal,
because both are header placements. A `url_path` harness with a `header` inject is not. On a
signed route the call is accepted and changes nothing, because there is no inject location.

## Request path

| Call | Answers |
|---|---|
| `attach_for(&self, req: Outbound<'_>) -> Result<Option<Attachment>>` | What to edit before this request goes upstream, as an `Attachment` of header, path, and query edits. `Ok(None)` when this vault governs no credential for the destination. |
| `redact_leaks(&self, res: Inbound<'_>) -> Option<Redactions>` | The `Redactions` a response needs because it echoed the injected secret back, or `None` when nothing leaked. It returns no `Result`: a response is already received, so there is nothing to fail closed on. |

`attach_for` performs binding dispatch, phantom location, phantom **validation**,
and SigV4 signing internally, so the phantom check is not a step a caller can skip.
It fails closed — rather than sending a request whose credential material is wrong —
when more than one **opaque** binding matches the destination, when the request presents no
phantom or a phantom that does not match its binding, or when a signed route's
service and region cannot be derived from the host.

Two things `attach_for` does in a fixed order, and a caller depends on both. A signed AWS
binding is tried first, so a destination matched by both a signed and an opaque route signs.
And the signed-route lookup takes the **first** matching pattern rather than refusing an
overlap, so two overlapping signed patterns let declaration order decide which profile signs.
Declare signed patterns that do not overlap.

`Backend::local().resolve(&locator)` resolves one locator to plaintext. Its signature is
`resolve(&self, locator: &Locator) -> Result<Zeroizing<String>>`. The caller owns the
returned secret and its lifetime.

## Credential references

| Form | Resolves to | Absent secret |
|---|---|---|
| `env://NAME` | A process environment variable. A nine-name denylist refuses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `LD_PRELOAD`, and `LD_LIBRARY_PATH`, case-insensitively. | soft when the variable is unset |
| `file:///path` | File contents, trailing newline stripped. | soft when the file is missing or unreadable |
| `op://vault/item/field` | The authenticated 1Password CLI. | hard: `op read` returns one exit code for missing, locked, and signed-out, so there is no "absent" signal to trust |
| `aws://profile` | Structured AWS session credentials for SigV4 signing. Not a single secret, so `Backend::resolve` rejects it. | hard |

A soft outcome means the vault comes up and the route appears in `skipped()`. A hard one aborts
the open. A present value is always judged on content, so an empty, whitespace-only, non-UTF-8,
or control-character value is hard whatever the scheme. Open the vault **before** the caller
activates its sandbox: a `file://` path unreachable afterwards reads as an absent secret rather
than an error.

## What this crate refuses

`open` returns an error naming the destination for a route whose locator is `cmd://` or
`oauth2://`, and the message says which references to use instead. `cmd://` has no
request-time capture path wired; `oauth2://` has no token-exchange lifecycle wired. The check
runs before any dispatch, so no branch can claim a route first and leave the field unread. It
previously loaded and registered a binding nothing dispatched, so the request went upstream
with no credential. One refused route aborts the whole open, so the vault never comes up with
the other routes bound and this one silently missing.

An OAuth2 *config block* is refused a step earlier: no `RouteSpec` constructor accepts one, so
it cannot be expressed here at all. The `oauth2://` locator refusal at `open` covers what a
constructor cannot see, because `open` is the one seam every route passes whatever built it.

## Secret handling

No public method vends a resolved plaintext to an egress caller. A resolved secret
lives only inside the vault, and reaches the wire as edits on an `Attachment`; the
one plaintext exit is `Backend::resolve`. Its caller must protect the returned value.

Secret-bearing values use `Zeroizing` storage and redact in `Debug`, including a
`{:?}` of a whole `Vault` or `Attachment`. Redaction happens at each constructor, not at the
logging site, so no caller can omit it: a credential reference becomes `scheme://[REDACTED]`
— `env://GITHUB_TOKEN` becomes `env://[REDACTED]` — and a reference with no scheme becomes a
bare `[REDACTED]`. A `Skipped` exposes `destination()`, `code()`, `message()`, and `hint()`,
and no accessor for the reference at all. Every resolve emits one audit record, success or
failure; failing to acquire a credential is itself security-relevant.

`Zeroizing` is a default, not a seal. It implements `Deref`, so `.to_string()` on a resolved
value compiles and yields un-wiped plaintext. Treat the type as a marker that a copy is
visible in review, and keep the plaintext inside the construction site.

A vault belongs to one tenant and holds it for its lifetime. Isolation is
structural: a vault opened for one tenant has no binding for another's destination,
so there is no code path that vends across tenants.

## Errors

| Variant | Result |
|---|---|
| `SecretNotFound` | The route appears in `skipped()`, or aborts the open under `require_every_route`. The only soft failure. It carries the redacted reference. |
| `Credential` | Credential production failed, a reference is unroutable, the route is unsupported, or a signed route's scope could not be derived. The generic hard failure. |
| `KeystoreAccess` | The selected source could not be reached, including an unreachable AWS provider chain. |
| `Ambiguous` | More than one opaque binding matched one destination. |
| `UnsupportedInjectType` | The resolved material cannot use the declared injection mode, or an observed phantom is missing or does not match its binding. |

`CredentialError::is_soft()` is the one place that classifies these: only `SecretNotFound` is
soft. `CredentialError` is `#[non_exhaustive]`, so match with a wildcard arm. `Result<T>` is
this crate's alias over it.


## What this crate guarantees, and what it refuses

A reader deciding whether to trust this boundary needs four claims, each enforced by a type
rather than by a convention.

**The workload never holds a secret.** It holds a phantom: a `strands_box_`-prefixed 64-hex
token from the OS CSPRNG, bound to one destination. Presenting it against a different
destination attaches nothing. A workload that exfiltrated its whole environment would be
leaking values that authenticate nowhere.

**A value that cannot authenticate never becomes a credential.** Every source returns a
crate-internal `Secret`, and its only constructor refuses an empty value, a whitespace-only
one, and any value carrying a C0 or DEL byte — so a route cannot come up attached to
`Authorization: Bearer ` with nothing after it, and a CRLF cannot forge a header boundary on
the wire. Because the rule is in the type, a source added later cannot omit it. `Secret` is not
on the façade, so a caller gets the refusal without holding the type.

**A placement that would break every request cannot be built.** `InjectMode`'s four
constructors are `header`, `basic_auth`, `url_path`, and `query_param`. `header` and `url_path`
refuse a template that does not carry exactly one `{}`. `header` refuses a header name that is
empty or not an RFC 7230 token. `query_param` refuses a name that is empty or carries a byte
outside ASCII alphanumerics and `-._~!$'*+`. That rule is deliberately stricter than the header
rule: `&`, `%`, and `#` are legal RFC 7230 token bytes, and each is a URL metacharacter. `&`
separates query parameters, `%` begins a percent-escape, and `#` begins the fragment. Only
`basic_auth` is infallible, because it carries no operator-supplied value. Each refused shape
used to open a vault cleanly and then fail every request to that destination.

**Nothing here vends plaintext.** The resolved secret is a private field; the request path
returns *edits*. `Backend::resolve` is the one public door that yields a string, for a caller
whose entire need is one api-key, and it applies the same content rule.

What it deliberately does not do: it does not decide reachability. A credential binding says
only what is attached to a request that policy already permitted, and no binding can make a
destination reachable — see
[a credential binding is configuration, not a policy action](../../docs/design/decisions.md#a-credential-binding-is-configuration-not-a-policy-action).

## Decisions worth reading before changing this crate

Five entries in [`docs/design/decisions.md`](../../docs/design/decisions.md) each answer one
question about this crate:

| Decision | The question it answers |
|---|---|
| [Unusable secret](../../docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable) | Where does the credential-content rule live? (A newtype, not a check.) |
| [Placement](../../docs/design/decisions.md#the-operator-selects-the-credential-placement) | What happens to an inject mode with no operator surface? |
| [Undeliverable credential](../../docs/design/decisions.md#an-undeliverable-credential-is-refused-at-load) | What does the box do with a credential scheme it cannot deliver? |
| [Endpoint breadth](../../docs/design/decisions.md#endpoint-breadth-is-refused-by-the-parsed-pattern) | Is endpoint breadth judged by the endpoint's text or its parsed shape? |
| [Identity substitution](../../docs/design/decisions.md#a-provider-refuses-an-identity-it-cannot-honour) | May a provider substitute an identity it cannot honour? |

Two are worth knowing even if you are only reading: the unusable-secret decision, because the
`Secret` type is the reason three sources cannot each be wrong about content; and the
endpoint-breadth decision, because the guard it replaced had been bypassable by writing `*:443`
instead of `*`.
