# Credentials Agent Guidance

Applies to `crates/credentials/**`. Follow the
[repository guidance](../../AGENTS.md) first.

**Interface-frozen.** The frozen surface is the `pub use` façade, the URI vocabulary (`env://`,
`aws://`, `file://`, `op://`), and the mint/inject split. Changing one, or a foundational premise,
needs the user's approval before code. A defect fix behind the current shape does not.

## Responsibility

This crate owns credential declarations, source resolution, secret material, destination matching,
phantom generation, acquisition audit records, and the two request legs: what attaches outbound, and
the scrub of an echoed secret. `strands-box-egress-gateway` applies the edits to bytes. Do not write
`egress-proxy`; no such crate exists.

## Public Contract

- Keep implementation modules private. `src/lib.rs` re-exports the supported surface: 19 public
  names — including `credsd_preflight`, the box's one entry to the startup credsd check, and
  `PhantomCheck`, the per-route placeholder-check mode — plus nine
  `pub(crate) use` re-exports (`Emitter`, `RequestId`, `audit_resolve`,
  `CredentialDiagnostic`, `redact_credential_ref`, `AwsSessionCredentials`, `PhantomToken`,
  `Secret`, `sign_request`). Count the lists separately; a move either way needs approval.
- Do not re-export our `Emitter`; `egress-gateway` exports its own.
- Keep `#![warn(missing_docs, unreachable_pub)]` on, and treat its output as findings.
- Add a public item only for a named external caller. A type in a public signature stays public
  (`Destination`, `DestinationPattern`).
- Keep four entry points and add no fifth: `Vault::open` (startup), `Vault::attach_for` (request
  leg), `Vault::redact_leaks` (response leg; no `Result`, `None` when ambiguous), `Backend::resolve`
  (one locator to plaintext).
- Do not re-split `attach_for` into `resolve_for`, `resolve_with_phantom`, and `get_aws`; a split
  makes validation the call site's choice.
- Return no binding, secret, or "credential for this destination" from any accessor.
- Add no destination, tenant, or request-id parameter to `Backend::resolve`; ingress has none, so
  the seam fabricates them.
- Keep backend selection a named `Backend` profile over a private enum. Return no trait object.
- Declare no `pub trait`, and keep `SecretSource` and `Emitter` `pub(crate)`, so no caller supplies
  an unreviewed backend.
- Keep `RouteSpec`'s fields sealed behind `opaque()`, `signed_aws()`, and `harness_location()`.
- Keep `DestinationPattern` shared with egress-gateway; use `as_written()` in operator text.

## Security Invariants

- Vend no resolved plaintext to an egress caller. A resolved secret lives only in the private
  `OpaqueBinding` and reaches the wire as `Attachment` values.
- Keep `Backend::resolve` the single plaintext exit, and digest the value at once.
- Store every secret-bearing value in `Zeroizing`, and print no plaintext in `Debug` or `Display`,
  including `{:?}` of a `Vault` or `Attachment`.
- Wrap every value holding key material: the `AWS4`-prefixed secret access key, `k_date`,
  `k_region`, `k_service`, `k_signing`, `canonical_headers`, and `canonical_request`. The last two
  embed the session token. `signed_headers` holds names only and `string_to_sign` a SHA-256, so both
  stay plain. `Redactions::set_headers` stays `&str`.
- Treat `Zeroizing` as a typing default, not a seal: `Deref` lets `to_string()` and `as_str()`
  compile and yield un-wiped plaintext, so the consumer upholds the invariant.
- Wipe bytes on every failure path: the non-UTF-8 arm wraps `e.into_bytes()`, the timeout arm wipes
  partial output.
- Keep an `op`-sourced secret in one buffer; `String::from_utf8` reuses the `Vec` and
  `trim_trailing_newline` truncates in place. Drain its stdout on a separate thread while the parent
  polls `try_wait`, or a large secret deadlocks the pipe.
- Redact credential references at the constructor, in `CredentialDiagnostic::new` and
  `CredentialAcquire::new`, never at the logging site.
- Serve one tenant per vault, and never consult the tenant while matching.
- Refuse two matches on the opaque path with `CredentialError::Ambiguous`.
- Treat an absent secret as the one soft failure, listed in `Opened::skipped()`.
  `require_every_route` makes it hard; every other failure aborts `open`.
- Treat an unreadable `file://` (`NotFound` or `PermissionDenied`) as soft. A non-UTF-8 file, any
  other I/O error, and content `Secret::new` refuses are hard.
- Enforce phantom uniqueness across the whole vault. A collision is hard, and a
  `PhantomToken::generate(prefix)` CSPRNG failure is hard rather than a weak fallback.
- Refuse a route the vault cannot credential; never register it. A `cmd://` or `oauth2://` locator is
  hard at `open`, or the route loads clean and sends an uncredentialed request.
- Check the phantom before every edit, per the binding's `PhantomCheck`. `swap_phantom` compares the
  phantom at the harness location against the binding's token before `attach_secret`. A `Strict`
  binding (the default) fails closed on an absent or mismatched phantom with `UnsupportedInjectType`;
  an `Advisory` binding warns through `Vault::warn` and attaches the secret anyway, for a route the
  box cannot seed the placeholder into. The mode never relaxes the destination binding.
- Strip the harness location when it differs from the attach location, so no phantom rides upstream.
  The strip is unconditional, so an `Advisory` route cannot carry a foreign token upstream either.
- Resolve signed AWS routes per request; session credentials expire.
- Strip every inbound signing artifact before signing. `STRIP_SIGNING_HEADERS` must cover the
  payload-hash and query-signature artifacts.
- Emit exactly one acquisition record per resolve, success or failure, including the per-request
  signing resolve. The discarding sink drops the record, never the build.
- Keep phantom tokens distinct from real material: non-secret, unguessable at 256 CSPRNG bits. A
  minted phantom is `<prefix><64hex>`; the prefix is `strands_box_` unless a route sets
  `secret.phantom_prefix` (validated by `check_phantom_prefix`), and the entropy is the suffix only.
- Keep audit records to correlation, tenant, and routing data.
- Depend on no workspace crate.

## Internal Ownership

`model/` owns destination, route, locator, injection, and AWS values. `config.rs` owns
`VaultConfig`. `backend.rs` owns the sealed profile and the locator-to-plaintext primitive.
`sources/` owns the adapters, all `pub(crate)`. `vault.rs` owns `open`, the binding tables, and
lookup. `legs.rs` owns `swap_phantom` and `sign_aws`; keep them here. `attach.rs` owns the borrowed
views. `opened.rs` owns the startup obligations. `audit.rs` and `diagnostic.rs` own secret-free
observability. `error.rs` owns the soft-versus-hard classification.

There is no OAuth2 mint provider, and `sources/oauth2.rs` is deleted. Add a route constructor, a
dispatch path, and a token lifecycle before any provider; unreachable mint machinery reads as a
wired feature.

## Sources Of Truth

`src/**` and `tests/**` own behavior and the contract; `../../docs/design/decisions.md` owns why;
`../../docs/conventions.md` the conventions; `README.md` the consumer contract. A doc may still say
`CredentialStore`, `CredentialRouteSpec` or `Route`, or `CredentialLocator` for `Vault`,
`RouteSpec`, and `Locator`.

## Change Checklist

Run `build`, `test`,
`clippy --all-targets`, and `fmt --check`, each with `--all-features`, then the doc gate with
`RUSTDOCFLAGS="-D warnings --document-private-items"`; the default gate misses a dangling intra-doc
link when this surface shrinks. Build and test the three consumers: `strands-box-egress-gateway`,
`strands-box`, and `strands-box-containment`. The last is a
`[dev-dependencies]` entry, so `cargo build` misses it. Run the required artifact critics. Modify
`Cargo.lock` only for a dependency this crate added.

## Lessons from the content-and-placement work

- Put `#[non_exhaustive]` on each *variant*; on the enum it seals only added variants, so a caller
  still writes `InjectMode::Header { .. }`. A private witness must be `pub` to appear there, so it
  does not help.
- Produce the compiler error behind a sealing claim: write the bypass out-of-crate, watch
  `error[E0639]`, delete it.
- Give one invariant one owner. `InjectMode`'s constructors own the RFC 7230 token rule.
- Keep the earlier call site when you delegate, and have it ask the owner; deleting it moves the
  refusal a phase later, which
  [a refusal stays in the phase that holds its input](../../docs/design/decisions.md#a-refusal-stays-in-the-phase-that-holds-its-input)
  counts as a defect.
- Grep every construction site after you make an infallible constructor fallible; a surviving
  `expect` turns operator input into a panic.
- Reintroduce the defect and watch each test fail. An emitter and an interceptor are different
  seams.
- Pin the property, not the line: assert "the phantom is stripped", not that one strip ran.
- Read no host state in a test. `resolve_rejects_wrong_form_or_source` and
  `resolve_without_profile_is_refused_under_deny_policy` drive `PanicProvider`, whose `provide`
  panics. Delete neither test.
- Refuse in the owning phase: `create` owns operator input, `open` the seam every route passes, a
  constructor what the value may be.
- Treat a doc column you cannot fill in as a finding.

## Measured leaks and footguns

### Constructor refusals

- `Secret::new` hard-refuses empty, whitespace-only, and any C0 or DEL byte (`< 0x20`, `0x7f`). An
  empty needle breaks `redact_in_bytes` and `Redactions::scan`; a CRLF forges a header boundary,
  which nothing else in the stack refuses. The error names the redacted reference only.
- Impose no minimum length; the raw-substring response scan is an oracle at any length.
- Require exactly one `{}` in a header `format`. Either malformed shape passes
  `require_every_route()`, then fails every request.
- `harness_location` refuses a harness placement of a different `std::mem::discriminant` from the
  inject placement (hard). They may differ in details, not in which part they name.
- Keep `query_param`'s rule separate from RFC 7230. It allows `is_ascii_alphanumeric()` plus
  `-._~!$'*+`; the token rule also allows the URL metacharacters `#`, `%`, and `&`, plus `^`,
  `` ` ``, and `|`. Refuse an empty name.

### Identity substitution

- `AwsSource::parse_profile` must check the scheme equals `AWS_SOURCE_TAG` (`"aws"`), not merely
  `split_once("://")`. A bare `split_once` signs with the ambient identity, makes
  `AmbientFallbackPolicy::Deny` unreachable, and emits a lying `AwsAcquisition::Profile(..)`. The
  `Structured` arm carries the mirror check on `source`.
- `EnvAwsProvider` errors hard on `Some(profile)`; it reads only `AWS_*`, and
  `AwsAcquisition::warning()` returns `None` there, so a substitution would be invisible.
- Build the per-request resolve from the vault's retained `ambient_policy` via
  `AwsSource::with_policy`, never `AwsSource::new()`, or `require_scoped_aws_profile` is unreachable.
- Derive the signing name with `derive_service_region`. `bedrock-runtime` and
  `bedrock-agent-runtime` sign as `bedrock`; a global host signs `us-east-1`; `execute-api` signs as
  itself; a trailing dot is trimmed; anything else returns `None`, so the caller refuses to sign.

### The shared destination matcher

- Match a host by suffix **with** a label-boundary check, so `*.github.com` excludes the apex and
  `evil-github.com`. Match case-insensitively.
- Match a port exactly; an unset pattern port infers `{443, 80}`.
- Match a path by prefix **with** a segment-boundary check, so `/v1/chat` excludes `/v1/chatbot`. A
  leading `/*` means suffix.
- Require the host half and the path half to both match; the port belongs to the host half. A plain
  `ends_with` or `starts_with` refactor credentials `evil-github.com`.
- Ask `matches_every_host()` in a breadth guard, never the operator's text; `parse` strips the port
  first, so `*:443` is all-hosts.

### Source schemes

- `env://` refuses every `DENYLIST` name (`src/sources/env.rs`), case-insensitively and hard, so a
  manifest cannot exfiltrate ambient credentials or process-injection state. It is a floor, not a
  catalogue. `EnvAwsProvider` reads those `AWS_*` names on purpose.
- Do not merge `DENYLIST` with `reserved_workload_environment` (`box/src/define/config.rs`), which
  governs what a credential may claim in the workload environment and refuses at `create`.
- `op://` has no soft tier; `op read` cannot signal absence, so every failure is hard.
- Read `file://` before sandbox activation, or every such route skips instead of erroring. The
  loader owns that ordering.
- Keep a signed route's `credential_ref` the sentinel `"aws-signed://route"`; no source claims that
  scheme, and a meaningful one couples an unrelated refusal to every signed route.
- Strip the parameter before a `QueryParam` attach; `set_query_param` appends.

### Open residuals

- `format!` grows its own buffer, so an intermediate allocation can hold a secret prefix and be
  freed un-scrubbed. Claim no completeness.
- The trusted process's memory hardening
  ([the trusted process's memory is a defended asset](../../docs/design/decisions.md#the-trusted-processs-memory-is-a-defended-asset))
  covers the `run` process only and raises the cost of reading that heap without removing it, so
  leave no new un-wiped copy. `PR_SET_DUMPABLE` is Linux-only, dies at `execve`, and root bypasses
  it; `PT_DENY_ATTACH` refuses a debugger only; `RLIMIT_CORE` stops a core file only and survives
  `execve`, so keep it beside dumpability.
- Signed-AWS lookup uses `first_match` and raises no `Ambiguous`, so declaration order picks between
  overlapping `*.amazonaws.com` routes.
- `Locator` carries `#[non_exhaustive]` on the enum only, so a caller can construct `Locator::Uri`
  or `Locator::Structured` and bypass `parse_uri` and `structured`. It fails closed only because
  `Locator::scheme()` returns `""`.
