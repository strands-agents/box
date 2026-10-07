# Egress Gateway Agent Guidance

Applies to `crates/egress-gateway/**`. Follow the
[repository guidance](../../AGENTS.md) first.

**Interface-frozen.** The `pub use` façade is frozen, and two of its
properties are foundational premises: `EffectInterceptor` is the single authorization source, and
`CapabilitySet` is a deny-only floor *beneath* policy, not a second authority. Get
the user's approval before you change either; a defect fix behind the current shape needs none. Do
not rename during the freeze.

## Public Contract

The façade exports 33 names (`src/lib.rs`): 29 unconditional, and 4 behind the default-on
`tls-intercept` feature — `MitmConfig`, `MitmHandle`, `MitmInterceptor`, `ResponseLimits` — which stay
behind it. `audit::Decision` exits as `AuditDecision`. A 34th name needs a named external caller.

- Keep implementation modules private, re-export the supported surface from `src/lib.rs`, and keep
  `#![warn(missing_docs, unreachable_pub)]` enabled.
- **Keep authorization out of this crate.** The authored policy decides, reached only through
  `EffectInterceptor`; the engine is Dogwood (`ENGINE_ID = "dogwood-0.1.0"`). Never add an allow or
  deny authority here, and never add an `Allow` variant to `CapabilityOutcome`. `AuditDecision`
  carries `Allow` and `Deny` and authorizes nothing.
- Do not depend on `policy`. The direction is `policy -> egress-gateway`.
- Preserve `CapabilitySet::validate` as the startup gate, and keep `evaluate_request` and
  `evaluate_response` socket-free.
- Keep interception side effects outside capabilities, domain decisions behind `EffectInterceptor`,
  and audit behind `Emitter`.
- Add a public item only for a concrete external consumer.

The seam is `EffectInterceptor::intercept`, taking an `&EffectAttempt` and returning a
`Box<dyn EffectPermit>` (`src/effect.rs`). It speaks `io::Result`, never `ProxyError`, and a denial is
`io::ErrorKind::PermissionDenied`. There are exactly three attempt kinds — `Connect`, `HttpRequest`,
`ResponseRelease` — each admitted before its effect and each reporting a terminal `EffectOutcome`.
`record_outcome` and `mark_indeterminate` consume `self: Box<Self>`, and `ClaimedEffectPermit`'s
`Drop` calls `mark_indeterminate`, so one permit makes one terminal transition even on a panic.

### One thing here is deliberately not authorization

The gateway holds no destination deny list. A metadata or link-local address is refused by a policy
`forbid` on `context.input.ip`, decided on the pinned address
([metadata protection is policy](../../docs/design/decisions.md#the-ssrf-and-metadata-floor-is-compiled-beneath-policy)).

- **`CapabilitySet` holds the credential mutators, not a second authority.** `CapabilityOutcome` is
  `Applied(Vec<Mutation>)` or `Unavailable(CapabilityFault)`, and it has **no `Allow` variant**. A
  fold's `Verdict::Allow` comes from the *absence* of a fault, never from a capability.

## Security Invariants

- Decide every connection and transport twice: the host before resolution, and each resolved,
  pinned address before its socket opens. The address decided is the address dialed.
- `open_upstream` authorizes through `EffectInterceptor` before the socket opens.
- One `CapabilityOutcome::Unavailable` denies the exchange, at any position in the fold.
- Apply request mutations only when the verdict allows.
- Use the same pinned addresses for resolution and for the upstream connection.
- Keep an intercepted HTTP authority bound to the admitted CONNECT destination.
- `CredentialCapability` checks the destination-bound phantom before it attaches material. The vault
  owns the check: a `Strict` route (the default) makes an absent or mismatched phantom a
  `CapabilityOutcome::Unavailable`; an `Advisory` route warns and attaches the secret anyway. The
  destination binding still gates injection in both modes. An advisory injection carries the vault's
  non-secret reason via `Attachment::advisory_reason` onto `InterceptedRequest::advisory_note`, and
  the request leg journals it on the allow `EgressDecision` (destination, reason, correlation).
- Keep secret-bearing headers and body content out of effect attempts.
- Keep audit values to routing, decision, reason, and correlation data.
- Fail startup on duplicate per-pattern capabilities. There is no visibility check, because
  [no connection is opaque](../../docs/design/decisions.md#no-connection-is-opaque-to-the-boundary).
  Do not re-add a visibility gate.
- The dependency direction stays `egress-gateway -> credentials`.

## Internal Ownership

The capability modules carry no authority.

- `ControlSet`, `Control`, `Cx`, and `Visibility` are gone, because
  [policy is the only authority](../../docs/design/decisions.md#the-authored-policy-is-the-only-decision-authority).
  Read `src/capability/`.
- Residual: `ProxyError::NotAuthorized`'s doc comment says "Connection-scope Decision Control" and is
  not live design. `DenyReason::NotAuthorized` is correct.

## Known naming debt (fact, not a plan)

Three divergences from `docs/conventions.md` are live, and none is license to rename:

- No root noun: 33 exports, no single type reached by one verb, `Interceptor` a one-method port,
  `MitmInterceptor::start` taking three arguments and returning `MitmHandle`, and
  `CapabilitySet::builder()` → `CapabilitySetBuilder::build()`.
- A bare `Emitter` export; `credentials` demoted its same-named trait to `pub(crate)`.
- `Mitm*` states the mechanism, and `ProxyError`'s "proxy" strings diverge from the crate name.

## Sources Of Truth

Behavior: `src/**`, `tests/**`. Decisions: [docs/design/decisions.md](../../docs/design/decisions.md).
Conventions: `docs/conventions.md`.

## Measured bypasses and footguns

- Hand policy the pinned `SocketAddr` unchanged. `policy/src/address.rs` unwraps the four IPv6
  transition encodings to the IPv4 address they carry; a forbid on `169.254.*` reopens through
  three spellings if that unwrapping is lost.
- Keep `Arc<dyn EffectInterceptor>` mandatory in `MitmInterceptor::start` and `start_with_emitter`,
  and never add `start_without_policy()` or an `Option` form.
- Use `write_trusted_diagnostic` only for static, secret-free, proxy-originated bytes. Upstream bytes
  always need a `ResponseRelease` permit.
- Keep the CONNECT `Proxy-Authorization` check best-effort; SDKs omit the header. Never weaken the
  `ProxyOnly` kernel pin, the real anti-hijack defence.
- Report the pre-mutation `workload_path`, which `emit_decision` reads from `DecisionSubject`. Never
  read `req.target.path`; a `UrlPath` credential makes it the secret.
- Keep `estimate_head_capacity` a correctness bound; `headers + 64` under-counted a plain
  `POST /v1/messages` by 6 bytes in 500 of 500 runs.
- Allocate `head.len() + body.len()` up front in the coalesce path; reuse relocated in 300 of 300
  runs. Treat head-buffer guards as security tests, because one added header line leaks a credential
  into freed heap silently.
- Keep `the_status_line_budget_covers_every_reason_phrase`; `STATUS_LINE_BYTES = 64` is a constant
  that a longer `reason()` phrase overruns.
- Never derive `Debug` on `HeaderMap` or `InterceptedRequest`, and never unwrap a value out of
  `Zeroizing`; one `eprintln!` then prints live credentials.
- Residual: `Target::path` and `Target::query` are plain `String`, so a `UrlPath` or `QueryParam`
  credential leaves un-wiped bytes.
- Residual: the CA private key is not `Zeroizing`, because `rcgen` holds it; the daemon's memory
  protection is its boundary
  ([memory is a defended asset](../../docs/design/decisions.md#the-trusted-processs-memory-is-a-defended-asset)).
  Only the public cert reaches disk, at `0o400`.
- Return `ResponseDecision::RedirectReentry` for a cross-host 3xx, only after the response fold.
  Otherwise a redirect reaches a refused host or releases an unscrubbed secret.
- Keep the set-level prefilter in `evaluate_request` and `evaluate_response`; deleting the
  "redundant" `continue` gives a two-route box a `MutationCollision` outage.
- Count only `SetHeader`, `RewritePath`, and `AddQueryParam` in collision detection; `StripQueryParam`
  shares its `MutationTarget`, so counting a strip makes a route collide with itself. The surfaced
  fault is the first `Unavailable`, deterministic only through one-capability-per-pattern.
- Decode the key in `strip_query_param`, because the workload picks the spelling and `a%2Fb`, `a%2fb`,
  and `a+b` are one key. Leave a malformed `%` escape verbatim. `AddQueryParam` appends, so keep
  `StripQueryParam` beside it.
- Keep `read_until_headers_end` byte-at-a-time and unbuffered; a `BufReader` strands the
  `ClientHello` and breaks TLS termination.
- Keep `BoundTransport`, and self-connect in `shutdown()` over the bound transport; a `u16`
  deadlocks `Drop`'s `join()` under the AF_UNIX pin, where `env_vars()` omits `HTTP(S)_PROXY`.
- Keep `MAX_CACHED_LEAVES = 64` and clear the cache on reaching it; each entry holds a leaf key for
  the daemon's lifetime, so a wildcard-host policy otherwise leaks without bound.
- Refuse an unframed message on a reusable connection when keep-alive lands. `read_body_to_close`
  reads to EOF, correct only while the close delimits.

## Change Checklist

```text
cargo build -p strands-box-egress-gateway --all-features
cargo build -p strands-box-egress-gateway --no-default-features
cargo test -p strands-box-egress-gateway --all-features
cargo clippy -p strands-box-egress-gateway --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc -p strands-box-egress-gateway --all-features --no-deps
```

Run the repository-required artifact critics unless the user limits validation. Do not modify
`Cargo.lock`.
