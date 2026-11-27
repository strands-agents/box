# Credentials guidance

The root freeze covers the facade, locator schemes, and mint/inject split. The vault returns
request edits, never a credential accessor or an authorization. Keep backend profiles sealed;
`Backend::resolve` is the plaintext exit and declared sources require an opened, checked program.

## Secret handling traps

- `Zeroizing` wipes on drop but does not redact `Debug` or prevent an un-wiped `to_string()` copy.
  A growing buffer can free a secret prefix before the final wipe. Keep capture buffers fixed-size
  and redact diagnostics at construction, including reference bodies and JSON field names.
- Streaming redaction must equal whole-body greedy redaction across every chunk split. Release its
  retained tail only on clean EOF; failure discards it. Keep memory bounded by credential length.
- SigV4 intermediate keys and canonical headers/request contain secret material, including session
  tokens. Header-name lists and the hashed string-to-sign do not. Preserve that distinction.
- Keep destination matching inside `attach_for`; splitting resolution from phantom checking makes
  validation optional for callers. Advisory phantoms relax the placeholder check only, never the
  destination binding. Strip the harness location even on an advisory route.
- Query parameter injection appends. Strip the existing key first; percent-encoded aliases must
  resolve to the same key. Host suffix and path prefix checks need label/segment boundaries.
- `env://`'s source denylist and Box's reserved workload environment answer different questions.
  A bare `aws://` deliberately uses ambient AWS identity; merging those lists breaks that route.

## AWS identity and refresh

- For the AWS SDK signing path, use
  `AwsSource::with_provider(self.aws_provider(), self.ambient_policy())`.
  Using `new()` or `Default` there would select `AllowWithWarning` and bypass
  `require_scoped_aws_profile`.
- Named profiles use the profile-only SDK provider. `DefaultCredentialsChain::profile_name` still
  tries environment keys first and can fall through to metadata, signing as the wrong identity.
  Preserve `named_profile_ignores_ambient_env_and_refuses_a_missing_profile`.
- Rebuild the provider on refresh: its cached profile parse otherwise hides rotated files.
  Re-resolve credentials without expiry on every request. Judge fallback expiry after the refresh
  finishes, since the wait itself can outlive the old credential.
- Snapshot restore invalidates cached identity even when the credential has not expired. A failed
  resolve after detected restore must never fall back to the old credential. `/dev/sysgenid` needs
  a mapped volatile load; reading the device blocks until a change. Without it, clock-gap detection
  can miss short restores and can invalidate on sleep or clock correction.
- Keep idle HTTP pooling disabled for credential resolution: snapshot restore can leave pooled
  metadata/STS connections attached to the old network while the monotonic timeout remains fresh.
- Bound SDK resolution outside the SDK. `credential_process` has no SDK timeout; cancellation can
  still leave the helper and its blocking worker alive. Preserve the caller and resolve deadlines.
- Keep named-profile region resolution tied to that profile for STS, independently of the route's
  signing region. The current SDK feature selection excludes SSO and `aws login`.

## credsd

- The route kind is the credsd type: `RouteSpec::signed_aws` over `credsd://` resolves session
  credentials per request; `RouteSpec::opaque` reads one `access_token` at open and reads it
  again on the first request near or past the daemon's `expires_at`. Before expiry that read runs
  on its own thread so no request waits on the daemon; never hold the token lock across a read.
  Every read refuses any other material type and any `token_type` but `Bearer`, compared without
  case. Routes of one vault that
  name one token share one read and one refresh. A route with an expiring token attaches only
  through `Vault::attach_with_redactor`, which keeps the token the request carried to scrub its
  response.
  `credsd_preflight` checks each listed credential's kind against the list it gets.
- A token's deadlines sit on both `Instant` and `SystemTime`, and pass when either clock reaches
  them. `Instant` alone ignores wall-clock steps but stops while the host sleeps on macOS and Linux,
  so it would keep an expired token after a laptop wakes. A refresh error keeps only its
  `GetFailure` class: credsd material and type labels never reach a gateway refusal.

## Declared source programs

- Run from `/`, with no shell or stdin and a composed environment. The trusted process's inherited
  cwd can be workload-writable and change a source program's configuration.
- Drain both pipes concurrently. Bound stdout waiting even after the direct child exits: a
  descendant can keep it open. Keep only bounded stderr and never include stdout or a JSON parser's
  value-bearing diagnostic in an error.
- Compare the program's path identity with its opened file before spawn and after exit. This does
  not prevent one execution after a race, in-place edits, or descendants surviving a timeout.
  The caller must protect the program from workload writes.
- Keep the fetched object before field selection, and share it across backend clones. Closing
  declared sources is final; another fetch would start a host program while the workload runs.
- Match redactions against original captured bytes, including overlap and a truncated prefix.
  Sequential text replacement leaks overlapping values. Stderr can still contain an unknown secret
  or only part of a reference; do not claim complete redaction or complete heap wiping.
- The declared-source JSON-object check is stricter than built-in `op://`; deeply nested JSON that
  exceeds parser limits can still be treated as text. Keep that limit separate from `#FIELD` checks.

## Verification beyond the root gates

Run rustdoc with warnings denied and private items documented; public-only docs miss dangling links
when a facade shrinks. Build and test consumers: gateway, Box, telemetry, and containment (the last
uses credentials only as a dev dependency). Use fake providers for tests, never host credentials.
