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

A route is one of four kinds. **Opaque** (`RouteSpec::opaque`) — one secret attached
at one location, standing behind a phantom. **Signed AWS**
(`RouteSpec::signed_aws`), SigV4-signed across several headers. And two for a re-route to a backend:
**box-owned** (`RouteSpec::box_owned`) attaches the box's own credential — a backend token — at one
location with no phantom; and **strip-phantom** (`RouteSpec::strip_phantom`) mints a placeholder the
workload presents and strips it, attaching nothing (a re-routed destination's own secret). A signed
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
| `response_redactor(&self, destination: Destination<'_>) -> Option<ResponseRedactor>` | An owned scrubber for a streamed response, or `None` when no unique opaque binding matches. |

`ResponseRedactor` keeps credential material private and replaces exact secret occurrences with
`[REDACTED]`. Use `redact_header()` for each header value and `push()` for each body chunk. Each
`push()` returns bytes ready for delivery and retains a trailing window of up to one less than the
credential's byte length, including any possible secret prefix. At clean completion, call `finish()`
to release the tail; on failure, drop the scrubber. Matches can cross chunk boundaries. A small event
can wait for more bytes or clean completion. Retained state depends on the credential size, not the
total response size.

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

`Backend::declared(declarations)` is the local source set plus one source for each
`SecretSourceCommand` and the opened program file that the caller checked for it.
`Backend::close_declared()` wipes each secret that those sources hold and refuses each later read
through one. See [Declared secret sources](#declared-secret-sources).

## Credential references

| Form | Resolves to | Absent secret |
|---|---|---|
| `env://NAME` | A process environment variable. A nine-name denylist refuses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `LD_PRELOAD`, and `LD_LIBRARY_PATH`, case-insensitively. | soft when the variable is unset |
| `file:///path` | File contents, trailing newline stripped. | soft when the file is missing or unreadable |
| `op://vault/item/field` | The authenticated 1Password CLI. | hard: `op read` returns one exit code for missing, locked, and signed-out, so there is no "absent" signal to trust |
| `aws://profile` | Structured AWS session credentials for SigV4 signing, resolved as the named profile through the AWS SDK (static keys, credential_process, assume-role, or web identity). Not a single secret, so `Backend::resolve` rejects it. | hard |
| `aws://` (no profile) | Structured AWS session credentials from the AWS SDK default credential provider chain (the host's ambient identity), driven on a worker thread and cached. Not a single secret, so `Backend::resolve` rejects it. | hard |
| `SCHEME://NAME` or `SCHEME://NAME#FIELD`, for a declared `SCHEME` | The stdout of the declared program, or one string field of it. Only `Backend::declared` resolves it. | hard: a program cannot signal "absent" |
| `credsd://credential` on `RouteSpec::signed_aws` | Structured AWS session credentials from one `credential/get` of that credential to the credsd daemon, on each request. Not a single secret, so `Backend::resolve` rejects it. | hard |
| `credsd://credential` on `RouteSpec::opaque` | The credential's `access_token`, read with one `credential/get` when the vault opens and held for the run. A `token_type` other than `Bearer` is refused. A token with an expiry warns at open, because the vault does not refresh it. | hard |

`credsd_preflight(socket, signed, tokens)` checks the daemon before a workload starts: its
protocol version, and with one `credential/list`, that each named credential exists and is
`session_credentials` for a `signed` name or `access_token` for a `tokens` one. The client
addresses credsd by credential name, as credsd 0.2 requires; it sends no `environment` member.

A soft outcome means the vault comes up and the route appears in `skipped()`. A hard one aborts
the open. A present value is always judged on content, so an empty, whitespace-only, non-UTF-8,
or control-character value is hard whatever the scheme. Open the vault **before** the caller
activates its sandbox: a `file://` path unreachable afterwards reads as an absent secret rather
than an error.

## Declared secret sources

A `SecretSourceCommand` declares one host program that prints one secret on stdout. A caller
builds one for each scheme, opens and checks the program file, and gives both to
`Backend::declared`:

```rust
use credentials::{Backend, Locator, SecretSourceCommand};

let command = ["/opt/homebrew/bin/op", "read", "op://{ref}"].map(String::from);
let declaration = SecretSourceCommand::new("op", SecretSourceCommand::PROTOCOL, &command)?
    .pass_env(["OP_ACCOUNT", "TMPDIR"])?
    .pass_secret_env(["OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_*"])?;
// The caller opens the file that the path resolves to, and checks it before this call.
let program = std::fs::File::open("/opt/homebrew/bin/op")?;
let backend = Backend::declared([(declaration, program)])?;
let secret = backend.resolve(&Locator::parse_uri("op://Private/GitHub/token")?)?;
// Each vault that needs the secret is open, so no declared source reads again.
backend.close_declared();
```

The example passes `TMPDIR`, because `op` keeps the session of `op signin` in a folder under it.

| Part | Rule |
|---|---|
| Scheme | A lowercase letter, then lowercase letters, digits, `+`, `.`, or `-`. No declaration can claim one of the nine reserved schemes: `env`, `file`, `aws`, `credsd`, `secret`, `cmd`, `oauth2`, `aws-signed`, and `strip-phantom`. The last two are the crate's own route markers. `SecretSourceCommand::check_scheme` is the check. A declared `op` takes the place of the built-in `op://` source. Two declarations of one scheme are refused. |
| Protocol | `SecretSourceCommand::PROTOCOL`, which is `box.secret-source.v1`. Any other value is refused. |
| Command | The program, then its arguments. The program is an absolute path. The source runs it with no shell. A command with no `{ref}` in its arguments is refused. |
| `{ref}` | The source replaces `{ref}` inside each argument with `NAME`, the text after `SCHEME://` without `#FIELD`. A reference whose text after `SCHEME://` starts with `-` is refused, so the program cannot read it as a flag. |
| Environment | `HOME` when the operator has one, `PATH=/usr/bin:/bin`, and each variable in `pass_env` or `pass_secret_env` that is set. An entry that ends with `*` passes each variable with that prefix. No entry replaces `HOME` or `PATH`. The entries `*`, `PATH`, and `HOME` are refused, and so is an entry with a `*` before its end. `SecretSourceCommand::passes_as_secret` says whether `pass_secret_env` names a variable, by an exact entry or by a prefix entry. |
| Bounds | No stdin. The working directory is `/`. A run of more than 30 seconds, or more than 1 MiB of stdout, stops the program and fails the fetch. A non-zero exit fails the fetch. |
| `output` | `text` (the default): stdout is the secret. `json`: stdout is one JSON string, and the decoded string is the secret. Any other JSON value, such as `null`, is refused. The source strips one trailing `\n` or `\r\n` first. With each form, the `#FIELD` rule then applies to the secret. |
| `#FIELD` | The source parses the secret as a JSON object and returns that one string field. Without `#FIELD`, a secret that is a JSON object is refused with each `output`, so that one destination never gets all the keys. The built-in `op://` source returns such a secret whole, so a declared `op` differs from it here. |
| Program file | The source keeps the opened file of each declaration. It starts the program only while the declared path names that file, by device and inode, and it compares again after the program exits. When the path names another file, or no file, the fetch fails and the output of that run is not read. |
| One fetch | The backend keeps each fetched secret until `close_declared`, or until its last clone drops. Two references that differ only in `#FIELD` name one secret, so the program runs once for both. `Backend` is `Clone`, and each clone shares the fetch. A run that fails, or whose output the source cannot read, is not kept. A run whose output is read is kept, also when the `#FIELD` step or the content check then refuses the value. |

A failure names the scheme, the program, and the redacted reference. After a non-zero exit it also
carries the last bytes of the program's stderr, at most 512, as one line. The reference name and the value
of each passed `pass_secret_env` variable are replaced with `[REDACTED]`, and the line holds no control
character. A program that prints one part of the reference name on its own, such as one path
segment, still shows that part. No failure carries stdout.

The program runs in the caller's process context, outside every sandbox, so declare only a program
that the operator chose. The caller checks the program file before it opens the backend, and this
crate holds the program to that file. The source starts the program by its path, so a replacement
between its comparison and the start of the program is not seen until the program exits. This
crate does not protect the program's files; the caller owns that.

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

No public method vends a resolved plaintext to an egress caller. Credential material stays
private to the vault and its owned response scrubber. It reaches the request wire as edits on an
`Attachment`; the one plaintext exit is `Backend::resolve`. Its caller must protect the returned value.

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
token from the OS CSPRNG, bound to one credential's destinations. Routes with an equal
`Locator` and prefix share one phantom; two credentials never do. Presenting it against a
destination outside that credential's routes attaches nothing. A workload that exfiltrated its
whole environment would be leaking values that authenticate nowhere.

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
`Secret` type is the reason no source can be wrong about content; and the
endpoint-breadth decision, because the guard it replaced had been bypassable by writing `*:443`
instead of `*`.

## Live daemon test

The `credsd_e2e` tests use local socket fixtures. One optional test checks a running
credsd daemon. Give the test process a credential that it can list, then run:

```sh
CREDSD_SOCKET=/path/to/credsd.sock CREDSD_TEST_CREDENTIAL=test-credential \
  cargo test -p strands-box-credentials --all-features --test end_to_end \
  credsd_e2e::a_live_daemon_maps_an_unknown_credential_to_a_hard_failure -- --exact --nocapture
```

The test checks daemon health and that the daemon lists the configured credential. Then it
requests a credential that does not exist. It requires the specific unknown-credential error.
A connection failure cannot satisfy that assertion. The configured credential is used
only for the credential-list check, not for credential acquisition.

An explicit socket or test credential makes setup failures fatal. Without either
setting, the test reports a skip. A skipped test does not prove daemon compatibility.
