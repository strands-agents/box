# Crate coding conventions (mechanical checklist)

House style for a crate under `crates/`, derived from the established siblings
(`containment`, `credentials`, `egress-gateway`). Owned crates live under
`crates/<name>/`. **The product name is part of the package name**, so the
directory layout and the package names agree.

> **One crate cited below no longer exists in the tree.** `journal`
> predates the 2026-07-12 crate reset; [`Cargo.toml`](../Cargo.toml) lists the live members. `box` is
> `[[bin]]`-only, so the `lib.rs` façade items below do not apply to it. Their examples are kept because each is a
> worked illustration of the rule it sits under — read them as *the shape to copy*,
> not as a file to open. Where you need a live reference, use `containment`. This is a **mechanical checklist** — each item is
phrased so an agent (or a reviewer, or a CI gate) can verify it by reading the
file or running the command, without judgement. Run it before committing a new
crate or a change that adds public surface, and treat a MUST miss as a
house-style break to fix.

If you change or add a convention, update this file and a sibling so the two stay
in agreement.

Scope: crate structure and idioms only. It is **not** a design doc. The code and its tests own
behaviour, and [`docs/design/decisions.md`](design/decisions.md) owns why.

---

## MUST — universal (every existing crate does this, with the product-name exception below)

Verify per crate under its `<crate-path>/` (for example,
`crates/credentials` or `crates/containment`):

- [ ] **The package name is the product name plus the crate directory.**

      > **Adopted 2026-08-11.** Owned box packages use the `strands-box` product name.
      > The vendored `strands-shell` keeps its upstream name because its `UPSTREAM.md`
      > pins it, and `.agents/pocs/` is unchanged because it is outside the workspace.

      A crate at
      `crates/<name>/` is the package `strands-box-<name>`, and `crates/box` is the
      package `strands-box`. So `crates/credentials` is `strands-box-credentials`.
      → `grep '^name' <crate-path>/Cargo.toml` shows `strands-box-<name>`, or
        `strands-box` for `crates/box`.

      **The package name identifies the product.** The repository is `box`;
      the product is `strands-box`. The box is a binary target.

      **Vendored crates keep their upstream names.** `strands-shell` is a pinned copy
      with an `UPSTREAM.md`; renaming it would make a re-vendor a merge. It is outside
      this rule by construction, not by exception.
- [ ] **Explicit `[lib]` block splits package name from import name.** `Cargo.toml`
      has `[lib]` with `name = "<name>"` (the short, unprefixed import name) and
      `path = "src/lib.rs"`. So the package is `strands-box-credentials` but code does
      `use credentials::…`.
      → `<crate-path>/Cargo.toml` contains a `[lib]` section.
- [ ] **Standard package metadata.** `[package]` sets `version = "0.1.0"`,
      `edition = "2024"`, `publish = false`, and a `description` that names the
      crate's scope and cites its governing spec/KD path.
- [ ] **Typed, fail-closed error model via `thiserror`.** Every public error type
      derives `#[derive(Debug, ..., thiserror::Error)]` with `#[error("…")]` per
      variant and `#[from]`/`#[error(transparent)]` for wrapped source errors — no
      hand-rolled `impl Display`/`impl std::error::Error`/`impl From` for an error
      type. `thiserror = "2"` is a dependency.
      → `grep -rn 'impl.*fmt::Display\|impl std::error::Error' <crate-path>/src`
        returns nothing for error types; `thiserror` is in `[dependencies]`.
- [ ] **Flat public façade at the crate root.** `src/lib.rs` re-exports the crate's
      public types with a `pub use <module>::{…};` block (feature-gated modules
      get a feature-gated `pub use`), so consumers import from the crate root, not
      through module paths. Tests and sibling crates should be able to write
      `use <name>::SomeType;`.
      → `src/lib.rs` contains `pub use` lines, not only `pub mod`.
- [ ] **Crate is a workspace member.** The crate's path is listed in the root
      `Cargo.toml` `[workspace] members` (added when it gains a real `Cargo.toml`,
      per AGENTS.md).
      → `grep '<crate-path>' Cargo.toml` (root) matches.

## MUST — public surface (the reference shape; two crates still diverge)

These are derived from `journal` and `containment`, which agree on all of them.
`egress-gateway` and `credentials` predate the rule and violate several — each
divergence is named inline so it reads as known debt, not as precedent. Apply
these to any new crate, and to an existing crate when you next touch its public
surface.

- [ ] **The façade is the whole surface — modules are `mod`, not `pub mod`.** A
      `pub use` block only *advertises* an API; it does not *bound* one. Declare
      every module `mod` so the re-export list is the complete reachable surface,
      and add `#![warn(missing_docs, unreachable_pub)]` so the compiler holds the
      line. **Every crate under `crates/` now does this** — as of
      2026-08-09 none declares a non-`test_support` `pub mod`, and the façades are
      `containment` 13 names, `credentials` 17, `policy` 20, `egress-gateway` 34.
      The rule is recorded with its history because the cost was concrete:
      `egress-gateway` once declared 7 `pub mod`, reaching 177 public items behind a
      42-name façade (4×), so `egress_gateway::MutationTarget` failed to resolve
      while `egress_gateway::boundary::MutationTarget` worked, and internal
      machinery (`intercept::mitm::http1`, `control::fold`) was public API nobody
      chose to publish. The one allowed `pub mod` is a `#[cfg(any(test, feature =
      "test-support"))] pub mod test_support;` — `containment` has exactly that and
      nothing else.
      *Private modules bound the surface but do not shrink it on their own:
      `credentials` had no `pub mod` and still reached 61 public methods of which
      **37 had no caller anywhere** (2026-08-07 audit). It is now **17 exported
      names**, all five phases landed. What catches the difference is
      `unreachable_pub` plus the "a public item needs a concrete external consumer"
      rule below — the lint fires the moment an item is left `pub` inside a private
      module, and demoting the last of them is what surfaced four dead methods and
      an unconstructible enum variant.*
      → `grep '^pub mod' <crate-path>/src/lib.rs` lists only a `test_support`
        module carrying a `#[cfg(…test-support…)]` attribute on the line above.
- [ ] **One composition entry point; root nouns match the owned lifecycle.**
      A mechanism crate names the thing the caller holds after the domain
      (`Journal`, `Containment`), reaches it through a single verb
      (`Journal::open`, `Containment::apply`), and passes **one** config value.
      `open` returns a live resource; `apply` mutates the caller irreversibly and
      returns nothing. Do not
      ship an `XBuilder` type or a `.build()` — put fluent consuming
      configuration on the config or root noun.
      → a mechanism crate root exports its domain noun and verb.
- [ ] **Extension traits are `pub(crate)` unless a third party must implement
      them.** A public trait is a permanent contract and an open extension set.
      `journal` keeps `ObjectStore`/`RefStore` `pub(crate)` so every provider is
      authored in-crate; `containment`'s backends are private the same way.
      Publish a trait only when an out-of-crate implementor is a named use case
      (`PolicyEngine` is the built engine-substitution axis).
      *`credentials::SecretSource` was cited here as the source axis until
      2026-08-07; it had **zero** out-of-crate implementors, so by this rule's own
      test it should never have been public. It is now `pub(crate)` behind
      `Backend::local()`, and a documented-but-unused axis is
      not a reason to publish a trait.*
      → each `pub trait` in the façade has a named external implementor.
- [ ] **Sealed profile for backend choice; no caller-constructed backends.** When
      a crate can be backed by more than one implementation, expose named
      profile constructors over a private enum — `journal::Config::local(..)` with
      `pub(crate) enum Profile`, not a `Box<dyn Backend>` the caller assembles.
      Adding a backend is then a new variant with no signature or caller change.
      `credentials` is **there** as of 2026-08-07: `auto_processor() -> Box<dyn
      CredentialProcessor>` is gone, replaced by `Backend::local()` over a
      `pub(crate) enum Profile`, so the Daemon and AgentCore
      rungs `ProcessorKind` named become new constructors. The `CredentialProcessor`
      trait that kept this only *partly* sealed is now deleted outright — the vault
      resolves through `Backend` directly, so there is no public trait an
      out-of-crate caller can use to assemble a backend the crate never reviewed.
      → backend selection is a named constructor, not a trait object parameter,
        **and** no public trait lets a caller supply one.
- [ ] **One owner per concept across sibling crates.** `egress-gateway` and
      `credentials` both exported an `Emitter` trait (an outright name collision);
      **resolved 2026-08-07** by making the vault's `pub(crate)` — the two are
      different concerns that shared a name (`EgressDecision` vs
      `CredentialAcquire`), and the proxy's is live, so deleting either would have
      removed working audit. `egress-gateway` also carried serde near-mirrors of four
      `credentials` shapes — `RouteConfig`/`CredentialRouteSpec`, `InjectModeConfig`/`InjectMode`,
      `AwsAuthConfig`, `OAuth2Config` — bridged by a `map_routes` function; **all four and
      the bridge are gone** as of 2026-08-09 (verified: zero occurrences in `crates/**/*.rs`
      beyond one doc comment recording the removal). (`RequestId` was a fifth shared name;
      **resolved 2026-08-07** by moving it to the gateway, which generates it — the vault
      discarded it unread.) The rule stands on the original problem: a reader at the
      call site cannot tell which crate a name came from. Own a concept in one
      crate and re-export it.
      → `rg 'pub (struct|enum|trait) <Name>' crates` returns one
        owner.
- [ ] **Domain vocabulary, and never `session`.** Name a type after what it is in
      this product, not after the mechanism implementing it or an abstract shape:
      `containment` does not call itself `SeatbeltSandbox`, so a boundary crate
      should not surface `Mitm*`. Reuse the operator's word where one exists.
      **`session` is banned in new public names** — it already means four things
      (the vault's tenant scope, the CLI's warm dev process, MCP's
      `mcp-session-id`, a handler `conversation_id`); use `workload` for the
      contained process. Avoid abbreviations (`Cx`) and a name that describes the
      collection rather than the concept (`ControlSet`, `CredentialStore` — which
      stores nothing).
      *`CredentialStore` was this rule's own long-standing counter-example and is
      **now resolved** (2026-08-09), along with the two redundant `Credential` prefixes
      beside it: the credentials crate ships `Vault` (in `src/vault.rs`, with
      `Opened::into_vault`), `RouteSpec`, and `Locator`. Kept as the worked example
      because of how the deviation was finally caught. All three were deferred on
      2026-08-07 to keep a ten-name sweep out of a commit carrying two fail-open fixes —
      a reasonable call — but the deferral left `Vault::open` taking a `VaultConfig`
      while the type was named `CredentialStore`, and it was **that mismatch a reader
      tripped over**, not this rule. Two lessons, and the second is the useful one: a
      half-applied rename advertises itself, so finish one; and a deferred rename needs a
      recorded owner and next step, or the record of the deferral reads as a decision
      rather than a queue. `strands-box-credentials` no longer stutters its own crate
      name in a type — a `Credential` prefix inside that crate said nothing a caller did
      not already know from the import.*
      → a new public name reads correctly at a call site with no doc open.

## SHOULD — common (most crates; diverge only with a recorded reason)

- [ ] **Dedicated `src/error.rs`.** Isolate the error taxonomy in `error.rs` and
      re-export it from `lib.rs` (containment, credentials, journal do —
      egress-gateway and handler inline theirs for a small surface). Prefer this once
      a crate has more than one or two error types.
- [ ] **Forward-compatible serde posture.** Wire/config structs use
      `#[serde(default)]` on additive fields and do **not** set
      `deny_unknown_fields`; growable enums carry a `#[serde(other)] Unknown`
      catch-all, while deliberately *frozen* enums omit it and treat an unknown
      value as an error. Match the crate's stated compatibility intent.
- [ ] **Tests live beside or under the crate.** Unit tests inline in
      `#[cfg(test)] mod tests`; integration/e2e tests in `tests/`. Name integration
      files by what they exercise (`e2e.rs`, `golden.rs`, `journal.rs`).
- [ ] **Dependencies are added only when used.** Do not declare a dependency
      before a consumer exists (see credentials' notes on deferred OAuth2/AWS
      deps); annotate a deliberately-deferred dep with a comment.

## OPTIONAL — single-crate patterns (adopt if it fits; not required)

- [ ] **`[lints.rust] unused_must_use = "deny"`** in `Cargo.toml` (containment
      does). Good for a crate whose ignored `Result` would silently fail open.
      (`#![warn(missing_docs, unreachable_pub)]` is **not** optional — it is part
      of the public-surface MUST above.)

---

## Gates (run before commit)

All must pass, and every one of them carries `--all-features`.

`<package-name>` is the product name plus the crate directory, per the naming item above — so
`strands-box-credentials` for `crates/credentials`, and `strands-box` for
`crates/box`. Read it from the crate
rather than guessing: `grep '^name' <crate-path>/Cargo.toml`. A wrong name answers
`package ID specification ... did not match any packages`.

```
cargo build   -p <package-name> --all-features
cargo test    -p <package-name> --all-features
cargo clippy  -p <package-name> --all-targets --all-features
cargo fmt     -p <package-name> --check
```

### Why `--all-features`, and not "default plus `--no-default-features`"

**A plain `cargo test` reports success while skipping the tests that matter.** `strands-box` declares
`test-support`, and `box_shell` and `box_credentials` each carry
`required-features = ["test-support"]`. Without the flag, cargo runs one integration suite instead of
three, says nothing about the two it dropped, and exits `0`. Those two are the suites asserting the
Shell boundary and the credential phantom.

**"Default features and `--no-default-features`" does not reach it.** `strands-box` declares no
`default` feature, so both spellings are the same empty set, and neither enables `test-support`. The
older wording therefore prescribed running the same configuration twice.

### Clippy: `-D warnings` is scoped, and it is unpassable per binary crate

**`-- -D warnings` is right for one owned crate**, where it is the compiler-enforced form of the
warning count the root `AGENTS.md` prescribes:

```
cargo clippy -p <owned-crate> --all-targets --all-features -- -D warnings
```

**It is unpassable for a crate that pulls in a vendored path dependency or a
platform-conditional backend.** Measured on 2026-08-20:
`cargo clippy -p strands-box --all-targets -- -D warnings` exits `101` with 58 errors, and none of
them is in `crates/box`. Forty-four come from `containment`'s `backend/macos` and
`backend/linux`, which are dead code on the other platform, and fourteen come from the vendored
`shell` and `dogwood-language`. A gate nobody can pass is a gate everybody skips.

So the honest guidance for such a crate is `--all-features` plus a count scoped to the crate's own
directory, which must print `0`:

```
cargo clippy -p <package-name> --all-targets --all-features 2>&1 \
  | grep -c -- '--> crates/<crate-directory>'
```

This is why `-D warnings` is not set workspace-wide. The vendored crates carry upstream lint
failures, so the check for them is an *unchanged* count, never zero.
