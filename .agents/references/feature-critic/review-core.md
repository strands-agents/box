# feature-critic: Core area

Paths: each crate under `crates/` outside `crates/cli/`, `test-integ/`, `test-native-filesystem/`,
`test-common/`, `test-workload/`, and `examples/`. The [CLI area](review-cli.md) covers
`crates/cli/`.

Read [`feature-critic.md`](../../agents/feature-critic.md) first. This file adds the checks for Box Core.

## What this area names

- **Contract, in precedence order.** The diff is the claim; the decisions, the spec, and the tests
  are the contract. Judge the claim against the contract, not against your own taste.
  0. **The `strands-box` interface freeze** (2026-08-10, while it holds): see the
     "`strands-box` is interface-frozen" section of `AGENTS.md`. An unapproved interface change or
     foundational-premise change in `crates/**` is a **BLOCKER**, and outranks everything below.
     Check this **first**, before requirements or design: a diff can satisfy every spec and still
     be unshippable because it moved a surface an external party is already built against.
  1. **Decisions:** the entries in `docs/design/decisions.md`, read as the shared Decision
     entries check says.
  2. **The local spec, when the requester names one:** a `.spec.md` and `.requirements.md` under
     `.agents/drafts/spec/`. Specs are never committed, so there is one only when the requester
     gives its path. A `SHALL` the code does not honour is a **BLOCKER**.
  3. **Tenets:** `docs/design/tenets.md`: best-security-**per-platform** (never lowest common
     denominator), extremely-easy-to-get-started, and the **zero-trust threat model** (the wrapped
     handler or child process is *untrusted*).
  4. **Repo conventions:** `AGENTS.md`/`CLAUDE.md` and `CONTRIBUTING.md`.

  New crates and specs are part of the feature.

  Note the workflow rule "nothing is decided just because it's written", but
  `docs/design/decisions.md` entries and an approved spec *are* decided; do not re-open them.
- **Approvals:** the `AGENTS.md` freeze table, a `docs/design/decisions.md` entry, or an in-diff
  record of the operator's call.
- **Anchors for a design finding:** the governing entry's chosen option in
  `docs/design/decisions.md`, a spec decision, a tenet, or an existing pattern (an analogous
  crate).
- **Decision log:** `docs/design/decisions.md`. **Decision skill:** `kd`.
  **Trigger table:** [What a change updates](../../../AGENTS.md#what-a-change-updates).
- **Place of a finding:** `file:line`. For correctness and security, point at the line. For design,
  also cite the `decisions.md` anchor, spec decision, tenet, or existing pattern it conflicts with.
- **Untrusted input:** input from the sandboxed workload or child process.
- **Also report:** a **SECURITY** issue, a stated **KD, spec, tenet, or convention** that the diff
  breaks, and **DESIGN FIT** (below). Naming alone is not a finding: if it does not change behavior,
  violate a documented decision, or break from an established pattern, drop it.

## Rules

- **Severity:** `BLOCKER` (wrong, insecure, missing requirement, breaks a gate) > `DESIGN`
  (violates a *cited* spec, tenet, or pattern, or goes against a `decisions.md` entry, which is a
  note that never blocks) > `NIT` (drop most).
- **Escape valves.** Do not invent problems to look thorough:
  - If the code matches the established pattern or the governing KD's chosen option, say so and
    move on.
  - If a deviation was **explicitly justified** in a spec's decision (which cites its
    `decisions.md` entry) or in a `decisions.md` entry's own rationale, it is **NOT** a finding.
    Do not re-litigate a settled decision.
  - **Neither escape valve applies to the interface freeze.** "It matches the established pattern"
    and "it's tidier this way" are not approvals for moving a frozen surface: the freeze is about
    who is downstream of the shape, not whether the shape is good. Only a decision record or an
    explicit operator call in the diff clears it.
- Do not reformat code and report it as a finding. Do not re-open decisions already justified in a
  KD or spec.

## Checks

- **Requirements coverage.** When the requester names a local spec, each EARS "WHEN … THE … SHALL
  …" criterion in its `*.requirements.md` is satisfied and ideally test-covered. Name any criterion
  with no code or test. A "SHALL" that the code does not enforce is a BLOCKER. With no spec, each
  behaviour that the diff claims, in its commit message or its docs, is pinned by a named test that
  exists.

0. **Interface freeze: run this check FIRST, and report it even when the answer is "no
   change".** While the freeze in `AGENTS.md` holds, any diff touching `crates/**` gets this pass
   before anything else. Two questions, both BLOCKER-tier:

   **(a) Did an interface move?** Walk the frozen surface. Do not reason from the diff summary;
   `grep` the actual definitions:
   - CLI verbs/flags: `command/cli.rs` `Cli`, `Command`: a verb added or removed, a flag renamed, a
     short form changed, an `Option<String>` given a clap `default_value` (that specific one
     silently kills the config file's `name` key), `trailing_var_arg` altered.
   - `box.toml`: `ConfigFile` in `record/config/mod.rs` and the section structs in
     `record/config/` (`EgressEntry` and its siblings): a key added, renamed, retyped, or made
     required. **A new key is a breaking change here**, because they carry `deny_unknown_fields`;
     likewise a removed key turns an existing operator file into a hard parse error.
   - The four box inputs (policy, credentials, name, workload). A fifth input, or a key naming a
     host path, a working directory, an env overlay, a proxy port, or a mechanism value, is a
     BLOCKER against the box contract in `crates/box/AGENTS.md`.
   - On-disk records: `Record`/`RECORD_VERSION`, `BoxLive`/`LIVE_VERSION`: a field added,
     removed, or retyped **without** a version bump is the worst case, since an old artifact then
     parses as if it were new. Confirm the bump; if the shape changed and the const did not, quote
     both lines.
   - Broker wire protocol: `run/broker/protocol.rs` `PROTOCOL_VERSION`: frame layout, message
     kinds, the `Open`→`Call`→`InputEof` sequence. Same bump rule. Note that the alias image is
     materialized by `configure`, so a protocol change that does not say "re-run `configure`"
     ships a stale-alias failure.
   - Alias names and derivation: `SHELL_ALIAS_NAMES`, `PYTHON_ALIAS_NAMES`, `public/bin/`,
     `public/run/*.sock`, and the rule that an alias derives its socket from its own path. A
     harness resolves these off `PATH` by name.
   - Policy vocabulary: action names (every `action` in
     `crates/policy/schema/actions.cedarschema`), the
     attributes a rule may read, what `when temporal { … }` observes. An operator's policy file is
     their source code; a renamed action silently stops matching.
   - Mechanism-crate façades: the `pub use` sets in `containment`, `credentials`, `policy`,
     `egress-gateway` `lib.rs`. An export removed or renamed is an interface change even if `box`
     is the only current caller.
   - `strands-box` library: the `pub` items in `crates/box/src/lib.rs`. Not frozen, but an
     addition without a named maintainer approval is UNAPPROVED.
   - The composed workload environment and `reserved_workload_environment`.
   - Operator-facing description: whatever onboarding text, README, or runbook an operator is
     handed. If the code change makes it wrong, that is an interface change *and* a doc BLOCKER,
     whatever files the diff touched.

   **(b) Did a foundational premise move?** These are what an external security review is written
   against, so weakening one invalidates that review: one `Policy` per box and the authored policy
   as sole authorizer; interpreters outside the Agent's Seatbelt domain with the SBPL minimums
   unchanged; deny-only floors beneath policy and never beside it (SSRF floor, Shell mount scope, a
   capability that returns edits or a refusal and never an allow); the workload untrusted and its
   home workload-writable (every resolver check that assumes a planted symlink, hardlink, or
   launcher registry); validate-once-then-act-on-the-approved-identity (`confine` returning a
   canonical path, never validating one spelling and reopening another); environment composed not
   inherited with box-owned values last; absent policy is default-deny; a credential binding is not
   an authorization; the daemon's memory hardened as the only plaintext-secret holder, reached by
   mediation rather than a process boundary.

   **Test deletion is the tell, and check for it explicitly.** A deleted, renamed, or newly
   `#[ignore]`d test in `tests/box_*.rs`, `containment`'s conformance suite,
   `shell/tests/kernel_effect_interception.rs`, or any test named in a crate's `AGENTS.md` ("must
   not be deleted") is a BLOCKER unless the diff says why the property it pinned no longer exists.

   **Check only the diff from the fork point.** A diff against `main` itself on a long-lived branch
   returns hundreds of hits, almost all of them tests that moved between files, and a reviewer who
   skims that output learns nothing. For each removed `fn` name, confirm whether it **reappears**
   elsewhere in the tree:

   ```sh
   git diff "$(git merge-base <base> HEAD)" -- '*tests*' | grep -oE '^-\s*(async )?fn [a-z0-9_]+' | awk '{print $NF}' \
     | while read -r t; do grep -rql "fn $t" crates/ || echo "GONE: $t"; done
   ```

   A name that still exists somewhere was moved or renamed: check that the *assertion* survived,
   then move on. A `GONE:` name is the finding. Also grep the diff for newly added `#[ignore]`.
   Named examples that must survive: `the_shell_cannot_read_the_daemons_resolved_secrets`,
   `lua_popen_is_judged_by_policy`, `a_dangling_symlink_cannot_be_written_through`,
   `an_intra_home_symlink_cannot_launder_a_scoped_read`,
   `command_substitution_is_admitted_as_its_own_event`.

   **How to judge it.** The freeze is a *scrutiny* gate, not a prohibition: a genuine security fix
   may require an interface change. So the finding is not "this changed" but **"this changed and
   the diff does not show it was approved and deliberate."** Approved and deliberate means: a
   `docs/design/decisions.md` entry that decides it, or an explicit in-diff record of the
   operator's call, plus the version bump, the user-doc update, and the migration consequence
   stated. **Incidental** changes get no benefit of the doubt: a rename during a refactor, a key
   added "for convenience", a shape changed because a test was easier to write that way, a façade
   export dropped as cleanup. Those are BLOCKERs on their own, with no security argument to weigh.

   Report this pass in a dedicated `FREEZE` block (format below) even when clean: say which
   surfaces you checked and that they are untouched. Silence here reads as "not checked", which is
   exactly the failure the freeze exists to prevent.
1. **Requirements coverage.** When the requester names a local spec, cross-check the diff against
   its `*.requirements.md`: is each EARS "WHEN … THE … SHALL …" criterion satisfied, and ideally
   test-covered? Name any criterion with no corresponding code or test. A "SHALL" that the code
   does not enforce is a BLOCKER.
2. **Scope.** In this multi-crate workspace, also flag: edits to crates *outside* the feature's
   crate(s); `Cargo.toml` `members` or dependency changes not required by the task; churn in
   unrelated docs; touching `.agents/pocs/` for a `crates/` task (or vice-versa).
3. **Design fit: does this belong as built, or is it a foreign body?** Judge against the repo's OWN
   decisions, anchoring every finding to one of: (a) the **governing KD's chosen option** (for
   example, "goes against `decisions.md#one-policy-engine-per-box`", a note under contract item 1);
   (b) a **spec** decision; (c) a **tenet**: did it take the best-per-platform path or settle for
   lowest-common-denominator? did it keep things easy-to-get-started?; (d) an **analogous existing
   crate**: find the nearest existing thing and compare; a new construct that reinvents an existing
   pattern is a finding.
4. **Security: zero-trust threat model (the child or handler is untrusted).** Recast the usual
   classes:
   - **Trust-boundary violations:** does anything trust input from the sandboxed workload or
     child? Untrusted input reaching a decode or dispatch path must degrade, never panic or desync.
   - **Sandbox escape or capability leak:** Seatbelt or Landlock profile too permissive; egress
     that bypasses the proxy; `NetworkMode` not restricted where the design requires it; an fd or
     handle that leaks a policy-exempt channel to a grandchild (CLOEXEC).
   - **Secret handling:** does the agent or handler ever *hold* a real secret (violates the
     mint/inject split: "the agent never sees the secret")? Do secrets reach the append-only
     events-log (must be **secret-free**)? Is `ctx`/`EnvCtx` still data-only (no secret, grant, or
     handle)?
   - **Classic supervisor risks:** command injection when spawning `-- <argv>`; path traversal
     (realpath before repo-root confinement); TOCTOU; privilege-drop ordering; `maxBuffer` or
     timeout on child I/O so a silent or flooding child cannot wedge or OOM the parent.

   Any secret-in-log, sandbox-permissiveness, or trust-boundary finding forces at least
   `fix-then-ship`: the zero-trust tenet outranks convenience.
5. **Rust correctness hygiene**, beyond the shared Rust correctness check:
   - An `unsafe` block without a `// SAFETY:` justification is near-BLOCKER in a security crate.
   - The `.unwrap()`/`.expect()`/`panic!` path should be a `Result`.
   - Panicking indexing (`v[i]`) where `.get()` is warranted; `as` truncation or overflow on
     lengths or ports; missing `#[must_use]` where dropping the value is a bug.
   - A `std::sync::Mutex` guard held across an `.await` (deadlock or blocking risk); blocking I/O
     in async.
6. **Feature-flag matrix integrity.** Features gate optional layers here. Verify the default-off
   build still enforces the baseline, and that no security-critical code is reachable *only* with a
   non-default feature. A feature-gated layer that fails to compile without defaults is a real
   defect (run the `--no-default-features` build below).
7. **Docs, bounded to what the diff falsifies.** The trigger table is in
   [`AGENTS.md`](../../../AGENTS.md#what-a-change-updates). Check 0(a) above already makes one doc
   finding BLOCKER-tier: operator-facing description that the change makes *wrong*. The shared
   Docs check is that same line, widened to the pages the trigger table names, and to nothing else.
   A wrong page states a verb, a flag, a `box.toml` key, a filesystem list, a policy action, a
   refusal or a warning an operator reads, a path, a record field, or a step.

   **Do NOT report:**
   - A page that merely *reads* as stale, thin, or out of date. Falsified or missing, or it is not
     a finding.
   - A `docs/design/decisions.md` entry that has aged. The log can lag the code, and the code is
     the authority where the two disagree. The shared Decision entries check governs an entry the
     diff goes against: one note, never a gate.
   - A **missing** decision entry. An entry enters only through `/kd`, and only after the user
     decides. A code change owes none.
   - A `file.rs:LINE` citation or a test name that moved. Docs already ban both, so a moved one is
     not this diff's debt.
   - A page for an in-flux flag, message, or error. The valve in the `AGENTS.md` Docs section says
     that is not doc debt. The freeze narrows the valve: a surface the freeze names is not in flux,
     so the valve does not cover it.

   Unbounded doc drift reporting is what made every code change carry pages of doc edits. The two
   bounds in the shared Docs check, not a ban, are what keep that from returning.
8. **Comment hygiene (code comments, not docs).** Beyond the shared Comments check:
   - A single bare provenance pointer ("graduated from `.agents/pocs/…`") is fine once as origin
     metadata. Explaining the code by contrast with a prior state the reader cannot see ("the POC
     used…", "unlike the POC") is history narration.
   - **Redundant WHAT:** a comment that restates what the next line self-evidently does, adding no
     why. Keep WHAT only when non-obvious (a magic number, an rmcp or tokio footgun, a SAFETY
     invariant).

   These are DESIGN-tier findings (they do not change behavior): report them, but never let them
   outrank a correctness or security issue.
9. **Keep comments and agent guidance focused.** Follow the root
   [placement rules](../../../AGENTS.md#design-and-implementation): short item and module docs,
   change rationale in the commit, durable reasoning in design docs, and current non-obvious traps
   in crate guidance. Flag comments that restate names or bury a signature in rationale. A short
   comment explaining a tricky line is useful. Do not require histories of resolved defects,
   measurement narratives, or API inventories in `AGENTS.md`.

## Gates

Scope to the touched crate with `-p <crate>` where possible. You **MUST** create mutation
worktrees and their Cargo targets under the scratch directory that the shared file names, and
remove that directory after the pins finish.

- `cargo build -p <crate> --all-features`
- `cargo test -p <crate> --all-features`
- `cargo clippy -p <crate> --all-targets --all-features`: owned warnings must be **zero**:
  `… 2>&1 | grep -c -- '--> crates/<crate-dir>'` must print `0`.
- `cargo fmt --check`
- `cargo build -p <crate> --no-default-features` *(critical: proves feature-gated layers
  isolate)*
- **`scripts/test-all.sh`: mandatory.** It reports a skip when no example supplies `run.sh`.
  Follow the Strands SDK tutorial for a live agent run. An example is a stronger promise than a
  test, because an operator runs it verbatim, and a key rename has broken one **three times** while
  every `cargo test` stayed green. A `⚠` line for a missing host dependency is that example's
  documented limitation; a `✗` is a BLOCKER.
- **The deterministic containment suite: mandatory for every review.** It lives in `test-integ/`
  and drives the real `strands-box` binary as a subprocess, so it catches containment and policy
  regressions that the in-repo `cargo test` does not. Run it against the box you just built:

  ```sh
  cargo build -p strands-box -p strands-box-containment --all-features
  PATH="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR first}/debug:$PATH" bash test-integ/run.sh > /tmp/det.log 2>&1
  echo "exit $?"; tail -n 30 /tmp/det.log; cat ~/det-results/verdict.json | head -c 2000
  ```

  Exit 0 means `GREEN` and exit 1 means `RED`. A `RED` case is a BLOCKER unless you show that the
  same case also fails on `main`. A `SKIP` in the quarantine list (`test-integ/src/quarantine.rs`)
  is expected. Any other `SKIP`, or a `coverage_gate: reduced` that the quarantine list does not
  explain, is a finding.
- If the change is workspace-wide: also `cargo test` / `cargo build` at the root (confirm
  `.agents/pocs/` stays excluded).

### Platforms: the host gates are blind to other platforms

A green macOS run proves nothing about `cfg(target_os = "linux")` code. Measured 2026-08-23: host
suite green, then the Dry Run Build failed with **39 errors** in Linux-only *test* code. Libraries
compiled; the `#[cfg(test)]` modules inside them never did.

- The command for the other platform is
  `cargo check -p <crate> --target x86_64-unknown-linux-gnu --all-features`. It is cheap and works
  on macOS, but covers the **library only**. `--all-targets` (the test modules, where those 39
  errors were) dies in `ring`'s build script for want of a C cross-compiler. **Never report this as
  full coverage.**
- The real cross-platform compiler is continuous integration, which builds and tests both
  platforms on every pull request. A local host cannot stand in for it.

If you cannot compile the other platform, the report reads
**"platform coverage: host only; `cfg(linux)` UNCOMPILED"**, and it is BLOCKER-tier risk. Silence
reads as coverage.

### Three reasons a gate is red, three different verdicts

- **A defect in the diff:** BLOCKER.
- **A documented missing host dependency** (`⚠` line): note and move on.
- **A gate that cannot pass on ANY host:** report a separate finding. If a test needs a binary,
  verify that a package declares it before prescribing a build.

## Output blocks

First, before `BLOCKERS`:

```
FREEZE   (always present for a crates/** diff, even when clean)
- surfaces checked: CLI | box.toml | four inputs | Record/BoxLive | wire protocol
  | alias names | policy vocabulary | crate façades | box library | workload env | operator-facing docs
- interface changes: none  (or: path/to/file.rs:12 : <surface> <what moved>; approved by <KD/spec> | UNAPPROVED)
- premise changes: none    (or: path/to/file.rs:34 : weakens <premise>; UNAPPROVED)
- security tests removed/ignored: none  (or: name each)
```

`PLATFORMS` lines:

```
- host: macOS : build/test/clippy/fmt green (numbers below)
- other targets: <cargo check --target … result> | NOT COMPILED
- dry-run build: <build URL + pass/fail> | not submitted, so cfg(linux) is UNVERIFIED
```

`GATES` lines:

```
- cargo test: <tail>            (say if any gate needed a signal to finish: that is not a pass)
- cargo clippy: <owned warning count>
- cargo build --no-default-features: <tail>
- cross-target check: <tail>
- scripts/test-all.sh: <verdict lines>
- containment suite (test-integ/run.sh): GREEN | RED <failing case ids> | not run: <reason>
```

## Verdict

Any UNAPPROVED interface or premise change, a removed security test, or an uncompiled platform
forces `rework`: it is not the author's call to absorb, and not yours either. Operator-facing
description that the change makes wrong is a BLOCKER under check 0(a). A secret-in-log,
sandbox-permissiveness, or trust-boundary finding forces at least `fix-then-ship`.
