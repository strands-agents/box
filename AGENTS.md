# AGENTS.md

Instructions for changing Box. Edit this file only when the user explicitly asks.
`CLAUDE.md` is a symlink; edit its `AGENTS.md` source.

**To run Box**, use the `setting-up-a-box` skill or follow
[getting started](docs/user/getting-started.md).

## `strands-box` is interface-frozen

Get the user's explicit approval **before writing code** that changes either:

- **An interface:** anything an external party observes or depends on. Additions, renames, and
  narrowings count, including changes made during a refactor or to simplify a test.
- **A foundational premise:** anything that changes why the box is safe.

An agent cannot approve its own change. Fix defects within the current contract. If the contract
must change, name the affected surface or premise and what breaks when you ask for approval.
`feature-critic` treats an unapproved change in either class as a BLOCKER.

The frozen surfaces include the CLI verbs and flags; `box.toml` keys and filesystem lists; the four
inputs (policy, credentials, name, workload); stored records; the broker protocol; aliases and their
socket derivation; policy actions, attributes, and temporal observations; each mechanism crate's
`pub use` set; and the composed environment, including `reserved_workload_environment`.
Read [the box contract](crates/box/AGENTS.md#the-box-contract) before changing any of these.
After approval, bump `RECORD_VERSION`, `LIVE_VERSION`, or `PROTOCOL_VERSION` when its shape changes.
An approved interface change carries its reference page in the same commit; apply
[What a change updates](#what-a-change-updates).

## Foundational premises

Preserve these premises and the tests that enforce them. Do not delete or `#[ignore]` a security
test to make a suite pass.

- **Policy is the only authorizer.** Absent policy is default-deny. Deny-only floors stay beneath
  policy. The egress gateway has no independent authorization authority, and `CapabilityOutcome`
  has no `Allow` variant. A credential binding is not an authorization.
- **The workload is untrusted.** It writes only where a filesystem list grants a write.
  Validate once, then act on the identity you approved.
- **Compose the environment; never inherit it.** Harden the box's trusted process. It holds only
  its own box's plaintext secrets.
- **One `run` owns one box directory and one policy engine.** Shell, Python, and egress share that
  engine and its temporal history. Box is a binary with no library target or daemon. See
  [one trusted process](docs/design/decisions.md#one-trusted-process-per-box),
  [one directory owner](docs/design/decisions.md#one-run-owns-one-box-directory), and
  [one policy engine](docs/design/decisions.md#one-policy-engine-per-box).
- **Strands Shell and Monty run in the trusted process, outside the agent's sandbox.**
  Create one Shell and one Monty VM per request; no state crosses a call boundary.
  The `zsh`, `bash`, `sh`, `python3`, and `python` aliases reach one `run/box.sock`.
  Each alias derives the socket from its own path; `argv[0]` selects the interpreter before connection.
  See [request isolation](docs/design/decisions.md#no-state-crosses-a-call-boundary).
- **A workload-named program runs only inside a sandbox.** Never execute it directly from the
  trusted process. A policy permit decides whether it runs; the sandbox bounds what it can do.
  Every declared stdio MCP server also starts in its own sandbox, after `shell:spawn` permits it.
  Preserve `runtime_mcp_start.rs::absent_start_permit_refuses_the_server_and_it_never_runs`.

### Filesystem reach

`HOME` defaults to the operator's home unless `[agent] env.HOME` names another directory.
The box directory is not a home; no verb copies configuration into a private home.
Neither `HOME` nor `workspace` grants filesystem reach. `workspace` sets the initial working
directory, which remains unreadable until a filesystem list names it.

The agent's filesystem lists govern its sandbox alone. Each tool gets its reach from its own
`[tool.<name>]` table. An absent filesystem section grants no direct reach. These grants bypass
`fs:*` decisions, so disclose each grant on stderr at startup. `write` does not imply `read`;
on Linux, a writable bind also reads, and its disclosure must state that limit.
Keep the box's own state unreachable from both the agent and its tools.
Preserve `box_filesystem.rs::the_boxs_own_private_tree_is_unreachable_from_inside` and
`run_config.rs::a_tool_grant_cannot_expose_the_box_directory`.

**Before changing filesystem reach**, read the HOME, workspace, and filesystem rules and their
named tests in [the box contract](crates/box/AGENTS.md#the-box-contract).
**Before changing tool or MCP startup**, also read
[sandboxes for tools and MCP servers](docs/design/decisions.md#sandboxes-for-tools-and-mcp-servers)
and the [box's open findings](crates/box/AGENTS.md#open-findings--divergences-no-decision-covers).
`contain_egress = false` bypasses the gateway; preserve its disclosure as residual risk.

### macOS execution

Keep the agent's exec grants enumerated: one `process-exec` rule for its command, each `exec` entry,
and each interpreter or MCP alias in `bin/`. Pair each with `file-read-metadata`, never `file-read*`.
A file uses a literal; a directory uses a subpath.
Keep `process-fork` unscoped; a generic filter compiles and authorizes nothing.
Its fork-bomb risk remains a stated limit.
Do not grant the agent `process-exec*`, the host OS's shell, or an inherited `PATH` tree.

**Before changing exec or fork grants**, read
[minimum process authority](crates/containment/README.md#the-minimum-process-authority-the-profile-grants)
for metadata pairing and fork-filter limits.

The broader execution and metadata grants for a tool or MCP server apply only to its own sandbox.
Keep the agent's profile unchanged by those exceptions, including its write-xor-execute restrictions.
**Before changing a profile**, read [macOS measurements](crates/containment/AGENTS.md#macos-measured)
and the tool and MCP rules linked above. Preserve
`the_agent_profile_never_carries_broad_exec` and `a_leaf_carries_broad_exec_and_the_main_box_does_not`.

## Read before implementation

Read the `AGENTS.md` for each crate you change or integrate. Read the relevant code and tests before
choosing a solution. Code and tests own behaviour; design decisions own why. Existing code or stale
prose does not approve a change to the frozen contract.

| Task | Required context |
| --- | --- |
| Change sandbox grants or operating system enforcement | [Containment guidance](crates/containment/AGENTS.md) |
| Change policy integration, events, or temporal history | [Policy guidance](crates/policy/AGENTS.md); its code and tests own commit, recovery, policy-change, and time behaviour |
| Build on telemetry or change its lifecycle | [Telemetry guidance](crates/telemetry/AGENTS.md); the workload can reach its receiver |
| Add a crate or change a public surface after approval | [Conventions](docs/conventions.md); use `containment` as the reference implementation |

Keep `Cargo.lock` unchanged. Do not relax version requirements.

## Design and implementation

For an architecture choice, research first, use `/kd` to compare the options, and let the user
decide before `/spec` and implementation. A candidate is not a decision.
Store research in `.agents/explorations/{topic}.exp.md`, prototypes in `.agents/pocs/`, and local
decision and spec drafts in `.agents/drafts/`. Keep drafts, explorations, and prototypes out of commits.
Product code belongs in `crates/`.

Name types after their role in the product. Use `workload`, never `session`, in new public names.
Avoid abbreviations. Follow [terminology](docs/design/terminology.md) when naming or writing.

Comments state what an item is. An item `///` is one sentence; a module `//!` is one sentence plus
a table when needed. Omit a comment that repeats the name or explains Rust syntax.
Put change rationale in the commit message. Put measurements, past defects, rejected alternatives,
and implementation caveats in the crate's `AGENTS.md`. Cite a decision's stable anchor for its rationale.

### Vendored code

For a change under `crates/shell/`, read its `AGENTS.md` and `UPSTREAM.md`. Ask whether upstream
would call the issue a bug: a wrong result, lost error, hang, unsound check, or unreportable suspension.
Fix an upstream bug there and explain its ownership in the diff. Put Box composition in `crates/box/`.

Make an invalid state impossible by construction, or refuse it at startup. Prove the guard fires:
introduce the defect, observe the refusal, then restore the fix. Keep the vendored suite green and
its warning count unchanged. Record divergence in `UPSTREAM.md`.
A local build workaround, relaxed version, or bypass of Box configuration is divergence.

## Verify before commit

For each changed Rust package, run:

```sh
cargo build   -p <package> --all-features
cargo test    -p <package> --all-features
cargo clippy  -p <package> --all-targets --all-features
cargo fmt     -p <package> --check
```

`--all-features` is required: `box_shell` and `box_credentials` need `test-support`, so a plain
`cargo test` skips them. Report interpreter-dependent `skipping: ...` messages.
Owned clippy warnings must be zero; vendored warnings must not increase. Check warning locations
against `crates/<changed-crate>/`. Use `just --list` for workspace gates and
[README.md](README.md) for prerequisites.

**For code changes, run [feature-critic](.agents/agents/feature-critic.md) once, immediately before
commit**, after implementation is complete. It reviews code, runs the required gates, and checks
docs against [What a change updates](#what-a-change-updates).
Finish only when the gates pass and every finding is fixed or has a stated reason for leaving it.
[Decision-critic](.agents/agents/decision-critic.md) reviews a decision or spec; it is not a code gate.
A doc review reports only prose the diff makes wrong, or missing pages for surfaces the diff adds
and the update table covers. It does not require new decision entries or general doc cleanup.

## Commit and pull request

Open the pull request against `main` and paste its URL in chat. The merge squashes the branch;
the pull request title becomes the commit subject on `main`. Leave that squash to the merge.

Add a commit for each change. After opening a pull request, preserve reviewed history: no amend,
squash, or force-push. Rebase onto `main` only to resolve a conflict.

The first commit has a subject, then exactly these three sections in order:

- `## Problem` — what is wrong and what it costs, before describing a solution.
- `## Solution` — what changed and every interface that moved. Name a rejected alternative only
  when a reviewer needs the reason.
- `## Tests` — what ran and what it proved. Put a named test beside each behaviour claim.
  State what did not run and what remains broken.

Later commits need only a subject that names the feedback or defect addressed.
Follow [the pull request template](.github/PULL_REQUEST_TEMPLATE.md).
Lead with the problem and reasoning the diff cannot show. State each decision the change depends on,
checks continuous integration cannot perform, and deferred follow-ups with their reasons.
Do not repeat the file list.

## Docs

Docs ship with the code they describe, in the same commit. Use `docs-writer` to draft,
`docs-reviewer` to review a draft, `docs-audit` to check an existing page, and `docs-planner` to plan
a backlog. Keep human-authored snapshots in `team/designs/` outside agent writing, audits, and updates.

### What a change updates

**Before writing or reviewing docs, or committing a code change**, read
[the documentation update rules](.agents/references/doc-updates.md).
They own the prose locations, the complete surface-to-page table, and the limits for features still
in flux. Apply every matching row; use `docs-sync` to check the docs against the diff.
Committed examples must still work.

### Decisions and prose

**Before creating or updating a decision entry**, use [kd](.agents/skills/kd/SKILL.md) for its format
and rewrite rules. Record an entry in `docs/design/decisions.md` only after the user decides it.
A code change adds no obligation to create an entry.

Cite behaviour by symbol or test name, and decisions by stable relative links. Keep file line numbers,
local specs, requirement numbers, and draft `KD-N` identifiers out of code citations.
Committed docs must not link to local drafts or explorations.
For Mermaid, quote every edge label as `A -.->|"source kind"| B` and compile every block with `mmdc`.

Use ASD-STE100 Simplified Technical English for prose, including comments, commits, and reviews.
Pages in `docs/user/` and `docs/design/` instead follow
[the plain-English voice guide](.agents/references/voice-guide.md).
