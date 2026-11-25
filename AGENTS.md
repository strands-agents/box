# AGENTS.md

Edit this file only when the user asks. `CLAUDE.md` files are symlinks; edit their `AGENTS.md` sources.
Keep this file and crate guidance to current constraints, approval boundaries, and costly,
non-obvious traps. Prefer enforcement in code and tests; retain prose when it adds constraints or
context they do not convey. Say what to do and what breaks. State each rule once and link to it.

When editing guidance, fix or remove stale rules. Put durable design rationale and detailed
measurements in design docs, and change rationale in commits and PRs. Leave obsolete history in
Git; keep code inventories and version counts out of guidance.

## Two products

- **Box Core**: `crates/` outside `crates/cli/`, `examples/`, and `test-*` outside `test-corpus/`.
  Its docs are `docs/user/` and `docs/design/` outside `cli/`. Core maintainers review it.
- **The `box` CLI**: `crates/cli/`, `resources/`, and `test-corpus/`; its docs are `docs/cli/` and
  `docs/design/cli/`. Follow [CLI guidance](crates/cli/AGENTS.md) for these paths.
- Workspace, release, publication, and `docs/dev/` files are shared. A Core contract addition needed
  by the CLI lands first in a separate Core PR. CLI syntax need not mirror `box.toml`.

To run an agent, use `setting-up-a-box` or [Get started](docs/cli/getting-started.md).
For Box Core directly, use [Run an agent with box.toml](docs/user/getting-started.md).

## `strands-box` is interface-frozen

Get explicit user approval **before writing code** that changes an external interface or a
foundational safety premise. Additions, renames, and narrowings count, including during refactors.
Name the affected surface and what breaks. Fixes within the existing contract need no approval.
Existing code or stale prose does not approve a contract change.

Frozen surfaces include verbs and flags; `box.toml`; the four inputs; stored records; broker
protocol; aliases and socket derivation; policy actions, attributes, and temporal observations;
mechanism crates' public facades; and the composed environment, including
`reserved_workload_environment`. Read [the box contract](crates/box/AGENTS.md#the-box-contract)
before changing one. Bump the affected record or protocol version when its shape changes.

The library API in `crates/box/src/lib.rs` is the exception: additions need a maintainer's approval
on the PR. `Cargo.lock` changes also need a maintainer's approval before merge; state which versions
moved and why. Keep version requirements intact.

The site manifest is separately frozen. Before changing publication identities, routes, schema, or
retirements, read [its contract](docs/dev/site-manifest.md).

## Foundational premises

- Policy is the only authorizer; absent policy denies. Credential bindings grant no authority,
  and capabilities return edits or refusals, never allows. Deny-only floors stay beneath policy.
- Compose the workload environment; never inherit it. Harden the trusted process, which holds
  only its own box's plaintext secrets.
- One `run` owns one box directory and one policy engine. Shell, Python, and egress share its
  history. One process runs at most one box, and Box has no daemon.
- Shell and Monty run in the trusted process. Each request gets fresh interpreter state.
  Workload-named programs, including declared stdio MCP servers, run only inside their sandboxes.
  [Log-only mode](docs/design/decisions.md#log-only-mode-turns-only-a-recorded-policy-denial-into-an-allow)
  changes recorded policy denials, never containment or other refusals.
- Validate an identity, then act on that identity. Keep Box's own state outside workload and tool
  reach. Preserve the tests enforcing these premises; never delete or ignore one to pass a suite.

## Before changing a boundary

Read the guidance for each crate you change or integrate. In particular:

| Change | Read first |
| --- | --- |
| Filesystem reach, tool or MCP startup | [Box contract](crates/box/AGENTS.md#the-box-contract) and [tool sandboxes](docs/design/decisions.md#sandboxes-for-tools-and-mcp-servers) |
| OS enforcement, exec or fork grants | [Containment guidance](crates/containment/AGENTS.md) and [minimum process authority](crates/containment/README.md#the-minimum-process-authority-the-profile-grants) |
| Policy events or history | [Policy guidance](crates/policy/AGENTS.md) |
| Telemetry or teardown | [Telemetry guidance](crates/telemetry/AGENTS.md); its receiver is workload-reachable |
| New crate or approved public surface | [Conventions](docs/conventions.md); containment is the reference crate |

## Design and implementation

Use `/kd` for an architecture choice, and let the user decide before `/spec` and implementation.
Only record decisions the user has made. Use `kd` for Core entries and `decision` for CLI entries;
keep stable anchors when rewriting. A missing decision entry alone is not a review finding.
Keep research, prototypes, and drafts in the ignored `.agents/explorations/`, `.agents/pocs/`, and
`.agents/drafts/` directories. Leave human snapshots in `team/designs/` alone.

Use `workload`, not `session`, in new public names; follow [terminology](docs/design/terminology.md).
Item doc comments are one sentence; module docs are one sentence plus a table when needed.
Cite symbols or tests, not line numbers or local drafts.

### TCP sockets

Set `TCP_NODELAY` best-effort on every TCP socket Box writes to, including accepted and received
sockets, and test `nodelay()`. Small writes otherwise wait for acknowledgements; the
[gateway measurements](crates/egress-gateway/AGENTS.md#tcp-latency) show the cost.
Libraries that already set it and connections carrying no data need no extra call. Document any
other exception at the socket and in its crate guidance.

### Upstream Shell

Fix Shell bugs upstream, then move the pin to the fix; Box carries no local Shell patch or relaxed
version. Box composition belongs in `crates/box/`. Make invalid composition impossible or refuse it
at startup, and prove the guard by introducing the defect and observing the refusal.

## Verify before commit

For each changed Rust package, run `cargo build`, `cargo test`, and `cargo clippy --all-targets`
with `-p <package> --all-features`, plus `cargo fmt -p <package> --check`. Owned warnings must be zero.
`--all-features` matters: otherwise `box_shell` and `box_credentials` silently do not run.
Report `skipping:` messages. Follow [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, including
`cargo fetch --locked` and rebuilding helper binaries before integration tests.

For publishable user pages, site manifests, or the manifest validator and its CI wiring, run
`cargo test -p strands-box --test site_manifest --locked --all-features`.

For code changes, run [feature-critic](.agents/agents/feature-critic.md) once immediately before
commit. Run [test-critic](.agents/agents/test-critic.md) alongside it when adding or rewriting tests.
Fix blockers, including `pins missing`; give a reason for any other finding left open.
CLI paths use the critics' CLI area files; Core paths use their Core area files.

## Docs

### What a change updates

Docs ship with their code. Before writing or reviewing docs or committing code, read the
[update rules](.agents/references/doc-updates.md) and apply every matching row. Use `docs-sync` to
check the diff, `docs-writer` to draft Core docs, and `docs-reviewer` to review them.
CLI docs follow [their own ownership rules](crates/cli/AGENTS.md#docs).
Core user and design pages follow the [voice guide](.agents/references/voice-guide.md).
Quote Mermaid edge labels and compile each block with `mmdc`.

## Commit and pull request

Open PRs against `main`, use a conventional-commit title, follow the
[template](.github/pull_request_template.md), and return the URL. State relied-on decisions,
checks CI cannot perform, and deferred work with reasons. After opening a PR, add commits:
never amend, rebase, squash, or force-push. Merge `origin/main` to resolve conflicts.
The merge squashes the branch and uses the PR title as its subject.
