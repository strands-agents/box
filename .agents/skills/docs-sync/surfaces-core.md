# docs-sync: Core area

Paths: each crate under `crates/` outside `crates/cli/`, `test-integ/`, `test-native-filesystem/`,
`test-common/`, `test-workload/`, and `examples/`. The [CLI area](surfaces-cli.md) covers
`crates/cli/`.

Read [`SKILL.md`](SKILL.md) first. This file adds the surfaces and checks for Box Core.

**How this differs from `docs-audit`.** The audit assesses one page end to end: accuracy,
placement, and voice. This skill starts from the code instead. It walks the surfaces a diff touches
and finds the pages that no longer agree. Use `docs-sync` to decide *which pages a change owes*. Use
`docs-audit` to decide *what is wrong with one page*.

## What this area names

- **Trigger table:** [`AGENTS.md`](../../../AGENTS.md#what-a-change-updates), which points to
  [the documentation update rules](../../references/doc-updates.md). The same table says which page
  owns each surface.
- **Decision log:** `docs/design/decisions.md`. **Decision skill:** [`kd`](../kd/SKILL.md). An
  entry enters only through `/kd`, and only after the user decides.
- **Fix skills:** `docs-writer` for a page in `docs/user/` or `docs/design/`, and the
  [`voice-guide.md`](../../references/voice-guide.md) layers for a crate `README.md`. Use `/kd` for
  `docs/design/decisions.md`.

## Step 1: surfaces

Group them by the trigger table's rows:

- A CLI verb, a flag, a short form, or a default in `crates/box/src/command/cli.rs`.
- A `box.toml` top-level key, or a field in `[agent]`, `[tool.<name>]`, `[egress.<name>]`,
  `[mcp.<name>]`, `[telemetry.<label>]`, or `[experimental-features]`.
- A filesystem list, or what a list grants.
- A policy action id, an attribute a rule reads, or what `when temporal` observes.
- A refusal, a denial, a warning, a startup disclosure line, or an exit status that an operator
  reads.
- A path the box owns: the box directory and its children, a socket, an alias name, or the records
  file.
- A record field, or `RECORD_VERSION`, `LIVE_VERSION`, and `PROTOCOL_VERSION`.
- An environment name the box reserves or composes.
- A crate's `pub use` facade.
- A build, test, or debug command, or a gate.

Classify each one as **ships** or **in flux**. A surface the freeze in `AGENTS.md` names always
ships.

## Step 2: in flux

A surface with no row and no page is in flux. The pre-1.0 valve in the `AGENTS.md` Docs section
covers it, so it is not doc debt. Say so and move on. Step 3 checks only the surfaces that ship.

## Step 3: user guide

Run a command only for a surface Step 1 recorded. Most runs of this skill need none.

- **A CLI verb, a flag, or a `box.toml` key needs no command here.**
  `crates/box/tests/documented_commands.rs` and `documented_inputs.rs` already hold
  `crates/box/README.md` to the parser, and continuous integration runs both. A diff that moves one
  gets a failing test, which is a louder signal than this sweep.
- **A policy action or a field does need a command**, because no test pins the page to the schema:

  ```sh
  cargo run -p strands-box -- policy generate-schema
  ```

  Each action id and each field the schema emits is in `docs/user/policy/actions.md`, and the page
  names no action the schema omits. Check the count of actions that `docs/user/policy.md` and
  `docs/user/policy/actions.md` state against `ACTION_IDS`.

When you fix a page, run `.agents/skills/docs-reviewer/check-prose.sh <page>` on it.

## Step 4: design guide

The design pages are in `docs/design/`. `docs/design/README.md` maps each page to the question it
answers, so use it to find the owner.

Hold each claim to [`claim-verification.md`](../../references/claim-verification.md): a test backs
each claim about behaviour, and the page names no test.

## Step 6: the crate README and the crate AGENTS.md

A crate whose `pub use` facade or purpose moved owns a `README.md` that a consumer reads. Report the
section the change makes wrong. Report a crate `AGENTS.md` whose frozen surface, premise, or gate
the diff moved, and the root `AGENTS.md` when the change moves a gate or a frozen surface it lists.

## Step 7: report

Add this section after the rows walked:

```markdown
### In flux, so not doc debt

- <surface> (no row, no page)
```

"None, because the diff touched no policy action" is a complete answer under **Checks run**.

## Rules

- **Falsified or missing, or it is not a finding.** A page that reads as thin or old is work for
  `docs-planner`, not for this skill.

## What this skill does not do

- Review a draft's voice. That is `docs-reviewer`.
- Plan the docs backlog. That is `docs-planner`.
- Commit, or open a pull request.
