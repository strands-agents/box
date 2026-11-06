---
name: docs-sync
description: Find each Box doc that a change makes wrong or incomplete, and report the page to update in the same commit. Read-only unless asked to fix. Use before a commit or a pull request, after a change that shipped without its docs, or when asked "what docs does this need", "are the docs current", "check the docs against the code", or "which page does this surface belong on".
---

# Docs sync

Compare a change, or the whole repository, with the committed prose, and report each page the code
makes wrong or leaves incomplete. The trigger table in
[`AGENTS.md`](../../../AGENTS.md#what-a-change-updates) says which surface maps to which page, and
this skill applies it.

**How this differs from `docs-audit`.** The audit assesses one page end to end: accuracy, placement,
and voice. This skill starts from the code instead. It walks the surfaces a diff touches and finds
the pages that no longer agree. Use `docs-sync` to decide *which pages a change owes*. Use
`docs-audit` to decide *what is wrong with one page*.

## Inputs

- **Scope**: a diff (the default is `git diff main...HEAD`, plus `git diff`, `git diff --staged`,
  and new files in `git status --short`), or `all` for the whole repository.
- **Fix**: report only (the default), or fix each gap.

## Process

### Step 1: List the surfaces the change touches

Read the diff and list each thing an operator or a consumer can observe. Group them by the trigger
table's rows:

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

For `all`, list the current surface from the code instead of from a diff.

Classify each one as **ships** or **in flux**. A surface the freeze in `AGENTS.md` names always
ships.

### Step 2: Walk the trigger table

For each surface, find its row and the page the row names. Record the row you used, because the
report must show which rows you walked.

A surface with no row and no page is in flux. The pre-1.0 valve in the `AGENTS.md` Docs section
covers it, so it is not doc debt. Say so and move on.

### Step 3: Check the user guide

For each surface that ships, open the page the row names and give it one status:

- **wrong**: the page states something the diff falsifies. Quote the sentence and name the symbol it
  disagrees with.
- **missing**: no page states the surface.
- **ok**: the page and the code agree.

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

### Step 4: Check the design guide

Report a `docs/design/` page whose parts, order, process boundary, or table the diff makes false.
`docs/design/README.md` maps each page to the question it answers, so use it to find the owner.

Hold each claim to [`claim-verification.md`](../../references/claim-verification.md): a test backs
each claim about behaviour, and the page names no test.

### Step 5: Check the crate README and the crate AGENTS.md

A crate whose `pub use` facade or purpose moved owns a `README.md` that a consumer reads. Report the
section the change makes wrong. Report a crate `AGENTS.md` whose frozen surface, premise, or gate
the diff moved, and the root `AGENTS.md` when the change moves a gate or a frozen surface it lists.

### Step 6: Check `docs/design/decisions.md` for regression only

1. Report an entry the diff **regresses**, and name the anchor. The diff rewrites that entry, or it
   does not ship.
2. Report two entries that answer the same question in two ways.
3. Never report a missing entry, and never report an aged one. An entry enters only through `/kd`,
   and only after the user decides. A code change owes no entry, and the code is the authority where
   an entry and the code already disagree.

### Step 7: Report

```markdown
## Docs sync: <scope>

| Page | Section | Status | What is wrong | Fix |
|---|---|---|---|---|
| ... | ... | wrong / missing | ... | ... |

### Trigger-table rows walked

- <row> -> <page> -> <status>

### In flux, so not doc debt

- <surface> (no row, no page)

### Checks run

List each command you ran, with its result. Name the command you did not run and the surface it
bears on, so a reader can see it was a choice. "None, because the diff touched no policy action" is
a complete answer.
```

When there is nothing to fix, say so, and still list the rows you walked. Silence reads as "not
checked".

## Fixing

When asked to fix, use `docs-writer` for a page in `docs/user/` or `docs/design/`, and the
`voice-guide.md` layers for a crate `README.md`. Use `/kd` for `docs/design/decisions.md`, and only
when the user decides the question.

## Rules

- **Report only what the trigger table requires.** A longer page is not a better page.
- **Never change code to make a page true.** Report the mismatch, and name the symbol.
- **The code is the authority.** Where a page and the code disagree, the page is wrong.
- **Falsified or missing, or it is not a finding.** A page that reads as thin or old is work for
  `docs-planner`, not for this skill.

## What this skill does not do

- Review a draft's voice. That is `docs-reviewer`.
- Plan the docs backlog. That is `docs-planner`.
- Commit, or open a pull request.
