# docs-sync: CLI area

Paths: `crates/cli/`, `resources/`, `test-corpus/`, `docs/cli/`, `docs/design/cli/`, and the CLI's
scripts and their tests in `scripts/`: `scripts/try-build.sh`, each `scripts/*-cli.py`,
`scripts/test_try_build.py`, and `scripts/test_ci_workflow.py`. The
[Core area](surfaces-core.md) covers the rest of `crates/`.

Read [`SKILL.md`](SKILL.md) first. This file adds the surfaces and checks for `box`.

## What this area names

- **Trigger table:** [`crates/cli/AGENTS.md`](../../../crates/cli/AGENTS.md#docs), which says which change needs which
  doc. **Owner of each fact:** [Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives).
- **Decision log:** `docs/design/cli/decisions.md`. **Decision skill:**
  [`decision`](../decision/SKILL.md).
- **Fix skills:** [`user-docs`](../user-docs/SKILL.md) for `docs/cli/`, and the
  [`decision`](../decision/SKILL.md) skill for `decisions.md`.

## Step 1: surfaces

Each change an operator can see:

- A command, a flag, a default, or help text in `crates/cli/app/src/main.rs`.
- An error message or a prompt.
- A path or a file that `box` reads or writes, or a `BOX_*` variable.
- A pack in `resources/packs/`.
- A refusal that is new, removed, or changed.

## Step 3: user docs

The owner of a fact is its page in [Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives),
or the pack's `README.md` when the change holds only for one shipped pack
([Pack READMEs](../../../crates/cli/AGENTS.md#pack-readmes)). A page is also **wrong** when it says something
other than the code. This area adds three statuses:

- **copy**: a page other than the owner restates a list, a default, accepted values, or a
  precedence order. The fix for a copy is to delete it and link the owner, not to update it.
- **misplaced**: a `docs/cli/` page holds a fact that only one pack has.
- **shape**: the diff adds to a user page what its type's shape leaves out
  ([Page types](../../references/writing.md#page-types)).

Then compare `docs/cli/cli.md` with `./target/debug/box <command> --help` for each command: each
flag is in its command's section, and the page names no flag that does not exist. Run
`just prose`.

## Step 5: decisions

When the diff adds to a list of keys, tables, or flags that an entry copies, report the entry as a
**copy**. For `all`, Step 5 reports only entries that contradict each other.

## Step 6: other pages

- Report a `docs/dev/` guide whose commands no longer work.
- For each changed line in a `resources/packs/*/pack.toml`, report a comment beside it that the
  diff makes false, and a reason only that pack has that is missing or that a design page holds
  instead ([Pack comments](../../../crates/cli/AGENTS.md#pack-comments)).
