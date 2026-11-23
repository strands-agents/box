---
name: feature
description: Build one box feature or behavior change end to end, with its docs in the same change. Plan locally, build test-first, update the user docs, decisions, and design pages as you go, verify, and run the feature-critic review. Use when asked to add, change, or remove a command, flag, profile behavior, or anything an operator sees, such as "add box X", "make box run do Y", "implement ...", or "build ...".
---

# Feature

Build one change to `box`, and leave the docs true when you stop. A change is not done until its
docs match it, in the same commit. [`crates/cli/AGENTS.md`](../../../crates/cli/AGENTS.md#docs) holds the rules this
skill follows.

## Inputs

- **The feature**: what changes for the operator. Required.
- **Constraints**: anything the user said about scope, names, or behavior.

A change that fits in one sentence and one file skips the plan file. It still does steps 3 to 6.

## Process

### 1. Read the context

Read these before you edit anything:

1. `crates/cli/AGENTS.md`.
2. The headings of [`docs/design/cli/decisions.md`](../../../docs/design/cli/decisions.md), then each
   entry in the area you touch.
3. The design page for the area in `docs/design/cli/`, if one exists.
4. The `docs/cli/` pages that describe the behavior you change.
5. The source you will change, in full. Send wider searches to a subagent.

### 2. Plan

Write the plan to `.agents/plans/<YYYY-MM-DD>-<slug>.md`. That directory is git-ignored. Never
commit a plan and never link one from a committed file.

The plan has these sections:

- **What changes.** Two or three sentences in the operator's words: what they type and
  what they see. This is the intent, and the PR description reuses it.
- **Requirements.** A numbered list. Each item is a behavior that a test can check.
- **Layer.** The smallest layer that holds the change. Try the layers in this order: a pack or
  a starter (an input, a `when` gate, a starter `ask` or question), then the profile language (a
  new key, such as a new input declaration key), then the CLI. An operator's choice is a pack input that a
  starter asks for, stored in `[options]`. `box run` asks nothing once a profile exists
  ([decisions](../../../docs/design/cli/decisions.md#box-run-takes-no-option-values)). A plan that
  uses a larger layer states why each smaller layer does not work, with evidence: what you tried,
  or the rule that refuses it. These are examples of signs of a larger layer: a new or changed
  command, flag, run-time prompt, or `BOX_*` variable that `box` reads; a new parameter that
  resolve, compile, and run all pass on; a change to the order of the run steps; and a rewrite
  that changes a `decisions.md` entry's answer (its title claim or `Rejected.`). The list is not
  complete: any other change at the CLI layer that adds or changes a choice the operator makes
  needs a Layer reason. A fix or a refactor that adds no operator choice needs none. The
  `feature-critic` agent checks the reason.
- **Decisions.** Each choice the work makes that someone could later question or undo. For each:
  the choice, the main alternative, and who decides. A choice that the operator would notice goes to
  the user. **Stop and ask before you build it.** Record
  every choice here, not in `decisions.md`. Step 4 sorts them.
- **Docs.** Each fact this change adds or changes, and the page that owns it
  ([Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives)). Then each other page this
  change makes wrong, from the trigger table in `crates/cli/AGENTS.md`. Name the page and the section. When
  another page repeats the fact, plan to delete the copy and link the owner.
- **Open questions.** If one changes the design, stop and ask.

### 3. Build, test first

For each requirement: write the test, run it and see it fail, write the code, and run it and see it
pass. Add the test for the refusal or the failure path too. Never edit a test to hide a defect in
the code.

### 4. Update the docs as you go

Update each doc when you write the code it describes, not at the end.

- **An operator sees it** (a command, a flag, a prompt, an error, a path, a variable): update the
  page that owns it with the [`user-docs`](../user-docs/SKILL.md) skill. When only one shipped pack
  has it, update that pack's `README.md` instead
  ([Pack READMEs](../../../crates/cli/AGENTS.md#pack-readmes)). Every command and flag appears in
  `docs/cli/cli.md`. A new flag adds one row to its command's table, and an example only if the
  flag needs one. A how-to page shows it only where its task needs it, and links there.
- **A profile key or table changed**: add or change its one row in its table in
  `docs/cli/profiles-reference.md`, or in `docs/cli/packs-reference.md` for a key that only a
  pack writes, and update the shipped guide
  `resources/editing-box-profile.md` where it repeats it.
- **Implementation detail** goes to the design page, or nowhere. It does not go on a user page
  ([Page types](../../references/writing.md#page-types)). A new concept that an operator needs to
  use `box` goes on the part's topic page, such as `docs/cli/profiles.md`.
- **A choice settled**: apply the test in [`decision`](../decision/SKILL.md#what-earns-an-entry).
  A choice that passes, and that the user decided, gets an entry, written with that skill. Every
  other choice is a sentence in the pull request. Never record your own choice for review.
- **An entry the change goes against**: fit the code to the entry, or rewrite the entry with the
  `decision` skill. A rewrite needs the user's approval. A change that alters what an entry says
  fixes that entry in the same change.
- **How a part works changed** (the steps of a run, the files it writes, what reaches Box Core):
  update the design page for that area.
- **A build, test, or manual-test step changed**: update the guide in `docs/dev/`.

When the plan's Docs list is wrong, fix the list, then the docs.

### 5. Verify

Run the gates and paste their output. Do not summarize them.

```sh
just check
```

For an interactive change, follow `docs/dev/interactive-testing.md`. To check a command that a
user page shows, run it with `HOME` set to a temporary directory, so it does not touch the real
`~/.strands/box`.

### 6. Review

Run the [`feature-critic`](../../agents/feature-critic.md) and
[`test-critic`](../../agents/test-critic.md) agents at the same time, each in a fresh context. Give
each the plan path and the base. `test-critic` proves that each new test fails without its change.
When the diff adds or rewrites an entry in `docs/design/cli/decisions.md`, also run the
[`decision-critic`](../../agents/decision-critic.md) agent at the same time, on each of those
anchors. For a rewritten entry, give it the text before the rewrite, from
`git show $(git merge-base <base> HEAD):docs/design/cli/decisions.md`. Fix each blocker, each docs finding, each test that
`test-critic` reports as `pins missing`, and each `decision-critic` blocker, then run the gates
again. Push back on a finding only with evidence.

### 7. Report

Report in chat:

1. **What changes**, from the plan.
2. **Requirements**, each with the test that checks it.
3. **Decisions**: each entry you wrote or rewrote, by anchor, with where the user approved it,
   and each choice that the pull request states in a sentence.
4. **Docs changed**: each page.
5. **Verification**: the gate output.
6. **Review**: each critic's verdict and how you resolved each finding. For a `test-critic`
   verdict of `pins unproven`, name each test that it did not prove, and the host where it can run.

## Commit and pull request

Commit only when the user asks. The pull request title is a conventional commit with a lowercase
subject, such as `feat(cli): let operators write their own policy starters`
([`crates/cli/AGENTS.md`](../../../crates/cli/AGENTS.md#pull-request-title)). The pull request body follows
[the template](../../../.github/pull_request_template.md):

```markdown
## Description
## Related Issues
## Type of Change
## Testing
## Checklist
```

Write the body as plain prose a teammate would write. Lead with the problem and why the change is
right, then say how it works in a few sentences. Do not use stacked bold labels or a file list.
Name each decision entry the change adds or rewrites by anchor, in a sentence. When `Cargo.lock`
changes, say which versions moved and why.

After you open a pull request, do not amend, rebase, or force-push. To catch up with `main` or fix
a conflict, merge `origin/main` into the branch and push. The squash merge drops those merge
commits.

## What this skill does not do

- Commit, push, or open a pull request without the user's request.
- Commit a plan, a draft, or a research note.
- Decide a contested choice for the user.
