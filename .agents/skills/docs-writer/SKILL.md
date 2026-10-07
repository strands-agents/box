---
name: docs-writer
description: Draft or rewrite a Box documentation page in docs/user/ (tutorial, how-to, or reference for an operator) or docs/design/ (explanation for a security evaluator or a contributor), or a crate README.md that serves a consumer. Use when asked to write a doc, draft a page, rewrite a page that failed audit, document a feature or a component, or write an architecture or security page. Not for docs/design/decisions.md (use kd), local specs (use spec), or research notes (use explore).
---

# Documentation writer

Draft or rewrite one Box documentation page in the voice of
[`voice-guide.md`](../../references/voice-guide.md).

## Inputs

- **Topic**: what the page covers. Required.
- **Content type**: tutorial, how-to, reference, or explanation. Classify it in Step 1 if the user
  doesn't give it.
- **Target file**: the path in `docs/user/` or `docs/design/`, if known.
- **Existing content**: the page to rewrite.

## Process

### Step 1: Place and classify

1. Read [`voice-guide.md`](../../references/voice-guide.md) and
   [`docs/design/terminology.md`](../../../docs/design/terminology.md).
2. Ask the placement question: does the reader need this page to use Box, or to trust or change
   Box? That picks `docs/user/` or `docs/design/`.
3. Classify the content type. A page in `docs/design/` is an explanation.
4. Stop if the page belongs to another owner: `decisions.md` (the `kd` skill), `terminology.md`, or
   `tenets.md` (only when the user asks).
5. Read the README of the guide, and each page the new page links to or replaces.

### Step 2: Gather the facts

Read the code on current `main` before you write about it.

- For each claim you expect to make, find the code that implements it and the test that pins it.
- For a design page, find each relevant entry in `docs/design/decisions.md` and note its anchor.
- For a user page, find the parser that owns each key, verb, or action.
- Note every place where the terminology lock disagrees with what the code, the binaries, or
  `decisions.md` call something.

Write down what you can't find: it goes to Tier 3 of
[`claim-verification.md`](../../references/claim-verification.md), not onto the page.

### Step 3: Sort the facts

You'll have far more than the page needs. Write a fact sheet to `.agents/drafts/<page>-facts.md`
that puts each fact in one of three piles:

- **This page.** It's at the page's altitude and the reader needs it here.
- **Another page.** It belongs to a sibling topic. It gets one clause and a link at most.
- **Nowhere.** An implementation detail that no reader of either page needs.

Expect most facts to land outside "this page".

### Step 4: Outline

Start from the skeleton for the subject in
[`page-templates.md`](../../references/page-templates.md). A page about several parts gets one
section per part. Read the outline for scope creep and for detail that belongs to another page.

Show the outline to the user before you draft when the page is new, or when the outline changes the
structure of an existing page. Raise each terminology clash from Step 2 at the same time.

### Step 5: Draft

- Each section opens with what the reader needs first (Layer 2).
- Use the register for the content type (Layer 3).
- Read each paragraph aloud as you go. Rewrite any sentence a person wouldn't say.
- User guide: describe what is, and explain why only when the reason changes the operator's action.
- Design guide: keep each claim within what its test pins, name no test, and link each decision by
  anchor.
- Examples are complete, realistic, and one concept per block, with the output below the command.
- Diagrams show the main path only.

### Step 6: Verify

Follow [`claim-verification.md`](../../references/claim-verification.md) for each claim and each
example. Don't skip this step. Remove each claim you can't verify, and report it.

### Step 7: Cut

Cut by altitude, not by a percentage. Look first for detail that belongs to another page, then for
a list said twice, then for sentences that restate the one before. Keep what this page's reader
needs. Most of the quality comes from this step.

### Step 8: Check

Run the mechanical check and clear or justify each hit:

```sh
.agents/skills/docs-reviewer/check-prose.sh <target-file>
```

Compile each Mermaid block with `mmdc`.

### Step 9: Review

Run the `docs-reviewer` skill on the draft in a fresh context. Fix its findings, then run it again
until the verdict is "Ship it".

### Step 10: Link the page

Add one row for a new page to the `README.md` of its guide. Remove the page from the "still to
come" list in `docs/design/README.md` if it's there.

## Output

1. The page, written to the target file.
2. A short note on the content type and each editorial choice.
3. Each claim you left out because you couldn't verify it, with the symbol and the tier that failed.
4. Open questions for the user: terminology, scope, and accuracy. When no user is in the loop
   (another agent ran this skill), this list replaces asking.
5. Each `decisions.md` entry that the code contradicts. Report it, and don't edit it: the `kd`
   skill owns that file.

In rewrite mode, also report:

6. Each claim in the original that current `main` contradicts, as its own list, so the author can
   fix the original even if they don't take the rewrite.
7. Whether the row for the page in its guide's `README.md` needs new wording for the new outline.

## What this skill doesn't do

- Commit, push, or open a pull request. Follow the commit flow in `AGENTS.md` when the user asks.
- Write an entry in `decisions.md`. That's the `kd` skill.
- Add or change a term in the terminology lock without the user's approval.
- Change code to agree with a page.

## Gotchas

- **A design page isn't a decision entry.** It explains how the parts fit together for a reader who
  wasn't there. Summarize a decision and link its anchor. Don't copy the argument.
- **A command and its binary can have different names.** Check what ships before you name one.
- **`--all-features` is required** when you run a test to verify a claim. Without it, some suites
  are skipped and report success.
- **The first draft carries detail from other pages.** Always.
