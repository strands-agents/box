---
name: docs-writer
description: Write or rewrite Box pages in docs/user/, docs/design/, docs/dev/, and crate READMEs. Use for new documentation, wording cleanup, or corrections after a docs audit. Use kd for decision entries, spec for local specs, and explore for research notes.
---

# Documentation writer

Draft or rewrite one Box documentation page in the voice of
[`voice-guide.md`](../../references/voice-guide.md).

## Inputs

- **Topic**: what the page covers. Required.
- **Content type**: tutorial, how-to, reference, or explanation. Classify it in Step 1 if the user
  doesn't give it.
- **Target file**: the path in `docs/user/`, `docs/design/`, `docs/dev/`, or a crate README.
- **Original**: for a rewrite, the unedited page or its commit and path. Record it before editing;
  the reviewer needs it to compare meaning.
- **Scope**: wording only, factual correction, or new content. A wording request does not authorize
  new behavior or design decisions.

## Process

### Step 1: Place and classify

1. Read [`voice-guide.md`](../../references/voice-guide.md) and
   [`docs/design/terminology.md`](../../../docs/design/terminology.md).
2. Use the guide's placement table to select the reader and directory.
3. Classify the content type and register. Keep Simplified Technical English for `docs/dev/`
   and crate READMEs.
4. Stop if the page belongs to another owner: `decisions.md` (the `kd` skill), `terminology.md`, or
   `tenets.md` (only when the user asks).
5. Read the guide's README if present, and each page the new page links to or replaces.

Continue when the target, reader, content type, and scope are recorded, with a baseline for rewrites.

### Step 2: Gather the facts

Read the code on current `main` before you write about it.

- For each proposed claim, find the evidence required by the claim-verification table. Behavior
  claims need the implementing code and a test that pins the behavior.
- For a design page, find each relevant entry in `docs/design/decisions.md` and note its anchor.
- For a user page, find the parser that owns each key, verb, or action.
- Note every place where the terminology lock disagrees with what the code, the binaries, or
  `decisions.md` call something.

Record missing evidence under Tier 3 of
[`claim-verification.md`](../../references/claim-verification.md).
Continue when every proposed claim has evidence or is recorded as unresolved.

### Step 3: Sort the facts

You'll have far more than the page needs. Write a fact sheet to `.agents/drafts/<page>-facts.md`
that puts each fact in one of three piles:

- **This page.** It's at the page's altitude and the reader needs it here.
- **Another page.** It belongs to a sibling topic. It gets one clause and a link at most.
- **Nowhere.** An implementation detail that no reader of either page needs.

For a rewrite, also record each distinct assertion and qualification in the original. Mark facts
that need correction separately. Continue when every fact has a place.

### Step 4: Outline

Start from the skeleton for the subject in
[`page-templates.md`](../../references/page-templates.md). A page about several parts gets one
section per part. Read the outline for scope creep and for detail that belongs to another page.

Show the outline to the user before you draft when the page is new, or when the outline changes the
structure of an existing page. Otherwise keep the existing outline. Raise each terminology clash
from Step 2 at the same time. Continue when each section has a defined purpose.

### Step 5: Draft

- Each section opens with what the reader needs first (Layer 2).
- Use the register for the content type (Layer 3).
- Apply the shared sentence rules while drafting (Layer 4). Keep the original assertions and
  protected text intact during a wording-only edit.
- User guide: describe what is, and explain why only when the reason changes the operator's action.
- Design guide: keep each claim within what its test pins, name no test, and link each decision by
  anchor.
- Examples are complete, realistic, and one concept per block, with the output below the command.
- Diagrams show the main path only.

Continue when the draft covers the facts assigned to the page without adding unsupported claims.

### Step 6: Verify

Follow [`claim-verification.md`](../../references/claim-verification.md) for each claim and each
example. Distinguish a contradicted claim from one that lacks evidence. Continue when each
remaining claim and example has evidence and each factual correction is recorded separately.

### Step 7: Edit and compare

Apply the voice guide's [self-check](../../references/voice-guide.md#self-check) to every paragraph.
Compare the draft with the fact sheet. For a rewrite, also compare it with the original. Continue
when every original assertion is preserved or has a verified, reported correction, and every style
finding is fixed or justified.

### Step 8: Check

Run the mechanical check and clear or justify each hit:

```sh
.agents/skills/docs-reviewer/check-prose.sh <target-file>
```

Compile each Mermaid block with `mmdc`.
Check that local links resolve. For a rewrite, check that protected text and anchors match the
original, except for changes within the requested scope. Continue when these checks pass.

### Step 9: Review

Run the [`docs-reviewer`](../docs-reviewer/SKILL.md) skill in a fresh agent context. Give it the
draft, audience, and scope. For a rewrite, include the original commit/path or saved text and a
list of verified factual corrections with their evidence. Let it form its own judgment of the
wording.

Fix the findings and review the revised draft again. Continue only when the verdict is "Ship it".
If a fresh reviewer is unavailable, report that the independent review is incomplete.

### Step 10: Link the page

For a new page, add a row to the guide's README when it exists. Remove the page from the "still to
come" list in `docs/design/README.md` if it is there. Follow the
[documentation update rules](../../references/doc-updates.md) for publication metadata.
Finish when all required navigation updates are complete.

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
8. The reviewer verdict, the baseline it compared, and any remaining justified warnings.

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
