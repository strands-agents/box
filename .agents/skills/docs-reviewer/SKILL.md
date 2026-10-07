---
name: docs-reviewer
description: Review a Box documentation draft in docs/user/ or docs/design/ for placement, structure, altitude, readability, terminology, and claim scope, and give a verdict (Ship it, Tighten, or Rethink). Use after docs-writer produces a draft, before a docs pull request, or when asked to "review this draft", "check my docs", or "is this page ready to ship". Read-only.
---

# Documentation reviewer

**Scope.** Whether a draft is in the right place, shaped around its subject, at the right altitude,
easy to read, and consistent with the terminology lock, measured against
[`voice-guide.md`](../../references/voice-guide.md). You don't check that a claim is *correct*
against the code and its tests. That's the `docs-audit` skill.

Readability and altitude come first. A page can pass every mechanical rule and still be a page
nobody wants to read, and that's a fail.

## Procedure

1. Read the draft once straight through, as its reader would. Note where you had to reread.
2. Run the mechanical check, and use its hits as input to dimension 4:

   ```sh
   .agents/skills/docs-reviewer/check-prose.sh <draft>
   ```

3. Classify the content type from the directory and the structure.
4. Score each dimension below as pass, warning, or fail.
5. Give one verdict.
6. Write the review in the output format.

## Dimensions

### 1. Placement and shape

- The page is in the right guide. A user page that argues a design, or a design page that's a list
  of options, is in the wrong guide.
- The structure follows the subject. A page about several parts has one section per part, and no
  part is spread across sections. A page about one task follows the reader's order.
- No section mixes content types. Conceptual background in a how-to guide is a finding.
- No section exists only to fill a template slot.
- The page doesn't do the job of `decisions.md`, `terminology.md`, or `tenets.md`.

### 2. Altitude

- Each detail belongs to this page. Detail that belongs to a sibling topic (a wire protocol on a
  page about binaries, Seatbelt rules on a page about policy) is a finding, even when that page
  doesn't exist yet.
- Length fits the subject. A draft that's much longer than the subject needs is a finding.

### 3. Readability

- Read aloud, each sentence sounds like a person said it. Quote each one that doesn't, and give a
  plainer version.
- Each section opens with what the reader needs first. A design section says what the thing is
  before what it guarantees.
- A list isn't walked through twice.
- Each term is introduced before its shorthand is used.

### 4. Constraints and terminology

- The words not to use, em-dashes, emoji, padded triads, and negative parallelism. Apply the
  override table for the content type.
- User guide: describe what is, and no "why" unless it changes the action.
- Each word from the "do not use" column of
  [`docs/design/terminology.md`](../../../docs/design/terminology.md) is a finding. A term the lock
  doesn't have, or a lock term that the code calls something else, is a question for the user.

### 5. Claim scope

- Each reason links its decision anchor the first time it comes up, and the decision is
  summarized, not copied. A reason with no link is a finding.
- A claim stated more broadly than the mechanism it describes is a finding.
- No test name, no source file, no issue or pull request number, no `file.rs:LINE` citation, and
  no link into `.agents/drafts/` or `.agents/explorations/`.

### 6. Examples, diagrams, and standing alone

- Each example is complete and realistic, one concept per block, with the output below the command.
- Prose and code agree.
- Each diagram shows the main path only, is Mermaid with every label quoted, and has no ASCII art.
- The first paragraph says what the page covers. Prerequisites are stated, terms are defined or
  linked on first use, and no cross-reference carries the load.

## Verdicts

**Ship it.** All dimensions pass, with one minor warning at most.

**Tighten.** Two or more warnings, or one fail that an edit in place fixes. Typical causes: a few
sentences that don't read aloud, detail that belongs on another page, terminology slips, or a draft
much longer than it needs to be. Give a fix for each finding, at its line.

**Rethink.** Two or more fails, or one structural fail: the wrong guide, a shape that spreads each
part across sections, a page mostly at the wrong altitude, or prose that reads like a spec
throughout. Give the diagnosis and the right approach.

If you can't decide between Tighten and Rethink, ask: can the writer fix this in place, or do they
need to re-outline? In place is Tighten. Re-outline is Rethink.

## Output format

```markdown
## Review: <page title>

**Guide and type:** <user guide or design guide>, <type>
**Verdict:** Ship it | Tighten | Rethink

| Dimension | Score | Key finding |
|---|---|---|
| Placement and shape | ... | ... |
| Altitude | ... | ... |
| Readability | ... | ... |
| Constraints and terminology | ... | ... |
| Claim scope | ... | ... |
| Examples, diagrams, standing alone | ... | ... |

### Findings

1. <file>:<line>: <the finding>. Fix: <the fix>.

### What works

<Two or three things the draft does right.>
```

## What this skill doesn't do

- Edit the draft. The writer fixes it.
- Check a claim against the code. That's `docs-audit`.
- Commit, push, or approve a pull request.
