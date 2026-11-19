---
name: docs-reviewer
description: Review Box drafts in docs/user/ or docs/design/, and wording-only rewrites in docs/dev/. Use after docs-writer, before a docs pull request, or for a requested doc review. Check style and preservation of meaning, then give a Ship it, Tighten, or Rethink verdict. Read-only.
---

# Documentation reviewer

**Scope.** Whether a draft is in the right place, shaped around its subject, at the right altitude,
easy to read, and consistent with the terminology lock, measured against
[`voice-guide.md`](../../references/voice-guide.md). You don't check that a claim is *correct*
against the code and its tests. That's the `docs-audit` skill.

For a rewrite, obtain the original commit and path or saved text and the requested scope.
Compare meaning as well as style. A wording-only review covers changed prose and preservation;
report pre-existing issues separately. For `docs/dev/`, apply the sentence rules in Layers 4 and 5
and preserve its structure, source and test references, and Simplified Technical English register.
The user/design placement and citation rules do not apply to that developer-doc wording review.

Readability and altitude come first. A page can pass every mechanical rule and still be a page
nobody wants to read, and that's a fail.

## Procedure

Read the voice guide and [terminology](../../../docs/design/terminology.md) before reviewing.

1. Read the draft once straight through, as its reader would. Note where you had to reread.
2. Run the mechanical check, and use its hits as input to dimension 4:

   ```sh
   .agents/skills/docs-reviewer/check-prose.sh <draft>
   ```

3. Classify the content type from the directory and the structure.
4. Apply every applicable rule in Layers 4 and 5 to the prose under review, then score each
   dimension below. For a rewrite, also compare each assertion and protected element with the
   original. A clean script result does not prove readability or preservation.
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

- Apply the voice guide's concrete-word, punctuation, and formatting rules. Use the content-type
  constraints that apply to the page.
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

### 7. Preservation of meaning

- For a rewrite, check every original assertion and protected element against
  [Preserve meaning](../../references/voice-guide.md#preserve-meaning). Quote both versions for
  each change in meaning, including omissions.
- A wording-only rewrite must preserve meaning. Report suspected factual errors separately;
  style does not establish that a claim is false.
- If the original is unavailable or a meaning change remains unresolved, the rewrite cannot
  receive "Ship it". For a new page, mark this dimension "not applicable".

## Verdicts

**Ship it.** All applicable dimensions pass, with one minor warning at most. A rewrite also needs
a complete comparison with the original and no unresolved change in meaning.

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

**Guide and type:** <user, design, or developer guide>, <type>
**Scope and baseline:** <new page, or rewrite scope and original commit/path>
**Verdict:** Ship it | Tighten | Rethink

| Dimension | Score | Key finding |
|---|---|---|
| Placement and shape | ... | ... |
| Altitude | ... | ... |
| Readability | ... | ... |
| Constraints and terminology | ... | ... |
| Claim scope | ... | ... |
| Examples, diagrams, standing alone | ... | ... |
| Preservation of meaning | ... | ... |

### Findings

1. <file>:<line>: <the finding>. Fix: <the fix>.

### What works

<The specific choices that help this page's reader.>
```

## What this skill doesn't do

- Edit the draft. The writer fixes it.
- Check a claim against the code. That's `docs-audit`.
- Commit, push, or approve a pull request.
