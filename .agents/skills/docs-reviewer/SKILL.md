---
name: docs-reviewer
description: Review Box drafts or rewrites in docs/user/, docs/design/, docs/dev/, or crate READMEs. Use after docs-writer, before a docs pull request, or for a requested doc review. Check style and preservation of meaning, then give a Ship it, Tighten, or Rethink verdict. Read-only.
---

# Documentation reviewer

**Scope.** Whether a draft is in the right place, shaped around its subject, at the right altitude,
easy to read, and consistent with the terminology lock, measured against
[`voice-guide.md`](../../references/voice-guide.md). For a rewrite, also check that it preserves
the original meaning. This comparison does not prove the original is correct. Verification against
code and tests belongs to the writer and the `docs-audit` skill.

Readability and altitude come first. A page can pass every mechanical rule and still be a page
nobody wants to read, and that's a fail.

## Procedure

1. Read the voice guide and [terminology](../../../docs/design/terminology.md). Identify the
   audience, content type, and scope. For a rewrite, obtain the original commit/path or saved
   text and the writer's list of verified factual corrections. If the original is unavailable,
   report that meaning could not be checked; the draft cannot receive "Ship it".
2. Read the draft once straight through, as its reader would. Note where you had to reread.
3. Run the mechanical check, and use its hits as input to dimension 4:

   ```sh
   .agents/skills/docs-reviewer/check-prose.sh <draft>
   ```

4. Apply every rule in Layers 4 and 5 to every paragraph. A clean script result is not a style
   verdict. For a rewrite, compare each original assertion, qualification, and protected element
   with the draft. Assess each reported factual correction against the evidence provided;
   refer unresolved accuracy questions to `docs-audit`.
5. Score each dimension below as pass, warning, or fail. Continue only when the whole draft and,
   for rewrites, the whole comparison have been checked.
6. Give one verdict and write the review in the output format.

## Dimensions

### 1. Placement and shape

- The page is in the right guide. A user page that argues a design, or a design page that's a list
  of options, is in the wrong guide.
- The structure follows the subject. A page about several parts has one section per part, and no
  part is spread across sections. A page about one task follows the reader's order.
- No section mixes content types. Conceptual background in a how-to guide is a finding.
- No section exists only to fill a template slot.
- The page doesn't do the job of `decisions.md`, `terminology.md`, or `tenets.md`.
- Developer pages explain repository tasks; crate READMEs introduce their public interface.
  Apply the corresponding register from the voice guide.

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

- Apply the voice guide's concrete-word, punctuation, and formatting rules, with its content-type
  constraints. Give a specific reason for any intentional exception.
- User guide: describe what is, and no "why" unless it changes the action.
- Each word from the "do not use" column of
  [`docs/design/terminology.md`](../../../docs/design/terminology.md) is a finding. A term the lock
  doesn't have, or a lock term that the code calls something else, is a question for the user.

### 5. Claim scope

- Each design choice links its decision anchor the first time it comes up, and the decision is
  summarized, not copied. Task prerequisites and diagnostic explanations need evidence from the
  code or tooling, but do not require a design decision entry.
- A claim stated more broadly than the mechanism it describes is a finding.
- Apply the design guide's citation limits to design pages. Developer pages may name the source
  paths, tests, and workflows needed for the task. Local drafts and explorations are not valid
  link targets in any committed page.

### 6. Examples, diagrams, and standing alone

- Each example is complete and realistic, one concept per block, with the output below the command.
- Prose and code agree.
- Each diagram shows the main path only, is Mermaid with every label quoted, and has no ASCII art.
- The first paragraph says what the page covers. Prerequisites are stated, terms are defined or
  linked on first use, and no cross-reference carries the load.

### 7. Preservation of meaning

- For a rewrite, check every original assertion and protected element against
  [Preserve meaning](../../references/voice-guide.md#preserve-meaning).
- Quote both versions for each change in meaning. Distinguish verified factual corrections from
  accidental changes, including omissions. An unresolved change in meaning is a failure, however
  readable the draft is.
- For a new page, mark this dimension "not applicable". Claim scope and evidence still apply.

## Verdicts

**Ship it.** All applicable dimensions pass, with one minor warning at most. A rewrite must have
a complete comparison and no unresolved change in meaning.

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

**Guide and type:** <user, design, developer, or crate README>, <type>
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
