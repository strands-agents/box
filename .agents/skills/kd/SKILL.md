---
name: kd
description: Deep-dive a SINGLE key decision. Frame the question, weigh the candidate options honestly, and land a defensible answer in a local draft. Once the user decides it, append one entry to docs/design/decisions.md, or update the entry it re-answers. Use when you need to rigorously decide one thing, such as "which X should we use", "should we do A or B", "evaluate the tradeoffs of ...", or "make the call on ...".
---

# Key Decision (KD) Skill

Take **one** decision and analyze it to the bottom. Frame the real question, enumerate the
candidate options, weigh each honestly, and **recommend an answer** with its cost stated.

The work has two outputs, and they live in different places:

| Output | Where | Committed? |
|---|---|---|
| The analysis: options, criteria, measurements, recommendation | `.agents/drafts/kd/{YYYY-MM-DD}-{slug}.md` | No. `.gitignore` holds `/.agents/drafts/`. |
| The decided entry | one entry in `docs/design/decisions.md` | Yes, and only after the user decides. |

## Skill Invocation

`/kd <the decision>`

Examples:

- `/kd which isolation primitive should back the box on Linux`
- `/kd should the egress gateway do static or semantic outbound control`
- `/kd how is temporal history stored`

## Process

1. **Check whether `decisions.md` already owns this question.** Search it by topic, not by
   wording. If an entry answers it, this run re-answers that entry. See
   [Re-answering an entry](#re-answering-an-entry).
2. **Frame the question.** State what must be decided and why it is hard. A question with an
   obvious answer is not a key decision. Say so and stop.
3. **Find the real options.** Three to six, each one a thing someone would actually build.
   Include the status quo. Reject a straw man rather than listing it.
4. **Weigh them.** Name the criteria that decide it, and say which option wins each. Where a
   claim needs evidence, measure it or read the source. Do not assert.
5. **Write the draft** to `.agents/drafts/kd/{YYYY-MM-DD}-{slug}.md`, in the
   [draft shape](#the-draft). Status is `Proposed`.
6. **Report in chat:** the one-line recommendation, its cost, and the draft's path. Then stop
   and wait.
7. **Append the entry only when the user says it is decided.** Set the draft's status to
   `Decided`, write the entry in the [entry shape](#the-entry), and report the anchor.

**An agent never decides on the user's behalf.** A recommendation is not a decision, and the
user's silence is not approval.

## The draft

The draft is where the argument lives, so it can be as long as the analysis needs.

```markdown
# {The question}

**Status:** Proposed | Decided {YYYY-MM-DD}
**Owns or re-answers:** {new | decisions.md#{anchor}}

## Why this is hard
## Options
## Criteria, and which option wins each
## Evidence
## Recommendation, and its cost
```

## The entry

An entry states the decision, not the argument. Read three neighbouring entries in
`decisions.md` before you write one, and match their shape.

```markdown
<a id="{slug}"></a>
### {The answer, stated as a claim. Never a question.}

{Two to six sentences. What is now true, in the present tense, and what it lands in: the type,
the module, or the mechanism. The obvious alternative, and why it lost, in one sentence. What the
decision costs the reader: a limitation, a residual risk, or a thing they must not do.}
```

- **Put it in the section that owns the area:** `Premises`, `The box`, `Policy`,
  `Containment`, `Interpreters`, `Egress`, `Credentials`, or `Telemetry`.
- **The slug is the claim, in kebab-case.** It is a permanent identifier, so pick it once.
  Code cites an entry by this anchor, as `docs/design/decisions.md#{slug}`.
- **Name a test that pins the claim**, when one exists. Verify the name with
  `git grep -n 'fn {name}'` first. An invented test name is worse than none.

## Re-answering an entry

**Rewrite the entry to state what is now true. Do not append a second entry beside it.** A
reader who must assemble one decision from a stale entry plus its correction reads the design
wrong.

- **Keep the `<a id="…">` anchor unchanged**, even when the title changes. Code links to it.
- **Rewrite the title, the answer, and every cost the change makes false.** A title that names
  a deleted mechanism is the first thing a reader trusts and the first thing that misleads.
- **Open a new entry only for a new question.**

## Rules

- **One entry, one decision.** Two decisions are two entries.
- **The entry never links the draft.** `.agents/drafts/` is gitignored, so the link is dead for
  every other reader and every clone. State the answer and its cost well enough that no reader
  needs the draft.
- **State the answer, not the argument.** The argument stays in the draft.
- **Never cite a `file.rs:LINE`.** Name the symbol, the type, or the test. A line number rots on
  the next edit above it.
- **Never restate a fact the code owns.** The code owns behaviour. The entry owns why.
- **No status line, no date, no "Updated" banner, and no "Proposed" in the entry.** An entry in
  `decisions.md` is decided by being there. The page is a historical record, and the code is the
  authority where the two disagree.
- **Write in ASD-STE100 Simplified Technical English**, with no em-dashes and no en-dashes.
