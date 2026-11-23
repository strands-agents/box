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

## Who decides

- Record an entry only when the choice passes the test in
  [What earns an entry](#what-earns-an-entry), and only after the user decides it. A choice that an
  operator would notice goes to the user before code. Every other choice is a sentence in the pull
  request. An agent never records its own choice for review.
- A recommendation is not a decision, and silence is not approval.
- A missing entry is never a review finding.
- The log can lag the code, and the code owns current behaviour. A change that goes against an
  entry either fits the code to the entry or rewrites the entry, and a human approves the rewrite.
  A pull request that changes what an entry says fixes that entry. Nobody sweeps the log for stale
  entries.

## What earns an entry

An entry records a constraint that future work must respect: a "never", an "only", or a trade-off
between two goals (safety, operator effort, a frozen surface) that a later change could pick
differently by accident. Write one only when it decides a change to a different feature, verb, or
key than the one it came from. Judge it by its title and first sentence.

Test: "Which change to another part of Box does this entry refuse or redirect?"

These are not entries:

- How a feature is shaped: what kind of thing it is, a key's name, a header, a syntax, how two
  sources combine. The design page holds that.
- How to add another thing of the same kind, such as another destination or input source.
- A limit that a dependency forces, such as the operating system. State it where it applies.
- What one feature does today, such as its checks or its flags.
- A constraint that another entry already decides.

A choice that fails the test is one to three sentences in the pull request body: the choice and
why, and, where it helps, what was tried first or what it costs.

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
7. **Append the entry only when the user says it is decided**, and only when the choice passes
   [What earns an entry](#what-earns-an-entry). Set the draft's status to `Decided`, write the entry
   in the [entry shape](#the-entry), and report the anchor.

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

An entry states the decision, not the argument. New and rewritten entries use this shape. An
existing entry in another shape keeps it until a change rewrites that entry.

```markdown
<a id="no-connection-is-opaque-to-the-boundary"></a>
### The gateway terminates every connection, so no tunnel is opaque

The gateway always terminates TLS, so an interceptor sees each request and each response. Every
connection raises `http:request`, and policy decides it.

**Rejected.** Opaque tunnelling, splicing, or raw byte copying: the boundary cannot read that
plaintext, so the connection would skip authorization.

**Cost.** A box cannot reach a plaintext or non-HTTP upstream over `CONNECT`.
```

- **The title is the decision, stated as a claim.** Never a question. A reader who reads only the
  titles must learn the design.
- **Put it in the section that owns the area:** `Premises`, `The box`, `Policy`,
  `Containment`, `Interpreters`, `Egress`, `Credentials`, or `Telemetry`. Keep the list at the top
  of the page in step with the sections.
- **The slug is the claim, in kebab-case.** It is a permanent identifier, so pick it once.
  Code cites an entry by this anchor, as `docs/design/decisions.md#{slug}`.
- **The paragraph** is two to four sentences: what is true now, and why.
- **`Rejected.`** is the alternative that lost and why, in one sentence. Add a second only when a
  reader would really propose it. If it was tried and reverted, say so.
- **`Cost.`** is what the decision costs: a limitation, a residual risk, or a thing a contributor
  must not do. Leave it out only when there is none.
- **Keep it under about 150 words.** A longer entry holds mechanism. Move the mechanism to the
  design page for the area and link it.
- **Name no test.** A test name goes stale, and the code and its tests hold the behaviour.

## Re-answering an entry

**Rewrite the entry to state what is now true. Do not append a second entry beside it.** A
reader who must assemble one decision from a stale entry plus its correction reads the design
wrong.

- **Keep the `<a id="…">` anchor unchanged**, even when the title changes. Code links to it.
- **Rewrite the title, the answer, `Rejected.`, and every cost the change makes false**, in the
  [entry shape](#the-entry). A title that names a deleted mechanism is the first thing a reader
  trusts and the first thing that misleads. If the old answer is now the rejected one, say it was
  tried and why it failed.
- **A rewrite needs the user's approval**, because it changes a decision.
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
- **No status line, no date, no "Updated" banner, no test name, and no "Proposed" in the entry.**
  An entry in `decisions.md` is decided by being there. The log can lag the code, and the code is
  the authority where the two disagree.
- **Write in plain English**, with no em-dashes and no en-dashes.
