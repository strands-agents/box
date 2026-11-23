---
name: decision
description: Record, re-answer, or weigh one box design decision as an entry in docs/design/cli/decisions.md. Use when the user settles a choice ("we decided ...", "record that", "why did we ..."), when a change reverses an earlier decision, or when the user asks to evaluate a hard choice ("should we do A or B", "weigh the options for ...", "make the call on ...").
---

# Decision

[`docs/design/cli/decisions.md`](../../../docs/design/cli/decisions.md) records why `box` is the way it
is. A reader can scan its headings and learn the design. Each entry states one decision as it
stands today. Git history holds how it got there.

## Modes

| Mode | When | Output |
| --- | --- | --- |
| **Record** | The user decided a choice that passes [What earns an entry](#what-earns-an-entry). | One new or rewritten entry. |
| **Weigh** | The user asks for help with an open, hard choice. | A local draft and a recommendation. The entry follows only after the user decides. |

## Who decides

- Record an entry only when the choice passes the test in
  [What earns an entry](#what-earns-an-entry), and only after the user decides it. A choice that an
  operator would notice goes to the user before code. Every other choice is a sentence in the pull
  request. An agent never records its own choice for review.
- A recommendation is not a decision, and silence is not approval.
- A missing entry is never a review finding.
- The log can lag the code, and the code owns current behavior. A change that goes against an
  entry either fits the code to the entry or rewrites the entry, and a human approves the rewrite.
  A pull request that changes what an entry says fixes that entry. Nobody sweeps the log for stale
  entries.

## What earns an entry

An entry records a constraint that future work must respect: a "never", an "only", or a trade-off
between two goals (safety, operator effort, the Box Core contract) that a later change could pick
differently by accident. Write one only when it decides a change to a different feature, command,
or key than the one it came from. Judge it by its title and first sentence.

Test: "Which change to another part of `box` does this entry refuse or redirect?"

These are not entries:

- How a feature is shaped: what kind of thing it is, a key's name, a header, a syntax, how two
  sources combine. The design page holds that.
- How to add another thing of the same kind, such as another provider or input source.
- A limit that a dependency forces, such as Box Core or the OS. State it where it applies.
- What one feature does today, such as its checks or its flags.
- A constraint that another entry already decides.
- A reason that only one shipped pack or plugin has, such as why it sets a variable or where a grant stops.
  It is a comment beside the line in that `pack.toml` or `plugin.toml`
  ([Pack comments](../../../crates/cli/AGENTS.md#pack-comments)).

A choice that fails the test is one to three sentences in the pull request body: the choice and
why, and, where it helps, what was tried first or what it costs.

## Process: Record

1. **Search `decisions.md` by topic**, not by wording. If an entry already answers the question,
   rewrite that entry. See [Re-answering](#re-answering).
2. **Read the entries next to it** and match their shape.
3. **Write the entry** in the section for its area, in the [shape below](#the-entry). Add its
   title to the list at the top of the page, or change the title there.
4. **Check each name** in the entry: `git grep` each symbol, flag, path, and variable. A name that
   does not exist is worse than no name. Name only what the decision is about. An entry does not
   copy the current list of keys, tables, or flags, or a default value: link the owner
   ([Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives)), so a new key or a renamed
   flag does not change the entry.
5. **Run `just prose`.**
6. **Report** the anchor.

## Process: Weigh

1. **Frame the question.** Say what must be decided and why it is hard. If the answer is obvious,
   say so and stop.
2. **Find the real options**, three to five, including the current behavior. Leave out straw men.
3. **Weigh them** against the criteria that decide it. Read the source or measure where a claim
   needs evidence.
4. **Write the draft** to `.agents/drafts/decisions/<YYYY-MM-DD>-<slug>.md`. It is git-ignored, so
   the argument can be as long as it needs.
5. **Review the draft.** Run the [`decision-critic`](../../agents/decision-critic.md) agent on it in
   a fresh context. Fix each blocker, or say in the report why you left it.
6. **Report** the recommendation, its cost, the draft path, and the critic's verdict. Then stop
   and wait.
7. **When the user decides**, follow [Record](#process-record).

## The entry

```markdown
<a id="each-run-gets-its-own-box"></a>
### Each run gets its own box, and only the operator removes an old one

Each `box run` creates a new instance with its own run directory and an empty `box_dir`. Two
runs of one profile can then run at the same time, and a `when temporal` rule sees only its own
run.

**Rejected.** One `box_dir` for each profile: Box Core locks `box_dir`, so a second run fails.

**Cost.** Run directories stay after a run stops, about 2 MB each, until the operator runs
`box profile clean`.
```

- **The title is the decision, stated as a claim.** Never a question. Use the operator's or the
  product's words. A reader who reads only the titles must learn the design.
- **The anchor is a short kebab-case form of the claim**, and it is permanent. Code and other pages cite
  `docs/design/cli/decisions.md#<anchor>`. When the title changes, keep the anchor.
- **The paragraph** is two to four sentences: what is true now, and why.
- **`Rejected.`** is the alternative that lost and why, in one sentence. Add a second only when a
  reader would really propose it. If it was tried and reverted, say so.
- **`Cost.`** is what the decision costs: a limit, a risk, or a thing a contributor must not do.
  Leave it out only when there is none.
- **Keep it under about 150 words.** A longer entry holds mechanism. Move the mechanism to the
  design page for the area and link it.

## Re-answering

**Rewrite the entry so it states what is true now.** Do not add a second entry beside it, and do
not add a note. A reader who must combine an old entry and its correction reads the design wrong.

- Keep the `<a id>` anchor.
- Rewrite the title (in the list at the top too), the paragraph, `Rejected.`, and `Cost.` where the
  change makes them false.
  If the old answer is now the rejected one, say it was tried and why it failed.
- Fix each page that cites the entry and repeats the old answer. On a design page, replace a
  repeated reason with a link to the entry. On the page that owns the present behavior
  ([Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives)), update the behavior there.
- Start a new entry only for a new question.

## Rules

- One entry, one decision.
- No number, date, status, "Updated" line, test name, pull request number, or `file.rs:LINE`.
  Git holds the history, and the code and its tests hold the behavior.
- Never link a draft, a plan, or a research note. They are not committed.
- Write in the precise voice of [`writing.md`](../../references/writing.md), and make the first
  sentence carry the point.
