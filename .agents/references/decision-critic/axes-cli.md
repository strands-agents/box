# decision-critic: CLI area

Artifacts:

- A draft that the `decision` skill's Weigh mode writes, under `.agents/drafts/decisions/`. The
  user has not decided it.
- An entry in `docs/design/cli/decisions.md`. The user decided it.

The [Core area](axes-core.md) names Box Core's decision artifacts.

Read [`decision-critic.md`](../../agents/decision-critic.md) first. This file adds the axes for a `box`
decision.

## What this area names

- **Decision skill:** [`decision`](../../skills/decision/SKILL.md).
- **Rules a decision must not contradict:** the rules in `crates/cli/AGENTS.md`.
- **Names to grep for:** each symbol, flag, path, key and variable that the text names.
- **Where to grep for a name:** the repository.
- **Where else to read**, in any section of `decisions.md`:
  - each entry that cites the artifact (Grep for `#<anchor>`),
  - each entry on the same topic, and
  - the design page that the artifact links to.
- **Cite code** by its symbol, never by `file.rs:LINE`. Cite a doc by `file:line`.

## Two more exceptions to "docs only"

1. Grep the repository to answer: does the code read, run, or trust a path or a name that the
   decision's reason depends on? A reason whose premise is false is a `WEAKNESS`, and a `BLOCKER`
   when the answer rests on that reason alone.
2. Read Box Core's docs in this repository, `docs/user/`, `docs/design/` outside
   `docs/design/cli/`, and `crates/box/AGENTS.md`, to check what a decision says about Box Core
   (the Box Core contract axis). Never read Box Core's source.

## An entry in this area

Also report an entry when it:

- works around something Box Core decided or asks the operator to do, or states something about
  Box Core that its docs contradict (the Box Core contract axis),
- leaves a safety cost out of `Cost.` (the Safety axis), or leaves out another cost that an
  operator meets (a `WEAKNESS`),
- states a premise that the code does not hold, in text that the change under review adds or
  rewrites, or
- has a title that its own `Cost.` or another entry makes false.

For an entry, the Framing, Real options, and Recommendation axes do not apply, because an entry
holds one answer and at most two rejected alternatives. The fair-case axis applies to its
`Rejected.` lines, and the forced-choice axis to each claim that something is forced. An obvious
option that neither the answer nor a `Rejected.` line covers is a `WEAKNESS`.

**A rewritten entry:** the caller gives the text before the rewrite, and you apply the skill's
"Re-answering" rules (the Consistency axis). If the caller does not give it, say that you did not
check them.

## Severity

`BLOCKER` also covers a contradiction with Box Core's docs, and a title that is false.
`WEAKNESS` also covers a cost that the decision leaves out.

## Axes

- **Real options, in a draft.** There are three to five options, and the current behavior is one
  of them.
- **A choice presented as forced, example.** A constraint can force a refusal that the code cannot
  avoid; the rest of the answer is still a choice.
- **Decision density: it earns an entry.** Apply the test in the `decision` skill's "What earns an
  entry". An entry for what the code makes obvious, for an internal name, for a limit that a
  dependency forces, or for a choice with no real alternative is over-decided: it belongs in a
  sentence in the pull request.
- **The Box Core contract.** `crates/cli/AGENTS.md` says that Box owns everything a box enforces, and that
  `box` must not break the box contract. So a decision that works around something Box Core
  decided or asks the operator to do (a consent the operator gives, a refusal, a required input)
  breaks `box`'s own rule, even when the code builds. Check each claim the decision makes about
  Box Core against Box Core's docs (exception 2). A decision that needs Box Core to
  change, or to agree, is not a `box` decision alone. Say so.
- **Safety.** A decision that changes what a compiled box grants, what a later run trusts, or how
  a credential reaches a box states that cost under `Cost.`. Check it against
  [`a-run-cannot-write-what-a-later-run-trusts`](../../../docs/design/cli/decisions.md#a-run-cannot-write-what-a-later-run-trusts),
  [`an-env-reference-cannot-read-a-credential`](../../../docs/design/cli/decisions.md#an-env-reference-cannot-read-a-credential),
  and [`every-profile-in-the-chain-is-trusted`](../../../docs/design/cli/decisions.md#every-profile-in-the-chain-is-trusted).
  When the artifact is one of these three, check it against the other two.
- **Consistency, for a rewrite.** Apply the skill's "Re-answering" rules: if the old answer is now
  the rejected one, the entry says it was tried and why it failed, and each page that cites the
  entry no longer repeats the old answer. The reason for a reversal is in the entry. A note on a
  design page that carries it ("this reverses ...") is a finding.
- **Reversibility.** `box` is not interface-frozen, and a change to the profile format, to
  `~/.strands/box`, or to a command needs no migration (`crates/cli/AGENTS.md`). So a `box`-only choice is usually
  easy to undo. If the draft says a choice is hard to undo, check the reason. If it says a choice
  is easy to undo, check that it does not change what a compiled box grants, because a wider grant
  is the part that is hard to take back.
- **Liveness, truth, and shape.**
  - Each premise of its reason holds in the code today (exception 1).
  - The title is a claim, not a question, and the list at the top of `decisions.md` has the same
    title. The title names the choice the entry decides, and it is true given the entry's own
    `Cost.` and the `Cost.` of each related entry. A title that claims more than the body gives is
    a BLOCKER.
  - One entry holds one decision.
  - The entry has no pull request number, `file.rs:LINE`, or link to a draft, a plan, or a
    research note.

## Output

`AXES CHECKED` is always present.

`reframe` also covers a decision that works around Box Core. For an entry, the user opens the
choice again with Box Core's owners when it touches Box Core.
