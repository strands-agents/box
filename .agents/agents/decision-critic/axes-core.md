# decision-critic: Core area

Artifacts:

- **Key Decisions:** a `/kd` draft under `.agents/drafts/kd/`, or an entry in
  `docs/design/decisions.md`.
- **Specs:** a local `.spec.md` under `.agents/drafts/spec/`.
- **Requirements:** a local `*.requirements.md` beside it (EARS acceptance criteria).

Read [`decision-critic.md`](../decision-critic.md) first. This file adds the axes for a Box Core
decision or spec.

## What this area names

- **Decision skills:** [`kd`](../../skills/kd/SKILL.md) for a Key Decision, and
  [`spec`](../../skills/spec/SKILL.md) for a spec. `/kd` already tells its author to weigh real
  options and state the recommendation's cost. You are not re-running that authoring step. Same
  subject, opposite stance (auditor vs. author), separate invocation, no shared context.
- **Rules a decision must not contradict:** the tenets in `docs/design/tenets.md`.
- **Where to grep for a name:** `crates/`. The seam holds: `feature-critic` asks "does the code
  honour this decision?", you ask "does the thing this decision talks about still exist?" Never go
  further than existence.
- **Where else to read:** the cited sibling KDs, the governing decision a spec claims to implement,
  and `docs/design/tenets.md`.

## Where the artifact lives

- **A `/kd` draft with `Status: Proposed`, or a local spec:** the user has not decided it. Be
  maximally rigorous.
- **An entry in `docs/design/decisions.md`, or a draft with `Status: Decided`:** the user has
  decided it. Flag it only if it contradicts another entry or a tenet in `docs/design/tenets.md`,
  or if a new artifact in the review set is inconsistent with it.
- Honor the repo tenet **"nothing is decided just because it's written"**: you flag weak
  reasoning; you do **not** ratify or declare anything decided. The author fixes via `/kd` or
  `/spec`.

## Severity

`BLOCKER` also covers a contradiction with a tenet, a "SHALL" that is not testable, and framing
that cannot support a defensible choice. `WEAKNESS` also covers miscalibrated decision density.

## Axes

- **Real options, in a draft.** The 2 to 5 options are genuinely distinct and defensible. Flag any
  option whose cons are inflated or whose pros are ignored.
- **A choice presented as forced, example.** Real example in this repo: an "always-drain reader"
  *was* forced by backpressure, but "invoke and attach are separate primitives" was a genuine
  design choice smuggled in as forced.
- **Decision density.** Is this **over-decided**: a two-way-door, uncontested, in-workspace
  triviality promoted to a full `/kd` (it should be a decision inside a spec)? Or
  **under-decided**: a genuinely contested, foundational, hard-to-reverse fork buried as a one-line
  spec decision that deserves a KD and group alignment? Use the repo's own bar: a KD earns its
  weight when it binds an external contract or is a *contested* fork worth the group's alignment
  time; hard-to-reverse alone is not enough.
- **KD traceability (the doc graph, not the code).** Does a spec's `KD-N` decision that makes a
  non-obvious mechanism choice **cite the governing `decisions.md` entry**? Is there a decision
  made "by fiat" that should trace to an entry but does not? Conversely, does an entry a spec cites
  actually exist and say what the spec claims? (This is upstream of `feature-critic`, which only
  checks that *code* cites it.)
- **Consistency across artifacts.** Do the spec and requirements agree with each other (a
  data-model sketch that contradicts a decision; a requirement that contradicts the spec's stated
  scope)? Does an "intentionally cut / deferred" item stay cut consistently across all the
  artifacts?
- **Requirements testability (EARS).** Is each acceptance criterion an independently testable
  "WHEN/IF/WHILE … THE … SHALL …", or a vague aspiration? A "SHALL" no one could write a test for
  is a BLOCKER (it will be silently unmet, as happens with un-enforced gating requirements).
- **Reversibility, example.** A decision labeled "two-way door" whose *downstream consequences* are
  actually one-way (for example, a shape other crates will build on) is mis-labeled.
- **Liveness.** Apply the shared Liveness and shape axis to a spec too, as to a draft. Repo rule:
  *"a pull request that changes what an entry says fixes that entry."*
  - Measured 2026-08-23: one entry documented a `--interpreter` flag and the check enforcing it,
    both deleted; a sibling's answer opened *"Box gains `[lib]`"* after that target was removed.
  - **A reversal rewrites its own entry**: update the title, the answer, and every cost it makes
    false, and keep the `<a id>`.
  - **A draft's `Status:` matches reality.** A `Proposed` draft whose decision already shipped is
    stale, and so is a `Decided` draft with no matching entry in `decisions.md`.
  - Spec notes too. Measured: one said a defect stayed open pending a fix through a library façade
    after that façade was deleted, so it named an impossible route.
