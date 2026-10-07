---
name: spec
description: Walk through spec-driven development, design then requirements, producing a local .spec.md and .requirements.md for one feature. Both files are local working material and are never committed. Use when planning a feature before building it.
---

# Spec Skill

Walk a feature through **spec-driven development**: two phases, each with a user approval gate.

```
Design ──[approve]──> Requirements ──[approve]──> build
```

**A spec is local working material, and it is never committed or promoted.** It guides one piece
of work while that work is being built. When the work lands, the spec has done its job:

| What the spec held | Where it goes when the work lands |
|---|---|
| Behaviour and its contract | The code and its tests. A test is the durable form of an acceptance criterion. |
| A decision someone would later ask "why" about | One entry in `docs/design/decisions.md`, through `/kd`, once the user decides it. |
| Everything else: options, task lists, open questions, history | Nowhere. It stays in the local draft. |

`docs/design/` pages are written for a reader who was not in the discussion. Write one fresh
from the code when one is needed. **Never copy or adapt a spec into one.**

**When implementing a feature, strictly honour its spec.** The design (`.spec.md`) defines the
architecture and the decisions, and the requirements define testable behaviour.

## Skill Invocation

`/spec {area}/{feature}`

Start at any phase or resume where you left off:
- `/spec policy/temporal-history`: start or continue the spec
- `/spec policy/temporal-history --phase requirements`: jump to the requirements phase

## Where a spec lives

```
.agents/drafts/spec/
  {area}/
    YYYY-MM-DD-{desc}.spec.md
    YYYY-MM-DD-{desc}.requirements.md
```

`.gitignore` holds `/.agents/drafts/`, so nothing here is committed. The area names a component,
such as `box`, `containment`, `credentials`, `egress-gateway`, `monty`, `policy`, `shell`, or
`telemetry`. The date and description match across the two files for one effort.

Because the folder is local, a spec exists only in the working tree that wrote it. A second
agent or a second clone does not see it. Hand off a spec by path, in chat.

## First Step: Check what already exists

**Before anything else**, read what already owns this area:

1. `ls .agents/drafts/spec/{area}/`: a spec effort already in progress here.
2. `docs/design/decisions.md`: the decisions already made in this area. A spec does not
   re-decide one silently. To change one, run `/kd` on it.
3. The crate itself: its `AGENTS.md`, its module docs, and its tests. The code owns behaviour.

Then decide scope, and say it to the user:
- **Extend** an existing local spec, or
- **Create** a new one for a topic not yet covered.

---

## Writing Style: ASD-STE100 Simplified Technical English

Write every sentence of both artifacts in it: the `.spec.md` prose and the `.requirements.md`
prose.

- Use the active voice. Say "the decoder borrows the buffer", not "the buffer is borrowed".
- Use the present tense. A design states what the system does, not what it will do.
- Give one idea in one sentence.
- Keep a descriptive sentence to 25 words or fewer, and an instruction to 20 or fewer.
- Use one word for one meaning across both files. A term that means two things
  belongs in the Glossary twice, under two names.
- Use no metaphor and no idiom.
- Make no noun cluster of more than three words.
- Keep a paragraph to six sentences or fewer, and prefer a list to a long sentence.

### What the style does not touch

- **EARS is a fixed grammar, and it wins inside an acceptance criterion.** Keep
  `WHEN … THE {System_Component} SHALL …` exactly as the pattern table specifies. `SHALL`
  stays; do not rewrite it to the present tense. Apply the style to the words you choose
  *inside* each clause: keep the trigger and the response short, concrete, and free of
  metaphor.
- **The user-story line keeps its template.** `As a {role}, I want {functionality}, so
  that {benefit}.` is a fixed shape.
- **Identifiers and glossary terms are not prose.** `Title_Case` terms, type names, config
  keys, file paths, JSON field names, and status values keep their exact spelling. The
  three-word noun-cluster limit does not apply to them.
- **The templates control the structure.** Section names, KD numbering, and requirement
  numbering stay as specified. Where the style and a template
  disagree on wording, the style wins.

Apply the style as a pass over each artifact before the approval gate, not while drafting.
Read for a sentence over 25 words, the passive voice, a paragraph over six sentences, metaphor,
idiom, and one meaning per word. Use [`docs/design/terminology.md`](../../../docs/design/terminology.md)
for the word to use for each thing.

---

## Phase 1: Design (`.spec.md`)

The design document captures **what** the system does and **why** — architecture, key decisions, component interactions, data flow.

### Workflow

1. **Gather information** — ask the user (one question at a time):
   - What feature or change to document?
   - What problem does it solve? What's the motivation?
   - What alternatives were considered?
   - Any existing code or interfaces to reference?

2. **Draft the design** — write Key Decisions with diagrams

3. **Present to user for approval** — "Here's the design. Want to adjust anything, or should I proceed to requirements?"

### Design Document Template

```markdown
# {Feature} — Design

## Overview

{1-3 sentences: what this feature does and why it's needed}

## Architecture

```mermaid
{high-level architecture diagram showing major components and relationships}
```

## Key Decisions

### KD-1: {Decision-shaped title}

**Context**: {What situation led to this decision}

**Decision**: {What the system does — 1-3 normative sentences only. No reasoning, no alternatives, no history. A reader who stops here knows the behavior.}

**Rationale**: {Why this over alternatives. All reasoning, tradeoffs, prior art, and justification goes here — clearly separated from the normative Decision above.}

```mermaid
{diagram illustrating this decision}
```

---

### KD-2: {Decision-shaped title}

{...}

---

## Components and Interfaces

### {Component 1}

**Purpose**: {What this component does}

**Interface**:
```rust
// src/path.rs — trait / struct / public fn signature
```

## Data Models

{Data structures, schemas, entity definitions — structs, enums, serde shapes}

## Error Handling

{Error categories, error enums / Result types, recovery strategies}

## Security Considerations

{Authentication, authorization, data protection, input validation implications}

## Backward Compatibility

| Change | Backward Compatible? | Migration |
|--------|---------------------|-----------|
| {API/field/behavior change} | Yes / No | {How existing callers/data are handled} |

Key questions:
- Can this be rolled back without data loss or manual intervention?
- Do existing serialized records, crate consumers, or config files continue to work unmodified?
- If a new field is added, what does its absence/`None` mean? (Document explicitly — a field name is an implicit contract.)
- Is this a one-way door (can't un-ship a public API shape) or two-way door (can revert via config/feature flag)?
- If config-driven, does it activate everywhere simultaneously or use staged rollout?

## Accepted Residuals

{What this spec explicitly does NOT cover and why. Every gap should be intentional and stated — silence about a topic reads as "covered" when it may be "out of scope." List each residual with a brief rationale for exclusion.}

- **{Residual 1}**: {Why it's out of scope — e.g., handled by another crate, deferred to a future phase, not yet designed}
- **{Residual 2}**: {…}

## Open Questions

{Threads not yet resolved. Each must annotate which requirements it would affect if resolved differently than currently assumed.}

- **{Question}** — Affects: Req {N.M}, {N.M}. {Current assumption and what would change.}
```

### Key Decision Guidelines

Each KD should be **self-contained**: a reader can understand the decision from just that section.

**Every KD must have a mermaid diagram.** Choose the right type:

| When showing... | Use |
|---|---|
| Data flow or request path | `flowchart LR` or `flowchart TD` |
| State transitions | `stateDiagram-v2` |
| Sequence of operations | `sequenceDiagram` |
| Component relationships | `flowchart TD` with subgraphs |
| Decision tree | `flowchart TD` with diamond nodes |

**Good KD titles** are decision-shaped:
- "Decoder borrows the input buffer (zero-copy)" (not "Decoder")
- "Builder returns `Result` on invalid config" (not "Builder API")
- "Snapshots are append-only" (not "Storage Backend")

**Decision vs Rationale separation:** The Decision field is normative — it states what the system does in 1-3 sentences. A reader scanning KDs for "what does this system do" should be able to read only Decision fields and get a complete picture. All reasoning, tradeoffs, internal research, prior art, LOC estimates, PRD reconciliation, and alternatives go in Rationale. Never mix mechanism justification into the Decision field.

**Backward compatibility:** Every KD that changes existing behavior must state whether the change is backward compatible and what happens to existing data/callers. If the answer is "absence = legacy behavior," document what `None`/missing means explicitly — a field name is an implicit contract.

**KD numbering:** Sequential within each doc (KD-1, KD-2, ...). When extending, continue from the last number. A spec's KD number is local to that spec, so **never cite it from code, a test, or a committed doc**: the spec is not committed, so the citation is dead for every reader. Code cites a decision by its `docs/design/decisions.md` anchor.

**Mermaid tips:**
- One concept per diagram, not the entire system
- Label edges with the important detail (latency, protocol, data format)
- **Quote every edge label**: `A -.->|"read(2)"| B`. Measured: unquoted labels fail the lexer when
  they contain `(` or `|`, and quoting always parses.
- Use subgraphs to group related components
- Prefer `flowchart` over `graph`

**Compile every block — a grep check cannot see a lexer error:**

```sh
export PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
mmdc -i block.mmd -o /tmp/block.svg
```

`mmdc` drives a headless browser and finds none by default, so without that variable it reports a
launch failure that reads like "mermaid is unavailable". The output path needs a real extension;
`-o /dev/null` fails on every input and proves nothing.

---

## Phase 2: Requirements (`.requirements.md`)

Requirements transform the design into **testable, formal specifications** using EARS notation. Each requirement is traced back to the design and structured as user stories with acceptance criteria.

### Workflow

1. **Read the design doc** (`.spec.md`) — extract every behavior, constraint, and edge case
2. **Identify requirement groups** — cluster by user story / capability
3. **Draft requirements** using EARS patterns
4. **Present to user for approval** — "Here are the requirements. Want to adjust anything?"

### Requirements Document Template

```markdown
# {Feature} — Requirements

## Introduction

{Overview of the feature, what problem it solves, why it's needed. Reference the design doc.}

## Glossary

{Define technical terms, acronyms, component names used in requirements. Use Title_Case for terms that appear in EARS statements to make them unambiguous. A term the whole product uses belongs in docs/design/terminology.md, and this glossary defines spec-specific terms only.}

- **{Term_Name}**: {Definition}

### Scope

{What is included and excluded from this requirements document. All terms used here MUST be defined in the Glossary above.}

## Requirements

### Requirement 1: {Capability Title}

**User Story:** As a {role}, I want {desired functionality}, so that {benefit/value}.

#### Acceptance Criteria

1. WHEN {specific event or trigger} THE {System_Component} SHALL {specific system response}
2. IF {condition or state} THE {System_Component} SHALL {required behavior}
3. WHILE {precondition} WHEN {trigger} THE {System_Component} SHALL {response}

#### Example

{One concrete input → expected output illustrating the happy path. Enough for a test author to see what pass/fail looks like without reverse-engineering the prose.}

### Requirement 2: {Capability Title}

**User Story:** As a {role}, I want {feature}, so that {benefit}.

#### Acceptance Criteria

1. WHEN ...
2. IF ...

#### Example

{...}

{... more requirements ...}

## Non-Functional Requirements

### Backward Compatibility

- WHEN {an existing crate consumer calls without the new field} THE {System} SHALL {behave identically to the current behavior}
- IF {rollback is triggered} THE {System} SHALL {return to previous behavior without manual data migration}
- WHEN {a record serialized before this change is deserialized} THE {System} SHALL {handle absent/None new fields as legacy behavior}

### Performance

{Latency, throughput, allocation, resource consumption requirements}

### Security

{Authentication, authorization, input validation, encryption requirements}

## Definition of Done

- [ ] All acceptance criteria are met
- [ ] Non-functional requirements are satisfied
- [ ] Design decisions are honored
- [ ] Each acceptance criterion is pinned by a named test
- [ ] Each decision a reader would ask "why" about is offered to the user for `/kd`
- [ ] User-facing behaviour that changed is reflected in `docs/user/`
- [ ] Accepted Residuals in the spec are not accidentally implemented or contradicted
```

### EARS Patterns

| Pattern | Syntax | Use when... |
|---------|--------|-------------|
| **Ubiquitous** | `THE {System} SHALL {response}` | Always true, no trigger needed |
| **Event-driven** | `WHEN {trigger} THE {System} SHALL {response}` | Triggered by a specific event |
| **State-driven** | `WHILE {precondition} THE {System} SHALL {response}` | Behavior depends on system state |
| **Conditional** | `IF {condition} THE {System} SHALL {response}` | Unwanted/exceptional behavior |
| **Optional** | `WHERE {feature} THE {System} SHALL {response}` | Feature-dependent behavior |
| **Combined** | `WHILE {state} WHEN {trigger} THE {System} SHALL {response}` | Complex multi-condition behavior |

**Guidelines:**
- Use Title_Case for system components and glossary terms in EARS statements
- Each acceptance criterion must be independently testable
- **One SHALL per criterion.** If a criterion contains AND or multiple SHALL clauses, split it into separate criteria. Each criterion = one assertion = one test case.
- **Acceptance criteria describe observable system behavior only.** Documentation obligations (rustdoc, README updates) belong in Definition of Done, not acceptance criteria.
- Cover happy paths, error paths, and edge cases
- Number acceptance criteria within each requirement (1, 2, 3...)
- Reference requirement numbers as `{N}.{M}` (e.g., `1.1`, `2.3`) for traceability **inside the spec only**. Never put `Req 1.1` in a code comment or a test: name the test instead.
- Every requirement MUST include an Example block showing one concrete input → expected output

---

## Phase Transitions

After each phase, explicitly ask for approval before proceeding:

**Design → Requirements:**
> "The design is ready at `.agents/drafts/spec/{area}/YYYY-MM-DD-{desc}.spec.md`. Review the key decisions and architecture. Want to adjust anything, or should I proceed to requirements?"

**Requirements → build:**
> "The requirements are ready at `.agents/drafts/spec/{area}/YYYY-MM-DD-{desc}.requirements.md`. Review the acceptance criteria. Want to adjust anything, or should I start building?"

**When the work lands**, close the spec out in chat rather than in a file:
- name the test that pins each acceptance criterion;
- list each key decision that a reader would later ask "why" about, and offer to record it with
  `/kd`. Record nothing in `decisions.md` until the user decides it;
- name any `docs/user/` page the change made stale.

## Extending Existing Specs

When extending an existing feature's specs:
- **Design**: Continue KD numbering from the last existing KD
- **Requirements**: Add new requirement groups, continue numbering
- Keep the same date prefix if extending the same effort, or use today's date for a new effort
