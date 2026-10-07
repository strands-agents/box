# Voice guide

How to write every page in `docs/user/` and `docs/design/`, and each crate `README.md` that serves
a consumer. The `docs-writer`, `docs-reviewer`, and `docs-audit` skills apply it. Walk the layers in
order.

## Contents

- [Placement: which guide owns the page](#placement-which-guide-owns-the-page)
- [Layer 1: Structure](#layer-1-structure)
- [Layer 2: Framing](#layer-2-framing)
- [Layer 3: Register](#layer-3-register)
- [Layer 4: Hard constraints](#layer-4-hard-constraints)
- [Layer 5: Authenticity](#layer-5-authenticity)
- [Readers that are people and readers that are agents](#readers-that-are-people-and-readers-that-are-agents)
- [Format](#format)
- [Self-check](#self-check)

## Placement: which guide owns the page

Ask one question of each page: does the reader need it to **use** Box, or to **trust or change**
Box?

| Guide | Directory | Reader | Content types | The "why" |
|---|---|---|---|---|
| User guide | `docs/user/` | An operator who runs an agent or another command under a policy. | Tutorial, how-to, reference. | Only when it changes what the operator does. |
| Design guide | `docs/design/` | A security evaluator, a contributor, or a curious reader. All of them clone the repo. | Explanation. | The point of the page. |

Technical doesn't mean design. The `box.toml` keys, the CLI, and the policy action vocabulary are
user-guide reference. The reasoning behind the same topics is design-guide explanation.

Three design-guide files have their own owner. Don't write them with `docs-writer`:

- `docs/design/decisions.md` takes an entry only through the `kd` skill, and only after the user
  decides it.
- `docs/design/terminology.md` is the terminology lock. Change it only when the user asks.
- `docs/design/tenets.md` states the tenets. Change it only when the user asks.

## Layer 1: Structure

Shape the page around its subject. Every section has one job, and the reader can tell what it is
from the heading.

- A page about several parts (three binaries, four filesystem lists) gets one section per part.
  Everything about a part goes in its section: what it is, why it exists, and how it's checked. Don't
  spread one part across a "what", a "why", and a "how" section.
- A page about one task or one mechanism gets sections in the order the reader needs them.
- A summary table or diagram that compares the parts can come after the part sections, as a recap.

Write the outline first for anything longer than a few paragraphs, and show it to the user. Read the
outline for scope creep before you write prose.

### Altitude

A page covers its own topic and nothing below it. When a detail belongs to another page (the
broker's wire protocol on a page about binaries, the Seatbelt rules on a page about policy), give it
one clause and a link, or leave it out. Do this even when the other page doesn't exist yet: link the
decision anchor for now.

Gathering facts for a page turns up far more than the page needs. Sort them before you write: this
page, another page, or nowhere.

## Layer 2: Framing

Each section opens with what the reader needs first.

User guide, where the reader has a task. Lead with the goal:

- Yes: "To let the workload read a directory, add the directory to `read` in `[agent.filesystem]`."
- No: "The `read` list holds paths."

Design guide, where the reader is building a mental model. Say what the thing is and when it runs,
then what it does for security:

- Yes: "`strands-box` is the entry point, and it starts everything else. ... While it runs, it holds
  everything that makes a security decision."
- No: "`strands-box` holds everything that makes a security decision." The reader doesn't know yet
  what `strands-box` is.

Reference pages are exempt. A reference entry opens with what the item is.

## Layer 3: Register

The base register is a colleague who knows the system and explains it the way they'd say it out
loud. Respect the reader's time. Be direct, and don't lecture. Classify each page before you write
it.

### Tutorial (user guide)

`getting-started.md` is the tutorial. Linear steps, and each step builds on the last. State the
prerequisites first, and describe the result before the steps start. Show the expected output after
each key step. End with what the reader has now and where to go next. Leave out alternative paths
and design reasons.

### How-to guide (user guide)

One task, for example "Grant the workload a directory" or "Bind a credential to a destination".
Put the goal in the title. List the prerequisites, then numbered steps in the imperative, then the
expected result. Add a troubleshooting section when a failure is likely. Link to the reference for
options the guide doesn't use, and to the design guide for background.

### Reference (user guide)

The contract between Box and the operator: `box.toml` keys, CLI verbs and flags, exit codes, and
the policy action vocabulary. Organize by key, verb, or action. For each item, give the type, the
default, the constraints, the errors, and an example. Use tables. Accuracy matters more than flow.
Passive voice is fine. No narrative, no recommendations, and no contractions.

### Explanation (design guide)

Every page in `docs/design/` that you write with `docs-writer` is an explanation page. It tells a
reader who wasn't part of the discussion how a part of Box works and why they can trust it.

- Start with what the thing is, or the problem it solves.
- Then say what Box does, where, and in which process.
- Add residual risk, platform differences, or a rejected alternative only when the reader would
  really ask for it. Don't add a section to fill a template.

Use "we" for a design choice ("We run one policy engine per box"). Use a diagram for a system-level
structure. Leave out step-by-step instructions and option tables, and link to the user guide for
them.

`decisions.md` is the record of why. When a decision is relevant, summarize it in a sentence and
link its anchor, for example
`[one trampoline spawns every contained process](decisions.md#one-trampoline-spawns-every-contained-process)`.
Don't copy its argument.

### Error documentation

Document an error only when its message doesn't tell the reader what to do next. Say what the error
means in plain words, the most likely cause, and the fix. Don't blame the reader.

## Layer 4: Hard constraints

### Plain English

Write it the way you'd explain it to a colleague out loud.

- **Read it aloud.** If a person wouldn't say a sentence that way, rewrite it. A sentence that needs
  a second read to parse is wrong, however correct it is.
- **Short, concrete sentences**, but as long as the idea needs. There's no word limit.
- **Active voice and the present tense**, except in reference.
- **One idea per paragraph.**
- **Contractions are fine**, except in reference.
- **Say a list once.** If the previous sentence named the items, don't walk through them again.

### Overrides by content type

| Constraint | Tutorial | How-to | Reference | Explanation | Error docs |
|---|---|---|---|---|---|
| Passive voice | Avoid | Avoid | **Fine** | Avoid | Avoid |
| Contractions | Fine | Fine | **Avoid** | Fine | Fine |
| Reader-goal framing (Layer 2) | Enforce | Enforce | **Exempt** | What it is first | Enforce |
| The "why" | Only when it changes the action | Only when it changes the action | No | **Required** | The cause only |
| Negative statements | Avoid | Avoid | Avoid | **Fine for a boundary** | Fine |

A negative statement is fine in explanation when the absence is the point. "The workload can't
reach the box directory" is the security claim, so say it as a negative. A test must pin it.

### User-guide rules

These come from the operator's need for a contract. They apply to every page in `docs/user/`.

1. **Describe what is, not what isn't.** If a sentence says "no", "not", "never", or "instead of",
   rewrite it to name the thing that is.
   - No: "There is no separate configuration flag. The workspace selects the file."
   - Yes: "`run` searches upward for `.strands-box/box.toml`."
2. **Don't raise a question the reader didn't ask.** Cut a parenthetical whose only job is to answer
   a question nobody had.
   - No: "An unknown key returns an error (including keys from a separate product)."
   - Yes: "An unknown key returns a configuration error."
3. **Don't explain why.** Document the behavior and the shape. Keep a reason only when it changes
   the operator's action, for example "Install the helpers beside `strands-box`, because the box
   finds them there."
4. **Document the present.** One `> **Status.**` line at the top is the only sentence about the
   future that a page may have.
5. **Open with the subject.** The first sentence defines the thing the reader runs or configures.
   Don't open with "This guide describes".
6. **Cut each section that doesn't help the operator act.** Trust boundaries and design history
   belong in the design guide.

### Design-guide rules

1. **Be exact about boundaries.** Name the process, the platform, and the mechanism. "The agent
   profile grants one `process-exec` rule per `exec` entry" is a claim a reader can check. "The agent
   has limited exec" isn't.
2. **A test backs each claim about behavior, and the page doesn't name it.** A test name is an
   implementation detail. Find the test before you write the claim, and don't claim more than it
   pins. See [`claim-verification.md`](./claim-verification.md).
3. **Never cite a test, a source file, an issue or pull request number, or `file.rs:LINE`.**
   Those are implementation detail, and they go stale.
4. **Link each reason's decision once, the first time the reason comes up.** Don't link a sentence
   that isn't a reason, and don't split a section to give a link a home.
5. **Never link a local draft or an exploration note.** `.agents/drafts/` and
   `.agents/explorations/` aren't committed, so the link is dead in every clone.

### Words not to use

AI tells: "notably", "importantly", "it's worth noting", "it's important to understand", "delve",
"comprehensive", "remarkably", "it should be noted", "as mentioned", "basically", "in general".

Marketing and filler: "robust", "powerful", "seamless", "seamlessly", "effortless", "elegant",
"rich", "flexible", "simply", "easily", "gracefully", "game-changing", "cutting-edge",
"state-of-the-art", "leverage" (as a verb), "utilize" (use "use").

Inflated significance: "crucial", "vital", "pivotal", "plays a key role", "boasts", "serves as".
Use "is", "has", or "uses".

Vague approval: "This is powerful." "This makes it easy to". If a feature works, show it working.

`docs-reviewer/check-prose.sh` greps for these words and for the punctuation below.

### Punctuation and rhythm

- **No em-dashes.** Use a colon, a comma, parentheses, or a period. This includes a glossary gloss:
  write "**`log`**: diagnostic output".
- **No emoji.**
- **Serial comma**, always.
- **No padded triads.** Use a list of three only when each item is a real, named thing.
- **No negative parallelism.** Don't write "not just X, but Y" or "it's not X, it's Y". Make the
  positive statement.
- **No connective padding.** Don't start a sentence with "Additionally", "Moreover", or
  "Furthermore". Don't end one with "..., allowing you to" or "..., ensuring that".

### Terminology

[`docs/design/terminology.md`](../../docs/design/terminology.md) is the lock. Use the term in its
first column, and never a word from its second column. The terms that drift most:

- "box" for the whole boundary, and "workload" for the processes in it. "Sandbox" only for the
  operating system boundary around one process. Not "cage" or "container".
- "the box's trusted process" (or "the trusted process", "its trusted process"), not "Box process",
  "trusted host", or "TCB".
- "surrounding OS", not "the host".
- "operator", not "user".
- "workload", "agent", and "harness" are three things. An agent is a kind of workload, and the
  Strands CLI is a harness.
- "policy" and "sandbox grants" are two tiers, not two words for one thing.

Don't add a synonym because it reads better in one sentence. If a page needs a term the lock doesn't
have, ask the user. If the lock disagrees with what the code, the binaries, or `decisions.md` call
something, ask the user which one wins. Don't silently follow the lock into a word nobody else uses.

### Examples

- **Complete.** An operator can copy a `box.toml` or a command and run it.
- **Realistic.** Use the Strands CLI or SDK, real paths (`~/src/project`), and real
  destinations. No `foo` or `bar`.
- **One concept per block.**
- **Output beside its command.** Put the expected output directly below the command. When the
  output changes from run to run, label it "Example output".
- **Verified.** See [`claim-verification.md`](./claim-verification.md).
- **Prose for a one-line change.** A single key or flag reads better as inline code in a sentence
  than as its own block.

### Diagrams

Show the main path only. One flow, not every variant: if the agent's sandbox makes the point, leave
out the sandboxes for tools and local MCP servers. Use a flowchart for structure, and a sequence
diagram when the order of events is the point. Use a fenced `mermaid` block, quote every label (for example `A -.->|"source kind"| B` in a
flowchart), and compile each block with `mmdc -i diagram.mmd -o diagram.svg` before you finish,
because a grep doesn't catch a lexer error. No ASCII art.

## Layer 5: Authenticity

After the draft, read it for signs that no person made a choice.

- **Structural sameness.** If every section has the same shape (intro sentence, detail, summary
  sentence), change some.
- **Visible judgment.** Make a recommendation: write "use X", not "you can use X or Y".
- **Cut by altitude, not by a percentage.** Remove detail that belongs to another page, sentences
  that restate what the reader knows, transitions a heading already does, and summaries of the
  paragraph above. Keep what this page's reader needs, even when the page stays long.

## Readers that are people and readers that are agents

A person can land on any page from a search. A coding agent can fetch one page with no navigation.
Each page must stand alone.

1. **Context at the top.** The first paragraph says what the page covers.
2. **Prerequisites stated.** Don't write "as shown before". Link the page that shows it.
3. **No cross-reference that carries the load.** If you link another page, give enough context
   inline that the reader can keep going without it.
4. **Terms defined or linked on first use** on each page.
5. **Examples that stand alone.** Each block has the setup it needs.
6. **Inline code in backticks.** A key, a path, a verb, or a type name is always `formatted`.

## Format

- GitHub-flavored Markdown. No YAML front matter.
- Each page opens with `# Title` and a sentence or two that say what the page covers.
- Use relative links between pages.
- Add an `<a id="...">` anchor above a heading that code or another page cites. Never rename an
  anchor, because code cites it.
- A new page gets one row in the `README.md` of its guide.

The page skeletons are in [`page-templates.md`](./page-templates.md).

## Self-check

1. The page is in the right guide, and its content type is classified.
2. The structure follows the subject, and each section has one job.
3. Every detail is at this page's altitude, or it's a clause and a link.
4. Each section opens with what the reader needs first.
5. Read aloud, every sentence sounds like a person said it.
6. User guide: each sentence describes what is, and no sentence explains why unless the reason
   changes the action.
7. Design guide: a test backs each claim, the page names no test, and each reason links a decision
   anchor.
8. No word from the list of words not to use, no em-dash, and no emoji.
9. The terminology matches the lock, and each clash with the code went to the user, or is listed
   as an open question.
10. The examples are complete, realistic, and verified.
11. Each diagram shows the main path and compiles with `mmdc`.
12. The page stands alone, and it's cut.
