# Voice guide

How to write every page in `docs/user/` and `docs/design/`, and each crate `README.md` that serves
a consumer. The `docs-writer`, `docs-reviewer`, and `docs-audit` skills apply it. Walk the layers in
order.

For a wording-only rewrite in `docs/dev/`, apply the sentence rules in Layers 4 and 5. Keep the
page's structure, source and test references, and Simplified Technical English register.

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
Name the actor when it matters to the contract. Omit narrative, recommendations, and contractions.

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

### Preserve meaning

For a rewrite, compare the original and the draft assertion by assertion. Keep each actor, action,
condition, and result. Preserve negation, obligation, defaults, counts, platform limits, event
order, and stated uncertainty. Removing repeated wording is safe; removing a unique qualification
changes the claim. A security refusal must remain a refusal.

During a wording-only edit, keep the structure, code blocks, commands, identifiers, literal output,
quotations, link targets, and explicit anchors unchanged. Preserve heading anchors when changing
heading case, for example by adding an explicit anchor with the old ID.

Report a suspected factual error separately. Keep the affected meaning unchanged until a factual
correction is in scope and verified. Style is not evidence for a new claim.

### Plain sentences

- Name the actor and use an active verb when the actor matters. Passive voice is appropriate when
  the actor is unknown or irrelevant to the reader.
- Give each sentence one main idea and each paragraph one topic. Split a sentence when the reader
  must return to an earlier clause to understand it. Keep the words that explain cause and order.
- Use complete sentences with articles and verbs. Write the relationship in words instead of
  arrows or compressed fragments. Table cells and labels can be short.
- Use the present tense for current behavior. Keep contractions to the plain-English guides and
  out of reference entries.
- State the point directly. Use a comparison only when it explains a choice the reader faces.
  Enumerate the actual items, however many there are. Use a range only for endpoints on a real scale.
- State a list once. A paragraph after a table or list should add information.

### Overrides by content type

| Constraint | Tutorial | How-to | Reference | Explanation | Error docs |
|---|---|---|---|---|---|
| Contractions | Fine | Fine | **Avoid** | Fine | Fine |
| Reader-goal framing (Layer 2) | Enforce | Enforce | **Exempt** | What it is first | Enforce |
| The "why" | Only when it changes the action | Only when it changes the action | No | **Required** | The cause only |
| Negative statements | Keep refusals and limits | Keep refusals and limits | Keep refusals and limits | Keep boundaries | Keep failures |

Keep a negative statement when the absence is the claim. "The workload cannot reach the box
directory" states a boundary. A style edit must preserve it.

### User-guide rules

These come from the operator's need for a contract. They apply to every page in `docs/user/`.

1. **Describe the contract directly.** Keep refusals and limits that affect the operator. Remove
   comparisons with other products unless the operator needs them to choose or configure Box.
2. **Answer the operator's question.** Keep a qualification when it affects the task. Remove
   tangents that neither explain the behavior nor change the next step.
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

### Concrete words and evidence

Use the shortest familiar word that keeps the technical meaning. The following patterns require
an edit or a specific reason to keep them.

| Pattern | Editing action |
|---|---|
| Inflated verbs such as "utilize", "leverage", "facilitate", "enhance", "garner", or "delve" | Use the direct action, such as "use", "help", "add", or "read". |
| Indirect definitions such as "serves as", "stands as", "boasts", or "features" | Use "is" or "has", or name the action. |
| Praise such as "crucial", "pivotal", "vibrant", "robust", "powerful", "seamless", or "elegant" | Give the relevant behavior or supported measurement. Otherwise remove the praise. |
| Abstract labels such as "substrate", "nexus", "landscape", "tapestry", "primitive", "API surface", or "modality" | Name the component, interface, input, or operation. Keep an exact technical term or identifier when it is the right name. |
| Figurative actions such as "rides along", "stands on", "wedges in", or "evacuates" | Say what moves, calls, contains, or depends on what. Apply the same test to metaphors such as a "north star", "flywheel", or "ratchet". |
| Padding such as "additionally", "it is important to note", "in order to", or "due to the fact that" | Start with the fact, or use "to" or "because". |

Each sentence must give the reader a fact, an instruction, or a reason needed for this page.
Replace a feeling about the software with what it does. If a sentence could advertise any project,
make it specific or remove it. Replace slogans and personified code with literal behavior.

Keep an adverb only when it adds a factual distinction. For a performance claim, use a verified
measurement; do not invent a number to replace "quickly". Keep supported uncertainty once,
without stacked hedges. Retain words such as "may" and "only" when they limit the claim.

An attribution needs a named source. A trailing phrase such as "highlighting its flexibility" or
"ensuring safety" needs a supported, concrete claim. Remove the phrase if it adds no fact.
Keep chat acknowledgments, praise for the question, offers of further help, and generic closing
summaries out of the document. End with a result or next step only when the reader needs it.

### Punctuation and rhythm

- Use periods or commas to separate prose clauses. Keep em dashes out of authored prose; an en
  dash, a spaced hyphen, or parentheses must not become a substitute.
- Use a colon to introduce a list or example. For a connection between two assertions, use a
  sentence or a conjunction.
- Use straight quotation marks and apostrophes, sentence case headings, and the serial comma.
  Keep proper names and identifiers in their exact case.
- Use bold for a needed emphasis or a short label, not for every name. A list label must add
  information instead of repeating the sentence. Write it as "**Label.** New information."
- Keep decorative emoji out of headings, bullets, and prose. The preservation rules above apply
  to literal output and quotations.

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
A style rule about metaphors does not rename a defined Box term.

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

Read the draft as a whole after checking individual sentences.

- Let each section's content determine its shape. Remove repeated introductions and summaries;
  keep parallel structure when it helps compare real alternatives.
- When the task needs a recommendation, name the choice and the evidence for it. Reference pages
  state the contract.
- Cut repeated ideas and detail outside the page's purpose. Keep every distinct condition and
  limit when rewriting. Word count is not a completion criterion.

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

Read every paragraph against all the rules in Layers 4 and 5, including the content-type rules.
Every finding needs an edit or a reason to keep the text. For a rewrite, compare each assertion
with the original. Report suspected factual errors separately from wording changes.

Then check placement, structure, terminology, examples, and whether the page stands alone.
The skills run the mechanical checks separately. The prose script catches only some vocabulary
and punctuation patterns; a clean run does not prove readability or preservation of meaning.
The reviewer makes those judgments.
