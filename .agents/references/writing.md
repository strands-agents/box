# Writing for this repository

Two kinds of reader read this repository, so it has two voices. The `user-docs` and `decision`
skills and the `feature-critic` and `decision-critic` agents apply this page.

| Prose | Reader | Voice |
| --- | --- | --- |
| `docs/cli/`, `resources/packs/<pack>/README.md`, `resources/plugins/<plugin>/README.md` | An operator at a terminal who wants to run an agent in a box. | [Plain English](#plain-english-for-user-pages), written for a person. |
| `docs/design/cli/` (not `decisions.md`) | A contributor or a reviewer who wants to know how `box` works and why to trust it. | Plain English, as an explanation: see [Design pages](#design-pages). |
| `docs/design/cli/decisions.md`, `docs/dev/`, `crates/cli/AGENTS.md`, skills, commit messages, code review, comments | A contributor or a coding agent who changes `box`. | [Precise engineering prose](#precise-prose-for-everything-else) in plain English. |

## Plain English for user pages

Write a user page the way a knowledgeable colleague would explain `box` to you at your desk: warm
but not chatty, expert but not condescending, direct but not curt. If a sentence is correct but a
person would not say it out loud, rewrite it.

### The reader

The operator knows a shell and knows their agent (Claude Code or Codex). They do not know Box Core,
Dogwood, or how `box` is built, and they do not need to. They want to finish a task and get back
to work.

### Rules

1. **Lead with the goal.** "To give the agent a second project, add it to `write`." Not "The
   `write` list holds paths."
2. **Talk to the reader.** Use "you" and the imperative in body text. Contractions are fine.
   Headings never use "you" or "your": write a noun phrase ("User profiles", "Custom packs,
   starters, and policies") or, on a how-to, a plain imperative ("Write custom rules").
3. **Show it working.** Put the command first, then the output the reader sees. Use real paths
   (`~/src/my-app`) and real names. No `foo`.
4. **State facts plainly.** "The box blocks it", not "the box can be used to block it". Say what
   happens. Use a negative when the absence is the point ("the agent can't see `~/.ssh`"). Define a
   thing by what it does, not by what it doesn't: "A support pack adds a route", not "A support
   pack runs nothing. It adds a route".
5. **Explain why only when it changes what the reader does.** "Run this in the project directory,
   because the box can write only there" is useful. The design history is not.
6. **Use the operator's words.** "Profile", "run", "box", "your project". Never a module name
   (`compile`, `reference`), a Rust type, or an internal step number.
7. **Make a recommendation.** Write "use X", not "you can use X or Y". If Y matters, say when.
8. **Link a term the first time a page uses it.** A concept (a profile, a pack, a starter, policy,
   a credential) links [`how-box-works.md`](../../docs/cli/how-box-works.md). Define a term in
   place only when no page owns it. Every page
   stands alone: a reader can land on it from a search. It stands alone by linking, not by
   copying: show the command or the TOML the task needs, and link the owner for the full list of
   values, the default, or the precedence ([Where each fact lives](../../crates/cli/AGENTS.md#where-each-fact-lives)).
9. **Document an error only when its message does not already say what to do.** Then say what it
   means, the likely cause, and the fix, without blame. A message that names its own fix needs no
   section.
10. **Document the present.** Describe what `box` does today, not what it may do later.
11. **Link a design page only for background.** A reader who follows no link still gets each fact
    they need to act. That fact is written on the user page that owns it, and the other pages link
    that page.

### Rhythm: sound like a person

Correct prose can still read as machine-written. The usual cause is uniformity: every sentence is
the same length, the same shape (subject, verb, object, period), and every section opens and closes
the same way. Break it.

- **Vary sentence length.** Let a long sentence carry a sequence or a condition, then follow it
  with a short one. A run of three short declaratives in a row is the main sign of choppy prose.
  Join two of them with "and", "but", "so", or a colon.
- **Connect the sentences.** A paragraph is an argument, not a list. Words like "so", "but",
  "then", "that means", and "instead" show how one sentence leads to the next.
- **Allow fragments and asides.** "Nothing else changes." "That's it." Start a sentence with "But"
  or "So" when it reads better.
- **Vary the sections.** Some open with the command, some with the problem, some are two sentences
  long. A page where each section has the same intro, detail, and wrap-up reads as a template.
- **Show judgment.** Say which option to pick and why, and name the trap a colleague would warn you
  about.
- **Cut setup and wrap-up.** Delete a sentence that restates the heading, a transition that the
  next heading already makes, and a summary of the paragraph above. First drafts run 30 to 50
  percent too long.

### Before and after

Accurate and hard to read:

> It refuses to replace a profile that holds other text, unless you give `--force`.

For a person:

> If a profile with that name already exists with different settings, `box` stops and leaves it
> alone. Add `--force` to replace it.

Correct, but choppy and uniform:

> `box` reads the profile again each time you run it. It finds the agent and each toolchain on
> your machine at that moment. So when the agent updates, the next run picks it up. You don't need
> to make the profile again. An edit to either file takes effect on the next run.

The same facts, with rhythm:

> A profile isn't a snapshot. Each time you run it, `box` looks up the agent and your toolchains
> again, so an agent update or a new Node.js shows up on the next run without any work from you.
> The same goes for your own edits: change either file, and the next run uses it.

### Page types

Each user page has one type, and each type has a shape. The shape is the default: depart from it
where that serves the reader better, and say where in the pull request. `feature-critic` checks
the shape of each page that a diff changes.

| Type | Purpose | Shape |
| --- | --- | --- |
| Tutorial (`getting-started.md`) | Take a new operator from nothing to a working run. | Prerequisites, then numbered steps that each show a command and its output, then "what you have now" and where to go next. One path, no alternatives. |
| Topic (`profiles.md`, `packs.md`, `plugins.md`, `starters.md`, `policies.md`) | Understand one part of `box`, and change it. | In this order: what the part is; where it is defined; what is in its file, as an annotated example; one section for each area of the file, which opens with one TOML example whose inline comments name each option, then a few short tasks; and last, one section of the commands for the part, which links `cli.md`. The file sections show no commands, and the commands section shows no file. Key tables go in the reference. |
| How-to (`install.md`) | Do one task, such as "Create a profile from a starter". | The goal as the title, then for each step the command or the TOML and what you see. Troubleshooting only when a failure is likely. It shows the few keys or flags the task needs and links the reference for the rest. |
| Reference (`cli.md`, `profiles-reference.md`, `packs-reference.md`, `plugins-reference.md`, `starters-reference.md`, `config.md`, and `policies-reference.md`) | Look up one command, flag, key, path, or variable. | See [Reference pages](#reference-pages). |
| Troubleshooting (`troubleshooting.md`) | Fix a failure whose message doesn't say what to do. | Sections grouped by when the failure shows, such as before the box starts or after it starts. Each section is a heading that names the symptom, the quoted message, the cause, and the fix. It holds only messages that don't name their own fix (rule 9). |
| Limits (`limitations.md`) | Know what a box leaves to the operator before you trust a run. | One section for each limit: what the box leaves open, who it affects, and what to check or turn off. It links the reference for a key, and holds no install or create steps. |
| Overview (`how-box-works.md`) | See what Box is and how its parts fit together. | Short sections, one for each part, that say how it relates to the others and link the part's topic page. No steps and no option lists. `docs/cli/README.md` lists it after the tutorial, how-to, and reference entries. |

#### Front matter: the page's reader and test

A user page can open with YAML front matter that states who the page is for and what belongs on it.
It is optional. Add it when a change reworks the page and the user agrees on the reader and the test:

```yaml
---
reader: Someone who has a profile, usually from Get started, and wants to understand it or change it.
belongs: A section belongs here only if most users need it in their first month. Anything else goes to profiles-reference.md, cli.md, or troubleshooting.md, and nowhere on this page.
---
```

When a page has it, read it before you edit the page. Apply `belongs` to each section you add or keep: a section that
fails it goes to the page that `belongs` names. Change the front matter only with the user's
approval. GitHub shows it as a table at the top of the page.

Every page opens with what the reader will do there, and covers what that reader came for. It does
not walk through every option, message, or edge case. A task or reference page has no glossary: it
links the part's topic page, or `how-box-works.md`, for a concept instead (rule 8).

#### Reference pages

`cli.md` covers the CLI's commands and flags, and nothing else. A reference page has this shape:

1. An introduction: what the page covers, and one example.
2. An overview table of the items, each linking its section. It names each item and what it is
   for, and nothing that the item's section states. In `profiles-reference.md`, the table in "What a
   profile holds" is the overview, and in `packs-reference.md`, the table in "What a pack holds",
   so a key has no second summary row.
3. One section for each item: one sentence on what it is for, the common example, the usage line
   or the TOML, a two-column table (the flag or key, what it does), and only the output the reader
   uses.

A section leaves out:

- A default, unless it changes what the reader does.
- An error whose message says what to do (rule 9).
- Behavior the reader can't act on: internal order, size limits, link handling, sort tie-breaks,
  and which file is written when. Implementation detail goes to the design page, or nowhere. A
  concept the reader needs to use `box` goes on the part's topic page, such as `profiles.md`.

Write reference text by hand. Do not generate it from the code.

## Design pages

A page in `docs/design/cli/` tells a reader who was not part of the discussion how a part of `box`
works and why they can trust it. Write it in plain English, as an explanation, with the
[rhythm](#rhythm-sound-like-a-person) of a user page. An existing page moves to this voice when a
change rewrites it.

- Start with what the thing is, or the problem it solves. Then say what `box` does, where, and in
  which step.
- Use "we" for a design choice ("We compile the profile again on each run").
- Be exact about boundaries: name the step, the file, and the check. "A run refuses a write grant
  over `~/.strands/box`" is a claim a reader can check. "Runs are protected" is not.
- Add a risk or a rejected alternative only when the reader would ask for it. Link each reason to
  its entry in `decisions.md`, and do not copy the argument.
- Leave out step-by-step instructions and option tables, and link the user page for them.
- Leave out the wording of an error message, so a new wording changes no design page. State the
  condition that `box` refuses. A section on how `box` builds a message may show its form with
  placeholders, such as `policy.dw:<line>: <message>`. Link `troubleshooting.md` for a message
  that does not say what to do.
- Use a diagram for a structure or an order of events.

## Precise prose for everything else

Decision entries, dev guides, and agent guidance are for engineers. They can be dense.
They are exact about mechanism: which process, which file, which check, which order.

- Write plain English: short declarative sentences, present tense, active voice, one instruction
  for each sentence.
- Name the symbol, the type, or the test. Never cite `file.rs:LINE`, because a line number goes
  stale on the next edit.
- State the present. Git history holds the past, so no "Updated" line, no "previously", and no
  "as of".
- Readable still matters. A reader must get the point of an entry or a section from its first
  sentence.

## For both voices

- **No em-dashes and no en-dashes** in `docs/cli/`, `docs/design/`, pack and policy READMEs, and
  decision entries. Use a period, a comma, a colon, or parentheses. Write ranges as "1 to 64".
- **No emoji.**
- **No filler or marketing words.** `just prose` checks the files that the dash rule names, and
  flags these:

  ```text
  robust, powerful, seamless, effortless, elegant, comprehensive, flexible, simply, easily,
  gracefully, leverage, utilize, delve, crucial, vital, pivotal, boasts, notably, importantly,
  remarkably, basically, additionally, moreover, furthermore, "it's worth noting",
  "it's important to", "in order to", "as mentioned", "plays a key role", "serves as",
  "not just X, but Y", cutting-edge, state-of-the-art
  ```

- **Say a list once.** If the last sentence named the items, do not walk through them again.
- **Code, paths, flags, keys, and variables go in backticks.**
- **A Dogwood rule in an example takes three lines.** Put `@id(...)` on its own line, the effect
  and scope (`permit (...)` or `forbid (...)`) on the next, and `when { ... }` or `unless { ... }`
  on the line after that. A long condition may wrap inside the braces. Put a blank line between
  rules. A rule that `box` writes itself, or text that shows what `box` prints, stays as `box`
  prints it.

  ```text
  @id("no_dynamodb")
  forbid (principal, action == Box::Action::"net:connect", resource)
  when { context.input.host like "*dynamodb*" || context.input.host like "*ddb.*" };
  ```
- **Diagrams show the main path.** Use a fenced `mermaid` block. No ASCII art, except a directory
  tree.

### Terms in user and design prose

In `docs/cli/`, pack READMEs, and `docs/design/cli/`, write "the surrounding OS" for the operating
system a box runs under, not "the host", and "operator" for the person who runs `box`, not "user".
A network host that the agent reaches is still "a host". Code, identifiers (such as the `host`
module), quoted output, and "host binary" are exempt. Box
Core's [terminology page](../../docs/design/terminology.md)
holds the full list.

"Your project" is the folder the operator starts `box` from, the working directory that a run
uses as its workspace. `how-box-works.md` defines it, and a user page that first names the project
in a section about access says so in a clause. Write "project", not "workspace", outside code and
placeholders such as `${{ workspace }}`.
