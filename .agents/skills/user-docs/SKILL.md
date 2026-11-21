---
name: user-docs
description: Write or rewrite a page in docs/cli/, or a shipped pack's or plugin's README.md, for an operator who runs box, in plain English a person can read aloud. Use when asked to document a command, a flag, a profile setting, or a failure for operators, to write a getting-started, how-to, or reference page, or when a change makes a user page wrong. Not for docs/design/cli/ (design pages, see writing.md) or decisions.md (use the decision skill).
---

# User docs

A page in `docs/cli/`, or a pack's `README.md` in `resources/packs/<pack>/`, is for a person at a
terminal. They want to run their agent in a box and get
back to work. Write the page for them, in the plain-English voice of
[`writing.md`](../../references/writing.md#plain-english-for-user-pages). Accuracy is required, but
it is not enough: a correct page that a person cannot follow is wrong.

## Inputs

- **Topic**: the command, setting, task, or failure. Required.
- **Target page**: a path in `docs/cli/`, `resources/packs/<pack>/README.md`, or `resources/plugins/<plugin>/README.md`, if known.

## Process

### 1. Place it

1. Read [`writing.md`](../../references/writing.md) and
   [`docs/cli/README.md`](../../../docs/cli/README.md). When the target page has front matter, read it
   ([Front matter](../../references/writing.md#front-matter-the-pages-reader-and-test)). A fact
   that fails its `belongs` test goes to the page that the test names, not to this page.
2. Choose the page type: tutorial, overview, topic, how-to, reference, troubleshooting, or limits. Every command has a section in
   `cli.md` and every flag a row in its command's table, and every profile key has a row in
   `profiles-reference.md`, and every key that only a pack writes a row in `packs-reference.md`. A part of `box`, such as profiles, gets a topic page that explains it and holds its tasks,
   such as `profiles.md`. `getting-started.md` is the only tutorial, and `how-box-works.md` the
   overview of every part. A reference fact goes on the page that
   owns it ([Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives)). A how-to names the
   keys its task uses, in an example, and links the reference for the rest.
3. Prefer a section in an existing page to a new page. Make a new page only for a new task, or for a
   part of `box` that has no topic page. Ask the user before you add a page.
4. A fact that holds only for one shipped pack goes in that pack's `resources/packs/<pack>/README.md`,
   and `docs/cli/` does not name it, not even as a link
   ([Pack READMEs](../../../crates/cli/AGENTS.md#pack-readmes)). The exception is `getting-started.md`, the
   Claude Code tutorial: it keeps the Claude Code facts an operator needs to finish it. A pack
   README follows this skill too. So does a plugin's `resources/plugins/<plugin>/README.md`, for a
   fact that holds only for that plugin.

### 2. Get the facts from the code

Read the code that owns each fact. Do not copy it from a design page. The code is the source of
truth for each fact, not for what the page includes: document what the reader needs to act, not
everything the code does ([Page types](../../references/writing.md#page-types)).

| Fact | Source |
| --- | --- |
| Commands, flags, defaults, help text | `crates/cli/app/src/main.rs` |
| Error messages | `crates/cli/profile/src/error.rs` and the module that returns the error |
| Packs that `box` ships | `resources/packs/` |
| Paths and variables | `crates/cli/profile/src/profile.rs`, `crates/cli/app/src/resources.rs`, `crates/cli/app/src/run.rs` |

Then run what the page will show. Use a temporary home, so you do not touch the real `~/.strands/box`.
`box` finds the agent and the toolchains under the home, so link in the directories they need:

```sh
cargo build --workspace
real="$HOME"
export HOME="$(mktemp -d /var/tmp/bx.XXXX)"   # Box Core refuses a home under /tmp, and $TMPDIR makes its socket path too long
mkdir -p "$HOME/.local/share"
ln -s "$real/.local/share/claude" "$HOME/.local/share/claude"   # Claude Code
ln -s "$real/.rustup" "$HOME/.rustup"; ln -s "$real/.cargo" "$HOME/.cargo"   # cargo
./target/debug/box profile create claude
```

Copy the real output. Replace the temporary home with `/Users/you` and keep the `~` paths that
`box` prints. Shorten a block only where it holds a value that varies, and label it "Example
output". If you cannot run a step (it needs Box Core or a model credential), say so in your
report and take the output from a test or from `docs/dev/manual-testing.md`.

### 3. Outline and shape

Write each section heading as the question or the task it answers. For a new page, or a change to
a page's structure, show the outline to the user before you draft.

Check the shape on every edit, not only for a new page. Before you add a section or a paragraph,
check that the page still has the shape of its
[type](../../references/writing.md#page-types). A new flag is one row in its command's table. A
new key is one row in its table. Put a fact that does not fit the shape on its owner, on the design
page, or nowhere.

### 4. Draft

- Open with what the reader will do on the page, then follow its type's shape.
- For each step: the goal, the command, then what the reader sees.
- Write each sentence the way you would say it to a colleague. Read each paragraph aloud.
- Leave out internals: module names, types, the order of internal checks, and design history.

### 5. Cut and give it rhythm

Cut what the reader does not need for this task. Look first for facts that belong on another page,
then for a list said twice, then for a sentence that repeats the one before it.

Then read the page aloud and apply [Rhythm](../../references/writing.md#rhythm-sound-like-a-person).
Find each run of short sentences with the same shape and join or vary them. Find each section that
opens and closes like its neighbor and change one.

### 6. Check

```sh
just prose
```

For `cli.md`, compare the page with `./target/debug/box <command> --help` for each command. Each
flag appears in its command's section, and the page names no flag that does not exist.

### 7. Review in a fresh context

Run two reviews, each in a subagent with no other context, and give each only the page.

1. **Cold read.** "You are an operator who uses Claude Code every day and has never used `box`.
   Follow this page. Report each place where you got stuck or had to guess, each section you
   skipped, each thing you had to search for, and each thing on the page you could not act on."
2. **Voice.** "Review this page against `.agents/references/writing.md`. Report sentences a person
   would not say, runs of uniform sentences, sections with the same shape, filler, and repetition.
   Give a verdict: Ship it, Tighten, or Rethink."

Fix a finding by rewriting the sentence or the step, not by adding a paragraph. Cut a section the
reader skipped and a thing they could not act on, unless another reader needs it. A page grows only
when the reader was blocked. Run the reviews again until the cold read reports no blocker and the
voice review says Ship it, for at most three rounds. Skip a finding that only reverses an earlier
fix: reviewers differ in taste. Then stop and report what the reviews still
find.

### 8. Link it

A new page gets one line in `docs/cli/README.md`. Update the links on the pages that lead to it.

## Report

1. The page and its type.
2. Each command you ran to check the page, and each output you could not check.
3. The review findings, the fixes, and the final voice verdict.
4. Each place where the code contradicts a decision or a design page. Report it, and do not change
   the code to match a page.

## What this skill does not do

- Send the operator to `docs/design/` for a fact they need to act. Write the fact for them, and
  link a design page only for background.
- Write a decision entry. Use the [`decision`](../decision/SKILL.md) skill.
- Document a planned behavior. Document what `box` does today.
