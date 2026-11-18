---
name: docs-sync
description: Find each doc that a change makes wrong or incomplete, and report the page to update in the same commit. Read-only unless asked to fix. Use before a commit or a pull request, after a change that shipped without its docs or was made without the feature workflow, or when asked "what docs does this need", "are the docs current", "check the docs against the code", "find stale docs", or "which page does this surface belong on".
---

# Docs sync

Compare a change, or the whole repository, with the committed docs, and report each page that the
code makes wrong or leaves incomplete. The trigger table that the area file names says which surface
maps to which page, and this skill applies it.

## Areas

Each part of the repository keeps its own surfaces, pages, and trigger table, in an area file in
this skill's directory. Each area file opens with the paths that it covers. For a diff, read each
area file that covers a changed path. For `all`, read every area file. Each area file names, for its
paths:

- its trigger table, and the table of which page owns each fact;
- the kinds of surface to list in Step 1;
- the statuses it adds in Step 3, and the commands that a check needs;
- its decision log and decision skill;
- the other pages it checks;
- the skills that fix a page.

## Inputs

- **Scope**: a diff, or `all` for the whole repository. The default is the diff from the fork point
  with `origin/main`, or with the base the caller names:
  `git diff $(git merge-base <base> HEAD)`, which includes the working tree, staged or not, plus
  each new file that `git status --short` lists. If `git merge-base` prints nothing (a shallow
  clone), stop and report it. Do not run `git diff` with no ref.
- **Fix**: report only (the default), or fix each gap.

## Process

### Step 1: List the surfaces the change touches

Read the diff and list each thing that an operator or a consumer can see, with the kinds that the
area file lists. For `all`, list the current surface from the code instead of from a diff.

### Step 2: Walk the trigger table

For each surface, find its row in the area's trigger table and the page that owns the fact. Record
the row you used, because the report shows which rows you walked.

### Step 3: Check the user docs

For each surface, open the page that owns it and give it one status:

- **wrong**: the page states something that the diff makes false, or what the area file adds.
  Quote the sentence, and name the symbol that it disagrees with.
- **missing**: no page states the surface.
- **ok**: the page and the code agree.
- each status that the area file adds.

Run the commands that the area file names for this step.

### Step 4: Check the design pages

Report a design page whose parts, steps, order, files, process boundary, or tables the diff makes
false.

### Step 5: Check the decisions

1. **Decision entries.** A missing entry is never a finding. An entry that the code has passed by,
   with no help from this diff, is never a finding: the log can lag the code. When the diff goes
   against what an entry in the area's decision log says, report one note that names the anchor,
   and it never blocks. The pull request then fits the code to the entry, or rewrites the entry,
   and a human approves the rewrite. A pull request that changes what an entry says fixes that
   entry.
2. Report two entries that contradict each other, or that answer the same question in two ways.

Do not sweep the log for stale names.

### Step 6: Check the other pages that the area file names

Each area file names the pages beyond the user docs, the design pages, and the decision log that a
change can make wrong, and what to report for each.

### Step 7: Report

```markdown
## Docs sync: <scope>

| Page | Section | Status | What is wrong | Fix |
|---|---|---|---|---|
| ... | ... | wrong / missing / <an area status> | ... | ... |

### Trigger-table rows walked

- <row> -> <page> -> <status>

### Checks run

List each check and each command you ran, with its result. Name each command you did not run and
the surface it bears on, so that a reader can see it was a choice.
```

Put the most serious gap first. Add each section that the area file adds. When there is nothing to
fix, say so, and still list the rows you walked. Silence reads as "not checked".

## Fixing

When asked to fix, use the skills that the area file names. Change a decision entry only with the
area's decision skill, and only when the user decides the question.

## Rules

- **Report only what the trigger table requires.** A longer page is not a better page.
- **Never change code to make a page true.** Report the mismatch, and name the symbol.
- **The code is the authority.** Where a page and the code disagree, the page is wrong.
