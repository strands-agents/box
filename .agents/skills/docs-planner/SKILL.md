---
name: docs-planner
description: Find the gaps in the Box documentation and produce a prioritized backlog for docs/user/ and docs/design/. Use when planning documentation work, after a feature or a binary ships without a page, for a periodic health check of the docs, or when asked "what docs need writing", "plan the docs work", "prioritize the docs backlog", or "what should we document next".
---

# Documentation planner

Find the gaps in the user guide and the design guide, and produce a backlog in priority order.

## Inputs

- **Scope**: all docs, one guide, or one area. The default is all docs.
- **Signals** (optional): issues, questions from operators, or review findings.

## Process

### Step 1: Inventory

List each page in `docs/user/` and `docs/design/`, and each crate `README.md` that serves a
consumer. For each page, record its guide, its content type, and its area. Also read:

- `docs/README.md` and the `README.md` of each guide, for the stated structure.
- The "still to come" list in `docs/design/README.md`, for the planned design pages.

### Step 2: Find the gaps

Compare the inventory with each of these:

- **The product surface.** Each CLI verb, each `box.toml` top-level key, each process
  specification key, each filesystem list, the policy action vocabulary, and each binary that
  ships. A part of the surface with no page is a gap.
- **The content types.** For each area, the user guide needs a how-to and a reference, and the
  design guide needs an explanation. An area with a reference and no how-to has a gap.
- **The premises in `AGENTS.md`.** Each premise needs a design page that explains it to a security
  evaluator. A premise that only `AGENTS.md` explains is a gap.
- **Signals.** If `gh` is available, read the open issues in the repository that mention docs. Map
  each to a page that is unclear or to a page that is missing.

### Step 3: Prioritize

- **P0, do now.** High impact, at any effort. Getting started, the architecture overview, and the
  security model.
- **P1, do soon.** Medium impact, low effort. A how-to for a common task, or a reference for a
  surface that has none.
- **P2, plan for.** Medium impact, high effort. An enforcement page, or the platform differences.
- **P3, backlog.** Low impact. An edge case.

### Step 4: Write the backlog

```markdown
## Docs backlog: <scope>

**Date:** <date>
**Pages inventoried:** <count>
**Gaps found:** <count>

### P0: do now

- [ ] <Task>: <content type>, <target path>. <Reason.>

### P1: do soon

...

### Coverage

| Area | Tutorial | How-to | Reference | Explanation |
|---|---|---|---|---|
| Running a harness | Y | ~ | N | N |
| Filesystem grants | N | N | ~ | N |
| Binaries | N | N | N | N |

### From signals

- <A theme from the signals, and the gap that it maps to.>
```

`Y` is covered, `~` is partial, and `N` is missing.

## What this skill does not do

- Write a page. That is `docs-writer`.
- Create issues or tasks in an external tool.
