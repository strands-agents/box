---
name: docs-audit
description: Audit an existing page in docs/user/, docs/design/, docs/dev/, or a crate README for accuracy, placement, and voice. Use when a page may have drifted from the code, before a rewrite that needs fact checking, or for a requested documentation audit.
---

# Documentation audit

Assess one existing page, and produce a structured assessment with the fixes in priority order.

**How this differs from `docs-reviewer`.** The reviewer is a voice gate for a draft. The audit is
for a page that already exists: it checks each claim against the code and its tests, finds the
gaps, and decides what needs work. Use the audit to decide *what to fix*. Use the reviewer to decide
*that a draft can ship*.

## Inputs

- **Target page**: a path in the repository.
- **Context** (optional): an issue, a changed behavior, or a concern.

## Process

### Step 1: Read and classify

Read the page. Classify its guide and its content type. A page that mixes types is itself a
finding, and it is the most common structural problem.

### Step 2: Accuracy

Follow [`claim-verification.md`](../../references/claim-verification.md). List each claim on the
page and check it against the evidence required by that table. Behavior claims need the
implementing code and a test that pins the behavior.

**The code is the authority.** Where the page and the code disagree, the page is wrong. Name the
symbol or the test that the page disagrees with. Never recommend a code change to agree with a page.

Check each of these:

- Each `box.toml` key, type, and default against the configuration parser.
- Each CLI verb, flag, and exit code against the argument parser.
- Each policy action and field against `strands-box policy generate-schema`.
- Each binary name against what ships (`Cargo.toml`, and the staging step in
  `.github/workflows/deploy-box-artifact.yml`).
- Each developer command, prerequisite, and expected result against the script or workflow that
  owns it.
- A test still pins each behavior claim. A test name on a design page is itself a finding.
- Each `decisions.md` anchor still exists, and the decision still says what the page says.
- Each relative link resolves.
- Each claim that a test pins is not stated more broadly than the test.

### Step 3: Voice

Walk the five layers of [`voice-guide.md`](../../references/voice-guide.md): structure, framing,
register, hard constraints, and authenticity. Run
`.agents/skills/docs-reviewer/check-prose.sh <page>` for the mechanical part.

### Step 4: Stands alone

Check the list in "Readers that are people and readers that are agents" in the voice guide.

### Step 5: Comparison (optional)

Run this step only for a design page about a topic that other sandboxes also document: the
architecture, the security model, containment, egress, or credentials. Read one to three pages from
comparable projects, for example the gVisor architecture guide, the Firecracker design document, or
a coding-agent sandbox's security page. Cite each URL and the date you read it. Give one
observation for each of coverage, depth, and structure. Copy structure or coverage only, never
voice.

## Output format

```markdown
## Docs audit: <page title>

**Path:** <path>
**Guide and type:** <guide>, <type>
**Verdict:** Strong | Needs work | Significant gaps

| Layer | Score | Key finding |
|---|---|---|
| Structure | ... | ... |
| Framing | ... | ... |
| Register | ... | ... |
| Constraints | ... | <count of hits> |
| Authenticity | ... | ... |

### Accuracy issues

- <The claim, the line, and the symbol or the test it disagrees with.> Or "None found".

### Stands-alone issues

- <Each issue.> Or "Passes".

### Recommended actions

1. <The fix with the highest priority.>
2. ...

### Comparison (if run)

- <One observation per axis, with the source.>
```

## What this skill does not do

- Rewrite the page. That is `docs-writer`.
- Edit any file, or commit.
