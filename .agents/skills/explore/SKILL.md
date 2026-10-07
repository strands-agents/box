---
name: explore
description: Launch a deep, multi-faceted investigation of a topic using parallel sub-agents. Each agent tackles a different angle simultaneously, and findings are synthesized into structured exploration documents.
---

# Explore Skill

Launch a deep, multi-faceted investigation of a topic using parallel sub-agents. Each agent tackles a different angle simultaneously, and findings are synthesized into structured exploration documents.

## Skill Invocation

`/explore <topic>` or `/explore <topic> --scope <narrow|wide>`

Examples:
- `/explore authentication patterns in this codebase`
- `/explore how the routing system works end-to-end`
- `/explore AWS SDK usage and error handling --scope wide`
- `/explore state management across components`

Output: `.agents/explorations/YYYY-MM-DD/<topic-slug>/<context>.exp.md`

A prototype that an exploration needs goes to `.agents/pocs/<topic-slug>/`, one directory
per POC. Git ignores both trees, and the Cargo workspace excludes `.agents/pocs/`.

## Output Structure

```
.agents/explorations/
  YYYY-MM-DD/
    auth-patterns/                  # One exploration
      overview.exp.md               # Synthesis of all findings
      token-validation.exp.md       # Facet deep dive
      session-management.exp.md     # Facet deep dive
      ...
    state-management/               # Another exploration same day
      overview.exp.md
      redux-usage.exp.md
      ...
```

Each exploration gets its own **topic subfolder** under the date. This allows multiple explorations per day without collision. The `overview.exp.md` inside each topic folder ties that exploration's facets together.

## Workflow

### 1. Scope the exploration

Before launching agents, understand what we're exploring:

1. Read the topic and identify **3-6 distinct facets** worth investigating independently
2. Present the facets to the user for confirmation:
   - "I'll explore **{topic}** across these angles:"
   - List each facet with a one-liner on what the agent will investigate
   - Ask: "Want to adjust any of these, or should I launch?"

**Facet selection guidelines:**
- Each facet should be independently researchable (no dependencies between agents)
- Cover breadth: code patterns, architecture, data flow, error handling, tests, external dependencies
- Cover depth: don't just list files — trace execution paths, understand why decisions were made
- Include at least one "connections" facet that maps how the topic interacts with the rest of the system

### 2. Launch parallel sub-agents

Dispatch **one agent per facet** using the Agent tool, all in a single message for maximum parallelism.

Each agent prompt must include:
- **What to investigate**: The specific facet and what questions to answer
- **How deep to go**: Trace call chains, read implementations, check tests, examine error paths
- **What to report**: Structured findings with file paths, line numbers, code snippets, and diagrams
- **Output format**: Markdown with headers, code blocks, and mermaid diagrams where helpful

**Agent prompt template:**
```
You are exploring: {topic} — specifically the "{facet}" angle.

## Investigation goals
{2-3 specific questions this agent should answer}

## How to investigate
- Read source files, trace execution paths, check test coverage
- Look at imports/exports to understand dependency graphs
- Check for patterns, anti-patterns, inconsistencies
- Note anything surprising or potentially problematic

## Report format
Return a structured markdown report with:
1. **Summary** (2-3 sentences)
2. **Findings** (detailed, with file:line references and code snippets)
3. **Diagram** (mermaid diagram showing relationships/flow)
4. **Observations** (patterns, risks, opportunities, surprises)

Be thorough. Include file paths and line numbers for every claim.
Do NOT write any files — just return your findings as text.
```

### 3. Synthesize findings

Once all agents complete:

1. **Read all agent results** carefully
2. **Identify cross-cutting themes** — patterns that appear across multiple facets
3. **Flag contradictions** — where one agent's findings conflict with another's
4. **Rank findings by impact** — what matters most for the user's goals

### 4. Write exploration documents

Derive a **topic slug** from the exploration topic (kebab-case, 2-4 words, e.g. `auth-patterns`, `routing-system`, `sdk-error-handling`). Create the output folder:

```
.agents/explorations/YYYY-MM-DD/<topic-slug>/
```

**overview.exp.md** (write this LAST, after all facet docs):
```markdown
# {Topic} — Exploration Overview

> Explored on YYYY-MM-DD

## TL;DR

{3-5 bullet points with the most important findings}

## Facets Explored

| Facet | Key Finding | Doc |
|-------|-------------|-----|
| {facet-1} | {one-liner} | [{facet-1}.exp.md](./{facet-1}.exp.md) |
| {facet-2} | {one-liner} | [{facet-2}.exp.md](./{facet-2}.exp.md) |
| ... | ... | ... |

## Cross-Cutting Themes

{Patterns and insights that emerged across multiple facets}

## Risks & Opportunities

{Things that look fragile, inconsistent, or ripe for improvement}

## Open Questions

{Questions that came up but weren't fully answered — threads to pull later}
```

**Each facet doc** (`<facet-name>.exp.md`):
```markdown
# {Topic} — {Facet Name}

> Part of [{Topic} exploration](./overview.exp.md) | YYYY-MM-DD

## Summary

{2-3 sentence overview of this facet}

## Findings

### {Finding 1}

{Detailed explanation with code references}

```language
// file/path:line — relevant code snippet
```

### {Finding 2}

{...}

## Architecture / Flow

```mermaid
{diagram showing relationships, data flow, or structure}
```

## Observations

- **Pattern**: {something consistent found}
- **Risk**: {something fragile or concerning}
- **Opportunity**: {something that could be improved}
```

### 5. Present results

After writing all files, give the user a concise summary:
- Link to `overview.exp.md`
- Top 3 most important/surprising findings
- Any open questions or recommended next steps

## Guidelines

**Go deep, not wide.** Each agent should trace code paths to their endpoints, not just grep for keywords. Read implementations, understand control flow, check edge cases.

**Every claim needs evidence.** File paths, line numbers, code snippets. No hand-waving.

**Mermaid diagrams are mandatory** for each facet doc. They should illuminate structure or flow that's hard to see from code alone.

**Quote every edge label and compile every block.** Write `A -.->|"read(2)"| B`: unquoted labels fail
the lexer when they contain `(` or `|`, and quoting always parses. Compile with
`mmdc -i block.mmd -o /tmp/block.svg`, after
`export PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"` —
`mmdc` drives a headless browser and finds none by default, so without that variable it reports a
launch failure that reads like "mermaid is unavailable". A grep check cannot see a lexer error.

**Name files descriptively.** Use kebab-case names that describe the facet: `error-handling.exp.md`, `data-flow.exp.md`, `test-coverage.exp.md`, not `part-1.exp.md`.

**Date folders use today's date** in `YYYY-MM-DD` format. Each exploration gets its own topic subfolder, so multiple explorations on the same day never collide.

**Agent count:** Aim for 3-6 parallel agents. Fewer than 3 isn't deep enough. More than 6 risks shallow coverage per agent.
