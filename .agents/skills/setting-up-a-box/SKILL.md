---
name: setting-up-a-box
description: Walk an operator through running an agent in a Strands Box for the first time, by following the getting started guide step by step. Use when someone asks to set up Box, try Box, run an agent in a box, or follow the getting started guide. Not for changing Box itself.
---

# Setting up a box

Walk the operator through [`docs/user/getting-started.md`](../../../docs/user/getting-started.md)
in this checkout. Read the whole page first, then follow it step by step. The page owns every step
and every command. This skill adds only what the page can't know: that you're inside a clone.

## Rules

Follow the rules in the prompt under "Set up with your coding agent" on that page. They say what
to check first, when to ask, and what never to do: don't touch the Bedrock API key, and don't run
`box run`.

## In a clone

- Use the page in this checkout, not the copy on GitHub, so the steps match the code you build.
- Offer to build Box from this checkout in place of the download. Run
  `cargo build --release -p strands-box -p strands-box-containment` here, then copy the three
  binaries into `~/box-tutorial/box-core` the way the page's "Build from source" section does.

## After setup

When the operator wants to change what the box allows, use the
[`authoring-box-policy`](../authoring-box-policy/SKILL.md) skill.
