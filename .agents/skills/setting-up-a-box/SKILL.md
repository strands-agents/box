---
name: setting-up-a-box
description: Walk an operator through running a coding agent in a Strands Box for the first time, by following the box CLI's Get started guide step by step, or Box Core's guide when they ask for box.toml. Use when someone asks to set up Box, try Box, run an agent in a box, or follow the getting started guide. Not for changing Box itself.
---

# Setting up a box

Walk the operator through [`docs/cli/getting-started.md`](../../../docs/cli/getting-started.md)
in this checkout. Read the whole page first, then follow it step by step. The page owns every step
and every command. This skill adds only what the page can't know: that you're inside a clone.

If the operator asks for Box Core, walk
[`docs/user/getting-started.md`](../../../docs/user/getting-started.md) instead. That route writes
`box.toml` and `policy.dw` by hand. Follow the rules in the prompt under "Set up with your coding
agent" on that page.

## Rules

Don't run `box run` yourself, because it starts an interactive agent. Give the operator the exact
command to run in their own terminal. To create or change a profile yourself, run `box help agent`
and follow it in place of the page's interactive `box profile create` step.

## In a clone

- Use the pages in this checkout, not the copies on GitHub, so the steps match the code you build.
- Offer to build `box` from this checkout in place of the installer. Run `just build-cli` here,
  then put `target/debug` on the operator's `PATH` the way
  [Build from source](../../../docs/cli/install.md#build-from-source) does.
- For Box Core, offer to run `cargo build --release -p strands-box -p strands-box-containment`
  here, then copy the three binaries into `~/box-tutorial/box-core` the way the "Build from source"
  section of `docs/user/getting-started.md` does.

## After setup

When the operator wants to change what the box allows, use the
[`authoring-box-profile`](../authoring-box-profile/SKILL.md) skill for a profile or a pack, or the
[`authoring-box-policy`](../authoring-box-policy/SKILL.md) skill for Box Core's `policy.dw`.
