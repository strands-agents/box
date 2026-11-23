# ripgrep in a box (`@box/rg`)

The `@box/rg` pack lets the agent run the `rg` that your `PATH` finds, such as ripgrep from
Homebrew, `cargo install`, or your system's package manager. `box profile create codex` adds it
to the profile's `packs`, because Codex searches with `rg`. To take the tool away, delete
`"@box/rg"` from `packs`. If `rg` isn't on your `PATH`, `box run` skips the tool and says so.

For a Codex profile made before this pack, or for another agent such as Claude Code, add
`"@box/rg"` to the profile's `packs`. Claude Code searches with its own Grep tool, which needs no
tool in the box.

## What rg can reach

`rg` reads your project, as [Project access](../../../docs/cli/profiles-reference.md#project-access)
allows, and can't change it, even with `access = "write"`. It writes only to its own `TMPDIR`. The
pack names no package host.

## Limitations

- `rg` reads nothing in your home folder outside the project, and the box doesn't pass it
  `RIPGREP_CONFIG_PATH`. So it uses no ripgrep configuration file, and no global ignore file from
  your git configuration. It still uses the `.gitignore`, `.ignore`, and `.rgignore` files in your
  project.
- `rg --pre <program>` and `rg --hostname-bin <program>` start the program that the agent names,
  and your policy doesn't decide it. That program runs with `rg`'s access, so the agent can run a
  program that it wrote in the project, as it can with `node` or `git`.
