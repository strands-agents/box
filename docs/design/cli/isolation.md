# Isolation between boxes

The profile is the unit of isolation. Each box of a profile can read and change what a later box of
the same profile keeps, loads, or runs, in any project. Boxes of two profiles share no storage.
The reason for this model is an entry in
[decisions.md](decisions.md#storage-is-one-directory-per-profile-and-workspace). The operator
guide is [limitations.md](../../cli/limitations.md#one-profile-is-shared-by-all-projects).

## What a box keeps

| State | Scope | Where |
| --- | --- | --- |
| Agent storage: settings, instructions, skills, memory, sessions | Profile | `~/.strands/box/storage/<profile>/default/agent/<dir>/` |
| MCP launcher caches, which are also each server's `TMPDIR` | Profile | `~/.strands/box/storage/<profile>/default/mcp-cache/<launcher>/` |
| A tool's own storage, such as the rustup toolchains that `cargo` runs | Profile | `~/.strands/box/storage/<profile>/default/tool/<tool>/<dir>/` |
| Agent tool caches, such as `CARGO_HOME` | Project | The workspace |
| Box directory, temporary files of the agent's tools | Run | `~/.strands/box/r/<id>/` |

[profile-language.md](profile-language.md#storage) states the storage layout. Boxes in different
projects use the profile's storage at the same time.

## Why no project scope

A project scope for some state does not keep projects apart while other state is shared. A box in
project A can write a hook or an instruction into agent storage. The next box in project B loads
it, and it runs with the agent's grants there. It can then write code that B's tools and servers
run, such as a `build.rs` for `cargo` or a project-local package for `npx`. So all state that
persists between runs has one scope, the profile.

## How to isolate

- Two projects that must stay apart use two profiles.
- Two boxes of one profile in one project share all of the state above, except the run scope.

## Namespaces

`default` is the one namespace of a profile's storage. A later option can add a namespace for
each project beside it, without a move of existing storage. A namespace holds all of the state
above that has the profile scope, so it isolates projects together. The profile selects the
namespace, as it states every other grant
([decisions.md](decisions.md#box-run-takes-no-option-values)). A file in the workspace never
selects it.
