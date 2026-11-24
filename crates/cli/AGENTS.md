# CLI guidance

## The CLI is not interface-frozen

Profiles, packs, commands, and `~/.strands/box` are in development and need no migration.
The CLI owns operator experience and compiles configuration; Box Core owns enforcement.
Treat Core's schema and library API as an external dependency even in this workspace.

### When the CLI needs something Box Core lacks

Follow the [product boundary](../../AGENTS.md#two-products): the Core change lands first in its
own PR, reviewed by Core maintainers. The CLI team reviews changes to the CLI's paths.
CLI syntax can diverge from `box.toml`.
Ask Core for its lists and policy checks; copying them creates a second contract to maintain.

## Build and test traps

- `just build-cli` builds `box` and the Core helpers. Keep the helpers beside `box`;
  `cargo test` alone can run stale helper binaries. Use `just test-engine` for the real-engine suite.
- Pack behavior tests belong in `strands-box-cli-pack-tests`. Some still use private CLI fixtures,
  so also run the corresponding `strands-box-cli --lib <pack>` tests when changing a shipped pack.
  Profile-language tests stay with the profile crate.
- For a prompt or terminal change, follow [interactive testing](../../docs/dev/interactive-testing.md)
  and drive a pseudo-terminal. Captured stdout does not prove the interactive behavior works.
  [Manual testing](../../docs/dev/manual-testing.md) covers trying a PR build.
- When a CLI check starts reading a new file, include it in the `cli` path filter in
  `.github/workflows/ci.yml`; otherwise a PR can skip the check it needs.

## Docs

Document shipped surfaces in the same commit. An intermediate change with no user-facing page is
not automatically doc debt. Use `user-docs` for operator pages and
[writing.md](../../.agents/references/writing.md) for voice.
One fact has one owner; other pages show only their task's example and link to that owner.

### Where each fact lives

Paths below are relative to `docs/cli/` unless stated otherwise.

| Fact | Owner |
| --- | --- |
| Profile keys and rules shared with packs | `profiles-reference.md` |
| Pack-only keys | `packs-reference.md` |
| Plugin keys and rules | `plugins-reference.md` |
| Commands, flags, `BOX_*`, exit status | `cli.md` |
| Installation and installer variables | `install.md` |
| Files under `~/.strands/box` | `files.md` |
| `config.toml` and banner precedence | `config.md` |
| Starter and policy-starter keys | `starters-reference.md` |
| Policy assembly and generated rule IDs | `policies-reference.md` |
| Tasks and concepts | The matching `profiles.md`, `packs.md`, `plugins.md`, `starters.md`, `policies.md`, or `how-box-works.md` |
| Shared errors and limits | `troubleshooting.md` and `limitations.md` |
| Pack or plugin setup, options, errors, and limits | Its `README.md` under `resources/` |
| Shipped pack and plugin list | `README.md` |
| Mechanism and design rationale | `docs/design/cli/<topic>.md` and user-approved entries in `decisions.md` |
| Build, test, and debug workflow | `docs/dev/` |

### What a change updates

Update the owning page and any how-to the change makes wrong. A mechanism change also updates its
design page; a workflow change updates its developer guide. Changes to profile language or editing
also update `resources/editing-box-profile.md`, the shipped guide for agents without this checkout.
It is the one allowed copy of the profile reference.

Use sample box ID `b-5b8e3d70c92f14ab` consistently. Cite symbols and stable anchors, not line numbers
or local drafts. Reverse a decision only with the user's approval, rewriting its entry in place.

### Pack comments

Keep a pack's reasons beside the affected lines in `pack.toml`, and a plugin's in `plugin.toml`:
what breaks without a grant, helper, or setting, and why it stops where it does. Put tested versions
at the top. Shared rationale belongs in the design docs, not copies in every pack.

### Pack READMEs

- Put pack-specific operator facts beside that pack. Use exact headings `## Limitations` and
  `## Troubleshooting` so the generic pointers in `docs/cli/` work.
- Keep the single pack/plugin list in `docs/cli/README.md`. Shared pages link to that list once
  instead of accumulating each pack's behavior.
- Use Claude Code and `@box/1password` as examples of shared mechanisms. Pack-specific behavior
  stays in the pack README, except what the Claude walkthrough in `getting-started.md` needs.
- Relative links to `../../../docs/cli/<page>.md` work in the repository, but those pages do not
  ship beside installed packs. Make the README usable with that limit.

## Pull request title

Use `type(scope): subject` with a lowercase imperative subject. Types are `feat`, `fix`, `docs`,
`refactor`, `perf`, `test`, `build`, `ci`, `chore`, and `revert`; scope is optional and names the area.
For docs, `user`, `design`, or `dev` can name the guide. The root guidance owns the PR workflow.
