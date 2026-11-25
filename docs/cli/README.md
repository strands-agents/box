# Box CLI guide

Box runs a coding agent, such as Claude Code, in a box on your machine. The agent can change files
in your project and reach what your profile allows, and the box stops everything else. This guide
shows how to set it up, run it, and change what the agent can reach.

## Common tasks

- [Run Claude Code in a box for the first time](getting-started.md)
- [Add another agent or model provider](profiles.md#make-a-profile-for-another-agent-or-provider)
- Let the agent reach [another host](profiles.md#let-the-agent-reach-another-host) or
  [another folder](profiles.md#give-the-agent-another-directory)
- [Pick the agent's policy](starters.md#pick-the-agents-policy), or
  [write custom rules](policies.md#write-custom-rules)
- [Give your team one standard setup](starters.md#build-a-team-starter)
- See what the box denied: [in the banner](cli.md#the-activity-banner) while it runs, or
  [with `box runs history`](cli.md#box-runs-history) afterward
- [Fix an error](troubleshooting.md)
- [Find out what a box doesn't protect you from](limitations.md)

## Tutorial

- [Get started](getting-started.md): install Box and run Claude Code in a box in your project.

## Topics

- [Profiles](profiles.md): what a profile decides and where it lives, then how to set up another
  agent or provider, change a setting or a toolchain, and change what the agent can reach.
- [Packs](packs.md): what a pack is and where it lives, then how to write one for an agent, a
  tool, or settings that a team shares.
- [Plugins](plugins.md): what a plugin is, how to read a key from your password manager with one,
  and how to write one.
- [Credentials](credentials.md): where a route's key comes from, such as a variable in your shell,
  your AWS credentials, the credentials daemon, or a password manager.
- [Starters](starters.md): what a starter is and where it lives, how to make a profile from one,
  and how to write a starter or a policy starter so your team gets one standard setup.
- [Policies](policies.md): what a policy checks, where a run's rules come from, including the ones
  your packs and profile settings write, and how to write your own.

## How-to

- [Install Box](install.md): install, upgrade, or remove a release.
- [Get help from a coding agent](profiles.md#get-help-from-a-coding-agent): tell your agent
  `Run box help agent and follow it to create a profile.`

## Reference

- [Command reference](cli.md): every `box` command, flag, variable, and exit status.
- [Where Box keeps its files](files.md): what each folder in `~/.strands/box` holds, and where your own
  packs and policies go.
- [Profile reference](profiles-reference.md): every key a profile can hold, and the rules that
  profiles and packs share.
- [Pack reference](packs-reference.md): every key that only a pack writes.
- [Plugin reference](plugins-reference.md): every key a plugin can hold, and the rules for plugins.
- [Starter reference](starters-reference.md): every key a starter and a policy starter can hold.
- [Box config reference](config.md): the `config.toml` tables that set the starter and policy
  menus, and the banner, for every profile.
- [Policy reference](policies-reference.md): how `box` joins a run's policy, and each rule it
  writes.
- [Usage telemetry](../../CLI_TELEMETRY.md): what `box` sends about your runs, and how to turn it off.

## Help

- [Troubleshooting](troubleshooting.md): what an error means, and how to fix it.
- [Limitations](limitations.md): what a box doesn't protect you from, and what to check before
  you trust a run.
- [Where file rules apply](file-rules.md): which processes a policy's file rules check, how to keep
  a file from every process, and how native filesystem policy will change that.

## Concepts

- [How Box works](how-box-works.md): the box, profiles, packs, starters, policy, and credentials,
  and how they fit together.

## Packs

These are the packs that Box ships. A pack that has its own setup steps, options, limits, and
fixes keeps them in a README, linked here.

**Shared settings**

- [`@box/base`](../../resources/packs/base/README.md): the terminal settings that every shipped agent pack includes

**Agents**

- [`@box/claude`](../../resources/packs/claude/README.md): Claude Code
- [`@box/codex`](../../resources/packs/codex/README.md): Codex
- [`@box/kiro`](../../resources/packs/kiro/README.md): Kiro CLI
- [`@box/pi`](../../resources/packs/pi/README.md): pi

**Model providers**

- [`@box/bedrock`](../../resources/packs/bedrock/README.md): Amazon Bedrock
- `@box/bedrock-mantle`: Amazon Bedrock's OpenAI-compatible endpoint, for Codex
- `@box/anthropic`: the Anthropic API
- [`@box/claude-subscription`](../../resources/packs/claude-subscription/README.md): a claude.ai subscription, for Claude Code
- `@box/openai`: the OpenAI API, for Codex

**Tools**

- `@box/bunx`
- [`@box/cargo`](../../resources/packs/cargo/README.md)
- [`@box/gh`](../../resources/packs/gh/README.md)
- [`@box/git`](../../resources/packs/git/README.md)
- [`@box/go`](../../resources/packs/go/README.md)
- [`@box/node`](../../resources/packs/node/README.md)
- [`@box/npm`](../../resources/packs/npm/README.md)
- [`@box/npx`](../../resources/packs/npx/README.md)
- [`@box/pnpm`](../../resources/packs/pnpm/README.md)
- [`@box/pnpx`](../../resources/packs/pnpx/README.md)
- [`@box/rg`](../../resources/packs/rg/README.md)
- [`@box/uv`](../../resources/packs/uv/README.md)
- [`@box/uvx`](../../resources/packs/uvx/README.md)
- [`@box/yarn`](../../resources/packs/yarn/README.md)

## Plugins

A plugin lets the box read a secret from your password manager or secret store when it starts.
Each plugin that Box ships says in its README how to sign in, what it passes to its program, and
what it can't do.

- [1Password](../../resources/plugins/1password/README.md)
- [AWS Secrets Manager](../../resources/plugins/aws-secrets-manager/README.md)
