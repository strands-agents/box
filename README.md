<div align="center">
  <div>
    <a href="https://strandsagents.com">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://strandsagents.com/latest/assets/wordmark-github-dark.svg">
        <img src="https://strandsagents.com/latest/assets/wordmark-github-light.svg" alt="Strands" width="320">
      </picture>
    </a>
  </div>

  <h1>Strands Box</h1>

  <h2>Run coding agents like Claude Code in a sandbox, under a policy you control.</h2>

  <div align="center">
    <a href="https://github.com/strands-agents/box/graphs/commit-activity"><img src="https://img.shields.io/github/commit-activity/m/strands-agents/box" alt="Commit Activity"></a>
    <a href="https://github.com/strands-agents/box/issues"><img src="https://img.shields.io/github/issues/strands-agents/box" alt="Open Issues"></a>
    <a href="https://github.com/strands-agents/box/pulls"><img src="https://img.shields.io/github/issues-pr/strands-agents/box" alt="Open PRs"></a>
    <a href="https://discord.gg/Wa4CQrxsP"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  </div>

</div>

<hr>

## Overview

With `box`, you run a coding agent such as Claude Code, Codex, Kiro CLI, or pi in a box on your own
machine. The agent can work in your project and reach whatever you allow. Your other files, your
keys, and services that listen only on localhost stay out of its reach. You use the agent the way
you always do, with its permission prompts off if you like.

Underneath `box` is [Box Core](#box-core), an engine you can also use on its own. `box` itself is in
preview, and it works on Apple silicon Macs with macOS 15 or later and on Linux ARM64 and x86-64.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/strands-agents/box/main/install.sh | sh
```

Or with Homebrew:

```sh
brew install --cask strands-agents/tap/box
```

Then open a new terminal and run `box --version` to check that it worked. For the Linux
requirements, upgrading, and uninstalling, see [Install Box](docs/cli/install.md).

## Run your first agent

You set up each agent once, in a profile, and then start it from any of your projects. For Claude
Code on Amazon Bedrock, install Claude Code with its
[native installer](docs/cli/getting-started.md#requirements), then create the profile:

```sh
box profile create claude --with bedrock
```

Press Enter to take each default, then choose **Save profile** and **Exit**. You'll need to
[connect to Bedrock](docs/cli/getting-started.md#3-connect-to-bedrock), and choose a model if
Claude Code doesn't already name one, before the first run. Then start Claude Code from the folder
you want it to work in:

```sh
cd ~/src/my-app
box run claude
```

For the full walkthrough, see [Get started](docs/cli/getting-started.md).

## How Box works

![The agent runs in an OS sandbox inside the box. Its requests go to Box, which checks each one against your policy before it reaches files, commands, the network, or MCP tools. Denied requests stop there.](docs/cli/images/how-box-works.png)

The agent runs in an operating system sandbox, so its own reads and writes stay within the files you
grant it. Box checks each shell command, network request, and MCP tool call against your policy
before it happens, and it does that outside the model, where nothing the agent reads can change the
answer.

You write policies in [Dogwood](https://dogwood-policy.github.io/dogwood/), or start from one that
comes with `box`. A rule can even depend on what the agent already did, such as a limit of 60 calls
to a server in an hour.

Your keys stay outside the box, too. When the agent calls its model or another service you've set
up, it only sees a placeholder, and Box puts in the real key as the request leaves.

To see how it all fits together, read [How Box works](docs/cli/how-box-works.md).

## Learn more

- [Box CLI guide](docs/cli/README.md): common tasks, and every page about `box`.
- [Profiles](docs/cli/profiles.md): set up another agent or model provider, or change what the
  agent can reach.
- [Get help from a coding agent](docs/cli/profiles.md#get-help-from-a-coding-agent): tell your
  agent `Run box help agent and follow it to create a profile.`
- [Troubleshooting](docs/cli/troubleshooting.md): what an error means, and how to fix it.
- [Command reference](docs/cli/cli.md): every command and flag.
- [Limitations](docs/cli/limitations.md): what a box doesn't protect you from. Read this before you
  trust a run with work that matters.
- [Design guide](docs/design/README.md): how Box works inside, and why.

## Box Core

Box Core is the engine under `box`. You can run it yourself, on your own machine or a cloud host, or
embed it in a Rust application. Instead of a profile, you describe each box in `box.toml` and its
policy in `policy.dw`. To download Box Core into `./box-core`:

```sh
curl -fsSL https://raw.githubusercontent.com/strands-agents/box/main/download.sh | sh
./box-core/box --version
```

Start with [Run an agent with box.toml](docs/user/getting-started.md). After that, you'll find the
`box.toml` reference, the policy guides, and cloud deployments in the
[Box Core guide](docs/user/README.md), and finished setups you can run in the
[examples](examples/README.md). To embed Box Core in your own application, see
[Use Box as a Rust library](crates/box/README.md#use-box-as-a-rust-library).

## Build from source

To build `box` yourself, you need [rustup](https://rustup.rs/) and
[`just`](https://github.com/casey/just):

```sh
git clone https://github.com/strands-agents/box.git
cd box
just build-cli
```

You'll find `box` and the Box Core programs it runs in `target/debug`. For the tests and the other
builds, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a problem

If something goes wrong, open an [issue](https://github.com/strands-agents/box/issues) with the
command you ran, what you expected, what happened instead, and the output of `box --version`. If
you think you've found a security problem, read [SECURITY.md](SECURITY.md) first.

## License

Apache License 2.0.
