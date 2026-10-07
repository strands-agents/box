# Codex CLI in a box

[Codex CLI](https://github.com/openai/codex) run under a [policy](../../docs/user/policy.md) on
a Mac, with the project out of its own reach. Its shell tool is its only way to a project file, and
each command it runs goes to the [box's shell](../../docs/user/shell.md), so the policy decides
every command and every file a command reads, writes, or deletes. The task comes from the command line.

[The tutorial](../../docs/user/tutorials/codex-cli.md) walks through this example step by step,
with the output of each run.

## Files

- `box.toml`: what the box runs and what Codex's own process can reach: its configuration and
  session directory, its temporary directory, and the names in the project. Its `command` also
  switches Codex's own spans, log records, and metrics on, as [Telemetry](#telemetry) describes.
- `policy.dw`: the policy. It permits Bedrock, the shell, reads and writes in the project, and
  `/dev/null`. Two of its `forbid` rules, which the tutorial exercises, refuse the project's `.env`
  file and every delete.
- `config.toml`: Codex's configuration. It selects the model and the Bedrock endpoint, and turns
  Codex's own sandbox off, so each command it runs goes to the box's shell.
- `AGENTS.md`: Codex's instructions. They tell it to read and edit files with shell commands.

## Before you start

- A Mac with Apple silicon and macOS 15 or later, and Box in `~/box-tutorial/box-core` from
  [getting started](../../docs/user/getting-started.md).
- The project in `~/box-tutorial/my-project` from getting started, with its `README.md`.
- Codex CLI from Homebrew's `npm`: `/opt/homebrew/bin/npm install -g @openai/codex@0.160.1`. This
  example uses Codex 0.160.1.
- A Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK`, made in `us-west-2`, with access to
  `openai.gpt-5.6-terra`.

## Run it

From `~/box-tutorial`:

```sh
[ -d box-src ] || git clone --depth 1 https://github.com/strands-agents/box.git box-src
cp -R box-src/examples/codex-cli codex
sed -i '' "s|<HOME>|$HOME|g" codex/box.toml
mkdir -p codex/home codex/tmp
cp codex/config.toml codex/AGENTS.md codex/home/
./box-core/box run --config codex/box.toml -- "Summarize README.md in one sentence."
```

Codex reads `README.md` through the box's shell and answers in one sentence. The tutorial shows
the full output, and four more tasks.

The paths in `box.toml` and `policy.dw` name `~/box-tutorial/my-project` as the project, and the
paths in `box.toml` name `~/box-tutorial/codex` as this directory. Edit both files to use another
project.

## Telemetry

The box records every decision it takes, and it also relays what the agent exports. So one file holds
both halves. This example declares no `[telemetry]` table, so the box writes to its default target,
which the agent cannot reach: `codex/state/private/telemetry/records.jsonl`.

`command` in `box.toml` holds the switches that turn Codex's own exporters on, with a comment on each.
Codex takes those settings from its own configuration rather than the environment, so each of its three
endpoints is a token the box substitutes at launch. An export needs no policy rule, and `policy.dw`
holds none.

**Expect a large file.** Codex exports its whole internal trace, so one task that reads one file
produced about 800 spans and about 1 MB in a measured run.

[Telemetry](../../docs/user/telemetry.md) states what a record carries and how to read the file.
