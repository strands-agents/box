# Claude Code in a box

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) runs under a
[policy](../../docs/user/policy.md) on a Mac. Its own file tools reach none of the project's
files, so every read, write, and delete goes through its Bash tool, where the
[box's shell](../../docs/user/shell.md) asks the policy about every command and every file. The
task comes from the command line.

[The tutorial](../../docs/user/tutorials/claude-code.md) walks through this example step by step,
with the output of each run.

## Files

- `box.toml`: what the box runs, and what the agent's own process can reach. That is the Claude
  Code installation, its `config` and `tmp` directories beside this file, and the file names in the
  project. It also switches Claude Code's own telemetry on, as [Telemetry](#telemetry) describes.
- `policy.dw`: the policy. It permits requests to Bedrock, every shell command, and reads and
  writes in the project, in Claude Code's two state directories, and to `/dev/null`. Two of its
  `forbid` rules, which the tutorial exercises, refuse the project's `.env` file and every delete.

## Before you start

- A Mac with Apple silicon and macOS 15 or later, and Box in `~/box-tutorial/box-core` from
  [getting started](../../docs/user/getting-started.md).
- The project in `~/box-tutorial/my-project` from getting started, with its `README.md`.
- Claude Code from its native installer: `curl -fsSL https://claude.ai/install.sh | bash`.
- A Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK`, made in `us-west-2`.

## Run it

From `~/box-tutorial`:

```sh
[ -d box-src ] || git clone --depth 1 https://github.com/strands-agents/box.git box-src
cp -R box-src/examples/claude-code claude-code
sed -i '' "s|<HOME>|$HOME|g" claude-code/box.toml
mkdir -p claude-code/config claude-code/tmp
./box-core/box run --config claude-code/box.toml -- -p "Summarize README.md in one sentence."
```

Claude Code reads `README.md` through the box's shell and answers in one sentence. Leave out `-p`
and the task to open its chat. The tutorial shows the full output, and four more tasks.

The paths in `box.toml` and `policy.dw` name `~/box-tutorial/my-project` as the project, and the
paths in `box.toml` name `~/box-tutorial/claude-code` as this directory. Edit both files to use
another project.

## Telemetry

The box records every decision it takes, and it also relays what the agent exports. So one file holds
both halves. This example declares no `[telemetry]` table, so the box writes to its default target,
which the agent cannot reach: `claude-code/state/private/telemetry/records.jsonl`.

`[agent.env]` in `box.toml` holds the switches that turn Claude Code's own exporters on, with a
comment on each. An export needs no policy rule, and `policy.dw` holds none.

Claude Code redacts prompt text by default. `OTEL_LOG_USER_PROMPTS` turns that off, and each prompt
then goes into the records file named above.

[Telemetry](../../docs/user/telemetry.md) states what a record carries and how to read the file.
