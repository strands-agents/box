# A Strands Agents SDK agent in a box

A small agent built with the [Strands Agents SDK](https://github.com/strands-agents/sdk-python),
run under a [policy](../../../docs/user/policy.md) on a Mac. It has three tools, and each one runs
a command through the [box's shell](../../../docs/user/shell.md), so the policy decides every
command it runs and every file a command touches. The task comes from the command line.

[The tutorial](../../../docs/user/tutorials/strands-sdk-agent.md) walks through this example step
by step, with the output of each run.

## Files

- `agent.py`: the agent. A Bedrock model and the tools `list_project`, `read_file`, and
  `run_command`.
- `requirements.txt`: the SDK.
- `setup.sh`: builds a virtual environment at `runtime/.venv`, installs the SDK into it, and makes
  `tmp`.
- `box.toml`: what the box runs and what the agent's own process can reach.
- `policy.dw`: the policy. It permits Bedrock, the shell, reads in the project, and `/dev/null`.
  Two of its `forbid` rules, which the tutorial exercises, refuse the project's `.env` file and
  every delete.

## Before you start

- A Mac with Apple silicon and macOS 15 or later, and Box in `~/box-tutorial/box-core` from
  [getting started](../../../docs/user/getting-started.md).
- The project in `~/box-tutorial/my-project` from getting started, with its `README.md`.
- Homebrew's Python 3.14: `brew install python@3.14`.
- A Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK`, made in `us-west-2`.

## Run it

From `~/box-tutorial`:

```sh
[ -d box-src ] || git clone --depth 1 https://github.com/strands-agents/box.git box-src
cp -R box-src/examples/strands-box/strands-sdk-agent strands-agent
sed -i '' "s|<HOME>|$HOME|g" strands-agent/box.toml
./strands-agent/setup.sh
./box-core/box run --config strands-agent/box.toml -- "Summarize README.md in one sentence."
```

The agent reads `README.md` through the box's shell and answers in one sentence. The tutorial shows
the full output, and three more tasks.

The paths in `box.toml` and `policy.dw` name `~/box-tutorial/my-project` as the project, and the
paths in `box.toml` name `~/box-tutorial/strands-agent` as this directory. Edit both files to use
another project.
