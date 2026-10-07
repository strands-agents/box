# pi in a box

[pi](https://pi.dev) runs under a [policy](../../docs/user/policy.md) on a Mac, with the project
out of its own reach. Its `bash` tool is its only way to a project file, and that tool runs the
[box's shell](../../docs/user/shell.md), so the policy decides every command and every file a
command reads, writes, or deletes. The task comes from the command line.

[The tutorial](../../docs/user/tutorials/pi.md) walks through this example step by step, with the
output of each run.

## Files

- `box.toml`: what the box runs, and what pi's own process can reach. That is its installation,
  its agent directory and its temporary directory beside this file, the preload file, Homebrew's
  OpenSSL settings, and the names in the project.
- `policy.dw`: the policy. It permits Bedrock, the shell, reads and writes in the project, and
  `/dev/null`. Two of its `forbid` rules, which the tutorial exercises, refuse the content of the
  project's `.env` file and every delete.
- `settings.json`: pi's settings. They select the model on Bedrock, and point pi's `bash` tool at
  the `bash` alias in the box directory's `bin`, the directory the box prints at startup as the
  first entry of the agent's `PATH`. `/bin/bash` is not executable in the agent box, so without this
  setting pi's `bash` tool gets `spawn EPERM` for every command.
- `box-preload.mjs`: a file Node loads before pi, through `--import` in `command`. It changes two
  Node calls pi makes at startup, and nothing else: the process title setter does nothing, because
  in a box that call ends the Node process, and the `utimes`, `futimes`, and `lutimes` functions
  report success without touching the file, because Box does not let the agent change file
  timestamps inside a write grant and pi's credential store probes them. Both are workarounds for
  Box limitations.

## Before you start

- A Mac with Apple silicon and macOS 15 or later, and Box in `~/box-tutorial/box-core` from
  [getting started](../../docs/user/getting-started.md).
- The project in `~/box-tutorial/my-project` from getting started, with its `README.md`.
- Node.js from Homebrew, and pi from its installer: `curl -fsSL https://pi.dev/install.sh | sh`.
- A Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK`, made in `us-west-2`.

## Run it

From `~/box-tutorial`:

```sh
[ -d box-src ] || git clone --depth 1 https://github.com/strands-agents/box.git box-src
cp -R box-src/examples/pi pi
sed -i '' "s|<HOME>|$HOME|g; s|<VERSION>|$(cat ~/.pi/agent/install/current-version)|g" pi/box.toml pi/settings.json
mkdir -p pi/agent pi/tmp
cp pi/settings.json pi/agent/
./box-core/box run --config pi/box.toml -- -p "Summarize README.md in one sentence."
```

pi reads `README.md` through the box's shell and answers in one sentence. The tutorial shows the
full output, and five more tasks.

The paths in `box.toml` and `policy.dw` name `~/box-tutorial/my-project` as the project. Edit both
files to use another project. The paths in `box.toml` and `settings.json` name `~/box-tutorial/pi`
as this directory. Edit both files to move it.
