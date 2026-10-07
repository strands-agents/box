# The Strands CLI in a box

The [Strands CLI](https://github.com/strands-agents/harness-sdk/tree/main/strands-cli), run under
a [policy](../../docs/user/policy.md) on a Mac. It has two tools: the
[box's shell](../../docs/user/shell.md), and `web_fetch`, which fetches through the box's egress
gateway. So the policy decides every command it runs, every file a command touches, and every host
it fetches from. The policy permits no fetch host, so `web_fetch` is refused until you add one.

[Getting started](../../docs/user/getting-started.md) builds these files step by step, and says
why each one is there. This directory holds the finished files, so you can copy them and run the
box.

## Files

- `box.toml`: what the box runs and what the agent's own process can reach.
- `policy.dw`: the policy. It permits Bedrock, the shell, reads in the project, and `/dev/null`.
- `proxy-preload.mjs`: sends the AWS SDK's requests through the box's egress gateway. Node loads it
  before the CLI starts.
- `strands-home/.strands/cli/config.json`: the CLI's settings. The box sets the CLI's `HOME` to
  `strands-home`, and the CLI keeps its sessions and memory there.

## Before you start

- A Mac with Apple silicon and macOS 15 or later, and Box in `~/box-tutorial/box-core` from
  [getting started](../../docs/user/getting-started.md).
- Node.js 22.21 or later from Homebrew: `brew install node`.
- An AWS account with access to Claude Opus 5 on Amazon Bedrock in `us-west-2`, and a Bedrock API
  key in `AWS_BEARER_TOKEN_BEDROCK`, made in `us-west-2`.

## Run it

From `~/box-tutorial`:

```sh
/opt/homebrew/bin/npm install -g @strands-agents/cli
[ -d my-project ] || { mkdir my-project && echo "# My project" > my-project/README.md; }
[ -d box-src ] || git clone --depth 1 https://github.com/strands-agents/box.git box-src
[ -d strands-cli ] || cp -R box-src/examples/strands-cli strands-cli
sed -i '' "s|<HOME>|$HOME|g" strands-cli/box.toml
./box-core/box run --config strands-cli/box.toml
```

The box prints what the agent can touch, then the CLI opens a chat. Ask it to read `README.md` and
add a line to it. The box permits the read and refuses the write, because the policy permits only
reads. Type `/exit` to stop the box. Getting started shows how to read the decision log and permit
the write.

The paths in `box.toml` and `policy.dw` name `~/box-tutorial/my-project` as the project, and the
paths in `box.toml` name `~/box-tutorial/strands-cli` as this directory. Edit both files to use
another project.
