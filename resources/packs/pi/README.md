# pi in a box (`@box/pi`)

The `@box/pi` pack runs [pi](https://pi.dev) in a box. pi can change files in your project and
reach its model and what your profile allows, and the box stops everything else. This page covers
what's different about pi. For profiles in general, see
[Profiles](../../../docs/cli/profiles.md).

## Install pi with npm

The box runs pi as npm installs it, with Node.js 22.19 or later:

```sh
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
```

## Make a profile

Name pi's model provider when you make the profile, Amazon Bedrock or the Anthropic API:

```sh
box profile create pi --with @box/pi,@box/bedrock
box profile create pi --with @box/pi,@box/anthropic
```

pi picks the provider whose credentials it finds. On Bedrock, the box signs in as the Bedrock
pack's [Sign in](../bedrock/README.md#sign-in) says, and pi sees stand-in AWS keys or a stand-in
`AWS_BEARER_TOKEN_BEDROCK`. For the Anthropic API, set `ANTHROPIC_API_KEY` in the terminal you run
`box run` from.

pi uses its default model for that provider. To pick one, pass it after `--`:

```sh
box run pi -- --model global.anthropic.claude-opus-5
```

To run pi without its interface:

```sh
box run pi -- -p "Summarize this project"
```

## How pi asks before it acts

pi never asks before it acts, on your machine or in the box. The box still checks each action.

## What comes into the box

The first time you run a profile, `box` copies your `~/.pi/agent/AGENTS.md`, `skills`, `prompts`,
`themes`, and `keybindings.json` into the profile's storage, and brings them up to date with your
machine on each run. From `~/.pi/agent/settings.json`, only how pi looks and thinks comes in, such
as `theme` and `defaultThinkingLevel`. Your provider, model, packages, extensions, and shell
settings stay on your machine. Your login (`auth.json`) doesn't come in, and your MCP servers come
in only when you turn them on (next section).

Each run sends pi's shell commands, and your `!` commands, through the box with a small pi
extension that `box` loads, `box-shell.ts`. pi's `shellPath` setting, yours or a project's,
doesn't apply in the box. `shellCommandPrefix` still does, and it runs in the box's shell.
`--no-builtin-tools`, `--tools`, and `defaultTools` turn the box's bash off as they turn off pi's. `box` also starts Node with a small preload that
stops pi from setting its process title, which ends Node in a box.

## Your MCP servers

`box profile create` asks whether to bring in your MCP servers (`pi.import-mcp`), and the answer
is no unless you say yes. With `pi.import-mcp = true`, each run reads the servers in
`~/.pi/agent/mcp.json`.
[MCP servers in the box](../../../docs/cli/limitations.md#mcp-servers-in-the-box)
says what that lets the agent do. The servers go in `agent/mcp.json` in the profile's storage, as
`mcpServers`, and the rest of your `mcp.json` stays on your machine.

`box` fills in each variable in a local server's `env`, written `${GITHUB_TOKEN}` or
`$GITHUB_TOKEN` as pi allows, from the shell you run `box` in. pi doesn't fill in variables in `command` or `args`, so `box` doesn't either.

For a remote server, the box can supply a key from a header that ends in one variable, such as
`"headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}` or `"Bearer $DOCS_TOKEN"`, which is what
`pi mcp add docs --url ... --bearer-token-env-var DOCS_TOKEN` writes. The agent gets a stand-in.

`box` skips a server whose `env` or `headers` holds a value that pi runs as a command, such as
`"!gh auth token"`, and says why when you run it. The box can't supply what the command prints. It
also skips a server that writes `$$` or `$!`, pi's escapes for a literal `$` or `!`. Use a variable
instead.

`box` doesn't read the project's `.pi/mcp.json`, because the agent can change it in the box. To
have `box` read one of those servers, add it to your own `~/.pi/agent/mcp.json` instead.

To import your servers again, follow the
[manual refresh steps](../../../docs/cli/troubleshooting.md#box-lists-an-mcp-server-but-my-agent-doesnt-show-it).
In step 4, remove the `mcpServers` property from `agent/mcp.json`.

## pi knows it runs in a box

Each time pi starts, `box` tells it how the box works, where your profile is, and that its shell is not a full bash. So when the box
blocks something, pi should say so, name the path, program, or host, and show the change to make
in `profile.toml`.

## Shell command timeout

pi's bash tool has no default timeout. The model can pass an optional `timeout` in seconds, and no pi setting sets one for it. A command with no timeout runs until it ends. For the box's own Shell timeout, see `shell.timeout` in the [profile reference](../../../docs/cli/profiles-reference.md#limits). This is true of pi 1.5.2.

## Limitations

- pi doesn't run on Linux yet. Node.js stops as it starts in the box: the box refuses the memory
  that Node's compiler needs, and Node exits with status 133 and
  `Check failed: 12 == (*__errno_location ())`.
- pi from its own installer doesn't run. Install it with npm.
- A server with `"type": "streamable-http"` is skipped. Leave `type` out, or write `"http"`, and
  pi still uses streamable HTTP for a `url`.
- A remote server that signs in with OAuth (`/mcp login`) keeps its tokens in `mcp-auth.json` in
  the profile's storage, where the agent can read them.
- An extension of yours or a project's that replaces pi's `bash` tool takes over from the box's,
  and its commands then fail in the box. `box` doesn't bring your extensions in.
- pi has no hooks that run a shell command. What a hook does in other agents, an extension does in
  pi, and your extensions stay outside the box.
- The agent can write the extensions in `.pi/extensions/` and the servers in `.pi/mcp.json` in your
  project. In a project you trust, pi on your machine runs those extensions and starts those
  servers without asking. Read these files after a run
  ([The agent can plant code that runs outside the box later](../../../docs/cli/limitations.md#the-agent-can-plant-code-that-runs-outside-the-box-later)).

## Troubleshooting

### pi isn't found

```text
box: error: ...: `agent.command.2`: `tool.pi.root` names no `[tool.pi]` with a `program` that this host has
```

pi's own installer (`curl -fsSL https://pi.dev/install.sh | sh`) puts a launcher script on your
`PATH` that the box can't run. Install pi with npm, and make sure that `pi` on your `PATH` is the
npm one: `ls -l (command -v pi)` in fish, or `ls -l "$(command -v pi)"` in bash or zsh, ends in
`pi-coding-agent/dist/bundle/cli.js`.
