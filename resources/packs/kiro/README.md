# Kiro CLI in a box (`@box/kiro`)

The `@box/kiro` pack runs Kiro CLI in a box. Kiro CLI can change files in your project and reach
Kiro's service and what your profile allows, and the box stops everything else. This page covers
what's different about Kiro CLI. For profiles in general, see
[Profiles](../../../docs/cli/profiles.md).

## Make a profile and sign in

`box profile create kiro` asks how Kiro CLI signs in (`kiro.sign-in`), whether to bring in your MCP
servers (`kiro.import-mcp`, see [Your MCP servers](#your-mcp-servers)), then the policy:

- **`login`, the default.** Run `box run kiro -- login --use-device-flow` once, and confirm the
  code in your browser. Kiro CLI keeps the login in the box's storage, where the agent can read it.
- **`api-key`.** Put your key in `KIRO_API_KEY` in the terminal you run `box run` from. The box
  adds it to each request, and Kiro CLI only sees a stand-in. Your Kiro plan has to allow API keys.

To switch later, set `kiro.sign-in` under `[options]` in `~/.strands/box/profiles/<profile>/profile.toml`.

## Set up the runtime folder first

Kiro CLI unpacks part of itself before it runs, and the box won't run files the agent can change.
So before the first run, unpack it into a folder on your machine that the box only reads:

```text
$ echo 'export KIRO_RUNTIME_DIR="$HOME/.kiro-runtime"' >> ~/.zshrc
$ export KIRO_RUNTIME_DIR="$HOME/.kiro-runtime"
$ kiro-cli --v3 chat --list-sessions
No saved chat sessions for /Users/you
```

After Kiro CLI updates itself, run `kiro-cli --v3 chat --list-sessions` again, or start Kiro CLI
on your machine once. Until then the box stops with `failed to spawn the v3 engine`.

## Run Kiro CLI without its interface

Pass `chat` and its options:

```sh
box run kiro -- chat --no-interactive "Summarize this project"
```

## What comes into the box

The first time you run a profile, `box` copies your `~/.kiro/steering`, `~/.kiro/skills`, and
`~/.kiro/prompts` into the profile's storage, and brings them up to date with your machine on each
run. Your steering goes into a `host` folder inside the box's steering folder. From
`~/.kiro/settings/cli.json`, only your model (`chat.defaultModel`) and
`chat.enableContextUsageIndicator` come in. Your custom agents, Kiro CLI's memory, and your powers
stay out unless you turn them on: see
[Bring in your custom agents](#bring-in-your-custom-agents),
[Bring in Kiro CLI's memory](#bring-in-kiro-clis-memory), and
[Bring in your powers](#bring-in-your-powers).

## Bring in your custom agents

Set `kiro.import-agents = true` under `[options]` in the profile's `profile.toml`:

```toml
[options]
kiro.import-agents = true
```

`box` then copies `~/.kiro/agents` into the box, brings it up to date with your machine on each
run, and keeps your `chat.defaultAgent` from `cli.json`. `kiro-cli agent list` in the box shows
your agents, and each agent's `allowedTools` and `toolsSettings` decide what Kiro CLI asks about, as
on your machine. The default agent comes in with the first copy of `cli.json`, so for a profile that
already ran, delete `home/.kiro/settings/cli.json` in the profile's storage folder,
`~/.strands/box/storage/<profile>/default/agent/`, before the next run. Turning the input off again
leaves the copied agents in the box, with any keys in their files: to take them out, set it to
`false` and delete `home/.kiro/agents` and `home/.kiro/settings/cli.json` in that folder.

It is off by default, because each agent's file comes in whole:

- **Hooks.** Kiro CLI 3.5.0 starts each hook through `/bin/sh` and ignores `SHELL`. A box does not
  run `/bin/sh`, so no hook in an agent runs.
- **MCP servers.** `box` does not check or declare an agent's `mcpServers`, and the agent can read
  any key in them. Keep keys out of the file: Kiro CLI reads `${VAR}` in a server's `env`, so
  `"GITHUB_TOKEN": "${GITHUB_TOKEN}"` takes the value from the environment instead.
- **The box still decides.** An agent's tool settings change what Kiro CLI asks about, not what the
  box allows. A profile's policy decides each action.

## Bring in Kiro CLI's memory

Set `kiro.import-memory = true` under `[options]` in the profile's `profile.toml`:

```toml
[options]
kiro.import-memory = true
```

On the profile's first run, `box` then copies `~/.kiro/memories` and `~/.kiro/identities` into the
box, once. Kiro CLI in the box recalls what you saved on your machine. What it saves in the box
stays in the box, and a later change on your machine doesn't come in. To copy your machine's
memory again, delete `home/.kiro/memories` and `home/.kiro/identities` in the profile's storage
folder, `~/.strands/box/storage/<profile>/default/agent/`. Do the same when you turn the input on
for a profile that already ran: Kiro CLI made its own memory in the box then, and `box` doesn't
replace it.

It is off by default, because Kiro CLI keeps one memory for every project. The box gets all of it:
your Global memories, each project's memories, and anything you told Kiro to remember.

Without a login, or with `kiro.sign-in = "api-key"`, Kiro CLI reads `~/.kiro/memories`. When you
log in, it reads your own memory under `~/.kiro/identities`, and fills it from `~/.kiro/memories`
the first time. `~/.kiro/identities` holds only that memory and its settings, no login.

Kiro CLI writes its memory as a database while it runs. When the database keeps changing while
`box` copies it, the first run stops with `changed each time box copied it`. Quit Kiro CLI on your
machine, then start the run again. See
[Copy files into storage](../../../docs/cli/packs-reference.md#copy-files-into-storage).

## Bring in your powers

Set `kiro.import-powers = true` under `[options]` in the profile's `profile.toml`:

```toml
[options]
kiro.import-powers = true
```

`box` then copies `~/.kiro/powers/installed.json` and each power's folder in
`~/.kiro/powers/installed` into the box, and brings them up to date with your machine on each run.
Kiro CLI in the box lists your powers, and can read each power's `POWER.md` or `plugin.json`, its
steering, and its skills.

It is off by default, and some parts of a power stay out even when it is on:

- **MCP servers.** Each power's `mcp.json` stays out, so a power's MCP servers don't start in the
  box. An `mcp.json` names programs that Kiro CLI starts, and its `env` and `headers` can hold
  keys. `box` checks the MCP servers it brings in, but not yet the servers of a power, so for now
  it brings in none. `box run` prints a `did not copy` line for each `mcp.json` it leaves out.
- **Server state.** `~/.kiro/powers/data` stays out. Kiro CLI makes a folder there for each power's
  MCP servers, and a server can keep its state or a token in it.
- **Catalogs.** `~/.kiro/powers/registries` stays out. Kiro CLI does not read it.

A power that comes in still shows its steering and skills to Kiro CLI, as your own steering does.
`box` does not check what they say.

### Installing a power inside the box

`kiro-cli powers install <name>` in the box downloads the catalog from
`prod.download.desktop.kiro.dev` and the power from `codeload.github.com`. The profile opens
neither host, so the box refuses the download. `kiro-cli powers install <folder>` copies a folder
that the box can read into the box's own `~/.kiro/powers`, with its `mcp.json`, and Kiro CLI then
starts that power's MCP servers in the box, where the profile's policy decides each action. A power
you install in the box does not reach your machine. With `kiro.import-powers` on, it does not last
either: after you install or remove a power on your machine, the next run replaces the box's
`installed.json` with yours, and Kiro CLI no longer lists the power you installed in the box.

## Your MCP servers

With `kiro.import-mcp = true` under `[options]`, `box` reads the servers in your
`~/.kiro/settings/mcp.json`, declares each one it can run in the box, and writes them under
`mcpServers` in the box's `~/.kiro/settings/mcp.json` in storage. It's off by default. When the run
starts, `box` prints a line for each server, and for a server it skips, the reason.

- Only your own `mcp.json` comes in. `box` reads no file in your project, so the servers in the
  project's `.kiro/settings/mcp.json` stay out, and so do the servers that an agent in
  `~/.kiro/agents` names.
- Kiro CLI fills in a variable written `${NAME}` in a server's `command`, `args`, and `env`, and
  `box` reads the same form. Kiro CLI 3.5.0 passes `$NAME`, `${env:NAME}`, and `${NAME:-default}`
  through as text. `box` also fills in `${NAME:-default}` in `command` and `env`, so there a server
  can get the default in the box where Kiro CLI on your machine passes the text.
- `box` skips a server with `"disabled": true`, so it gets no hosts, keys, or program in the box.
- `box` skips a remote server (`url`) that has `env`, even an empty one. Remove `env` from it in
  your `mcp.json` to bring it in.
- `autoApprove`, `disabledTools`, `timeout`, and Kiro's other keys go into the box's copy as they
  are, and keep no server out.
- `box` writes the section only while the box's copy has no `mcpServers`. To bring in a server you
  add later, remove `mcpServers` from that copy, as the
  [refresh steps](../../../docs/cli/troubleshooting.md#box-lists-an-mcp-server-but-my-agent-doesnt-show-it)
  say.

## Kiro CLI knows it runs in a box

Each time Kiro CLI starts, `box` tells it how the box works, where your profile is, and that its shell is not a full bash, through a
steering file named `box`. So when the box blocks something, Kiro CLI should say so, name the path,
program, or host, and show the change to make in `profile.toml`.

## How Kiro CLI asks before it acts

Kiro CLI asks before it runs a tool, as its default agent does on your machine. Your own agents in
`~/.kiro/agents` don't come into the box unless `kiro.import-agents` is on, so their tool settings
don't apply.

With `agent.skip-permissions = true` under `[options]` in a Kiro CLI profile, it starts with
`--trust-all-tools` and runs every tool without asking. That option belongs to Kiro CLI's `chat`, so
the profile starts `chat` for you: leave `chat` out of the arguments after `--`. To sign in inside
the box, remove that line from `~/.strands/box/profiles/<profile>/profile.toml`, run
`box run <profile> -- login --use-device-flow`, and then add it back.

## Shell command timeout

Kiro CLI documents no timeout for its shell tool, and 3.4.0 has no timeout setting for it. We could not confirm that no limit applies. For the box's own Shell timeout, see `shell.timeout` in the [profile reference](../../../docs/cli/profiles-reference.md#limits).

## Limitations

These don't work in the box yet:

- Kiro CLI's older engine (`--v2`).
- The MCP servers of a power you bring in.
- A Kiro profile outside the `us-east-1` region. The packs open only Kiro's `us-east-1` hosts.
- Hooks. Kiro CLI starts each hook through `/bin/sh` and ignores `SHELL`, and a box doesn't run
  `/bin/sh`, so no hook runs: not one in an agent you bring in, and not one in the project.

The agent can write `.kiro/settings/mcp.json` and `.kiro/agents/`. In a trusted workspace, Kiro CLI
on your machine runs their servers and hooks without asking, and
`kiro-cli chat --no-interactive --agent <name>` starts their servers in any workspace. [Read them after a run](../../../docs/cli/limitations.md#the-agent-can-plant-code-that-runs-outside-the-box-later).

On macOS, when file times are off, as with `file-attributes = false` or when you run `box` as
root, Kiro CLI waits about 15 seconds each time it starts. See
[File times on macOS](../../../docs/cli/limitations.md#file-times-on-macos).

## Troubleshooting

### Kiro CLI's runtime folder is missing or out of date

```text
strands-box: error: `[agent]` filesystem entry "/Users/you/.kiro-runtime" is refused: /Users/you/.kiro-runtime is not there
```

```text
error: failed to spawn the v3 engine: node binary `/Users/you/.strands/box/storage/kiro/default/agent/home/Library/Application Support/kiro-cli/node` ... Operation not permitted
```

The first message means you haven't filled Kiro CLI's runtime folder yet. The second means Kiro CLI
updated itself since you last filled it. Either way, fill it again on your machine, as in
[Set up the runtime folder first](#set-up-the-runtime-folder-first), then start the run again:

```sh
KIRO_RUNTIME_DIR="$HOME/.kiro-runtime" kiro-cli --v3 chat --list-sessions
```

If you keep the folder somewhere else, set `KIRO_RUNTIME_DIR` to it in the terminal you run
`box run` from.

### The runtime folder holds your project

```text
box: error: the `exec` folder /Users/you holds the write grant /Users/you/src/my-app, so the workload can run a file it writes
```

`KIRO_RUNTIME_DIR` names a folder that holds your project or `~/.strands/box`, such as your home folder.
Give the runtime a folder of its own, such as `~/.kiro-runtime`.

### Kiro CLI crashes with `Attempted to create a NULL object`

```text
The application panicked (crashed).
Message:  Attempted to create a NULL object.
...
error: ACP new_session failed
```

In the box, Kiro CLI crashes this way when its API key is wrong or expired, instead of saying so.
Check that `KIRO_API_KEY` in this terminal holds a current Kiro API key, then start the run again.

For errors that every agent can hit, see [Troubleshooting](../../../docs/cli/troubleshooting.md).
