# Kiro CLI in a box (`@box/kiro`)

The `@box/kiro` pack runs Kiro CLI in a box. Kiro CLI can change files in your project and reach
Kiro's service and what your profile allows, and the box stops everything else. This page covers
what's different about Kiro CLI. For profiles in general, see
[Profiles](../../../docs/cli/profiles.md).

## Make a profile and sign in

`box profile create kiro` asks how Kiro CLI signs in (`kiro.sign-in`), then the policy:

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
`chat.enableContextUsageIndicator` come in.

## Kiro CLI knows it runs in a box

Each time Kiro CLI starts, `box` tells it how the box works, where your profile is, and that its shell is not a full bash, through a
steering file named `box`. So when the box blocks something, Kiro CLI should say so, name the path,
program, or host, and show the change to make in `profile.toml`.

## How Kiro CLI asks before it acts

Kiro CLI asks before it runs a tool, as its default agent does on your machine. Your own agents in
`~/.kiro/agents` don't come into the box, so their tool settings don't apply.

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
- Your MCP servers. `box` doesn't bring the servers in your `~/.kiro/settings/mcp.json` into the
  box.
- A Kiro profile outside the `us-east-1` region. The packs open only Kiro's `us-east-1` hosts.
- Hooks. Kiro CLI starts each hook through `/bin/sh`, and a box doesn't run `/bin/sh`, so no hook
  runs: not one you bring in, and not one in the project.

On macOS, when file times are off, as with `file-attributes = false` or when you run `box` as
root, Kiro CLI waits about 15 seconds each time it starts. See
[File times on macOS](../../../docs/cli/limitations.md#file-times-on-macos).

## Troubleshooting

### Kiro CLI's runtime folder is missing or out of date

```text
strands-box: error[B0102]: `[agent]` filesystem entry "/Users/you/.kiro-runtime" is refused: /Users/you/.kiro-runtime is not there
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
