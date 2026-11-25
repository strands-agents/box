# Codex in a box (`@box/codex`)

The `@box/codex` pack runs Codex in a box. Codex reaches its model through Amazon Bedrock
Runtime or Mantle, or through the OpenAI API with an API key. This page covers what's different
about Codex.
For profiles in general, see [Profiles](../../../docs/cli/profiles.md).

## Make a profile

For Bedrock Mantle in `us-east-1`, set a model that supports the Responses API in your Codex
folder's `config.toml` before the first run, such as
[GPT-6.2 Sol](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-6-2-sol.html):

```toml
model = "openai.gpt-6.2-sol"
```

Match the `model_provider` in your Codex folder's `config.toml`: use `bedrock` for
`amazon-bedrock-runtime`, `bedrock-mantle` for `amazon-bedrock`, or `openai` for the OpenAI API:

```sh
box profile create codex-runtime --with codex,bedrock
box profile create codex-mantle --with codex,bedrock-mantle --option bedrock.region=us-east-1
box profile create codex-openai --with codex,openai
```

If you run `box profile create codex` without naming a provider, Box asks which one to use, with
the provider in your Codex folder's `config.toml` selected when it recognizes it. Otherwise, Mantle
is the default. Without a terminal, Box uses that provider or the default. To choose a
region, pass `--option bedrock.region=us-east-1`. Without it, the starter checks the selected
provider's `aws.region` in that file, then `AWS_REGION`.
The starter also asks how the box signs in to Bedrock ([Sign in](../bedrock/README.md#sign-in)),
whether to bring in your MCP servers and hooks, and which policy to use.

For a Runtime profile you write by hand, include `@box/bedrock` in `packs` and set this in
`profile.toml`:

```toml
[options]
codex.host = "amazon-bedrock-runtime"
```

Mantle uses `@box/bedrock-mantle` and the default `codex.host = "amazon-bedrock"`.
The OpenAI API uses `@box/openai` and `codex.host = "openai"`.

## Use the OpenAI API

With `@box/openai`, export your OpenAI API key as `OPENAI_API_KEY` in the terminal you run
`box run` from. The box sends the key to `api.openai.com`, and Codex gets a stand-in.

Codex's own `openai` provider signs in with `codex login` and doesn't read a key from the
environment, and your login stays outside the box. So the box gives Codex a provider of its own,
`openai-api`, that sends `OPENAI_API_KEY` to `https://api.openai.com/v1`. Signing in with a
ChatGPT account isn't supported in the box.

## How Codex asks before it acts

On your machine, Codex asks when a command needs to leave its own sandbox. In the box, the box is
the sandbox, so Codex's own is off and nothing needs to leave it. By default, Codex edits files and runs
commands without asking, and asks only before a forced `rm`, such as `rm -rf build`, or a command
that one of your Codex rules says to ask about. Those rules come into the box with
the commands you've already approved. With `agent.skip-permissions = true` in a Codex profile,
Codex refuses those commands instead of asking, unless your organization requires approval.

Codex reads your organization's `/etc/codex/requirements.toml` and
`/etc/codex/managed_config.toml` read-only.

## What comes into the box

Your Codex folder is `CODEX_HOME`, or `~/.codex` when that variable is unset or empty.
Codex itself still uses the profile's private storage.
If `CODEX_HOME` is relative, contains `..`, or is in a folder Box can write, Box skips its
imports and says why. Existing copies in Box stay available, except imported hooks, which are
removed.

The first time you run a profile, `box` copies that folder's `AGENTS.md` and `rules` into the
profile's storage. Your `AGENTS.md` stays up to date with your Mac on each run. Your `rules` come
in once: after that, the box keeps its own, with the commands you approve in the box.

Box also imports `model`, `model_verbosity`, `model_reasoning_effort`, `personality`, `agents`,
`tui.animations`, `tui.show_tooltips`, `tui.theme`, `tui.keymap`, `tui.presets` (saved prompts),
`features.memories`, `[memories]`, and the current folder's `projects.<path>.trust_level` from
your Codex folder's `config.toml` when the box has no saved value for that setting.
Trust saved for a repository root comes in when you run Box from that root.
A choice saved in the box stays, even if you change the host setting. If neither has a model set,
Codex uses its own default. Other settings, except `mcp_servers`, and your sessions stay outside
the box.

If both files set a model and the values differ, Box warns before each run and keeps the saved
choice. To change it, use Codex's `/model`. To import these settings again, stop the profile's
runs and use `box profile reset <profile>`, then start a new run. Reset also deletes that
profile's agent sessions and memory ([Reset](../../../docs/cli/cli.md#box-profile-reset)).

Your Codex folder's `agents/` folder comes into `home/agents`. Its `skills` and `~/.agents/skills` come into separate folders,
`home/skills/codex` and `home/skills/agents`, so matching names stay separate.
Custom themes in your Codex folder's `themes` come into `home/themes`.
They follow the same [copy and sync rules](../../../docs/cli/limitations.md#instructions-skills-and-settings-in-the-box).

To stop importing skills, set `codex.import-skills = false` under `[options]` in your profile.
Existing copies stay available. To remove them, delete those two folders from the profile's
storage, which `box profile show` lists.

## Memories

To let Codex create memories, install Git and add `@box/git` to your profile's `packs`.
Merge these settings into existing tables, appending the filesystem paths to existing lists.
Put Git's directory before your existing `PATH`:

```toml
[agent.env]
PATH = "${{ tool.git.root }}:/usr/bin:/bin"
GIT_CONFIG_NOSYSTEM = "1"
GIT_CONFIG_GLOBAL = "/dev/null"

[agent.filesystem]
read_file = ["${{ tool.git.root }}/git"]
exec = ["${{ tool.git.root }}/git"]
```

## Your MCP servers

With `codex.import-mcp = true`, each run reads the servers in your Codex folder's `config.toml`.
[MCP servers in the box](../../../docs/cli/limitations.md#mcp-servers-in-the-box)
says what that lets the agent do. The servers go in the `mcp_servers` table of
`home/config.toml` in the profile's storage.

For a remote server, the box can supply a key from a variable named in
`bearer_token_env_var = "DOCS_TOKEN"`, or in `env_http_headers = { "X-Api-Key" = "DOCS_TOKEN" }`.
Codex's `http_headers` come in as written, so a key typed there is one the agent can read.

For a local server, each name in `env_vars` gets its value from your shell if it is set. Unset
names are omitted, and the server keeps its policy. An empty value is kept, and an explicit `env`
value wins. Entries can be strings or objects such as
`{ name = "GITHUB_TOKEN", source = "local" }`. You can omit `source`; `"remote"` is not supported
for a local server. A server's `env` is copied as written: `box` fills in no variable there.

`box` doesn't read the project's `.codex/config.toml`, because the agent can change it in the box.
To have `box` read one of those servers, add it to your own Codex folder's `config.toml` instead.

To import your servers again, follow the
[manual refresh steps](../../../docs/cli/troubleshooting.md#box-lists-an-mcp-server-but-my-agent-doesnt-show-it).
In step 4, remove the whole `mcp_servers` table from `home/config.toml`, including every
`[mcp_servers.<name>]` subtable.

## Your hooks

Codex in a box doesn't run the hooks in your Codex folder's `hooks.json` unless you turn them on,
and in the box a hook is a convenience, not a guardrail. To bring your hooks in, answer yes when
`box profile create` asks, or set this under `[options]` in the profile:

```toml
codex.import-hooks = true
```

On each run, `box` reads your `hooks.json` again and keeps each `command` hook that runs one shell
script, such as `~/.codex/hooks/format.sh` or `bash ~/.codex/hooks/format.sh`. It writes them to
`home/hooks.json` in the profile's storage. The script runs in the box's shell with the agent's own
policy, gets the event on its standard input, and its exit code reaches Codex, so a `PreToolUse`
script that exits with 2 still blocks the tool. A script gets at most 1 MiB of the event,
unless you raise `shell.max_stdin` under `[limits]` in the profile. The shell reads the script with
`.`, so `$0` isn't the script's path: a script that finds its own folder with `dirname "$0"` needs
the full path written out. `box run` lists each script:

```text
box: imported hooks run ~/.codex/hooks/format.sh, and the policy permits its read
```

`box` adds a rule to the run's policy that lets the box read each of these scripts, and nothing
else in their folder. The agent can read them too, so keep secrets out of them.

### Trust your hooks once

Codex runs a hook only after you trust it. The first time you run the profile with hooks, start
Codex with its interface, and when it shows **Hooks need review**, choose **Trust all and
continue**:

```sh
box run codex
```

Codex keeps your answer in the box, so later runs don't ask again. It asks again when one of your
hooks changes. Do this before you run Codex without its interface, such as with `exec`: there,
Codex skips a hook you haven't trusted, or one that changed, and prints nothing about it.

### What doesn't come in

`box` leaves out each hook it can't run in a box, and says why when the run starts:

- **An inline command**, such as `jq -r .tool_input.file_path | xargs prettier --write`. Put the
  command in a script and name the script.
- **A hook with arguments**, such as `~/.codex/hooks/check.sh --strict`.
- **A script in this run's project**, or anywhere else this profile's box can write, or one whose
  path passes through a folder or link there, because the agent could change what it does in later
  runs.
- **A script in a folder that a [plugin](../../../docs/cli/plugins.md) keeps on
  your machine**, such as `~/.config/op`, when your profile lists the plugin.
- **A script that isn't a shell script**, such as a Python script.
- **A command that starts another program**, such as `python3 ~/.codex/hooks/check.py`.
- **A script whose real path has a space, a quote, or another character** outside letters, digits,
  and `/._-+@,`.
- **An `mcp_tool` hook.**

```text
box: did not import the hook PreToolUse (Bash) #1: an inline command is not imported; ...
```

With `codex.import-hooks = false`, the default, `box` removes every hook from `home/hooks.json` in
the box, including ones an earlier run brought in. A hook that Codex or the agent writes to that
file in a box doesn't last: each run sets the file's hooks from yours again.

A hook can't stop the agent from doing something, because the agent can change its own settings
during a run. To make a rule that holds, write it in the profile's policy.

## Codex knows it runs in a box

Each time Codex starts, `box` tells it how the box works, where your profile is, and that its shell is not a full bash. So when the box
blocks something, Codex should say so, name the path, program, or host, and show the change to
make in `profile.toml`. A conversation you resume keeps what it was told when it started.

If you pass Codex your own `-c developer_instructions` in `agent-args`, it replaces what `box`
tells Codex.

## Shell command timeout

Codex's default shell tool does not kill a command at a timeout. After 10 seconds, Codex gives the model a session ID, the command keeps running, and the model polls it. For the box's own Shell timeout, see `shell.timeout` in the [profile reference](../../../docs/cli/profiles-reference.md#limits). This comes from the Codex 0.166.0 source. Other versions were not checked.

## Limitations

- Policies set through macOS device management aren't supported.
- Preference import does not read named Codex profiles in `config.toml`.
- An MCP server's `cwd` setting may fail when Codex uses the server.
- Hooks in the `[hooks]` table of `~/.codex/config.toml` don't come into the box, and neither does
  an `mcp_tool` hook. [Your hooks](#your-hooks) says which hooks do.
- `box` doesn't read `[features] hooks = false` in your `~/.codex/config.toml`. To run Codex in the
  box without your hooks, leave `codex.import-hooks` off.
- The agent in the box can change `.codex/config.toml`, `.codex/hooks.json`, and `.codex/rules/` in
  your project, and Codex uses them the next time you run it there.
  For more info, check [the limitations section](../../../docs/cli/limitations.md#the-agent-can-plant-code-that-runs-outside-the-box-later).

## Troubleshooting

### Codex isn't found

`npm install` puts Codex on your Mac as a Node.js script, and the box stops with
`a node script, which the box cannot start`. Install Codex's own program for macOS instead of the
npm package.

If Codex lives somewhere `box` doesn't look, set `codex.path` under `[options]`, as
[The agent isn't found](../../../docs/cli/troubleshooting.md#the-agent-isnt-found) shows for
`claude.path`.
