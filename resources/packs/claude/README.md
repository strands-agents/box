# Claude Code in a box (`@box/claude`)

The `@box/claude` pack runs Claude Code in a box. [Get started](../../../docs/cli/getting-started.md)
walks through a first run. This page covers what's different about Claude Code.

## Make a profile

`box profile create claude` asks which model provider Claude Code uses, then the region, whether
to bring in your MCP servers (`claude.import-mcp`), whether to run your command hooks
(`claude.import-hooks`), and the policy. It skips the provider and region questions when your
Claude Code settings already answer them, as
[Starters](../../../docs/cli/starters.md#skip-questions-the-agents-settings-already-answer)
shows. It always asks the MCP and hooks questions at a terminal, because each one shows a warning
first; pass `--option claude.import-mcp=false` or `--option claude.import-hooks=false` to answer
one ahead of time.

`box` doesn't read Claude Code's managed settings, the files an admin puts in
`/Library/Application Support/ClaudeCode/`. If your provider is set there, answer the question
yourself.

## How Claude Code asks before it acts

Claude Code in the box starts with the permission settings from your machine. The first time you
run a profile, the box copies your permission settings from `~/.claude/settings.json` into Claude
Code's own settings in the profile's [storage](../../../docs/cli/files.md#profile-storage-and-runs): your
default mode, and your allow, ask, and deny
rules. After that, the box keeps its own copy, so a later change to your settings doesn't reach
the box, and a change in the box doesn't reach your settings. `additionalDirectories` stays out,
because the box grants no folder outside the project for it. So does
`disableBypassPermissionsMode`, so `agent.skip-permissions = true` below still works.

Three places in the box can set the starting mode and add rules:

- Claude Code's own `config/settings.json` in the profile's storage, which starts as that copy.
  Claude Code and the agent can both write it, for example when you answer yes to "Make auto mode
  your default permission mode?", and the change stays for later runs of the profile in every
  project.
- The project's `.claude/settings.json` or `.claude/settings.local.json`. Claude Code ignores
  `bypassPermissions` there.
- Your organization's policy ([see below](#your-organizations-claude-code-policy-applies-in-the-box)).

With no mode in any of them, Claude Code starts in its own default, and the box checks each action
as well. In current versions of Claude Code that's auto mode: a second model reviews each action
instead of asking you.

To have Claude Code ask you before each action (its Manual mode) in this profile, whatever your
settings say, add this line to the profile, such as `~/.strands/box/profiles/claude/profile.toml`, next to
the `packs` line:

```toml
agent-args = ["--permission-mode", "manual"]
```

Claude Code still runs the commands and edits that an allow rule lists, without asking.

To have Claude Code never ask in this profile, whatever your settings say, set this under
`[options]` instead:

```toml
[options]
agent.skip-permissions = true
```

Then Claude Code's own prompt is no longer an extra check, and the box's file and program grants
and its policy decide what Claude Code can do. Claude Code's status line says
`bypass permissions on`, and it no longer asks before it edits a file or runs a command. Whatever
the box allows, Claude Code does, including deleting files in your project, so read
[Before turning permission prompts off](../../../docs/cli/limitations.md#before-turning-permission-prompts-off)
first. With `false`, the default, the profile changes nothing and your settings decide.

## What comes into the box

The first time you run a profile, `box` copies these into the profile's storage, and Claude Code
reads them from there in every project:

- Your `~/.claude` `CLAUDE.md`, `rules`, `skills`, `commands`, `agents`, `output-styles`,
  `themes`, and `keybindings.json`.
- From `~/.claude/settings.json`, only your display preferences, such as `theme`, `outputStyle`,
  `editorMode`, and `tui` (`default` or `fullscreen`), your model (`model`), and your permission
  mode and rules.
- From `~/.claude.json`, that you finished onboarding, your answer to the folder trust question
  for this project, and your interface toggles, such as `copyOnSelect`.
- On the first run in each project, that project's folder trust answer and Claude Code's auto
  memory for that project.

The rest of your setup stays outside the box, so Claude Code doesn't see:

- Your shell's environment variables, except fourteen that change only how Claude Code behaves or
  which model it asks for, such as `MAX_THINKING_TOKENS`, `BASH_DEFAULT_TIMEOUT_MS`, and
  `ANTHROPIC_MODEL`. The same fourteen come in from the `env` of `~/.claude/settings.json`.
- The rest of `~/.claude/settings.json`, such as the rest of `env`, `permissions`, and
  `apiKeyHelper`, the rest of `~/.claude.json`, such as your account and other projects, and your
  sessions.
- Your `hooks`, unless you [turn them on](#your-hooks).

Your instructions, skills, and look stay up to date with your Mac on each run, as
[Limitations](../../../docs/cli/limitations.md#instructions-skills-and-settings-in-the-box)
explains. Your settings from `settings.json` and `~/.claude.json`, and Claude Code's auto memory,
come in once: after that, the box keeps its own.

Claude Code keeps your folder trust and your auto memory under the root of the git repository. So
both come in when you run `box` at the root of the repository. From a folder inside it, Claude Code
asks the trust question once in the box, and starts with no memories.

Every project that runs the profile shares its storage, but Claude Code still keeps its
conversations apart by project, so `claude --continue` in one project shows that project's
sessions.

Your onboarding, trust answer, and toggles work a little differently from the other copies: on
every run, `box` adds each one that the box's `config/.claude.json` doesn't have yet. It never
changes one that's there. So a project that already ran in a box gets them on its next run, and
an answer you give in the box stays.

To run Claude Code without your skills, set `claude.import-skills = false` under `[options]` in the
profile. To run it without your display preferences and permission settings, set
`claude.import-settings = false`. For onboarding, trust, and toggles, it's
`claude.import-app-state = false`, and for auto memory, `claude.import-memory = false`. To keep
the fourteen variables from your shell out, set `claude.import-env = false`. The ones in the `env`
of `~/.claude/settings.json` come in with your display preferences, so `claude.import-settings`
decides those.

## Your organization's Claude Code policy applies in the box

If your organization manages Claude Code on your machine, the same policy applies in the box. Claude
Code in the box reads what your organization puts in the managed settings folder
(`/Library/Application Support/ClaudeCode` on a Mac, `/etc/claude-code` on Linux) and, on a Mac,
the device's managed preferences for `com.anthropic.claudecode`, as it does on your machine. It
can't change them.

So a policy that turns off the no-approval mode turns it off in the box too: with
`agent.skip-permissions = true`, Claude Code still asks before it acts, as it would on your machine.
The policy applies whole, so a value your organization sets in its `env`, keys included, reaches
the agent in the box, and its hooks run in the box.

A policy that your organization sets only for your user account on a Mac, rather than for the whole
device, doesn't reach the box. Neither do server-managed settings, which Claude Code fetches from
Anthropic, or a file in `managed-settings.d` that is a link to somewhere outside the folder.

## Your MCP servers

With `claude.import-mcp = true`, each run reads the servers in `~/.claude.json`: your own, and the
ones for the current project. A yes also covers the servers of each project you run the profile
in. [MCP servers in the box](../../../docs/cli/limitations.md#mcp-servers-in-the-box)
says what that lets the agent do.

The servers go in `config/.claude.json` in the profile's storage. Your own servers go in once for
the profile, as `mcpServers`. Each project's servers go in that project's own section,
`projects["<project path>"].mcpServers`, the first time you run the profile there, so a project's
servers show up only in that project. Claude Code writes an empty project section itself on its
first run in a project, so `box` still fills an empty project section. If your first project has
a `docs` server that replaces your own `docs` server, your own entry is left out and may be
missing when you use the profile in other projects.

`box` fills in each variable in a local server's `command` and `env`, such as `${GITHUB_TOKEN}` or
`${LOG_LEVEL:-info}`, from the shell you run `box` in. In `env`, `~/` at the start of a value means
your home folder, so `~/logs` becomes `/Users/you/logs`. When a variable in `command` or `env` has
no value and no `:-default`, `box` generates no policy for the server. Claude Code would start it
with the `${LINEAR_TOKEN}` text in place of the key instead.

For a remote server, the box can supply a key from a variable in a header that ends in one
variable, such as `"headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}` or
`"X-Api-Key": "${DOCS_TOKEN}"`, or in a URL whose query holds one, such as
`https://docs.example.com/mcp?api_key=${DOCS_TOKEN}`.

Claude Code also accepts a literal fallback, such as `Bearer ${DOCS_TOKEN:-public}` or
`?api_key=${DOCS_TOKEN:-public}`. When `DOCS_TOKEN` is set, the box supplies its value and the
agent gets a placeholder. When it is unset, Claude Code uses `public`, which remains readable in
the configuration inside the box. If the variable is empty or contains only whitespace, `box`
generates no policy for the server; it does not select the fallback. Nested variables and text
after the reference are not supported.

`box` doesn't read the project's `.mcp.json`, because the agent can change it in the box. To have
`box` read one of those servers, add it to your own configuration instead, for example with
`claude mcp add --scope user`.

To import your servers again, follow the
[manual refresh steps](../../../docs/cli/troubleshooting.md#box-lists-an-mcp-server-but-my-agent-doesnt-show-it).
In step 4, remove the complete top-level `mcpServers` property from `config/.claude.json` for
your own servers, or `projects["<project path>"].mcpServers` for one project's servers.

## Your hooks

Claude Code in a box doesn't run the hooks in your `~/.claude/settings.json` unless you turn them
on, and in the box a hook is a convenience, not a guardrail. To bring your hooks in, set this under
`[options]` in the profile:

```toml
claude.import-hooks = true
```

On each run, `box` reads your hooks again and keeps each command hook that runs one shell script,
such as `~/.claude/hooks/format.sh` or `bash ~/.claude/hooks/format.sh`. The script runs in the
box's shell with the agent's own policy, gets the event on its standard input, and its exit code
and output reach Claude Code as on your machine.

A script gets at most 1 MiB of the event. A larger event, such as a `PostToolUse` event for a
big file write, can make a script hang or see an empty event, and the run may print
`strands-box: stdin is more than 1048576 bytes`. For hooks that read large events, raise both
limits in the profile:

```toml
[limits]
shell.max_stdin = 4194304
shell.max_output = 4194304
```

`box` adds a rule to the run's policy that lets the box read each of these scripts, and nothing
else in their folder. The agent can read them too, so keep secrets out of them. `box run` lists
each script:

```text
box: imported hooks run ~/.claude/hooks/format.sh, and the policy permits its read
```

`box` leaves out each hook it can't run in a box, and says why:

- **An inline command**, such as `jq -r .tool_input.file_path | xargs prettier --write`. Put the
  command in a script and name the script.
- **A hook with arguments**, such as `~/.claude/hooks/check.sh --strict`.
- **A script in this run's project**, or anywhere else this profile's box can write, or one whose
  path passes through a folder or link there, because the agent could change what it does, or which
  file it names, in later runs. `box` can't see your other projects, so keep hook
  scripts out of every project folder.
- **A script in a folder that a [plugin](../../../docs/cli/plugins.md) keeps on
  your machine**, such as `~/.config/op`, when your profile lists the plugin.
- **A script that isn't a shell script**, such as one that starts with `#!/usr/bin/env python3`.
- **A hook for another shell**, such as one with `"shell": "powershell"`. The box's shell runs
  bash scripts only.
- **A command that starts another program**, such as `python3 ~/.claude/hooks/check.py`.
- **A script whose real path has a space, a quote, or another character** outside letters, digits,
  and `/._-+@,`. Rename the folder or the script.
- **An `http`, `prompt`, `agent`, or `mcp_tool` hook.**

```text
box: did not import the hook PostToolUse (Edit) #1: an inline command is not imported; ...
```

If your settings set `disableAllHooks`, no hook comes in, and Claude Code in the box runs no hook at
all, whether or not `claude.import-hooks` is on. The copy's `disableAllHooks` follows your settings,
so one set only in the box does not persist; if `box` cannot read your settings, it leaves the
copy's value as it is and says so. With `claude.import-hooks = false`, the default, `box` removes
every hook in the box's copy of your user settings, including ones an earlier run brought in. If
`box` cannot parse that copy, the run stops and names the file; fix the file, or delete it so that
`box` copies it again.

Hooks in the box's copy of your user settings come from your host settings. A hook that is added or
changed there inside a box, for example by saving it to user settings with Claude Code's `/hooks`
menu, does not persist to the next run: each run sets those hooks from your settings again and
removes the hooks written in the box. A hook saved to the project's `.claude/settings.json` or
`.claude/settings.local.json` stays in the project, and later runs and Claude Code outside the box
run it; see [The agent can plant code that runs outside the box
later](../../../docs/cli/limitations.md#the-agent-can-plant-code-that-runs-outside-the-box-later). Other settings the agent writes
in the box stay, including a plugin it installs or a `statusLine` command, and those run in later
runs too. `box` never changes your own `~/.claude/settings.json`.

A script runs in the box's shell whether it names `sh`, `bash`, or `zsh`, so syntax that only zsh
knows doesn't work. The shell reads the script with `.`, so `$0` isn't the script's path: a script
that finds its own folder with `dirname "$0"` needs the full path written out.

A profile is one trust zone: a box in one project can affect the profile's other projects. Use a
separate profile for projects that must stay apart. For example, all runs of one profile share one
copy of the settings, so while two runs are open at once, a hook that one run's agent writes can
reach the other run until that run starts again.

`box` doesn't change the hooks in a project's `.claude/settings.json`. In a box, such a hook runs
only when it names its program and arguments apart, as `{"command": "bash", "args": ["..."]}`. A
hook's script can't read the `CLAUDE_PROJECT_DIR` variable. A program that the script starts, such
as `npx`, gets no standard input.

A hook can't stop the agent from doing something. The agent can change its own settings during a
run, and a hook that fails lets the action go ahead. To make a rule that holds, write it in the
profile's policy. For example, once the box has a git tool grammar
([tool grammars](https://github.com/strands-agents/box/blob/main/docs/user/tool-grammars.md)), this
[Dogwood](../../../docs/cli/how-box-works.md#policy) rule refuses every push that rewrites a
remote branch, however the agent spells it:

```text
@id("no_force_push")
forbid (principal, action == Tool::git::Action::"push", resource)
when { context.input.effects.contains(Tool::git::Effect::"force_push") };
```

## Claude Code knows it runs in a box

Each time Claude Code starts, `box` tells it how the box works, where your profile is, and that its shell is not a full bash. So when
the box blocks something, Claude Code should say so, name the path, program, or host, and show the
change to make in `profile.toml`. A conversation you resume keeps what it was told when it started.
Claude Code updates it when it compacts the conversation.

## Shell command timeout

According to Claude Code's documentation, its Bash tool waits 2 minutes for a command by default, and the model can ask for up to 10 minutes. At the limit, Claude Code moves the command to the background and does not stop it. `BASH_DEFAULT_TIMEOUT_MS` and `BASH_MAX_TIMEOUT_MS` come into the box from your shell or from the `env` of `~/.claude/settings.json`, unless you set `claude.import-env` to `false`. For the box's own Shell timeout, see `shell.timeout` in the [profile reference](../../../docs/cli/profiles-reference.md#limits).

## WebFetch checks each site with Anthropic

Before each WebFetch, Claude Code asks `api.anthropic.com` whether the site is safe to fetch. A
Bedrock profile doesn't route that host, so under a policy that refuses hosts the profile doesn't
route, such as Scoped, the check fails and so does every fetch. So in a Bedrock profile, each run
sets `"skipWebFetchPreflight": true` in Claude Code's `config/settings.json` in the profile's
storage, and Claude Code skips the check, whatever the policy. The profile's routes and its policy
decide which sites WebFetch reaches. Under a policy that permits every host, such as Open, nothing
takes the check's place.

A Bedrock profile writes that file on its first run even when `~/.claude/settings.json` doesn't
exist yet. Because the box copies your settings only when it has no copy, settings that you create
on your machine after that first run don't come into the box. To bring them in, delete
`agent/config/settings.json` from the storage folder that `box profile show` prints, and the next
run copies your file again.

With the Anthropic API (`claude.host = "anthropic"`), the `@box/anthropic` route reaches
`api.anthropic.com`, so the check stays on. A profile that you move from Bedrock to the Anthropic
API keeps the setting from its earlier runs. To turn the check back on, remove
`skipWebFetchPreflight` from `agent/config/settings.json` in the storage folder that
`box profile show` prints.

## Limitations

- Signing in with a claude.ai subscription doesn't work in a box. Use an Anthropic API key
  (`@box/anthropic`) or Amazon Bedrock (`@box/bedrock`).
- If your organization deploys `managed-mcp.json`, Claude Code uses only the MCP servers it lists,
  and those servers don't work in the box yet. Your own servers from `~/.claude.json` don't load
  either, because the policy turns them off.
- With `claude.import-settings = false`, `box` doesn't set `skipWebFetchPreflight`, so in a
  Bedrock profile WebFetch fails with `Unable to verify if domain ... is safe to fetch`. Add
  `"skipWebFetchPreflight": true` to `agent/config/settings.json` in the storage folder that
  `box profile show` prints.
- `box` doesn't read the setting Claude Code uses when you turn off a server with `/mcp`.
- A sign-in helper (`headersHelper`) for an MCP server may fail in the box.
- With the Locked policy (`@box/locked`), Claude Code's Bash tool runs no command, `git` included,
  because it runs setup commands of its own before each one, such as `setopt` and `true`. Its file
  tools still work. To let it run commands, add the `shell_commands` rule from the comment in your
  `policy.dw` without its condition, which gives the shell what
  [Scoped](../../policies/scoped/README.md) allows. A condition that
  lists commands must also name each setup command; `box runs history <box-id> --deny --action
  shell:exec` lists the ones a run refused.

## Troubleshooting

### Claude Code isn't found

```text
box: error: /Users/you/.strands/box/profiles/claude/profile.toml: `agent.command.0`: no `claude` that the box can run in the folders `[inputs.claude.path] search` names; passed over /opt/homebrew/bin/claude (a node script, which the box cannot start). Install it, or set `claude.path` in your profile's `[options]`
```

`npm install` puts Claude Code on your Mac as a Node.js script, but the box needs its own program.
Reinstall with Anthropic's native installer:

```sh
curl -fsSL https://claude.ai/install.sh | bash
```

If Claude Code lives somewhere `box` doesn't look, set `claude.path` under `[options]`, as
[The agent isn't found](../../../docs/cli/troubleshooting.md#the-agent-isnt-found) shows.

### Claude Code starts, then sits there

Most likely your AWS account can't use the model Claude Code picked. Bedrock answers each request
with 403, Claude Code keeps retrying without a word, and the run looks hung.

The box uses the model from your Claude Code settings, and Claude Code's default model when you set
none. The model has to be one that Bedrock serves in the profile's region. Where the model came
from decides how to change it in the box:

| Where you set the model | How to change it in the box |
| --- | --- |
| `model` in `~/.claude/settings.json` | Type `/model` in Claude Code in the box and pick another one. The box keeps that choice for later runs. |
| `ANTHROPIC_MODEL` in your shell | Set `ANTHROPIC_MODEL` in the `[agent.env]` section of `profile.toml`, as below. It replaces the value from your shell on every run, and `/model` doesn't. |
| `ANTHROPIC_MODEL` in the `env` of `~/.claude/settings.json` | The box copied it once, on the profile's first run. Change it in the box's copy: `agent/config/settings.json` in the storage folder that `box profile show` prints. |
| Nowhere | Set `ANTHROPIC_MODEL` in the `[agent.env]` section of `profile.toml`, as below. |

Add the section to `profile.toml` if it isn't there:

```toml
[agent.env]
ANTHROPIC_MODEL = "global.anthropic.claude-opus-5-5"
```

To see which models your account can use, run the command in
[Get started](../../../docs/cli/getting-started.md#3-choose-the-model).

Then stop the stuck run with Ctrl-C and start it again. If it still hangs, work through
[Every model request fails with 403](../bedrock/README.md#every-model-request-fails-with-403).

### Your settings file isn't valid JSON

```text
box: error: cannot copy /Users/you/.claude/settings.json into storage: `storage.files[8]`: the source is not JSON: trailing comma at line 1 column 18
```

Fix the file, for example by removing the trailing comma, and run again. To run without your
display preferences and permission settings, set `claude.import-settings = false` under
`[options]` in the profile. For `~/.claude.json`, which holds your onboarding and folder trust,
set `claude.import-app-state = false`.
