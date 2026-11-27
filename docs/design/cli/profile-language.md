# The profile language

A profile tells `box run` how to run one agent in a box on any host. This page states the
language that profiles and packs are written in: how a value names something on the host, how a
pack declares what it reads, how packs compose, and the rules that keep a value from changing what
it means. The reason for each choice is an entry in [decisions.md](decisions.md).

Audience: developers of `box`, and authors of packs. The commands are in
[cli.md](../../cli/cli.md).

## The model

There are three kinds of file, each TOML in the shape of Box Core's `box.toml`
([decisions.md](decisions.md#base-is-reserved)): the profile, the pack, and the [plugin](plugins.md),
which declares a host program that Box Core runs outside the box, in the same `[run]`, `[env]`,
and `[filesystem]` tables as a pack that runs one program. Each pack states its [kind](#pack-kinds) in
`[pack] kind`. A pack holds only tables, and `[pack]` comes first. An agent pack and a tool pack
each run one program: `[run]` says how it starts, and `[env]` and `[filesystem]` are its own
([Agent packs](#agent-packs), [Tool packs](#tool-packs)). A profile holds the operator's values
and additions, and only a pack declares inputs or extends another pack. Which keys and tables
each file holds and refuses is in
[What a profile holds](../../cli/profiles-reference.md#what-a-profile-holds) and
[What a pack holds](../../cli/packs-reference.md#what-a-pack-holds), and
[Pack kinds](#pack-kinds) says how `box` checks a pack against its kind:

| | Profile | Support pack | Agent pack | Tool pack |
| --- | --- | --- | --- | --- |
| File | `~/.strands/box/profiles/<name>/profile.toml` | `<folder>/pack.toml` | `<folder>/pack.toml` | `<folder>/pack.toml` |
| `box run` takes it | Yes | No | No | No |
| Imported by | Nothing | A profile's `packs`, or a pack's `extend` | A profile's `packs`, or a pack's `extend` | A profile's `packs`, or a pack's `extend` |

`box` checks the keys of each file before the merge: the top level, `[pack]`, `[storage]`, `[experimental-features]`,
`[run]`, `[agent]`, each `[tool.<name>]`, their `filesystem` tables, and each `[tool.<name>.network]`, which only a profile writes and which takes no `when`. A refusal of a key names the file
and the key's line, from the `toml_edit` spans. It suggests the one known key closest to it, when
that key is at most one edit away for each three characters (and at least one edit). A swap of two
neighbors is one edit, and a tie suggests nothing. `[egress]`, `[mcp]`, and `[telemetry]` keys go to Box Core as
written, and Box Core checks them.

The profile's `[limits.shell]` table reaches Box Core with the keys the profile sets, and with
`timeout = false` when the profile sets no `timeout`. Outside a box a shell has no per-command limit,
and only the agent's own tool timeout applies, so the box adds no second one and Box Core's own
30 seconds does not apply. Box Core supplies the defaults for the other keys. Packs cannot set these limits. The
[profile reference](../../cli/profiles-reference.md#limits) defines each setting.

The profile's `[project]` table holds one key, `access` (`profile::ProjectAccess`). Its values
and default are in [Project access](../../cli/profiles-reference.md#project-access).
`lang::check_project` refuses another key or value, and a pack that holds the table.
`Resolved::project_access` reads it and supplies the default when the profile has no table.
Three steps read it: `compile` for the agent's `filesystem.read` and `filesystem.write` and for the
`project_*` permits, `tool::compose` for each tool that names a `program`, and the MCP
grant step for each detected stdio server (`mcp::Context::project`). `read` adds the project to
`read`, and `write` adds it to `read` and `write`. The `<project>/.box` deny and the
`project_configuration_*` forbids do not depend on it
([decisions.md](decisions.md#project-access-is-one-profile-level)).

The profile's top-level `[filesystem]` holds `deny`, `deny_write`, and `when`
(`profile::ProfileFilesystem`). `lang::check_profile_filesystem` refuses another key, and a support
pack refuses the table; in an agent or tool pack it is that pack's process. Its entries expand as a
filesystem list. `compile` adds each entry to the `deny_write` of the agent, each tool, and each
stdio MCP server, before it drops each entry that no write grant of that process holds. It adds
each `deny` entry to the `deny` of every process and writes the `filesystem_deny_*` forbids. Each
`deny_write_*` and `filesystem_deny_*` forbid carries an `@description` that names its list, so a
Shell or Monty denial says where the rule comes from
([decisions.md](decisions.md#an-agents-deny-write-folder-is-closed-to-the-shell-and-monty)).

**`${{ name }}` in a string marks a value that `box run` fills in, so a value that changes is a string.**
A literal can have another type where its key allows one, such as a `[[storage.files.set]]` value.
A name is built in, or is `inputs.<name>` for an input that a pack declares. A profile only sets
an input's value. A pack makes an agent run as it runs on the host, and never extends the agent
([decisions.md](decisions.md#a-pack-makes-an-agent-run-and-never-extends-it)).

`box run` works in two phases. It loads each file, writes a tool pack as its tool table, and
binds `${{ pack }}` in it to that file's folder. Then it merges the files and fills in every other
placeholder.

### Incoming mount selections

`filesystem.receive_mounts` selects directories for one agent, tool, or local MCP server.
`lang::is_receive_mounts` keeps this selection separate from access lists, so it never adds
a read, write, or execute grant. Pack composition appends selections for the same process;
resolution fills path placeholders, expands `~/`, and removes duplicate strings without
resolving links or expanding wildcards. Box Core validates the selected directories and
pins their identities when it prepares each process.

`profile::Filesystem` stores an optional list so compilation preserves explicit `[]` separately
from omission. After evaluating `when`, the resolver rejects a present selection on macOS,
including an empty list. Compilation carries the selection to the same process in `box.toml`
and adds no experimental feature switch or policy rule. The CLI accepts native read, write, and execute access only for an `exec` entry that exactly
matches the same process's selected directory. A covering ancestor `exec` entry is refused with
an instruction to name the selected directory and other executable directories separately.
The exception applies only to generic executable-directory checks. Configured commands,
command files, search-path directories, secret sources, and protected state keep their existing
write protections, even when they overlap a selection. There is no deferred filesystem resolution.

## An example

`box profile create claude --with bedrock --option bedrock.region=us-east-1 --policy open` writes
a profile like this one, shortened (the tool packs, the header comment, and the other options are
left out; [What's in a profile](../../cli/profiles.md#whats-in-a-profile) shows the whole
file), and a copy of `@box/open`'s rules in `policy.dw` beside it
([starters.md](starters.md#the-policy-question)):

```toml
packs = ["@box/claude", "@box/bedrock"]
policies = ["policy.dw"]

# How much of your project the agent reaches: "none", "read", "write".
[project]
access = "write"

[options]
bedrock.region = "us-east-1"
```

`@box/claude` is a pack that `box` ships. It extends one more, and declares its inputs (the
telemetry variables, the input `claude.import-skills`, and the copies are left out):

```toml
[pack]
name = "@box/claude"
version = 1
kind = "agent"
extend = ["@box/base"]

[run]
command = [
    "${{ inputs.claude.path }}",
    { value = "--dangerously-skip-permissions", when = { variable = "inputs.agent.skip-permissions", equals = "true" } },
    { value = "--settings", when = { variable = "inputs.agent.skip-permissions", equals = "true" } },
    { value = '{"skipDangerousModePermissionPrompt":true}', when = { variable = "inputs.agent.skip-permissions", equals = "true" } },
]

[inputs.claude.path]
description = "The Claude Code program."
type = "program"
program = "claude"
search = [{ env = "PATH" }, "${{ home }}/.local/bin"]

[inputs.agent.skip-permissions]
description = "Turn off Claude Code's permission prompts, whatever your copied settings say, unless your organization's policy turns that mode off. The box still allows or refuses each action."
type = "bool"
default = false

[inputs.claude.host]
description = "Where Claude Code's model runs."
type = "string"
values = ["bedrock", "anthropic"]
default = "bedrock"

[storage]
directories = ["config", "tmp"]

[env]
CLAUDE_CONFIG_DIR = "${{ storage.config }}"
CLAUDE_CODE_TMPDIR = "${{ storage.tmp }}"
TMPDIR = "${{ storage.tmp }}"
CLAUDE_CODE_USE_BEDROCK = { value = "1", when = { variable = "inputs.claude.host", equals = "bedrock" } }

[filesystem]
read = ["${{ inputs.claude.path }}"]
exec = ["${{ inputs.claude.path }}"]
```

`@box/base` declares `terminal.term` and `terminal.colorterm`, and `@box/bedrock` declares
`bedrock.region`, `bedrock.sign-in`, and one model route for each sign-in, each with a `when` on
`bedrock.sign-in`.

## Packs

### Lookup

`@box/<name>` is `resources/packs/<name>/pack.toml` (or `$BOX_RESOURCES/packs/<name>/pack.toml`),
a pack that `box` ships ([decisions.md](decisions.md#the-starters-are-files-beside-box)). A plain
name is `~/.strands/box/packs/<name>/pack.toml`, a pack that the operator adds. Any other
`@<scope>/<name>` is `~/.strands/box/external/<scope>/packs/<name>/pack.toml`, a pack in a
[collection](../../cli/files.md#collections) that the operator cloned into the box home
(`Lookup::in_collection`). A scope with no folder in `external/` stops the load. Plugins, starters, and policy starters use the same three places, in `plugins/`,
`starters/`, and `policies/`.

A plain name never reaches a collection, and a collection never answers an `@box/` name. So a
`git pull` in a collection changes only the profiles that name its packs in full, and each of
those profiles names the pack it gets. The short part of a name is letters, digits, `.`, `_`, and `-`, and does not start
with `.`. A name in `packs` or `extend` holds no placeholder.

### The header

Every pack starts with `[pack]`. Its keys are in
[`[pack]`](../../cli/packs-reference.md#pack). `lang::check_kind` checks the header, and refuses
any other key in it, before it loads the packs that the pack extends: `name` must be the name that
imports the pack. Before that, `lang::take_requires` checks the file's `[requires]` against
`box`'s own version and takes the table out, so the merge never sees it. It does the same for a
plugin and for the profile, and checks `box` before any other requirement. `Profile::parse` takes
the profile's `[requires]` out before its own key checks, so a profile for a later `box` gets the
version before a key of `[banner]` or `policies` that the later `box` added. The load takes
`extend` out of the header and keeps it at the top of the table. `box profile show` prints each
pack's `name` and `version` in the order that `packs` and `extend` name them: a pack, then the
packs it extends, and each pack once.

### Pack kinds

`[pack] kind` states what a pack is. It is required, and it alone decides which keys the pack
holds: `box` checks the pack's keys against its kind, and its kind against the packs it extends
([decisions.md](decisions.md#a-pack-states-its-kind)).
[What a pack holds](../../cli/packs-reference.md#what-a-pack-holds) lists the kinds and the packs
each kind can extend, and the keys of `[run]` are in
[An agent pack's `[run]`](../../cli/packs-reference.md#an-agent-packs-run) and
[Tool packs](../../cli/packs-reference.md#tool-packs).

`lang::pack_layout` checks the file when it loads: only tables at the top, the header with its
`kind`, and the keys of `[run]` against `AGENT_RUN_KEYS` or `TOOL_RUN_KEYS`. A support pack with
`[run]`, `[env]`, or `[filesystem]` stops there. It hands the load `extend` and the keys of
`[run]` at the top of the table, so [Agent packs](#agent-packs) and [Tool packs](#tool-packs) move
them on. `lang::check_kind_of_bases` checks the kinds of the bases after they load. It refuses a
tool or support pack that extends an agent pack, an agent or support pack that extends a tool pack
(an agent pack names a tool pack in `include` instead), and an agent pack when neither it nor a pack it
extends holds `[run] command`. A support pack writes `[agent.env]` and the other `[agent]` tables
by name, as `@box/base` and the provider packs do.

A tool pack that extends a tool pack inherits that pack's tool, as an agent pack that extends an
agent pack adds to the same agent. `lang::merge` records, for each tool a tool pack writes, the
tools of the tool packs it extends, through the whole chain and the nearest first
(`Merged::tool_bases`). In the compose step, after every skip, `[tool.go]` gets the resolved
`[tool.git]`: its variables but `PATH` and `TMPDIR`, every `[filesystem]` list with the writes, a
read of git's program, and git's folder on go's `PATH`. go's own variable wins, and a nearer base
wins over a farther one. A skipped base gives nothing, and the tool is kept. A support pack in the
chain gives nothing and ends it, and `helpers` gives only what it gave before.

A tool that only `extend` brings in is not a tool of its own (`Merged::hidden_tools`): after the
checks that need every tool, `tool::hide_bases` leaves `[tool.git]` out of `box.toml`, so it has no
spawn permit, and moves its `hosts` and `upgrade_http` to the tools that extend it. A tool pack that
the profile's `packs` or a pack's `include` names is a tool of its own, as is a tool whose `program`
the profile or a support pack sets. `include` names tool packs
only, loads them before the pack that names them, and merges nothing of them into it, so a support
pack includes `@box/npm` to add to `[tool.npm]`. An agent pack names a tool pack in `include`, and
`extend` of one stops the load, as does a support pack's `extend` of a tool pack. A `dependency` on
a hidden tool stops the load (`reference::refuse_hidden_dependencies`).

### Trust

Every pack is trusted like the operator's own profile
([decisions.md](decisions.md#every-profile-in-the-chain-is-trusted)), and a collection's packs
are trusted like the packs in `~/.strands/box/packs/`. A collection lives in the box home, so each
run protects it as it protects the rest of the box home, and a collection folder that is a link is
refused. A pack from a registry is [not built](#not-built).

## Values

A value is a TOML string. `${{ name }}` marks a placeholder. Everything else in the string is
literal, so `${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}` in a Codex argument stays as it is
([decisions.md](decisions.md#values-that-change-are-explicit-references)).

| Rule | Detail |
| --- | --- |
| Closed names | A placeholder names a built-in name or a declared input. Any other name stops the load, with the file and the reason. |
| One expansion | `box` expands a value once. A value that holds `${{` after expansion stays literal. |
| Escape | `$${{` writes a literal `${{`. |
| Template fields | A placeholder goes only in the fields that [Which fields take a placeholder](../../cli/profiles-reference.md#which-fields-take-a-placeholder) lists. For the tables that reach `box.toml`, `takes_template` decides it. Every other field is literal, and a table key never holds a placeholder. |
| Option values | A value in `[options]` is literal. A placeholder in it stops the load. |
| Paths | A path field is a filesystem list entry, a `[[storage.files]]` `source`, a `[[mcp-servers]]` `file`, and a `command` element that holds a placeholder and is element 0 or starts with a path name (`workspace` with or without steps, `home`, `profile`, `box`, `cache`, `storage.*`, `root` and `tool.*.root` with or without steps, `macos.developer_dir`, `macos.toolchain`, `macos.sdk_root`, or a `program` input). An `agent-args` element is never element 0, so it is a path only when it starts with a path name. In a path field, a placeholder comes first, each later placeholder fills one path component (no `/`, not `.` or `..`), and the result is absolute (or starts with `~/`, which Box Core accepts in a filesystem list) with no `..`. |
| Grants | `box` resolves existing filesystem entries to their real paths. A `read_file` link to a file keeps its name in its real parent folder, so Box Core can make that name available. An entry that resolves through a link inside a place a box can write stops the run ([safety rules](#safety-rules)). |
| Encoding | The destination encodes the value. A policy rule gets a quoted policy literal (`render::literal`). `box` never builds shell text. |

Terraform's JSON syntax takes the same approach: in a plain data format, a string is a template, a
published list of fields is always literal, and a reader sees the template where the value is used.

### Built-in names

[Placeholders](../../cli/profiles-reference.md#placeholders) lists each built-in name and its value.
`Resolver::name` resolves them after the merge, and refuses any other name. `pack` is the
exception: the load binds it to the folder of each file before the merge, so a `pack` that reaches
`Resolver::name` stops the run. These names need more than a value of the run:

- `root` is the folder of the real file that `[agent] command` element 0 names, and in a tool pack
  `box` rewrites it to `tool.<name>.root` ([Root steps](#root-steps), [Tool packs](#tool-packs)).
  `tool.<name>.root` exists only for a tool whose program the host has
  ([Resolution](#resolution)).
- `storage.<dir>` in a tool table names the tool's own directory first
  ([Tool storage](#tool-storage)).
- `cache` exists only in a tool table. It is `<workspace>/.cache/<name>` for a tool of the agent,
  and `<storage>/mcp-cache/<name>` for an MCP launcher ([Launcher packs](#launcher-packs)).
- The `macos.*` names run `xcode-select` once per run, and only when a kept entry names one
  ([The developer folder](#the-developer-folder)).
- `workspace.dashed` puts one `-` for each UTF-16 unit of each character other than an ASCII letter
  or digit (`lang::dashed`), so it matches Claude Code's project folder name.

### Path steps

`workspace`, `root`, and `tool.<name>.root` take steps. Each `.parent` after the name, as in
`workspace.parent` or `root.parent.parent`, moves to the parent folder. At `/`, a step stays at
`/`. Any other step stops the run with `` `<step>` is not a step of `<name>`; use `parent` ``.
`<name>` is `workspace` or `root`. A step of `tool.<name>.root` is a step of `root`, because a tool
pack writes `root` and `box` rewrites it to `tool.<name>.root`
([Tool packs](#tool-packs)). One function applies the steps for all three names.

`dashed` comes only right after `workspace`. `workspace.parent.dashed` and
`workspace.dashed.parent` stop the run. `workspace.dashed` is one path component and not a folder,
so it takes no step.

A name with steps is a path name, so a `command` element that starts with it is a path field
([Values](#values)). In a `[[storage.files]]` `target`, and after the first placeholder of a path,
a placeholder fills one name, so `workspace.parent` stops the load there. A key in a `keep`, `set`,
or `target-key` list is one key, not one path component, so `${{ workspace.parent }}` is a valid
key.

## Inputs

An input is a value that the operator or the host supplies. A pack declares it, and a profile can
set it. A reviewer reads the `[inputs]` tables to learn every value a run reads from outside the
packs.

### Declaration

A pack declares an input under its full dotted name, which does not depend on the pack's folder:

```toml
[inputs.claude.host]
description = "Where Claude Code's model runs."
type = "string"
values = ["bedrock", "anthropic"]
default = "bedrock"

[inputs.terminal.term]
description = "The terminal type the agent draws for."
from = "env:TERM"
default = "xterm-256color"
```

The declaration keys, their values, and their defaults are in
[Inputs](../../cli/packs-reference.md#inputs). `lang` checks each table under `[inputs]`
against `DECLARATION_KEYS`. A table that holds a declaration key is one input, and it cannot also
hold other inputs. `description`, `type`, `pattern`, `from`, `key`, `program`, and `warning` are literal.
`program` and `search` drive the [program search](#program-search), and `pattern` and `values` are
the [bounds](#bounds).

`from` is the only host source of a declaration. `key` narrows it to one item of a
comma-separated `key=value` list (`lang::list_value`), so a pack reads a value that a host puts in
such a list, as OpenTelemetry does in its header and resource variables. A pack reads no host file, except the folders and
`#!` lines that a program search reads
([decisions.md](decisions.md#a-pack-reads-a-host-file-for-now)), and a starter reads the agent's
settings files once, at create ([detection](detection.md)). `warning` is for the starter:
it asks for each input that has one, shows it under the prompt, and writes the answer to the
profile ([starters.md](starters.md#answer)).

### The value

[Where the value comes from](../../cli/packs-reference.md#where-the-value-comes-from) gives the
order of an input's sources. A TOML
`true`, `false`, or integer in `[options]` becomes its text. An `[options]` entry that no pack
declares, or that fails its declaration, stops the load. A `default` has its placeholders filled
in before it is used, and an unset or empty `from` variable falls through to the next source, as
does a list that holds no value for `key`. [Inputs](../../cli/packs-reference.md#inputs) says which
lists and values stop the run.

An input with no value from any source stops the run. `box` then checks the value against
the declaration, whatever its source: a `bool` is `true` or `false`, the value is in each `values`
list, and it matches each `pattern`. `box profile show` prints each input that a run reads, its
value, and its source (`your profile`, the `from` source, `search`, or `default`).

- A `program` value is an absolute, executable file outside the workspace, the run's storage, and
  `~/.strands/box`. After `box` fills in the whole profile, the [write grant check](#safety-rules) also
  refuses one under a write grant. `box` runs no `program` value while it resolves a profile. The
  program of a [secret source](plugins.md) is the one exception: Box Core runs it outside the box,
  in the `box` process, when the run starts.
- `box` compares a `program` value with a root twice: as written, and as its real path (each link
  in the path and in its parents followed). Each root is compared as given and as its real path.
  So a link in the workspace to a file outside it, and a link outside the workspace to a file in
  it, both stop the run.
- A search that finds no program is a host absence, not a profile error. `box run` stops on it.
  `box profile create` reports it as an agent that is not on the host, and stops on every other
  error.
- An `env:` input cannot read a variable that an `env://` credential reference or a `secret.env`
  in the merged profile names, or that a [secret source](plugins.md) passes to its program as a
  credential: a plugin's `[env]` entry that its `[protect] env` names, or a `pass-secret-env` entry of a
  profile's source ([decisions.md](decisions.md#an-env-reference-cannot-read-a-credential)).
- An input whose default names itself, directly or not, stops the run.

### Program search

A `program` input with `program` names a file, and `search` names the folders it can be in. An
agent pack declares its agent this way, so `box` holds no list of agents or of where each one
installs:

```toml
[inputs.claude.path]
type = "program"
program = "claude"
search = [
    "${{ home }}/agents/claude/*",
    { env = "PATH" },
    "${{ home }}/.local/bin",
]
```

A `search` entry is one of these:

- A folder, as a path field with placeholders. A literal `*` in one component matches each name in
  that folder.
- `{ env = "<NAME>" }`: each absolute folder in the variable `<NAME>` of the shell that runs
  `box`, split on `:`, in order. A relative or empty folder is passed over, and an unset variable
  adds no folder. The `env` name is literal, and it cannot name a variable that an `env://`
  credential reference or a `secret.env` in the merged profile names, or that a `pass-secret-env`
  entry holds. For `PATH`, `box` reads the search path that
  it also uses for tools.

`box` tries `<folder>/<program>` in each folder, in the order that `search` lists them:

1. A candidate that does not exist is skipped.
2. `box` follows each link to the real file.
3. `box` passes over a candidate that is not an executable file, that is a script whose `#!` line
   runs node, or that lies in the workspace, the run's storage, or `~/.strands/box`, as written or real.
4. The first candidate that remains is the value, as its real path.

An `[options]` or `from` value of an input with `program` passes the same checks, and its value
is its real path, so a node script set by hand stops the run with the same reason. A value of an
input without `program` stays as written, because a link name can choose the mode of a program
(`clang++` is a link to `clang`). After `box` fills in the profile, it refuses a `program` input at
`[agent] command` element 0 that is a node script, from any source. A tool can run a node script,
because it takes the grants of its `#!` chain.

`box` never runs a candidate. When no candidate remains, the error lists each candidate that
`box` passed over and why, and names the option that sets the input.

**How a `*` sorts.** The folders that one entry matches sort newest first by the numbers in each
folder's path. Each run of digits is one number, and two paths compare number by number, left to
right. So `10.0.0` sorts before `2.0.0`, and `2.1.316` before `2.1.314`. When the shared numbers
are equal, the path with more numbers sorts first. Paths with the same numbers sort by name, in
reverse. The matches of one entry stay together, so the entries keep the order that `search`
lists.

`program` and `search` stop the load on an input whose `type` is not `program`, and on an input
that has a `default`. `search` without `program` stops the load. Two packs that declare one input
follow [One input in two packs](#one-input-in-two-packs).

### Bounds

An input that reaches a field where a program parses it, or where it names a route's host, must
have `pattern` or `values`
([decisions.md](decisions.md#an-input-in-a-command-or-route-is-bounded)). A telemetry target's URL
`destination` gets the same bound, because the box sends its records and the target's credential
there. A `file` target's `destination` takes no placeholder at all, so no input, host variable, or
built-in name such as `${{ workspace }}` picks the file that gets the records. The agent can write
the workspace and the run's storage, and a records file there is one it could truncate or forge.
`region` and the CloudWatch names need no bound, because Box Core builds the AWS host from `region`
and checks each name.
[Inputs that reach `command` or a route](../../cli/packs-reference.md#inputs-that-reach-command-or-a-route)
lists the fields and the exemptions. `Resolver::input` checks the bound when it expands the input
in one of those fields, so an input that reaches none of them needs none. A free-form value goes in `env`.

### One input in two packs

Two packs can declare one name, and then they declare one input:

| Part | Rule |
| --- | --- |
| `type` | Must be the same in each declaration. |
| `pattern`, `values` | The value must satisfy each one. |
| `warning` | `box` keeps each distinct warning, in pack order. |
| `default`, `from`, `program` and `search` | When two packs give different values, or one gives a `search` and another a `default`, `box` uses none, and the error names each pack and its value. The operator sets the input in `[options]`, and then no pack's value is read. |

`@box/bedrock` and `@box/bedrock-mantle` both declare `bedrock.region`, and `@box/codex` uses it.

An input exists only when it changes what the box allows or how the box is wired
([decisions.md](decisions.md#an-option-changes-what-the-box-allows)).

## Entries and `when`

A list entry is a string. An entry that needs a flag is a table with a `path`:

```toml
read_file = [
    "${{ pack }}/settings.json",
    { path = "/opt/homebrew/etc/openssl@3/openssl.cnf", optional = true, when = "macos" },
]
```

- `optional = true`: `box run` drops the entry when its path does not exist, or is a link whose
  target does not exist. Box Core refuses a
  grant on a missing path, so a pack that runs on many hosts needs this. In a tool table that
  names a `program`, every grant entry is optional, and a literal `*` in one path component
  matches each existing name (see [Tools](#tools)). A `deny` entry is kept as written.
- `when`: the entry applies only when the condition holds.

An entry table has no other keys.

`when` takes a string or a table
([decisions.md](decisions.md#a-bool-input-switches-with-when)). The string is `macos`, `linux`, or
a placeholder for a `bool` input. The table is `{ variable = "<name>", equals = "<text>" }`, and it
holds when the name `variable` resolves to the string `equals`. `variable` is a name without
`${{ }}`, such as `inputs.claude.host`, and the table holds no other key.

An `env` variable can take its value from the host, by name:

```toml
[agent.env]
MAX_THINKING_TOKENS = { from = "env:MAX_THINKING_TOKENS" }
```

When the environment of `box run` sets the variable, `box` writes its value, as a literal, so a
`${{` in it stays text. When it does not, `box` drops the variable. The table holds `from` and,
optionally, `when`. A later layer replaces an `env` value whole. `from` outside the `env` table of
`[agent]`, a `[tool.<name>]`, or an `[mcp.<name>]`, a `from` that is not `env:<NAME>` with a name of
letters, digits, and `_`, and a variable that an `env://` credential reads, a `secret.env` names,
or a `pass-secret-env` entry holds stop the load
([decisions.md](decisions.md#the-agent-gets-only-the-host-variables-a-pack-names)). `box profile
show` lists each variable it copies, with its value and source.

`when` goes on a filesystem entry and on any other table, such as a `[tool.<name>]`, an `[egress.<name>]`, or `[agent.env]`. When it does not hold,
`box` drops the entry or the whole table. One value takes `when` in a `{ value = <value>, when =
... }` table: a key of a table, such as one `[agent.env]` variable, or a list element that is not a
filesystem entry, such as one `command` element. When the `when` holds, `box` puts `value` in
place of the table. When it does not hold, `box` drops the key or the element. A flag and its
value in `command` are two elements, so each needs the same `when`. Element 0 of an `[agent]`,
`[tool.<name>]`, or `[mcp.<name>]` `command` takes no `when`, and neither does the `secret` of an
`[egress.<name>]` route. The load of its file stops
([decisions.md](decisions.md#a-when-never-drops-a-program)).

## Composition

```toml
# a profile
packs = ["@box/claude", "@box/bedrock"]

# a pack
[pack]
extend = ["@box/base"]
```

| Rule | Detail |
| --- | --- |
| Order | Depth first, left to right, each pack once (its first place), then each [plugin](plugins.md) in `plugins` order, and the profile itself last. |
| Tables | Merge key by key. |
| Tool replacement | A profile's `[tool.<name>]` with `command` and no `program` replaces the whole inherited table when that table has `program`. The inherited grammar and tool-pack source are removed with it. |
| Operator commands | A command without `program` in an operator pack (a name without `@box/`) replaces a shipped program-form tool in either order. Each shipped table and grammar for that tool is omitted, including separate additions to it. Other tool tables and other pack settings keep the normal merge rules. |
| Lists | Filesystem lists, `dependency`, `[storage] directories`, `[[storage.files]]`, and `[[agent.ingress]]` join. A filesystem list, `dependency`, and `[storage] directories` drop a repeat. Every other list is replaced, so `command` keeps its order and its repeated flags. An `[agent] command` element `{ slot = "agent-args" }` marks where the profile's `agent-args` go, and each file's slot is checked when that file loads. A slot in a `[tool]` or `[mcp]` command stops the load. Only the profile holds `agent-args`, so no merge order decides it, and each element is a string with no `when`. |
| Strings, numbers, booleans | The later file wins. |
| Inputs | See [One input in two packs](#one-input-in-two-packs). |
| Copies | Two `[[storage.files]]` rows without a `when`, with one `target` or with one target inside the other, stop the load, and the error names both files. Two rows that both apply, where one has a `when`, stop the run, and the error names both targets and the input that turns the row off. So a profile cannot replace or remove a pack's copy while it applies. A pack that lets an operator turn a copy off gives it a `when` on a `bool` input, and a profile that turns it off can copy to that target itself. |
| MCP sources | `[[mcp-servers]]` rows join. A later row replaces a server of the same name from an earlier row. An `[mcp.<name>]` table with a `type`, which only the profile holds, wins over a detected server of that name. A table with no `type`, in a pack (grants only) or the profile, merges over it in merge order, so the packs' tables apply first and the profile wins on a key. Its `destinations` join the detected list, and it gives the server no key ([MCP servers](profiles.md#mcp-servers)). A table with no `type` that no detected server takes is dropped and reported, with the pack that holds it as its source, or the profile when the profile holds it too. |
| Routes | Two packs that declare one `[egress.<name>]` stop the load, and the error names both packs. Two packs whose routes read one `env://` variable also stop the load, and the error names both routes. One pack can read one variable from several routes. The operator's own profile can change a key of an inherited route, such as `secret.ref`, and can declare a route that reads a pack's variable. |
| Agents | The profile names one agent pack, and each other agent pack in it is one that this pack extends, directly or not (`lang::refuse_two_agents`, [decision](decisions.md#a-profile-runs-one-agent)). Two packs that declare `[agent] command` where neither extends the other, or two agent packs that no agent pack of the profile extends, stop the merge, and the error names two of them. A pack that extends an agent pack and declares its own `command` replaces it, by the list rule. The profile's own `[agent] command` is not counted. |
| `pack` | Bound to each file's own real folder before the merge. |
| Policy | Only files in the profile's `policies`. Box Core refuses two rules with one `@id` when it checks the run's policy. |
| Cycles | A pack that imports itself, directly or not, stops the load. |

The list rules come from nono's `extend` (github.com/nolabs-ai/nono). nono hardcodes runtimes as
groups of candidate paths. In `box`, a tool pack states paths relative to where the tool is
installed, and one resolver finds the one program the agent uses. How an installer lays out files
is host discovery, so it is code
([decision](decisions.md#an-installation-pack-names-a-layout)).

## Experimental native filesystem policy

Only `profile.toml` accepts `[experimental-features].native-filesystem-policy` as a boolean,
including a conditional value. The language validates the table before merging, including
unknown keys and value types. The resolved profile retains an omitted value separately from
explicit `false`.

Every pack is checked before merging or evaluating conditions, including packs reached through
`extend`. A pack that declares `[experimental-features]` or any process's
`native-filesystem-policy` setting fails validation, even when its value is `false` or its
condition would remove it. The error names the pack and invalid field. For global, agent, and tool settings, it also
points to `profile.toml`. No merge order or profile override can accept such a pack.

`compile` copies the selected value into the generated `[experimental-features]` table and
still enables `tool-grammars` when a retained tool has a grammar. Profiles do not set that
automatic flag. Box Core supplies the disabled default when the native setting is absent.

A profile can set `native-filesystem-policy` in its `[agent]`, `[tool.<name>]`, and local
`[mcp.<name>]` tables. The resolved process values reach Box Core unchanged. Each process
inherits the global value independently when its setting is absent; an agent override does
not change the default for tools or local servers. A pack's MCP additions retain their
filesystem/network-only boundary.

Box Core owns selection inheritance, build and platform validation, and enforcement. It rejects
a process opt-in when the global feature is off. No CLI error path retries a selected run with
native checks disabled. See the [profile setting](../../cli/profiles-reference.md#experimental-native-filesystem-policy)
for operator behavior and limits.

## Tools

A `[tool.<name>]` table with a `program` is a tool that `box` finds on the host. A table with a
`command` and no `program` reaches Box Core as written. `box` knows no tool by name: each fact
about a tool is pack data. The installation layouts know installers by their file names, such as
`bin/node` and `INSTALL_RECEIPT.json`, but they declare no tool.

The keys of a tool table are in [Tools](../../cli/profiles-reference.md#tools). `box` reads the
keys of `lang::TOOL_KEYS` (`program`, `helpers`, `hosts`, `installation`, and `upgrade_http`) and
the tool's `storage`, and removes them, so `box.toml` never holds them. `program` starts the
[resolution](#resolution), and the table then holds no `command`. Each helper gets steps 1 to 3 of
the resolution, a read grant on the name `PATH` finds it by (Box Core shows its real file there
too), a read grant on what the [installation layouts](#installation-layouts) find for it, and its
folder on the tool's `PATH`. A helper gets no table and no permit, and an absent helper is
dropped. `hosts` and `upgrade_http` become permits and gateway settings
([Upgraded hosts](#upgraded-hosts)), and `storage` is the [tool's own](#tool-storage).

A `detect` key stops the load, and so do `pack`, `extend`, and `inputs` in a tool table that
names a `program`, because a tool pack keeps those keys out of its tool.

### Agent packs

An agent pack is a pack of kind `agent`. When `box` loads it, `box` (`lang::lift_agent_pack`):

1. Refuses an `[agent]` table, because `[run]`, `[env]`, and `[filesystem]` are the agent's.
2. Moves the keys of `[run]`, `[env]`, and `[filesystem]` into `[agent]`. Every other table
   stays where it is, such as `[storage]`, `[[mcp-servers]]`, `[egress.<name>]`, and
   `[tool.<name>]`.

The load checks run on the moved table, so a refusal names the full key, such as `[agent]
command`, and `Refusal::in_file` finds its line under `[run]` or the top-level table. A profile
with a top-level `command`, `dependency`, or `env` stops the load, and the error
names `[agent]` and `[tool.<name>]`
([decisions.md](decisions.md#a-profile-uses-box-core-table-names)). A profile's top-level
`[filesystem]` with a key other than `deny`, `deny_write`, or `when` stops it too.

### Tool packs

A tool pack is a pack of kind `tool`. Its `[run] command` is one element, the pack's `program`
input, such as `["${{ inputs.git.path }}"]`. When `box` loads it, `box` (`lang::pack_layout` and
`lang::tool_program`, then `lang::lift_tool_pack`):

1. Takes the program from that input. The input is `type = "program"`, its `search` is absent or
   exactly `[{ env = "PATH" }]`, and it holds only `description`, `type`, `program`, and `search`.
   No other string in the pack names it, in `[run]` or anywhere else. The input leaves the pack,
   `[run]` gets the input's `program`, and `Layer.program_input` keeps the input's name.
   `lang::merge` refuses an `[options]` value for it with the same reason
   ([A tool override](#not-built)). It also refuses another pack that declares an input of the
   same name, and any string in the merged table that names it.
2. Takes the tool name from the last part of the pack name: `@box/git` is `git`, and the operator
   pack `rt` is `rt`. The name is letters, digits, `_`, and `-`, or the load stops.
3. Refuses the keys and tables that
   [Tool packs](../../cli/packs-reference.md#tool-packs) lists, because a tool pack writes one
   tool, and `name` and `box_dir`, which `box run` sets. Its `[storage]` is the tool's own
   ([Tool storage](#tool-storage)).
4. Rewrites `${{ root }}` to `${{ tool.<name>.root }}` in every string, and keeps each step, so
   `${{ root.parent }}` becomes `${{ tool.<name>.root.parent }}`.
5. Keeps `[pack]`, `extend`, and `[inputs]` out of the tool, and moves the keys of `[run]` and
   every other table under `[tool.<name>]`. So `program`, `helpers`, `hosts`, `upgrade_http`, `installation`, `env`, `storage`, `filesystem` with each of its lists,
   `when`, and a key that Box Core adds later all reach the tool table. Box Core refuses
   `filesystem.metadata` and `filesystem.exec` on a tool table, so a tool pack that writes them
   stops when the run starts.
6. Reads `grammar.toml` beside `pack.toml`, when it exists, as the tool's grammar. A
   `grammar.toml` beside a pack that is not a tool pack stops the load.

`lang::take_grammars` moves each `[tool.<name>.grammar]`, and the grammar of `grammar.toml`, out
of the layer's table into `Layer.grammars` before `${{ pack }}` is bound, and a tool pack must write
its grammar in `grammar.toml`. So no placeholder, `when`, `value`, or `from` step of `box` rewrites
a grammar. `Profile::parse` still refuses a malformed `${{` in a grammar that a profile writes
inline, because it checks the whole file. `lang::merge` refuses a second grammar for one
tool and a second grammar with the same `name` or `program`, and checks that `name` is the tool name
and `program` is the merged tool's `program`. `reference::resolve_tools` puts each grammar back
into its tool table after the expansion, so a tool that the run skips loses its grammar too, and
`compile` writes `[experimental-features] tool-grammars = true` when a kept tool has one.
`compile` also writes `[experimental-features] ingress = true` when the agent declares an
`[[agent.ingress]]`, which it copies into `box.toml` as written. The rows join across layers, as
`[[storage.files]]` and `[[mcp-servers]]` do, so a profile's rows add to a pack's. As a later
`[[mcp-servers]]` row replaces a server of the same name, a profile row replaces every pack row
for its `workload_port`, so a profile can narrow a pack's `listen` address. The replace runs in the
condition walk, after `when`, so a row whose `when` is false replaces nothing. `merge` marks the
profile's rows, and the walk removes the mark. Rows of the profile never replace each other, and
two packs never replace each other's rows, so Box Core refuses two pack rows for one port. Box Core owns every rule about a row, including the count, the unique ports, and
the macOS port rule, as it owns the keys of `[egress.<name>]` and `[telemetry.<label>]`.

The merge then treats the result as a pack in the full form, so `Merged.tool_packs` names the pack
for each tool. A pack in the full form, with `[tool.<name>] program`, still loads, and a profile
writes its additions to a tool in the full form. `program`, `helpers`, `hosts`, or `installation`
at the top of a profile stops the load, and so does `program` in `[pack]`, which takes only the
header keys.

`box profile create` adds each tool pack that `box` ships, unless `--tools` names some.

### Tool storage

A `[storage]` table in a tool table, or in a tool pack, declares storage that belongs to
the tool. Each directory is `<storage>/tool/<tool>/<dir>`, and `${{ storage.<dir> }}` in the tool
table names it. `box run` creates it, as it creates a launcher cache, and a filesystem entry at it
is kept before it exists. Unlike the agent's `[storage] directories`, it adds no grant and no
permit: the tool reaches it only through its own `read` and `write` entries, and the agent cannot
name it ([decisions.md](decisions.md#a-tool-owns-its-state-outside-the-workspace)). A tool
directory can share a name with an agent directory, such as `tmp`: the folders differ, and in the
tool table `${{ storage.<dir> }}` names the tool's own, so that tool table cannot name the agent's
directory of that name. A tool that the run
leaves out, because its `when` is false or its program is missing, adds no storage, no copies,
and no links, and its rows are not checked.

```toml
[storage]
directories = ["rustup"]

[[storage.files]]
source = "${{ inputs.rust.home }}/toolchains"
target = "rustup/toolchains"
mode = "link-children"
```

A tool's `[[storage.files]]` row copies or links a host path into the tool's storage. Its keys and
the three values of `mode` are in
[Give a tool its own storage](../../cli/packs-reference.md#give-a-tool-its-own-storage). A copy
row (`mode = "copy"`) is an agent row ([Copies](#copies)) whose target is in the tool's storage,
and `box` copies it the same way. The copy reader passes over the link rows (`"link"` and
`"link-children"`), and `Resolver::storage_links` resolves them. A link row lets a tool with one
home, such as rustup, keep what the box installs in its storage and still use the operator's own
files there, read-only. A copy grants the agent nothing, as the tool's directories do. A tool's row
has no default mode ([a tool's row names its mode](decisions.md#a-tools-row-names-its-mode)), and
an agent row with a link mode stops the load. A source in the workspace, the run's storage,
`~/.strands/box`, or a write grant stops the run, but a copy row may read `box`'s own packs in `~/.strands/box`.

Two rows of one tool cannot have equal or nested targets. This includes a copy row and a link row,
so a copy is never made inside a `link-children` folder.

A row can change from a link to a copy. `box` then removes the link that the old row left, at the
target or at a folder above it in the tool's storage, without following it, and copies as usual. A folder that still holds the links of an
old `link-children` row stops the run and names the folder, because the tool may have put its own
entries beside them. Delete the folder, and the next run copies it.

Each run, after it creates the storage, `box` brings each link up to date with its source: it makes
a missing link, points a link at a new source, such as a moved `RUSTUP_HOME`, and removes a link
whose source the host lacks. Something at the target that is not a link stays, so what the tool
installed there wins. `box` creates no folder through a link, so storage that a box changed cannot
point a new link elsewhere. A link grants nothing: the tool still needs a read grant on the source,
and Box Core checks the real path.

Every project of the profile shares a tool's storage. A pack keeps what belongs to one project in
a folder named for it, such as `${{ storage.<dir> }}/${{ workspace.dashed }}`. Two boxes of one
profile can run the tool at the same time, and `box` takes no lock for them, so the tool's own
locking decides what happens. rustup has none, so two boxes that install one toolchain at the same
time can break it.

### Installation layouts

`install_layout::Layout` knows how four installers lay out files, and has a `directory` fallback. It contains no tool and no
command. A tool pack's `installation` names the layouts that can hold its program, and
`install_layout::resolve` applies them to the tool's selected program. A detected local MCP server
applies every layout to its program and its `#!` interpreter.

```toml
# resources/packs/node/pack.toml, shortened
[run]
command = ["${{ inputs.node.path }}"]
installation = ["node", "homebrew"]
```

| Layout | Matches the physical path | Reads |
| --- | --- | --- |
| `node` | `<root>/bin/node` or `<root>/bin/node-<digits>` | `<root>/bin`, which Node from nvm needs at startup, and each `<root>/share/node-*` folder. |
| `npm` | A path below `<prefix>/node_modules`, or `<root>/bin/npm` or `<root>/bin/npm-cli.js` | The outermost containing `node_modules` tree below a prefix, or `<root>`. |
| `python` | A path below a folder that holds `pyvenv.cfg` (for the invocation spelling and for the physical path), `<root>/bin/python[<version>]`, or a path below `uv/tools/<name>` or `uv/python/<name>` | The environment folder, `<root>/lib` and the executable as a file, or the uv folder. |
| `homebrew` | A path below `<prefix>/Cellar/<formula>/<version>` | The keg and `<prefix>/etc/<formula>`. On macOS it lists `<prefix>/bin` and `<prefix>/opt`. Each runtime dependency in the keg's `INSTALL_RECEIPT.json` resolves the same way. |
| `directory` | Any path, only when no other named layout matches it | The folder that holds the path. |

A layout that does not match adds nothing, so `["node", "homebrew"]` serves Node from nvm and
Node from Homebrew. The npm layout takes the first `node_modules` folder in the physical path;
the other named folder matches take the last occurrence. Every match needs at least one folder
before it. A path component is literal: a `*` in a host path matches only a folder of that name.

A Homebrew receipt stays below the keg's physical root. Each dependency name consists of safe path
components, and its last component names the formula. `<prefix>/opt/<formula>` must resolve below
`<prefix>/Cellar/<formula>`, which itself contains no links. Resolution repeats for that physical
target and stops at a visited path. A missing or invalid receipt or dependency stops resolution;
a read path can be absent. A path with a `.` or `..` part stops resolution.

The resolver limits each receipt to 1 MiB, each dependency list and traversal to 1024 items,
each `share/node-*` listing to 1024 matches, and the `pyvenv.cfg` search to 64 levels. Receipts and
targets pass source checks before their content is read. For a tool, Box Core's
`strands_box::check_read_grant()` judges each path: a credential store, or a folder that holds
one, skips the tool. Derived directory reads and listings classified as
`Forbidden(SystemTree)` are dropped. Loader directories that Core accepts are kept.
A new installer is a new `Layout`
variant. Installation provenance appears as comments in `box.toml`, such as
`# installation tool.node homebrew: <path>`, one for each layout and path it matched and each
receipt it read.

### Resolution

Before it fills in placeholders, `box` does this for each tool table:

1. Takes the first executable `program` in an absolute folder of the operator's `PATH`. When the
   agent types the bare name, Box Core's Shell finds this same file on `PATH`, so the table and its
   permit name the file that the agent's command runs. Box Core's Shell also runs a table's file for
   the name of that real file, such as `npm-cli.js` for `npm`, whatever `PATH` finds first. On
   macOS, Apple's `/usr/bin/git` gives way to the `git` in the developer folder
   ([The developer folder](#the-developer-folder)).
2. Refuses the program when it lies in the workspace, the run's storage, or `~/.strands/box`, as written
   or real. The tool is then skipped. After the fill, a tool whose program or helper lies under a
   write grant of the run is skipped too.
3. Follows each link to the real file, which becomes `command`. Box Core picks a tool table by this
   file.
4. Reads the `#!` line of the real file. `#!/usr/bin/env <name>` names the tool table whose
   `program` is `<name>`. `env` is followed past each flag, the value of `-u`, `-C`, `-L`, `-a`,
   `--unset`, `--chdir`, and `--argv0`, and each `NAME=value`, so `#!/usr/bin/env -S node --flag`
   and `#!/usr/bin/env -u NODE_OPTIONS node` name `node`, as for an MCP server. A line with `-P`
   names no table, because `env -P` finds the program outside `PATH`. An absolute line names the tool table whose real file is the line's real
   file. A tool whose line names no such table is skipped.
5. Binds `tool.<name>.root` to the folder that holds the real file.
6. Skips the tool, with a reason, when its program is absent, refused, or its interpreter's table
   is skipped. A skipped tool's table and its `dependency` entries leave the run.

Then the merge fills in placeholders. In a tool table that names a `program`, a grant entry
(`read`, `read_file`, `write`, `write_file`, `list`, `metadata`, `exec`) whose path does not exist
is dropped and recorded, and a literal `*` in one component expands to each existing name, in name
order. A `*` that a placeholder's value holds stays literal. A `deny` entry is kept as written. On
macOS, a deny on a path that appears during the run still protects it. On Linux, Box Core refuses
a deny on a path that does not exist when the run starts, so that run stops. A literal `*` in a
`deny` entry stops the load, because Box Core matches no pattern. A tool table with a `command`
and no `program` keeps every entry as written, as in `[agent]`.

After the fill, `box` composes each kept tool:

- **Interpreter.** A script follows its `#!` chain: its interpreter table, that table's own
  interpreter table, and so on. Box Core on Linux starts a script only when its table grants each
  program of the chain. For each interpreter table, the script reads the table's command and what the
  installation layouts find for it, and gets the table's `read`, `read_file`, `list`, and `deny`
  entries. Box
  Core applies `deny` per process, so a read without the deny that narrows it would widen the
  script's reach. The interpreter folders go first on the script's `PATH`, in chain order, so each
  `#!/usr/bin/env <program>` line finds its program. The script also reads the real `env` file of
  each such line, as a file and never as its folder. This step gives the script no interpreter's `env`
  or `hosts`. When the script's tool pack extends the interpreter's tool pack, as `@box/pnpm`
  extends `@box/node`, the script gets the interpreter's `env` from that `extend`
  ([Pack kinds](#pack-kinds)), and still not its `hosts`. A script whose `env` lies under a write grant, or whose interpreter table a `when`
  dropped, is skipped.
- **Helpers.** Each helper adds its executable, and what the installation layouts find for it, to
  `read`.
  Its folder goes on `PATH` unless `PATH` holds it. Whole system trees are excluded from derived
  runtime reads.
- **One grant per file.** Box Core refuses a file that both `read` and `read_file` grant, and a
  `read_file` inside a `read` folder. So `box` drops each `read_file` entry that a `read` entry
  covers. A helper's Python keeps only its `read`, although the Python layout gives it `read_file`.
- **Defaults.** A tool gets `PATH = "/usr/bin:/bin"` and
  `TMPDIR = "<run directory>/tool-tmp/<tool>"` when its `env` sets neither. The run directory is
  `~/.strands/box/r/<run>`, which holds `box.toml`, `policy.dw`, the journal, and the box folder
  `box`. `box` sets them before it adds the interpreter and helper folders, so those folders come
  first on `PATH`. A tool that gets the default `TMPDIR` also gets that folder, and nothing else
  in the run directory, in `read` and `write`. The agent gets none of them. The run that claims
  the run directory creates each one and empties it before the agent starts, and refuses a link
  at one.
- **Workspace.** With `[project] access = "read"` or `"write"`, the workspace is the first `read`
  entry, and with `"write"` it is also a `write` entry. Every `read` entry at or below another is
  dropped.
- **The folder that `PATH` names.** When `PATH` found the program through a link,
  `tool::spelling_folder` gives the folder of that link, and `box` puts it last on the tool's
  `PATH`, unless a grant writes into it. So a package script that runs the tool by name finds it.
  This adds no grant, so the lookup works only where the tool already sees the link: in the home
  folder, and in Homebrew's `bin` folder for a tool that node runs. On Linux, a script still cannot
  run the tool by name this way.

### Tools and agents

A tool and a `program` input share one module, `program`: the check that refuses a program in the
workspace, the run's storage, or `~/.strands/box` (as written or real), the dangling-link and executable
checks, and one `#!` reader. They differ only where Box Core or the role of the program decides:

| | Tool (`[tool.<name>] program`) | Agent or other `program` input |
| --- | --- | --- |
| Where `box` looks | The first `program` on the operator's `PATH` | Each `search` folder in order |
| Why | The agent's bare name then runs the file that the operator's own shell runs | Element 0 of `[agent] command` is the program that Box Core starts |
| A refused first match | The tool is skipped | The search passes over it and tries the next folder |
| Under a write grant | The tool is skipped | The run stops ([decisions.md](decisions.md#a-write-grant-never-picks-the-program)) |
| A script whose `#!` runs node | Takes the `node` table's grants | Refused, because nothing grants the agent node's reads |
| A value set by hand | None | `[options]` or `from` |

A tool is optional, so a run goes on without it. A run needs its agent, so it stops.

### Root steps

`root` is the folder that holds a program's real file. It takes `.parent` steps, as in
`root.parent` or `tool.<name>.root.parent.parent` ([Path steps](#path-steps)). The
shipped tool packs use `root.parent` for each file beside the install, because most tools' real
file sits in a `bin` folder, and `root` for a file beside the program. A pack whose program can sit
in a folder it shares with other files, such as `uvx` and `pnpm`, names files under `root` rather
than `root` itself.

In an agent pack's `[run]`, `[env]`, and `[filesystem]`, or in an `[agent]` table of a support
pack or the profile,
`root` is the folder of the real file that `[agent] command` element 0 names, with each link followed. Element 0 must expand to an absolute
path, so a bare name stops the run, and element 0 cannot name `root`. `box` expands element 0 for
`root` with the bounds of a `command` head. A `root` outside a tool pack and outside `[agent]`
stops the load.

### The developer folder

Apple's `/usr/bin` stubs, such as `git` and `cc`, forward to the selected Apple developer folder,
and only Apple's tools report which folder that is. A pack names it as
`${{ macos.developer_dir }}`:

- `box` runs the fixed program `/usr/bin/xcode-select -p`, with no arguments from a pack, in `/`,
  for at most 10 seconds and 64 KB of output, once per run, and only when a kept entry names it.
  `tool::locate` also asks for the folder, for a `git` table that names it, and shares that one
  answer.
- The name is valid only in a value that `when = "macos"` governs: the entry's own `when`, or the
  `when` of a table that holds it. Anywhere else, the load stops.
- When the program fails or prints nothing, the tool whose table names the folder is skipped, with
  the reason, and the run goes on.
- `box profile show` prints the folder, with `xcode-select -p` as its source.

With full Xcode selected, the `/usr/bin/cc` stub asks `xcodebuild` for the compiler, and
`xcodebuild` does not start in a box. So a pack that compiles names the compiler and the SDK
directly, as `@box/cargo` does with `SDKROOT` and the per-target `CC_<target>`, `CXX_<target>`,
`AR_<target>`, and linker variables of the two Apple targets:

- `${{ macos.toolchain }}` is the first of `Toolchains/XcodeDefault.xctoolchain/usr/bin` and
  `usr/bin` in the developer folder whose `cc` passes the checks of a `program` value: an
  executable file outside the workspace, the run's storage, and `~/.strands/box`. The value is the real
  path of the folder.
- `${{ macos.sdk_root }}` is the first of `Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk` and
  `SDKs/MacOSX.sdk` in the developer folder that is a folder, as its real path.
- `box` finds each by checking these paths, and runs no program for them beyond
  `xcode-select -p`. They follow the rules of `macos.developer_dir`: valid only under
  `when = "macos"`, and a tool whose table names one that is not found is skipped, with the reason.
  `box profile show` prints each, with `macos.developer_dir` as its source.

The `/usr/bin/git` stub fails in a box for the same reason: it cannot ask for the developer folder,
and with full Xcode it falls back to `xcodebuild`. So when the `PATH` lookup of a tool whose
`program` is in `tool::PAST_APPLE_STUBS` (only `git`), and whose table names
`${{ macos.developer_dir }}`, finds a file in `/usr/bin` on macOS, `tool::locate` replaces it
with `<developer folder>/usr/bin/<program>`, which becomes the table's `command` and the file its
`shell:spawn` permit names. The file passes the same checks as a
`program`, and a file that is absent or fails one skips the tool with the reason. When
`xcode-select -p` fails, the stub stays, and the table's `${{ macos.developer_dir }}` then skips the
tool. A `git` table that does not name the folder keeps the stub, because it cannot read the folder
that the other file runs from.

Box Core's Shell runs a table's file for the file name of its command before any `PATH` lookup,
so the agent's bare `git` reaches the developer folder's `git` although `/usr/bin` comes first on
`PATH`. Other `/usr/bin` stubs stay as they are, because a pack that runs one directly must also
read the developer folder.

`box` writes one `shell:spawn` permit for each kept tool, on its real file and its `program`.
Box Core still decides a name of that file that the grammar does not bind as `shell:spawn`, so a
tool with a grammar keeps the permit. It also gets `tool_<name>`, a permit on
`Tool::<name>::Action::"*"` and `Tool::<name>::Action::"unmodeled"`, because the `"*"` group
excludes `unmodeled`. The namespace takes `::v<version>` for a grammar version above 1.
It collects the kept tools' distinct `hosts` into a `package_hosts_connect` permit on port 443
and a `package_hosts_request` HTTP permit. With no hosts, it writes neither host permit.

#### Upgraded hosts

Some tools check certificates with the macOS platform verifier, which cannot trust the box's
certificate authority. rustup is one. Such a tool can ask the gateway over plain `http://`, and the
gateway makes the `https://` call and checks the server's certificate itself. A tool lists each
such host in `upgrade_http`. `box` drops an entry that is not in the tool's `hosts`, so a profile
that narrows `hosts` narrows the upgrade with it, and a tool never widens what the gateway
upgrades. `box` collects the kept tools' distinct `upgrade_http` hosts into Box Core's
`[gateway] upgrade_http`. With none, `box.toml` holds no `[gateway]`. A launcher pack that sets
`upgrade_http` skips MCP discovery ([Launcher packs](#launcher-packs)).

The gateway decides an upgraded request as `https://` on port 443, so the tool's host permits
cover it, and it never adds a credential to one. The list applies to every process in the box, and
the hop from the process to the gateway is plain HTTP that stays on the machine. A tool also
points its program at the `http://` address. `@box/cargo` sets
`RUSTUP_DIST_SERVER = "http://static.rust-lang.org"` on macOS only, so rustup on Linux keeps
`https://` all the way.

`box` keeps no list of folders that are too broad to grant. Box Core refuses such a grant when the
run starts, so a pack names subfolders of an install root that can be a system folder, such as
`/usr` for dnf.

## Providers

A model provider is a pack beside the agent's. It holds the route to a model host and the
`secret.ref` for its key. It is a `support` pack, and declares no marker that it is a provider.

An agent pack is a pack of kind `agent`. A profile names one provider pack beside its
agent pack, but `box` adds no provider check of its own. The merge still refuses two packs that declare
one route or read one `env://` variable, and resolution refuses a placeholder that reads an input no pack declares. A combination
that passes both and does not work fails when the agent runs. `box profile create` adds no
provider: `--with` names it. The profile sets a key other than the pack's own with `secret.ref`
under the route.

An agent pack that works with more than one provider, and needs a setting for one of them,
declares an `<agent>.host` input with `values`, and puts a `{ variable, equals }` `when` on the
setting. The input's default applies unless the profile sets it in `[options]`.
`box profile create` does not set it. An agent pack that works with one provider writes its
settings with no input.

Box Core gives the agent a stand-in value in the route's variable and adds the real credential to
each request, so the agent finds its provider's usual variable. The agent's own settings choose
the model. When those settings name a provider that the profile does not route, the gateway refuses
the requests with a `403` and the `x-strands-box-egress: refused` header.

## Routes with only `destinations`

An `[egress.<name>]` route whose one key is `destinations`, a non-empty list of strings, in a pack
or in the profile, names hosts that the agent reaches with no credential from the box, such as a
login service. Box Core refuses an entry with no secret ("an entry with no secret declares only a
destination, which policy already decides"), so `compile::is_open_route` keeps such a route out of
`box.toml`. Each other route goes to `box.toml`, so Box Core still reads it: a misspelled
`secrets.ref`, a `header` outside `secret`, or `protocol = "mcp"` stops the run as before.
`lang::check_secrets` refuses a `when` on a route's `secret` at load, because a `when` that drops
it would leave a route with only `destinations`
([decisions.md](decisions.md#a-when-never-drops-a-program)). `compile` still writes its
`route_<name>_connect` and `route_<name>_request` permits with `reach_rules`, the helper for every
route, so it gets the same port rule (default 443) and the same limit of 100 hosts. Before that,
`compile::refuse_open_destinations` refuses each destination that is not a lowercase host name
(`tool::is_host_name`) with an optional port: a URL, a path (the permits cover the whole host), a
`*` wildcard, an upper-case name, and a trailing dot. Box Core refuses a rule on an upper-case name
or a trailing dot, so `box` refuses those at the route that names them. A route keeps its other rules: two packs cannot declare one route, and the
profile can change a key of an inherited route, so it can replace a pack's `destinations`.
`box profile show` lists each such route as "no credential" (`compile::open_routes`). Box Core
permits a host for the whole box, so every process in the box reaches these hosts
([decisions.md](decisions.md#a-route-with-only-destinations-opens-a-host)). `mcp::detect` skips a
detected http server whose host a route holds only when that route goes to `box.toml`.

An IPv6 literal such as `::1` is not a host name, so `refuse_open_destinations` refuses it. `box`
refuses no loopback host name on a route with only `destinations` or on an http server that
`mcp::detect` imports ([decisions.md](decisions.md#a-pack-adds-no-policy)). `compile::reach_rules` refuses more than
100 hosts in one rule, for a route or an http MCP server. The cap is a product limit: it came from
an older Box Core whose policy check overflowed its stack on a condition of about 490 terms, and the
current Box Core refuses such a condition with a parse error instead. A tool's `hosts` join into one
rule across tools and have no cap of their own. Box Core refuses an expression nested deeper than
32 levels, and each `||` in a chain adds one level. So `render::any_of` writes every list of terms
(the hosts of a route, a server, or the tools, and the storage folders that the box home forbids
leave out) as chains of at most 8 terms, each group in parentheses. Each factor of 8 adds 7
levels, so Box Core accepts a tool-hosts rule of 1,000 hosts and refuses one of 4,096.

## Packs that `box` ships

Each pack is a folder in [`resources/packs/`](../../../resources/packs/). Its `pack.toml` states
its kind and what it holds, and the [user guide](../../cli/README.md#packs) lists them. These
packs do something that the sections above do not show:

- Each agent pack extends [`@box/base`](../../../resources/packs/base/pack.toml), which holds shared
  terminal settings and `PATH`. A profile names an agent pack with
  one [provider](#providers) pack.
- [`@box/codex`](../../../resources/packs/codex/pack.toml) reaches its model through
  `@box/bedrock-mantle`, Amazon Bedrock's OpenAI-compatible endpoint, `@box/bedrock`, or
  `@box/openai`. With `@box/openai`, it defines its own Codex provider that reads
  `OPENAI_API_KEY`, because Codex's built-in `openai` provider signs in only with `codex login`.
- [`@box/kiro`](../../../resources/packs/kiro/pack.toml) runs the runtime it unpacks from a host
  folder that the box only reads. It holds its own routes to Kiro's service, because no other
  agent uses them: `kiro.sign-in` picks a login inside the box, with no credential, or a Kiro API
  key.
- [`@box/pi`](../../../resources/packs/pi/pack.toml) is started by node. A `[tool.pi]` table finds
  the script that npm installs, and the agent's command names it by `tool.pi.root`.
- `@box/go`, `@box/cargo`, and `@box/npm` keep their download caches in their own
  [tool storage](#tool-storage). `@box/uv` keeps its cache and the Pythons it downloads in the
  project.
- `@box/npx`, `@box/uvx`, `@box/pnpx`, and `@box/bunx` also start MCP servers
  ([Launcher packs](#launcher-packs)).

An MCP pack holds only `[mcp.<name>]` tables with no `type`. No starter adds one, and a profile
lists it in `packs`. `box` ships no MCP pack.

## Storage

`box` creates no file in the workspace
([decisions.md](decisions.md#a-profile-can-name-launch-directories)). The state an agent keeps
between runs goes in storage:

```text
~/.strands/box/storage/<profile>/default/agent/<dir>/
```

Each profile gets one storage folder, which every workspace the profile runs in shares
([decisions.md](decisions.md#storage-is-one-directory-per-profile-and-workspace),
[isolation.md](isolation.md)). `default` is
its one namespace today. The name is reserved, so a later option can add other namespaces of a
profile's storage beside it without moving existing storage. The agent
keeps its sessions apart by the directory it starts in. A pack keeps per-project state apart with
a name or a key from the workspace, such as `${{ workspace.dashed }}` in a `target` or
`${{ workspace }}` in a `target-key`.

- `[storage] directories` names each directory. It goes in the `agent` folder of the storage root,
  so no name can be one of the entries that `box` keeps beside it: the record of copies, each
  tool's storage, and the launcher caches. `box run` creates it, and adds `read` and `write`
  grants and `fs:*` permits for it. The permits matter: the box's shell reaches only the paths the
  policy permits, whatever the grants say.
- `box run` refuses a storage directory that is a link.
- `box run` refuses a write grant in `~/.strands/box`
  ([decisions.md](decisions.md#a-run-cannot-write-what-a-later-run-trusts)). Storage is the one
  exception: a run can write its own storage directories.

### Copies

A `[[storage.files]]` row copies a host file or directory into storage:

```toml
[[storage.files]]
source = "${{ home }}/.claude/skills"
target = "config/skills"
optional = true
when = { variable = "inputs.claude.import-skills", equals = "true" }
```

The row's keys, their values, and their defaults are in
[Copy files into storage](../../cli/packs-reference.md#copy-files-into-storage).
`box` reads the source's kind, file or directory, from the host. `Resolver::target_in` checks the
`target`: a placeholder fills one name below the storage directory, and one that fills the storage
directory, or more than one name, stops the load. `Resolver::edit` reads `kind`, `keep`, `set`,
and `fill` together: `kind` comes with `keep`, `set`, or `fill`, and never without one of them,
and the file name selects no format. `keep` paths and `set` keys are key paths, as in
`[[mcp-servers]] key`. `sync` is refused beside any of them for now, and so is `exclude`, which
names entries of a folder by file name. `exclude` also needs `sync = true`: only a `sync` update
checks the copy against it on each run, so on a row without `sync` an `exclude` added after the
first copy would leave the named file in the box with no line. An agent row with a link `mode` stops the load
([Tool storage](#tool-storage)).

An optional row whose source uses an environment-sourced input as a directory prefix first
checks that root.
A relative root, a root with `..`, or a root in a refused location skips the row and
reports its environment source. Target and edit validation still apply. An existing copy stays.

For each row, `box run` does this:

1. **Skip it if the target exists.** If anything is already at the target, even a link, the copy
   belongs to the box, and `box` does not copy the host file again
   ([decisions.md](decisions.md#a-copy-belongs-to-the-box)). A row with `sync` updates the copy
   instead ([`sync`](#sync)). A row with `set` still rewrites its
   values, and a link at the target then stops the run ([`keep` and `set`](#keep-and-set)). A row
   with `fill` still adds what the copy lacks ([`fill`](#fill)). If the box deletes the target, the
   next run copies it again.
2. **Check the source.** `box` refuses a source in the workspace, the run's storage, `~/.strands/box`, or
   a write grant ([decisions.md](decisions.md#the-packs-decide-what-is-copied)). A source in
   `box`'s own packs passes, as written and real, when only `~/.strands/box` holds them. The pack decides
   what is copied: `box` does not judge what a file holds. The one exception is a path that a
   declared [secret source](plugins.md#what-stays-on-the-host) lists in `reads` or `deny`. A source that
   is, holds, or lies in one stops the load, and the refusal names the source and its plugin.
3. **Copy it, following links.**
   - A link inside the source is copied as the file or folder it points to.
   - A link out of the source is followed if its target passes the step 2 checks.
   - `box` leaves out a link that fails the checks, a broken link, a link that loops back, a file
     it cannot read, and anything that is not a file or a folder.
   - `box` leaves out each entry, at any depth, whose name the row's `exclude` lists, before it
     follows a link of that name. A name matches whole and without regard to case, because macOS
     file systems usually ignore case, so `MCP.json` is read as `mcp.json`. `exclude` takes no
     pattern, and a name with `*`, `?`, or `[` stops the load. The walk that a `sync` update makes
     of the host is the same walk, so an entry that `exclude` names never comes in. A copy from an
     earlier run that a later `exclude` names stays in storage, because `box` deletes nothing the
     box may hold. Each run and `box profile show` name it in a `kept` line, not as gone from the
     host, until the operator deletes it. A
     source that is one file, with `exclude`, stops the run.
4. **Check that nothing changed.** `box` notes each host file's device, inode, size, and
   modification and change times when it plans the copy. It compares them when it opens the file,
   and again for every file once the whole copy is made. A file that changed or went in that time
   fails the copy, so a copy of a database and its journal comes from one moment. `box` then plans
   the row again and tries again, three times in all. When the files still change, the run stops
   with `Error::Unsettled`, which names the file, before the box starts. Going on without the copy
   would let the agent make the target itself, and the copy would then never be made. This is a
   check that the files held still, not a database snapshot: `box` reads no file's format. Only a
   first copy makes it. A `sync` update keeps its device and inode check, so a run does not stop
   each time the host agent writes a synced file, and a file written during an update is fixed
   by the next one.
5. **Move it into place.** `box` builds the copy in the run directory, where no box can reach. It
   opens each folder on the way to the target's folder without following a link, makes a
   missing folder inside the one it holds open, and moves the copy into the last one. A link on the
   way stops the run. The move replaces nothing, so a target that appeared since step 1 is kept.
   A row with `kind` copies one file: `box` parses it, keeps the `keep`
   paths, sets each `set` value, and writes the result.

`box profile show` does steps 1 to 3 without copying anything. It lists each copy, each link it
follows, and each entry it leaves out. For a row with `kind`, it lists the key paths that the copy
keeps, drops, and lacks, and the keys it sets, never a value. A row with `fill` lists no dropped
paths, and when its copy exists, it lists the paths that it adds when the copy lacks them. `box run` prints each entry it leaves
out.

#### `keep` and `set`

```toml
[[storage.files]]
source = "${{ home }}/.pi/agent/settings.json"
target = "agent/settings.json"
kind = "json"
optional = true

[[storage.files.set]]
key = ["shellPath"]
value = "${{ box }}/bin/bash"
```

- **`keep` applies once**, at the first copy, like the rest of the copy. A `keep` path that the source
  lacks is skipped and listed. A TOML copy with `keep` has no comments, because a comment can hold
  a commented-out key.
- **`set` applies on every run.** A value such as `${{ box }}` names this run's box, and each run gets
  a new one. When the target is already in storage, `box run` reads the copy, sets each value, and
  writes the copy only if it changed. The host file is not read again. Two runs at the same time in
  one workspace share the copy, so the run that starts last holds each value.
- **`set` needs no host file.** When the source and the target are both absent, `box run` writes a
  new file at the target that holds only the `set` values. Kiro CLI's settings must be in place
  before the agent first starts. The new file is a copy like any other,
  so a host file made later does not reach the box until the box's file is removed.
  `box profile show` lists the copy as `absent on this host, so it will hold only what it sets`.
- **Each `set` row replaces one value.** Its `value` is a string, a number, `true` or `false`, or
  a list of those, and only a string holds a placeholder. A table, a date, `nan`, or `inf` stops
  the load. It replaces any value that is not a table where it stands, a list included, adds a
  missing key at the end of its table, and creates each missing table. A key that holds a table,
  or a parent that is not a table, stops the run. There are no list indexes. Two rows on one key, or on a key and a key below it, stop the load.
- **A `set` row can take a `when`**, read at load like any other `when`. A row whose `when` does
  not hold writes nothing, and the copy keeps whatever value it has there, so a value an earlier
  run set stays. Two rows on one key load when no run can hold both, such as one for each system.
- **JSON** is written back with two-space indentation and its key order. A JSON file with comments
  does not parse, so it stops the run. **TOML** keeps its comments and layout when `set` rewrites a
  copy. A new table gets its own header, except inside an inline table, where it is an inline table
  too.

#### `fill`

A row with `fill = true` is for a file that the agent writes itself, which also holds a few host
values the box needs, such as Claude Code's finished onboarding in `.claude.json`. The agent
creates that file on its first run, so a copy made once never brings the host values in.

- **When the target is absent**, the row copies the `keep` values, as a `keep` row does. When the
  host file holds none of them, it creates no file.
- **When the target exists**, each run reads the host file again, with the source checks of a
  copy, and adds each `keep` path that the copy lacks, creating each missing table. A value that
  the copy holds stays, whatever it is. A path whose parent in the copy is not a table is not
  added. The copy is written only if it changed, by the same walk as a `set` rewrite.
- **When `warn-if-different` selects a `keep` path**, differing parsed values present in both
  source and copy produce a warning before each run. The selection defaults to empty and needs
  `fill = true`. The guarded read supplies the comparison, and the copy keeps its value.
  Interactive runs save the warning in `box.log` and, when the log is retained, print an exit
  reminder outside the bounded error preview.
- **A copy that is a link, not a file, or a file with another hard link** is left alone, as the
  MCP import leaves it, and `box run` reports it. A `set` rewrite stops the run there instead.
- A host file or a copy that does not parse as its `kind` stops the run.
- A row with `fill` can share its target with an `[[mcp-servers]]` `target` of the same format
  when no `keep` path equals, contains, or lies below that row's `target-key`. Copies run before
  the MCP import, and each adds only what the file lacks.

#### `sync`

A row with `sync = true` brings its copy up to date with the host on each run, so an edit to a host
file reaches every project of the profile. `box` keeps the SHA-256 of each file it copied in a
record, `copies.json` in the storage root, and compares the host file and the copy with it:

| Host file changed since the last copy? | Box changed its copy? | What happens |
| --- | --- | --- |
| No | No | Nothing |
| No | Yes | The box's edit stays |
| Yes | No | The host file is copied in |
| Yes | Yes | The host file is copied in, and the run prints which copy it replaced |

- **A folder** is compared file by file. A file the host adds is copied in. A file only the box has
  stays. A file the host no longer has stays as the box left it, the run prints it once, and the
  record drops it.
- **A row with no record**, such as a copy made before the row had `sync`: each file that differs
  from the host stays as the box left it, and the run prints it once. The record takes the host
  file, so a later host edit replaces the copy. A record that is missing, is not a file, has another
  hard link, or does not parse counts as no record.
- **A host file new to a row with a record**, or one the host deleted and then made again, replaces
  the box's file of that name, as a host edit does.
- **A copy that `box` cannot read**, such as a link, a file with another hard link, or a file of a
  size that matches neither the host file nor the record, counts as changed, and `box` does not read
  it. A copy that `box` cannot write is printed, and the run goes on.
- **A host problem on a copy in storage**, such as a host file `box` cannot read, one that changes
  between the plan and the read, a source the run refuses, or a required source the host no longer
  has, is printed, and the copy stays as it is. The run goes on. For a first copy it stops the run,
  because there is no copy to keep.
- **A first copy** records the files as storage holds them after the copy.
- **The source checks of a copy** apply on each run, and a link left out of a folder is printed as
  for a first copy.
- `box` opens each directory from the storage root down without following a link, writes a new
  file beside the copy, and renames it over the copy, so a link at the copy is replaced and never
  followed. A link or a file above the copy leaves it unchanged, and the run prints why. A missing
  directory is created.
- One run of a profile updates its copies at a time: a run holds a lock on the storage root while
  it copies, waits up to 60 seconds for another run's lock, and then stops.
- No grant or permit reaches the record: a write grant in the storage root outside its directories,
  its tools' storage, and its launcher caches is refused, the policy's forbid on `~/.strands/box` covers
  the storage root outside its directories and its tools' storage, and the agent's directories
  are in its own folder of the root.
- If the box deletes the whole copy, the next run copies it again, as for every row.

A run writes a copy that the box can change, so the rewrite trusts nothing in it
([decisions.md](decisions.md#a-copy-belongs-to-the-box)):

- No value read from the copy reaches `box.toml`, `policy.dw`, or a grant.
- `box` opens each directory from the storage root down to the copy without following a link, so
  a link at the copy or above it stops the run. A copy that is not a file stops the run.
- It writes a new file beside the copy and renames it over the copy.
- A copy that no longer parses as its `kind` stops the run, and the error names the file.
  `box` does not copy the host file again. If the box deletes the copy, the next run copies it
  again, as for every row.

The details: each check looks at the path and at its real path. A link above the target, or a file
that changes between the check and the copy, stops the run. A copy keeps each file's execute bits.

### Hooks

A `[[storage.hooks]]` row makes the hooks of a JSON copy in storage a per-run view of the hooks in
a host file ([decisions.md](decisions.md#imported-hooks-are-rebuilt-on-each-run)). The pack states
where the file holds its hooks and what an imported hook looks like. `box` knows no harness's
layout ([decisions.md](decisions.md#box-knows-no-provider)). This is the row of `@box/claude`:

```toml
[[storage.hooks]]
source = "${{ home }}/.claude/settings.json"
target = "config/settings.json"
kind = "json"
when = { variable = "inputs.claude.import-hooks", equals = "true" }
key = ["hooks", "*", "*", "hooks", "*"]
keep-above = ["matcher"]
only = { key = ["type"], equals = "command" }
command = ["command"]
args = ["args"]
keep = [["type"], ["timeout"], ["async"], ["asyncRewake"], ["statusMessage"], ["onFailure"], ["if"]]
drop = [{ key = ["shell"], equals = "bash" }]
disable-key = "disableAllHooks"

[[storage.hooks.set]]
key = ["command"]
value = "bash"

[[storage.hooks.set]]
key = ["args"]
value = ["-c", ". ${{ script }}"]
```

The row's keys and their values are in
[Import hooks](../../cli/packs-reference.md#import-hooks-storagehooks).
Each key path is a list of one or more keys, as in `[[mcp-servers]] key`. `command`, `args`, and
each `keep` and `drop` path name fields that do not overlap. A `set` key does not overlap a `keep`
path or another `set` key. A hook that holds a field that none of `only`, `command`, `args`,
`keep`, and `drop` names is refused, so no field that the pack does not account for reaches the
copy. A row that breaks one of these rules, or that holds another key, stops the load.

The two `set` rows above write the exec form `{"command": "bash", "args": ["-c", ". <script>"]}`.
A harness that takes one command string has one row:

```toml
[[storage.hooks.set]]
key = ["command"]
value = ". ${{ script }}"
```

When `when` holds, the run does this:

1. **Read `source` once.** `box` refuses a file over 1 MiB, a file that is not a JSON object, and
   a file that a box can write or that a link in such a place leads to. An unsafe root from an
   environment input skips the import.
2. **Find each hook** with `key`. `box` inspects at most 1024 hooks and imports at most 64.
3. **Read the script** that the command names. The command is `SCRIPT`, or `sh`, `bash`, or `zsh`
   with `SCRIPT`, as one string or as a command with one argument in `args`. A script is named from
   `/`, `~/`, `$HOME/`, or `${HOME}/`, with no other variable, quote, or shell character.
4. **Check the script.** It is a regular file with one hard link, of at most 64 KiB, outside each
   place a box can write and each `reads` or `deny` path of a declared secret source, with a `#!`
   line, if any, that names `sh`, `bash`, or `zsh` with no
   flags. Its real path holds only letters, digits, and `/._-+@,`, so the path is one word in each
   shell and cannot change the command that `set` puts it in.
5. **Write the hook** with its `keep` values and its `set` values.

- `box run` generates one `fs:read` permit for each script, on its real path
  ([Generated policy](#generated-policy)). No `[agent.filesystem]` grant names a script. The pack
  writes a `set` form that makes the box's shell read the script, so the read is a policy decision.
- Each run replaces the value at the first key of `key` in the copy with the kept hooks, and
  removes it when the run keeps none. Nothing that the copy holds reaches a permit. The rewrite
  follows the copy rules above: no link, one hard link, at most 1 MiB, and a copy that does not
  parse stops the run.
- A host file that sets `disable-key` reaches the copy with `when` false too. When `box` cannot
  read the host file, the copy keeps its value.
- `box run` prints each script, each refused hook with its reason (at most 20), and each
  replacement. A refused hook is named by the keys that lead to it, each `keep-above` string in
  parentheses, and its place in its list, and never by its command.

## MCP servers

A pack names the host files that hold its agent's MCP servers
([decisions.md](decisions.md#a-pack-names-where-its-agents-mcp-servers-are)), and declares no
server itself ([decisions.md](decisions.md#a-pack-makes-an-agent-run-and-never-extends-it)). A
pack's `[mcp.<name>]` table holds only `filesystem` and `network`, and a `when` goes only on one filesystem entry, because a table's `when` is read after the merge and would drop the profile's keys too. It adds grants to a
server that the run finds, as a profile table with no `type` does, and `check_kind` refuses any
other key:

```toml
[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
target = "config/.claude.json"
target-key = ["projects", "${{ workspace }}", "mcpServers"]
key = ["projects", "${{ workspace }}", "mcpServers"]
env-var-locations = { command = "references", args = "references", env = "references", headers = "header-references" }
env-var-syntax = "${NAME}"
when = { variable = "inputs.claude.import-mcp", equals = "true" }
```

The row's keys, the five roles, and their defaults are in
[`[[mcp-servers]]` in a pack](../../cli/packs-reference.md#mcp-servers-in-a-pack). `box` checks
them when it merges the file:

- `file` is a path field. `key` and a list `target-key` are lists of template fields, so a key
  that holds a `.` or a path needs no quoting. A top-level `target-key` is a nonempty literal. A
  missing or other `kind` stops the load, and the error names the pack and the key.
- A field with a role is a known field. `references` goes only on `command`, `args`, or `env`.
  Any other role on a field that `box` already reads (`type`, `command`, `args`, `env`, `url`,
  `enabled`), or an unknown role, stops the load.
- `env-var-syntax` and `command-prefix` are literal. An empty list or an empty prefix stops the
  load. `box` reads a string in one pass and, at each place, tries the form with the longest
  opening first, so a value it fills in is never read again. A form with no closing text, such as
  pi's `$NAME`, opens a variable only before a letter or `_`, and makes `$$` and the
  `command-prefix` after `$` escapes that skip the server. A `url` is read with the forms that have
  closing text only, so a `$` in it, such as OData's `$filter`, is text.
- A `header-references` value keeps the text before its variable as the key's prefix. A
  `NAME:-default` reference uses its literal fallback only when `NAME` is unset. A
  `variable-names` entry with a `source` other than `null` or `"local"`, or an unknown field, is
  refused, and an unset name is omitted before the value checks.
- Rows that share a `target` need the same `kind`, and keys where neither is inside the other. A
  section below the top level that is empty counts as absent, because an agent can write an empty
  one itself, such as Claude Code's default project entry.

The shipped agent packs map their fields as `@box/claude` does above (`headers` to
`header-references`, and `command`, `args`, and `env` to `references`). `@box/codex` maps
`bearer_token_env_var` to `bearer-variable`, `env_http_headers` to `header-variables`, and
`env_vars` to `variable-names`. `@box/pi` maps `headers` to `header-references` and `env` to
`references`.

The first three roles are for a remote server, and the last two for a stdio server. A field
with a local role on a remote server skips the server with `uses <field>`. On a stdio server,
a field with a remote role skips the server when `mcp::keys` reads a variable in it or cannot
read it as its role states. A field with a remote role that holds no variable, such as Claude
Code's `"headers": {}` or `"headers": {"X-Client": "claude"}`, passes through. A field without
`references` is copied as written, except arguments with variable markers. Those become
whole-argument `*` entries with `argument_wildcards = true`, regardless of the role. Box Core
matches the fixed words and forwards caller-supplied wildcard values without expansion.
[profiles.md](profiles.md#mcp-servers) states the marker and literal-star rules.

`box` checks each row's keys, its `kind`, and its `key` list when it merges the file,
so the error names the pack. A row reads no file that the `[[storage.files]]` source check
refuses. `box` removes `[[mcp-servers]]` before Box Core reads the config. [profiles.md](profiles.md#mcp-servers)
states how a server becomes an `[mcp.<name>]` table, and each skip reason.

The reader is generic: `box` knows the MCP fields and the roles, not a harness. The code has one reader seam
(`mcp::Reader`) with one variant. A pack key that selects another reader comes with the first
reader that needs code.

Each target receives entries from the same parsed source snapshot used for detection.
Later source rows win by server name before output is built, including the target of the winning
row. Each selected entry is held until declaration checks finish, then inserted into its target once.
An entry that fails those checks remains in the import without host variable expansion
([decisions.md](decisions.md#mcp-import-does-not-require-generated-policy)).
A stdio entry declared from host settings retains its other settings. Its `command` names the
selected executable's filename, including the authored filename when the executable is a
symlink. The Core table keeps the full absolute path when one was given. Command collisions
compare that filename and the arguments, so different installation paths alone do not
distinguish two servers. The imported `args` contains the fixed arguments from the same
declaration. A wildcard slot keeps the source argument, including
its variable references, so the harness supplies its value when it calls Core.
The `env` and `variable-names` fields are removed when a final stdio declaration covers the
imported command; Core supplies that declaration's environment. This also applies to an entry
without its own generated declaration. A matching name or partial wildcard overlap is
insufficient. They are also removed from a stdio entry whose `env`, as written, holds the
operator's value of a variable that a `pass-secret-env` entry covers ([What stays on the host](plugins.md#what-stays-on-the-host)).
Other entries retain those fields. Each removal reaches only a section that the import writes, so
a section that the box saved earlier keeps the `env` it holds, and the import reports it as
different.
A declared HTTP entry retains its URL, headers, and variable references, so the agent reads Box's runtime
stand-ins. No second host environment expansion occurs.

After policy validation and storage preparation, `mcp_config::Config` returns `Empty` without
filesystem access when it has no entries. Otherwise, it inserts the selected entries
only when the `target-key` path is absent, creating each missing table on the way. A missing file
starts with only that section. An existing file retains its other values and TOML comments.
Imported TOML tables stay together after the existing tables, including nested tables and arrays
of tables, except below an inline table, where the section and each missing parent are inline
tables in place. An existing key of any type, including an empty table, leaves the complete file
unchanged, and so does a parent on the path that is not a table. The one exception is an empty
section below the top level, such as `projects.<workspace>.mcpServers`, which the agent writes by
default and which counts as absent. Invalid documents stop the run without a
write. Target links and nonregular files remain unchanged, and parent directories must be real
directories. Missing, refused, and unreadable sources contribute no entries. Inactive rows create
no import target, but their resolved target definitions remain available for
[context observation](telemetry.md#stored-mcp-configuration). Removing the section allows
the next run with entries to import again
([decisions.md](decisions.md#a-copy-belongs-to-the-box)).

The import opens each parent and the target without following links. A lock on the parent
directory serializes `box` imports. New bytes are staged in the protected run directory and
published relative to the open parent directory. An absent target is published without
replacement. For an existing target, the import checks its identity and contents again before
replacement. A detected change stops the run. Agents do not take this lock, so a write after
the final check can still race the replacement. Stop other runs before reimporting.

The importer returns an outcome for each target: empty, imported, matching, different,
invalid section, or skipped.
`Launcher::prepare` carries the outcome into the run report. Declared server lines say `declared from`;
declaration refusals say `no automatic MCP declaration for`;
import notices report a section write, a difference, an invalid section, or a skipped target.
Matching sections, disabled imports, and empty imports produce no notice. The comparison parses the same stored
text used for the presence check and compares only the section with the selected import entries.
Object order, whitespace, comments, and unrelated settings do not affect equality. A difference
reports sorted missing, changed, and saved-only names, escaped for terminal output, never values.

Stored content is read to preserve settings, check section presence, report differences, and
observe the telemetry context. It supplies no
declaration or permit. Host discovery still supplies both on every run, so a stored entry can
outlive its host declaration and stop working. Importing only MCP entries keeps host model
selection, login state, and hooks out of the box. Preview builds the output in memory and
writes no target.

### Launcher packs

`@box/npx`, `@box/uvx`, `@box/pnpx`, and `@box/bunx` are ordinary tool packs.
`lang::Lookup::launchers` loads their normal pack chains independently of the profile's pack
list. `reference::resolve` uses the same tool resolution for each MCP launcher, with a separate
`${{ cache }}` binding. It resolves each selected executable independently, so an absolute command
uses its own installation for `root` and runtime grants. Other helpers still resolve on the
operator's `PATH`; agent tools keep their own resolution. It imports the resolved environment,
read and list grants, denies, and registry hosts into the detected server. It does not add those tools to
the agent's tool tables. When tool resolution supplies its default scratch directory, the MCP
server uses its cache for `TMPDIR` instead.
MCP startup keeps the full entries of the operator's `PATH`, in order, so the bare launcher and
its runtime match host discovery. It drops each entry that is not a full path, because the server
starts in the workspace. Derived tool `PATH` folders follow those entries. A missing runtime
skips that launcher with the tool resolution reason. A pack that needs additional write,
metadata, or exec grants, or that sets `upgrade_http`, also skips automatic discovery; the
operator must declare that server in the profile.

Helpers contribute their installed runtime directories and exact executable paths. Existing
runtime paths pass the MCP writable-path and forbidden-directory checks. `${{ cache }}` is
`<storage>/mcp-cache/<program>`, shared by servers that use that launcher in the same profile, in
every workspace ([isolation.md](isolation.md)). Each server receives cache read and write grants.
`box run` refuses a write grant in the cache on any other process, and the policy's forbid on
`~/.strands/box` covers the cache, so the Shell and Monty cannot write it
([decisions.md](decisions.md#launcher-caches-are-separate-from-agent-tool-caches)). Ordinary tool imports use
`<workspace>/.cache/<tool>`. Run preparation creates MCP caches. The tools create their own workspace caches.

A launcher tool and an MCP server can share a program name. Hosted shell commands select the
ordinary tool by its resolved executable. Native MCP calls use the alias and exact server
command. A call that matches no server runs the next ordinary program on the agent's `PATH` with
the agent's grants, and Box Core writes an unmatched MCP record to the run's `records.jsonl`.

Each launcher pack states, in a comment beside each line, why it sets that variable or grant.

## Generated policy

`box run` combines authored policy files with generated rules into the run's `policy.dw`.
Packs cannot declare `policies` ([decisions.md](decisions.md#a-pack-adds-no-policy)).

`box profile create` writes a copy of the picked policy starter as `policy.dw`, and lists it
([decisions.md](decisions.md#a-policy-starter-is-copied-into-the-profile)).
`Profiles::load` reads only the files listed in `policies`. An omitted or empty list loads no
authored files. Each entry is a nonempty literal path. Relative paths resolve beside `profile.toml`.
Relative and absolute paths, including each symbolic-link target, must stay in the profile folder
or its subdirectories. The loader refuses a redirected profile folder or profiles root, a path
that leaves the folder, an unreadable file, or a repeated canonical path, including a symlink alias.
Each opened file must be a regular file with exactly one hard link before its text is read.
Errors for individual files identify the profile and the zero-based `policies` index. The
[profile reference](../../cli/profiles-reference.md#what-a-profile-holds) states the field's syntax.

The output contains these parts, in order:

1. The files that the profile lists in `policies`, in list order.
2. A `shell:spawn` permit for each tool that the run keeps, a grammar permit for each kept tool
   with a grammar, a `net:connect` permit for its package
   hosts on port 443, and an `http:request` permit on each host. A skipped tool or one whose `when`
   does not hold gets no permit.
3. For each `[egress.<name>]` route, with or without a secret, a `net:connect` permit on each
   destination's host and port (default 443), and an `http:request` permit on each host.
4. For each `[mcp.<name>]` table, detected or written by hand, an `mcp:call` permit for the name (`mcp_<name>_call`). A stdio
   server also gets a `shell:spawn` permit on its `program` and its real `program_path`
   (`mcp_<name>_spawn`), in the shape of a tool's. An absolute `command[0]` selects that
   executable; `program` is its authored filename and `program_path` is its canonical path.
   For a bare name, `box` looks where Box Core does: on the server's `env.PATH` when it sets one,
   else on the operator's `PATH`, and on `/usr/bin:/bin` when that path is empty.
   Each `PATH` entry that is not absolute, `~` included, is skipped. A
   server whose program `box` cannot find gets no
   `shell:spawn` permit, because Box Core could not start it and a permit on the name alone
   would also let the agent run a program of that name. The run reports it. An absolute command
   never falls back to `PATH`. The compile checks each intermediate executable link against the
   box's write grants, including commands written by hand. A relative or `~` path in
   `command[0]` stops the compile. An http server gets
   the route permits for its `destinations` (`mcp_<name>_connect`, `mcp_<name>_request`). A
   destination port outside 1 to 65535 stops the compile, for a route and a server alike. A detected
   launcher adds `launcher_<name>_registry_connect` and `launcher_<name>_registry_request` for its pack's
   registry hosts. Like other network permits, these apply to the whole box.
5. `fs:read`, `fs:write`, `fs:delete`, and `fs:move` permits for each storage directory, one
   `fs:read` permit for each distinct script that a [`[[storage.hooks]]`](#hooks) row imports
   (`hook_script_<index>_read`), the `forbid` rules for `~/.strands/box` outside the storage directories and the tools' storage, and
   the `resources_*` forbids: on the resolved resources directory when it lies outside every box
   home, and on moving or deleting each folder above it and each folder or link on the written
   path, each reported with its parent resolved, outside the box homes. Each other protected root
   outside the box homes, such as `~/.local/bin`, gets the same forbids as `protected_<n>_*`. A script's permit is an equality on its real path, written as `~/...` when the path is under the
   home, and quoted by `render::literal`.
6. The `project_*` permits for the workspace that `[project] access` declares: `project_read` for
   `"read"`, all four for `"write"`, and none for `"none"` or no `[project]`.
7. The `forbid` rules for `<workspace>/.box`.

`box` writes no permit that no table declares. The rules for
the shell's commands and `/dev/null` are in each policy starter, so they reach the run through the
profile's copy in part 1. No generated rule forbids a cloud metadata service. `@box/open` forbids
link-local addresses, an address class rather than a provider list
([decisions.md](decisions.md#a-pack-adds-no-policy)).

`box` removes leading and trailing blank lines from each file and joins nonempty files with one
blank line. It preserves comments and formatting within each file, without variable substitution
([decisions.md](decisions.md#policy-holds-no-placeholder)).

Server call, spawn, and remote route IDs start with `mcp_`. Launcher registry IDs start with
`launcher_`, so a server named `<name>_registry` cannot collide with a launcher's registry rule.
These prefixes keep server rules separate from other generated rules. A script permit ID starts
with `hook_script_`, which no server, launcher, tool, or route ID starts with. An authored rule can still
hold one of these `@id`s, and Box Core then refuses the duplicate.

`box` does not check the `@id`s itself. Each generator builds its rules as data (`render::Rules`),
so `Compiled` holds the `@id` of each generated rule, and the refusal says which `@id` `box` writes
([profiles.md](profiles.md#where-a-policy-error-points)).

The combined policy is one program. Output order gives no rule priority. An applicable `forbid`
wins over a `permit`. Box Core rejects duplicate `@id` values across authored and generated rules.

## Safety rules

| Risk | Rule |
| --- | --- |
| A value breaks out of its quotes | Each destination encodes the value. No placeholder in `policy.dw`, in a key, or in an `[options]` value, and no shell text. |
| A value changes what a program parses, or a route's host | The input needs `pattern` or `values` ([Bounds](#bounds)). |
| A credential reaches another provider's host | Two packs cannot declare one route, and two packs cannot read one `env://` variable. Box Core gives one stand-in value to each variable, and that value works at each host of each route that reads it. |
| A pack reads a secret into the box | No `from = "env:<NAME>"`, on an input or an `env` entry, for a variable that an `env://` credential reads, a `secret.env` names, or a secret source passes to its program as a credential. A downloaded pack needs more limits, listed under [Not built](#not-built). |
| A pack widens the policy | A pack holds no `policies`, even an empty list. |
| A pack opens a host | A route with only `destinations` permits only lowercase host names with an optional port, and only `net:connect` and `http:request` ([routes with only `destinations`](#routes-with-only-destinations)). |
| A pack opens a service on the operator's loopback | `box` refuses no host name. `@box/open` forbids `net:connect` to a loopback address after DNS, whatever name resolves to it. `@box/scoped` and `@box/locked` reach a loopback host only when a profile or pack names it, and `box profile show` lists such a route as "no credential" ([decisions.md](decisions.md#a-pack-adds-no-policy)). |
| A pack lets a tool bypass the gateway | Only a profile writes `[tool.<name>.network]`, which holds only `contain_egress`, and `box` passes it to Box Core as written. The load refuses `[network]` and `[tool.<name>.network]` in every pack ([decisions.md](decisions.md#only-a-profile-turns-off-a-tools-network-containment)). Box Core records `egress:native` each time the tool runs. |
| Two packs disagree on an input | The value must satisfy each declaration, and a different default or source stops the run. |
| A pack runs host code | A pack holds data, and `box` runs no program that a pack's input names. The one host program `box` runs for a pack is the fixed `/usr/bin/xcode-select -p`, for [`macos.developer_dir`](#the-developer-folder). A program that runs outside the box comes from a [plugin](plugins.md), which only the profile lists, or from the profile's own `[secret-source.<scheme>]`. An input of a plugin belongs to that plugin, so no pack and no other plugin declares it, and the profile's own source reads no input. |
| A box plants a tool for a later run | A tool's program or helper in the workspace, the run's storage, `~/.strands/box`, or under a write grant of the run, as written or real, is skipped. A program that a tool starts from its own storage, such as the `rustc` that rustup starts, is not checked: project code the tool runs can change it for every project of the profile, the unit of isolation ([decisions.md](decisions.md#a-tool-owns-its-state-outside-the-workspace)). |
| A script runs an interpreter with no grants | A `#!` line must name a tool table of the run, or the script is skipped. |
| A box plants a program for a later run | A `program` value in the workspace, the run's storage, or `~/.strands/box` stops the run, as written or through a link. After `box` fills in the profile, it resolves each `write` and `write_file` entry of the agent, each `[tool.<name>]`, and each stdio `[mcp.<name>]`, and each storage directory, through its links. A `program` value under one of them, as written or real, stops the run, and so does an `exec` folder that holds a write grant (`Error::WriteUnderExec`). |
| A path escapes its root | The rules under [Values](#values). |
| A storage path escapes storage | Each storage directory name is one plain path component, and a copy's `target` starts with a declared storage directory, then plain names. |
| A copy carries a credential into the box | Each pack names only the files its agent needs, and `box` copies only what a row names and does not judge what a file holds ([decisions.md](decisions.md#the-packs-decide-what-is-copied)). The one exception is a `reads` or `deny` path of a declared secret source. A copy row or a tool's link row whose source meets one, as written or real, stops the load. A link that a copy follows to one is left out ([What stays on the host](plugins.md#what-stays-on-the-host)). |
| A copy reads what a box planted | A source, and each link that a copy follows, cannot reach the workspace, the run's storage, `~/.strands/box`, or a write grant, as written or real. `box`'s own packs in `~/.strands/box` are the exception, because a run cannot write them. |
| A box redirects a later copy | A copy is built in the run directory, out of every box's reach. `box` opens each folder on the way to the target without following a link, and moves the copy into the folder it holds open, so a folder that a box swaps for a link receives nothing. The move replaces nothing: a target that exists, a link included, is left alone, except that a row with `set` rewrites its values and stops the run at a link or a hard link, and a row with `fill` adds what it lacks and leaves a link or a hard link alone ([copies](#copies)). |
| A source file changes after the check | A first copy takes a file only when the file it opens has the device, inode, size, and times it planned, and reaches storage only when every file still has them once the copy is made ([copies](#copies)). A `sync` update reads a file only when it has the device and inode it planned. |
| The box rewrites what a later run trusts | The policy forbids writes, deletes, and moves in `~/.strands/box` except the run's own storage, and `box run` refuses a write grant there ([decisions.md](decisions.md#a-run-cannot-write-what-a-later-run-trusts)). |
| A grant follows a link the box planted | A filesystem entry that resolves through a link stops the run when the link is inside a place a box can write: the workspace, the run's storage, `~/.strands/box`, or a write grant of the agent, a tool, or a stdio MCP server. `box` checks each entry after it fills in the profile, and it compares the real folder that holds the link. So a link above such a place is followed, such as `/tmp` on macOS or a home folder that is a link. |
| A box plants an MCP configuration for a later run | A `[[mcp-servers]]` `file` that is, holds, or lies in the workspace, the run's storage, `~/.strands/box`, or a write grant, as written or real, is not read ([decisions.md](decisions.md#no-file-a-box-can-write-is-an-input)). |
| A detected server runs what a box planted | A stdio server's program, its real file, its `#!` interpreter, and each full `PATH` directory must lie outside those places, or the server is skipped. A `[mcp.<name>]` table with no `type` counts as a write grant holder, so its `write` entries join the places checked. |
| A stdio server finds a program a box planted through `PATH` | An entry of the operator's `PATH` that is not a full path (`.`, an empty part, or one that starts with `~`) finds programs in the workspace, where each server starts. It reaches no stdio server that inherits that `PATH`, whether `box` detects the server or the profile declares it. A table whose `env.PATH` the profile writes keeps it as written. |
| A detected server's key reaches the agent | For a server declared from host settings, a remote key reaches `box.toml` only as `secret.ref = "env://<VAR>"`, and a header that holds a variable but is not exactly one, or a variable in its `url` other than a whole query value, prevents that declaration. A field `box` does not read, a plain header included, goes into no `box.toml` table ([decisions.md](decisions.md#a-detected-server-carries-no-credential)). A stdio server's key is a value in its own `[mcp.<name>] env`, which only its own sandbox gets ([decisions.md](decisions.md#a-local-servers-key-is-in-box-toml)). An imported entry that a final stdio declaration matches keeps no environment fields, and neither does an imported stdio entry whose `env` holds the operator's value of a variable that a `pass-secret-env` entry covers, or that sets such a variable. An imported stdio entry with that value in an argument, as written, keeps no `args`. Other entries keep their original fields in the agent's settings, including literal keys ([MCP import](decisions.md#mcp-import-does-not-require-generated-policy)). A profile table with no `type` gives a detected server no key ([MCP servers](profiles.md#mcp-servers)). |
| A detected server carries a vault credential | A detected stdio server whose `references` or `variable-names` field reads a `pass-secret-env` variable of a declared source, a prefix entry included, is skipped, whether the variable is set or not. So is one whose `env` or arguments hold the operator's value of a variable that an entry covers, a prefix entry included, one whose `command`, `env`, or `variable-names` field reads a variable that a `secret.env` names for a key from a source, and a remote server whose key comes from one ([profiles.md](profiles.md#mcp-servers)). |
| A detected server's `env` loads code or redirects the box | An `env` name that makes a program load code, or `PATH`, skips the server, and a name the box sets itself is dropped. A relative `HOME` or `TMPDIR` skips the server. A full path is copied, so a home in the workspace is one the agent reads and writes too. Any other `env` value with a path in it skips the server when the path starts with `./`, `../`, or a `~/` that `box` did not fill in, or is or lies in the workspace, the run's storage, `~/.strands/box`, or a write grant, as written or real, and so does a path list with a part that is not a full path. A value that opens as options do is no path list, and the report names its variable ([profiles.md](profiles.md#mcp-servers)). |
| A box plants a settings file that picks a later profile's provider | A starter's `[[source]]` place in the current directory, `~/.strands/box`, or a write grant that detection can fill before the answers is not read, and a value can only pick a starter choice or fill an input that `pattern` or `values` bounds. A pack keeps a settings folder under any other grant read-only with `deny_write` ([detection](detection.md#what-detection-never-reads)). |
| A host path reads as a template | `box` escapes each tool's real file before it fills in placeholders, so a path that holds `${{` stays literal. |

The rows for secret sources are in [plugins.md](plugins.md#safety-rules).

**Residual risk.** `box` creates each storage directory, and moves each first copy, relative to a
directory that it holds open, and it opens no link on the way. Box Core then takes each storage
directory by path. A box of the same profile that is still running, in any workspace, can swap a
storage directory for a link between that check and the run's start. `box` still makes a tool's
link rows by path, so the same holds for the folder that receives a link.

## Box Core behavior that the packs follow

| Finding | Effect |
| --- | --- |
| Box Core v0.1.0 refuses `[agent] dependency` (`unknown field`). | `box` does not write `dependency` into `box.toml`. |
| Box Core makes one stand-in value for each `env://` variable, and each destination that names the variable shares it ([Box Core](../credentials.md)). It refuses two routes that name one variable with a different `phantom_prefix`. | A route with an `env://` reference can name several hosts, and two routes of one pack, or of the operator's profile, can read one variable. |

## Rejected alternatives

| Alternative | Why it lost |
| --- | --- |
| Reference tables outside an `env` value (`{ from = "env", name = "TERM" }`, or `{ env = "TERM" }`) | [decisions.md](decisions.md#values-that-change-are-explicit-references) |
| Both tables and strings | Two forms for one job. Agents copy the patterns they see, and a reviewer has to know both. |
| `{{ }}`, `${ }`, or `$NAME` | Agent files use them: templates in prompts and settings use `{{ }}`, and shells and agent settings use `${ }` and `$NAME`. nono's `$VAR` is a plain text replacement. |
| A default inside the placeholder (`${{ env.TERM ?? "x" }}`) | It hides an input inside one string. The default goes in the declaration. |
| A programmable language (CUE, Pkl, Nickel, Dhall, KCL, Jsonnet, Starlark, Nix) | `box` would write programs, not data. CUE and Pkl need a Go or JVM runtime. Pkl, KCL, and Nix can read or write host files by default. |
| YAML | Implicit types, and the `serde_yaml` crates are deprecated or idle. TOML also matches Box Core's own `box.toml`. |
| An `[env.<NAME>]` section | A second kind of input, with fewer checks, that a profile cannot set. |
| An input name built from the pack's folder | It ties each option to where a pack lives, so a rename or a copy of a pack renames its inputs. |
| A `model` input | [decisions.md](decisions.md#an-option-changes-what-the-box-allows) |
| One kind of file for profiles and packs | [decisions.md](decisions.md#base-is-reserved) |

## Not built

- Packs from a registry. A downloaded pack can do anything the operator's profile can. Before a
  registry, `box` needs signatures (nono's packs use Sigstore and GitHub OIDC) and limits on what
  an untrusted pack declares: no `secret.ref`, no `telemetry` table, and only non-secret
  `env:` inputs (`TERM`, `COLORTERM`, `LANG`, `LC_ALL`, `TZ`, `NO_COLOR`).
- A copy that follows the host. `box` would record a digest of each file it copies in the storage
  root, where no box writes. On each run it copies a host file again only when the host file
  changed since the last copy, keeps the box's edit otherwise, and keeps each file that the box
  created. When both changed, the host file wins and `box` names the copy it replaced.
- The agent's settings file, hooks, and sessions in storage
  ([decisions.md](decisions.md#a-pack-makes-an-agent-run-and-never-extends-it)). A copy cannot change
  a value in a file it copies.
- MCP servers from a managed scope, from Claude Code's `disabledMcpServers`, and from Kiro CLI's
  active-agent rule.
- A list of the host MCP servers that a profile imports, in place of all or none.
- Each pack that declares an input, in `box profile show`.
- Asking a tool where its files are, such as `git --exec-path` or `rustup show active-toolchain`,
  for exact paths in place of `root`-relative ones.
- `required = true` on a tool or a tool entry, to skip a tool at startup when a path it cannot work
  without is absent.
- A tool override: a tool's program from another folder than `PATH` finds, by a `search` folder in
  its program input or by an `[options]` value. Box Core's Shell runs a table's file only for the
  name of its real file, and finds any other bare name on `PATH`, so the agent never reaches an
  override for a linked program, such as `~/.cargo/bin/cargo` (a link to `rustup`), by the name it
  types. `box` refuses both forms when it loads the pack, so the result does not depend on the
  host. To allow them, `box` would check at resolve time that the chosen file is the first on
  `PATH` or has the tool's name as its real name, and skip the tool otherwise.
- Tools that keep their state out of the workspace
  ([decisions.md](decisions.md#a-profile-can-name-launch-directories)).
