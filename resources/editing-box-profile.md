---
name: editing-box-profile
description: Create a box profile, or change an existing one, its policy files, or the settings of packs it imports. Includes a procedure for each task and the reference for options, permissions, tools, storage, and MCP changes without the Box CLI source repository.
---

# Creating and changing a Box profile

Create a profile, or edit a `profile.toml` and the configuration it uses. A profile selects packs
and sets their inputs. Packs supply reusable commands, grants, and defaults. Box CLI resolves
these files and writes a run's `box.toml` and `policy.dw` for Box Core to enforce. Change the
profile's source files, not those generated run files.

## Tasks

Each task has one section. Read [Read before editing](#read-before-editing) first, then the
section for the task, then the reference sections that it names.

| Task | Section |
| --- | --- |
| Make a new profile | [Create a profile](#create-a-profile) |
| Add a pack or take one out | [Add or remove a pack](#add-or-remove-a-pack) |
| Let the agent run a program | [Add a tool](#add-a-tool) |
| Give the agent an MCP server | [Add an MCP server](#add-an-mcp-server) |
| Change where the model runs, or its key | [Choose the model provider](#choose-the-model-provider) |
| Bring host files or settings into the box | [Edit stored files](#edit-stored-files) |
| Allow or refuse an action | [Edit policy](#edit-policy) |
| Confirm that a change is correct | [Check a change](#check-a-change) |
| Repair a profile that `box` refuses | [Fix an error](#fix-an-error) |

## Read before editing

1. Read the target `profile.toml` and every file in its `policies` list, in list order.
2. Read each pack in `packs`, and follow its `extend` recursively. Read all input declarations,
   including inputs the profile leaves unset. Read support files that the proposed edit uses.
3. If `box` is available, run `box profile show --full <name>` from the intended project
   directory. It shows resolved settings and generated policy without starting a box or writing
   run files. It lists only inputs that a placeholder reads, so it does not replace step 2.
   A resolution error is evidence for a repair; continue reading the files.
4. Choose the owning file. Set an existing input in the profile's `[options]` when it covers the
   request. Put additions for this profile in the profile or its listed policy files. Edit a
   shared pack only when the change should reach every profile that imports it. Preserve
   unrelated settings and policy list entries.
5. After editing, run `box profile show --full <name>` again when available. Check the changed
   commands, routes, filesystem grants, and policy against the request. Policy error locations
   refer to the combined policy in that output. Start `box run <name>` only when the task calls
   for a runtime check. Report which files changed and which checks ran.

Edit from the host. A boxed agent cannot write the profile or packs that later runs trust. An
agent without file access needs the operator to supply the files above. State missing context
or unavailable checks; do not infer missing pack contents.

This file is `editing-box-profile.md`. It ships with `box`, in the `resources` folder of the
installed Box CLI, and `box help agent` prints its path. No command writes a guide into the Box
home or into a profile folder. The Box home is `~/.strands/box` unless `BOX_HOME` names another directory.

| Configuration | Location |
| --- | --- |
| Profile named `claude` | `~/.strands/box/profiles/claude/profile.toml` |
| Shipped pack `@box/claude` | `$BOX_RESOURCES/packs/claude/pack.toml` when `BOX_RESOURCES` is set; otherwise `resources/packs/claude/pack.toml` beside the installed `box` program |
| Operator pack `team-agent` | `~/.strands/box/packs/team-agent/pack.toml` |
| Collection pack `@acme/team-agent` | `~/.strands/box/external/acme/packs/team-agent/pack.toml`. Each folder in `~/.strands/box/external/` is a collection, and its folder name is the scope. The folder also holds `plugins/`, `starters/`, and `policies/`, named the same way. |
| Listed policy file | Relative to the profile folder, unless its path is absolute |

Every imported pack has the same authority as the profile: it can change commands, grants, and
routes. Read a pack before adding it. `${{ pack }}` names the folder of the file that contains
it, so support files remain relative to their owning pack.

The reference sections hold every rule:

- [File boundaries and merge rules](#file-boundaries-and-merge-rules)
- [Experimental native filesystem policy](#experimental-native-filesystem-policy)
- [Options, commands, and environment](#options-commands-and-environment)
- [Placeholders, paths, and conditions](#placeholders-paths-and-conditions)
- [Model providers and network access](#model-providers-and-network-access)
- [Filesystem access and policy](#filesystem-access-and-policy)
- [Tools and program trust](#tools-and-program-trust)
- [Stored files and settings](#stored-files-and-settings)
- [MCP servers](#mcp-servers)

## Create a profile

`box profile create` writes `profile.toml` and a copy of the chosen policy as `policy.dw`, in
`~/.strands/box/profiles/<name>/`. Without a terminal it asks nothing, so give every answer as a flag.

1. Run `box profile list`. It prints the profiles that exist and the starters. Do not replace an
   existing profile unless the operator asks.
2. Choose the agent and the model provider with the operator. Do not guess them.
3. Run the command from the project directory:

   ```sh
   box profile create <name> --with <agent>,<provider> --policy <open|scoped|locked> --option <input>=<value>
   ```

| Flag | Meaning |
| --- | --- |
| `<name>` | The profile name: 1 to 64 letters, digits, `.`, `_`, and `-`. It cannot start with `.` or `-`, and it cannot be `base` or `box`. A name that is a starter's name selects that starter. |
| `--with` | The starter and packs, separated by commas, such as `--with claude,bedrock`. A short name is the operator's own starter or pack when one exists, else the one that ships with `box`. A short name never names a collection's starter or pack: give its full name, such as `--with @acme/claude`. |
| `--option` | One `[options]` value, as `name=value`. Repeat the flag for more. The name is an input that a pack in the profile declares. |
| `--policy` | The policy the profile starts with: `open`, `scoped`, or `locked`, or another policy in the menu, such as the operator's `team` or a collection's `@acme/team`. Required without a terminal. Ask the operator; `open` lets the agent reach any host. |
| `--tools` | The tool packs to add, separated by commas. Without it, `box` adds its default tool packs. |
| `--force` | Replace an existing `profile.toml` and `policy.dw`. Their edits are lost. Use it only when the operator asks. |

4. A message `box profile create <name> needs an answer to "<question>"` means a question has no
   answer. Add the `--policy`, `--option`, or `--with` value that answers it, and run the command
   again.
5. The report names each variable or AWS profile that must hold a key, or the plugin that reads it
   from a vault. Tell the operator. Do not read, print, or write a key value.
6. Do [Check a change](#check-a-change).

## Add or remove a pack

A pack has the same authority as the profile. Read `pack.toml` and `README.md` in the pack's
folder before you add it. The folders are in the table of [Read before editing](#read-before-editing).

To add a pack:

1. Add its name to `packs` in `profile.toml`: `@box/<name>` for a pack that ships with `box`, a
   plain name for a folder in `~/.strands/box/packs/`, and `@<scope>/<name>` for a pack in a
   collection. Order matters; see
   [File boundaries and merge rules](#file-boundaries-and-merge-rules).
2. Set each input the pack needs in `[options]`, by its full name.
3. A profile runs one agent. Do not add a second agent pack or a second model provider beside the
   first.

To remove a pack:

1. Delete its name from `packs`.
2. Delete each `[options]` value for an input that only that pack declares. A value that no pack
   declares fails.
3. Delete profile tables that only extended that pack's tables, such as a `[tool.<name>.env]`
   addition for a tool that is gone.
4. A pack that another listed pack names in `extend` still loads. Remove the pack that extends it
   too, if the operator wants it gone.

Do [Check a change](#check-a-change) after either edit.

## Add a tool

Choose the first form that fits. The rules are in [Tools and program trust](#tools-and-program-trust).

1. A tool pack ships for the program: add `@box/<tool>` to `packs`. A JavaScript tool pack brings
   `node` with it.
2. No pack exists, and the program is on the host `PATH`: declare `[tool.<name>] program =
   "<executable>"` in the profile. `box` finds the program and writes its spawn permit.
3. The program must run from one fixed path: declare `[tool.<name>] command = ["/absolute/path"]`,
   give it a `[tool.<name>.filesystem]` table, and add a `shell:spawn` permit for that path to a
   listed policy file.

Then give the tool what it needs and no more: `filesystem` entries for paths outside the project,
`hosts` for package hosts, and `env` values. A tool that the host does not have is skipped and
reported; it is not an error. Do [Check a change](#check-a-change), and confirm that the output
holds the tool's table.

## Add an MCP server

The rules are in [MCP servers](#mcp-servers). Choose one form:

1. The server is in the agent's host configuration: set the agent pack's import input in
   `[options]`, such as `claude.import-mcp = true` or `codex.import-mcp = true`. Read the input's
   warning to the operator first, because it permits every supported host server.
2. A found server needs more access: add `[mcp.<name>.filesystem]` or `destinations` in the
   profile, with no `type` key. Such a table takes no `secret`: one that adds to or changes the
   found server's key skips the server, so use form 3 to give a server a key.
3. The server is not in the host configuration, or its declaration must differ: write a complete
   `[mcp.<name>]` table with `type` in the profile, and supply the agent-side entry separately.

   ```toml
   [mcp.notes]
   type = "stdio"
   command = ["/usr/local/bin/notes-server", "serve"]
   ```

   `type` is `"stdio"` for a local program, with `command` as an argument list. `type` is
   `"http"` for a remote server, with `destinations`: a host with an optional port and path, not
   a URL.

   ```toml
   [mcp.docs]
   type = "http"
   destinations = ["mcp.example.com"]
   ```

Do not write permits for the server; `box` writes its call, spawn, and network permits. Do
[Check a change](#check-a-change), and confirm that the output lists the server. A server that
`box` skips is reported with its reason.

## Choose the model provider

A provider is a support pack with a route to the model host and the name of its credential. The
rules are in [Model providers and network access](#model-providers-and-network-access).

1. Read the agent pack's inputs. An input such as `claude.host` selects the provider on the agent's
   side, and its `values` list names what the agent accepts.
2. Put exactly one provider pack in `packs`, and set the agent's input to match it in `[options]`.
   Remove the provider pack that is no longer used. `box` does not refuse two provider packs, so
   the check passes with both: read the routes in its output yourself.
3. Set the provider's own inputs, such as `bedrock.region`.
4. The route's `secret.ref` names where the key comes from: `env://<NAME>` is a variable in the
   shell that runs `box`, and `aws://<profile>` is an AWS profile. Tell the operator which one to
   set. Do not put a key value in any file, and do not forward the key through `env`. A reference in
   a scheme that a plugin declares, such as `op://`, is read from the vault when the box starts.
   Set it on the route in the profile, with `secret.env`, as
   [File boundaries and merge rules](#file-boundaries-and-merge-rules) states.

`box` does not check that the agent works with the provider, and neither does this guide. Do
[Check a change](#check-a-change). The output must hold one model route and no route of the
provider that was removed.

## Edit stored files

Storage holds the agent's state for a profile. The rules are in
[Stored files and settings](#stored-files-and-settings).

1. Find the row that owns the target. A pack's copy is turned off through its input, such as
   `claude.import-settings = false`, not by a second row for the same target.
2. Add a `[[storage.files]]` row to the profile with a `source` on the host and a `target` in a
   declared storage directory. Add `optional = true` when the source can be absent.
3. Copy selected keys with `kind` and `keep` from a file that can hold a credential. Do not copy a
   credential file or a folder that holds one.
4. An ordinary copy is taken once. Use `sync = true` for host files that must stay current, and
   `[[storage.files.set]]` for a value that must be restored on each run.

Do [Check a change](#check-a-change). A stored copy that exists is not replaced by a new row, so
tell the operator when an old copy must be removed.

## Edit policy

A rule permits or forbids one action. The box refuses what no rule permits, and a `forbid` wins
over every `permit`. Where rules live, and what `box` writes itself, is in
[Filesystem access and policy](#filesystem-access-and-policy).

Write each rule on three lines: `@id(...)` on its own line, the effect and scope (`permit (...)` or
`forbid (...)`) on the next, and `when { ... }` or `unless { ... }` on the line after that. A long
condition may wrap inside the braces, and a blank line separates two rules:

```text
@id("no_dynamodb")
forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input.host like "*dynamodb*" };
```

| Action | Fields of `context.input` |
| --- | --- |
| `fs:read` | `path`, and `operation`: `read_content`, `read_metadata`, `enumerate`, `read_link`, `change_dir`, `exec` |
| `fs:write` | `path`, and `operation`: `write_content`, `create_dir`, `set_permissions`, `symlink` |
| `fs:delete` | `path`, and `operation`: `remove_file`, `remove_dir` |
| `fs:move` | `path`, and `operation`: `rename` |
| `net:connect` | `host`, `port`, and optional `ip4`, `ip6` |
| `http:request` | `host`, `port`, `method`, `path` (the URL path), `body_bytes`, `intercepted` |
| `shell:exec` | `program`, `command`, `arg_count`, `cwd`, and optional `arg1`, `arg2` |
| `shell:spawn` | The `shell:exec` fields, `program_path`, and optional `credential_reads` |
| `mcp:call` | `server`, `method`, and optional `tool`, `prompt`, `uri` |

An `operation` value is written with its type, which is the action's name in the form
`Box::FsWriteOperation`: `context.input.operation == Box::FsWriteOperation::"set_permissions"`.
The types are `FsReadOperation`, `FsWriteOperation`, `FsDeleteOperation`, and `FsMoveOperation`.
The action `fs:other` is reserved, and a rule that names only it is refused.

`arg_count` is the number of arguments after the program, and `arg1` and `arg2` are the first two
of them. For `npm install left-pad`, `arg1` is `install`, `arg2` is `left-pad`, and `arg_count`
is 2. The box decides a program that a tool table declares, such as `npm` from `@box/npm`, as
`shell:spawn`, so write a rule about one of those programs on `shell:spawn`.

1. Write the rule in a file that `policies` lists. Add a new file beside `profile.toml` and add
   its name to `policies` to keep the change apart from the copied `policy.dw`.
2. Give the rule an `@id` that no other rule has, in your files or in the generated rules that
   `box profile show --full` prints.
3. Name one action for each rule, or a list of actions of one family with `action in [...]`,
   such as `fs:read` and `fs:write`. One action does not cover another: `fs:read` does not permit
   `fs:write`.
4. An optional field needs a guard before the rule reads it, such as
   `context.input has arg1 && context.input.arg1 == "install"`. The table names each optional field.
5. To refuse one case of something that is permitted, write a `forbid`. A narrow `permit` does not
   limit a broad one.
6. A host needs both `net:connect` and `http:request`. A route in `profile.toml` writes both, so
   prefer a route to hand-written network permits.
7. Keep the `shell_commands` and `dev_null` rules of the copied `policy.dw` unless the operator
   asks to change them.
8. An `fs:*` rule decides only the Shell and Monty. The agent's own file tools, each tool, and
   each local MCP server reach their filesystem grants with no policy decision, and their reads
   do not enter the history that `when temporal` reads. To keep a path from every process, add it
   to the profile's `[filesystem] deny`, or a folder to `[filesystem] deny_write`.
   `[project] access = "read"` makes the project grant that `box` adds read-only, and a pack or
   profile entry that names a folder there still applies. A rule that refuses only deletes or moves, or that uses a pattern,
   has no list that matches it. Tell the operator when a rule that they ask for cannot hold for
   every process.

Do [Check a change](#check-a-change). It loads the combined policy, and a rule with a wrong
action, field, or `@id` fails there with the name that `box` expected.

## Check a change

1. Run `box profile show --full <name>` from the project directory. It starts no box and writes no
   run files.
2. Exit status 0 means that the profile resolves and the combined policy loads. Any other status
   is an error to repair; see [Fix an error](#fix-an-error).
3. Read the output against the request: the packs, the `[options]` values, the tool and MCP
   tables, the routes, the filesystem lists, and the rules in `policy.dw`.
4. Read the notices. A skipped tool, a skipped MCP server, or an omitted extension is reported
   there and does not change the exit status.
5. Run `box run <name>` only when the operator asks for a runtime check.
6. Report the files that changed and the checks that ran. Change only the profile's own folder,
   and an operator pack when the operator asks. Do not change a pack that ships with `box`.

## Fix an error

A message names the file and the line, then the problem. For a policy mistake it names the
combined `policy.dw` that `box profile show --full` prints, not one listed file, so find the rule
by its `@id`, action, or field.

| Message holds | Repair |
| --- | --- |
| `sets an input that no pack declares` | Use the input's full name, such as `bedrock.region`, or add the pack that declares it. |
| `does not match its pattern` | The `[options]` value is not one the pack allows. Read the input's `pattern` and `values`. |
| `holds the unknown key` | Correct the key. The message names the nearest key that exists. |
| `is not one of` | The `[options]` value is not in the input's `values` list. The message lists the values. |
| ``no `<program>` that the box can run`` | The agent's program is not on this host, so the check cannot finish. Tell the operator. Do not edit the profile to remove the message. |
| `two packs cannot declare one route` | Two packs declare a route with the same name. Remove the pack that was not intended. |
| `two packs cannot read one key` | Two routes read the same credential. Remove the pack that was not intended. |
| `does not exist` after a pack name | Correct the name in `packs`: `@box/<name>` ships with `box`, a plain name is a folder in `~/.strands/box/packs/`, and `@<scope>/<name>` is a folder in `~/.strands/box/external/<scope>/packs/`. |
| `this pack needs box` | The pack needs a newer `box`. Remove the pack, or tell the operator to upgrade. |
| ``a profile holds no `box_dir` ``, or `name`, or `workspace` | Delete the line. `box run` sets these values. |
| `box writes a rule with the id` | An authored rule has the `@id` of a generated rule. Rename it, or delete it when `box` now writes that permit. |
| `unable to guarantee safety of access to optional attribute` | The rule reads an optional field with no guard. Add `context.input has <field> &&` before the read. |
| `unrecognized action`, or `not found` after an attribute | Correct the action or field name in the rule. Use the table in [Edit policy](#edit-policy). |
| `is not an absolute path` | Write a full path, or a program name that is on `PATH`. |
| `needs an answer to` | `box profile create` ran without a terminal. Add the flag that answers the question. |

Repair the cause in the file that owns it. Do not delete a rule or a grant only to make the
message go away. Then do [Check a change](#check-a-change).

## File boundaries and merge rules

In a profile, keep top-level TOML keys, such as `packs`, `policies`, and `agent-args`, before
the first table. A key below `[options]` belongs to that table until another table starts. A pack
has no top-level keys: every key is in a table, and the file starts with `[pack]`.

| File | Accepted contents |
| --- | --- |
| Profile | `packs`, `plugins`, `policies`, `agent-args`, `file-attributes`; `[profile]`, `[options]`, `[limits]`, `[project]`, `[filesystem]` with only `deny` and `deny_write`, `[banner]`, `[experimental-features]`, `[agent]`, `[[agent.ingress]]`, `[tool.<name>]`, `[egress.<name>]`, `[mcp.<name>]`, `[storage]`, `[telemetry]`, `[secret-source.<scheme>]` |
| Agent pack | `[pack]`, `[inputs.<name>]`, `[run]` with `command`, `dependency`, `file-watching`, and `when`, then `[env]` and `[filesystem]` for the agent, which `box` reads as `[agent]`, plus `[tool.<name>]`, `[egress.<name>]`, `[storage]`, `[telemetry]`, and `[[mcp-servers]]`. It writes no `[agent]` table. |
| Support pack | `[pack]`, `[inputs.<name>]`, `[agent]`, `[[agent.ingress]]`, `[tool.<name>]`, `[egress.<name>]`, `[storage]`, `[telemetry]`, `[[mcp-servers]]`; `[mcp.<name>]` may add only `filesystem` and `network` grants. No `[run]`, `[env]`, or `[filesystem]`. |
| Tool pack | `[pack]`, `[inputs.<name>]` with the program input, `[run]` with `command` and the tool's other keys, then the tool's tables, such as `[env]` and `[filesystem]`. See [Tools](#tools-and-program-trust). |
| Plugin | `[plugin]` with `name`, `version`, `kind = "secret-source"`, and `scheme`; optional `[requires]`; `[inputs.<name>]`; `[run]` with `command` and optional `output`; `[env]`, where each entry is `NAME = { from = "env:NAME" }` and nothing else; `[protect]` with only `env`, a list of names of `[env]`, and `paths`, a list of path strings. Nothing else: no `[filesystem]` and no `[secret-source.<scheme>]` table. |

A profile has no `[pack]`, `[inputs]`, `extend`, `include`, `[run]`, or `[[mcp-servers]]`. Packs have no `packs`,
`plugins`, `policies`, `[profile]`, `[options]`, `agent-args`, `file-attributes`, `[limits]`, `[project]`,
`[banner]`, `[experimental-features]`, or `[secret-source.<scheme>]`.
`[banner] enabled = false` turns off the activity banner for the profile; it changes no grant or rule.
Only `profile.toml` can set `native-filesystem-policy` for any process. Unknown keys fail.

A plugin's secret source runs a host program outside the box, such as 1Password's `op`. The
program reads each secret that a reference in its scheme names, such as
`op://Personal/GitHub/token`. Only the
profile lists a plugin, in `plugins`: `@box/<name>` is a shipped plugin, a plain name is
`~/.strands/box/plugins/<name>/plugin.toml`, and `@<scope>/<name>` is
`~/.strands/box/external/<scope>/plugins/<name>/plugin.toml`. A shipped plugin is a folder in
`resources/plugins/` beside the installed `box` program, or in `$BOX_RESOURCES/plugins/`.
`packs`, `extend`, and `include` refuse a plugin. One scheme has one
declaration, from a plugin or the profile. Only the profile writes a reference in a declared
scheme. Put it on the route in the profile, and name the agent's variable in `secret.env`, such as
`[egress.github.secret] ref = "op://Personal/GitHub/token"` and `env = "GH_TOKEN"`. A plugin looks like an agent pack, but its program runs on the host: `[plugin] scheme` is the scheme it reads, `[env]` names each host variable that the program gets, under its own name, and a name takes no `*`. `[protect]` says what the box keeps from the agent, each tool, and each MCP server, and grants nothing: `env` lists each name of `[env]` that is a credential of the vault, and `paths` lists the vault's paths, as `${{ home }}/...`, `~/...`, or a full path, which no grant can reach. An entry of `paths` takes no `when` or `optional`. A plugin holds no `[filesystem]`. Element 0 of a
plugin's `[run] command` is `${{ inputs.<name> }}` for its `program` input, which `[options]` can set to
another path, and one argument holds `{ref}`. A profile file that runs by its path holds no `[secret-source.<scheme>]`, and in `[options]` it sets no plugin's `program` input, and a plugin's other input only when it is a `bool` or the plugin lists its `values`: use a plugin in `~/.strands/box/plugins/<name>/`, the program on `PATH`, or a profile in `~/.strands/box/profiles/<name>/`. Such a file lists no plugin whose `[inputs]` or `[run] command` reads `${{ profile }}` or `${{ profile.file }}`, which there name that file and its folder: write a fixed path in the plugin. A plugin's `[run] command` and its own `[inputs]` read only the plugin's inputs, and no
pack and no second plugin declares one of them. A `[secret-source.<scheme>]` in the profile reads no input: write its
program's full path and each other value of `command`. No source reads `${{ root }}` or `${{ tool.<name>.root }}`. Keep a source's program, its `#!` interpreter, and each full path in its `command`, a folder and a file that is not there yet included, outside the project, `~/.strands/box`, and every write grant, and pass no folder that holds a write grant. A source takes no `when`. No input or `env` entry of a pack or the profile reads a variable that a plugin lists in `[protect] env`, or that a profile's source lists in `pass-secret-env`. An imported MCP server that reads one, or holds your value of one in its `env` or an argument, is
left out. A `[[storage.files]]` row whose `source` is, holds, or lies in a path that a plugin's
`[protect] paths` names, or that a profile's source lists in `reads` or `deny`, fails.
Neither file sets run-owned `name`, `box_dir`, `workspace`, `policy`, or `[telemetry.records]`.
This includes `workspace` inside an agent or tool table.

When editing a pack, retain its `[pack]` header: `name` must match its import name,
`version` is a whole number, `kind` is `"agent"`, `"tool"`, or `"support"`, optional `extend`
lists the packs it builds on (agent packs extend agent and support packs, tool packs extend tool
and support packs, support packs extend support packs; a tool pack that extends a tool pack takes
that tool's env, filesystem with writes, and program folder on `PATH` into its own tool, its own env
wins, not `PATH` or `TMPDIR`, a skipped base gives nothing, and the base is not a tool of its own
unless the profile or a support pack sets its `[tool.<name>] program`),
and optional `include` lists tool packs to load as tools of their own (nothing merged).
The header accepts only these keys. A separate optional `[requires]` table with `box = ">=X.Y.Z"` names the oldest Box CLI that the pack, plugin, or profile needs.

`kind` decides what `[run]` holds. A `tool` pack's `[run]` sets `command` to its program input alone, and the pack extends
tool and support packs. An `agent` pack's `[run]` sets `command`, or the pack extends an agent pack
and adds to it; any pack
that extends an agent pack is an `agent` pack. Every other pack, such as a model provider, is
`support`. A profile runs one agent, named by one agent pack that extends every other agent pack
in the profile. Two agent packs where neither extends the other fail: name one pack that
extends both instead.

| Setting | Merge behavior |
| --- | --- |
| Pack order | Resolve `packs` left to right. Each pack's `extend` merges before that pack. A shared dependency merges once, on its first occurrence. Cycles fail. Each plugin in `plugins` merges after the packs, and the profile merges last. |
| Tables and scalar values | Tables merge by key, except for tool replacement below; a later scalar replaces the earlier value. A later table cannot remove an inherited key. |
| Tool replacement | A profile's `[tool.<name>]` with `command` and no `program` replaces a pack's tool of that name that uses `program`, including its settings and grammar. Supply the command tool's own settings and policy permit. |
| Operator commands | A command without `program` in an operator pack replaces a shipped program-form tool in either order. All shipped settings and grammar for that tool are omitted. Other tool tables and other pack settings keep the normal merge rules. |
| Filesystem lists and `[storage] directories` | Append and deduplicate. An empty list does not revoke inherited entries. Change the owning pack or its controlling input to remove them. |
| `[[storage.files]]` | Rows append. Active rows with equal or overlapping targets fail; see [Stored files](#stored-files-and-settings). |
| `[[storage.hooks]]` | Rows append. Two rows with one target fail. |
| `[[agent.ingress]]` | Rows append, packs before the profile. A profile row whose `when` holds replaces every pack row for its `workload_port`, so a profile can move or narrow a pack's listener; a row whose `when` is false replaces nothing. Two packs never replace each other's rows, so Box Core refuses two pack rows for one port. |
| Other arrays, including `command` | The later array replaces the whole earlier array. To change one command flag, supply the complete command. |
| Input declarations | All declarations contribute constraints; see [Inputs](#input-declarations-and-values). |
| Routes | Two packs cannot declare the same `[egress.<name>]`. The profile can override a pack's route keys or add its own route. |
| MCP imports | `[[mcp-servers]]` rows append. A later row wins for a server with the same name. Profile tables then replace or extend it according to `type`; see [MCP servers](#mcp-servers). |

Conditions apply after merging. A false `when` on a table removes everything merged into that
table, including another file's additions. Put conditions on the narrowest entry or value that
should change.

## Experimental native filesystem policy

Box Core supports this experiment on macOS 27 or later and Linux ARM64. Use a CLI
build that includes the Cargo feature `native-filesystem-policy`. On macOS, activating the feature
requires a binary built with the macOS 27 software development kit (SDK) or later. The executable
must have a valid signature and Apple's Endpoint Security entitlement
(`com.apple.developer.endpoint-security.client`), which permits interception of selected system
requests. The profile setting does not compile support into an existing binary.

On Linux ARM64, the host must support seccomp user notifications and descriptor injection, which
let Box pause a system call and supply an approved file descriptor. It also needs BPF Linux
Security Module hooks and BPF type information so Box can load kernel checks for file identity.
When any workload selects native checks, start the trusted Box process with `CAP_BPF` and
`CAP_PERFMON`, the Linux capabilities for loading these programs and using their tracing hooks.
A normal install does not provide these capabilities. Box loads its checks and drops these
capabilities before launching workloads. Missing capabilities or kernel support stop launch.
Linux x86-64 refuses selection.

The feature adds policy checks for supported file operations that processes perform directly.
It does not expand their filesystem grants, check every operation, or revoke access through an
already-open file. Box can reject an unavailable selection during configuration checks or
refuse startup; it does not run a selected process without the checks.

On macOS, native policy checks need the `box` process to stay alive. If an uncatchable
signal such as `SIGKILL` terminates it, programs in the box can survive. Those programs
can then perform new file operations within their existing filesystem grants without
native policy checks, so previously denied operations can succeed. Because `box` cannot
catch that signal, it cannot run its normal shutdown cleanup.

Only `profile.toml` can select native filesystem policy. Native checks remain disabled unless
you select them in the profile. Write `true` or `false` without quotes, either directly or as
the `value` in a `when` condition:

```toml
[experimental-features]
native-filesystem-policy = true
```

To request checks only on macOS, write:

```toml
[experimental-features]
native-filesystem-policy = { value = true, when = "macos" }
```

The condition tests the operating system, not its version or build support. The macOS
prerequisites above still apply. If the condition is unmet, Box removes the setting.

The default is `false`, including when a condition removes the setting. To disable native
checks, remove the setting or set it to `false` in `profile.toml`. Remove or disable any explicit
process-level `true` values too; they require the global selection.
Do not copy other Box Core experimental settings into this table;
only `native-filesystem-policy` is accepted. Box enables tool grammars when a configured tool
has one.

The agent, each tool, and each local MCP server inherit the global value independently. In a
profile, set `native-filesystem-policy = false` in an existing `[agent]`, `[tool.<name>]`, or local
`[mcp.<name>]` table to opt that process out. A process setting of `true` requires the global
feature to be `true`. Remote MCP servers cannot use the setting. Retain each table's required
command and other fields. A local MCP server that a launcher pack such as `@box/npx` starts needs
`native-filesystem-policy = false` in its `[mcp.<name>]` table: the policy cannot tell it from the
agent, so `box_home_write` would refuse its writes to its launcher cache, and `box run` does not
start it without the opt-out.

For example, this profile selects checks for tools and local servers while opting out the agent:

```toml
[experimental-features]
native-filesystem-policy = true

[agent]
native-filesystem-policy = false
```

Packs cannot declare `[experimental-features]` or set `native-filesystem-policy` for any
process. Box rejects such a pack during profile inspection or startup. The error names the
pack and invalid field. For global, agent, and tool settings, it also points to `profile.toml`. This includes `false` values,
conditional settings, and packs imported through `extend`. A profile override cannot hide
the invalid setting. A pack's MCP additions still accept only filesystem and network grants.
Restart the run after changing a selection.

`box profile show <name>` lists the selected packs but has no separate native feature summary.
Use `box profile show --full <name>` to inspect the generated global setting and any process
overrides. Core can reject an unsupported selection during this inspection. These commands do
not start a box or prove that native enforcement is active.

## Options, commands, and environment

Use the full name of an input that an imported pack declares:

```toml
[options]
bedrock.region = "eu-west-1"
```

An option is a literal string, integer, or boolean. Box reads integers and booleans as text.
Options contain no placeholders. Removing an option restores its input's host source or
default; it does not remove the setting that uses the input.

### Input declarations and values

Read the complete declaration before changing an option or its constraints in a pack.

| Declaration key | Meaning |
| --- | --- |
| `type` | `string` by default, `bool`, or `program` |
| `description` | Text for the person reading the input |
| `from` | `env:<NAME>` reads the shell where `box` runs |
| `key` | With `from`, reads one key of a comma-separated `key=value` list in the variable: items split at the first `=`, keys and values trimmed, the value percent-decoded. A key listed twice, an invalid escape, or a decoded NUL fails. |
| `default` | String or boolean used when no option or host value supplies one; may contain placeholders |
| `pattern` | A Rust regular expression that the entire value must match |
| `values` | Allowed values |
| `program` | For `type = "program"`, the executable name to discover; cannot be combined with `default` |
| `search` | With `program`, ordered search folders; defaults to `PATH`. Entries may contain placeholders or `*`; `{ env = "PATH" }` expands the host's search path. Version matches are tried newest first. |
| `warning` | What choosing a value permits. Creation shows it with the input's question and saves the answer even when it is the default. Cannot combine with `from` or program discovery. |

The value precedence is the profile's option, then a nonempty `from` variable (with `key`, a
nonempty value for that key), then program discovery or `default`. A missing value fails when the input is used. Every source passes the same checks:
`bool` is `true` or `false`, and the value satisfies every declared `pattern` and `values` list.
A program passes the [program trust checks](#tools-and-program-trust).

Two packs declaring one input must agree on `type`; their constraints all apply. Different
`from` sources or defaults are ambiguous until the profile explicitly sets the option. Input
names use letters, digits, `_`, and `-`, in components separated by `.`. `description`, `type`,
`pattern`, `from`, `key`, `program`, and `warning` are literal. Warnings from different packs accumulate;
they do not validate or change the input's value.

An input used in `command`, `agent-args`, route `destinations`, a route's backend `url` or
`auth.aws.region`, or the URL `destination` of a telemetry target needs `pattern` or `values`. Boolean inputs are exempt. A program input is exempt only as element 0 of `command`, never in
`agent-args`. Built-in placeholders such as `${{ home }}` are exempt. Pass unconstrained text
through the environment instead of command arguments. An input's `from` cannot read a variable
that a route uses as a credential.

### Agent arguments and environment

Use profile `agent-args` to add arguments at the agent pack's `{ slot = "agent-args" }`. A slot
appears at most once in `[agent] command`, after the program. Its `default = [...]` applies only
when the profile has no `agent-args`. Setting `agent-args` without a slot fails. Its elements are
plain strings, may contain supported placeholders, and have no `when`. Arguments supplied after
`--` to `box run` still come last.

To replace a flag already in a pack's `command`, copy the full resolved command structure and
edit that array. A command is an argument list, not shell text. Its first element is the program
and cannot have a condition.

The agent does not inherit the host shell environment. Set a literal value or forward one named
variable:

```toml
[agent.env]
MAX_THINKING_TOKENS = { from = "env:MAX_THINKING_TOKENS" }
```

A missing host variable produces no entry. A forwarded value is copied literally without
placeholder expansion. The same `from` form works in tool and MCP `env` tables. A profile's
literal value replaces a pack's `from`. Credential variables used by routes cannot be forwarded.
Read the pack's import options before changing host settings: an agent may also import selected
settings into [storage](#stored-files-and-settings).

To let a caller outside the box reach a server the agent runs, add `[[agent.ingress]]` rows. Each
row takes `listen`, an IP address and port that Box binds outside the sandbox, and
`workload_port`, the port the agent listens on inside it. Both are required, and both are literal:
no placeholder. `[agent]` alone takes ingress; a row in a tool or MCP table fails. Box Core accepts
at most five rows, each with its own `listen` port and its own `workload_port`, and on macOS no
`listen` port may equal any `workload_port`. `box` turns on Box Core's experimental `ingress`
switch for a profile that has a row, so nothing else is needed.

```toml
[[agent.ingress]]
listen        = "127.0.0.1:8080"
workload_port = 8081
```

For execution limits, `[limits] shell.timeout` accepts 1 to 31536000 seconds or `false` for no
limit; its default is `false`: the box sets no Shell timeout, so the agent's own tool timeout applies,
as it does outside a box. Set `[limits] shell.timeout = <seconds>` to stop a command sooner. `[limits] shell.max_input` is the bytes of command text sent to
the Shell at once: a whole number, 262144 by default, and `0` disables it.
`[limits] shell.max_stdin` is the bytes of standard input one command through the box's `zsh`,
`bash`, or `sh` receives: a whole number from 1, 1048576 by default, and it can't be turned off. Past it, the command gets no end of input: a command that reads all of
it fails at the Shell timeout, or with `shell.timeout = false` waits until its caller stops it. The
key alone helps a plain command that writes its input, such as `cat > file` or `wc -c`. A command
that holds the input, such as `x=$(cat)` or `jq`, or a loop or group with a redirect, such as
`while read ...; done > file` or `{ cat; } > file`, also needs `[limits] shell.max_output`:
the bytes in each Shell output buffer, including command substitution, which Shell also applies when
it loads a script with `source`. It is a whole number, 1048576 by default, and `0` disables it. Raising
any size lets the Shell hold more data in the box's trusted process. No other `[limits]` key is
accepted. Profile `file-attributes` defaults to `true`, except when Box
CLI runs as root. On macOS it permits file times, set-ID bits, group changes, and ACL changes in
writable folders.

## Placeholders, paths, and conditions

Box expands `${{ name }}` once in supported string fields. Spaces inside the braces are
optional. `$${{` produces literal `${{`. Table keys never contain placeholders.

| Name | Value and scope |
| --- | --- |
| `workspace` | The intended project directory, with links resolved |
| `workspace.dashed` | The project path with each non-ASCII-alphanumeric character replaced by `-`, as used in Claude Code's project folder names |
| `workspace.parent`, repeated `.parent` | The folders above the project directory; at `/` it stays at `/`. No other step is supported, and `dashed` goes only right after `workspace`. |
| `home` | The operator's home directory |
| `pack` | Folder of the profile or pack file that holds this placeholder, resolved before merging |
| `profile` | The profile folder |
| `profile.file` | The profile's own file, such as `profile.toml` in the profile folder or the profile file that `box run` named |
| `box` | This run's Box Core folder; its shell is in `${{ box }}/bin` |
| `storage.<dir>` | A directory declared in `[storage] directories`; in a tool table, the tool's own storage directory of that name comes first |
| `inputs.<name>` | An input's resolved value |
| `root`, `root.parent`, repeated `.parent` | Folder of the real executable, or its ancestors. In a tool pack it refers to that tool; inside `[agent]` it refers to the agent program. No other step is supported. |
| `tool.<name>.root`, with `.parent` steps | The same executable folder for a named tool |
| `cache` | In a tool table, `${{ workspace }}/.cache/<tool>`; for an MCP launcher it is a separate cache in profile storage |
| `macos.developer_dir`, `macos.toolchain`, `macos.sdk_root` | Selected Apple developer directory, compiler directory, and SDK. Use only under `when = "macos"`. Discovery failure skips the tool that needs them. |

An agent's `root` requires `command` element 0 to be an absolute path or a program input, and
that element cannot itself use `root`. Other unknown placeholder names fail. `$HOME`, `${HOME}`,
and `{{ home }}` stay literal to Box CLI. Box Core separately expands only its telemetry
`${NAME}` variables in command arguments and refuses other `${NAME}` names there.

| Fields that support placeholders | Scope |
| --- | --- |
| `command`, `agent-args` elements | Agent, tool, or MCP command; profile arguments |
| `env` values | Agent, tool, MCP, or tool pack |
| Filesystem list entries | `read`, `write`, `read_file`, `write_file`, `list`, `metadata`, `exec`, `deny`, `deny_write`, and a profile's `[filesystem] deny` and `deny_write`; tool tables have no `metadata` or `exec` |
| `destinations` | Route or MCP server |
| backend `url` | Each `[[egress.<name>.backends]]` or `[[mcp.<name>.backends]]` row |
| backend `auth.aws.region` | The same rows, with an `aws://` `auth.ref` |
| `project`, `region`, `log_group`, `log_stream` | Each `[telemetry.<label>]` target of any kind; Box Core checks the expanded value. An input value in `project` that holds a control character fails, and so does one that starts or ends with white space, unless `[options]` sets it. |
| `destination` | Each `[telemetry.<label>]` target whose `kind` is not `file`; Box Core checks the expanded value |
| `when` | A boolean input condition |
| `default`, `search` paths | Input declaration |
| `source`, `keep` keys | Storage copy |
| `key`, `value` | Storage `set` row |
| `file`, `key` | MCP import row |

Storage targets and MCP `target-key` also support placeholders as described in their sections.
Other fields, including `packs`, `extend`, route and telemetry `secret` fields, a telemetry
target's `kind`, `include`, `accepts`, and `headers`, a `file` telemetry target's `destination`,
pack headers, and option values, are literal.

### Paths and filesystem entries

A filesystem entry is a path. So are copy sources, the program in a command, and command or
`agent-args` elements that start with a path placeholder. These rules apply:

- A path containing a placeholder starts with one: `${{ home }}/.config`, not `/Users/${{ home }}`.
- Every later placeholder fills one component, with no `/`, `.` or `..` value.
- The result is absolute and contains no `..` component.

Existing filesystem paths are resolved through links. A path through a link in the project or
run storage fails because the workload can change it. A missing required path can resolve but
Box Core refuses it when the run starts. Use an entry table for a path that is optional or
conditional:

```toml
[agent.filesystem]
read_file = [
    { path = "/opt/homebrew/etc/openssl@3/openssl.cnf", optional = true, when = "macos" },
]
```

The only entry keys are required `path`, optional `optional` (default `false`), and `when`.
An optional missing path or broken link is dropped.

### Conditions

`when` accepts `"macos"`, `"linux"`, a boolean input placeholder, or
`{ variable = "inputs.<name>", equals = "<value>" }`. There is no `not`. A placeholder condition
must resolve to `true` or `false`.

Conditions go on filesystem entries, nested tables such as a route or tool, or a single value
wrapped as `{ value = ..., when = ... }`. For example, both parts of a command flag must share
the condition:

```toml
[agent]
command = [
    "${{ inputs.team.program }}",
    { value = "--provider", when = { variable = "inputs.team.host", equals = "bedrock" } },
    { value = "bedrock", when = { variable = "inputs.team.host", equals = "bedrock" } },
]
```

This replaces the complete inherited command; retain its other required arguments in a real
edit. Element 0 has no `when`. A route's `secret` also has no `when`; condition the entire route.
A `when` on `[agent.env]` removes all merged variables when false, so condition individual
variables when only those should change. A pack's MCP grants accept conditions on filesystem
entries, not on the MCP table.

## Model providers and network access

Changing a model provider may require both a different provider pack or route and a different
agent option, such as `claude.host`. Read their declarations together. Box does not verify that
an agent/provider combination works; a profile can resolve yet send requests to an unrouted
host. Keep one intended provider and remove obsolete settings through their owning files.

Routes declare the destinations the box permits and, optionally, a credential that Box Core
adds to requests. A profile can override an existing route key or declare a route:

```toml
[egress.github]
destinations = ["api.github.com"]
secret.ref = "env://GITHUB_TOKEN"
```

| Credential setting | Meaning |
| --- | --- |
| `secret.ref` | `env://<NAME>` reads a host variable; `aws://<profile>` signs with an AWS profile; `aws://` with no profile signs with the host's default AWS credential chain. A reference in a scheme that a plugin or the profile declares is read by that source's program. Input/environment `from` uses `env:<NAME>` instead. |
| `secret.header` | Optional HTTP header, such as `x-api-key` |
| `secret.phantom_prefix` | Optional prefix for the stand-in value, such as `sk-ant-`, when the agent checks key format |

The agent receives a stand-in, and the box supplies the real credential on requests. Do not
also forward the credential in `env` or through an input. Give a credentialed route one
destination; Box Core does not attach credentials to a route with two hosts.
Credentialed destinations may specify a port or path; `*.example.com` matches subdomains.
Destinations are not URLs.

For public access, use a route with only `destinations` (and an optional route-level `when`):

```toml
[egress.docs]
destinations = ["docs.rs", "builds.example.com:8443"]
```

Public destinations are lowercase host names with an optional port: no URL scheme, path, or
wildcard. The default port is 443. A route accepts at most 100 destinations. Each listed host
is reachable by every program in the box. Changing `destinations` replaces the inherited list.
Box generates connect and HTTP permits for routes, so no additional policy rule is needed.

A login created inside the box stays in storage, readable by programs in the box.

An unexpected route key makes it a credentialed route and must pass that validation. A
conditional `secret` is refused because removing it could open unauthenticated access. Use two
separately conditioned routes if authentication differs between systems.

## Filesystem access and policy

`[project] access` sets how much of the project the agent, each tool, and each detected MCP
server reach: `"write"` (read, change, delete, move), `"read"` (read only), or `"none"`. A profile
without `[project]` gets no project access. It decides both the filesystem grants and the
generated `project_*` permits, so change the value, not the lists, to change project access. A
filesystem entry in a pack or the profile that names a folder in the project still applies on top. Keep
the value the operator chose; the policy starter set it at create.

A profile's top-level `[filesystem]` holds only `deny` and `deny_write`. `deny` lists paths that
no process reaches: `box` adds each to every process's `deny` and writes `filesystem_deny_*` forbids
for the Shell and Monty. `deny_write` lists folders that every process whose
write grants reach them keeps read-only, such as a `.venv` the agent runs from. `box` adds each
entry to the agent, each tool, and each MCP server, detected ones included, and drops it where no
write grant of that process reaches it. It also adds `deny_write_*` forbids for the Shell and
Monty. Prefer it over a per-process `deny_write`: a program in a write grant runs only when every
process that can write its folder protects the folder, and the error names the one that does not.

```toml
[agent.filesystem]
exec = ["${{ workspace }}/.venv"]

[filesystem]
deny_write = ["${{ workspace }}/.venv"]
```

Each entry names an existing folder, not a file. `{ path = "...", optional = true }` drops an entry
whose folder a project does not have, because one profile runs in many projects. In an agent or
tool pack, `[filesystem]` is that pack's own process, so a pack cannot set a list for every process.
Both lists win over every grant, a pack's included. A Shell or Monty denial names the rule and the
list, such as `[policy: filesystem_deny_read_0]: The profile's [filesystem] deny keeps this path
out of the box.`. A process's own refusal prints no rule, so check `[filesystem]` and that
process's `filesystem` table. To let one process reach a path, leave it out of `[filesystem]` and
put `deny` or `deny_write` on the other processes' tables.

Profile `policies` is an ordered list of files. Paths are literal, with no placeholders.
Relative paths start in the profile folder; absolute paths and symlink targets must also stay
inside that folder or its subdirectories. Hard-linked policy files fail. Only listed files
load. Preserve current rules: a copied policy is the operator's file, not a fresh copy of a
shipped starter.

Box appends generated rules after the listed policy text and expands no placeholders in that
text. A matching `forbid` wins over every `permit`, regardless of order. Give each authored rule
a unique `@id` across all listed files, and avoid generated IDs shown by `box profile show
--full`. That command checks the combined policy and reports duplicate IDs and rule errors.

Filesystem grants and shell policy are separate. To allow another directory, add the agent's
filesystem entries for its file tools and policy rules for shell file operations. For example,
merge these paths into the current lists and preserve all current policy entries:

```toml
policies = ["policy.dw", "shared-lib.dw"]

[agent.filesystem]
read = ["~/src/shared-lib"]
write = ["~/src/shared-lib"]
```

Create `shared-lib.dw` beside the profile:

```text
@id("shared_lib_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/src/shared-lib" || context.input.path like "~/src/shared-lib/*" };

@id("shared_lib_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/src/shared-lib" || context.input.path like "~/src/shared-lib/*" };
```

Here `~` means the operator's home. For read-only access omit both `write` and the write rule.
These rules do not add delete or move access. They do not extend a toolchain's filesystem
permissions; edit its own tool table if it needs the directory. Running from a common parent
instead grants the project access for that whole parent directory.

Box generates policy for the project (as `[project] access` allows), declared storage, discovered tools, routes, and MCP
servers. It also forbids writes to protected Box configuration and `~/.local/bin`, and additional permits cannot
override those forbids. The copied `policy.dw` holds the rules Box does not generate: the shell's
`shell_commands` permit and the `/dev/null` permit. Keep them unless the operator asks otherwise;
without `shell_commands` the shell runs no command. Box generates no cloud metadata block. A
`@box/open` copy forbids link-local addresses, which covers the common metadata address; any other
metadata `forbid` is the operator's to add. Box refuses write grants to trusted
locations such as `~/.strands/box` outside the agent's and tools' storage directories, the installation, or a directory containing a
program that later runs trust. Keep programs outside writable locations.

When investigating a runtime denial, use the action and resource in the run's `records.jsonl`:
`fs:*` may need the relevant filesystem grant and shell rule, network calls need a route, and
`shell:spawn` needs a tool declaration or authored spawn permit. Do not grant access merely to
remove a denial; match it to the requested task.

## Tools and program trust

To add a supported tool, import its installed pack in `packs`. Read its requirements and
inherited packs. To change that tool, merge additions into its table:

```toml
[tool.git.env]
GIT_AUTHOR_NAME = "Your Name"

[tool.git.filesystem]
read = ["${{ tool.git.root.parent }}/share/doc/git"]
```

A profile can also declare `[tool.<name>] program = "<executable>"`. `program` enables host
discovery, generated spawn permits, runtime grants, helper discovery, and private temporary
storage. A tool pack writes the same table at top level; its imported table name is the
last component of the pack name. Tool names use letters, digits, `_`, and `-`. In a tool pack,
`[run] command` is the pack's program input alone, and that input finds its program on `PATH`
only:

```toml
[inputs.git.path]
type = "program"
program = "git"
search = [{ env = "PATH" }]

[run]
command = ["${{ inputs.git.path }}"]
```

`search` may be left out, which is the same. Box refuses another `search` folder, a `default`,
any other string that names the input (in this pack or in a pack that extends it), another
declaration of the input, and a profile `[options]` value for it, because the agent's bare `git`
might not reach a file from another folder. A pack that extends a tool pack declares a program
input of its own, or uses `${{ tool.git.root }}`.

| Tool key | Effect |
| --- | --- |
| `program` | Find the named program on the host `PATH`; Box writes its `command` |
| `installation` | Select runtime layouts: `node`, `npm`, `python`, `homebrew`, or `directory`; matching layouts add runtime reads |
| `helpers` | Find other programs the tool starts, add their runtime read grants and folders to its `PATH`; missing helpers are dropped |
| `hosts` | Permit the whole box to reach package hosts on port 443; another port needs a route or authored permit |
| `upgrade_http` | Hosts from `hosts` whose plain `http://` request the gateway sends as `https://`, for a tool that cannot trust the box's certificate, such as rustup on macOS; it applies to the whole box, and only to a host that needs no login |
| `file-watching` | Let the tool watch files through macOS FSEvents, which also discloses names of files it cannot read; off when omitted; `[agent]` and stdio `[mcp.<name>]` take it too |
| `network` | `contain_egress = false` lets the tool and the programs it starts connect directly, outside the gateway and policy, with no gateway credential; for a client the gateway cannot carry; the key alone does not enable SSH for `@box/git`, which still rewrites GitHub SSH remotes to HTTPS and grants no `ssh`, and Box Core refuses any grant in `~/.ssh`; a condition goes on the value, `contain_egress = { value = false, when = "..." }`, not on the table; never on a general client or an interpreter; only a profile writes it, as `[tool.<name>.network]`, and every pack that holds `[network]` or `[tool.<name>.network]` is refused |
| `storage` | The tool's own storage: `directories` at `<storage>/tool/<tool>/<dir>`, shared by every workspace of the profile, with no grant or permit for the agent; the tool reaches each one through its own `read` and `write` entries. `[[storage.files]]` rows here take `source` (a host path), `target` (a tool directory and names below it), and `mode`. Each row must name its `mode`. `"copy"` copies the source into the tool's storage and takes every key of an agent copy row. `"link"` makes one read-only link to the source. `"link-children"` makes a real folder with one read-only link for each entry inside the source folder, and if the source is a file the box does not start. Each run links the source in, points a moved link at the new source, and removes a link whose source is gone. A source in the workspace, storage, `~/.strands/box`, or a write grant is refused. Two rows of one tool cannot have equal or nested targets, a copy and a link included |
| `native-filesystem-policy` | In a profile's `[tool.<name>]` only, override the global [experimental native filesystem policy selection](#experimental-native-filesystem-policy) for this tool |
| `env`, `filesystem`, `when` | Configure the tool's own environment, file access, and condition |

List each layout that can hold the program, such as `installation = ["node", "homebrew"]`.
A layout adds nothing when it does not match. An omitted or empty list selects no layout for
the tool's own program. A custom tool pack can still declare runtime paths in `[filesystem]`.

A tool pack cannot declare `workspace`, `[agent]`, `[tool]`, `[egress]`,
`[mcp]`, or `[telemetry]`. Its `[storage]` is the tool's own (see `storage` above).
Put cross-tool settings in the profile or an ordinary pack.
No pack can declare `[experimental-features]`; write that table in `profile.toml`.
In an ordinary pack's explicit tool table, use `tool.<name>.root` rather than bare `root`.

Program inputs and tools cannot run a program planted in the project, storage, `~/.strands/box`, or
another directory the workload can write. These checks follow links. An explicitly supplied
program path must be absolute and executable; Box does not silently replace an invalid override
with another copy. Program-input discovery tries eligible copies in search order, but an agent
program cannot be a Node.js script. A missing tool is skipped and reported.

For a discovered tool, Box uses the real executable path, grants project read/write access,
and drops nonexistent granted paths. A `*` can match installed path components. `deny` paths
have no wildcard and remain as written: they may be absent on macOS, but must exist on Linux.
Each tool starts with `PATH = "/usr/bin:/bin"` and a private run-specific `TMPDIR`; explicit
settings override them.

A script tool's `#!` interpreter must be another available tool table. For example, npm needs
node. It inherits that interpreter's executable, `read`, `read_file`, `list`, and `deny` grants, with
the interpreter folder first on `PATH`. It does not inherit that tool's `env` or `hosts`.
Helpers and interpreters get runtime reads from every matching installation layout.
MCP servers reuse supported launcher packs automatically and keep separate caches in storage;
adding the same launcher to `packs` is only needed when the agent itself runs it as a tool.

For an explicit `command` tool, Box does not generate the spawn permit. Supply both the table
and a rule in a listed policy file, using the program's real path:

```toml
[tool.jq]
command = ["/usr/bin/jq"]

[tool.jq.filesystem]
read = ["${{ workspace }}"]
```

```text
@id("spawn_my_jq")
permit (principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program_path == "/usr/bin/jq" };
```

## Stored files and settings

`[storage] directories` declares single-component names, such as `directories = ["config"]`.
Each lives under `~/.strands/box/storage/<profile>/default/agent/` and is shared by all projects and runs of
that profile. `${{ storage.config }}` names the example directory. Box creates it, rejects a
symlink in its place, and supplies agent read/write grants and policy automatically.

Read the existing copy and its source before changing a `[[storage.files]]` row. Changing the
host source alone does not update an existing ordinary copy.

| Copy key | Meaning |
| --- | --- |
| `source` | Host file or folder, with the path rules above |
| `target` | Declared storage directory followed by a relative path, such as `config/skills`; a placeholder below the directory may fill one component, such as `config/projects/${{ workspace.dashed }}/memory` |
| `optional` | Skip a missing source, or an unsafe directory prefix read from an environment input, instead of failing |
| `when` | Apply the row only when its condition holds |
| `kind` | `json` or `toml` when selecting or rewriting structured values |
| `keep` | Array of key paths to retain, such as `[["theme"], ["spinnerVerbs", "mode"]]`; requires `kind` |
| `sync` | Copy changed host files on every run; cannot combine with `kind`, `keep`, `set`, or `fill` |
| `fill` | Add missing selected values on every run; requires `keep` and `kind = "json"` or `"toml"`, and cannot have `set` |

Active rows cannot have equal or nested targets. A profile row does not replace an inherited
row. Disable the pack's copy through its controlling input before adding your own for that
target. For example, `claude.import-settings = false` disables the shipped Claude settings copy.

Copy sources cannot be in the project, `~/.strands/box`, or locations writable by the workload. A folder's links
are followed only when their targets pass the same checks; unreadable entries are omitted and
reported. Box does not inspect files for credentials. Copy selected safe keys from mixed
settings files rather than copying credential files or entire credential-bearing folders.

| Update mode | Effect on an existing copy |
| --- | --- |
| Ordinary copy, including `keep` | Copy only when the target is absent. Host edits do not propagate; remove the copy to take a new one. |
| `mode = "link"` | Only in a tool's own storage. No copy: one read-only link to the host path, which each run brings up to date. |
| `mode = "link-children"` | Only in a tool's own storage. No copy: a real folder with one read-only link for each entry inside the host folder. Each run adds links for new entries and removes links whose entry is gone. |
| `mode = "copy"` | The default in an agent row. A tool row must write it. A tool row's copy is in the tool's own storage, and the agent cannot reach it. A link mode on an agent row is refused. |
| `sync = true` | A host file changed since the last copy replaces its stored copy, including any agent edit to that file. Unchanged host files preserve agent edits. Agent-only files and files deleted on the host remain. Avoid this for agent-maintained memory. |
| `fill = true` | Add each `keep` value only if absent; preserve existing values. A target that is a symlink, hard link, or non-file is left unchanged with a reason. |
| `[[storage.files.set]]` | Rewrite each named value before every run, preserving the rest. Concurrent runs share the file, so the last run's values win. A row with a `when` that does not hold writes nothing and leaves the stored value. |
| `[[storage.hooks]]` | Replace the hooks of the copy before every run with the hooks of `source` that each run one shell script, or remove them when the row's `when` is false. `kind = "json"` is the file format. `key` is the key path to each hook, with `"*"` for each key or item, and the row owns the value at its first key. `keep-above` names the keys an object above a hook keeps. `only = { key, equals }` selects the hooks that run a command. `command` and `args` name where a hook holds them. `keep` and `drop` name the other fields a hook can hold, and a `drop` entry of `{ key, equals }` accepts only that one value. `[[storage.hooks.set]]` rows give each imported hook its fields, with `${{ script }}` once for the script's real path. `disable-key` names the host's off switch, which the copy gets too. Each script gets one generated `fs:read` permit and no file grant. Agent edits to the hooks do not survive a run. |

For example, after disabling an inherited copy to this target, select only the wanted keys:

```toml
[[storage.files]]
source = "${{ home }}/.claude/settings.json"
target = "config/settings.json"
kind = "json"
optional = true
keep = [["theme"], ["outputStyle"]]
```

A `keep` path selects one value at each named nesting level. Unlisted keys stay out. Selection
runs at the initial copy; TOML comments are lost. Use `fill = true` when missing selected JSON or
TOML values should enter an existing file on every run. A fill may share an MCP import target only
with the same format and when its `keep` paths do not overlap that import's `target-key`.

For a setting that must be restored each run, add `set` under its copy row:

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

`key` is a nested key path and may contain placeholders. `value` may be a string, number,
boolean, or list of those; a list replaces the complete stored list. A `when` on the row writes
the value only when it holds. A set fails if the source
is a folder, the stored file is invalid for its `kind`, a target or parent is a symlink, the
selected key holds a table, or a parent key holds a non-table. Fix the stored file or take a
fresh copy rather than changing unrelated keys.

## MCP servers

The shipped Claude and Codex packs leave host MCP import off by default. Set
`claude.import-mcp = true` or `codex.import-mcp = true` in `[options]` to enable it. This permits
the supported host servers found now and on later runs, including each project's local scope.
Other host entries remain in the import without generated policy. Read the input's warning
before changing it.

Read the pack's `[[mcp-servers]]` rows and the host configuration they name. These rows discover
servers; they belong in packs, not profiles. Host files in the project, `~/.strands/box`, or a writable
folder are refused. A missing source or key yields no servers.

For an existing discovered server, omit `type` to add grants or settings while retaining its
imported agent configuration:

```toml
[mcp.fetch.filesystem]
read = ["${{ home }}/notes"]
```

A pack can add only `filesystem` and `network`; a profile can add other server settings. If the
server is absent, an extension is omitted and reported. A profile table with `type` replaces the
discovered declaration. The host entry remains in the agent configuration import; the profile
table supplies its permissions and Box configuration. If the host has no entry, supply the
agent-side configuration separately. When the table changes the executable filename or
arguments, update the host entry to match and [refresh the saved configuration](#refresh-saved-mcp-configuration).

A remote server extension's `destinations` joins its original host. If it has a credential,
every added destination receives that credential too. Hosts already owned by another server or
route fail. Repeating an already-covered host and port adds nothing; another port adds access.
A wildcard that overlaps the server's own host and port skips the server. This comparison
ignores paths; an omitted port overlaps both 80 and 443.

Detected local servers may read their installation files, interpreter dependencies, and the
project, and write the project.
They receive their configured environment, including credentials; the agent does not read that
environment directly. Additional API access needs a route. Arguments supplied later may select
any file the server can reach, so grant only the required directories. When extending a
discovered server, fixed file arguments must also be outside locations writable by any boxed
process. The check covers links, project-relative paths, and `--key=path` arguments.

Box generates MCP call, spawn, and network permits for supported servers. A local command is an
installed program name on `PATH` or an absolute executable path. An absolute path selects that
file without a `PATH` fallback. The program and its executable links must be outside folders the
box can write. Relative and `~` paths, shell commands, unsupported runtime scripts or launchers,
and programs inside credential directories get no generated policy. Box reports the reason and
keeps the host entry in the import. Supported launchers get files from the selected installation,
runtime helpers, registry access, and separate storage caches. To use a
private npm registry, grant only the server read access to the required `.npmrc`, set its
`npm_config_userconfig` if its `HOME` differs, and add a registry route with only `destinations`.
npm supplies the credential from `.npmrc`; the agent receives no file grant from this addition.

Remote servers use HTTP or HTTPS; injecting a credential from a variable requires HTTPS.
Variables in URL hosts and paths are unsupported. Literal keys
in imported headers remain readable by the agent. Variable-backed credentials use stand-ins;
when an unset variable has a literal fallback, that fallback remains readable. An empty or
whitespace-only variable prevents policy generation instead of selecting its fallback.

### Import fields and variable handling

Change these only when the host's MCP configuration format or saved destination must change:

| `[[mcp-servers]]` key | Meaning |
| --- | --- |
| `file`, `kind`, `key` | Host path, required `json` or `toml` format, and nested key path to the server table. `file` and `key` may contain placeholders. |
| `when` | Disable discovery for this row when false; leave any saved configuration unchanged |
| `target`, `target-key` | Optional storage file and required destination key. The key may be a string or nested key list with placeholders. With no target, servers are declared but no agent configuration is written. |
| `env-var-locations` | Map agent setting names to one of the roles below |
| `env-var-syntax` | Variable syntax containing `NAME`, such as `${NAME}`, or a list of forms, such as `["${NAME}", "$NAME"]`; required by reference roles. A form with no closing text, such as `$NAME`, takes no `:-default`, and a server that writes `$$`, or `$` before the `command-prefix`, is skipped. It also enables references in URL query values. |
| `command-prefix` | Text that starts a value the agent runs as a command, such as `!`; a server with one is skipped. Needs `env-var-syntax`. |

| Variable role | Setting contents |
| --- | --- |
| `bearer-variable` | Name of the variable holding a remote token |
| `header-variables` | Headers mapped to variable names |
| `header-references` | Headers ending in one variable reference, optionally with a literal prefix or fallback |
| `references` | Variable references in `command`, `args`, or `env` only |
| `variable-names` | Forwarded variable names, as strings or `{ name = "TOKEN", source = "local" }` objects; `source` is optional |

The first three roles apply to remote servers; the last two apply to local servers. When Box
declares a server, referenced `command` and `env` values expand from the host shell. Without that
role they stay literal.
An `args` element containing a variable marker becomes a wildcard for the whole argument,
even when the marker is embedded, such as `--level=${LEVEL:-info}`. The box accepts the value
the agent supplies, including literal reference text. Other arguments remain fixed. Mixing
variable arguments with a literal `*` argument prevents policy generation because both cannot be
represented together.

Host entries enter the saved configuration even when they receive no generated policy.
A local entry declared from host settings uses the executable's filename as its program alias,
including the authored filename of a symlink. Box keeps the full absolute path in its server
configuration. Arguments retain variable references. When a final stdio declaration matches a
local entry's executable filename and arguments, the entry gets the bare filename and omits `env`
and variable-name forwarding fields, whatever directory its command named. It also omits them when its `env`, as written, holds the
operator's value of a variable that a secret source's `pass-secret-env` entry covers, a prefix entry
such as `OP_SESSION_*` included, or when its `env` sets such a variable. An entry whose argument, as written, holds such a value loses its `args`, even when a final stdio declaration matches it, and its server is left out. A matching server name
or partial wildcard overlap is insufficient. Other entries retain their environment fields
without host variable expansion, so literal keys in those fields remain visible to the agent, and
the skip line says so when a profile table with `type` replaces the entry. A saved import keeps the
fields it was written with until the operator refreshes it.
Remote entries retain plain headers and variable references. Import copies no other host settings
and grants no permissions.

Local command collisions compare the executable's filename and arguments. Different installation
paths alone do not distinguish two servers. An omitted duplicate declaration leaves its imported
entry in place, and calls routed to a declared server use that server's permissions and environment.
An exact command takes precedence when a call also matches a wildcard command.

### Refresh saved MCP configuration

The host configuration is read on every run to decide permissions. Editing the saved agent
configuration does not change those permissions. A host edit can therefore leave a saved
server entry unusable until the saved configuration is refreshed.

An import writes only when its destination key is absent. An existing empty top-level section
still blocks import; an empty nested section is filled. No host entries means no write.
Invalid JSON or TOML fails without changing the file. Symlinks, hard links, or non-file targets
are left unchanged; symlink parents are refused. Rows sharing a target must use the same format.
They can name the same section or separate sections, but one section cannot be inside the other.
A normal storage copy cannot overlap that target; only a non-overlapping `fill` row may share it.

To refresh after changing host servers:

1. Stop runs of the profile. Use `box profile show <name>` to check the server declarations and
   find the storage folder.
2. Back up the saved file named by the pack's `target`.
3. Remove the complete section named by `target-key`, preserving other settings and valid
   JSON or TOML. Remove a top-level section entirely, not just its entries.
4. Start the profile with its MCP import option enabled, such as `claude.import-mcp = true`
   or `codex.import-mcp = true`.

The next run imports host servers into the missing section and replaces edits previously
made in that section. The shipped Claude target is `config/.claude.json` with `mcpServers`;
Codex uses `home/config.toml` with `mcp_servers`. For a pack with a project-specific target key,
remove that exact nested section instead. Read the current pack rather than assuming a key.
