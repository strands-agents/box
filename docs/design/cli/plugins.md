# Plugins

A plugin declares a secret source: a host program that reads a secret for each reference in its
scheme. Box Core runs it outside every sandbox, with the operator's rights. A pack holds data,
and each program that a pack names runs in the box. So a plugin is its own kind of file, and only
the profile lists one ([decisions.md](decisions.md#only-a-profile-lists-a-plugin)). The profile
names each reference, and the agent holds a placeholder for it:

```toml
plugins = ["@box/1password"]

[egress.github]
destinations = ["api.github.com"]
secret.ref = "op://Personal/GitHub/token"
secret.env = "GH_TOKEN"
```

The operator guides are [plugins.md](../../cli/plugins.md), for using and writing a plugin, and the [plugin reference](../../cli/plugins-reference.md), for each key and rule.

## Lookup

`@box/<name>` is `resources/plugins/<name>/plugin.toml` (or `$BOX_RESOURCES/plugins/<name>/plugin.toml`).
A plain name is `~/.strands/box/plugins/<name>/plugin.toml`. `Lookup::plugin_folder` takes the `plugins`
folder beside the pack folder of each root. A name follows the pack name rules, and holds no
placeholder. A name that `plugins` lists twice loads once.

## The file

```toml
[plugin]
name    = "1password"
version = 1
kind    = "secret-source"
scheme  = "op"

[inputs.onepassword.path]
type    = "program"
program = "op"

[run]
command = ["${{ inputs.onepassword.path }}", "read", "op://{ref}"]

[env]
OP_ACCOUNT               = { from = "env:OP_ACCOUNT" }
OP_CONNECT_HOST          = { from = "env:OP_CONNECT_HOST" }
OP_SERVICE_ACCOUNT_TOKEN = { from = "env:OP_SERVICE_ACCOUNT_TOKEN" }
OP_CONNECT_TOKEN         = { from = "env:OP_CONNECT_TOKEN" }

[protect]
env   = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"]
paths = ["${{ home }}/.config/op"]
```

A plugin runs one program, as an agent pack and a tool pack do, so it names that program's
`[run]` and `[env]`
([decisions.md](decisions.md#a-profile-uses-box-core-table-names)). The program runs on the host,
so each of the two takes less than a pack's, and `from = "env:<NAME>"` has its form from an `env`
value of a pack. `[protect]` is not the program's: it names what the box keeps from the agent,
each tool, and each MCP server. So a plugin holds no `[filesystem]`, which in a pack grants a
path. `plugin::load` checks the file when the
profile loads (`plugin::check`). `box` checks the shape that the translation needs: the keys of
each table, the type of each value, and the rules that are its own, such as the program input.
Box Core checks what a source may hold, such as the form of a scheme, the `{ref}`, and the form
of a path, when the box starts, as it does for a source of the profile, because `box` keeps no
copy of a Box Core rule ([decisions.md](decisions.md#box-runs-a-pinned-box-core-release)):

- `[plugin]` comes first. It holds the keys of `[pack]`: `name`, `version`, `kind`, and the
  optional `engine`, and `scheme`. Each shared key means what it means in `[pack]`, and
  `lang::check_header` checks both headers. `kind = "secret-source"` is the one kind. `scheme` is a
  string that is not empty.
- The file holds `[plugin]`, `[inputs]`, `[run]`, `[env]`, and `[protect]`. A
  `[secret-source.<scheme>]` table in a plugin stops the load, and the message names the keys of
  a plugin. A `[filesystem]` table stops the load too, and the message names `[protect] paths`.
- `[inputs]` declares inputs as a pack does, and the profile sets them in `[options]`. `[run]
  command`, and each placeholder in `[inputs]`, such as a `search` folder or a `default`, reads
  only the inputs of its own plugin and no program folder (`root` or `tool.<name>.root`), so no
  pack's input chooses the program.
- `[run]` holds `command` and `output`, and `kind` decides that, as `[pack] kind` decides the keys
  of a pack's `[run]`. `command` is a list of strings, so no element takes a `when`, and
  `output` is a string. Element 0 of `command` is exactly
  `${{ inputs.<name> }}`, for an input of the plugin with `type = "program"`. The
  [program search](profile-language.md#program-search) finds it, the checks of a `program` value
  apply to it, and `box` writes its real path. Each later element is a template field with the
  [bounds](profile-language.md#bounds) of a `command`. `{ref}` is literal text, which Box Core
  fills in.
- `[env]` names each host variable that the program gets. An entry is `{ from = "env:<NAME>" }`
  for the entry's own name, and nothing else: Box Core passes a
  variable under its own name, so a rename, a value, a `default`, and a `when` stop the load. A
  name is letters, digits, and `_`, and does not start with a digit, as in every `from`, so a
  plugin names no prefix with `*`.
- `[protect]` holds `env` and `paths`, lists of strings. Each name in `env` is a key of the
  plugin's `[env]`, because `pass-secret-env` both passes a variable to the program and keeps it
  back. An entry
  of `paths` holds no placeholder
  other than a leading `${{ home }}`, which `box` writes as `~`, the name of the home in Box
  Core's table. An entry is not a grant, so it takes no entry table, and no `when` or `optional`,
  and a `*` in it is literal text that no step of `box` matches against a folder.

`plugin::translated` then builds the layer that the merge reads. It removes `[run]`, `[env]`, and
`[protect]`, and writes one `[secret-source.<scheme>]` table in Box Core's form:

| Plugin file | `[secret-source.<scheme>]` |
| --- | --- |
| `[plugin] scheme` | The name of the table. |
| `[run] command`, `[run] output` | `command`, `output`. |
| An `[env]` entry | `pass-env`. |
| An `[env]` entry that `[protect] env` names | `pass-secret-env`. |
| `[protect] paths` | `deny`, with `~` for `${{ home }}`. |
| Nothing | `protocol = "box.secret-source.v1"`. |

Each pass list keeps the order of `[env]` in the file. The
layer keeps no `run`, `env`, or `protect`, so
no step after the load can read a plugin's variable or path as the agent's. Each later step reads
the translated table: the merge, `plugin::declared`, the resolver, `reference::Credentials`, and
`compile`. So a plugin and a source of the profile pass the same checks.

A message about a plugin's source names the plugin, such as "the plugin @box/1password", and a
key of the plugin's file, such as `` `run.command.0` of the plugin @box/1password ``
(`plugin::shown`, `plugin::source_name`, `plugin::command_name`). A message about a source of the
profile names its table, `[secret-source.<scheme>]`. A message that Box Core writes names the
table and the keys of `box.toml`.

A source of the profile is a `[secret-source.<scheme>]` table in Box Core's form, as each table
of a profile is. `plugin::check_sources` checks it, and these checks cover both kinds of source:

- `compile::refuse_reach` checks element 0 of each source's `command` against the write grants
  of the run, as it checks a tool's `command`. It checks each later element that is a full path,
  `~`, or a path under `~`, and such a path after the `=` of a `<flag>=<path>` element, whether
  or not something is there: a folder, or a file that is absent, under a write grant is one that
  the box can fill before a later run. It also refuses such a path that holds a write grant. It
  reads each element as written, so a path that `{ref}` completes when Box Core runs the program
  is not checked. For
  a tool or an MCP server, it checks a later element only when it is an existing file, because
  that program runs in its sandbox. It checks each `#!` interpreter that element 0 starts as it
  checks a later element, a program
  that `#!/usr/bin/env` finds on Box Core's fixed `PATH` of `/usr/bin:/bin` included
  (`compile::source_interpreters`). A `#!` line that box cannot follow to a full path, such as
  a relative path, an `env` line other than `env <program>` or `env -S <program>` with the
  program's own arguments after it, or a program that `env` does not find on `/usr/bin:/bin`,
  stops the load, and so does a chain of more than 8 `#!` lines. A `deny_write` of the writer does not exempt any of them,
  because the program runs outside every sandbox (`Error::SourceProgramUnderWrite`). Each of them
  that lies in the workspace, the run's storage, or a box home, as written or real, stops the
  compile too, whatever the project access, as a `program` value does (`compile::writable_root`).
  An element under `~` is read under the home for this check too.
  `mcp::check_links` then refuses each of them that reaches its file through a
  link in a write grant, as for an `[mcp.<name>]` command.
- A source takes no `when`, at any depth. So the declared schemes are the same on every host and
  for every input value.
- Every key of a profile's table other than `command` is literal and reaches `box.toml` as
  written. Box Core checks those keys.

## Plugins that `box` ships

Each plugin is a folder in [`resources/plugins/`](../../../resources/plugins/) with a
`plugin.toml` and a `README.md`, and the [user guide](../../cli/README.md#plugins) lists them. Each
declares one source, as the [file](#the-file) describes:

- [`@box/1password`](../../../resources/plugins/1password/plugin.toml): `op://` references, which
  `op read` reads as text. It protects `op`'s two settings folders and, on macOS, the 1Password
  app's group container, which holds its settings and its sockets.
- [`@box/aws-secrets-manager`](../../../resources/plugins/aws-secrets-manager/plugin.toml):
  `aws-secretsmanager://` references, which `aws secretsmanager get-secret-value` reads as one
  JSON string. It passes the variables of each identity that a bare `aws://` route can use.

## Who declares and who refers

| Rule | Check |
| --- | --- |
| Only the profile lists a plugin, in `plugins`. | `lang::visit` refuses a plugin name in `packs`, `extend`, or `include` (`plugin::named_as_pack`), and names the list, and `plugin::load` refuses a pack name in `plugins`. `check_kind` refuses `plugins` in a pack, and `pack_layout` refuses a `pack.toml` that starts with `[plugin]`. |
| Only a plugin or the profile declares a secret source. | `check_kind` refuses a `[secret-source.<scheme>]` table in a pack of each kind, before a tool pack becomes its tool table. |
| One scheme has one declaration. | `plugin::declared` refuses two plugins, or a plugin and the profile, that declare one scheme, and names both. |
| Only a plugin declares its inputs, and an input belongs to one plugin. | `plugin::refuse_foreign_inputs` refuses a pack, or a later plugin in `plugins`, that declares an input that a plugin declares, and names both. Otherwise its `from` would choose the program, because `from` comes before a `search` ([The value](profile-language.md#the-value)). `plugin::check` also refuses a placeholder in the plugin's `[inputs]` that names an input the plugin does not declare, so a pack's input cannot reach a `search` folder or a `default`. A pack can read a plugin's input. |
| A profile file that runs by its path declares no source, lists no plugin that reads `${{ profile }}`, and sets no program input of a plugin and no input that the plugin lists no `values` for. | `plugin::refuse_path_profile_programs` refuses a `[secret-source.<scheme>]` in the file's own table, and an `[options]` value for an input that a listed plugin declares with `type = "program"`, or that is not a `bool` and has no `values`. A `pattern` limits the form of a value, not what it names: a folder that the program input's `default` or `search` reads, or an argument in `command`, such as a server address. So the check reads the declaration and walks no placeholder. `compile_run` calls it after the layers load and before the merge, when `Launcher::locate` read the profile by its path (`Loaded::by_path`), so `box run`, `box profile show`, and a policy reload refuse it the same way. The file can list a plugin, set the plugin's `bool` inputs and its inputs with `values`, and name a reference in a declared scheme. It also refuses a listed plugin whose `[inputs]` or `[run] command` reads `profile` or `profile.file`, because in such a file they name that file and its folder. A named profile keeps its checks: there the folder lies in `~/.strands/box`, where the program checks refuse a program and each file of a source. |
| A source of the profile reads no input. | `plugin::check_sources` refuses an `inputs.*` placeholder in a `[secret-source.<scheme>]` of the profile. A profile declares no input, so each one comes from a pack or a plugin, which would then choose what the source runs. A built-in name, such as `${{ home }}`, is allowed, but not `root`, `tool.<name>.root`, or their parents, in a plugin's `[run] command` either, because a pack's input finds that program. |
| Only the profile names a reference in a declared scheme. | `plugin::refuse_pack_references` refuses a reference in a declared scheme in a pack. It reads the `secret` (a string, or a table's `ref`) of each `[egress.<name>]`, `[mcp.<name>]`, and `[telemetry.<name>]`, and the `auth` of each route's `backends`. It reads the scheme after the white space at each end, as Box Core reads a telemetry reference. The refusal names the pack and the key. Box Core decides a reference in a scheme that nothing declares. |

## What reaches Box Core

The merge puts each plugin after the packs and before the profile. Each `[secret-source.<scheme>]`,
translated from a plugin or written in the profile, reaches `box.toml` through
`Resolved::secret_source`. A plugin's `[protect] paths` reach Box Core in `deny`, and a plugin's
table holds no `reads`: Box Core gives the two lists one effect (no grant can reach a path in
either, and each sandbox denies it), and `deny` states that effect and no more, where `reads` also
states that the program reads the path. A source of the profile can hold both lists.
A route's `secret.env` reaches `box.toml`
as written. `compile` writes `[experimental-features] secret-sources = true` when `box.toml` holds
a `[secret-source.<scheme>]` table, from a plugin or the profile, or a `secret.env` key on an
egress route or an MCP server (`compile::names_secret_env`). Box Core reads both only with that
switch, and a profile cannot set it: its `[experimental-features]` takes only
`native-filesystem-policy`. `reference::Credentials` holds the host
variables that no input and no `env` entry copies into the box
([decisions.md](decisions.md#an-env-reference-cannot-read-a-credential)): each variable that an
`env://` reference reads, or the `secret://` alias of a telemetry reference, or a `secret.env`
names, and each `pass-secret-env` entry of a source, which is each `[env]` entry of a plugin that
its `[protect] env` names. An
entry of a profile's own source that ends with `*`, such as `OP_SESSION_*`, holds each variable
with that prefix. The refusal
names the plugin, or the table of the profile, that declares the source. A `pass-env` name is a
plain setting.

`Layer::plugin` keeps a plugin out of the packs that telemetry hashes.

## What stays on the host

`box` acts before Box Core starts, so Box Core's checks of a source's paths and variables cannot
see what `box` itself copies or writes. `reference::Credentials` holds each `pass-secret-env`
entry and each `reads` and `deny` path of each declared source, with the plugin or the profile
that declares it:

- MCP detection skips a server that reads a `pass-secret-env` variable, a prefix entry included,
  whose `env` sets such a variable, or whose `env` holds the operator's value of a variable that
  an entry covers, a prefix entry included: `Sources::env_with_prefix` lists the variables that
  start with a prefix ([profiles.md](profiles.md#mcp-servers)). Box Core does not look for these
  values in `box.toml`, so this is the only check. It also skips a stdio server whose
  `command`, `env`, or `variable-names` field reads a variable that a `secret.env` names for a key
  from a source, because the host's value of that variable is not the key. In `args`, such a
  variable stays for the harness, which passes the stand-in.
- `Credentials::protected` adds each `reads` and `deny` path, with `~` read as the home, to
  `storage_files::Refusals`. A copy row, a tool's link row, or a link that a copy follows, whose
  source is, holds, or lies in one of them, as written or real, is refused ([Copies](profile-language.md#copies)).
  A starter's file place that meets one is skipped
  ([detection.md](detection.md#what-detection-never-reads)), and so is an `[[mcp-servers]]` file
  ([profiles.md](profiles.md#mcp-servers)). So is a detected stdio server whose program, real file,
  `#!` interpreter, runtime directory, or installation path meets one, and a server's CA file there
  is dropped, because Box Core refuses a grant that reaches such a path and would stop the run.

## Reports

`box profile show` prints a `plugins` line after `packs`, from `plugin::versions`. It then prints
one `source` line for each declared source, from `plugin::sources`: the scheme, `command[0]` as it
reaches `box.toml`, and the plugin, or `your profile`. `Preview::overview` holds these lines.
`Preview::json` gives them as the `plugins` and `sources` lists, with `null` for the plugin of a
profile's own source.
`Launcher::preview` builds the preview, then runs Box Core's policy check on it.

The `box profile create` report reads the same declarations. `Credential::from_reference` returns
`Credential::Source` for a reference in a declared scheme. The "Next" and "Before running" steps
then say that the box reads the key at startup with the program of that plugin, or of the
profile's own source, and they name no variable
([decisions.md](decisions.md#box-knows-no-provider)). When the host lacks a source's program, the
resolve stops with `Error::NotOnHost`, whose reason starts with the key path, such as
`secret-source.op.command.0`. The report then names that program and its plugin, such as
`op (@box/1password)`, and not the agent. Box Core prints each declared source and its program at
startup.

## Safety rules

The plugin rows of the [safety rules](profile-language.md#safety-rules).

| Risk | Rule |
| --- | --- |
| A pack chooses which secret the box reads | A pack declares no secret source, and writes no reference in a scheme that a plugin or the profile declares ([decisions.md](decisions.md#only-a-profile-lists-a-plugin)). |
| A box plants a program for a later run | The `command` of a source, from a plugin or the profile, element 0, each `#!` interpreter that it starts, and each full path or path under `~` in it, such as the path of `-config=<path>`, is checked against each write grant, as written and through its links, whether or not something is there. So a source's program under a write grant stops the compile, whatever the `deny_write` lists say, and so does a folder in its `command` that lies under a write grant or holds one. Each of them in the workspace, the run's storage, or `~/.strands/box`, as written or real, stops the compile too, whatever the project access. A source's program in the project of another run is not checked: a box there can change it before this profile runs in another folder, and `limitations.md` says so. |
