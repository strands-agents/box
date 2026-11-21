# Profiles

A profile is a named, reusable description of how `box` runs one coding agent in a box.
`box run <profile>` resolves the profile against the host and the current directory, compiles it
into one engine config for one run, and starts Box Core with it. Box Core never reads a profile.

Audience: developers of `box` or Box Core, and anyone who wants to know what `box run claude` does
and what reaches Box Core. The language that profiles and packs are written in is
[profile-language.md](profile-language.md). The reason for each choice is an entry in
[decisions.md](decisions.md). The operator guides are in [docs/cli/](../../cli/).

## The short version

```sh
box profile create claude --with bedrock --option bedrock.region=us-east-1  # once: write ~/.strands/box/profiles/claude/
cd ~/src/my-app
box run claude -- --continue                                                # each time: a new box for this directory
box run claude --box-id b-5b8e3d70c92f14ab                             # or: the box of an earlier run again
```

`box run claude` reads the profile and every pack it uses, fills in each placeholder for this host
and directory, writes one `box.toml` and one `policy.dw` into a new run directory, and
calls Box Core:

```text
strands_box::run(config, args, options)
```

Box Core appends `--continue` to the agent's command.

## The box home

The box home is `~/.strands/box`, or the folder that `BOX_HOME` names. `Host::box_home` holds it.
The paths below start there, except [installation metadata](telemetry.md#installation-identity),
which stays in `~/.strands/box`. `HOME` stays the operator home, so packs still read host files such
as `~/.claude` from it. A run protects both the box home and `~/.strands/box`
([why](decisions.md#a-run-cannot-write-what-a-later-run-trusts)).

```text
~/.strands/box/
|-- config.toml              the operator's settings for box
|-- installation.toml        installation metadata
|-- profiles/
|   `-- claude/
|       |-- profile.toml     packs = ["@box/claude", "@box/bedrock"]
|       |                    policies = ["service.dw"]
|       `-- service.dw       authored policy
|-- packs/                   packs the operator adds; `packs` and `extend` name one as <name>
|   `-- <name>/
|       `-- pack.toml
|-- storage/
|   `-- claude/
|       `-- default/                    the one namespace of the profile's storage
|           |-- agent/                  [storage] directories, one set for each profile
|           |   |-- config/
|           |   |   |-- CLAUDE.md       [[storage.files]], copied on the first run, then synced
|           |   |   |-- skills/
|           |   |   `-- projects/<dashed path>/   the agent's sessions and memory for one project
|           |   `-- tmp/
|           `-- copies.json             what box last copied, for sync rows
`-- r/
    `-- b-5b8e3d70c92f14ab/
        |-- box.toml         written by box run
        |-- policy.dw        written by box run
        |-- profile-name     written by box run: the full profile name
        |-- records.jsonl    written by Box Core
        `-- box/             box_dir: Box Core's state for this run
```

[Where box keeps its files](../../cli/files.md#custom-packs-starters-and-policies) names the
tables of `~/.strands/box/config.toml`, and [The starters list](starters.md#the-starters-list) says how `box` reads
them. `base` is not a profile name. The packs that `box` ships, `@box/<name>`, are in
`resources/packs/<name>/pack.toml` beside the `box` binary (or
`$BOX_RESOURCES/packs/<name>/pack.toml`).

The release ships `resources/editing-box-profile.md`, a standalone guide with editing rules and
examples for use without the source checkout. It is beside the shipped packs, so `box` finds it
as it finds them. Its links stay within the file. Maintain this file when the profile language
or editing workflow changes. The repository authoring skill keeps its source-checkout context.

[`box help agent`](../../cli/cli.md#box-help-agent) is a help
topic. It prints on standard output the path of the shipped guide, the version of `box`, the Box
home, the profiles folder with the profile names, and the folder of the shipped packs. It names
each profile that `box profile list` lists, also one that does not parse, and it prints nothing
on standard error. The first line of `box help` and of `box --help` tells a coding agent to run
it. It writes no file and makes no folder, so it works before the Box home exists. When `box`
cannot find its resources, or the guide in them, the command fails and names each place it
looked. A file named `editing-box-profile.md` that an earlier version wrote into the Box home
stays there, and no command reads it.

No command writes the guide. Profile creation writes the profile and the selected
policy only, and the generated profile comment names the command. `box profile show`, `box run`,
profile listing, and library previews leave a guide copy in a profile folder as it is. The
[ownership decision](decisions.md#the-binary-owns-the-profile-editing-guide) and the
[command decision](decisions.md#the-guide-for-a-coding-agent-is-a-command) state why.

## What `box run <profile>` does

`box run <profile> [--box-id <id>] [-- args]` runs these steps in order. It takes no input values
([decisions.md](decisions.md#box-run-takes-no-option-values)). A step that fails stops the run,
and `box` prints `box: error: <reason>` and exits with status `1`.

`Launcher::prepare_with_context` also returns the installation ID and an immutable
[telemetry context](telemetry.md), including partial observations when a step fails.
Ordinary preparation skips context construction and identity persistence.

### Load the profile

`box` reads `~/.strands/box/profiles/<profile>/profile.toml`, refuses a key that belongs to one run, and
checks the syntax of each placeholder. It reads the authored files in `policies`, as
[Generated policy](profile-language.md#generated-policy) states. When the profile does not exist and
the name is a starter, `box` creates it first, as `box profile create <name>` does
([starters](starters.md)). For any other name, `box` stops with `ProfileMissing`, which lists a
`box profile create <name> --with <starter>` line for each starter.

### Check the current directory

The current directory, resolved through links, is the workspace. `box` refuses a `<workspace>/.box`
that is a link or a file.

### Mint or find the instance

Without `--box-id`, `box` creates `~/.strands/box/r/b-<16 hex digits>/` and its `box/`
subdirectory, both mode `0700`, each with one `mkdir`. The ID is 8 bytes from `/dev/urandom`,
written as 16 lowercase hexadecimal digits after `b-`. The prefix satisfies Box Core's
identity format. When the name exists, it takes new digits.
`box` passes the ID to Box Core as `RunOptions::box_id` on every run, so Box Core
stores it as the box's `box_id` and labels its records with it.

The socket path is `~/.strands/box/r/<id>/box/run/box.sock`, with 51 bytes after the host home.
A 52-byte home fits Box Core's 103-byte limit on macOS and Linux.
Box Core checks the full path. Profile names do not appear in it.

With `--box-id <id>`, `box` uses `~/.strands/box/r/<id>/`. It refuses an ID that is not one path
component or names no run directory with a `box.toml` and a `box/` (none of them a link), an ID
that is not `b-` followed by 16 lowercase hexadecimal digits, and a run whose `box.toml` names no
workspace. A box ID works from any workspace: the reused run's `box.toml` and policy are compiled for the workspace of this
run, so its grants are that workspace's, and its history carries on. When the `box.toml` it
replaces names another workspace, `box` prints `box: box ID ... was last set up for <old>; it now
runs in <new>`. A new run writes the full profile name to `profile-name` in its run directory, mode
`0600`. The profile check reads the `profile-name` record, which must be a file that names this profile
exactly. Every run then holds an exclusive lock on its run directory until it ends, opened without
following a link, and `box` refuses a run directory that another `box run` holds, or that a
`box clean` holds while it removes it.

### Load the packs

`box` loads each pack in the profile's `packs` and each pack's `extend`, depth first, each pack
once. It refuses a key in the wrong kind of file or in neither, a pack with no valid `[pack]`
header, a pack that declares `policies`, a misplaced slot, and an `agent-args` that is not a list of
strings. It writes each tool pack as its `[tool.<name>]` table
([profile-language.md](profile-language.md#tool-packs)), and binds `${{ pack }}` in each file to
that file's own folder.

### Merge

`box` merges the files in order, the profile last. It collects each pack's `[inputs]` declarations
and the profile's `[options]` values, refuses a value that no pack declares or that fails its
declaration. It does not check that the profile names a provider. It puts a bare
`{ slot = "agent-args" }` marker in place of the slot. When the profile sets no `agent-args`, the
slot's `default` follows the marker.

### Resolve

`box` resolves each tool table that names a `program`
([profile-language.md](profile-language.md#tools)), drops each entry, table, and `{ value, when }`
value whose `when` does not hold, puts `value` in place of each other `{ value, when }` table, and
fills in every other placeholder: the built-in names and the inputs (the profile's `[options]`
value, else the `from` source, else the default). It checks each input value against every
declaration of it. It refuses a `program` value in the workspace, the run's storage, `~/.strands/box`, or
under a write grant of the resolved profile. It resolves each `[[storage.files]]` row whose `when`
holds, and refuses a source that reaches a credential path, the workspace, the run's storage,
`~/.strands/box`, or a write grant. It resolves `agent-args` as its own field, so a refusal names an
`agent-args` element, and puts the result in place of the slot. Last, it resolves each
`[[mcp-servers]]` row whose `when` holds, reads each file that passes the same source check, and
turns each server that the box can run into an `[mcp.<name>]` table (see [MCP servers](#mcp-servers)). Shipped tool packs supply
each launcher's cache, environment, and registry hosts. It reports each omitted automatic
declaration and its reason. Each selected host entry remains in the configuration import.

### Compile

`box` builds the run's `box.toml` and `policy.dw` (see
[What Box Core receives](#what-box-core-receives)), and checks what it refuses (see
[What `box run` refuses](#what-box-run-refuses)).

### Preserve incoming storage rules

For an enabled profile's `[storage] mounts`, Boxy passes the mount paths and the
`linux-storage-mounts` feature flag to Box Core. It keeps required filesystem rules that
cannot yet be resolved against the incoming filesystem, including program-resolved tools'
missing literal paths and symbolic links that enter a declared mount path.

Path resolution checks existing components only up to the incoming mount. Wildcard expansion
must reject a path before entering that mount, including entry through an outer symbolic link.
Boxy does not enumerate the incoming filesystem. Optional paths retain their ordinary semantics.

An incoming write grant can reach an external denial through a symbolic link. Boxy therefore
preserves authored `deny_write` paths that it cannot yet prove irrelevant. It keeps the same
paths in generated Shell and Monty policy. Move and delete restrictions on their ancestors use
exact path comparisons, so they do not prohibit operations on unrelated sibling files.

Box Core owns mount detection, preparation of each process's restricted view, and publication.
Boxy adds no mount watcher or readiness gate. The application can start while the declared
storage is inaccessible. Failure to apply a required rule stops the affected Box.

Box Core also gives hosted Shell and Python (Monty) the agent's protected incoming storage view.
Their existing `fs:*` policy decisions remain mandatory. The broker retains a handle to the
protected view and resolves storage operations through it, including when a declared root
is nested beneath a home or workspace mapping. It does not reopen the host's raw storage path.
Without an agent view, declared hosted storage remains unavailable.

### Write the run's files

For a new run, `box` writes `box.toml` and `policy.dw` into the run directory. For a reused run, it
writes them into a private scratch directory first, as `box profile show` does.

### Check the policy

`box` calls `strands_box::check_policy()` on the run's `box.toml`. Box Core reads the `policy.dw`
that `box.toml` names and validates it as a box does when it opens. It starts nothing and writes
nothing. Each error stops the run with `Error::Policy`. `box` places each error (see
[Where a policy error points](#where-a-policy-error-points)). `box run` does not print a warning,
because Box Core prints each warning when the box opens. It does not refuse a per-tool MCP rule that
the check cannot validate, because only a running box learns the server's tools. When the check
passes for a reused run, `box` writes each file beside its target in the run directory and renames
it over the target, so the run gets the new files whole. A reused run whose check fails keeps its
earlier files.

### Prepare storage

`box` creates each managed storage directory and each detected launcher's cache, and refuses one that is a
link. It copies each `[[storage.files]]` source whose target does not exist yet, brings each
`sync = true` copy up to date with the host, writes each
`[[storage.files.set]]` value into a copy already in storage, and prints each link or entry that the
copy leaves out (see [Copies](profile-language.md#copies)). It then inserts selected source entries,
including servers without generated policy, into each missing MCP target section, or an empty
one below the top level, preserving other settings
and existing sections (see [MCP servers](profile-language.md#mcp-servers)). When a step from
[Load the packs](#load-the-packs) to this one fails, `box` removes a run directory it minted, and
keeps a reused one with its box. A policy error comes before this step, so it creates no storage
directory and copies nothing.

`[storage] mounts` names incoming host mount paths. This preparation step does not create
those paths or their contents.

### Start Box Core

`box` calls `strands_box::run()`. At a terminal, its `on_ready` callback starts stderr capture,
then writes the run report before the workload starts. Redirected runs write the report before
the Core call:

```text
box: running profile claude with box ID b-5b8e3d70c92f14ab (records: ~/.strands/box/r/b-5b8e3d70c92f14ab/records.jsonl)
box: to reuse this box run: box run claude --box-id b-5b8e3d70c92f14ab
```

A reused run prints `box: running profile claude with box ID b-5b8e3d70c92f14ab again` instead.

If Core refuses a fresh run while its `box` directory is still empty, the CLI removes that run
directory. It keeps reused runs and any run where Core has written state, including a workload
that exits with a nonzero status.

Once `box` calls `strands_box::run()`, Box Core runs in the `box` process. It owns the signals. The
CLI reference describes [terminal behavior](../../cli/cli.md#the-activity-banner) and
[exit status](../../cli/cli.md#exit-status).

With the activity banner on, `box` first reads the box's `records.jsonl` with the reader
`box runs history` uses, and the run starts after that read. A rerun of a box (`--box-id`) so opens
with the counts history lists, and none of those decisions shows as a new denial. Box Core has not
started yet and `box` holds the box's lock, so the read holds every earlier run and nothing of this
one.

**Cost.** The read delays the agent's start in proportion to the box's history, because Core appends
every decision of every run, and every span the workload exports, and never trims the file. A review
measured about 2 seconds for 100,000 earlier decisions (217 MB) and 20 seconds for 1,000,000.
Without native filesystem policy, we estimate that a day of agent work records hundreds to a few
thousand decisions, so a reused box rarely gets near that. With native filesystem policy, one `npm
install` can record tens of thousands, and a workload that exports large spans grows the file too.
Two later optimizations would cut the cost. Skipping the log lines, which repeat each decision and
which the banner does not read, before they are parsed halves it. Storing the banner's counts in the
run folder when a run ends removes the read.

`box` then passes
`RunOptions::policy_decisions`, the sending half of a channel from `strands_box::policy_decisions`.
Box Core puts each policy decision on it as the decision is made, so the banner reads this run's
decisions in memory and does not poll `records.jsonl`. Box Core never waits for the banner: when the
channel is full, it drops the decision from the channel and counts it.

## What `box profile show` runs

`box profile show <name>` runs
[Load the profile](#load-the-profile) and
[Load the packs](#load-the-packs) to [Compile](#compile) for an instance named `b-0000000000000000`,
the same 18-character stand-in that profile creation uses, and
[Check the policy](#check-the-policy) in a private temporary directory: it writes `box.toml` and
`policy.dw` there, checks them, and removes the directory. Then it prints the packs, the plugins,
each declared source and its program, the storage directory, each input, each copy with what a run does with it, each MCP server that the run declares
or skips, and each warning of the check as Box Core's text, which names the rule. A warning does not
fail the command, and `box` does not place it on a line. It leaves no run files behind. `box run` prints
each MCP server and each skip to stderr before [Prepare storage](#prepare-storage). `--full` also
prints the `box.toml` and `policy.dw`.

`--format json` prints one JSON document on one line, and no text lines. The document holds the
same lists, and each name of a `parts` row is its key path. As in the text report, only `--full`
adds the `box.toml` as an object and the `policy.dw` text. Each key of the `box.toml` object is in
the sequence where it first occurs in the file. `Preview::json` parses the `box.toml` text that
`--full` prints again. Thus the object holds the same tables and values. A TOML datetime becomes a
JSON string, and a float that is not finite becomes `null`. If the preview stops with an error,
`--format json` does not print the `Saved settings` section, and stdout stays empty.

## Where a policy error points

A policy finding names the combined `policy.dw`. A line or rule position in the message counts
from the start of that output. `box` does
not map a finding back to a file in `policies` or parse the policy language
([decisions.md](decisions.md#box-never-parses-the-policy-language)).

`check::place` uses Box Core's location and the `@id`s of the rules it names. Every rule that
`box` writes has a unique `@id`, and `Compiled::generated_ids` lists them. `compile` builds
that list from the rules it writes (`render::Rules`), not from the policy text.

| The finding | What `box` prints |
| --- | --- |
| A location after the authored text, with no rule, and some authored text | `policy.dw: <message>`, with no line. A parse error in the authored text, such as a missing final `;`, can extend into generated rules. |
| Any other location | `policy.dw:<line>: <message>` |
| No location | `policy.dw: rule <position> (@id "<id>"): <message>`, one `rule ...` for each rule Box Core names. A rule with no `@id` is `rule <position>`. A finding with no rule prints only the message after the path. |
| An `@id` that `box` writes is on more of the named rules than `box` writes it | Adds a request to give the authored rule another `@id`. One of the rules is authored. Box Core reports a shared `@id` with no location. |
| A finding belongs to generated rules | Adds a request to report the defect as a `box` bug. The parse error in the first row gets no such request. |

A finding has no location when Box Core's own checks find it (a duplicate `@id`, a cap written
as a `permit`, a reserved action), and for every finding in a box with a local MCP server.
Each finding carries Box Core's message, then its help, such as ``did you mean `path`?``.
The path has no run directory, because `box` removes that directory after a failed check.
`box profile show --full` prints the combined policy of a profile that passes the check.
When `strands_box::check_policy()` cannot read the configuration or the policy, `box` stops
with `Error::PolicyCheck`.

## What Box Core receives

| Input | Value |
| --- | --- |
| Arguments | `<run directory>/box.toml` and `<args>`, with each `<arg>` from `box run <profile> -- <args>`, unchanged. |
| Working directory | The directory where the operator ran `box run`. |
| Environment | The environment of `box run`. Box Core reads a credential such as `env://AWS_BEARER_TOKEN_BEDROCK` from it. The agent gets only its `[agent] env`, and Box Core adds the variables it owns. |
| Files | `box.toml` and `policy.dw` in the run directory. |

With the banner, `box run` sets `TERM=xterm-256color` and `COLORTERM=truecolor` in `[agent.env]`.
Profile previews and runs without the banner use the profile's values.

### Whether a run shows the banner

`box run` decides the display once, after it loads the profile and before it resolves the packs.
The first of these that is set wins, and the banner is on when none is set:

1. `--banner` or `--no-banner`. Clap's `overrides_with` makes the last of the two win, so an
   alias or a wrapper script that adds one flag can be overridden on the command line.
2. `[banner] enabled` in `profile.toml`.
3. `[banner] enabled` in `~/.strands/box/config.toml`.

The banner shows only when all three standard streams are terminals, so `enabled = true` does not
force it into a piped run. This is why the choice is on or off, and not a three-value
`--banner=auto|always|never` as with `--color`: `always` cannot be honored.

The flag is a `--banner` and `--no-banner` pair, as in git and cargo, and not `--banner=<bool>`.
No other flag of `box` takes `true` or `false` as a value, and `--help` shows each of the pair as
its own line.

Both files hold the same `[banner]` table with the same keys, so a profile overrides the
operator's file key by key, with no rename. The table names the thing it sets, not the command
that reads it (`[run]`) or a category (`[display]`, `[settings]`), so a later banner key has one
home and an unrelated `box run` setting does not join it. `enabled` is its only key.

The profile holds `[banner]`, though it changes no grant or rule
([decisions](decisions.md#box-run-takes-no-option-values)), because the display reaches
`box.toml`: the banner sets the agent's `TERM` and `COLORTERM`. A pack holds no `[banner]`, as it
holds no `agent-args`: the display is the operator's choice. `[banner]` is a language key, so it is
removed before the merge and never reaches `box.toml`. `Profile::parse` checks it, so a bad value
fails at load with the line, before the run directory exists. The operator's file is read on every
run, whole: `Launcher::display_for` loads the starters menu, checks `[policy-starters]` with
`PolicyMenu::check_config`, and reads `[banner]`, so any error in the file stops the run with the
path of the file, as it stops `box profile create`. A malformed settings file never runs quietly.
The check reads only `config.toml`, never a policy folder that it lists.

The policy refresh compiles with the display that the run started with. A `[banner]` edit during a
run then leaves `box.toml` unchanged, so it does not block a policy update, and it takes effect on
the next run.

This is the `box.toml` that `box run claude` writes with the banner in `~/src/my-app` for the profile above
(shortened: the `[tool.*]` tables and the telemetry variables are left out, and paths are under
`/Users/me`):

```toml
name = "b-5b8e3d70c92f14ab"
box_dir = "/Users/me/.strands/box/r/b-5b8e3d70c92f14ab/box"
policy = "policy.dw"
file-attributes = true

[agent]
command = ["/Users/me/.local/share/claude/versions/2.1.296"]
workspace = "/Users/me/src/my-app"

[agent.env]
AWS_REGION = "us-east-1"
CLAUDE_CODE_TMPDIR = "/Users/me/.strands/box/storage/claude/default/agent/tmp"
CLAUDE_CODE_USE_BEDROCK = "1"
CLAUDE_CONFIG_DIR = "/Users/me/.strands/box/storage/claude/default/agent/config"
COLORTERM = "truecolor"
DISABLE_AUTOUPDATER = "1"
IS_SANDBOX = "1"
PATH = "/usr/bin:/bin"
TERM = "xterm-256color"
TMPDIR = "/Users/me/.strands/box/storage/claude/default/agent/tmp"

[agent.filesystem]
read = [
    "/Users/me/src/my-app",
    "/Users/me/.local/share/claude/versions/2.1.296",
    "/Users/me/.strands/box/storage/claude/default/agent/config",
    "/Users/me/.strands/box/storage/claude/default/agent/tmp",
]
write = [
    "/Users/me/src/my-app",
    "/Users/me/.strands/box/storage/claude/default/agent/config",
    "/Users/me/.strands/box/storage/claude/default/agent/tmp",
]
exec = ["/Users/me/.local/share/claude/versions/2.1.296"]
deny = ["/Users/me/src/my-app/.box"]

[egress.bedrock]
destinations = ["bedrock-runtime.us-east-1.amazonaws.com"]

[egress.bedrock.secret]
ref = "aws://"

[telemetry.records]
destination = "/Users/me/.strands/box/r/b-5b8e3d70c92f14ab/records.jsonl"
include = ["deny", "permit", "trace", "logs"]
kind = "file"
```

Compared with the merged profile and packs, `box run` made these changes:

| Change | Where |
| --- | --- |
| Set `name` and `box_dir` to the new instance, and `policy` to the run's own `policy.dw`. | Top level. |
| Set `file-attributes` to the profile's value, or to `true` when `box` does not run as root ([decisions.md](decisions.md#file-times-follow-the-user-id)). | Top level. |
| Replaced each placeholder with its value, each existing filesystem entry with its real path, dropped each `optional` entry that does not exist, dropped each entry, table, and `{ value, when }` value whose `when` does not hold, and put `value` in place of each other `{ value, when }` table. | Every template field. |
| Replaced `program`, `helpers`, and `hosts` with the real file as `command`, set the base `PATH` and `TMPDIR` that the table does not set (with read and write on the default `TMPDIR`, the tool's own folder `tool-tmp/<tool>` in the run's directory), added the interpreter's reads and deny entries and the helpers, added the variables, filesystem, and program folder of each kept tool that the tool's tool pack extends, left out each tool that only a tool pack's `extend` brings in, and put the workspace first in `read`, and in `write`, as far as `[project] access` allows. | Each `[tool.<name>]` that names a `program`. |
| Set the workspace, put it first in `read` and `write` as far as `[project] access` allows, and added each storage directory. | `[agent]`, `[agent.filesystem]`. |
| Added an `[mcp.<name>]` table for each server that the packs' `[[mcp-servers]]` rows name and the box can run. | `[mcp]`. |
| Added a deny of `<workspace>/.box`. | `[agent.filesystem]`, each `[tool.<name>.filesystem]`, each `type = "stdio"` `[mcp.<name>.filesystem]`. A detected stdio server gets every `deny` entry of the agent. |
| Added each entry of the profile's `[filesystem] deny_write` to each process's `deny_write`, then dropped each `deny_write` entry that no write grant of that process holds. Added each entry of its `[filesystem] deny` to each process's `deny`. | `[agent.filesystem]`, each `[tool.<name>.filesystem]`, each `type = "stdio"` `[mcp.<name>.filesystem]`, detected servers included. |
| When the operator's `PATH` mixes full and relative entries, set `env.PATH` to its full entries, in order (`compile::inherit_path`). With a nonempty `PATH` that has no full entry, an absolute command gets `/usr/bin:/bin`; a bare command gets no `shell:spawn` permit. An empty operator `PATH` already uses Core's `/usr/bin:/bin` default. A detected launcher's `PATH` holds only full entries already, and a table whose `env.PATH` the profile writes keeps it. The report names each dropped entry once when a server inherits the operator's `PATH`. | Each `type = "stdio"` `[mcp.<name>]` with no `env.PATH`. |
| Added a file target for the run's records. | `[telemetry.records]`. |
| Removed `packs`, `policies`, `extend`, `[pack]`, `[inputs]`, `[options]`, `[storage]`, the profile's `[filesystem]`, `[[mcp-servers]]`, each `when`, `dependency`, and each `[egress.<name>]` with only `destinations`. | `box run` uses them itself. Box Core v0.1.0 refuses `dependency` and an `[egress]` entry with no secret. |

The run's `policy.dw` holds the files in the profile's `policies` list, then the rules that `box`
generates: the tools, the routes, the MCP servers, storage, `~/.strands/box`, `box`'s resources directory
when it lies outside the box home, the workspace, and
`<workspace>/.box`. A pack adds no policy, and the rules that no table declares, such as the
shell's commands, come from the policy starter that the profile copied
([decisions.md](decisions.md#a-pack-adds-no-policy)).
[profile-language.md](profile-language.md#generated-policy) lists the parts in order. A path
under the operator home is written with `~`, the form Box Core reports in a decision. The `deny`
entries limit the syscalls of each process in the cage. The `forbid` rules govern the Strands Shell
and Monty, which run outside the cage and act only after a policy decision.

## MCP servers

An agent pack lists the host files that hold its agent's MCP servers in `[[mcp-servers]]` rows
([decisions.md](decisions.md#a-pack-names-where-its-agents-mcp-servers-are)).
[profile-language.md](profile-language.md#mcp-servers) states the row. `mcp::detect` does the
work in this order:

1. **Read.** Each row's `file` is JSON or TOML, as its `kind` says. `box` follows the `key` list to a
   table of servers by name. A missing file or key gives no servers. A file that fails the source
   check, or that is, holds, or lies in a `reads` or `deny` path of a declared secret source, or
   that does not parse, is not read, and the report names it with the reason. A later
   row replaces a server of the same name from an earlier row, including its import target.
   Each selected entry is held until declaration checks finish, then inserted into its target
   once. A skipped declaration supplies no generated MCP table or policy. Its imported entry
   retains the original fields, except when a final stdio declaration matches its command's
   filename and arguments, as Box Core selects a server. Then the entry gets the bare filename,
   so the agent starts that declaration's server from `PATH`, and loses `env` and each field with
   the `variable-names` role, so the agent cannot read their keys. The entry also loses `env` and those fields when its
   `env` holds the operator's value of a variable that a `pass-secret-env` entry covers, or sets
   such a variable, and it loses `args` when an argument, as written, holds that value, even when a declaration matches, so the agent starts no declared server with it. A profile table with a `type`
   that replaces an entry that keeps environment fields and does not match it adds that to the skip line.
2. **Check each server.** `box` reads `type`, `command`, `args`, `env`, `url`, `enabled`, and
   each field the row's `env-var-locations` gives a role. Every other field passes through: it
   stays in the agent's configuration, `box.toml` never holds it, and it keeps no server out
   ([decisions.md](decisions.md#a-pack-names-where-its-agents-mcp-servers-are)). An explicit
   `type` of `stdio` or `http` wins, else `command` means stdio and `url` means http. A server
   with `enabled = false`, or with a field of the other transport (`url` on stdio, `command`,
   `args`, or `env` on http), is skipped. A field with a local role on a remote server also
   skips it. `Role::is_local` identifies local roles. A field with a remote role on a stdio
   server skips it when `mcp::keys` reads a variable in that field or cannot read it. A field
   with a remote role and no variable passes through
   ([decisions.md](decisions.md#a-detected-server-carries-no-credential)).
3. **stdio.** The server's `env` and the variables in its fields follow this table, in order
   ([decisions.md](decisions.md#a-local-servers-key-is-in-box-toml)). Each rule that skips a
   server follows discovery restrictions or what the server needs to start.

   | In the server's configuration | `box` | Why |
   | --- | --- | --- |
   | A variable that a `pass-secret-env` entry of a declared secret source covers, a prefix entry included: a name in a `variable-names` field, or a variable that a `references` field writes in the row's `env-var-syntax`, set or not | Skips the server (`mcp::reads_credential`), and the reason names the variable and the source. | The variable is a vault credential, and `box.toml` would hold its value. Box Core does not compare a workload's `env` with the vault's credentials, so this check keeps it out. |
   | An `env` value, after `box` fills it in, that holds the operator's value of a variable that a `pass-secret-env` entry covers, a prefix entry included, such as a pasted token or another variable with the same value | Skips the server (`mcp::holds_credential`), and the reason names the `env` name, the variable, and the source. Its entry in the agent's configuration loses its environment fields, as for a declared server, and so does the entry of any stdio server whose `env`, as written, holds that value, whatever skips it (`mcp::imports_credential`). For a prefix entry, such as `OP_SESSION_*`, `Sources::env_with_prefix` lists each variable that starts with the prefix. Box Core does not look for these values, so this is the only check. | As above. |
   | An argument, as written, that holds the operator's value of a variable that a `pass-secret-env` entry covers, a prefix entry included, with or without a variable beside it | Skips the server (`mcp::holds_argument`), before an argument with a variable becomes `*`. The reason names the place of the argument, the variable, and the source, and never the argument. Its entry in the agent's configuration loses `args`, whatever skips it (`mcp::imports_argument`). The comparison is the one of the `env` row: the value is a part of the text. `box` compares no header and no `url` of a remote server, and [limitations.md](../../cli/limitations.md#mcp-servers-in-the-box) names that gap. | The value would be in the `command` of `box.toml`, or, beside a variable, reach the server through the agent's invocation, and it would be in the agent's configuration. |
   | An `env` name that a `pass-secret-env` entry of a declared secret source covers, a prefix entry included, whatever its value | Skips the server (`mcp::sets_credential`), and the reason names the `env` name and the source. Its entry in the agent's configuration loses its environment fields (`mcp::imports_credential`). | The server would hold a vault credential, such as a pasted `OP_SESSION_<account>` session. |
   | A variable in `command` or `env` with the `references` role: `NAME` in a form of the row's `env-var-syntax`, or `${NAME:-default}` | Fills it in from the operator's environment (`mcp::expand`), in one pass, so a filled-in value is not read again. An empty value counts as set. | Claude Code does the same on the host. |
   | A value in a `references` or `header-references` field that starts with the row's `command-prefix`, or holds an escape of a form with no closing text (`$$`, or `$` before the prefix) | Skips the server (`mcp::unread`). | `box` cannot supply what the command prints, and does not read the escape as the harness does. |
   | A required `command` or `env` reference with no value or fallback | Skips the server. | There is no value to give it. |
   | A variable that a profile route sends as `secret.ref = "env://<VAR>"` | Fills it in with the real value. | The server's own `env` wins over the route's placeholder, so the route still works. A remote server is skipped instead (the http step). |
   | A variable that a route or a profile `type = "http"` server names in `secret.env` for a key in another scheme, such as `op://`, set or not, in `command`, `env`, or a `variable-names` field | Skips the server (`mcp::stand_ins`, read in `mcp::reads_credential`), and the reason names the variable, the route or the server, and the scheme. In `args` it is a wildcard argument, as any variable there, so the server comes in. | The variable holds a stand-in in the box, and the host's value of it is not the key that the box reads from the secret source. `box` fills in no `args`, so the harness passes the stand-in there. |
   | A `variable-names` field (Codex `env_vars`) | Reads string names or objects with `name` and optional `source` (`null` or `"local"`). Omits unset names before value checks; preserves empty values. `env` wins over it. | Codex does the same on the host. |
   | An `env` name that is not `[A-Za-z_][A-Za-z0-9_]*` | Skips the server. | It is not a variable name. |
   | A name that makes a program load code (`strands_box::reserved_env` returns `LoadsCode`) | Skips the server. | Automatic discovery refuses variables that select code to load. |
   | A name that Box Core sets (`strands_box::reserved_env` returns `GatewayProxy`, `GatewayCaFile`, or `SetByBox`) | Drops the name, and the report names it. When the merged table has `contain_egress = false`, keeps each `GatewayProxy` and `GatewayCaFile` name with its value, and adds each `GatewayCaFile` file to `filesystem.read_file`. A CA path with a link in it becomes the real file it names, in `env` and in `read_file`, because Core refuses a grant path with a link. A CA value that is not a full path to a file, or that a refused root or Core's read-grant check covers, stays dropped with that reason. An unset reference in a kept name skips the server. | Box Core refuses it and sets its own. For a native-egress server Core sets no proxy or CA, accepts the server's own, and needs a `read_file` entry for a CA file. |
   | `PATH` | Skips the server. | The server and its helpers use the operator's `PATH`; a server-specific value can select different programs. |
   | `~` or `~/` at the start of an `env` value that `references` fills in | Starts the value with the operator's home. A value copied as written keeps its `~`. | Claude Code's rules fill it in. |
   | A relative `HOME` or `TMPDIR` | Skips the server. A full path is copied wherever it points. | Box Core refuses a relative one. A full path is the operator's choice. |
   | Any other `env` value, after `box` fills it in, with a path in it. `box` splits the value at `:`, `;`, `,`, `=`, `@`, a quote, and white space. It also reads the value whole, and each part between `:` or `;` whole, so that a folder name with a space stays one path. A part is a path when it starts with `/`, `./`, `../`, or `~/`, or is `~`. | Skips the server (`mcp::writable_path`) when a part starts with `./`, `../`, or `~/`, or when a part is or lies in the workspace, the run's storage, `~/.strands/box`, or a write grant, as written or real. `Refusals::inside` answers that from the roots that refuse the server's program and each `PATH` directory. A `~/` that `box` did not fill in reaches the server as written, and a program reads it as a path that is not a full path. A full path anywhere else is copied, and so is a folder that holds one of those places, such as the operator's home. | A program loads code from the files and folders that its variables name, and a path that is not a full path starts from the workspace, where each server starts. The check reads where a value points, so it needs no list of names, and a URL such as `file://` is read by its path. |
   | Any other `env` value that is a list of paths with `:` or `;` between them: each part is a path, `.`, `..`, or empty, or the name ends as the name of a path does, in either case ([the endings](../../cli/troubleshooting.md#an-mcp-server-has-no-automatic-declaration)). A value with `://`, a number, and `true`, `false`, `yes`, `no`, `on`, and `off` are no list. | Skips the server when a part is not a full path. Under a name with one of those endings, the reason says that `box` reads the value as a path by its name. | A plain word in a path list, such as `lib`, and an empty part both lead into the workspace. A plain word under any other name is copied, because `box` cannot tell a folder from a mode or a repository name. |
   | An `env` value that opens with `-` or `--` and a letter, after any white space | Checks each path in it as in any other value, but reads it as no list of paths. When it passes, copies it, and the report names the variable in a `did not check` line (`Servers::option_lines`). | The value holds options, such as `JDK_JAVA_OPTIONS` does, and `box` reads no option. An option can load code by a plain word, which `box` does not see as a path, and [limitations.md](../../cli/limitations.md#mcp-servers-in-the-box) names that gap. |
   | An argument that holds `${`, `{env:`, or the opening part of a form of `env-var-syntax`, with or without `references` (a form with no closing text, such as `$NAME`, only with `references` on `args`; the same rule applies to `command`) | Replaces the whole argument with `*` and sets `argument_wildcards = true`. It reads no host variable for that argument. | Core forwards the caller's argument unchanged, including literal variable text. |
   | A literal whole `*` beside a variable argument | Skips the server. | Core would interpret both as wildcards. With no variable arguments, the star stays literal and the flag is omitted. |

   The box-owned and code-loading names come from Core's `strands_box::reserved_env`. The table gets `env` with
   the real values. The server's grants do not cover a home outside the workspace, so a server that
   writes such a home fails at run time. The report names each `env` name and each variable that
   `command` takes, never a value. `box profile show --full` prints the values, which is
   not a boundary: a process that can run it already holds the operator's environment.

   `command` is a program name on the operator's `PATH` or an absolute executable path.
   An absolute command selects that file without a `PATH` fallback. The filename is not a
   name in `strands_box::INTERPRETER_ALIASES` (`zsh`, `bash`, `sh`, `python3`, `python`), which
   the box keeps for its own interpreters, and not an unsupported launcher (`docker`) or a
   runtime that runs a script or a package (`mcp::RUNTIMES`: `node`, `deno`,
   `bun`, `ruby`, `perl`, `php`, `java`, `uv`, `pipx`, `npm`, `pnpm`, `yarn`). Relative command
   paths and `~` command paths are refused. The program, its real
   file, and the interpreter its `#!` line names must lie outside the workspace, the run's
   storage, `~/.strands/box`, and each write grant. So must each full `PATH` directory, because the
   server inherits `PATH`. A relative or empty `PATH` entry finds programs in the workspace, so the
   compile step drops it from the `PATH` of each stdio server that inherits the operator's `PATH`
   (see [What Box Core receives](#what-box-core-receives)). Absolute executable paths also pass
   `mcp::stays`, which checks intermediate links against those writable roots.
   `mcp::detect` does not check argument paths, and `compile::refuse_reach` treats the later
   `command` elements of a detected server as arguments when no profile table extends it
   (`mcp::Detected::extended`). So a server with a
   project file in its arguments, such as
   `--db-path ./data.sqlite`, comes into the box and the run compiles
   ([decisions.md](decisions.md#a-detected-servers-arguments-are-not-programs)).
   For an extended detected server, `compile::argument_files` checks each existing file named
   by a fixed argument or by the value after `=` in a fixed flag. It expands `~`, resolves relative paths
   against the workspace, and follows links before the write-grant check. The command written
   to `box.toml` keeps fixed arguments unchanged. Wildcard slots have no concrete path to check.
   A runtime value can name a writable file even for an extended server. The whole argument is
   caller-controlled, including a flag prefix before a variable reference. The table gets `read` on the
   install directories, and the workspace grants that `[project] access` gives the agent
   ([decisions.md](decisions.md#a-detected-server-reads-its-install-directory)). A supported launcher
   adds its tool pack's environment, read grants, denies, cache read and
   write grants, and registry permits. Cache directories are shared per launcher and profile, in every
   workspace ([isolation.md](isolation.md)). It keeps
   `contain_egress = true` unless an addition's `[mcp.<name>.network]` sets it to `false` ([decisions.md](decisions.md#a-network-permit-needs-a-named-destination)).

   For an absolute executable path outside the workspace, `mcp::stays` follows each link before
   the next path component, including `..`. It uses the filesystem's spelling for ordinary
   components, checks that their identity and parent stay the same, and checks each link's
   location against the refused roots. A link in one of those roots skips the server. This
   includes a writable link reached through a fixed external link. An ordinary `..` component is
   not a link.
4. **http.** `url` is `http://` or `https://`, on any host. The table gets
   `destinations = ["<host>[:<port>]"]`, with port 80 written for `http://`, because a destination
   defaults to 443. A server with a gateway credential and an `http://` URL is skipped before
   its table is emitted, because Core sends credentials only over TLS. An explicit port 443
   does not change this rule.
   `mcp::keys` reads each variable that a field with a role names
   ([profile-language.md](profile-language.md#mcp-servers) lists the roles). A
   `header-references` value with no variable is left to the agent, which sends it as on the
   host ([decisions.md](decisions.md#a-detected-server-carries-no-credential)). Its header name
   is not checked because it never becomes `secret.header`. Header names that carry a variable
   must contain only letters, digits, and `-`, and must not be empty. A
   `header-references` value with a variable must end in one variable written in the
   row's `env-var-syntax`
   (`${NAME}` for `@box/claude`, `${NAME}` or `$NAME` for `@box/pi`), and the text before it becomes
   `secret.prefix`. A reference can
   include a literal `:-default`, except in a form with no closing text, such as `$NAME`. If the variable is unset, the reference creates no credential
   binding; the harness uses the fallback in its own configuration. A variable that a route or a
   `type = "http"` server names in `secret.env` for a key from a source counts as set, because the
   agent gets its stand-in. Reserved names and profile
   environment conflicts are checked before this selection. Nested references are refused. With a
   `env-var-syntax`, a query parameter of `url` whose whole value is one variable is a key too
   (read with the row's forms that have closing text only, so `?$filter=x` is text),
   with `secret.placement = "query_param"` and `secret.param`. Any other variable in `url`, a
   header with text after its variable or a second variable, or a name that is not
   `[A-Za-z_][A-Za-z0-9_]*`, skips the server. So does text before a header's variable outside
   letters, digits, spaces, `-`, `_`, `.`, and `:`, because Box Core refuses a prefix with a brace
   or a control character. A variable in the URL's host, path, or fragment skips the server, and a
   query key's destination comes from the URL without its query. A variable that is unset without
   a fallback, or is set but holds only whitespace, skips the server, unless a route or a
   `type = "http"` server names it in `secret.env` for a key from a source: that variable holds
   only a stand-in, so the later skip names the route or the server. So does a variable Box Core sets itself or writes
   over (`reserved_for_key`), because Box Core refuses the config for it. A
   server with one variable gets `secret.ref = "env://<VAR>"`, plus `secret.header` and
   `secret.prefix` for a header key. Box Core keeps the default `phantom` injection, so the
   gateway adds the key only to a request that carries the agent's placeholder, and a harness
   that withholds a variable from a remote server withholds the key too. These servers are
   skipped: a server with two variables, or with one variable in two places; a server whose
   variable a route binds (`env://<VAR>` or `secret.env`, `mcp::key_variable`); a server whose
   variable the profile's `[agent.env]` sets (Box Core writes the agent's variables over the
   placeholders); and a server whose variable a `pass-secret-env` entry of a declared source
   covers (Box Core refuses that `env://` reference). So is
   a server whose profile table with no `type` sets a `secret` that adds to or changes the
   detected one, because a profile key goes only to the `destinations` of a server the profile
   declares, and a detected server's host comes from the agent's settings. So is a later server whose variable an
   earlier one or a profile table with `type = "http"` takes, by `env://` or `secret.env`, because
   Box Core gives each binding its own placeholder under the one variable.
5. **Name.** A server whose name holds a character outside `[A-Za-z0-9._-]` is skipped
   ([decisions.md](decisions.md#a-server-name-is-renamed-and-a-collision-is-skipped)). A server
   whose name a profile table with a `type` holds keeps that table and is skipped. A table with no
   `type` adds to the detected server of its name (`lang::merge_table`, so its filesystem lists
   join). Its `destinations` join the detected list after the URL's host, so the server keeps the
   host that the gateway routes it by. An added destination on that host and port (a case-only
   copy, or no port against 443 or 80, as Box Core reads ports, or a path) is dropped, and a `*.`
   wildcard that covers that host on an overlapping port skips the server, because Box Core refuses two overlapping destinations in one entry. Box Core attaches
   a key to each destination. After detection, `mcp::detect` drops each table with no `type` that no detected server
   took. It reports the table as a skip, unless the server of that name already has a skip line.
   A stdio server is skipped when the agent or an unrelated tool runs its program name.
   A supported launcher can also be an agent tool. Box Core selects a server by its executable's
   filename and arguments, so different installation paths alone do not distinguish servers.
   A duplicate command is skipped. Two wildcard commands must not match the same arguments; a
   later overlapping pattern is skipped. An exact command can coexist with a wildcard pattern
   and takes precedence when both match a call.
   An http server whose host a route in `box.toml`, a `*.` route, or another http server holds is
   skipped, because Box Core routes a remote server by its host alone and refuses the config.
   A route with only `destinations` stays out of `box.toml`, so it shares its host.

`mcp::detect` reads and parses each file once, however many rows name it.

`mcp::stdio` applies every `install_layout::Layout` to the selected program and to each interpreter
of its `#!` chain as its line names it, so a Python environment stays distinct from its base
interpreter. The same resolver serves the `installation` list in a tool pack. The
[installation layouts](profile-language.md#installation-layouts) find installation trees, Homebrew
receipts, and supporting read paths. A program that no installer layout matches reads its own
directory. The output keeps recursive reads, exact file reads, and macOS directory listings
separate. The compiled `box.toml` names each layout, path, and Homebrew receipt in
`# installation` comments. A path that a run can write stops resolution, and a missing or invalid
Homebrew receipt skips the server; the resolver never substitutes a whole installation prefix.

`box` skips a server whose install directory holds the home or the workspace. It also skips a
server whose program, real file, `#!` interpreter, runtime directory, or installation path is,
holds, or lies in a `reads` or `deny` path of a declared secret source (`Refusals::protects`), and
drops a CA variable whose file does, because Box Core refuses a grant that reaches such a path.
Then it asks Box
Core about each install directory, and about the program's and the interpreter's real files, with
`strands_box::check_read_grant()`, the check that Box Core applies to a `read` entry in `box.toml`:

| Box Core's answer | For an install directory | For the program or the interpreter |
| --- | --- | --- |
| `Ok(false)` | `read` grant. | No change. |
| `Ok(true)`, a credential store such as `~/.ssh` | The server is skipped. | The server is skipped. |
| `Err(GrantRefused)`: a system tree such as `/bin` or `/usr/bin`, a folder that holds a credential store such as `~/.config` or `~/Library`, a link, or an absent path | Dropped only for `GrantRefusal::Forbidden(ForbiddenClass::SystemTree)`, which the box reads without a grant; otherwise the server is skipped with Box Core's reason, such as a program directly in `~/.config`. | The server is skipped with Box Core's reason, such as a file under `/Library/Keychains`. |

`Sources::read_grant` preserves both `strands_box::GrantRefused::kind()` and its message.
A path that Box Core refuses never reaches `box.toml`, and a row that Box Core adds to its
forbidden paths reaches `box` with the pin. Unknown refusal kinds skip the server
rather than treating the directory as a system tree.

Box Core on Linux starts a script only when its table grants each program of the `#!` chain
at its real path. `mcp::interpreters` follows the chain (`env`, the interpreter, and the
interpreter's own `#!` line). Each real file that no `read` directory holds gets `read_file`.
An interpreter also adds what the layouts find for it. An `env` file adds only itself, because on
a host such as Ubuntu 26.04 or NixOS its folder holds every coreutils program. Runtime directories
and helper files from a launcher pass the same path and Core grant checks.

## Running a profile more than once

Each run gets its own instance, so one profile can run in many terminals at the same time. Each
run starts with an empty `box_dir`, so a `when temporal` rule sees only its own run.
`--box-id <id>` runs in an earlier instance instead: the same `box_dir`, so Box Core recovers its
history and each `when temporal` rule that the compiled policy has not changed keeps counting
([decisions.md](decisions.md#each-run-gets-its-own-box)). One instance runs once at a time, and its run directory keeps only the last run's `box.toml` and
`policy.dw`. Two runs of
one profile in one workspace share its storage, so the run that starts last writes each
`[[storage.files.set]]` value into the shared copy. Run directories stay after the run stops, about
2 MB each. `box clean <BOX_ID>` removes one run directory, and `box clean --all` removes every run
directory whose box is not running. It asks `[y/N]` first, and `--no-ask` removes without asking.

## What `box run` refuses

Each refusal prints `box: error: <reason>`, exits with status `1`, and leaves no new run
directory. A refused `--box-id` run leaves the earlier run as it was. This section states the
conditions. The message text is in the code that refuses, mostly the profile crate's `Error` type.
[Troubleshooting](../../cli/troubleshooting.md) explains each message that does not say what to
do.

**The workspace.** `box run` refuses a workspace that is the home directory or holds it. It checks
this before a starter asks a question, and `box run` and `box profile show` check it before the
program search. It also refuses a workspace that holds the run directory or lies inside it, and a
`<workspace>/.box` that is a link or a file.

**Write grants.**

- A `write` or `write_file` entry holds or lies inside a protected directory (`~/.strands/box`, the
  directory of the `box` binary, or the resources directory), and is not inside the run's own
  storage.
- A program lies under a write grant of a table (`agent`, `tool.<name>`, or `mcp.<name>`), and
  that table's `deny_write`, after the profile's `[filesystem] deny_write` joins it, holds no
  folder that holds the program. A program here is element 0 of a
  `command`, an existing argument file (absolute for an authored process; also relative or in a
  flag value for an extended detected MCP server), an `exec` entry, or a directory on a process's
  `env.PATH`, or on the operator's `PATH` for a process with no `env.PATH` and for each stdio MCP
  server. An unextended detected server's arguments are exempt. The message names the table.

**Program inputs.** A `program` value lies in the workspace, the run's storage, or `~/.strands/box`.
`box` compares the path as written and its real path with each root as given and its real path.
After the resolve, it also refuses a value that lies, as written or real, under a resolved
`write` or `write_file` entry of the agent, a tool, or a stdio MCP server, or under a storage
directory. The [program search](profile-language.md#program-search) refuses when it finds no
candidate it can run, and lists each candidate it passed over and why.

**Storage.**

- A storage directory, or a directory above it in `~/.strands/box`, is a link, or a directory above a
  copy's target is.
- A `[[storage.files]]` source is, holds, or lies in the workspace, the run's storage, `~/.strands/box`
  (except `box`'s own packs), a write grant, or a `reads` or `deny` path of a declared secret
  source, as written or real. A tool's link row stops the same way.
- A source that is not `optional` is missing, and its target is not in storage.
- Two rows name one target, or one target lies inside another. When one row has a `when`, the
  error names both targets and the input that turns that row off.
- A source file is not the file `box` planned to copy.
- A row with `kind` names a folder, or its source does not parse as its `kind`.
- The copy that a `set` row rewrites no longer parses as its `kind`, or it, or a directory between
  the storage root and it, is a link.
- A `set` key holds a table, or a parent on its path is not a table.

**The profile and its policy.**

- The profile name breaks the rules in [`box profile create`](../../cli/cli.md#box-profile-create).
- The profile or a pack breaks a rule of the language, such as a key in the wrong kind of file, a
  bad `[pack]` header, an `[options]` value that no pack declares, or an unbounded input in
  `command` or `destinations` ([Safety rules](profile-language.md#safety-rules)). The error names
  the key's line when one key is wrong (`locate::line_of`).
- A `policies` entry is invalid, leaves the profile folder through a path or link, has multiple
  hard links, cannot be read, or resolves to a path already listed. Its index starts at zero. The
  profile also cannot list policy files when its folder or the profiles root is a link.
- A stdio server's `command[0]` is a relative path or starts with `~`.
- A route's or an http server's destination has an empty port or one outside 1 to 65535.
- Box Core refuses the run's policy, or finds two rules with one `@id`, including a rule that
  `box` generates ([Check the policy](#check-the-policy),
  [Where a policy error points](#where-a-policy-error-points)), or
  `strands_box::check_policy()` cannot read the run's `box.toml` or `policy.dw`.

**`--box-id`.** The value is not `b-` followed by 16 lowercase hexadecimal digits, names no run
directory with a `box.toml` and a `box/` (none of them a link), or names a run whose `box.toml`
names no workspace. The run's `profile-name` record is missing, is not a file, or does not name
this profile exactly. Another `box run` holds the run directory, or a `box clean` holds it while
it removes it.

## Paths and variables

| Name | Meaning |
| --- | --- |
| `~/.strands/box/profiles/<name>/` | A profile: `profile.toml` and any files it names. The `policies` list names authored policy files. |
| `resources/editing-box-profile.md` | The standalone editing guide, beside the shipped packs. `box help agent` prints its path. |
| `~/.strands/box/packs/<name>/pack.toml` | A pack the operator adds. |
| `~/.strands/box/storage/<profile>/default/` | The storage of one profile, which every workspace it runs in shares. |
| `~/.strands/box/r/<id>/` | One run: `box.toml`, `policy.dw`, `profile-name`, `records.jsonl`, and `box/` (its `box_dir`). |
| `<workspace>/.box` | The project configuration directory. Every run denies the workload a write there. |
| `BOX_RESOURCES` | The directory that holds `packs/<name>/pack.toml`. Default: `resources/` beside the `box` binary, then, in a debug build, the source tree's `resources/`. |

## See also

- [profile-language.md](profile-language.md): the language.
- [decisions.md](decisions.md): the decisions.
- `crates/cli/profile/src/lang.rs`: placeholders, packs and their headers, inputs, and the merge.
- `crates/cli/profile/src/compile.rs`: what `box run` adds and refuses.
- `crates/cli/app/tests/engine.rs`: the tests that run `box run` against Box Core.
- Box Core's [`docs/user/config.md`](../../user/config.md):
  the `box.toml` that `box run` writes.
