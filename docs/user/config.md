# The `box.toml` reference

`box.toml` is the complete run configuration for one box. Pass its path through
`strands-box run --config FILE`; the tutorial's download names the binary `box`. Box reads the
selected file and its policy on every start.

Audience: an operator who runs an agent or another command under a box, and who declares the
paths, hosts, credentials, MCP servers, and telemetry targets it can use. The example on this page
is the box that [getting started](./getting-started.md) builds: the Strands CLI on a
Mac. Each section below annotates it. To write the policy the file points at, read
[policy](./policy.md), and point a coding agent at
[the policy-authoring skill](../../.agents/skills/authoring-box-policy/SKILL.md).

## Example

This release runs on macOS. Getting started builds the example one file at a time, and the block is
the tutorial's `my-box/box.toml`, with its one longer comment shortened to a line.

```toml
# To author or change the policy next to this file, point your coding agent at the skill:
#   https://raw.githubusercontent.com/strands-agents/box/main/.agents/skills/authoring-box-policy/SKILL.md

# The box's name, and where it keeps its own state. The agent can't reach box_dir.
name = "strands"
box_dir = "<HOME>/box-tutorial/my-box/state"
# The policy file, next to this one.
policy = "policy.dw"

[agent]
# The program the box starts. Node loads the preload file first, then runs the CLI.
command = [
  "/opt/homebrew/bin/node",
  "--import=<HOME>/box-tutorial/proxy-preload.mjs",
  "/opt/homebrew/lib/node_modules/@strands-agents/cli/bin/strands.js",
  # Give the agent its shell and web fetch, and no file tools, so the policy decides each file it works on.
  "--set", 'builtinTools={"*":false,"shell":true,"web_fetch":{"transport":"direct"}}',
  # Keep sessions and memory out of the project.
  "--set", 'session.dir="<HOME>/box-tutorial/strands-home/sessions"',
  "--set", 'memory.dir="<HOME>/box-tutorial/strands-home/memory"',
]
# The directory the agent starts in. This alone grants nothing.
workspace = "<HOME>/box-tutorial/my-project"
# The agent gets these variables, plus the ones the box adds. Nothing comes from your shell.
env = { AWS_REGION = "us-west-2", HOME = "<HOME>/box-tutorial/strands-home", PATH = "/usr/bin:/bin", TERM = "xterm-256color" }

# What the agent's own process can touch without asking the policy.
[agent.filesystem]
# Node loads the CLI, and the CLI reads its settings.
read = ["/opt/homebrew/lib/node_modules/@strands-agents/cli", "~/box-tutorial/strands-home"]
# Node loads the preload file, and reads Homebrew's OpenSSL settings when it starts.
read_file = ["~/box-tutorial/proxy-preload.mjs", "/opt/homebrew/etc/openssl@3/openssl.cnf"]
# The CLI writes its sessions and memory.
write = ["~/box-tutorial/strands-home"]
# The CLI lists the names in its working directory. It can't open the files itself.
list = ["~/box-tutorial/my-project"]

# The box adds your Bedrock API key to each Bedrock request; the agent gets a stand-in value.
[egress.model]
destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
secret.ref = "env://AWS_BEARER_TOKEN_BEDROCK"
```

`<HOME>` stands for the operator's home directory. The paths in `box_dir`, `command`, `workspace`,
and `env` must be absolute, and a filesystem list entry may start with `~`, so getting started
replaces `<HOME>` with `sed -i '' "s|<HOME>|$HOME|g" my-box/box.toml`.

An unknown key at any level is a load error.

## Keys

The file carries eight keys. `name` and `box_dir` are required.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Which box this is. One path component of letters, digits, `.`, `_`, or `-`, at most 32 bytes. |
| `box_dir` | string | Where the box keeps its private state. Required, and absolute. |
| `policy` | string | The Dogwood policy, relative to this file's directory unless absolute. Absent means no authored policy, and absent policy denies. |
| `[agent]` | table | The one process the box runs. |
| `[tool.<name>]` | tables | One process each, which the agent selects by invocation. The label takes the same characters as `name`. |
| `[egress.<name>]` | tables | Which secret attaches to which outbound destination. |
| `[mcp.<name>]` | tables | The MCP servers this box declares. |
| `[telemetry.<label>]` | tables | Where this box's decision records and agent spans go. |

The example uses five of the eight: `name`, `box_dir`, `policy`, `[agent]`, and one
`[egress.<name>]` table. It declares no tool, no MCP server, and no telemetry target.

`name` and `box_dir` are the two required keys. `name` labels the box in its record and its
telemetry. `box_dir` selects the box: one directory is one box. A `name` outside
its limits is refused with ``box name "<name>" is invalid: <reason>; use one component of letters,
digits, '.', '_', or '-'``.

Box creates the directory `box_dir` names, with mode `0700`, and creates **no** directory above it.
Create the parent yourself, or the run is refused with ``the box directory's parent does not exist;
create it, because Box creates no directory above the one `box_dir` names``. Everything Box writes
for a box is under `box_dir`, or under a path the file names. The example's
`box_dir` is `my-box/state`, under the `my-box` directory the operator made for the two files.

`box_dir` may not be the agent's workspace or lie below it, and neither `box.toml` nor `policy.dw`
may lie inside it. Each is refused by name: ``` `box_dir` <path> is equal to or below the agent's
workspace <path>```, ``configuration source <path> is inside `box_dir` <path>``, and ``policy source
<path> is inside `box_dir` <path>``.

The directory holds `bin`, `run`, `trust`, and `private`. None of them is a home, and no box reaches
its own private tree from inside. It stays until you delete it: end the `run` process to stop a box,
and remove the directory to delete one.

## `[agent]` and `[tool.<name>]`

Both tables hold one process, in one shape. Four fields:

| Key | Type | Meaning |
|---|---|---|
| `command` | string array | The first entry is the program; the rest are its fixed leading arguments. Arguments passed to `run` come after them. |
| `workspace` | string | The process's initial working directory. The box enters it; a `filesystem` list grants reach to it. |
| `env` | table | The literal environment. `HOME` and `PATH` default to the operator's own; every other variable is present only when `env` names it. |
| `[<table>.filesystem]` | table | The path lists the process's own system calls reach. Eight for `[agent]`; six for a `[tool.<name>]`, which has no `metadata` or `exec` list. |

The box adds the runtime minimum to every process; see
[the runtime minimum](../design/containment.md#the-runtime-minimum).

The program is an absolute path, or a bare name. A bare name resolves on `env.PATH`,
then on the operator's own `PATH`, then on `/usr/bin:/bin`. A relative path with more than one
component is refused: ``` `command` element 0 "<program>" is a relative path; write an absolute
path, or a bare name that `env.PATH` resolves```. When `command` is a script, add the interpreter
its first line names to `exec`. The example's `command` runs
Homebrew's `node`, which loads the preload file and then the CLI's script; the arguments after the
script are the CLI's own.

`workspace` is absolute, and it is optional: when absent, the box uses the directory `run` was
started from. The directory must exist, and it may not be the operator's home. The box enters it.
The process reads nothing in it until a list in `filesystem` names it: the example's `workspace` is
the project, and the `list` entry below is what lets the CLI see the names in it.

`env` is literal. Four kinds of name have their own rule:

- **Names Box sets itself, which a table cannot claim:** `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`,
  `https_proxy`, `NO_PROXY`, `no_proxy`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `NODE_USE_ENV_PROXY`, `CODEX_CA_CERTIFICATE`, `AWS_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO`, `PWD`, `USER`, and every name that starts with `OTEL_EXPORTER_OTLP_`.
- **Names that make a runtime load code, refused:** `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `RUBYOPT`,
  `PERL5LIB`, `PERL5OPT`, `GEM_PATH`, `CLASSPATH`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, and every
  name that starts with `LD_`, `DYLD_`, or `PYTHON`.
- **`HOME`:** an absolute path. It stays the operator's own home unless `[agent] env.HOME` names
  another directory; the example names `strands-home`, so the CLI reads its settings and writes its
  sessions there. A home inside `box_dir` is refused with ``` `env.HOME` is <path>, which lies in
  trusted Box state. The box directory holds `bin`, `run`, `trust`, and `private`, and none of them
  is a home. Name a directory outside it, or omit `env.HOME` for the operator's own home```, and a
  home that encloses `box_dir` is refused with ``` `env.HOME` is <path>, which encloses the box
  directory <path>. A declared home is reachable, so a home above the box directory would put this
  box's own state, and any sibling box's, inside the reachable set. Name a home beside the box
  directory rather than above it, or omit `env.HOME` for the operator's own home```.
- **`TMPDIR`:** an absolute path.

A name from the first two kinds is refused with ``` `env` name "<name>" is set by the box itself,
so a table cannot claim it```.

`TERM` and `COLORTERM` reach the process only when `env` names them, so a program that picks colors
from them renders plain otherwise. The example names `TERM`; an operator who wants a program's
colors writes their own terminal's values for both.

The agent reaches every `[egress.<name>]` route, every `[tool.<name>]`, and every `[mcp.<name>]`
the file declares. A tool or MCP server reaches every
egress route and starts no tool or MCP server of its own. All of them share one egress gateway, so
the box is the credential boundary: a process that must not hold a credential goes in another box.
Each tool and each `stdio` MCP server runs in its own separate sandbox (see
[the sandboxes for tools and local MCP servers](../design/containment.md#the-agents-box-and-leaf-boxes)).

## `[agent.filesystem]` and `[tool.<name>.filesystem]`

Each list, and what one entry in it grants. `[agent.filesystem]` takes all eight;
`[tool.<name>.filesystem]` takes six, and a `metadata` or `exec` list there is refused by name at
load. [A tool's sandbox](../design/containment.md#a-tools-leaf-box) states what a tool reaches in
their place.

| List | What each entry grants |
|---|---|
| `read` | Read the path. A directory entry covers everything below it. |
| `write` | Write the path. `write` grants write only; add the path to `read` to read it. |
| `read_file` | Read one exact file. The entry names a file. |
| `write_file` | Write one exact file. The entry names a file. |
| `list` | List the directory, and read nothing in it. The entry names a directory. |
| `metadata` | Stat everything below the directory, and read nothing. The entry names a directory. **`[agent.filesystem]` only.** |
| `exec` | Run the path. A file entry names an executable; a directory entry covers the binaries below it. **`[agent.filesystem]` only.** |
| `deny` | Refuse the path, even when another list grants it. |

The example uses four lists. `read` covers the CLI's install tree and `strands-home`, `read_file`
names the preload file and Homebrew's OpenSSL settings, `write` covers `strands-home`, and `list`
names the project. `strands-home` is in both `read` and `write`, because `write` grants write only.
The project is in `list` alone, so the CLI sees the names in it and the policy decides each file
its shell opens.

Each entry is absolute, or is `~` or starts with `~/`. An entry carries no pattern, no control
character, and no `..` component. A directory entry that encloses this box's `box.toml` and
`policy.dw` grants everything below it except the directory that holds those two files.

**An entry names the file the kernel checks**, so an entry that is itself a symbolic link is refused,
and the refusal names what the link points at. Whether a path such as `/bin/sh` is a link depends
on the surrounding OS, so the same `exec = ["/bin/sh"]` entry loads under one and is refused under
another. Write the target the refusal names.

**No policy decision covers a filesystem list**, so `run` discloses each entry on stderr before the
workload starts, under `strands-box: [agent] runs <program> with no policy decision over these
paths:`. Getting started shows the example's disclosure. A credential store, such as `~/.aws` or
`~/.ssh`, is disclosed by name as well, as `strands-box: [tool.<name>]: exposes ~/.ssh (read)` for
a tool granted the operator's SSH directory.

With no `filesystem` table, the process reaches its `command` and the runtime minimum. The
command's own exec grant is implicit: a process may always run its `command`, and the startup
disclosure shows that grant as `exec <command> (command, implicit)`. So removing a directory from
`exec` does not refuse the process's own command. The controls on a host binary are the
`shell:spawn` permit and the `[tool.<name>]` table; [shell policy](./shell-policy.md)
states how a rule spells `program_path`.

### What is refused

Every refusal below names the table and the entry, as ``` `[agent]` filesystem entry "<entry>" is
refused: <reason>```. `<path>` stands for the path the message names, and `filesystem.read` for
whichever list holds the entry. Shape refusals happen at parse; existence and identity refusals
happen after the box directory is created and before the workload starts.

| Entry | Refusal |
|---|---|
| A relative path | ``` `filesystem.read` path "<entry>" must be absolute or start with `~/`, so a checked-in configuration holds in every clone``` |
| A pattern or a control character | ``` `filesystem.read` path "<entry>" must be exact and contain no pattern or control character``` |
| A `..` component | ``` `filesystem.read` path "<entry>" carries `..`; name the path it means``` |
| The same path twice in one list | ``` `filesystem.read` path <path> is duplicated``` |
| A path that does not exist | `<path> is not there: No such file or directory (os error 2). A grant on a path that does not exist grants nothing and says so nowhere` |
| A symbolic link | `<path> is a symbolic link. A grant carries the identity the kernel checks, so a link renders a rule that matches nothing; name what it points at` |
| A spelling the kernel resolves elsewhere | `<path> is not the path the kernel checks, which is <path>. A grant carries the identity it acts on, so name that path instead` |
| A directory in `read_file` or `write_file` | ``<path> is a directory; `read_file` names one file, and a tree belongs in `read` `` |
| A file in `list` | ``<path> is a file, and `list` enumerates a directory tree`` |
| A file in `metadata` | ``<path> is a file, and a file's metadata comes with the `read_file` or `exec` grant that names it`` |
| A file in `exec` that is not executable | `<path> is not an executable regular file` |
| Two grants of one operation that name one path, or that nest | ``<path> lies inside <path>, granted by `read`. The union is the wider grant, so the narrower one enforces nothing it appears to`` |
| A grant wholly inside a `deny` entry or the directory that holds `box.toml` and `policy.dw` | `<path> is at or inside <path>, which no grant reaches. The grant would render and reach nothing, so it is refused rather than left enforcing nothing` |
| A writable grant that reaches the policy file without subtracting it | ``` `write` reaches this box's policy file, <path>. A grant may enclose it only when it is subtracted, and nothing subtracts it here``` |
| A writable grant at or above a directory on the operator's `PATH` | `<path> is at or above <path>, which is on the search path this box resolves a bare-name MCP program against. That program starts outside containment at the operator's identity, so a writable directory there is a program the workload chooses` |
| A system directory or a credential store the box always refuses | `<path> is refused beneath every grant: <reason>` |

Create the path first, or name the existing directory above it. The same rule holds for a
`[tool.<name>] command` that names a file the workload has not built yet, which is refused with
`containment config failed: path does not exist: <path>`. In the example, the CLI install,
`strands-home`, the preload file, and the project all exist before the first `run`, because the
tutorial's earlier steps made them.

**A `write` grant alone is not runnable.** The agent's sandbox refuses to map code from a writable
grant. When the agent's `command` or one of its interpreters lies inside a writable grant, the
startup disclosure carries a warning:
`strands-box: warning: [agent] command <path> lies inside the writable grant <path>, so the process
can replace the program it runs`.

## `[tool.<name>]` selection

A tool table applies when a program the agent's shell starts begins with the tool's `command`: the
same program, then the same fixed arguments. Box resolves the program to its canonical path before
it matches. The longest matching prefix wins. Every declared tool is selectable, and a
program under one of the agent's own `exec` entries needs no table of its own.

The example box declares no tool, so a program its shell names is a `shell:spawn` decision with no
table behind it, and the example policy permits none. A git tool for the CLI's shell, with git from
`brew install git`, needs `read` on the Homebrew trees git loads from, and `read` and `write` on
the project:

```toml
[tool.git]
command = ["/opt/homebrew/bin/git"]
env     = { PATH = "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM = "1", GIT_CONFIG_GLOBAL = "/dev/null" }

[tool.git.filesystem]
read  = [
  "/opt/homebrew/Cellar", "/opt/homebrew/opt", "/opt/homebrew/etc", "/opt/homebrew/bin",
  "~/box-tutorial/my-project",
]
write = ["~/box-tutorial/my-project"]
```

A `shell:spawn` permit that admits `git` goes with the table, which by itself starts nothing.

A list entry that names a credential store gives the selected tool the operator's long-lived
credential bytes. To give a tool a secret, bind it with an `[egress.<name>] secret.ref`, and keep a
tool's `env` for non-secret literals.

## `[egress.<name>]`

Each table binds one secret to a set of destinations, and its name is the operator's own label.
The example's `[egress.model]` binds `AWS_BEARER_TOKEN_BEDROCK` to the Bedrock endpoint, and `run`
reads the key from its own environment. The agent, and every tool or MCP server in the box, gets a
placeholder in that variable, and the gateway swaps the key in on each request to the destination.
A binding attaches a credential to a request the policy already permitted, and grants no network
reach of its own: the example policy's `net:connect` and `http:request` rules are what let the
requests out. The current reference for this table is
[`egress.md`](./egress.md).

| Key | Type | Meaning |
|---|---|---|
| `destinations` | string array | A host, `host:port`, a path prefix or `/*` suffix, or a `*.` wildcard. A pattern that matches every host is refused, and two entries may not overlap. |
| `protocol` | string | `http`, the default and the only accepted value. |
| `secret.ref` | string | `env://NAME` for a variable on the operator's side, `aws://PROFILE` for SigV4 signing, or `credsd://ENVIRONMENT` for a credsd environment. Required. A literal value is refused. |
| `secret.placement` | string | `header` (default), `basic_auth`, or `query_param`. |
| `secret.header` | string | The header the secret lands in. Defaults to `Authorization`. |
| `secret.prefix` | string | Text before the secret in the header value. Defaults to `Bearer ` on `Authorization`, and empty elsewhere. |
| `secret.param` | string | The query-parameter name. Required by, and only valid for, `placement = "query_param"`. |
| `secret.inject` | string | `phantom` (default) or `always`. `phantom` attaches the real secret only to a request that presents the box's placeholder, and rejects any other. `always` attaches the real secret to every request to the destinations, with or without a placeholder, and the decision record carries an advisory note. Valid only for an `env://` route. |
| `secret.phantom_prefix` | string | The literal prefix of the minted placeholder, before its random suffix. Defaults to `strands_box_`. Set it, such as `sk-ant-`, so a harness that checks its key format accepts the placeholder. At most 64 characters from `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`. Valid only for an `env://` route. |

The example takes every default: the key lands in the `Authorization` header with a `Bearer `
prefix, and only a request that carries the placeholder gets it.

An entry needs a `secret`. One without is refused: `an entry with no secret declares only a
destination, which policy already decides; give it a secret, or set protocol = "mcp" for a remote
MCP server`. `protocol` on this table takes `http` alone; declare a remote MCP server as
`[mcp.<name>]` with `type = "http"`, which the next section describes.

An `aws://` or `credsd://` route signs inside the box, so it takes no `header`, `prefix`,
`placement`, `param`, `inject`, or `phantom_prefix`. Setting one is refused: `a signed AWS secret
(aws:// or a credsd:// source) is signed in-boundary across several headers, so it takes no header,
prefix, placement, or param`. A `credsd://` reference names an environment, and an empty one is
refused: `a credsd:// reference must name an environment, as in credsd://prod-inference`.

## `[mcp.<name>]`

Each table declares one MCP server. `type` selects the transport. A `stdio` server is a local
program that the box starts in its own separate sandbox. It starts only when a `shell:spawn` permit
covers its `command`; [MCP policy](./mcp-policy.md) lists the fields that decision
carries. When no permit covers it, the open fails with `MCP server "<name>" may not start:
<decision>` and the server does not run. An `http` server is a remote
server the workload reaches through the egress gateway. Each request is an `mcp:call` decision, and a rule
reads the table's name as `context.input.server`. The current reference for this table is
[`mcp.md`](./mcp.md). The box adds the runtime minimum to the server's process; see
[the runtime minimum](../design/containment.md#the-runtime-minimum).

The example box declares no MCP server. To give the Strands CLI one, declare it here, and name the
same program under `mcpServers` in the file the CLI reads through its `--mcp-config` option. The
box places an alias with the program's name on the agent's `PATH`, so when the CLI starts
`mcp-server-fetch`, the box runs this table's `command` in a separate sandbox:

```toml
[mcp.fetch]
type    = "stdio"
command = ["mcp-server-fetch"]

[mcp.fetch.filesystem]
read = ["~/.local/share/uv/tools/mcp-server-fetch", "~/.local/share/uv/python"]
```

| Key | Type | Meaning |
|---|---|---|
| `type` | string | `stdio` or `http`. |
| `command` | string array | For `stdio`: what to start. The first entry is the program and names the alias in the box's `bin/`; the rest are its arguments, fixed here. |
| `workspace` | string | For `stdio`: the server's initial working directory. It grants nothing. |
| `env` | table | For `stdio`: the literal environment the server receives. `HOME` and `PATH` default to the operator's own, as for `[agent]`. |
| `filesystem` | table | For `stdio`: the six lists the server's own syscalls reach, the same six a `[tool.<name>.filesystem]` takes; a `metadata` or `exec` list is refused by name. An absent table grants nothing, so the server's sandbox has the runtime minimum and the reach that [a local MCP server's sandbox](../design/containment.md#local-mcp-servers) states. |
| `network.contain_egress` | bool | For `stdio`: `true` by default. `false` gives this one server direct network access, with no gateway, no policy decision per request, and no credential injection. |
| `destinations` | string array | For `http`: the hosts the server answers on. |
| `secret.ref` | string | For `http`: the credential the gateway attaches on the way out. |

No `fs:*` decision covers a `stdio` server's filesystem grants. The startup report lists the agent's
and each tool's grants, and a `stdio` server's grants are in its table alone, so read the table
before you let the server start. See [the security page](./security.md) for what `box.toml` grants
directly.

## `[telemetry.<label>]`

Each table declares one export target. The label is your own, and a refusal names it. The example
box declares none, so its decisions go to the default record file under `box_dir`, which getting
started reads with `jq`.

| Key | Type | Meaning |
|---|---|---|
| `kind` | string | `file` or `otlp`. |
| `destination` | string | For `file`, an absolute or `~/`-relative path. Inside this box's `box_dir` it must lie under `private/`; outside the box any path is accepted. For `otlp`, the collector endpoint. |
| `include` | string array | Which records reach this target: `deny`, `permit`, `trace`, `logs`, or `metrics`. `trace` names the agent's own spans **and** the box's own records together. **Absent means every one of them**, so write `include` only to narrow the target. An empty list is refused, and so is a repeated word. |
| `secret.ref` | string | `env://NAME` or `secret://NAME`, attached on the way out. |
| `secret.header` | string | Defaults to `Authorization` with a `Bearer ` prefix. |

A file destination inside the box directory and outside `private/` is refused: `"<path>" is inside
the box directory <path> but outside its private tree, where a process could truncate it; name a
destination under `private/`, or outside the box, or declare no target and take the default`. An
empty `include` is refused with `the target names no signal, so nothing would reach it; write one or
more of: deny, permit, trace, logs, metrics`, and a repeated word with `the target names deny twice`.

### `logs` and `metrics` are unconditional

`logs` and `metrics` are accepted in `include` and change nothing: every target receives the agent's
log records and metrics. `include = ["deny"]` delivers the refusals, the log records, and the
metrics.

`include` narrows `deny`, `permit`, and `trace`, where `trace` covers the agent's spans and the
box's own records.

### Agent spans, logs, and metrics need the agent's exporter

A target receives an agent span, log record, or metric only when the agent exports it. These three
`env` variables turn the OpenTelemetry exporters on. The example writes `env` as an inline table;
they go in it, or in an `[agent.env]` table, which is the same key:

```toml
[agent.env]
OTEL_TRACES_EXPORTER = "otlp"
OTEL_LOGS_EXPORTER = "otlp"
OTEL_METRICS_EXPORTER = "otlp"
```

The box sets `OTEL_EXPORTER_OTLP_ENDPOINT` to its own loopback receiver, and the OpenTelemetry SDK
appends `/v1/traces`, `/v1/logs`, or `/v1/metrics`. The box owns every `OTEL_EXPORTER_OTLP_*` name, so
`[agent.env]` may not set one. A switch left at `none` means that signal never arrives, whatever
`include` says.

Each decision exports one span of kind INTERNAL and one log record that share a trace ID and a span
ID. When the request carries a `traceparent`, the span joins that trace; otherwise it is a root span.
Each `run` adds `strands.box.run.id` to its own records and to the agent resources it relays.

### Which trace variables the box reads

The box reads `TRACEPARENT` and `TRACESTATE` from the shell or Python child's own environment, because
every harness spells those two the same way. The box reads no other variable, and it names no
harness. So a shell or Python decision reports no conversation identifier. Correlate one by
`strands.box.run.id`, or by the trace ID when the agent sets `TRACEPARENT`.

An MCP frame carries `params._meta.threadId` or `sessionId`, and an HTTP egress request carries a
`thread-id` or `session-id` header. Both lanes still report a conversation, because each reads the
identifier from its own request.

A conversation identifier is a correlation hint and never an authorization. A workload can set the
value, so no decision depends on one.

Policy spans mark the decision instant; their start and end times are equal. Normal denials have
UNSET status. Evaluator faults have ERROR status. A policy target receives both `/v1/logs` and
`/v1/traces`. Use the OTLP base URL in `destination`, and select `resourceLogs` or `resourceSpans`
when reading a file target. The scope for policy decisions is `strands-box.policy`.

Select decisions by the `strands-box.policy` scope, or by `strands.box.source == "box"`. The agent's
own log records share the `resourceLogs` key, and severity numbers do not separate the two.

### What a decision carries

A value never carries the policy engine's own spelling: read `fs:read`, not `Box::Action::"fs:read"`.
Each log record's `event_name` field is `strands.box.policy.decision`.

| Group | Keys |
|---|---|
| The decision | `strands.box.policy.action`, `.resource`, `.verdict`, `.cause`, `.reason`, `.principal`, and `error.type` on an evaluator fault |
| The governing rule | `strands.box.policy.rule` (your `@id`, else the rule reached), `strands.box.policy.description` (your `@description`), `strands.box.policy.category`, plus `strands.box.policy.determining.ids` for audit |
| Correlation | `strands.box.request.id` (egress only), `jsonrpc.request.id` (an MCP request), and `strands.box.trace.parent_span_id`, `.parent_sampled`, `.state` on the log record |
| What it was about | `server.address` and `server.port` on a `net:*` decision, `http.request.method` on a request, `file.path` on `fs:*` |

The shipped example under [`examples/strands-box/strands-sdk-agent/`](../../examples/strands-box/strands-sdk-agent/README.md)
writes a `@description` on its rules. It runs a Strands Agents SDK agent written in Python, which is
a different workload from the Strands CLI on this page.

The record omits `url.full` and `process.command_line`.

## Errors

A refusal of the file's shape happens at parse, before any box state exists: an unknown key, an
absent or invalid `name`, an absent or relative `box_dir`, an empty or relative `command` program, a
relative `workspace`, an `env` name the box owns, a relative `env.HOME` or `env.TMPDIR`, a patterned
or relative `filesystem` path, a `filesystem` path carrying `..`, a duplicated `filesystem` path, an
overlapping or all-hosts egress destination, a secretless egress entry, and a literal egress secret.

A `box_dir` whose parent does not exist is refused before anything is created. Every other refusal
that needs the surrounding OS happens after `run` has created `box_dir`, and before the workload
starts: a `workspace` that does not exist, an `env.HOME` inside or enclosing `box_dir`, a telemetry
file destination inside the box directory and outside `private/`, a `filesystem` entry whose path
does not exist or is a symbolic link, and a `[tool.<name>] command` that names a missing file. The
box directory stays behind. It is empty when the refusal came before the record was written, and it
holds the record when the refusal came after. The next `run` against it judges the file again and
reports the same refusal until the file is fixed.

A stored record whose version is not the one this build writes is refused by its version. Remove
that box's `box_dir`, and the next `run` writes a new record into a fresh one.

## See also

- [`getting-started.md`](./getting-started.md): the tutorial that builds the example box on this
  page.
- [`egress.md`](./egress.md): the `[egress.<name>]` table in full.
- [`mcp.md`](./mcp.md): the `[mcp.<name>]` table in full.
- [`policy.md`](./policy.md): the policy the file points at.
- [`security.md`](./security.md): what `box.toml` grants directly, and what you own.
