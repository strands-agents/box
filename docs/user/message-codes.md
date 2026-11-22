# Message codes

Box writes its own messages to stderr in one format, and most messages carry a code that names
their kind. This page explains each code and what to do when you see it.

## How a message reads

Each message starts with a line in this form:

```text
<source>: <severity>[<code>]: <text>
```

For example:

```text
policy: warning[P0201]: dogwood evaluation failed: <reason>; denying
```

| Part | In the example | Meaning |
|---|---|---|
| Source | `policy` | The part of Box that wrote the message. |
| Severity | `warning` | How serious the message is. |
| Code | `P0201` | The kind of message. Each code has one row on this page. |
| Text | `dogwood evaluation failed: <reason>; denying` | What happened, with the details of this case. |

A message has one of five sources:

- `strands-box`: the box's trusted process.
- `policy`: the policy engine.
- `telemetry`: the telemetry collector.
- `strands-box-sock-alias`: the alias that every interpreter and MCP program in the box runs.
- `strands-box-contain-trampoline`: the helper that applies a sandbox and then starts its program.

The last two run inside the box and write to the agent's own stderr, so the agent reads their
messages. The codes for those messages start with `H`.

A message has one of three severities:

- `error`: something failed, and the run, or the request the message names, did not go ahead.
- `warning`: something went wrong, and the run goes on.
- `note`: a statement the operator should see, such as a startup disclosure.

A line that starts with a space or a tab belongs to the message above it:

```text
strands-box: note[B0201]: [tool.check] interpreter aliases for configured access:
  alias       /bin/sh -> /usr/bin/dash  (interpreter spelling)
```

A message with no code, such as `strands-box: error: <text>`, reports an internal failure of Box.
Nothing on this page explains it. Report it as a bug, with the full stderr of the run.

A line in no other form, such as a line that a workload prints, is not a Box message.

## A coded line does not prove that Box wrote it

The format is a convention on a shared stream. It is not an authenticated channel. The processes
that the box starts, such as MCP servers and tools, write to the same stderr as the box, and any of
them can print a line that looks like a coded Box message. Do not treat a coded line as proof that
Box wrote it.

The decision log is the record of what the box decided. See [Telemetry](telemetry.md).

<a id="p01"></a>

## P01: Policy loading

The box prints these warnings when it loads a policy, and then it starts.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `P0101` | warning | A `like` pattern names the operator's home after a wildcard, so the load cannot judge what it reaches. | Spell a path under the operator's home as `~/...`. See [address spellings that refuse to load](policy.md#address-spellings-that-refuse-to-load). |
| `P0102` | warning | A `program` literal holds a path separator, so it matches only that spelling of the program. | Compare `context.input.program_path` to match the resolved binary. See [address spellings that refuse to load](policy.md#address-spellings-that-refuse-to-load). |
| `P0103` | warning | A permit's temporal clause sits beside another permit for the same principal and action, so its budget may never apply. | Write the cap as a `forbid`. See [a cap written as a permit](policy.md#a-cap-written-as-a-permit). |

<a id="p02"></a>

## P02: Policy decisions

The box denies the request that each of these messages names, and the run goes on.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `P0201` | warning | A rule errored while it decided a request, so the request was denied. | Read the reason in the text, and correct the rule. The agent receives the denial `because the request could not be evaluated.`, as [how a denial reads](policy.md#how-a-denial-reads) describes. |
| `P0202` | warning | Policy could not check a request, so it was denied as an internal fault. | When the text starts with `durable timestamp` or `an earlier outcome is not recorded yet`, correct the system clock, as [a reused box whose history and record disagree](policy.md#a-reused-box-whose-history-and-record-disagree) describes. Otherwise, report it as a bug with the full stderr of the run. |

<a id="p03"></a>

## P03: Policy history

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `P0301` | warning | Outcomes that later decisions depend on were not recorded in the policy history. | A rule that counts or reads earlier outcomes does not see these. See [history persistence and process crashes](policy.md#history-persistence-and-process-crashes). |
| `P0302` | warning | The policy history was not written to disk when it was due. | Check the disk that holds the box directory. Events that were not written can be lost if the run stops, as [history persistence and process crashes](policy.md#history-persistence-and-process-crashes) describes. |

<a id="t01"></a>

## T01: Telemetry

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `T0101` | warning | Telemetry records were lost before they reached a target. | The count is exports, not records, and the run's exit code does not change. See [errors and exit codes](telemetry.md#errors-and-exit-codes). |
| `T0102` | warning | One export of telemetry records to a target failed. | Read the cause in the text, and check the target's destination and credential. See [failed sends](telemetry.md#failed-sends). |
| `T0103` | error | A telemetry target could not be opened, so the box did not start. | Correct the `[telemetry.<label>]` table that the text names. See [errors and exit codes](telemetry.md#errors-and-exit-codes). |

<a id="b01"></a>

## B01: Refusals at startup

Each of these stops the run before the workload starts. `strands-box` exits with status `1`.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0101` | error | The configuration is not valid, so the box did not start. | Correct the `box.toml` key that the text names. See [errors](config.md#errors). |
| `B0102` | error | A filesystem grant is refused, so the box did not start. | Correct the entry that the text names. See [what is refused](config.md#what-is-refused). |
| `B0103` | error | The policy could not be read, checked, or installed, so the box did not start. | Correct the policy. See [troubleshooting load failures](policy.md#troubleshooting-load-failures). |
| `B0104` | error | A credential or secret source could not be set up, so the box did not start. | Read the line before it for the reason. See [how a run reads the secrets](config.md#how-a-run-reads-the-secrets) and [egress errors](egress.md#errors-and-exit-codes). |
| `B0105` | error | The box directory holds another box, a newer record, or history that disagrees with its record. | Remove the box directory to start again, or name a new `box_dir`. See [a reused box whose history and record disagree](policy.md#a-reused-box-whose-history-and-record-disagree) and [if something goes wrong](getting-started.md#if-something-goes-wrong). |
| `B0106` | error | The box is already running, or this process already ran a box. | Stop the other run of this box, or give this box its own `box_dir`. |
| `B0107` | error | A program the box needs is missing from its installation, or cannot be trusted. | Keep all of the Box executables from one build together. See [Linux requirements](linux-requirements.md#requirements), [macOS requirements](macos-requirements.md#check-the-installed-package), and [installation integrity](config.md#installation-integrity). |
| `B0108` | error | This host cannot harden the box's process or build its sandboxes, so the box did not start. | See [operating system and container permissions](linux-requirements.md#operating-system-and-container-permissions) on Linux, and [macOS requirements](macos-requirements.md#requirements). |
| `B0109` | error | A declared MCP server could not be prepared, so the box did not start. | Read the step that the text names. See [MCP errors and exit codes](mcp.md#errors-and-exit-codes). |
| `B0110` | error | The egress gateway or its relay failed, so the box did not start or stopped. | Report it as a bug with the full stderr of the run. |
| `B0111` | error | The socket the box's interpreters reach could not be served. | Report it as a bug with the full stderr of the run. |

<a id="b02"></a>

## B02: Startup disclosures

The box prints these before the workload starts. A note needs no action when the reach it describes
is what you intended.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0201` | note | A process reaches these paths directly, with no policy decision. | Check each path. Remove an entry from the filesystem lists if the process must not reach it. See [`[agent.filesystem]` and `[tool.<name>.filesystem]`](config.md#agentfilesystem-and-toolnamefilesystem). |
| `B0202` | note | A process's filesystem grant reaches a credential store. | Remove the grant unless the process needs that store. See [`[agent.filesystem]` and `[tool.<name>.filesystem]`](config.md#agentfilesystem-and-toolnamefilesystem). |
| `B0203` | note | A secret source runs a host program outside every sandbox, or skips a path it protects. | See [how a run reads the secrets](config.md#how-a-run-reads-the-secrets) and [what Box protects](config.md#what-box-protects). |
| `B0204` | note | The egress gateway also trusts root certificates from this host's trust store. | See [networks that re-sign TLS](egress.md#networks-that-re-sign-tls). |
| `B0205` | warning | The host's trust store could not be read, so the gateway trusts only its own roots. | A server whose certificate chains to a root on this host fails its TLS handshake. See [networks that re-sign TLS](egress.md#networks-that-re-sign-tls). |
| `B0206` | note | File watching may disclose names and event metadata outside the process's grants. | Remove `file-watching = true` if denied names must stay confidential. See [file watching](config.md#file-watching). |
| `B0207` | note | A tool's program is not installed, so the box left the tool out of this run. | Install the program, or build it, before `run`. See [a tool whose program is not installed](config.md#a-tool-whose-program-is-not-installed). |
| `B0208` | note | How a bare program name in the Shell resolves differs from what a table suggests. | See [a grammar action replaces `shell:spawn`](tool-grammars.md#a-grammar-action-replaces-shellspawn), [`monty`](config.md#monty), and [`PATH`](shell.md#path). |
| `B0209` | note | A telemetry target receives each MCP tool call's arguments and output in clear text. | Remove `mcp_tool_calls` from the target's `include` unless it must receive them. See [a tool call](telemetry.md#a-tool-call). |

<a id="b03"></a>

## B03: Lifecycle

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0301` | note | The box was created, opened, or refreshed. | No action. |
| `B0302` | note | The box starts its workload. | No action. |

<a id="b04"></a>

## B04: MCP at run time

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0401` | warning | A server's tool catalog could not be read, so its calls are decided without per-tool actions. | Read the reason in the text. See [when a rule cannot load](mcp-policy.md#when-a-rule-cannot-load). |
| `B0402` | warning | A server's per-tool policy rules did not load, so they decide none of its calls. | Check the rule's tool and argument names against the server's catalog. See [when a rule cannot load](mcp-policy.md#when-a-rule-cannot-load) and [which rules Box can refuse for](mcp-policy.md#which-rules-box-can-refuse-for). |

<a id="b05"></a>

## B05: Egress and fetch

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0501` | warning | A request through the egress gateway to an upstream failed. | Read the reason in the text. See [egress errors and exit codes](egress.md#errors-and-exit-codes). |
| `B0502` | warning | A Monty fetch was refused because no egress route reaches it. | The script's Python has no network in this box, and the request was not sent. See [`fetch()`](monty.md#fetch). |
| `B0503` | warning | A Monty fetch was refused because it names a private or local address. | The request was not sent. See the `OSError: access denied` row in [`fetch()`](monty.md#fetch). |

<a id="b06"></a>

## B06: Credentials at run time

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0601` | warning | A secret source program failed to read a secret. | Sign in to the vault or correct the reference. See [how a run reads the secrets](config.md#how-a-run-reads-the-secrets). |
| `B0602` | warning | A credential capability reported a condition that does not stop the run. | Read the condition in the text. For a bare `aws://` route, name a profile as `aws://PROFILE`. See [credential sources](egress.md#credential-sources). |

<a id="b07"></a>

## B07: Ingress

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0701` | note | A host listener is relayed to a port of the agent. | No action. See [`[[agent.ingress]]`](config.md#agentingress). |
| `B0702` | warning | Accepting a caller on a host listener failed, and the relay retries. | Read the reason in the text. See [`[[agent.ingress]]`](config.md#agentingress). |
| `B0703` | warning | The agent's port did not answer a relayed caller. | Make the agent listen on its `workload_port` on `127.0.0.1` or `0.0.0.0`. See [`[[agent.ingress]]`](config.md#agentingress). |

<a id="b08"></a>

## B08: Native filesystem policy

These apply only when native filesystem policy is on. See
[experimental native filesystem policy](native-filesystem-policy.md).

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0801` | note | This host's kernel limits what native filesystem policy can intercept. | See [Linux ARM64](native-filesystem-policy.md#linux-arm64). |
| `B0802` | warning | Native filesystem policy refused a request it cannot decide. | The workload received a permission error. See [Linux ARM64](native-filesystem-policy.md#linux-arm64) for the requests it refuses. |
| `B0803` | warning | A native filesystem request was denied because deciding it failed. | Read the reason in the text. See [macOS](native-filesystem-policy.md#macos). |
| `B0804` | note | Native filesystem enforcement is ready. | No action. |

<a id="b09"></a>

## B09: Sandbox supervisors

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B0901` | error | The namespace reaper failed, so it stopped the sandbox. | Report it as a bug with the full stderr of the run. |
| `B0902` | error | The filesystem query supervisor failed. | Report it as a bug with the full stderr of the run. |

<a id="b10"></a>

## B10: Shutdown

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B1001` | warning | Part of the box's shutdown failed. | Read the part that the text names. A failed final history flush can lose pending history, as [history persistence and process crashes](policy.md#history-persistence-and-process-crashes) describes. |

<a id="b11"></a>

## B11: Broker connections

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `B1101` | warning | The broker rejected a client of its socket. | Read the reason in the text. If it repeats, report it with the full stderr of the run. |
| `B1102` | warning | Serving a client of the broker's socket failed. | Read the reason in the text. If it repeats, report it with the full stderr of the run. |

<a id="h01"></a>

## H01: Broker refusals seen by the agent

The alias prints these on the agent's stderr when the box refuses a call.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `H0101` | error | The alias and the box speak different protocol versions. | Install the alias and `strands-box` from the same build. See [Linux requirements](linux-requirements.md#requirements). |
| `H0102` | error | The box refused a malformed frame from the alias. | Report it as a bug with the full stderr of the run. |
| `H0103` | error | A call exceeded a size or output budget, such as the stdin limit. | Send less input or output, or raise the limit in [`[limits]`](config.md#limits). See [standard input](shell.md#standard-input). |
| `H0104` | error | A call was refused because the program was busy or its input was not read in time. | Retry the call. |
| `H0105` | error | A call outlived its deadline. | Shorten the command, or raise `shell.timeout`. See [`limits.shell.timeout`](shell.md#limitsshelltimeout). |

<a id="h02"></a>

## H02: The alias

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `H0201` | error | The alias could not read its input. | The alias stopped the command and exited with status `125`. See [standard input](shell.md#standard-input). |
| `H0202` | error | The alias could not start or reach the box. | Check that the box is still running. If it is, report it with the full stderr of the run. |

<a id="h03"></a>

## H03: Ordinary programs

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `H0301` | error | No ordinary program by that name is on the agent's `PATH`. | The alias exits with status `127`. On Linux, a missing grant can hide a program. See [MCP errors and exit codes](mcp.md#errors-and-exit-codes) and [`PATH`](shell.md#path). |
| `H0302` | error | The ordinary program could not be run. | The alias exits with status `126`. A script needs a `#!` line and a visible interpreter. See [MCP errors and exit codes](mcp.md#errors-and-exit-codes). |

<a id="h04"></a>

## H04: Sandbox setup

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `H0401` | error | Applying a sandbox failed before its program started. | Read the stage in the text. See [check sandbox startup](linux-requirements.md#check-sandbox-startup) on Linux, and [check sandbox startup and the workload](macos-requirements.md#check-sandbox-startup-and-the-workload) on macOS. |
| `H0402` | warning | A sandbox's configuration carries a limit the operator should know. | When a path is both writable and executable, remove the write, because the workload can replace a program it runs. See [what is refused](config.md#what-is-refused). |
