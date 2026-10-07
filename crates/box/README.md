# Box

`strands-box` runs one workload inside a zero-trust box. It composes the
four mechanism crates — policy, credentials, egress-gateway, and containment — into
one command: the workload runs under an operating-system boundary, reaches the
network only through a governed proxy, and holds no real secret.

Audience: operators running an agent or command inside a box, and Rust developers
composing over the same mechanisms.

## The Interface

A run is described completely by **four inputs**. Two are authority, one selects identity and
state, and one selects the workload:

| Input | Kind | Spelled | What it decides |
|---|---|---|---|
| Policy | authority | `policy` in the config file | Which effects this box may cause, decided per request. Scoped to this box |
| Credentials | authority | `[egress.<name>]` in the config file | Which secret is attached once a request is permitted |
| Identity and state | state | `name` in the config file | Which box this is, and where it keeps its persistent state |
| Workload | selection | `[agent] command` in the config file, and `run`'s trailing argv | Which process runs |

The caller always passes one configuration path. `[agent] command` is the complete command the box
starts. A trailing argv after `--` is **appended** to it: nothing replaces the command, and nothing
merges with it. An `[mcp.<name>]` keeps the plain name `command`, because no argv appends to an MCP
server's command.

`box_dir` is required, and it must be absolute. The box creates that one directory with mode `0700`
when its parent exists, and creates **no** directory above it: a caller who names a deeper path
creates the parent first. A symbolic link at that path, or at any child the box creates, is refused
rather than followed.

Write a complete `box.toml` and `policy.dw`. `run --config FILE` initializes or reuses the box
state and starts the workload.

```text
strands-box run    --config <file> [-- <args>...]
strands-box policy generate-schema --config <file> --output-dir <dir>
```

There are two verbs. The caller that created `box_dir` owns its lifecycle: it holds the path, so it
stops a box by ending the `run` process and deletes one by removing the directory.

`policy generate-schema` reads the MCP servers that `--config` declares and requests each one's tool
descriptions. It writes `actions.cedarschema`, with the Box action schema and each generated server
schema, and `events.dwschema`, with the event kinds available to temporal policy, into
`--output-dir`. A configuration with zero declared servers receives both canonical files. It starts
each `stdio` server outside containment, from the trusted process, which `run` never does. Runtime
policy staging uses live server discovery.

Authority reaches a box through the exact configuration and policy sources that `run` loads. A
relative policy path resolves beside the selected configuration. The policy governs **that box
alone**. Each loaded box holds its own authority, so one box's rules never decide for another.
Authored policy uses the fixed `Box::Agent::"self"` principal and
`Box::Resource::"unused"` resource.

**The edit-and-run loop replaces a separate configure verb.** Edit the selected policy
and run again: `run` re-reads the configuration, and when the files differ from the stored record
it applies them and reopens the box. There is no second verb. The durable policy-change contract
retains unchanged temporal formulas and updates changed or removed formulas. The workload cannot
provoke a change because it cannot invoke `run`, and the authority-source floor refuses mutations
to the loaded configuration and policy identities. Every run rereads the selected sources and
opens the durable engine. An unchanged run avoids rewriting stored authority and recovers its
`when temporal { … }` history. `run` never rewrites the selected files; it only reads them.

The interim `rm` and `reset` commands apply only to the legacy named namespace. They refuse a
running legacy box unless `--force` is present.

**The selected configuration is the only configuration source.** `run` accepts
`--config <file>` and reads no configuration from parent directories. The path can be relative to
the process working directory. Box canonicalizes it before use.

**The operator home is not a workspace, and `run` refuses it.** A policy scoped to
the home reads `permit fs:write … when path like "~/*"`. That reaches `~/.aws/config`, `~/.ssh`, and
every harness's stored credentials, through an interpreter that runs outside containment. The
refusal tells the operator to make a directory for the workspace and to work there, and
`the_operator_home_is_not_a_project` pins it.

The config file's complete key set is **eight**: `name`, `box_dir`, `policy`, `[agent]`,
`[tool.<label>]`, `[egress.<name>]`, `[mcp.<name>]`, and `[telemetry.<kind>]`. `name` and `box_dir`
are required. The file rejects an unknown key rather than ignoring it, so a typo is a load error, and
every removed spelling is refused by its own name with its replacement.
`four_inputs.rs::the_config_record_carries_only_the_four_inputs` pins the set, and
`run_config.rs::name_is_required_and_every_removed_key_is_refused_by_name` pins the refusals.

**Four of those eight are keys and not inputs.** The four inputs are policy, credentials, name, and
workload; a key becomes an input when it decides which requests are governed.

**`[agent]` and each `[tool.<label>]` hold the same four fields.** `[agent]` is the process the
operator starts. A `[tool.<label>]` is a process the Shell runs for a request the policy already
decided, so a tool needs no authority of its own.

Both tables hold the same four fields:

| Field | What it states |
|---|---|
| `command` | The complete command this process runs. Required. `run`'s trailing argv appends to the agent's |
| `workspace` | The initial working directory. It grants nothing |
| `env` | Variables the box adds to this process's composed environment |
| `filesystem` | The direct reach of this process's own filesystem calls |

`filesystem` holds eight lists — `read`, `write`, `read_file`, `write_file`, `list`, `metadata`,
`exec`, and `deny`. They give this process's own filesystem calls direct reach, because an
unmodified coding agent's `Read`, `Write` and `Edit` issue those calls and containment refuses every
one. A directory entry is recursive, and a file entry is exact. `write` does not imply `read`. Linux
is the residual: a writable bind reads there, and the startup disclosure says so on that entry's
line.

What a grant costs is that no `fs:*` decision records these operations, so the box prints each one
on stderr when it starts. A grant that would expose the box's own directory is refused, which
`run_config.rs::a_tool_grant_cannot_expose_the_box_directory` pins, and a command inside a writable
grant is disclosed as a warning, which `a_writable_command_is_disclosed_as_a_warning` pins.

**A `filesystem` list governs one process, and nothing else.** The agent's lists do not govern a
tool, and a tool's lists do not govern the agent. A path absent from a process's own lists is a path
that process cannot reach; it does not mean nothing in the box reaches it, because the Shell reaches
what the policy permits.

`workspace` names the initial working directory and grants nothing. The box enters it, and this
process cannot read it until a list names it, which
`box_filesystem.rs::the_workspace_is_enterable_and_unreadable_until_listed` pins. A table with no
`workspace` uses the agent's, judged by the same rules, which
`a_fallback_working_directory_is_judged_like_a_declared_one` pins.

`env` cannot claim a name the box owns: proxy routing, CA trust, the OTLP exporter family, `PWD`,
`USER`, and every loader-hook name are refused at load. `HOME`, `PATH`, and `TMPDIR` are the
operator's, so a table may declare one. An `env` value makes no path reachable.

`[mcp.<name>]` declares an MCP server. Its `type` selects the transport: `type = "stdio"` is a local
server that fixes its `command`, and `type = "http"` is a remote server that names `destinations` and
is gated through the egress gateway. For a local (`stdio`) server, MCP `Open` starts the declared
program in its own contained leaf box, once `shell:spawn` permits it. The first root `tools/list` request discovers its tools. The broker
exposes the server after its schema is accepted and the complete policy bundle is ready. Each tool
call uses its generated `<normalized-server>::Action::"<tool>"` action. Other MCP methods use
`Box::Action::"mcp:call"`.

For example, server `issues-mcp` and tool `SearchIssues` use
`issues_mcp::Action::"SearchIssues"`. Run `strands-box policy generate-schema` and copy the
exact UID from the `actions.cedarschema` it writes.

**Nothing else is an input.** The box accepts no policy flag, no box name, no proxy port, and no
mechanism value. It owns its own filesystem layout, composes the workload's
environment itself, and takes every containment grant from those four values.
`--work-dir`, `--bind`, `--read-path`, and `--home` are not box arguments; they
reach the workload as its own argv.

**MCP servers are `[mcp.<name>]` tables in the selected configuration**, one per server, each with a
`type`: a local `type = "stdio"` server names one `command` array, a remote `type = "http"` server
names `destinations`. They were a separate `.strands-box/mcp.toml`; folding them into the
selected configuration binds them to the exact authority source that `run` loaded. The authority
source floor refuses mutations by filesystem identity. Reads still require an authored policy
permit. This matters because the trusted `run` process starts the declared program **outside
containment**. The name is the table key, so it appears once.

Two properties of that table carry the design:

- **A credential declaration is not an authorization.** It says only what is attached to
  a request the policy already permitted; it can never make a destination
  reachable. An entry with no `secret` is refused, because a destination alone *would* be a
  reachability claim — which is the policy's to make.
- **The server name is policy identity.** An `mcp:call` decision reads it as
  `context.input.server`. The command's program names the executable alias, so the
  two values are not interchangeable.

## Policy

A Dogwood file — conventionally `.dw` — over fixed Box actions and generated MCP tool actions.
Dogwood is a Cedar superset, so an authored `.cedar` file loads unchanged; what `.dw`
adds is `when temporal { … }`, whose verdict depends on the history of effects already
recorded. An unknown action or undeclared attribute is a hard startup error, not a
request-time miss.

Filesystem effects authorize one of four customer-altitude actions — `fs:read`,
`fs:write`, `fs:delete`, `fs:move` — plus a reserved `fs:other`. The kernel's exact
verb rides `context.input.operation`, so a rule can permit listing a directory while
refusing to read the files in it:

```dw
permit(principal, action == Box::Action::"fs:read", resource);   // every read
permit(principal, action == Box::Action::"fs:read", resource)    // narrowed to enumeration
when { context.input.operation == Box::FsReadOperation::"enumerate" };
```

There are no group actions. A removed name — a fine per-verb name like `fs:read_content`,
or an old group like `fs:exec` — is a **hard load error** rather than a rule that matches
nothing. `fs:other` is declared and has no producer today: every kernel verb maps to one
of the four actions, and the slot is reserved for a verb upstream has not yet added. It is
its own action, so a permit written for a different verb never inherits it.

The rest of the fixed vocabulary is `Box::Action::"net:connect"`,
`Box::Action::"http:request"`, `Box::Action::"shell:exec"`,
`Box::Action::"shell:spawn"`, and `Box::Action::"mcp:call"`. MCP discovery adds one namespaced
action for each tool.

**There is no `net:response` action.** The reply is a phase of `http:request`. It takes no
decision, and one exchange records one `http:request::response` at reply time, carrying the
reply's `output.status`, so a temporal rule can count server errors; a rule cannot budget on a
reply's size.

**Four** enforcement points read the same authority, and each sees the actions it can enforce. The
egress gateway decides `net:connect` and `http:request`. The Strands Shell decides `shell:exec`,
`shell:spawn`, and `fs:*`. The Python interpreter decides `fs:*`. The local MCP broker decides
`mcp:call` and generated tool refinements. All four are adapters over the one `PolicyEngine` the
trusted `run` process holds for that box, so they share one decision history.

**A cap must be a `forbid`.** Permits combine by permit-overrides, so a second
`permit … when temporal { count < N }` scoped to a whole action grants everything the
narrower rules excluded — a budget that widens the policy:

```dw
// Wrong: this permits every command, not just the narrow rule's.
permit(principal, action == Box::Action::"shell:exec", resource)
when temporal { /* … count < 20 … */ };

// Right: composes by deny-overrides, so it can only subtract.
forbid(principal, action == Box::Action::"shell:exec", resource)
when temporal { /* … count >= 20 … */ };
```

One HTTPS call is **two** decisions: the L4 connect and the L7 request. The connect leg runs
before TLS, so it sees a host and a port and no more; the request leg runs after the gateway
terminates TLS, so it reads the method and the path.

```cedar
permit(principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "api.stripe.com" && context.input.port == 443 };

permit(principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.stripe.com"
       && context.input.method == "POST"
       && context.input.path like "/v1/charges*" };
```

The connect leg runs once per pinned address, so it is not one decision per exchange.
`http:request` is, which makes it the key for a counting rule.

The box loads the authored text and nothing else. Omitting the policy is
default-deny rather than unconstrained: an empty policy set holds no `permit`,
so nothing is reachable.

Egress is the enforced principal. The proxy asks the policy per request, and no
destination allowlist exists beside it.

## Egress targets

`.strands-box/box.toml` declares which host-side secret is attached at which
destination:

```toml
name   = "my-box"
policy = "policy.dw"        # relative paths resolve beside this file

[agent]                     # a trailing `-- ...` argv appends to `command`
command    = ["/Users/me/src/my-agent/run"]
workspace  = "/Users/me/src/my-agent"

[agent.env]
AWS_REGION = "us-west-2"

[agent.filesystem]
read  = ["/Users/me/src/my-agent"]
write = ["/Users/me/src/my-agent/target"]

[egress.stripe]             # the table key names the entry; a refusal quotes that name
destinations = ["api.stripe.com"]
secret.ref   = "env://STRIPE_SECRET_KEY"

[egress.anthropic]
destinations  = ["*.anthropic.com"]
secret.ref    = "env://ANTHROPIC_API_KEY"
secret.header = "x-api-key"

[egress.model]
destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
secret.ref   = "aws://prod"
```

| Key | Default | Meaning |
|---|---|---|
| `destinations` | required | One or more destinations this secret is attached at. Each is an exact host, a `*.` suffix wildcard, an explicit `:port`, and a path prefix or `/*suffix`. Not a regex. |
| `protocol` | `http` | What the destination speaks. `mcp` makes the gateway parse JSON-RPC frames and raise `mcp:call`; `http` is an ordinary request. |
| `secret.ref` | required | `env://NAME`, `aws://profile`, or `credsd://environment`. No other scheme. An `aws://` profile must carry **static keys**; see below. |
| `secret.placement` | `header` | Where the credential lands: `header`, `basic_auth`, or `query_param`. |
| `secret.header` | `Authorization` | The header the credential is attached under. `header` placement only. |
| `secret.prefix` | `Bearer ` for `Authorization`, else empty | Literal text prepended to the credential in the header value. `header` placement only, and carries no braces. |
| `secret.param` | required for `query_param` | The query-parameter name the credential is attached under. |
| `secret.inject` | `phantom` | When the gateway attaches the real secret. `phantom` attaches it only to a request that carries the route's phantom, and refuses any other; `always` attaches it to every request to the destinations, and warns. `env://` only. |
| `secret.phantom_prefix` | `strands_box_` | The literal prefix the minted phantom carries, before its random suffix. `env://` only, so a harness that checks its key format accepts the phantom. |

A `credsd://` reference names a daemon environment and nothing more. The box infers the credential
type from the `credential/get` response and signs the request in-boundary; today a
`session_credentials` response signs with SigV4, and any other material type fails the request. The
entry carries no credential-type key, so a `secret.type` on any scheme is an unknown key the box
refuses.

**A host pattern is not a reachability claim.** An entry says only what is
attached to a request the policy already permitted, so widening one attaches a
credential in more places and makes no new destination reachable — which is why
the pattern vocabulary is safe here. A host pattern that matches **every** host is refused, whatever its
spelling — `*` and every `*:<port>` form — because it would attach one credential to
every permitted request, including hosts the operator never considered. The refusal
asks the parsed pattern, not the text, so a suffix wildcard such as `*.example.com`
is still accepted. Two entries that could both match one request are refused at startup,
by overlap rather than by string equality, because such a request would have no
unambiguous credential.

An `env://` credential mints one phantom and places it in the workload's
environment under that name; the real secret is read by the box and never crosses
the boundary, and the proxy swaps the phantom back at the edge.

**Every process in the box gets every route.** The agent, each tool, and each MCP server receive
every phantom and every signing placeholder the box provisions. No table selects a subset, because
every process shares one gateway and the gateway cannot tell which process made a call. The box is
the credential boundary: if a process must not get a credential, put it in another box.

An `aws://` credential is a **signed route**. The box resolves the profile on the trusted side and
signs each request, so the workload holds no credential at all. It receives placeholder AWS
credentials, and the signed leg strips whatever it signed with before signing again.

**An `aws://` profile must carry static keys.** `credential_process` is **refused**, and the refusal
names the command it would have run. Honouring it means the trusted `run` process executes a program named by
`~/.aws/config`, outside containment and at the operator's uid. No floor defends that file, so a policy
permitting writes across the home would turn an agent write into trusted-process code execution.

A profile that assumes a role or uses SSO is refused too. Resolving one needs an HTTP call to STS, and
the credentials crate carries no HTTP client. Export `AWS_BEARER_TOKEN_BEDROCK` and bind that instead.

**Only `env://`, `aws://`, and `credsd://` are accepted**, and the config load refuses the rest by
name.
`file://` and `op://` resolve host-side and place nothing in the workload's
environment — which for a credential the workload must present is not a different
mode but an unusable one: the vault mints a phantom the box cannot deliver, so every
request to that destination is refused for a missing placeholder. `cmd://` and
`oauth2://` have no mint path at all. The vault still dereferences `file://` and
`op://` for callers that need one secret and no placeholder, such as an ingress
front door; this narrows the box's config surface, not the crate's.

A credential whose value is empty, only whitespace, or carrying a control character
is refused — at the config load for `env://`, and by the vault at box load for any
scheme. A value that cannot authenticate never becomes a binding.

`secret.placement` chooses where the swap happens: the `secret.header` value, the
`Authorization` header as the password half of a Basic pair, or the query parameter
`secret.param` names. A fourth placement splices the credential into the request path
and is **not available**: the policy and the audit inputs both read the path, so
`secret.placement = "url_path"` is refused by name. An `aws://` credential is
SigV4-signed inside the boundary across several headers, so it takes no header,
prefix, placement, or param, and it mints no phantom.

A route that cannot resolve is a startup error, not a bare request: a call meant
to carry a secret must not go out uncredentialed.

Refused, each at startup with the destination named:

| Entry | Refused because |
|---|---|
| `destinations = []` | An entry with no destination attaches its secret to nothing. |
| `destinations = ["*"]` | It would attach this secret to every permitted request. A wildcard needs a domain, as in `*.example.com`. |
| `destinations = ["*.*"]` | A misplaced wildcard names no destination. |
| `destinations = [""]` | A destination must name a host. |
| `destinations = ["api.test:0"]` | The port must be 1–65535. |
| `secret.ref = ""` | A destination alone is a reachability claim. |
| `secret.ref = "STRIPE_KEY"` | A bare name is not a URI. |
| `secret.ref = "env://PATH"` | The box sets that variable itself. |
| `secret.ref = "env://UNSET"` | A phantom would stand in for nothing. |
| An `aws://` secret with any other `secret` key | A signature has no single attach location. |
| `secret.header = "X-Bad: injected"` | An HTTP field name is a token (RFC 7230 §3.2.6). |
| `heder = "x-api-key"` | An unknown key is a load error, not a silent drop. |
| Two entries whose destinations overlap | Such a request has no unambiguous credential. Checked by overlap, not string equality. |

`destinations = ["*.example.com"]` and `destinations = ["api.example.com/v1"]` are
**accepted**. Both narrow which requests carry the credential, and neither makes a
destination reachable.

## Box directory and filesystem

`box_dir` selects the root and does not grant workload access. It is required and absolute. The box
creates that one directory with mode `0700`, owned by the current operating-system user, when its
parent exists, and creates no directory above it. An existing symbolic link at that path, or at any
child the box creates, is refused rather than followed. Box validates and opens the root, then uses
the opened directory identity for persistent and generated state. It generates an immutable `box_id`
and creates the children. The root persists across runs, so an agent's logins, caches, and history
persist with it. Everything below is relative to `box_dir`:

```text
bin/{zsh,bash,sh,python3,python}  0500 aliases — the interpreter aliases, prepended to PATH
run/box.sock                 the broker's one socket, connect-only
trust/cert.pem               0400, the proxy's ephemeral CA certificate
private/box.toml             0600, the stored record — never named to the workload
private/box.toml.pending     0600, the staged record a commit renames into place
private/configured           0600, the marker binding a committed record to its inode
private/policy.dw            0400, the box's copy of the policy — unreachable too
private/live.json            this box's port and the run process id, while it is running
private/.lock                the flock one run holds, which is what proves ownership
private/dogwood.redb         the durable policy history
private/alias-image.stamp    which installed image the placed aliases were copied from
private/telemetry/records.jsonl  the default destination, when no target is declared
private/containment/         one config per profile digest
private/trampoline/          the verified trampoline image, named by its digest
private/mcp/                 where a local MCP server is started
```

**The box owns nothing above `box_dir`.** There is no product directory under the operator's home,
and no namespace a verb can enumerate: a caller holds the path, so Box cannot locate a box it was
not handed.

Each declared MCP server adds one more alias to `bin/`, named for its program.

**There are four children, and none of them is a home.** `HOME` is the operator's own home unless
`[agent] env.HOME` names another directory, and the box copies no configuration into the box
directory. `box_filesystem.rs::home_is_the_operators_unless_the_agent_declares_one` pins the
default.

`private/` is the tree no profile placeholder names, which is what puts the record,
the policy copy, and the containment configs out of the workload's reach.

Distinct directories are distinct boxes and share no state. The generated `box_id` labels a box
but does not locate it.

## Workload

The program is resolved once, and the resolved path becomes the profile's single
`process-exec` literal:

- an absolute path is used as authored;
- a relative path with a separator is refused, because no directory is its root;
- a bare name is searched on this process's own declared search path.

The profile permits one literal, so a wrapper script found that way needs an `exec` grant on the
interpreter it runs. The box reads what `box.toml` gives it.

That search path is `env.PATH` when the table declares one, the operator's `PATH` when it does
not, and `/usr/bin:/bin` when neither is set. It is a resolution input, not a grant. A candidate
that is not an executable regular file is refused.

## The Shell

The workload has no host shell: the profile permits exec on the literals the box
granted and nothing else, so `/bin/sh` and `/bin/zsh` are refused by the kernel.
What it has instead is five aliases on its `PATH` — `zsh`, `bash`, `sh`, `python3`,
and `python` — each forwarding to an interpreter hosted by the trusted `run` process, which asks the
policy before parsing anything:

```text
strands-box run                        holds the box's ONE Policy
├── Strands Shell   (one per REQUEST) ─┤
├── Monty / Python  (one per REQUEST) ─┤ all on that same Policy
├── egress gateway ───────────────────┘
└── strands-box-contain-trampoline → workload
                    └── bin/{zsh,bash,sh,python3,python} → run/box.sock
```

All five aliases reach the one socket; `argv[0]` selects the interpreter.

An unmodified agent harness needs no changes — it resolves `zsh` off `PATH` and gets
the alias. `shell:exec` governs each resolved command; the Shell then resolves each
filesystem effect out of it and authorizes those individually as `fs:*`, which is
what makes an `fs:` rule enforceable rather than advisory.

**One Shell per request**
([no state crosses a call](../../docs/design/decisions.md#no-state-crosses-a-call-boundary)):
each connection builds its own, so no cwd, variable, or function crosses a request boundary,
and there is no queue or shared worker. Two runs share *authority* — one policy, one
history — never a mutable session.

The Shell runs outside the workload's Seatbelt domain, reached only over a pathname
socket, because it is a large parser fed attacker-controlled text. Four properties keep
that boundary honest:

| Property | Why |
|---|---|
| The alias image has no serving role at all | The workload can exec the alias, so a `--serve` flag would let it start its own Shell with no policy. The role is gone rather than guarded |
| The alias derives its socket from its own path | An argument would let the workload aim requests at a socket it controls |
| The hosted Shell has no network of its own | It is not behind the proxy, so egress there would bypass the only governed route |
| The Shell's binds are **not** a floor | It gets one bind per reachable root, so the scope alone withholds nothing an operator keeps there. Policy decides every operation inside them, and deny-only floors sit beneath policy. `a_snapshotted_bind_refuses_to_serve` pins that a bind which drifts from its snapshot refuses to serve |

The floors are not the bind scope. The product-state floor refuses the box product directory and
every authority source this run loaded, whatever a rule permits. The authority-source floor refuses mutations to the exact configuration and
policy identities that this run loaded. Reads of those sources still require an authored policy
permit, and an unrelated file with the same basename remains ordinary data.

The alias is a hard link to the installed `strands-box-sock-alias` when the scaffold and
the install share a filesystem, and a length-verified copy of it otherwise. Since the
scaffold lives under `$TMPDIR`, the copy is usually what happens.
`strands-box-sock-alias` must be installed beside the box executable, like
`strands-box-contain-trampoline`.

A denied command exits `126` and produces no output; a Shell failure exits `125`.
The alias never falls back to a host shell — that would run the exact command policy
was asked about.

Three facts about the hosted Shell are worth knowing.

- **The trusted `run` process is not itself OS-contained**, and it hosts the Shell beside the in-memory
  CA key and the resolved secrets. What holds is *mediation*, not a process boundary: the
  Shell asks policy before every operation, and the deny-only floors above protect the
  run process's own state whatever a rule permits.
- **Every `Shell` is `!Send`** (one `Rc` field in the vendored crate), and a command future
  is not `Send` either. So each connection gets its **own thread** and its own
  current-thread runtime. `ShellSpec` is `Send`, which is what crosses that boundary; the
  Shell is built on the thread that serves it. A non-yielding command — the embedded Lua
  interpreter — pins its own thread and nothing else. The broker serves 64 connections at
  once and reaps one before it accepts the next.
- **The vendored Shell embeds a Lua 5.4 C interpreter**, non-optionally. Its `io.popen` and
  `os.execute` bypassed `shell:exec` admission until 2026-08-08
  ([one admission point](../../docs/design/decisions.md#one-admission-point-after-resolution)). That is
  **closed**: admission moved into the one function every command-text route funnels
  through, so `find -exec` and `xargs` closed with it. `lua_popen_is_judged_by_policy` in
  `tests/box_shell.rs` is the guard, and it runs.

## The workload's environment

Composed by the box, not inherited. Box-owned values are applied last, so a
credential phantom can never displace proxy routing or CA trust:

| Variable | Value |
|---|---|
| `HOME` | The operator's own home, unless `[agent] env.HOME` names another. It grants no reach either way |
| `PWD` | The process's own `workspace`. It is the working directory, and it grants nothing |
| `USER` | `strands-box` — the operator's real username never reaches the workload |
| `PATH` | The box's alias directory, prepended to this process's own declared `PATH` |
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | The box's proxy on localhost |
| `NO_PROXY`, `no_proxy` | `127.0.0.1,localhost`, so only loopback bypasses the proxy |
| `NODE_USE_ENV_PROXY` | `1`, so a Node harness reads the proxy names |
| `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CODEX_CA_CERTIFICATE`, `AWS_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` | The proxy's ephemeral CA |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` | This box's loopback collector, and `http/protobuf`. Always set |
| one per `env://` binding | The minted phantom |

`PATH` is composed rather than owned. The box prepends its alias directory and keeps the rest, so
an alias wins a bare-name search while the operator's own tools stay resolvable. A profile still
permits exec on the literals the box granted, so a longer `PATH` advertises nothing the box will
run. `a_declared_home_and_path_win_beneath_cores_names` pins the order.

`TERM`, `TMPDIR`, `LANG`, and `TZ` are the operator's to set, in `env`.

## Running

`strands-box-contain-trampoline` must sit beside the `strands-box` executable; the box resolves it
only there and does not search `PATH`.

```sh
cargo build -p strands-box -p strands-box-containment

# Write .strands-box/box.toml and policy.dw.
cd ~/workspace/service
target/debug/strands-box run --config .strands-box/box.toml
target/debug/strands-box run --config .strands-box/box.toml -- "summarize this repository"
```

The first `run` validates the complete configuration and authority sources, creates `box_dir`, and
starts `[agent] command`. The second appends its trailing argv to that command. A later run
refreshes changed authority and launches another workload. The box directory persists until the
caller deletes it: end the `run` process to stop a box, and remove the directory to delete one.
The kernel releases the ownership lock however the run dies, so a killed run leaves no box a later
`run` cannot take.

The workload runs in its own process group with the terminal handed to it, so
job control and Ctrl-C behave as they would outside the box. `SIGINT` is
forwarded to that group; the group is terminated and the terminal restored when
the run ends, however it ends. The exit code is the workload's, or `128 + signal`
when it died from one. A containment setup failure is reported as its stage —
config read, config validation, containment apply, target environment, or target
exec — and is never confused with an authentic workload exit.

## Tests

```sh
cargo test -p strands-box --all-features
```

The credential end-to-end suite and its `box-egress-probe` workload are gated
behind the non-default `test-support` feature, so a normal build produces neither.
`tests/box_credentials.rs`, `tests/box_filesystem.rs`, and `tests/box_shell.rs` drive the
shipped binaries: they assert what the kernel, the proxy, and the shim actually did, not
what a rendered profile says. They run on macOS, and on Linux where the namespace launcher
is the selected backend and the host permits it. They are not macOS-only. Each such
assertion announces its own skip, so watch for a `skipping:` line rather than reading a
green run as a run.

`box_shell.rs` runs `/bin/bash` as its workload, because it resolves `zsh` off `PATH`
exactly as an agent harness does, so the test exercises routing without an installed harness.
It covers both directions: a permitted command routes and returns, an unpermitted one
is denied with no output, a temporal cap denies after its budget, host interpreters
are refused, the workload cannot start its own serving shim or replace the socket, and the
shim's policy is unreachable from inside.
