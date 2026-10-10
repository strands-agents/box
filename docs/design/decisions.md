# Decisions

This page records why Box is built the way it is. Each entry states one decision, the
alternative it rejected where that explains the shape, and what the decision costs you: a
limitation, a residual risk, or a thing you must not do.

> **Read this as a historical record, not as a specification.** An entry says why a choice was made,
> at the time it was made. Box keeps moving, and an entry can fall behind the code. **The code is the
> only authority.** Where this page and the code disagree, the code is right and the entry is stale.
> So use an entry to understand the reasoning, and read the named test or the crate to learn the
> current behaviour. If you find a stale entry, correcting it is welcome.

Each entry has a stable anchor. Code and other documents link an entry by that anchor, so do not
rename one.

- [Premises](#premises)
- [The box](#the-box)
- [Policy](#policy)
- [Containment](#containment)
- [Interpreters](#interpreters)
- [Egress](#egress)
- [Credentials](#credentials)
- [Telemetry](#telemetry)

## Premises

These four statements bound every other entry on this page.

<a id="the-agent-is-hostile"></a>
### The workload is hostile by assumption

Box assumes the workload runs code from an actor who wants to cause harm. An agent earns that
assumption: it runs model output, and it reads content it did not write, such as repositories, web
pages, and tool results. Box therefore grants no reach that the operator did not state, and it adds
no trust for a harness that behaves well. The cost is real: every path a harness needs becomes an
explicit grant, so a harness that starts on an open machine can fail inside a box until the operator
names what it reads.

<a id="box-protects-the-machine-not-the-box"></a>
### The sandbox protects the surrounding system from the box, and not the box from anything

The sandbox protects the operator's machine and everything that machine reaches: their files, their
credentials, and the network. The protection runs one way. Four caveats bound it. The two tiers
decide at different granularity, because operating system enforcement decides once before the first process starts
and policy decides each operation. A direct grant removes the policy decision instead of adding to
it. The workload can still name a path it cannot reach, and hand that name to the box's trusted process,
which can reach it. And some read-only locations are shared between boxes, so the sandbox closes no
side channel. Do not read a box as a confidentiality boundary for its own contents.

<a id="some-channels-never-reach-enforcement"></a>
### Some channels never reach enforcement, and the enforcing code can itself be wrong

Box states two assumptions rather than hiding them. Some channels do not pass through the
operating system enforcement or policy interfaces at all, such as hardware and timing side channels, so no
requirement in this design closes them. And the boundary is only as correct as the code that builds
it: the box's trusted process performs the containing, so nothing else contains a defect in it. Ordinary
code review is the only compensating control for the second. Read Box as a large reduction of reach,
and not as a proof.

<a id="containment-does-not-govern-authored-code"></a>
### The sandbox does not govern the code the agent writes

The sandbox governs the syscalls the workload makes itself. It does not govern code the agent writes
and then gets run elsewhere. A program the box starts on the workload's behalf, such as a host binary
or a stdio MCP server, runs in its own sandbox. Policy decides whether such a program starts, and
policy decides each later call the box makes into it, but inside that sandbox no policy decision
constrains what the program does.

## The box

<a id="the-boundary-is-the-surrounding-os-not-a-virtual-machine"></a>
### The boundary is the surrounding OS's own sandboxing, and not a virtual machine

Box contains the workload with the sandboxing the surrounding OS already has: Seatbelt on macOS, and
namespaces with a syscall filter on Linux. It boots no guest operating system and starts no
container. A microVM is the stronger isolation boundary, and Box rejects it anyway, because the
workload has to do its job in the operator's own environment, at the paths where that environment
already sits: their project, their toolchain, and their harness configuration. A guest is a second
environment to provision and keep current, and every file and every program the workload needs
becomes a decision about how it crosses in. Isolation also decides nothing on its own. Once the
workload can reach a tool, something still has to govern what it does with that tool, which is the
policy tier's job and not the boundary's. The cost is the boundary's strength: a kernel escape
defeats operating system enforcement, and no part of Box compensates for one. That residual risk belongs to
the platform's own isolation tier.

<a id="box-decides-outside-the-harness"></a>
### Box decides outside the harness, so a harness's own permission prompt is not the boundary

Many harnesses ship an allowlist and an approval prompt of their own. Box neither relies on one nor
reads one. A harness's check runs inside the agent's own process, and
[the workload is hostile by assumption](#the-agent-is-hostile), so a check there is a floor and never
a wall. It also judges the tool call rather than the effect: the harness sees "run this command", and
not the files the command opens or the hosts it reaches. Each harness states its rules in its own
format as well, so a rule written for one carries to no other. Box decides in the trusted process
instead, at the OS boundary and at the network boundary, from one `box.toml` and one `policy.dw` that
hold whatever harness the operator runs. The cost is duplication: a harness keeps prompting for what
it believes it governs, so an operator who wants the prompts gone states the same intent twice.

<a id="box-is-a-process-and-reads-one-complete-configuration"></a>
### Box is a process, and it reads one complete configuration

Box ships as a binary with no library target, so every caller starts `strands-box run` and nothing
links Box into another process. A box has four inputs: policy, credentials, a name, and a workload.
One `run --config FILE` supplies them: the file states a required `name`, a required absolute
`box_dir`, and an `[agent]` table holding `command` and `workspace`. A trailing argv appends to
`[agent] command`, a relative configuration path resolves from the process working directory, and a
relative policy path resolves beside the configuration. The process boundary keeps the composition
types private, so no caller can obtain the boundary, the trampoline, or the attachment and assemble
a weaker box. You cannot embed Box in your own process, and the workload owns stdin and stdout, so
every Box diagnostic goes to stderr.

<a id="one-trusted-process-per-box"></a>
### Each box has its own trusted process, and that process is `run`

The box's trusted process is its own `run` process. It holds that box's policy engine and temporal
history, its two interpreters, its egress gateway, its certificate authority, and only that box's
resolved secrets. There is no daemon and no supervisor. One shared process would hold every box's
plaintext secrets and signing keys in one address space, where a single memory-safety failure
reaches them all. The caller supplies the absolute `box_dir`, and the `run` process holds an
exclusive lock on `private/.lock` inside it for its whole life, so Box needs no lifecycle verbs: the
caller ends the process to stop a box, and removes the directory to delete one. Two residuals stay
open. A killed trusted process leaves the contained workload without a parent, on both platforms:
nothing in the product sets `PR_SET_PDEATHSIG`. And the deny floor covers this box's own directory
alone, so a `permit fs:read` can reach a sibling box's stored policy when both directories sit under
one parent.

<a id="one-run-owns-one-box-directory"></a>
### One `run` owns one box directory, and a second `run` refuses

A `run` holds that box's lock for the whole run. A second `run` against the same `box_dir` refuses,
and `run` accepts no `-n` or `--name` option. Two trusted processes for one box mean two policy engines
and two temporal histories, so a rule that spans `fs:*` and `net:*` loads in both and enforces in
neither, and it fails silently. The other way to keep one history is a control socket that a second
run attaches to, which is daemon complexity moved inside the box. To run two agents over one
project, supply two box directories and two complete configurations. This bounds workloads, not
requests: one box still serves many requests at once.

<a id="one-policy-engine-per-box"></a>
### A box has exactly one policy engine, in its own trusted process

Every enforcement point in a box decides on one shared policy engine instance: the egress gateway,
the Strands Shell, and the Python broker. No component opens a policy engine of its own. Two
instances mean two temporal histories, so a rule such as
`forbid net:connect when temporal { ... fs:read ... }` loads in both and fires in neither. Hosting
the enforcement points beside the one engine costs three process-level controls that cannot be
recovered in-process: `env_clear()`, a closed inherited file-descriptor table, and a separate process
group for the interpreters. It also puts the interpreters in the same address space as the in-memory
certificate-authority key and the resolved secrets. Box accepts that on the mediation the shared
engine buys, and not on any claim about how small the interpreters are. See
[the interpreters run in the box's trusted process](#the-interpreters-run-in-the-trusted-process).

<a id="a-run-validates-once-then-acts-on-the-identity-it-approved"></a>
### A run validates once, then acts on the identity it approved

One prepared run owns the box lock, one record snapshot, the workload, and one policy engine value.
`run` opens the selected configuration and policy, records the canonical path and filesystem identity
of each opened source, locks the `box_dir`, and validates the complete contract before it writes any
Box state. All later persistent and generated state operations use the opened directory identity,
and assembly rereads no mutable configuration. The loaded sources are integrity assets: the
interpreter floor refuses any operation that can change or replace that identity, including an
operation through a hard link or a symbolic link. A filename carries no authority, so an unrelated
file named `box.toml` or `policy.dw` gets ordinary policy treatment. The cost is on teardown: a
blocking generation or staging job must finish before the box lock releases, because the lock
releases last.

<a id="the-trusted-processs-memory-is-a-defended-asset"></a>
### The box's trusted process refuses another process its address space

Before the async runtime starts and before any secret resolves, the box's trusted process applies
`setrlimit(RLIMIT_CORE, {0, 0})` on both platforms, `prctl(PR_SET_DUMPABLE, 0)` on Linux, and
`ptrace(PT_DENY_ATTACH)` on macOS. Each mechanism is always on, with no operator switch, and the two
observable ones are checked by read-back: a disagreement refuses startup rather than degrading.
`PT_DENY_ATTACH` has no read-back, and its documented failure mode is to kill the caller, so Box
applies it last and does not check it. This defends against a same-user local attacker, which the
threat model deprioritizes, so treat it as defence in depth rather than a guarantee. Root bypasses it
entirely. Two costs: you cannot attach a debugger to a running box without a source change and a
rebuild, and an operator whose host raises the core-dump soft limit stops getting dumps. The macOS
cells are reasoned rather than measured, so `RLIMIT_CORE` and `PT_DENY_ATTACH` on macOS are
unverified. Swap stays open: `mlockall` is deliberately absent, because under a finite
`RLIMIT_MEMLOCK` it either locks nothing or starves the heap.

<a id="interpreters-are-brokered-aliases"></a>
### An interpreter runs beside the workload, never inside it

A contained workload finds `zsh`, `bash`, `sh`, `python3`, and `python` on its `PATH`. Each name is an
alias of one verified image, and the image forwards the request over a Unix pathname socket to the
broker in the box's own trusted process. No interpreter runs inside the workload's sandbox, and
`argv[0]` selects the interpreter before the client connects. The Python the workload gets is Monty,
a Python subset, so a script that uses unsupported syntax must fail with an error naming the
environment, not with something that reads like the script's own bug. Each alias adds one exec
literal and its paired metadata read to the generated profile, and nothing else: no wildcard, and no
directory grant. Only the agent's sandbox gets the aliases, their directory on its
`PATH`, and a connect to `run/box.sock`, where the broker listens. The broker cannot tell which process calls it, so it
judges every call as the agent. A tool's or MCP server's sandbox with a route to the broker
would therefore act as the agent. So that sandbox has no alias and cannot connect to
`run/box.sock`. Its `PATH` is its own search path alone, without the alias directory.
`boundary.rs::a_leaf_holds_no_route_back_to_the_broker` pins this. The alternative was to identify
each caller, by peer credentials or one socket per sandbox, and judge each tool or server as its own
principal. That
needs a caller identity on the frozen broker protocol and in the policy principal vocabulary. The
cost of this answer: a tool or MCP server cannot reach Strands Shell or Monty, so a bare `bash` or
`python3` in either sandbox runs the host OS's program inside that sandbox.

Each alias name is a hard link to the box's own alias image, `bin/.alias-image`, and never to the
installed image. Box places that image at the box's first run as a clone of the installed
`strands-box-sock-alias`, or as a byte copy on a volume that clones nothing. It keeps the image
across runs of the same `box_dir`, and replaces it only when the SHA-256 of the installed image
changes, which `private/alias-image.stamp` records. So the file a box executes has no name outside
that box's `bin/`, and no other box can remove a name of it. This matters because macOS Gatekeeper
kills an exec with `SIGKILL` when a name of the file under assessment disappears, and one shared
image gave every box on a host that power over every other box. Box unlinks an alias name only
while it holds the run lock and before the workload starts, which is when it reconciles a newer
installed image or a dropped MCP server, so no exec from that box's workload is in flight.
`aliases::materialize` takes the lock as an argument, and
`box_project::a_run_on_a_running_box_is_refused_before_it_touches_an_alias` pins it. Two residuals
stay: a process that escaped an earlier run's process group can still exec a name the next run
replaces, and an operator who removes a box directory while its `run` is alive still kills that box's
own execs. The cost: the host assesses one more file per box, once, at that box's first run, and it
serializes those assessments, so boxes that start together each wait for the ones before them.
`every_alias_shares_the_boxs_own_image_inode_and_not_the_installed_one` and
`a_second_materialize_reuses_the_clone_and_unlinks_no_alias` pin the layout. **Updated:**
2026-10-07.

<a id="a-box-is-one-kernel-and-many-programs"></a>
### A box is one kernel and many programs, and the socket is transport

Box names three levels and keeps them separate. The kernel is one per box: policy, temporal history,
the virtual filesystem, the credential vault, and the egress gateway, all shared, because a shared
filesystem is the correct semantics. A program is one per contained program that talks to the box:
it owns the working directory, the environment, exported variables, shell functions, aliases, file
descriptors, and background jobs, and no program observes another's. A call is one per submitted unit
of work, and it owns the deadline and the output limits, re-armed each time. Two consequences a
contributor must respect: the peer process id enters the audit record as a field and must never enter
the request, and the connection capacity no longer bounds in-flight work once one connection carries
several programs, so a second explicit cap is still owed.

<a id="no-state-crosses-a-call-boundary"></a>
### No interpreter state crosses a call boundary

The box's trusted process builds one Shell per connection and one Monty virtual machine per request, each
on the box's one shared policy engine. There is no request queue, no shared worker, and no operator
knob for cardinality. Working directory, environment, and shell functions do not survive a request,
so two runs cannot observe each other and a failure is per request by construction rather than by a
guard. Per request is the normative property, and per connection is only how the Shell reaches it
today, because it reads exactly one request per connection: if the protocol ever carries two requests
on one connection, the Shell must be rebuilt per request. Each connection runs on its own thread with
its own runtime, so a non-yielding command such as the embedded Lua interpreter pins its own thread
and nobody else's. Only a listener failure stays fatal, because with no listener there is nothing to
serve.

<a id="the-broker-protocol-is-framed-versioned-and-refuses-with-a-reason-code"></a>
### The broker protocol is framed, versioned, and refuses with a reason code

Each frame is `{version, program, frame_type, body}`, with `frame_type` in the header beside
`version` and `program`, and `body` carrying the payload alone. Framing is a 4-byte big-endian length
prefix, one frame is at most 1 MiB and the size is checked before allocation, the encoding is UTF-8
JSON with base64 for binary payloads, and an unknown field is a refusal at both the header and the
body. `exit` and `denied` are separate terminals, and a `denied` carries a fixed reason code, so a
client branches on the cause without parsing prose. One framing serves Shell, Python, and MCP, and a
future client needs no new wire format. Two costs: the header layout carries a hand-written
serializer, because flattening drops the unknown-field refusal, and base64 grows a binary payload by a
third. Both ends ship together, and the version gate refuses a stale alias image rather than
tolerating it.

<a id="a-host-binary-runs-in-a-leaf-box-and-the-policy-is-the-only-allowlist"></a>
### A host binary runs in its own sandbox, and the policy is the only allowlist

A program the Shell does not implement itself runs as a real host binary inside its own sandbox,
after a `shell:spawn` decision admits it. The authored policy is the entire allowlist: there is no
config key, no default set, and no profile entry that names permitted binaries, because a second list
over the same effect is a second authority. `shell:exec` and `shell:spawn` are decided at one point,
and dispatch then takes the path that matches the action that was judged, so the two cannot disagree.
Exit status `127` stays distinct from `126`, so "nowhere on `PATH`" and "denied" do not collapse into
one answer. No `fs:*` decision fires for anything the binary does, because it makes raw syscalls, so
its sandbox profile and the credential floor are what bound it, and one decision
covers a whole process tree, because children raise no decision of their own. The box's trusted process
starts the program in the program's own sandbox, and passes it an argument vector, an environment,
and a working directory. The program returns its response on its standard output and standard error pipes and its exit status. It has no route to the
broker, so it cannot send a second request as the agent. Its network traffic
still goes through the egress gateway, which judges that traffic as the agent.

<a id="box-derives-a-read-closure-and-refuses-to-derive-an-exec-closure"></a>
### Box derives a read closure and refuses to derive an exec closure

A read root is established by a path shape and bounded by checks Box applies itself, so Box derives
read roots and grants them. Box derives no exec literal from a runtime's own dependency graph: the exec set is the resolved
workload program, each `exec` entry, and each `#!` interpreter hop. The agent's sandbox adds the five
aliases and one alias per declared MCP server. A probe that traced a runtime's
dependency graph would have to import the code it is bounding, which runs third-party module-level
code in whichever process probes, and a dynamic trace only ever sees the paths it took. The
load-bearing reason holds however the closure is computed: the interesting helpers are universal over
authored data (`/bin/sh`, `/usr/bin/env`, `git`, a bundled agent binary inside a package tree), and a
derived allowlist would grant these with no operator decision. The cost is that a dependency which
shells out to a helper fails at the moment of the call rather than at startup, with a kernel `EPERM`
naming the path.

<a id="a-program-starts-through-its-route-and-is-granted-on-its-target"></a>
### A program starts through its route and is granted on its target

Resolution returns two values: the route as invoked, and the canonical identity the profile names.
Box execs the route, keeping the route's own final component, and authorizes the canonical identity,
because the kernel resolves the route to the identity at exec. Exec'ing the canonical identity
instead loses a virtualenv, because CPython reads `pyvenv.cfg` from the directory it was started
through. The route's directory is canonicalized even so, because Seatbelt resolves a route one
component at a time and matches a read root under its canonical spelling. Nothing is executed to learn
the install trees, because a virtualenv's `site-packages` may hold a `.pth` file that CPython runs at
startup, which would put third-party code in the process holding the certificate-authority key and
every resolved secret. The cost is real: the read root over the interpreter tree is kernel reach with
no policy decision in the path, so an operator who keeps a secret inside a virtualenv has handed it to
the agent.

<a id="one-process-spec-and-one-translator"></a>
### One process specification states every process, and one translator applies it

`[agent]`, each `[tool.<name>]`, and each stdio `[mcp.<name>]` deserialize into the same type, and one
translator takes that type with a launch role. A spec holds four fields: `command` (the program and
its fixed leading arguments), `workspace` (the initial working directory, which grants nothing), `env`
(the literal environment, with no host inheritance), and `filesystem` (the path lists the process's own syscalls reach: eight for `[agent]`, and six for a
`[tool.<name>]`, which refuses `metadata` and `exec` by name because a tool's sandbox already discovers metadata
and runs its toolchain through broad exec). Before this, the agent table and the
tool table had grown apart, each with its own grant keys and its own translation. One type makes what
a box reaches answerable from the configuration file, and one translator makes a fault in either half
a fault in both. A spec selects nothing it may use: the agent can use every tool and MCP server the
file declares, and every process gets every egress route. The reason is no attribution: the box
cannot tell which process made a request
([the box is the credential boundary](#the-box-is-the-credential-boundary)). A tool's or MCP server's sandbox has no route to the command
channel, so neither can start a tool. A declared tool is not an
authorization: it still needs its own `filesystem` entries and its own policy decisions. This is not a zero-secret guarantee: an operator who lists
`~/.gitconfig` gets what they asked for, and a `~/.gitconfig` can hold a credential helper.

<a id="home-is-the-operators-and-the-workspace-is-entered"></a>
### `HOME` is the operator's own home, and a home grants no reach

`HOME` is the operator's own home directory unless `[agent] env.HOME` names another one, and there is
no private box home. A home grants no reach at all: the workload reaches a path under it only where a
list in `[agent.filesystem]` names that path. A declared home may not lie in trusted Box state, so Box
refuses an `env.HOME` that resolves into a reserved host root, into the box directory, or through a
`.strands-box` component, and the deny floor carries no exception for a home. A per-box home lost
because it needed a copy of the harness's own configuration, it cost one harness sign-in per box, and
it made reach unreadable from the configuration file. `[agent] workspace` names the initial working
directory: Box renders one entry-only cell for it, so `chdir` succeeds and a relative path resolves
while the workload's own read and write are both refused, which
`the_workspace_is_enterable_and_unreadable_until_listed` pins. A stdio MCP server also receives the operator's
home, because it runs as the operator and looks for its session there.

<a id="direct-filesystem-reach-is-declared-and-disclosed"></a>
### Direct filesystem reach is declared in the configuration and disclosed at startup

`[agent.filesystem]` carries eight lists: `read`, `write`, `read_file`, `write_file`, `list`,
`metadata`, `exec`, and `deny`. Each entry names one host path the process's own syscalls reach, a
directory entry is recursive, a file entry is exact, there is no wildcard syntax, a path is absolute
or `~`-relative, and `write` does not imply `read`. These keys exist because an unmodified coding
agent cannot otherwise edit a file in a box: its native file tools issue direct syscalls, the sandbox
refused every one, and the agent degraded to `cat` and shell heredocs. Routing everything through the
mediated Shell instead was rejected, because it makes every native file tool dead for every
unmodified harness. These grants are kernel reach that no `fs:*` decision covers, so the startup
disclosure on stderr naming every grant is the whole compensating control, pinned by
`the_startup_disclosure_names_every_grant_and_the_home_and_path`. Box subtracts its own authority
from any grant, by path: the box directory, and the directory holding each source this run loaded
(the `box.toml` that `--config` named and the policy it names), wherever the operator placed them and
whatever they are called. Without that, a host binary the agent runs could rewrite the policy that
governs the next run. `a_project_entry_subtracts_the_directory_holding_this_boxs_authority` pins
it, and `a_config_outside_the_workspace_is_protected_by_path` pins a configuration loaded from
outside the workspace.

No directory name is special. The subtraction once keyed on the name `.strands-box` and walked every
granted tree for it, which protected a sibling box only when that box kept the default layout, and
protected this box not at all when `--config` named a file elsewhere. **A sibling box's directory
under a grant is now the operator's stated reach**, named on stderr by the grant that encloses it.
The box defends the authority it loaded, and re-checks that by identity at every spawn, which
`a_spawn_refuses_a_reach_whose_subtracted_authority_moved` pins.

Three limits to plan around. On Linux a writable bind is also readable, so `write` without `read`
holds on macOS only, and the disclosure names such an entry as readable too. On Linux, when the
authority directory sits more than one level below a write grant, the workload can rename the
ancestor between them and create a fresh directory at the vacated path, which a later run whose
`--config` names that path adopts; macOS refuses the ancestor rename, and
`this_boxs_authority_survives_a_rename_of_its_parent` records both platforms. Placing the authority
directly under the granted root, as `<project>/.strands-box` is, leaves no ancestor to rename. And a
path these lists name does not join the Shell's reachable set, so `read = ["~/vendor/sdk"]` makes the
agent's own read work while `cat` through the Shell stays refused.

<a id="the-runtime-minimum-is-two-sets-and-the-agent-takes-the-smaller-one"></a>
### The runtime minimum is two sets, and the agent takes only the smaller one

Kernel reach comes from two runtime sets plus the process's own `filesystem` lists, and from nothing
else. The `agent` set states what any process reaches whatever its configuration says: the null
device for read and write, the local time and time-zone data, an entry-only cell for `/`, metadata
cells for a few system directories, and on macOS the system library tree and the one on-disk
library Apple's libffi loads for a callback, `/usr/lib/libffi-trampolines.dylib`. Without it, a
Python linked against that libffi aborts on its first C callback. The `tool` set states what
a host toolchain additionally reaches: the entropy devices, locale and terminal data, framework and
linker-cache trees, the certificate-authority bundle directory, and the loader's library directories.
The active developer directory is in neither set: a tool that runs an Apple `/usr/bin` stub states
`read` on it in its own `filesystem` lists, which
`os_paths.rs::no_containment_reaches_the_developer_directory` pins. The agent takes the first set
only, and every tool takes both,
because a harness reads its own configuration and talks to a model, so a compiler toolchain is reach
it never uses and an attacker who reaches it does. Neither set grants an exec cell or states a denial,
and the only write in either is the null device, which
`os_paths.rs::a_set_has_no_list_for_an_exec_grant_a_denial_or_a_write_tree` and
`os_paths.rs::only_the_null_device_is_written` pin. A credential store (`~/.aws`,
`~/.ssh`, a keychain, a browser profile) is refused when a list entry encloses it, and runs with a
disclosure only when an entry names it exactly, because that entry is deliberate where an enclosing
tree is an accident. **That floor covers the process's own syscalls and nothing else.** A read through
an interpreter is a policy decision, and no credential floor sits beneath it. See
[no credential floor sits beneath the interpreters](#no-credential-floor-sits-beneath-the-interpreters).

<a id="the-agent-gets-one-exec-rule-per-grant"></a>
### The agent gets one exec rule per grant, and Box follows a script's interpreter chain

The agent gets one exec rule for its own `command` and one more for each `exec` entry, a literal for a
file and a subpath for a directory, each paired with a metadata read and never with a broad file
read. The agent never renders the broad exec form, which `the_agent_profile_never_carries_broad_exec`
pins. Box grants the interpreter chain of the one program it was told to run: it reads the program's
first bytes, follows a `#!` line to the real interpreter, repeats when an interpreter is itself a
script, and grants exec at file scope on each hop. Box derives no wider exec closure, so a program
that runs a helper needs that helper's directory in its own `exec` list. Two residual risks are
stated. Write and exec on one path is a warning and not a refusal, so a workload that can write a
path it can also run can run code it wrote there. And a granted shell can interpret workload-authored
input inside its parent's boundary, because native descendants raise no new decision.

<a id="ca-trust-is-a-per-process-environment-value"></a>
### CA trust is a per-process environment value, not a system trust store

Box composes six CA environment names for each process and sets each one to the gateway's CA:
`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CODEX_CA_CERTIFICATE`, `AWS_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
and `GIT_SSL_CAINFO`. The general alternative is one system trust store, which on macOS is the
keychain, and a contained process can neither reach nor change it. Most runtimes honour
`SSL_CERT_FILE`, but not all: `botocore` reads `AWS_CA_BUNDLE` and never consults `SSL_CERT_FILE`, and
the libcurl in Apple git reads only `GIT_SSL_CAINFO`. Setting a name a runtime ignores costs nothing,
so the rule is "every name a supported runtime reads", and the list grows when a runtime is added.
Each name is also reserved, so a table that states one is refused at startup: a workload-chosen CA
bundle is a workload-chosen trust root. A CA name is trust and never authorization, and the gateway
stays the one outbound boundary.

<a id="an-mcp-server-is-one-configuration-table"></a>
### Every MCP server is one `[mcp.<name>]` table, and its start is a policy decision

Each MCP server is one `[mcp.<name>]` table in the selected configuration, and `type` selects the
transport: `type = "stdio"` names a local server and carries `command`, and `type = "http"` names a
remote server and carries `destinations` and an optional `secret.ref`. There is no
second MCP file, and the older `[egress.<name>] protocol = "mcp"` spelling is refused with a message
that names the new one. A table header rather than an array entry means the name is stated once, and
the operator's file assigns it: the box never reads a server name from a frame, because a name the
agent can choose is a name it can borrow. A stdio server starts only under a `shell:spawn` permit,
decided on the declared program and its arguments before the process exists, so a forbid or an absent
permit leaves the server unstarted, which `absent_start_permit_refuses_the_server_and_it_never_runs`
pins. A remote credential is always a `secret.ref` locator and never a literal token, and the box never
parses a harness's own configuration file to find one.

<a id="a-stdio-mcp-server-runs-contained"></a>
### Every stdio MCP server runs contained, in its own sandbox

A sandbox for a stdio MCP server is not optional. A `type = "stdio"` entry carries the same grant
fields as any other process (`workspace`, `env`, `filesystem`), Box synthesizes one
process spec from the entry, and it runs through the one translator, so the same floors apply. The
startup disclosure does **not**: it prints for `[agent]` and each `[tool.<name>]`, and the boundary of an MCP
server's sandbox is built when the server starts, so an `[mcp.<name>.filesystem]` grant is kernel
reach that no `fs:*` decision covers and no disclosure names. A server that declares no grants still
runs contained, on the baseline every tool's and MCP server's sandbox gets. One escape exists and it is network-only: `[mcp.<name>.network] contain_egress = false` gives
that server's sandbox direct egress instead of the gateway-routed default, for a trusted client that
cannot honour `HTTPS_PROXY`. See
[native egress is an operator-declared escape from a tool's or server's sandbox](#native-egress-is-an-operator-declared-leaf-escape)
for its cost. The server's sandbox stays filesystem-contained and Box records the downgrade
explicitly. Both platforms honour the key, and Linux hands over more: that sandbox joins the host
network namespace, so it
reaches the private network, the machine's own loopback services, and the instance metadata endpoint.
`native_egress_translates_on_linux` pins that translation. The cost is that a server needs its reach
stated.

<a id="mcp-tool-schemas-are-discovered-from-the-live-server"></a>
### Box discovers an MCP tool schema from the live server's own list, for both kinds of server

`run` starts no MCP process for discovery. A declared MCP open starts its live child at that moment,
and the MCP client initializes the child through the broker. Box then reads the replies to the MCP
client's own `tools/list`, through the broker for a stdio server and through the gateway for an http
server, into one tool catalog per server. Box sends no `tools/list` of its own. A list is captured
only when its first request names no cursor and each later request names the cursor that the
previous page returned on the same connection. Box holds the reply to the last page until the schema
stages, so a client never sees a tool before its rules enforce. A list that does not change the
catalog commits nothing. A list that changes it replaces it, and a refused list keeps a stdio
server's accepted catalog. Box paging the server itself was replaced, because it made the broker an
MCP client and kept two discovery models. The cost is that a server whose client stops paging is
never staged, and its tool calls are refused. A server the MCP client never lists stays undiscovered,
and a terminal server failure stops a later open from starting another process in that run. The
broker accepts four MCP protocol revisions during `initialize`, refuses any other, and forwards
accepted initialization frames unchanged. See
[discovery serves the schema-independent subset](#discovery-serves-the-schema-independent-subset) for
what a box decides while discovery is pending.

<a id="a-client-reply-to-a-server-request-is-decided"></a>
### The client's reply to a stdio server's own request is decided as `mcp:call`

A stdio server can send its own request, such as `roots/list`, `sampling/createMessage`,
`elicitation/create`, or `ping`. The broker forwards the request to the MCP client and records its
id. The client's one reply to that id is decided as `mcp:call`, with the server and the method of the
request it answers, so a server permit admits it and a `forbid` can refuse it. A refused reply
reaches the server as a JSON-RPC error. A reply to `ping` crosses with no decision, as `ping` does,
and the server receives an empty result whatever the client put in it.
Any other response from the client is refused. Forwarding the reply with no decision was rejected,
because it opens a path from the agent to the server that no rule can close. The cost is that a
policy that permits only named methods must also name these. An http server's own requests are not
supported yet, because the gateway buffers each response and does not stream it.

<a id="remote-mcp-schemas-are-generated-through-a-direct-client"></a>
### `policy generate-schema` covers a remote MCP server through its own discovery client

`policy generate-schema` covers a remote MCP server with a Streamable-HTTP discovery client: it runs
`initialize`, captures the session id, sends the initialized notification, and reads a paginated
`tools/list` against each `type = "http"` server. A remote server's credential resolves directly
through the credentials backend at generation time, not through the runtime vault and phantom path,
because generation has no workload to protect and the egress gateway is not running. The cost:
generation makes a real network call to each remote server, so a server must be reachable and
credentialed when you generate, and a credential placement the discovery path does not support refuses
with a named error rather than guessing.

<a id="a-harness-hook-runs-only-in-exec-form"></a>
### A harness hook runs only in exec form, and Box rewrites nothing

Box rewrites no harness configuration. The operator keeps the harness configuration in a directory
that a list in `[agent.filesystem]` names, points the harness at it with `[agent] env`, and either
removes the hooks or rewrites each one to exec `<box_dir>/bin/zsh -c "<command>"`. A shell-form hook
fails, and it fails silently: every hook event reports
`EPERM: operation not permitted, posix_spawn '/bin/sh'`, nothing reaches stderr, and `run` exits 0.
Granting `process-exec` on `/bin/sh` would make it work, but the commands the hook issues would then
raise no decision, so an authored `forbid` would never see them. Once rewritten, each hook command
reaches the mediated Shell and raises `shell:exec`, and each file it touches raises its own `fs:*`. Two
limits stay: a hook that reads its payload on stdin sees nothing, because the alias forwards no input,
and plugin hooks stay broken because most of them exec a script.

## Policy

<a id="the-authored-policy-is-the-only-decision-authority"></a>
### The authored policy is the only decision authority

On every mediated path (the interpreters and egress), exactly one component decides authorization:
the policy engine, reached through the `EffectInterceptor` seam. Every other mechanism on those paths
is either a deny-only floor that policy cannot widen, which runs before policy on the network path
and after it on the interpreter path, or a mutator that carries no vote. Any code path
that could return "allowed" without asking the engine is deleted, and the types carry the rule:
`CapabilityOutcome` holds `Applied` and `Unavailable`, with no `Allow` and no `Deny`, so a capability
cannot authorize. `egress-gateway` keeps no dependency on `policy` at all. Do not add a second allow
path, and do not give a mechanism its own verdict to save a round trip.

<a id="no-connection-is-opaque-to-the-boundary"></a>
### The gateway terminates every connection, so no tunnel is opaque

An interceptor must see each request and each response effect, so the gateway always terminates TLS.
Opaque tunnelling, splicing, and raw byte copying are gone: a connection whose plaintext the boundary
cannot read could not raise `http:request`, so it would escape that authorization entirely. The
cost is direct. A plaintext or non-HTTP upstream over `CONNECT` is not reachable through the box.

<a id="the-ssrf-and-metadata-floor-is-compiled-beneath-policy"></a>
### Cloud-metadata protection is policy, and the gateway holds no destination list

Core compiles no metadata or link-local deny list and holds no opinion on which destinations to
refuse. A metadata address is refused by an ordinary `forbid` on `net:connect`'s
`context.input.ip`, which the gateway decides on each resolved, pinned address before its socket
opens, so the address decided is the address dialed and a DNS name cannot route around the rule.
Every range the former floor held is
expressible exactly as a rule: `169.254.0.0/16` as `like "169.254.*"`, `fe80::/10` as the four
prefixes `fe8`, `fe9`, `fea` and `feb` (its first group runs `fe80` to `febf`), and EC2's IPv6
endpoint as the one address `fd00:ec2::254`, not the unique-local range around it.

The cost is direct. A box carries the protection only if its policy carries the forbids, so a policy
without them can reach metadata. A new metadata endpoint is a policy change, not a Core release, and
it reaches an existing box only when that box's policy is edited.

<a id="deny-overrides-composition-with-no-compiled-rule-tier"></a>
### Composition is deny-overrides, and no rule tier is compiled into the engine

The authored sources compose into one policy set under deny-overrides. A `forbid` always beats a
`permit`, and an empty set denies everything. Every rule the engine evaluates is authored: no tier is
compiled in, because a compiled `forbid` prepended to the authored set is a floor beside policy rather
than beneath it. What no policy may open is refused below the engine by a deny-only floor. The reachable paths
check refuses the interpreters every operation on the `box.toml` and policy this run loaded, a read
included, and any change to the directories that hold them, and the sandbox subtracts those
directories from a native grant. A sibling box's directory under the reachable set is policy's to
decide, which `a_sibling_boxs_authority_passes_the_floor_and_policy_decides` pins. So express a restriction as a `forbid` that carves a hole, never as a narrower permit: adding a
permit widens, and cannot take reach away.

<a id="no-credential-floor-sits-beneath-the-interpreters"></a>
### No credential floor sits beneath the interpreters, so one broad rule reaches the operator's secrets

The interpreters see the whole operator home, and the authored policy is the only thing that decides
each access. The deny floor beneath them refuses the box's own product directories and the policy and
configuration this run loaded, and nothing else: it does not name `~/.aws`, `~/.ssh`, a keychain, or a
browser profile. The credential floor that does name those paths belongs to the sandbox, and it
governs the syscalls a process makes itself. A mediated read goes through the box's trusted process instead,
so it never meets that floor. One `permit fs:read` with no path condition therefore lets the workload
read the operator's cloud credentials, SSH keys, and source through the Shell or through Python.

This is the widest exposure in the product, and it has no compensating control today. Treat a
path-unconditional `fs:read` or `fs:write` permit as a grant of everything the operator can read.
Write every filesystem rule with a path condition, and prefer a `forbid` on the credential paths in
any policy you author. Closing this needs a deny-only floor beneath policy that carries the credential list that
the sandbox uses, which is not built.

<a id="every-decision-is-local-and-in-process"></a>
### Every decision is local and in-process

Each governed request is decided in the box's own trusted process, on every request. No network call
and no signature check sits on a decision path, because a per-decision remote call fails open during
an outage and blows the latency budget. The consequence is that there is no control plane: no signed
bundle distribution, no signature verifier, no organizational ceiling tier, no quarantine push, and no
remote authorizer. An operator distributes a policy file, and a fleet-wide change or revocation is
that operator's problem to solve outside the box.

<a id="the-engine-is-dogwood"></a>
### The policy language is Dogwood, a superset of Cedar

Policies are authored in Dogwood, a strict superset of Cedar that adds history-aware rules, and the
engine runs in the box's trusted process, one per run, with no network per decision. That placement
is fixed; the engine behind the facade is not. The Cedar crate stays pinned at an exact version,
because the schema and the request gate are Cedar types. The engine comes from the published
`dogwood-language` and `dogwood-local-engine` crates, each pinned at an exact version, so the policy
engine builds from registry dependencies alone.

<a id="a-policy-computes-no-fact-from-a-provider"></a>
### A policy computes no fact from an external provider

A policy states its conditions over the request's own typed context, and nothing else. A
`Provider::Name(args)` call aborts box startup, because this build registers no information provider. A
provider-free `guardrails { … }` clause is a tag, and the engine evaluates its condition without
calling any classifier. The box also scans no source text,
because the earlier scanners produced both false positives and false negatives. Do not reach for a
computed or model-derived fact from a rule: there is no path to one.

<a id="one-principal-one-resource-and-the-action-scopes-the-rule"></a>
### One principal, one resource, and the action scopes the rule

Every request and every history event uses `Box::Agent::"self"` and `Box::Resource::"unused"`. Three
principals collapsed into one, because the action already names the boundary that raised the request:
`net:connect` and `http:request` come from the gateway, `shell:exec` and `shell:spawn` from the shell,
`mcp:call` from an MCP stream, and `fs:*` from either interpreter. One private action identity builds
the request UID, the history event, and the observed value from one variant, so a rule and a temporal
predicate cannot name different namespaces. A policy is therefore portable and cannot depend on a box
name, but a rule also cannot discriminate by box name. Isolation comes from one engine and one history
file per box, not from an identity.

<a id="the-action-vocabulary-is-closed-and-strict-validated-at-load"></a>
### The action vocabulary is closed and strict-validated at load

The actions are `fs:read`, `fs:write`, `fs:delete`, `fs:move`, `fs:other`, `net:connect`,
`http:request`, `shell:exec`, `shell:spawn`, and `mcp:call`, plus one generated action per discovered
MCP tool. A policy names one; it cannot add one. Each action declares its own typed `context.input`,
and the resource holds no attributes, so the action and the context carry all discrimination; there is
no `context.system` and no `now`. The engine strict-validates the whole bundle at load, so an unknown
action or a mistyped attribute is a hard load error (`PolicyError::UnknownAction`) that aborts startup
rather than a rule that silently never matches. The per-request schema gate stays in `decide` even
though no caller can build a non-conforming request today: do not delete it for looking unreachable.

<a id="a-rule-that-cannot-fire-is-refused-at-load-and-an-uncertain-one-warns"></a>
### A rule that cannot fire is refused at load, and a rule that might is a warning

Strict validation catches a name the schema does not declare, and nothing else. A well-typed rule
that no request can ever match loaded, passed review, and decided nothing: a path literal spelled
absolute under the operator's home when every reported path is `~/…`, a directory spelled with a
trailing slash, one `@id` on two rules, or a rule whose only action is the reserved `fs:other`. So
the load refuses every rule it can prove inert and names the spelling to write. A finding the load
cannot prove is a warning on stderr, because an operator may mean it: a `program` literal spelled as
a path matches one spelling of the first word, and a `like` pattern that names the home after a
wildcard may match nothing. Two alternatives lost. Refusing the uncertain class too would turn a
deliberate rule into a startup failure. Warning for the provable class too, as
[write plus execute warns](#write-plus-execute-warns-and-does-not-refuse) does for a configuration
that is wider than intended, was rejected because an inert rule is not wider than intended but
absent: a `forbid` the operator relies on protects nothing while the box runs, and a warning that
scrolls past the startup disclosure does not stop the run. The cost has three parts. A policy that
loaded yesterday stops the box when a check is added. The home check judges a literal against this
operator's home, so one policy text loads on one machine and refuses on another. And a class of inert
rules stays unprovable and loads: a comparison across two enum types, and a `has`-guarded read of
`context.output` outside a temporal clause. A cap written as a `permit` is judged by what sits beside
it: beside a permit that admits the same action with no condition it is refused, because a permit
cannot narrow another permit; beside a conditioned permit for the same action it warns, because it is
inert only for the requests that permit admits; and alone it loads, because it is then a widening and
not a cap.

<a id="the-enforced-surface-is-the-whole-vocabulary"></a>
### The enforced surface is the whole vocabulary, so there are no harness actions and no risk tags

The vocabulary holds only what a real enforcement point raises. There is no `tool:invoke`,
`model:invoke`, `agent:invoke`, or credential action, and naming one is an `UnknownAction` load error.
There is no `tool_risk` context field, so no rule can gate on a declared risk level. A declared but
unenforced action must never be mistaken for a live control. Govern a tool through `mcp:call` and its
generated per-tool action instead.

<a id="filesystem-authorization-uses-four-verbs-and-a-catch-all"></a>
### Filesystem authorization uses four verbs and a fail-closed catch-all

The actions are `fs:read`, `fs:write`, `fs:delete`, and `fs:move`, with `fs:other` as a catch-all that
no rule written against the named set matches. The kernel's exact verb rides
`context.input.operation`, so a rule narrows inside an action. There are no group actions and no
`fs:exec`: running a program is a shell decision, and a test of an executable bit is a metadata read on
`fs:read`. The `PATH` walk's candidate test maps to no action at all, so a rule that counts `fs:read`
counts programs and not directory entries. A coarse permit is broad, because `fs:write` covers
`set_permissions` and `symlink`, so a precise operator adds an `operation` guard.
`every_declared_kernel_verb_rides_a_named_action_and_none_rides_fs_other` pins the mapping.

<a id="an-overwriting-rename-also-deletes-the-destination"></a>
### An overwriting rename also raises a delete on the destination

A rename is a multi-leg operation. The source and the destination each raise `fs:move`, the source
also raises `fs:read` (its bytes become reachable under the new name), and a rename onto a name that is
already bound raises `fs:delete` on the destination. Every leg must permit, and the first refusal names
its path. So a rule that protects a file's content must forbid `fs:delete` on that file as well as
`fs:write`: a `forbid` on `fs:write` alone does not stop a rename over it, and an atomic save (write a
temporary file, then rename it into place) needs `fs:delete` on the original. A dangling symlink counts
as a bound name, and on a host bind a rename onto a symlink is refused beneath policy.
`an_overwriting_rename_is_refused_by_a_forbid_on_deleting_the_destination` pins the Shell, and
`a_python_rename_onto_an_existing_file_is_refused_by_a_forbid_on_deleting_it` pins Python.

<a id="a-credential-binding-is-configuration-not-a-policy-action"></a>
### A credential binding is configuration, not a policy action

There is no credential action in the schema. An operator declares a binding in `box.toml`, and that
binding says only which secret is attached to a request the policy already permits. Reachability stays
the policy's decision alone, so a binding never opens a destination, and the two must name the same
host. There is no spelling for ambient credentials: an empty `aws://` body does not parse, because
silent pickup of whatever credentials sit in the environment is exactly what a zero-trust box must not
do. A secret rides TLS only; see [a secret rides only TLS](#a-secret-rides-only-tls).

<a id="temporal-rules-ride-the-closed-context"></a>
### A temporal rule rides the same closed context as an ordinary rule

A history-aware rule is an ordinary `permit` or `forbid` whose `when` or `unless` hosts a
`temporal { … }` block of past-only formulas, evaluated over recorded history at the decision point. A
predicate reads only the fields the action's `context.input` and `context.output` already declare,
projected onto past events by the event schema, and the event kinds are `::request`, `::response`, and
`::error`. Temporal is therefore additive: the action schema does not change, and a rule gains history
by adding a clause. One motivating rule is still not authorable: "no egress after the workload reads
sensitive data" needs a `sensitive` tag stamped on a filesystem path, and no such tag exists. A
temporal predicate also has no prefix or `like` operator, so a sensitive subtree cannot be matched on
the path instead.

<a id="temporal-rules-are-enforced-against-recorded-history"></a>
### Temporal rules are enforced, against recorded history, with no tamper claim

A `when temporal { … }` clause loads, evaluates, and denies. The guarantee is bounded: rules are
enforced against recorded history, so do not claim tamper resistance for them. A `::request` predicate
is satisfied by a denied attempt, because the request event carries no verdict, so a step-up rule keyed
on `::request` is defeated by asking and being refused. Key a precondition on `::response` instead;
`a_denied_attempt_satisfies_a_request_keyed_precondition` pins the failure mode, which is known and
open. A missing outcome event also makes a counting rule undercount and fail open. History is pruned to
the deepest authored window and the workload itself fills that window, so treat window depth as an
availability bound and not as a strength claim. A counting rule also evaluates against recorded
history and not against requests in flight, so a parallel burst can exceed a limit together while each
request passes alone.

<a id="history-is-durable-per-box-and-has-no-rewind"></a>
### History is durable per box, and it offers no rewind and no audit record

One box owns one engine, one policy source set, and one history file, and a restart reuses that file.
`open` recovers the history to a decision-equivalent state before it returns an authority, or it
returns an error: the box never starts on empty or partial history as a fallback. The engine assigns
each event a timestamp from the trusted system wall clock and a caller cannot supply one; if the clock
steps backwards, each append advances one nanosecond until it catches up, which can hold a restriction
active longer than the apparent interval. A policy edit is prospective: a temporal identity that still
matches keeps its state, and an unmatched one starts empty. The contract excludes checkpoint, rewind,
branch, tamper evidence, an audit record, atomic commit across an external effect, and any history
shared between boxes.

<a id="a-temporal-rule-names-one-action"></a>
### A temporal rule names one action, so a budget does not span a family

A temporal predicate cannot name an action group, and it has no `or` and no wildcard. Covering a
family therefore costs one clause per action. "At most N writes in five minutes" written over
`fs:write` is not consumed by `fs:move`, `fs:delete`, or `fs:other`, so the rule loads, passes review,
and undercounts while the sibling verbs spend freely. The same trap hits an exfiltration guard: one
keyed on reading content does not fire when the data leaves through a metadata read or a directory
listing. Write one clause per action, and say in the policy which actions the budget covers. A cap
must also be a `forbid`, never a second `permit`: permits combine by permit-overrides, so a capped
`permit` scoped to a whole action grants everything the narrow rules excluded.

<a id="only-trusted-enforcement-points-submit-history"></a>
### Only trusted enforcement points submit history

A trusted policy enforcement point submits the requests it evaluates. The workload never submits a
history event. Each MCP transport owns its own tool enforcement point, so the local broker and the
remote gateway must keep parsing, attribution, refinement, and history behaviour equivalent in two
trusted components. The bound is that the gateway cannot detect a remote provider that replays an
authorized request or performs extra work behind one.

<a id="there-is-no-approval-verdict"></a>
### There is no approval verdict, so no rule pauses for a human

`Decision` carries `Allow` and `Deny` only, so no rule can pause a request for a person. If human
review ever lands, the fail-closed spine is fixed in advance: a timeout, a backend error, an explicit
refusal, and a missing backend all resolve to deny, and a backend may only lift an approval the engine
already emitted, never turn a deny into an allow. Until then, gate a risky action with a `forbid` and a
second run.

<a id="mcp-authorization-is-two-gates"></a>
### An MCP tool call passes two gates, and the second is not default-deny

Coarse `mcp:call` is the MCP-layer gate, and its permit covers every method and tool on that server.
One request variant carries every method, with the server, the method, and the optional tool, prompt,
or resource identity, so a rule can gate any method on its own name. For a tool call, a generated
per-tool action refines that grant through `refine_tool_call`, at the local broker and the remote
gateway alike. Refinement is not default-deny: if the per-tool rule does not match, gate 1's allow
stands, and if no generated action exists for the tool, gate 2 is skipped. So a coarse grant is broad
by design, and a precise operator writes a `forbid` per risky tool.

<a id="four-mcp-methods-are-never-gated"></a>
### The protocol floor is narrow, and the two doors do not hold the same floor

A few methods run undecided, because a connection needs them before any rule can run. The local stdio
door holds four in `UNDECIDED_METHODS`: `initialize`, `server/discover`, `ping`, and
`subscriptions/listen`. The remote gateway holds three of those and **decides `initialize`**, so the
two doors differ and a rule can gate a remote handshake. A notification also crosses undecided at both
doors, because a frame with no `id` has no reply channel to carry a refusal. Every other method is
decided through coarse `mcp:call`, including `tools/list`, `prompts/list`, and `resources/list`, so an
operator can gate discovery and a server cannot enumerate tools a policy hides. Keep the floor at the
connection-critical set: a method the protocol needs but the floor omits denies the whole connection.

<a id="one-namespace-per-mcp-server-carries-its-generated-actions"></a>
### Each MCP server owns one namespace that carries its generated actions and types

A server's configured name normalizes into one namespace: keep ASCII letters, digits, and `_`, replace
every other character with `_`, prefix a leading digit with `_`, and append `_` to a reserved keyword.
That one namespace owns the server's generated actions and its generated input, common, and entity
types, and tool arguments stay typed under `context.input`. Staging refuses a fragment whose
declarations reach outside its own namespace, and refuses any fragment that claims `Box`, which is
reserved for the built-in schema. Two different server names can normalize to the same namespace, so
generation and composition refuse the collision. The authored server name and its namespace can differ
in punctuation.

<a id="generated-argument-types-are-lowered-so-a-rule-compares-plain-values"></a>
### Generated argument types are lowered, so a rule compares plain values

A tool's JSON schema uses shapes the policy language has no native form for, so the generator lowers
them: an `enum` field drops the enum and keeps its base type, a number or float becomes an integer, and
a nullable `["X","null"]` collapses to `X`. The runtime then types the raw JSON against the lowered
fragment, so a rule writes a normal comparison on a plain value. Wrapping the value into an enum entity
at runtime was rejected, because an enum entity cannot be compared to a string. The lowering is lossy:
the schema no longer enforces an enum's allowed-value set, so a rule and not the type restricts values.
Union types and a standalone `null` are not lowered and cannot take a bare value.

<a id="discovery-serves-the-schema-independent-subset"></a>
### While MCP discovery is pending, the box serves the schema-independent subset

`open_staged` parses the authored bundle once and installs every rule that validates without a
discovered schema, which covers `net:connect`, `http:request`, the filesystem and shell actions, coarse
`mcp:call`, and name-level or method-level MCP rules. The box decides normally in that state, so there
is no deny-all startup window and the model stays reachable while catalogs load. The only request held
is a tool call whose per-tool typed action is still pending: it returns a transient pending denial that
the caller may retry, and never a silent allow, so an out-of-band call cannot slip past an argument
constraint. Each accepted schema installs a fuller set, and the last one makes the authority ready.
Every install retains unchanged policy identities and their temporal state, so an incremental install
replays no history.

<a id="a-server-whose-discovery-a-policy-denies-degrades-alone"></a>
### A server whose discovery a policy denies degrades alone

A policy can deny `tools/list` for a server and still carry a per-tool rule for it. The typed rule can
only come from that server's discovered catalog, so it can never be enforced. The box starts anyway and
degrades that one server: it connects with zero tools, its typed rule is inert, and its tool calls deny
fail-closed, so a hardcoded call cannot ride the coarse permit with its argument constraint unenforced.
A loud diagnostic on stderr and a telemetry record name the server and the inert rule. Refusing the
whole policy at load was rejected, because it took the model, the shell, and every other server down
over one server's mistake. The cost is that `validate` does not report the contradiction, so a reader
learns of it from the run's warning.

<a id="the-policy-crate-exposes-one-facade"></a>
### The policy crate exposes one facade

`PolicyEngine` is the one public authority, with the lifecycle `open`, `decide`, `record`, and
`effective`. The engine, the event mapping, the request gate, the staged-authority transition, and
every engine-library type stay private, so an enforcement adapter cannot skip parsing, composition, or
strict validation. The rule proved itself: the authorizer moved from Cedar to Dogwood and no consumer
signature changed. An adapter may narrow a verdict and must never manufacture an allow. A new engine or
loading profile needs a change inside the crate, and a public extension point needs a named external
consumer before it is added.

<a id="the-observation-seam-is-write-only"></a>
### The one observation seam is write-only

`DecisionObserver` is public and `observed_by` installs one, as a consuming setter, so one observer sees
the authority's whole life. Four properties make it an output of a decision and not an input to one:
`observed` returns nothing, it runs after the operation has already selected its verdict, it receives
the action and resource already extracted instead of the request, and it receives no principal. An
observer therefore cannot alter, veto, or delay a verdict, and a failing observer cannot fail a
decision. An observer must not block, await, or perform input or output, because it runs inside a
decision operation; the type cannot enforce that, so it is a contract you must honour. An enforcement
point can still narrow the value an observer saw, so do not treat the observer as the box's audit
source.

<a id="the-effective-policy-report-is-diagnostic-not-an-attestation"></a>
### The effective-policy report is diagnostic, not an attestation

`EffectivePolicy` reports the engine identity and a policy label. Treat that label as diagnostic and
never as an attested digest: it is not a content hash and not a verified bundle revision, so the report
cannot prove which policy text ran. Any run gate of the form "refuse to run unless registered and
baseline-satisfied" belongs to the caller, because only the caller sees every input the gate needs. A
security evaluator should read this report as a label and verify the policy file itself.

<a id="a-reviewed-example-library-is-the-authoring-floor"></a>
### A maintained library of reviewed example policies is the authoring floor

The box is deny-by-default, so an operator must state every allowed action before the workload can act,
and writing that allow-list is a product surface. The box ships and maintains a library of reviewed
example policies, and both authoring modes rest on it: a human reads and edits from it, and a local
agent uses it as source material to turn an intent into a policy. Documentation alone was rejected,
because it faces every author with a blank file. Agent generation alone was rejected, because it
strands an operator who runs no agent and leaves review without a trusted reference. The cost is a
standing maintenance burden: the examples and the authoring skill must track the action vocabulary as
it moves.

## Containment

<a id="box-owns-its-containment-code"></a>
### Box owns its containment code

Box writes and owns its containment crate. It takes no runtime dependency on an external sandbox
project, and it does not fork one. The cost is that Box owns platform correctness, conformance
coverage, and incident response for a security boundary. In exchange Box can remove behaviour it
cannot enforce, and patch enforcement directly.

<a id="containment-is-fixed-and-built-without-running-a-program"></a>
### Box builds the sandbox grants without running a program, and fixes them for the box's life

Box reads its configuration inputs and writes the sandbox grants. It runs no program to
author one. It does not run the operator's named runtime to learn its version or its location, for two
reasons: running a program to inspect it is still running it, and that run would happen before the
boundary exists, so a tampered runtime would run with the operator's full reach. The operator states
every path and version up front. The configuration then never changes while the box runs, and no
process inside or outside it can make it less strict. Two costs: a wrongly stated path fails the start
inside the boundary instead of producing an earlier, friendlier warning, and the contract does not say
what happens if a mechanism detaches while the box runs.

<a id="the-closed-choice-is-the-default"></a>
### An omitted field keeps the closed default

A new set of sandbox grants carries no filesystem grants, no socket grants, blocked network,
isolated signals and process information, inter-process communication limited to shared memory, and no
backend override. An omitted field keeps that baseline. So a caller that forgets a field gets the
closed choice, and never a wider one.

<a id="every-failed-or-unsupported-apply-refuses-the-workload"></a>
### Every unsupported or failed apply refuses the workload

Host detection, backend selection, support checks, validation, and the kernel apply all happen inside
one call, and any error there means the workload does not run. There is no warning-only mode, no
automatic weaker backend, and no uncontained fallback. Box also refuses to run when it cannot verify
that the sandbox is in place for this box. The cost is on the operator: a platform or an architecture Box
cannot enforce on stays unsupported until a mechanism covers it, and the operator gets a refusal rather
than a degraded box.

<a id="the-linux-boundary-is-namespaces-not-landlock"></a>
### The Linux boundary is namespaces and a syscall filter, and never Landlock

On Linux, Box builds the boundary from namespaces, a mount view, and a syscall permit filter. Box
rejects Landlock as the baseline, because no Landlock right denies all network at any ABI version, so a
contained child would keep unrestricted network. Box also probes no kernel ABI version: a gate on a
probed version once refused every kernel Box ships on. Platform and architecture alone select the
mechanism: macOS selects Seatbelt, Linux selects the namespace launcher on ARM64, and Box refuses every
other Linux architecture by name.

<a id="containment-ends-with-the-contained-process"></a>
### The sandbox ends with the contained process

Apply is one irreversible transition on the calling process. It lasts until that process exits, and
the process's descendants inherit it. There is no lifecycle handle, no teardown call, no checkpoint,
and no recovery call. The cost lands on the caller: a supervisor owns the working directory, the
environment, termination, and durable state, because the sandbox owns none of them.

<a id="children-inherit-the-boundary"></a>
### Children inherit the boundary, and no call widens it

Every process created after a successful apply is bound by at least the same boundary, for every
generation the box runs, and program replacement keeps it. No call elevates a child. A process that
needs different reach needs a different configuration and a fresh contained process, and applying
twice widens nothing. Process creation is granted with no limit, so the sandbox does not bound fork
bombs, disk fill, or CPU consumption.

<a id="one-private-backend-enforces-the-whole-configuration"></a>
### One private backend enforces the whole configuration

A caller declares one set of sandbox grants and selects no mechanism. Apply detects the
surrounding OS privately, chooses one backend, and requires that backend to enforce the whole request.
The backend traits, the backends, and the detection stay crate-private, so no caller can ask for a
weaker mechanism or a partial apply. A product that wants visible protection tiers must define them
above operating system enforcement, because it offers none.

<a id="containment-evaluates-no-policy"></a>
### The sandbox applies its grants and evaluates no policy

The containment crate enforces a caller-supplied configuration. It evaluates no authorization policy,
and it imports no policy engine, no principal, and no product identifier. The dependency direction is
one way: a policy layer builds a configuration, and then calls containment. Two authorities would give
two answers to one question, so the authored policy stays the only authorizer, and containment stays a
deny-only floor beneath it.

<a id="one-trampoline-spawns-every-contained-process"></a>
### One owned, process-agnostic trampoline spawns every contained process

One small program applies the sandbox and then execs the target, and one grammar serves every caller:
a configuration file, a digest over it, the target environment as JSON, optional status and control
descriptors, and then the command. It is process-agnostic, so nothing about a particular workload lives
inside it. Its exit codes separate three failures: a setup error before the sandbox applies, a failed apply,
and a contained process whose environment decode or exec failed.

<a id="the-configuration-crosses-exec-as-digest-bound-json"></a>
### The configuration crosses the exec boundary as an inherited descriptor, bound by a digest

Box serializes the complete request, writes it to a file the target is not granted, computes a digest
over those exact bytes, and passes the open descriptor to the trampoline. The trampoline reads the
inherited descriptor and not the name, so replacing or truncating the file after the box opened it
changes nothing that applies. A digest failure or a load failure stops apply and exec, so a swapped
configuration becomes a refusal rather than a weaker boundary.
`config_load_returns_exact_bytes_and_keeps_the_caller_owned_file` and
`inherited_config_read_uses_the_opened_file_after_a_path_swap` pin the two halves.

<a id="a-grant-is-one-operation-at-one-scope"></a>
### A grant is one operation at one scope, and eight combinations are unrepresentable

A grant states one operation (exec, read, write, connect, list, metadata, or deny) at one scope (one
file, one directory, or a whole tree). Eight combinations are unrepresentable rather than refused later,
so no backend ever receives a pair it cannot render: a directory has no bytes to execute, a file has no
entries to enumerate, and a socket grant names one existing file. Metadata is the cell for a path the
workload stats and never reads, and exec at whole-tree scope authorizes every program in a named
toolchain directory. Read plus write is membership in two lists, so write does not imply read, which is
the consequence an operator meets daily. A grant states what it authorizes and never who asked for it.

<a id="the-configuration-is-its-own-wire-format"></a>
### The configuration is the wire format, and there is no mirror type

The configuration type serializes and deserializes directly. Every field that holds an invariant
revalidates on load: a path grant re-runs its validated constructor and refuses a drifted resolved
path, and the network field re-runs the builder's port checks. Unknown keys are refused at every level, and a
missing key is an error except for one additive field that only a tool's or MCP server's sandbox
sets. Its default is the closed value, so an older trampoline reading a newer configuration gets the
agent posture rather than the wider tool-and-server posture. A parallel set of spec types that only
restated the model is a second copy of the model that drifts from it silently, so there is none. A
refusal reaches the operator as the serializer's parse-error text, reported verbatim.

<a id="localhost-names-the-ports-the-workload-reaches"></a>
### Loopback network access names the ports the workload reaches, and no count bounds them

The loopback network mode carries two lists, one for outbound connect and one for listen. Only
`connect` renders: both backends refuse a non-empty `listen`, so an inbound bind is an unimplemented
field and not a capability. An empty connect list is refused, because a mode that reaches nothing
states something it does not carry, and a repeated entry is refused. No count bounds the lists, because
a limit there would refuse a composition the caller authorized, at a layer that cannot see what was
asked for. What stops the list becoming a destination allowlist is that every entry is loopback and
policy still decides each request.

<a id="a-denial-is-an-operation-not-a-second-list"></a>
### A denial is an operation, not a second list

A caller that must grant a directory holding something it does not own states two entries: the grant,
and a denial on the same path type, in the same list. There is no second type and no second wire key.
A denial wins over every path grant, in any order the caller stated them, and it is exempt from the
bounding floors, because a denial hands over nothing. It is the only entry that may name a path that
does not exist, because a harness configuration directory is commonly absent and a grant enclosing its
future location must still be subtracted. It is legal at file scope and whole-tree scope and refused at
directory scope, because a directory's own entry alone would leave its contents reachable. The
guarantee covers the denials known at launch, so a hard link to a refused object, and a box state
directory created after launch, stay residual risks.

<a id="an-opened-file-can-require-identity-or-write-protection"></a>
### An opened file can require identity, or write protection, and the two are separate

A caller can load authority before the sandbox applies, for example a certificate bundle. It passes the
opened regular file and its canonical path to one of two configuration methods. Both record the device
and inode, require the file to have one filesystem name, and revalidate path and identity at each
backend's last safe point. One method also subtracts writes, for a file that sits below a wider
writable grant; the other grants no access at all, for a file outside every writable grant. A backend
that cannot keep both the write subtraction and write-xor-execute may make the file non-executable, so
a caller must not use write protection to preserve an execute grant.

<a id="the-deny-only-floors-run-beneath-every-backend"></a>
### The deny-only floors run beneath every backend, in one module

One module holds every check that judges a grant set, and one function is its only caller, so each
check runs beneath every backend instead of inside some of them. The checks run in cost order: the pure
checks read only recorded values and run first, and the check that re-resolves a path on the filesystem
runs last. A grant naming the root is therefore refused without a single canonicalization, which
matters because a grant's path can be workload-influenced, and refusing it must not require acting on
it first. Three refusals carry the weight: no grant may reach a forbidden path; two writable entries that nest
are refused, because the inner grant enforces nothing it appears to; and an `Exec` grant on a setuid or
setgid file is refused, walking a whole tree at root scope without following a link, which is the only
code-level enforcement of no-escalation for an exec grant.

<a id="write-plus-execute-warns-and-does-not-refuse"></a>
### Write plus execute on one path warns, and does not refuse

An operator who names one directory in both a write list and an exec list gets a warning at startup,
and the box still runs. A refusal was wrong for a real build, which loads and runs what it compiles.
The warning names the executable and the write grant that reaches it. The cost is stated rather than
hidden: an operator who reads the warning and continues leaves that program replaceable by the
workload.

<a id="one-forbidden-path-list-and-each-row-states-its-rule"></a>
### One forbidden-path list, and each row states its own match rule

One list states every path no grant may reach. A row holds four fields: an anchor (absolute, or
relative to the operator's home), a match rule, the cells the row lets through, and a class that
supplies the reason an operator reads in the refusal. The class is also the exemption gate: a
credential store is the one class an operator can name exactly and punch through, and
`only_a_credential_store_row_is_exemptible` pins that nothing else can. The match rule takes no default, because the two rules fail in opposite
directions: exact match under-refuses silently, and overlap match over-refuses loudly. A row's
permitted cells carry one authority, which is that a workload may stat what it cannot read, and every
new row refuses all cells until somebody names one. This one list replaced a second credential-path
list another crate held, because two lists with two owners produce the one dangerous state of a path in
neither. A misclassified row is a residual risk that only one case table over the whole list can catch.

<a id="a-caller-adds-a-floor-anchor-and-never-moves-one"></a>
### A caller adds a floor anchor and can never move one

The floor anchors every home-relative row at the account database home, and a caller resolves its own
grants against the environment's home. The two can differ, under a preserved-environment `sudo`, a
container, a CI runner, or a test fixture. So the configuration carries the home the caller resolved
its grants against, and the floor resolves every row over the union of that home and the account
database home, which is always present. Adding an anchor is monotone: each anchor contributes refusals
and removes none, so a caller that names a wrong or hostile home widens the refusal set and can never
narrow it. A caller that declines to state its home gets the account database anchor alone, and the
floor cannot detect that.

<a id="the-operating-system-states-its-own-paths-as-data"></a>
### The operating system states its own paths as data, not as code

The paths every process needs from the surrounding OS, and the paths no grant may reach, live in data
files in the containment crate. One file per platform states two grant sets: what any process needs to
load and run, and what a host toolchain needs in addition. A third file states every forbidden row. The
grant sets are per platform, because one cross-platform list would grant paths on Linux that a Linux
workload must not receive. The forbidden rows carry both platform spellings on every host, because a
configuration authored on one platform can be applied on another. A malformed file panics at first
use, which is correct because the data is compiled in.

<a id="a-direct-grant-replaces-the-policy-decision"></a>
### A direct grant replaces the policy decision, and does not add to it

An operator can expose a surrounding-OS file or directory tree to the workload directly. The workload
then reaches it with its own syscalls, so no policy decision fires for that access and no record of it
exists. Box keeps no second positive allowlist of paths an operator may grant: the deny-only floors are
the whole bound, and they still refuse a protected path. Both sets start empty, and each entry needs
explicit operator action. A broad read grant can expose source, configuration, or a credential the
floor does not name, and a broad write grant can corrupt host state or alter an input another process
reads.

<a id="resolve-the-path-once-then-act-on-the-object"></a>
### The box's trusted process resolves a path once, then acts on the object it resolved

The box's trusted process resolves any path the box supplies before it decides, and then acts on the object
it resolved, holding that object across the decision. It refuses a symlink met during resolution, and
it refuses any component that leaves the set it resolved within. It never walks a path a second time
after deciding. A name is not an object, and two walks of one name can reach two objects, so a decision
on one string and an action on another turns the box's trusted process against the boundary it enforces. "A
path the box supplies" means every path derived from anything the box controls, including argv, the
working directory, an environment value, and a path inside a file the box wrote.

<a id="a-denial-names-the-rule-that-refused-it"></a>
### A refusal names the component, the reason, and the rule that decided

A denied request tells the workload which component rejected it, why, and which rule decided. The
alternative was one generic refusal, so a workload could not probe operations and rebuild the policy
from which ones fail differently. Box chooses diagnosability, and the accepted cost is exactly that
oracle.

<a id="box-does-not-filter-workload-output"></a>
### Box does not filter workload output

An interactive agent receives the operator's terminal directly, and Box passes its output through
unchanged. Filtering that stream added no protection for the surrounding OS under a hostile-workload
assumption, and it broke terminal compatibility. The cost: a terminal emulator interprets control
sequences in workload output, and the workload chooses those bytes.

### Sandboxes for tools and MCP servers

Box starts a separate sandbox for each operator-declared host program: a toolchain binary that a
`shell:spawn` permit admits, or a stdio MCP server. Each is contained separately from the agent's
sandbox, and each exception below applies to that sandbox alone. The configuration and rendered profile of the agent's
sandbox stay byte-identical whether or not any such sandbox exists.

<a id="a-leaf-discovers-existence-and-metadata-content-stays-gated"></a>
#### A tool or MCP server discovers existence and metadata across the operator home, and content stays gated

A permitted host binary probes for optional configuration it may never read: a version control tool
looks for its own configuration file in the home. Under the existence-denied home of the agent's sandbox, that
probe dies on a fatal permission error instead of receiving a clean not-found, so the sandbox for a
tool or MCP server renders the inverse posture. It can test existence and read metadata across the
operator home, and content stays gated behind that sandbox's own read grants. Two subtractions render last, so no discovery rule
reopens them: the box state namespace is denied existence and metadata except for the exact paths a
grant already names beneath it, and the credential floor is refused existence and metadata even under
discovery. `a_leaf_discovers_the_operator_home_and_the_main_box_does_not` pins it. The cost is a real
disclosure: a tool or MCP server learns which paths exist across the operator home. This renders on macOS only.

<a id="a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds"></a>
#### A tool or MCP server runs its whole toolchain, and loads what it builds

A permitted host binary re-execs helpers nobody can enumerate up front (a version control tool ships
roughly 150 of them), and a build must load and run what it compiles. So on macOS the sandbox for a tool or
MCP server renders broad exec, and over that sandbox's own writable grants one executable-mapping
allow, so a build loads its own output. This applies only to that sandbox, and only after policy
already admitted the one top-level program,
which `a_leaf_carries_broad_exec_and_the_main_box_does_not` pins. Write-xor-execute still holds
everywhere except that sandbox's own writable grants: the carve-out never covers the operator home,
the system directories, or box state, and the agent's sandbox keeps the invariant whole. So a tool's
or MCP server's sandbox is a bounded filesystem-and-network envelope inside which arbitrary native
code can run. On Linux a
read-only bind already confers execute, and the mount view bounds the exec set instead.

<a id="native-egress-is-an-operator-declared-leaf-escape"></a>
#### Native egress is an operator-declared escape from a tool's or server's sandbox, recorded as a downgrade

A trusted tool or MCP server may run a client that cannot honour a proxy setting, so gateway-routed
egress blocks its calls. An operator can declare native egress for one named tool or server, a stdio
MCP server with
`[mcp.<name>.network] contain_egress = false` or a declared tool with `[tool.<name>.network]
contain_egress = false`, and that program's sandbox then reaches the network directly, losing gateway
mediation, per-request network policy, credential injection, and connection-level journaling. The
agent refuses the key, so it and every tool or server that does not opt in keep the gateway,
including a program that runs under an `exec` grant rather than a tool table. The box's trusted process emits an `egress:native`
decision naming the server or the tool whose traffic will not appear, after its sandbox starts. A tool
costs more than a server: the agent chooses a tool's arguments, so a native tool is direct egress
the agent can aim, and a general client such as `curl` or an interpreter declared native gives the
agent unmediated reach. The two
platforms differ in what the flag hands over, and on Linux, that program's sandbox joins the
surrounding OS network position, so it reaches the public network, the private network, the
machine's own loopback services, and the instance metadata endpoint. Treat this flag as a host-network
trust grant for one named tool or server, never a default.

<a id="a-leaf-reaches-the-host-startup-runtime-services"></a>
#### Agents get account lookup; tool and MCP server sandboxes can also request network startup services

On macOS, agent profiles allow lookup of `com.apple.system.opendirectoryd.libinfo` because Codex requires it to load managed preferences.
Tool and MCP server processes already receive this lookup through their sandbox's runtime-services option; the change makes that existing capability directly available to agents.
A TOML option adds configuration without limiting service requests once enabled, so account lookup belongs in the agent runtime minimum.
The grant does not limit service messages to read-only queries or the current user's record; service-side authorization remains outside this sandbox rule.
`agent_account_lookup_does_not_grant_leaf_network_runtime_services` proves the agent gains neither `net.*` reads nor a routing socket, while tool and MCP server sandboxes that don't opt in gain no lookup.
`account_lookup_is_allowed_but_preferences_services_remain_denied` checks live account lookup and preference-service denials against successful outside controls.

## Interpreters

Box runs two interpreters for the workload: the vendored Strands Shell, and Monty, which is the Python
interpreter.

<a id="interpreters-are-vendored-not-the-host-shell"></a>
### Box runs a vendored interpreter, never the host OS's shell

Box runs every shell command the agent issues through Strands Shell, an open-source interpreter
that Box vendors at a pinned revision. It never runs `bash` or `zsh` from the surrounding OS for the
agent's sandbox. A tool's or MCP server's sandbox runs programs of the surrounding OS, a shell included, inside that
sandbox. A harness runs a real shell for its
command tool, so Box gives it something with the same exit codes, the same stdout and stderr shape, and
the same argument conventions. The difference is that each filesystem operation is a Rust method call
that Box intercepts before it acts, and not a syscall that a process makes on its own authority. Box
vendors the interpreter instead of writing one, because upstream already holds the parser, the
pipelines, the control flow, and more than fifty builtins. The cost is ownership: each builtin must go
through the interception seam, a re-vendor is a merge and not a copy, and an upstream defect that Box
hits is Box's defect to fix.

<a id="the-interpreters-run-in-the-trusted-process"></a>
### Both interpreters run in the box's trusted process, and that is stated residual risk

The Shell and Monty run in the `run` process. That process is outside the sandbox boundary, and it
holds the policy engine, the interception CA key, and the resolved secrets. The vendored Shell embeds a
Lua 5.4 C interpreter, not optionally, and a workload reaches it as the `lua` builtin, so do not
describe the Shell as a small interpreter with no `unsafe` code. Monty is weaker again: at the pinned
version it carries 46 `unsafe` blocks, one of which is a hand-rolled raw-pointer heap. What makes the
placement acceptable is mediation and not memory safety. Neither interpreter performs I/O of its own:
each effect is a suspension that the box's trusted process performs, only on a policy-approved canonical path,
and the deny-only floors hold whatever the interpreter does internally. A security evaluator must treat
a memory defect in either interpreter as code execution in the box's trusted process. The named escalation is
to move the interpreter out and let it ask for each decision over a channel. Box does not do that today.

<a id="the-shell-checks-policy-at-two-levels"></a>
### The Shell asks policy at two levels, on the resolved effect, above a deny-only floor

The Shell asks policy twice. The command level asks whether the agent may run the program at all:
`shell:exec` for a program the Shell implements, and `shell:spawn` for a host binary. It asks once,
before the program starts. The effect level asks whether each filesystem operation of the running
command is allowed, as an `fs:*` action. Each effect runs resolve, then check, then execute, then
report, so policy judges the resolved path and never the name that the agent typed. A deny-only floor
sits beneath policy, and no rule widens it. The command check stops a forbidden program before it
starts, and the effect check stops a permitted program from reaching a path that no rule granted. Each
filesystem verb must go through one kernel method, so a re-implemented command calls the seam and not
the OS.

<a id="one-admission-point-after-resolution"></a>
### One admission point judges every route that evaluates command text, after resolution

Command admission happens in one function that every command-text route reaches, and it happens after
resolution, not at the outer entry points. Routes such as the Lua `io.popen` and `os.execute` builtins,
`find -exec`, `xargs`, `sh <file>`, the `.` and `source` builtins, an `EXIT` trap body, and command
substitution all re-enter the executor from inside the crate. A gate on the public entry points misses
each of them, so one permitted command fans out to many unjudged ones. `lua_popen_is_judged_by_policy`
and `find_exec_and_xargs_are_judged_per_nested_command` pin the rule. Admission also happens after
parsing, expansion, and resolution of the first word, because only then is the real program known. A
nested command is its own decision, so `find -exec` over N matches raises N decisions plus the outer
one. Do not add a second admission call at an entry point, because it counts one submission twice. A
`forbid` on command text is a weak control, because one effect has many spellings: write a rule on the
resolved `program`, or on the path-scoped `fs:*` rules.

<a id="a-resolved-token-binds-the-object-it-names"></a>
### A resolved token binds the object it names, so a symlink swap cannot divert an effect

The token that a path check produces carries a device and inode identity, captured when the path
resolves. A host-backed effect re-derives that identity immediately before it acts, and it refuses on
any mismatch. A host path whose identity Box cannot derive fails closed, for a read as well as for a
write. An in-memory effect re-resolves the token path under the same lock as the mutation.
`a_background_symlink_swap_cannot_beat_the_admission_window` and
`a_host_effect_with_an_unbindable_identity_fails_closed` pin the two halves. A host write holds the opened file across the
check and flushes through that descriptor, so a directory swapped inside the admission window cannot
divert it, which
`in_mount_admission_window.rs::a_directory_swapped_inside_the_admission_window_cannot_divert_a_host_write`
pins.

<a id="host-backed-effects-refuse-what-a-write-cannot-produce"></a>
### On a shared inode, a host-backed effect is stricter than a write

A host `chmod` applies the ordinary permission bits and refuses an explicit request to set setuid,
setgid, or the sticky bit. A host `ln -s` refuses a target that is absolute, or that leaves the bind.
The Shell acts on inodes that a writable bind shares with the operator's real filesystem, from outside
the cage: a set-user-ID bit written there lands on real disk and a process outside the box honours it,
and a symlink stores its target as given, so a reader outside the box would follow it. Each refusal is
a deny-only limit beneath policy. Two costs: a script that runs `chmod 4755`, or links to an absolute
path, fails loudly, and an ordinary `chmod +x` drops a setgid or sticky bit that the file already
carried. This does not cover the workload's own `fchmod` or `symlinkat` syscall inside the cage.

<a id="shell-network-goes-through-the-egress-gateway"></a>
### The Shell's outbound HTTP goes through the box's egress gateway

The Shell builds no HTTP client of its own. It dials the box's egress gateway on loopback and trusts the
gateway's interception CA. The gateway stays the one authority for `net:connect` and `http:request`, so
a Shell `curl` becomes one more source of decisions that the gateway already raises. A direct client
would be a second unaudited route to an effect the gateway governs. The Shell resolves no credential and
attaches no secret, and it runs its network off-switch before any transport. A build-time check fails
the build if a network client appears in the Shell sources outside the two sanctioned files, but that
check is a lint and not a guarantee.

<a id="a-gateway-refusal-never-reports-success"></a>
### A gateway refusal never reaches the workload as a successful response

The gateway forges the origin's leaf certificate when it intercepts a request, so a refusal it writes
inside its own tunnel would reach the Shell as an ordinary HTTP status, and `curl` exits 0 for any
status unless the caller passes `-f`. The gateway therefore marks each response it writes itself with a
header, and the Shell turns such a response into a permission-denied error, so `curl` prints one
reason line and exits 1. The marker is not authorization: the gateway already refused, and the marker
only says who wrote the refusal. `a_gateway_refusal_exits_non_zero_and_is_not_rendered` pins it.

**The conversion is the Shell's alone, and Monty does not have it.** A Monty `fetch` builds its own
client and never reads the marker, so a denied request reaches the script as an ordinary response
carrying a `403` status. A script that does not check the status reads a refusal as an answer. That is
an open residual rather than a closed case.

<a id="python-in-the-shell-is-monty"></a>
### A workload reaches Monty two ways, and Box judges both on its one policy

The workload runs the `python3` alias directly, and the broker serves that. Or it types `python` or
`python3` in the hosted Shell, which forwards the source through a script seam to Monty. Both routes
run one Monty VM per request, and Box judges both as the same principal under its one policy engine, so
no route reaches an interpreter that policy does not see. Without the second route a `python` typed in
the Shell exited 127, so an agent that reaches interpreters only through its shell never reached Monty.
Two differences between the routes are deliberate: the direct route adds an outer request timeout, and
a script file argument through the Shell reaches a bind, while the direct alias cannot.

<a id="a-bare-python-name-always-means-monty"></a>
### A bare `python` name always means Monty, so a host interpreter needs its absolute path

The Shell's registered `python` and `python3` commands win over any host interpreter on `PATH`, and
over a declared `[tool.<name>]` table that names a host interpreter. So `python --version` returns a
Monty identifying string, and `python3 -m venv` fails. That precedence is a known gap: a declared tool
cannot take over the bare name. A workload that runs an interpreter by its own absolute path, or runs a
virtual environment's `python` by absolute path, reaches the host OS's Python under the `[tool.<name>]` table
whose `command` names that path. Monty is stateless and refuses the interactive frames, so a `python`
with no `-c` and no script file refuses instead of opening a REPL.

<a id="monty-is-judged-at-the-effect-level-alone"></a>
### Monty is judged at the effect level alone, above two deny-only floors

Each OS call a Monty script makes suspends the VM. The box's trusted process admits the call against the
box's one policy engine, and performs it only when policy permits. Monty has no command level: the
whole script arrives as one call, and running a script is not itself an effect. So a rule for Monty
always names an `fs:*` action on a path. Two deny-only floors sit beneath policy. Box sets Monty's
working directory to the box's own, and Monty roots a relative path under it before policy sees it,
which `a_bare_name_resolves_under_the_working_directory` pins. Then the approval step checks the
canonical path after policy allows, and returns the canonical path that the host must act on. The
floors closed two real escapes, each pinned by a test that must not be deleted:
`a_dangling_symlink_cannot_be_written_through` and
`an_intra_home_symlink_cannot_launder_a_scoped_read`. A refusal names the absolute path, because
Monty joins a relative path to its working directory before the host receives the call, so the host
never sees the spelling the script used.

<a id="monty-performs-only-effects-the-box-can-govern"></a>
### Monty performs an effect only when policy can govern it and it leaks no host detail

Two conditions gate each effect Monty performs: policy can name and decide it, and its result carries
no resolved host path and no host identity value. Directory listing, rename, stat, binary read and
write, append, and the symlink test meet both, so Monty performs them. Path resolution and
absolute-path construction fail the second, because each returns a path to the script, so both stay
refused with a "not supported" error. A stat result normalizes the user ID, group ID, and link count,
which are host account identity. A rename is judged and floored on both endpoints. The clock reads real
system time in UTC, never the operator's local zone, which diverges from CPython on purpose.
`time.time()`, the monotonic clocks, and `os.urandom` are answered without a policy decision, because
none of them names a resource that a rule can name. `time.sleep()` and `asyncio.sleep()` both block,
because the broker has no event loop, so two concurrent sleeps take the sum of their delays.
`the_clock_and_entropy_are_answered_without_a_policy_decision` and
`both_sleeps_block_and_concurrent_sleeps_take_the_sum` pin both.

<a id="monty-is-per-request-and-buffers-its-output"></a>
### Monty handles one request per VM, holds no state, buffers its output, and bounds each allocation

Monty builds one VM per call and keeps no state between calls. It buffers the script's output and
returns it once, under a size cap. It refuses the interactive frames, so a script has no stdin and
`input()` cannot read. Status 0 means completed, 1 means the script raised, and 125 means a broker
or interpreter fault. The interpreter stops a script after 2 minutes of execution time, from inside
its own run loop, so `while True: pass` stops even when the script makes no OS call. Time suspended
on the host does not count against that budget, so Box bounds the rest: 5 minutes of wall-clock time
for each request, 60 seconds for each `fetch`, 3 minutes for all sleeps, 10,000 suspensions, and 1
MiB for each `os.urandom` call. Each of these bounds is less than the wall clock. A sleep is never
shortened: one that would pass the sleep total raises `TimeoutError` before it waits, which
`a_sleep_longer_than_the_total_raises_at_once` pins. `a_script_stops_at_its_suspension_limit` and
`urandom_above_its_cap_is_a_catchable_python_error` pin two of them. Monty refuses one allocation
above 128 MiB and stops the script with a `MemoryError`, which
`an_oversized_allocation_stops_the_script_and_not_the_box` pins. A script has no limit on its total
memory, because Monty enforces one only through a global allocator that counts the whole trusted
process and ends it on an overrun. A worker process for each script restores that limit, and it lost
because it changes the process layout of the box. The costs: there is no interactive session, a long
script shows nothing until it ends, and a script that grows its memory in small steps can use all
the memory of its box's trusted process, which is residual risk.

<a id="a-monty-script-reaches-the-network-through-one-fetch-function"></a>
### A Monty script reaches the network through one `fetch` function, and only that

Box exposes one host function to a script, `fetch(url, method, headers, body)`. A call suspends the VM,
and the box's trusted process services it with a client that dials this box's egress gateway, never the origin.
The gateway raises `net:connect` and `http:request` against the box's one policy engine, so Monty adds
no second decision site. No egress routing means the network stays off. The client offers no TLS-relax
option, and it reuses the Shell's URL safety check, so the two share one list. Three limits: only one
synchronous `fetch` works; the Python package ecosystem (`requests`, `boto3`, `urllib`, `socket`) is out
of reach, because that needs the host OS's Python as the contained workload; and this widens what the box's trusted
process performs from filesystem to filesystem and network, in the weakest memory-safety component.

<a id="an-unserviced-suspension-is-a-python-error"></a>
### A suspension that Box does not service reports an honest Python error, not a broker failure

An unknown name resumes as undefined and an unknown function call resumes as not found, so the VM raises
a catchable `NameError` at status 1. An async resolution raises a `RuntimeError` that names async as
unsupported. Status 125 means only that Box broke, so a typo in a script and a broken box no longer
report the same thing. The suspension enum is closed, so a future interpreter version that adds a
variant is a compile error and never a silent 125. Box cannot tell a typo from a real CPython builtin
that Monty lacks, such as `memoryview`, so every unresolved callable reports `NameError`.

<a id="a-host-binary-runs-in-a-contained-leaf-box"></a>
### A tool's sandbox reuses the policy engine and egress gateway of the box's trusted process

A command the Shell does not implement runs in its own sandbox: a second set of sandbox grants,
applied by the same trampoline, and supervised from the `run` process. `shell:spawn` decides whether the binary
starts, once, before Box builds that sandbox. A tool's sandbox builds no second trusted process. The box's trusted process
starts it, and the sandbox uses that process's one policy engine and one egress gateway. So one temporal
history governs the whole box tree, and a rule that spans `fs:*` and `net:*` still enforces. The sandbox
has no route to the broker: it has no alias, and it cannot connect to
`run/box.sock`. A tool's sandbox is ephemeral, one per `shell:spawn`. A program that a `[tool.<name>]` table names gets
its reach from that table. A program that no table names, but that lies under one of the caller's own
`exec` entries, runs in its own sandbox with the caller's path lists, which
`a_program_under_the_callers_exec_grant_runs_in_the_callers_boundary` pins. So a binary with no table
can still run. It holds the caller's path lists rather than a narrower set, and its sandbox has no route to
the broker either.

<a id="the-box-runs-a-host-binary-through-the-spawn-host-seam"></a>
### Box runs a host binary through a spawn seam that the Shell names and Box implements

The Shell names a `spawn_host` seam and calls the hook that an embedder installs. Box installs the hook,
and inside it Box selects a tool, translates that tool's process spec into a boundary, and drives the
result. The split exists because the Shell crate depends on neither the containment crate nor the
policy crate, so the Shell owns the interpreter boundary and Box owns operating system enforcement. The seam is
buffered: it returns captured stdout and stderr plus a status, so a long operation such as a large
`git clone` does not stream. This seam is a divergence from the upstream Shell, recorded in its
`UPSTREAM.md`.

<a id="the-spawn-host-seam-fails-closed"></a>
### With no contained spawner installed, a host binary is refused and not run uncontained

The spawn seam defaults to unsupported. With no hook installed there is no contained path, so a host
binary is refused rather than run with the crate's built-in fork and exec inside the box's trusted process.
An embedder must install that built-in explicitly to opt in to uncontained execution, and nothing
installs it by default. `a_host_binary_is_refused_when_no_spawn_hook_is_installed` pins it. So
sandboxing a host binary does not depend on remembering to wire the hook: absence is a refusal.

<a id="a-tool-reaches-only-the-paths-its-own-lists-name"></a>
### A tool reaches the project only where its own filesystem lists say so, raw and ungoverned by `fs:*`

A tool makes raw filesystem syscalls, so its reach is a set of containment cells and not a set of
policy decisions. Box grants no blanket project read and write. A tool's `filesystem` table holds six
lists, `read`, `write`, `read_file`, `write_file`, `list`, and `deny`. A tool states no `metadata`
list, because a tool's sandbox discovers existence and metadata across the operator home, and no `exec` list,
because on macOS a tool's sandbox runs its whole toolchain through broad exec; Box refuses both names on a tool.
On Linux a tool reaches a runnable binary through a `read` entry, which confers exec. A cell raises no
`fs:*` decision and enters no temporal history, so inside a granted tree a tool can touch a file that
the operator's per-path policy denies to the agent; Box discloses each cell at startup, and an operator
must read that disclosure. No tool grant can name the box directory, which
`a_tool_grant_cannot_expose_the_box_directory` pins.

<a id="a-host-binary-resolves-on-the-operator-path"></a>
### A host binary resolves against the operator's real `PATH`, and the longest command prefix selects the tool

The Shell resolves a host binary against the operator's real host `PATH`, with `/usr/bin:/bin` as the
fallback, so Box finds a tool under Homebrew, nvm, or mise. Each process's search path is the table's
own `env.PATH`, else the operator's real `PATH`, else the fallback. Selection compares the canonical
resolved path of each tool's program with the program the workload invoked, and compares the tool's
fixed leading arguments with the head of the argv. The longest matching `command` wins, so
`[tool.git-read]` and `[tool.git-push]` can differ only in their fixed arguments, which
`the_longest_matching_command_prefix_selects_the_tool` pins. Box names a program by its canonical
identity for the `shell:spawn` decision, for selection, and for credentials, and the seam runs only an
identity that was bound to an existing file when the decision was made. `shell:spawn` stays the one
control on whether a program runs; a larger `PATH` changes only where Box finds a permitted program.

<a id="the-caller-spelling-becomes-argument-zero"></a>
### The identity selects the program, and the caller's spelling becomes `argv[0]`

Box runs the canonical identity, but it passes the caller's own spelling as `argv[0]`, because an
interpreter reads `argv[0]`. A workload that ran a virtual environment's `.venv/bin/python` once ran
the canonical system interpreter under the system name, so the virtual environment was discarded with no
error. The spelling names the same file and nothing else: Box records a spelling only when its own
canonicalization produced the identity, and it is never resolved again. The residual risk is stated: a
workload that can write a directory, put a link to a declared interpreter in it, and place a
`pyvenv.cfg` beside that link can make the interpreter load modules from that directory. That is not
separable from the feature, because a virtual environment is exactly that shape.

## Egress

<a id="plain-http-takes-the-same-governed-path-as-https"></a>
### The gateway forwards plain HTTP through the same governed path as HTTPS

The gateway reads the request head, routes a `CONNECT` one way and a plain `http://` request the other,
and both converge on the same network controls and the same request and response legs. Plain HTTP
therefore adds no second authorization path, and the same policy judges it. Refusing plain HTTP
outright would close every cleartext hazard at once, but it also blocks a legitimate local `http://`
endpoint. Plain HTTP reaches any host the policy permits, not loopback only. The accepted residual risk
is that the box carries cleartext to a permitted host, so anything on that path can read the traffic.

<a id="a-secret-rides-only-tls"></a>
### A secret rides only TLS

A bare-host credential pattern matches port 80 as well as 443, and a target carries no scheme, so a
cleartext request to a credential-bound host would otherwise receive the real secret. The plain-HTTP
path therefore refuses with `403` when any credential control matches the destination, before the
request leg runs. The refusal keys on the destination and not on the request content, so there is no
way to opt out of it per request. An operator cannot bind a credential to a plain `http://` upstream,
not even a local one.

<a id="the-plain-path-binds-its-own-destination-and-reports-its-transport"></a>
### The plain path binds its own destination and reports its transport truthfully

The plain path has no `CONNECT` authority to check an inner `Host` against, so it rewrites `Host` to the
URL authority before the legs run. The destination the box authorized is then the destination the
upstream routes on, so a virtual-host name cannot smuggle past the decision. The request carries an
`intercepted` flag, true on the TLS path and false on the plain path, so a rule that admits only
TLS-terminated traffic is not silently widened to admit cleartext. The parser drops a URL fragment,
because a fragment is client-only and must never reach an origin server.

<a id="a-remote-mcp-tool-call-passes-a-second-gate"></a>
### A remote MCP tool call passes a second gate after the transport gate

The gateway classifies each JSON-RPC frame, then raises `mcp:call { server, tool }` after
`http:request`, and a deny at either gate wins. A `tools/call` reuses the same per-tool refinement the
local stdio path uses, so per-argument policy behaves the same on both. `initialize` and the `*/list`
discovery methods carry the server, so a rule can gate them. The gateway must terminate TLS and parse
frames, so a remote MCP server's traffic is buffered and not streamed. The credential controls stay
deny-only beneath policy, so the classifier adds no allow authority.

<a id="remote-tool-schemas-are-discovered-at-runtime-in-memory"></a>
### The box discovers a remote MCP server's tool schemas at runtime, in memory

The gateway captures the catalog from the workload's own `tools/list` response, and the box's tool
catalogs stage the per-tool schema in memory, as they do for a stdio server. Nothing is written to
disk, and the runtime never reads the offline `policy generate-schema` output, which stays an
authoring aid. Pages accumulate per `Mcp-Session-Id`, and a request that carries no session id
continues only the cursor chain it names. A catalog that fails to parse counts as terminal, so a
broken remote server fails loudly instead of hanging the box.

<a id="a-pending-authority-bootstraps-a-handshake-and-never-an-act"></a>
### A pending verdict holds one tool call, and the gateway's bootstrap arms are dead code

A per-tool rule can name an action whose schema is not yet staged. That tool call returns a transient
pending denial the caller may retry. Nothing else is held: a pending verdict is raised only for an MCP
tool identity, so a `net:connect` or an `http:request` can never carry it, and the box decides every
other request against the schema-independent subset instead. See
[discovery serves the schema-independent subset](#discovery-serves-the-schema-independent-subset).

The egress adapter still carries three arms that would admit a handshake frame while a verdict is
pending. They cannot fire, because no non-tool request reaches that state. They are residue from a
design that denied everything while discovery ran, and they should be deleted rather than documented
as a capability. Do not build on them, and do not read them as a pre-policy admission path: there is
no such path today.

<a id="the-box-coordinates-discovery-completion"></a>
### The box coordinates discovery completion, and the policy facade does not

Two paths stage into one policy engine, through one set of tool catalogs: the stdio broker and the
egress gateway. A run-owned coordinator holds the set of paths a run must hear from. Each path
reports once every server of its kind has an accepted, refused, or failed tool list, and the one that
empties the set finishes discovery exactly once. A per-tool rule that never resolved degrades
that one server, with a warning on stderr, exactly as
[a server whose discovery a policy denies](#a-server-whose-discovery-a-policy-denies-degrades-alone)
describes. Only a durable fault is fatal to the box. Putting that orchestration inside the policy engine was rejected, because it
changes the policy facade to buy something the box already owns.

## Credentials

<a id="the-workload-holds-a-phantom-and-the-gateway-holds-the-secret"></a>
### The workload holds a phantom token, and the gateway swaps in the real secret at the bound destination

For an `env://` binding the box mints a random phantom token and places that value, and never the real
secret, in the workload's environment. The gateway holds the real secret and swaps the phantom for it
only on a request to the destination the binding names. The phantom is a 256-bit random value, unique
across the vault. At the bound destination the gateway clears the harness's own credential location
before it writes the real secret, so the phantom does not ride out beside it. A phantom sent anywhere
else is not rewritten, and needs no rewrite, because it is random and authenticates nothing: an
upstream that receives one receives a useless value. The box opens one vault for each route, so an
ambiguous match inside a vault is refused, and an overlap between two routes is caught at the gateway
instead: a mutation collision is denied, and a strict phantom check refuses a mismatch. The workload
can read the phantom and learn that a credential exists.

<a id="the-box-is-the-credential-boundary"></a>
### The box is the credential boundary, so every process in a box gets every route

The box here is the whole of what one `box.toml` declares: the agent's sandbox, the box's trusted
process, and every sandbox it starts for a tool or an MCP server. Every request and response flows inside it.
Every process in the box gets every egress route that `box.toml` declares: the agent, each tool,
and each MCP server hold every route's phantom or placeholder. Every process in the box shares one gateway, and the gateway cannot tell which process made a call. An `aws://`
route mints no phantom: every process gets the same public placeholder keys, and the
gateway signs any matching request with the real credentials. An `env://` route with `secret.inject =
"always"` attaches the real secret with or without the phantom. An `env://` route with
`secret.inject = "phantom"`, the default, refuses a caller without the phantom,
and every process in the box holds the phantom, so it does not separate processes inside the box.
So the box is the credential boundary: if a process must not get a credential, do not put it in that
box. A stdio MCP server runs in its own sandbox inside the box, so it gets every egress route like a tool
does. The
future work is request attribution: the gateway names the process that made a call, the agent, a
tool, or an MCP server.

The cost is that a `phantom` route, the default, does not keep a credential from a tool or a
third-party stdio MCP server: either can use every route the box declares.

<a id="an-unusable-secret-value-is-unrepresentable"></a>
### An unusable secret value is unrepresentable, not validated

A resolved secret is a newtype whose only constructor refuses an empty value, a value that is empty
after a trim, and a value that holds a byte below `0x20` or equal to `0x7f`. Every credential source
returns that type, so no source can deliver a value that skipped the check. Redaction in `Debug` output
and zeroize on drop are one implementation on that type. The box cannot hold a deliberately empty
credential.

<a id="the-operator-selects-the-credential-placement"></a>
### The operator selects the credential placement, and `url_path` is refused at the box boundary

An egress target takes `secret.placement`, which is `header` (the default), `basic_auth`, or
`query_param`, with `secret.param` naming the parameter for the last. A fourth placement,
`url_path`, is **refused when the configuration loads**, because it splices the secret into the
request path. The gateway already records the path from before it adds the credential, which
`attempts_carry_the_pre_mutation_path_for_a_path_spliced_credential` pins, so the audit record does
not carry the secret. Exposing `url_path` is therefore a decision to make, not a defect to fix
first.

The refusal is at the box's boundary, and not an absence of the mechanism. The credentials crate
carries a working `InjectMode::UrlPath` that the box's trusted process uses on its own paths, so
path-splicing injection code does run in that process and an evaluator should read it. The box also
keeps its own `Placement` enum and its placement strings, which map onto `InjectMode`, so two
spellings exist and must agree. One residual stays: the gateway holds the spliced path as a plain
string, so a spliced secret leaves bytes in its heap that nothing wipes.

<a id="an-undeliverable-credential-is-refused-at-load"></a>
### A credential the box cannot deliver is refused when the config loads

A box egress entry may name the `env://` or `aws://` credential scheme. Every other scheme
is refused when the config loads, and the message names the accepted set. The credentials crate can
also resolve `file://` and `op://`, but a box egress entry may not name them, because the box has no way
to deliver them. `an_undeliverable_credential_scheme_is_refused` pins the refusal.

<a id="endpoint-breadth-is-refused-by-the-parsed-pattern"></a>
### Endpoint breadth is refused by the parsed pattern, and never by its text

Validation asks the parsed destination pattern whether it matches every host, and refuses that entry.
A text comparison would miss each new authority form the parser learns, and the two checks would then
disagree. A suffix wildcard such as `*.example.com` stays valid.

<a id="a-refusal-stays-in-the-phase-that-holds-its-input"></a>
### A refusal stays in the phase that holds its input

Some checks look redundant and are deliberate. The box checks the operator's environment and the config
text when it configures a box. The credentials crate checks the resolved secret and the sealed placement
when the vault opens, which is later and on a different input. Deleting a box-side check moves its
refusal one phase later, so the operator learns about a broken config after the box starts. Do not
delete one because the other exists.

<a id="a-provider-refuses-an-identity-it-cannot-honour"></a>
### A credential provider refuses an identity it cannot honour, instead of substituting one

The environment-backed AWS provider reads the ambient `AWS_*` variables, so it cannot resolve a named
profile. It never falls back to the ambient identity, because a credential that is not the one the operator
named is a silent authority change. A named profile resolves through the AWS profile chain, with one
exception refused by name: `credential_process`. Honouring it would make the box's trusted process run
a program that `~/.aws/config` names, and no floor defends that file, so it is the
never-run-a-workload-named-program rule applied to credentials.

<a id="a-route-may-set-the-phantom-check-to-advisory"></a>
### A route may attach its secret always, not only against the phantom

`secret.inject` takes `phantom`, the default, or `always`, and it is valid only on an `env://` route.
`phantom` fails closed: an absent or mismatched phantom refuses the request. `always` warns and
attaches the real secret anyway, for a harness that writes its own credential file and that the box
therefore cannot seed the phantom into, or a client that sends its first request with no credential.
`always` relaxes only the phantom check: the destination match, the ambiguity refusal, and the strip at
a foreign location are unchanged. An `always` route drops the one check that proves a request came from
the box's own binding, and the only signals are a per-request warning on stderr and a journalled allow
record. The key names what happens to the secret, not how the phantom is checked; it replaces
`secret.phantom`, whose `strict` and `advisory` are `phantom` and `always`.

<a id="a-route-may-set-the-minted-phantoms-prefix"></a>
### A route may set the minted phantom's prefix

`secret.phantom_prefix` replaces the default `strands_box_` prefix, and it is valid only on an `env://`
route. A harness that validates its key format then accepts the injected phantom. The prefix changes the
leading literal only. The box validates it once: not empty, at most 64 characters, and from the RFC
3986 unreserved set. A custom-prefixed phantom looks like a real key, so a reader of a log or a bug
report can no longer recognize it as a placeholder.

## Telemetry

<a id="one-collector-per-box-in-the-trusted-process"></a>
### One collector per box, inside that box's own trusted process

Each box runs its own collector in its own `run` process. There is no sidecar to deploy and no buffer
that two boxes share. A shared local collector would hold N boxes' records in one address space, so one
compromise would reach every box's audit trail. A collector the box spawns is worse, because the box's
trusted process may never run a program that a config file names. Records are per box, so an operator
who wants one store points several boxes at one destination and reads `strands.box.name` on each
record.

<a id="opentelemetry-owns-the-schema-and-the-box-owns-its-queues"></a>
### OpenTelemetry owns the schema, and the box owns its queues and its transport

The crate depends on `opentelemetry-proto` for the OTLP types, so one typed representation writes a
file line as OTLP-JSON, writes an endpoint body as protobuf, and reads both encodings from a harness. A
typed walk is exhaustive, so the reserved-namespace strip cannot miss a level. Each target wraps the SDK's own batch processor, which is the
bounded queue the audit-suppression control rests on. What the crate declines is the OTLP exporter
crate, because it needs a major version of an HTTP client that two other crates already use at a lower
version, and two TLS stacks in the process that holds the CA key is not a trade worth making.

<a id="a-target-is-a-file-or-an-otlp-endpoint"></a>
### A target is a file or an OTLP endpoint, and no other type parses

`box.toml` accepts `file` and `otlp`. Any other exporter name is refused when the config loads, and the
refusal names the two that exist. A vendor this build does not dial is reachable through a separate
OTLP collector process that carries that vendor's exporter, so an `otlp` target at that process's port
is the route.

<a id="every-box-records-by-default"></a>
### Every box records by default, to a file the workload cannot reach

An absent `telemetry` key means one `file` target that takes every signal: every effective denial and
permit, the box's own control-plane records, and the harness's relayed spans, logs, and metrics. A box that decides a thousand times and records none of it cannot be audited, and the
operator who most needs a record is the one who has configured nothing. The file sits in the box's own
private tree, which a deny-only floor refuses to the workload whatever a permit says. A declared target
replaces the default instead of adding to it. The file grows without bound and nothing rotates it.

<a id="a-target-names-a-set-of-signals"></a>
### A target names a set of signals, and an absent list takes every signal

`[telemetry.<label>] include` takes five words: `deny` and `permit` name the two effective verdicts,
`trace` names the agent's relayed spans and the box's own control-plane records, and `logs` and
`metrics` name the agent's relayed log and metric records. A target names a set, with no ordering, and
no signal contains another. A target that names no `include` receives every signal, which
`an_absent_include_takes_every_signal` pins. An empty list, a repeated word, and a misspelled word are
each refused before the box exists. The box relays a harness signal and never produces one, so the
harness's own exporter settings decide whether any such record exists.

<a id="the-strands-box-namespace-is-reserved"></a>
### `strands.box.` is reserved, and the collector strips it from an agent's payload at every level

The collector rewrites an agent's payload before anything can route it: every attribute with a
`strands.box.` prefix is removed wherever it sits, and a scope that claims the box's own `strands-box.`
namespace is renamed. Each resource is then stamped `strands.box.source = "agent"`, and the box's own
records carry `strands.box.source = "box"`. The strip is a recursive walk and not a list of known
places, because an earlier version stamped the resource only, and an agent could then post a record that
read as a permit the box had granted. The reserve is `strands.box.` and not all of `strands.`, because
the Strands Agents SDK writes its own attributes under `strands.`. Any future box-owned key must sit
under `strands.box.`.

<a id="the-operator-adds-resource-identity-through-the-environment"></a>
### The operator adds resource identity through `OTEL_RESOURCE_ATTRIBUTES`, and the agent cannot override it

The `run` process reads `OTEL_RESOURCE_ATTRIBUTES` once, and every box record and every relayed
payload carries those keys on its resource, so a backend attributes a decision to a tenant or a
conversation without a header the workload chose to send. The box's own keys and `service.name` cannot
be set this way, and a malformed value stops the run before the workload starts. On a relayed payload,
an agent attribute under an operator key is removed before the stamp. A `box run` flag and a
`[telemetry]` field were rejected: the first moves the CLI, and the second is fixed per box and takes a
name from the target labels. The cost: the identity is per process environment, so a caller that
starts many runs from one shell must set it per run.

<a id="the-collector-listens-on-a-second-loopback-port"></a>
### The collector listens on a second loopback port

The workload reaches the collector on `127.0.0.1:<port>`, pinned per box exactly as the gateway port
is, so an unmodified agent SDK exports with one environment variable and no code change. A Unix socket
was rejected, because the OTLP exporter specification requires an HTTP endpoint. The proxy exemption
for that port is `127.0.0.1,localhost` and nothing else. The port is reachable by every process at the
operator's uid, not by the contained workload alone, because a loopback listener has no peer check.
Such a process cannot forge a box record, but it can inject noise attributed to the agent.

<a id="the-agents-lane-and-the-boxs-lane-share-no-queue"></a>
### The agent's lane and the box's lane share no queue, and the agent's lane holds one permit

The box's decisions go through one bounded queue per target. An agent's span is relayed inline behind a
capacity of one permit, taken without waiting. One shared queue would let a workload that posts
continuously fill the queue so the box dropped its own refusal records. The permit is taken before the
decode, and a resource-count limit refuses an amplifying body on every route. A slow target delays the
agent's own spans, and nothing bounds the connection count on that port.

<a id="delivery-is-best-effort"></a>
### Delivery is best effort, and a record can be lost

A failing target prints to stderr, and the record is gone. A relayed agent span does not take part in
the shutdown drain, so a shutdown can lose one in flight; a refusal cannot be lost that way. A record
that the SDK's own queue refuses is not counted. The drain sits at the one point every exit reaches, so
a box that fails before its workload starts still records its stop.

<a id="the-effective-decision-is-the-canonical-record"></a>
### The effective decision from the enforcement point is the canonical record

The enforcement point submits one record after every policy gate and every deny-only floor finishes: a
permit before the effect starts, or a denial before it returns the refusal. The box does not record the
raw engine verdict, because a floor can refuse what policy permitted and a bootstrap pass can permit
what policy denied. The record names every policy that determined it, in
`strands.box.policy.determining.ids`, and a cause in `strands.box.policy.cause`, one of `permitted`,
`forbidden`, `no_match`, `policy_pending`, `internal_fault`, and `enforcement`.

<a id="every-box-record-is-both-a-span-and-a-log-record"></a>
### Every box record is both a span and a log record

Each effective decision produces one internal span and one audit log record that share a trace ID and a
span ID. The span marks the instant the enforcement point submits the decision, so it measures no
evaluation latency. The collector mints one trace ID and one root span when it opens, and every
control-plane operation names that root as its parent, so one box life is one trace. A decision is
exported even when the caller's parent is unsampled, because a sampling flag must not suppress policy
evidence. `decisions_export_spans_and_matching_logs_with_request_parentage` pins the contract.

<a id="correlation-context-is-a-hint-and-never-authority"></a>
### Correlation context is a hint, and never evidence of authority

A decision joins the caller's own trace through context the caller supplies: the alias environment for
a Shell or Monty call, the request headers for HTTP egress, and `params._meta` for an MCP frame. Every
box record carries `strands.box.run.id`, generated once per `run`. The box copies named fields only,
bounds their size, and validates before it retains anything. Tool arguments, prompts, authorization
headers, and arbitrary baggage are excluded, and a caller-supplied identifier is never evidence of
caller identity. Roughly half of all decisions arrive unparented and join by `strands.box.run.id` alone.

<a id="the-policy-attribute-names-are-this-products-own"></a>
### The policy attribute names are this product's own, and the set is fixed

A decision carries `strands.box.policy.action`, `.resource`, `.verdict`, `.cause`, `.reason` on a deny,
`.principal`, `.rule`, `.description`, and `.category`. No OpenTelemetry convention covers
authorization, so this namespace is authoritative here, and the set is fixed because a backend indexes
on these keys. Standard keys carry the lane detail where one exists: `server.address`, `server.port`,
`http.request.method`, `file.path`, `process.command`, `process.command_args`, and
`process.working_directory`. `url.full` and `process.command_line` stay excluded, because each
routinely carries a secret.

**`.cause` is mandatory, and it must agree with `.verdict`.** `DecisionRecord` holds a
`DecisionCause` rather than an option, a permit defaults to `Permitted` and a deny to `Forbidden`,
and `caused_by` refuses a pair that cannot occur. The alternative — an optional cause every call site
happens to set — states the same fact by convention, so a new enforcement point drops it with no
build failure. The verdict is **not** derived from the cause, because `Enforcement` reaches both.

<a id="a-span-omits-what-a-span-field-states"></a>
### A decision span omits only what one of its own fields already states

The span carries every attribute of its log record except `strands.box.trace.parent_span_id`, which
the span states as `parentSpanId`. That key costs a consumer twice — stored, indexed, and billed on
both halves — and names nothing a trace reader cannot already see. The log record keeps it, because a
log record has no such field, and the two share a trace id and a span id, so a reader pivots by id.
`SPAN_OMITS` is the list, and it holds that one key.

Nothing else is omitted, and two keys left the record altogether rather than joining the list.
`strands.box.trace.parent_sampled` and `strands.box.trace.state` are no longer emitted: no consumer
read either, and each costs about two lines to restore, which is the test
[emit only what a consumer reads today](#the-policy-attribute-names-are-this-products-own) applies.
Deleting `trace.state` took the span's `traceState` field with it, and the box still propagates a
caller's `tracestate` downstream, so only the record changed. The whole decision tuple stays —
`principal`, `action`, `resource`, `verdict` — because a span stating three of four describes a
decision with no subject of authority. `strands.box.policy.determining.ids` stays, because omitting it
leaves a trace-only consumer unable to see that a permit rested on more than one policy, and a fact
the record would otherwise lose outranks a saved copy.

The cost: a reader that wants the caller's parent as an *attribute* must read the log record. That is
the trade for one copy of each fact.

<a id="a-shell-record-names-only-a-literal-argument"></a>
### A shell record names an argument only when the script stated it literally

The record reports an argument whose word was literal in the submitted script, and for an expanded word
reports it only when it is a path or a plain flag. Every other argument becomes `<redacted>`, because
the Shell holds arguments after expansion, so `echo $(cat secret.txt)` would otherwise write the file's
contents into the record. A shape test alone was useless: `pipefail` and `hunter2` are the same shape.
Provenance separates them, because a literal word already sits in a file the operator can read. The
policy engine never receives provenance, because a decision is about what runs and not about how a word
was spelled.
