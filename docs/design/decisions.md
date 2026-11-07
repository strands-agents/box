# Decisions

This page records the reasons for Box's design. Each entry states a decision and its limitations,
residual risks, or required precautions. It also names a rejected alternative when that explains the
decision.

> This is a historical record of design choices. An entry explains the reasoning at the time of the
> decision and can fall behind the code. The code owns current behaviour. Use an entry to understand
> the reasoning, then read its named tests or crate to check current behaviour. Correct an entry if
> it disagrees with the code.

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

Box assumes the workload runs code from an actor who wants to cause harm. An agent runs model output
and reads content it did not write, such as repositories, web pages, and tool results. Box treats
that code and content as untrusted. Box therefore grants no reach that the operator did not state,
and it adds no trust for a harness that behaves well. Every path a harness needs requires an
explicit grant. A harness that starts on an unrestricted machine can fail inside a box until the
operator names what it reads.

<a id="box-protects-the-machine-not-the-box"></a>
### The sandbox protects the surrounding system from the box, and not the box from anything

The sandbox protects the operator's machine and everything that machine reaches: their files, their
credentials, and the network. This protection applies only in that direction and has four limits.
The two tiers decide at different granularity, because operating system enforcement decides once
before the first process starts and policy decides each operation. A direct grant removes the policy
decision instead of adding to it. The workload can still name a path it cannot reach, and hand that
name to the box's trusted process, which can reach it. Some read-only locations are shared between
boxes, so the sandbox does not prevent side channels. A box is not a confidentiality boundary for
its own contents.

<a id="some-channels-never-reach-enforcement"></a>
### Some channels never reach enforcement, and the enforcing code can itself be wrong

Box makes two assumptions about enforcement. Some channels do not pass through the operating system
enforcement or policy interfaces at all, such as hardware and timing side channels, so no
requirement in this design closes them. The box's trusted process also builds the boundary, so a
defect in that process has no further containment. Ordinary code review is the only compensating
control for that risk. Box greatly reduces reach but does not prove isolation.

<a id="containment-does-not-govern-authored-code"></a>
### The sandbox does not govern the code the agent writes

The sandbox governs the syscalls the workload makes itself. It does not govern code the agent writes
and then gets run elsewhere. Programs that Box starts for the workload, including host binaries and
stdio MCP servers, run in their own sandboxes. Policy decides whether such a program starts, and
policy decides each later call the box makes into it, but inside that sandbox no policy decision
constrains what the program does.

## The box

<a id="linux-evaluation-requires-explicit-consent"></a>
### Linux startup does not require an environment opt-in

The Linux command line and library validate configuration without an environment opt-in.
`EXPERIMENTAL_LINUX_SUPPORT` has no effect, including when an existing script sets it to `TRUE`. An
extra environment gate would require every caller and test to supply consent separately from
configuration. The cost is that the variable no longer prevents accidental Linux use. Host
requirements, process hardening, filesystem grants, and containment checks still apply. A missing or
invalid configuration still fails before a workload starts.

Stable releases can include Linux ARM64, and `publish_linux=false` retains a macOS-only stable
release without a workflow revert. Keeping Linux in preview only would prevent an accepted Linux
build from using the stable channel. The release owner must establish Linux readiness before
publishing its archive. Linux previews always include ARM64 Linux and leave the latest stable
release unchanged. Removing the startup flag does not authorize a release or establish security
acceptance. The native filesystem policy experiment retains its separate configuration and Cargo
feature controls.

<a id="native-filesystem-policy-requires-explicit-selection"></a>
### Native filesystem policy requires explicit selection

The `native-filesystem-policy` Cargo feature includes the adapter but does not activate it.
`[experimental-features] native-filesystem-policy = true` enables the mechanism and supplies the
default for each workload. An optional `native-filesystem-policy` boolean in `[agent]`,
`[tool.<name>]`, or a local `[mcp.<name>]` overrides that default. Each table inherits the global
default independently. Remote MCP entries refuse the setting. An explicit process enablement
requires the global gate. Signed macOS releases include the adapter, but retain this explicit
runtime selection.

Before execution, the trusted launcher holds the workload and registers its selection against the
process identity observed by the kernel. Children inherit the selection across forks and executable
changes. Only trusted launches apply table overrides. Disabling mediation retains sandbox
restrictions and descendant shutdown tracking, but omits those native operations from Dogwood
history. The adapter checks kernel event sequences even for bypassed operations. Bypassed operations
avoid the Dogwood work queue. A single box-wide selection cannot exempt a build tool while retaining
checks for the agent, so it is insufficient.

The adapter uses the existing durable policy engine. It adds no memory-history setting or
asynchronous persistence. The directory-entry resolver uses `PathResolver::approve_host_entry` to
check rename and unlink without following the final symlink.

Without process overrides, disabled configurations use record version 21 and enabled configurations
use version 22. Explicit overrides require version 23. Older binaries refuse unsupported records.
Changing the selection does not erase existing history. See [operator
instructions](../user/native-filesystem-policy.md).

Signed native tests live in `test-native-filesystem`, separately from ordinary workspace tests that
require no signing identity.

<a id="the-boundary-is-the-surrounding-os-not-a-virtual-machine"></a>
### The boundary is the surrounding OS's own sandboxing, and not a virtual machine

Box contains the workload with the sandboxing the surrounding OS already has: Seatbelt on macOS, and
namespaces with a syscall filter on Linux. It boots no guest operating system and starts no
container. A microVM provides stronger isolation. We rejected it because the workload must use the
operator's existing project, toolchain, and harness configuration at their existing paths. A guest
would require a second environment to provision and maintain. Each file and program the workload
needs would also need a way into that environment. Isolation also decides nothing on its own. Once
the workload can reach a tool, something still has to govern what it does with that tool, which is
the policy tier's job and not the boundary's. A kernel escape defeats operating system enforcement,
and no part of Box compensates for one. That residual risk belongs to the platform's own isolation
tier.

<a id="box-decides-outside-the-harness"></a>
### Box decides outside the harness, so a harness's own permission prompt is not the boundary

Many harnesses ship an allowlist and an approval prompt of their own. Box neither relies on one nor
reads one. A harness's check runs inside the agent's own process, and [the workload is hostile by
assumption](#the-agent-is-hostile), so a check inside the harness cannot enforce the boundary. The
harness also judges a tool call rather than its effects. It sees "run this command", but it does not
see which files the command opens or hosts it reaches. Each harness states its rules in its own
format as well, so a rule written for one carries to no other. Box decides in the trusted process
instead, at the OS boundary and at the network boundary, using one `box.toml` and one `policy.dw`
for whichever harness the operator runs. The harness continues to show its own permission prompts.
An operator who wants to remove those prompts must state the same intent in both configurations.

<a id="box-is-a-process-and-reads-one-complete-configuration"></a>
### Box is a process, and it reads one complete configuration

Box ships a binary and a library so external applications can call the existing run code. A box has
four inputs: policy, credentials, a name, and a workload. One `run --config FILE` supplies all four
inputs. The file states a required `name`, a required absolute `box_dir`, and an `[agent]` table
with `command` and `workspace`. A trailing argv appends to `[agent] command`, a relative
configuration path resolves from the process working directory, and a relative policy path resolves
beside the configuration. Box keeps the composition types private, so no caller can obtain the
boundary, the trampoline, or the attachment and assemble a weaker box. The workload owns stdin and
stdout, so every Box diagnostic goes to stderr.

<a id="one-trusted-process-per-box"></a>
### Each box has its own trusted process, and that process is `run`

The box's trusted process is its own `run` process. It holds that box's policy engine and temporal
history, its two interpreters, its egress gateway, its certificate authority, and only that box's
resolved secrets. There is no daemon and no supervisor. One shared process would hold every box's
plaintext secrets and signing keys in one address space, where a single memory-safety failure
reaches them all. The caller supplies the absolute `box_dir`, and the `run` process holds an
exclusive lock on `private/.lock` inside it for its whole life. The caller ends the process to stop
a box and removes the directory to delete one, so Box needs no lifecycle verbs.

Two residual risks remain. On both platforms, killing the trusted process leaves the contained
workload without a parent because Box does not set `PR_SET_PDEATHSIG`. The deny floor also covers
only this box's directory. A `permit fs:read` can therefore reach a sibling box's stored policy when
both directories sit under one parent.

<a id="one-run-owns-one-box-directory"></a>
### One `run` owns one box directory, and a second `run` refuses

A `run` holds that box's lock for the whole run. A second `run` against the same `box_dir` refuses,
and `run` accepts no `-n` or `--name` option. Two trusted processes for one box would have two
policy engines and two temporal histories. A rule that spans `fs:*` and `net:*` would load in both
but enforce in neither, with no error. The other way to keep one history is a control socket that a
second run attaches to, which would require daemon-like coordination inside the box. To run two
agents over one project, supply two box directories and two complete configurations. The limit
applies to workloads. One box still serves many requests at once.

<a id="one-policy-engine-per-box"></a>
### A box has exactly one policy engine, in its own trusted process

Every enforcement point in a box decides on one shared policy engine instance: the egress gateway,
the Strands Shell, and the Python broker. No component opens a policy engine of its own. Two
instances mean two temporal histories, so a rule such as
`forbid net:connect when temporal { ... fs:read ... }` loads in both and fires in neither. Hosting
the enforcement points beside the one engine costs three process-level controls that cannot be
recovered in-process: `env_clear()`, a closed inherited file-descriptor table, and a separate
process group for the interpreters. It also puts the interpreters in the same address space as the
in-memory certificate-authority key and the resolved secrets. We accept that risk to give every
enforcement point the same policy engine. The decision does not depend on the interpreters being
small. See [the interpreters run in the box's trusted
process](#the-interpreters-run-in-the-trusted-process).

<a id="a-run-validates-once-then-acts-on-the-identity-it-approved"></a>
### A run validates once, then acts on the identity it approved

One prepared run owns the box lock, one record snapshot, the workload, and one policy engine value.
`run` opens the selected configuration and policy, records the canonical path and filesystem
identity of each opened source, locks the `box_dir`, and validates the complete contract before it
writes any Box state. All later persistent and generated state operations use the opened directory
identity, and assembly rereads no mutable configuration. Box protects the integrity of the loaded
sources. The interpreter floor refuses any operation that can change or replace their identities,
including operations through hard links or symbolic links. A filename carries no authority, so an
unrelated file named `box.toml` or `policy.dw` gets ordinary policy treatment. During teardown, a
blocking generation or staging job must finish before Box releases the lock. The lock releases last.

<a id="the-trusted-processs-memory-is-a-defended-asset"></a>
### The box's trusted process refuses another process its address space

Before the async runtime starts and before any secret resolves, the box's trusted process applies
`setrlimit(RLIMIT_CORE, {0, 0})` on both platforms, `prctl(PR_SET_DUMPABLE, 0)` on Linux, and
`ptrace(PT_DENY_ATTACH)` on macOS. Each mechanism is always on, with no operator switch, and Box
reads back the values of the two mechanisms that support it. A disagreement refuses startup.
`PT_DENY_ATTACH` has no read-back, and its documented failure mode is to kill the caller, so Box
applies it last and does not check it. This defends against a same-user local attacker, which the
threat model deprioritizes, so treat it as defence in depth rather than a guarantee. Root bypasses
it entirely. You cannot attach a debugger to a running box without changing and rebuilding the
source. An operator whose surrounding OS raises the core-dump soft limit also stops getting dumps.
The macOS claims rely on reasoning rather than measurements. `RLIMIT_CORE` and `PT_DENY_ATTACH`
therefore remain unverified on macOS. Swap remains a risk. We omit `mlockall` because a finite
`RLIMIT_MEMLOCK` makes it either lock nothing or prevent heap allocation.

<a id="interpreters-are-brokered-aliases"></a>
### An interpreter runs beside the workload, never inside it

A contained workload finds `zsh`, `bash`, `sh`, `python3`, and `python` on its `PATH`. Each name is
an alias of one verified image, and the image forwards the request over a Unix pathname socket to
the broker in the box's own trusted process. No interpreter runs inside the workload's sandbox, and
`argv[0]` selects the interpreter before the client connects. The Python the workload gets is Monty,
a Python subset, so a script that uses unsupported syntax must fail with an error naming the
environment, not with something that reads like the script's own bug. Each alias adds one exec
literal and its paired metadata read to the generated profile. It adds no wildcard or directory
grant. Only the agent's sandbox gets the aliases, their directory on its `PATH`, and a connect to
`run/box.sock`, where the broker listens.

The broker cannot tell which process calls it, so it judges every call as the agent. A tool's or MCP
server's sandbox with a route to the broker would therefore act as the agent. So that sandbox has no
alias and cannot connect to `run/box.sock`. Its `PATH` is its own search path alone, without the
alias directory. `boundary.rs::a_leaf_holds_no_route_back_to_the_broker` pins this. The alternative
was to identify each caller, by peer credentials or one socket per sandbox, and judge each tool or
server as its own principal. That needs a caller identity on the frozen broker protocol and in the
policy principal vocabulary. A tool or MCP server consequently cannot reach Strands Shell or Monty.
A bare `bash` or `python3` in either sandbox runs the surrounding OS's program inside that sandbox.

Each alias name is a hard link to the box's own alias image, `bin/.alias-image`, and never to the
installed image. Box places that image at the box's first run as a clone of the installed
`strands-box-sock-alias`, or as a byte copy on a volume that does not support cloning. It keeps the
image across runs of the same `box_dir`, and replaces it only when the SHA-256 of the installed
image changes, which `private/alias-image.stamp` records. So the file a box executes has no name
outside that box's `bin/`, and no other box can remove a name of it. macOS Gatekeeper kills an exec
with `SIGKILL` when a name of the file under assessment disappears. With a shared image, any box on
a machine could cause that failure in every other box. Box unlinks an alias name only while it holds
the run lock and before the workload starts, which is when it reconciles a newer installed image or
a dropped MCP server, so no exec from that box's workload is in flight. `aliases::materialize` takes
the lock as an argument, and
`box_project::a_run_on_a_running_box_is_refused_before_it_touches_an_alias` pins it. Two residual
risks remain. A process that escaped an earlier run's process group can still exec a name the next
run replaces. An operator who removes a box directory while its `run` is alive still kills that
box's own execs. The surrounding OS must assess one more file per box at that box's first run. It
serializes those assessments, so boxes that start together wait for the preceding assessments.
`every_alias_shares_the_boxs_own_image_inode_and_not_the_installed_one` and
`a_second_materialize_reuses_the_clone_and_unlinks_no_alias` pin the layout. **Updated:**
2026-10-07.

<a id="a-box-is-one-kernel-and-many-programs"></a>
### A box is one kernel and many programs, and the socket is transport

Box separates state into three levels. Each box has one kernel that shares policy, temporal history,
the virtual filesystem, the credential vault, and the egress gateway. Programs in a box must share a
filesystem. Each contained program that talks to the box has its own program state. That state holds
its working directory, environment, exported variables, shell functions, aliases, file descriptors,
and background jobs. No program observes another's state. Each submitted unit of work is a call with
a fresh deadline and output limits.

The peer process id belongs in the audit record and must never enter the request. Connection
capacity also stops bounding in-flight work once one connection carries several programs. That work
still needs a separate explicit cap.

<a id="no-state-crosses-a-call-boundary"></a>
### No interpreter state crosses a call boundary

The box's trusted process builds one Shell per connection and one Monty virtual machine per request,
each on the box's one shared policy engine. There is no request queue, shared worker, or operator
setting for the number of interpreters. Working directory, environment, and shell functions do not
survive a request, so two runs cannot observe each other and a failure stays within one request
without a separate guard. The requirement is one Shell per request. Creating one per connection
meets it today because each connection carries exactly one request. If the protocol ever carries two
requests on a connection, Box must rebuild the Shell for each request. Each connection runs on its
own thread with its own runtime, so a non-yielding command such as the embedded Lua interpreter
blocks only its own thread. Only a listener failure stays fatal, because with no listener there is
nothing to serve.

<a id="the-broker-protocol-is-framed-versioned-and-refuses-with-a-reason-code"></a>
### The broker protocol is framed, versioned, and refuses with a reason code

Each frame is `{version, program, frame_type, body}`, with `frame_type` in the header beside
`version` and `program`, and `body` carrying the payload alone. Each frame has a 4-byte big-endian
length prefix and a maximum size of 1 MiB. The receiver checks the size before allocation. The
encoding is UTF-8 JSON with base64 for binary payloads. The receiver refuses unknown fields in both
the header and the body. `exit` and `denied` are separate terminals, and a `denied` carries a fixed
reason code, so a client branches on the cause without parsing prose. One framing serves Shell,
Python, and MCP, and a future client needs no new wire format. The header layout requires a
hand-written serializer because flattening removes the unknown-field refusal. Base64 also grows a
binary payload by a third. Both ends ship together, and the version gate refuses a stale alias image
rather than tolerating it.

<a id="a-host-binary-runs-in-a-leaf-box-and-the-policy-is-the-only-allowlist"></a>
### A host binary runs in its own sandbox, and the policy is the only allowlist

A program the Shell does not implement itself runs as a real host binary inside its own sandbox,
after a `shell:spawn` decision admits it. The authored policy is the entire allowlist. No config
key, default set, or profile entry names permitted binaries because a second list for the same
effect would create a second authority. `shell:exec` and `shell:spawn` are decided at one point, and
dispatch then takes the path that matches the action that was judged, so the two cannot disagree.
Exit status `127` stays distinct from `126`, so "nowhere on `PATH`" and "denied" do not collapse
into one answer. The binary makes raw syscalls, which raise no `fs:*` decisions. Its sandbox profile
and the credential floor bound those syscalls. One spawn decision covers the whole process tree
because children raise no decision of their own. The box's trusted process starts the program in the
program's own sandbox, and passes it an argument vector, an environment, and a working directory.
The program returns its response on its standard output and standard error pipes and its exit
status. It has no route to the broker, so it cannot send a second request as the agent. Its network
traffic still goes through the egress gateway, which judges that traffic as the agent.

<a id="box-derives-a-read-closure-and-refuses-to-derive-an-exec-closure"></a>
### Box bounds derived reads from writable dependency chains and derives no exec closure

Box keeps automatic dependency discovery and derives bounded runtime read roots. If the workload can
change a dependency branch, that branch requires existing content-read authority or trusted
system-library allowances. The floors still apply. That restriction includes replaceable resolution
paths and follows indirect dependencies. With a writable directory, Box also restricts multiply
linked files because path checks cannot exclude a writable alias. Other chains outside the
workload's write reach retain automatic derived reads. Box derives no exec permission from a
dependency graph because it could authorize general-purpose helpers without an operator decision.
The cost is additional Read entries for writable programs and for hard-linked files whose other
names cannot be ruled out as writable. A previously malicious artifact that is now read-only can
remain outside this restriction. The [dependency startup
design](containment.md#dependency-read-startup-design) states the operator experience and the limits
of static discovery.

<a id="a-program-starts-through-its-route-and-is-granted-on-its-target"></a>
### A program starts through its route and is granted on its target

Resolution returns two values: the route as invoked, and the canonical identity the profile names.
Box execs the route, keeping the route's own final component, and authorizes the canonical identity,
because the kernel resolves the route to the identity at exec. Executing the canonical identity
instead would lose a virtualenv. CPython reads `pyvenv.cfg` from the directory it was started
through. The route's directory is canonicalized even so, because Seatbelt resolves a route one
component at a time and matches a read root under its canonical spelling. Box runs no program to
discover install trees. A virtualenv's `site-packages` may hold a `.pth` file that CPython runs at
startup. Running it would execute third-party code in the process holding the certificate-authority
key and every resolved secret. The read root over the interpreter tree grants kernel reach without a
policy decision. An operator who keeps a secret inside a virtualenv therefore grants the agent
access to it.

<a id="one-process-spec-and-one-translator"></a>
### One process specification states every process, and one translator applies it

`[agent]`, each `[tool.<name>]`, and each stdio `[mcp.<name>]` deserialize into the same type, and
one translator takes that type with a launch role. A spec holds four fields. `command` names the
program and its fixed leading arguments. `workspace` sets the initial working directory and grants
nothing. `env` supplies the literal environment with no inheritance from the surrounding OS.
`filesystem` lists the paths the process's own syscalls can reach. It has eight lists for `[agent]`
and six for `[tool.<name>]`. A tool refuses `metadata` and `exec` by name because its sandbox
already discovers metadata and runs its toolchain through broad exec. Before this, the agent table
and the tool table had grown apart, each with its own grant keys and its own translation. With one
type, the configuration file states each process's reach in the same form. A fault in the shared
translator affects both the agent and tools.

The spec does not select which tools or routes a process may use. The agent can use every tool and
MCP server the file declares, and every process gets every egress route. The box cannot attribute a
request to a process. See [the box is the credential boundary](#the-box-is-the-credential-boundary).
A tool's or MCP server's sandbox has no route to the broker, so neither can start a tool. A declared
tool is not an authorization: it still needs its own `filesystem` entries and its own policy
decisions. These checks do not guarantee the absence of secrets. An operator who lists
`~/.gitconfig` grants access to that file, which can hold a credential helper.

<a id="home-is-the-operators-and-the-workspace-is-entered"></a>
### `HOME` is the operator's own home, and a home grants no reach

`HOME` is the operator's own home directory unless `[agent] env.HOME` names another one, and there
is no private box home. A home grants no reach. The workload reaches a path under it only when a
list in `[agent.filesystem]` names that path. A declared home may not lie in trusted Box state, so
Box refuses an `env.HOME` that resolves into a reserved host root, into the box directory, or
through a `.strands-box` component, and the deny floor carries no exception for a home. We rejected
a per-box home because it required a copy of the harness's configuration and one harness sign-in per
box. The configuration file also could not show all the resulting reach. `[agent] workspace` names
the initial working directory. Box renders one entry-only cell for it, so `chdir` succeeds and
relative paths resolve. The workload's own reads and writes remain refused, as
`the_workspace_is_enterable_and_unreadable_until_listed` checks. A stdio MCP server also receives
the operator's home, because it runs as the operator and looks for its session there.

<a id="direct-filesystem-reach-is-declared-and-disclosed"></a>
### Direct filesystem reach is declared in the configuration and disclosed at startup

`[agent.filesystem]` carries eight lists: `read`, `write`, `read_file`, `write_file`, `list`,
`metadata`, `exec`, and `deny`. Each entry names one path on the surrounding OS that the process's
own syscalls can reach. Directory entries are recursive and file entries are exact. Paths are
absolute or `~`-relative, with no wildcard syntax. `write` does not imply `read`. These keys let an
unmodified coding agent edit files in a box. Its native file tools issue direct syscalls. When the
sandbox refused all of them, the agent had to use `cat` and shell heredocs. Routing everything
through the mediated Shell instead was rejected, because it prevents unmodified harnesses from using
their native file tools. These grants are kernel reach that no `fs:*` decision covers, so the
startup disclosure on stderr naming every grant is the whole compensating control, pinned by
`the_startup_disclosure_names_every_grant_and_the_home_and_path`.

Box subtracts the paths that hold its own authority from every grant. These are the box directory
and the directories holding the `box.toml` selected by `--config` and its policy. Their names and
locations do not change that protection. Without that, a host binary the agent runs could rewrite
the policy that governs the next run.
`a_project_entry_subtracts_the_directory_holding_this_boxs_authority` pins it, and
`a_config_outside_the_workspace_is_protected_by_path` pins a configuration loaded from outside the
workspace.

No directory name is special. The subtraction once keyed on the name `.strands-box` and walked every
granted tree for it, which protected a sibling box only when that box kept the default layout, and
protected this box not at all when `--config` named a file elsewhere. **A sibling box's directory
under a grant is now the operator's stated reach**, named on stderr by the grant that encloses it.
The box defends the authority it loaded, and re-checks that by identity at every spawn, which
`a_spawn_refuses_a_reach_whose_subtracted_authority_moved` pins.

There are three limits. Linux writable mounts also permit reads. Box therefore refuses each Linux
write grant without explicit read coverage before any agent, tool, or local server runs. A matching
file read or an enclosing directory read supplies that coverage. A child read cannot cover a parent
write grant. macOS retains write-only access. The disclosure names complete and partial read-write
access. `linux_rejects_write_only_before_any_process_runs` pins startup refusal.
`explicit_read_write_succeeds_for_every_process_and_scope` pins explicit access and overlapping
scopes. This accepted platform limitation avoids silently adding read permission. Landlock is the
planned long-term approach; its implementation and qualification remain deferred.

Both platforms refuse native workload renames of ancestors between a write grant and the loaded
authority directory. Linux keeps these ancestors fixed with mounts inside the workload's mount
namespace; macOS denies changes to their directory entries. The test
`this_boxs_authority_survives_a_rename_of_its_parent` checks both platforms and confirms that
unrelated sibling operations still work. On Linux, this protection does not cover a permitted Shell
move executed outside the workload's mount namespace.

A path these lists name does not join the Shell's reachable set, so `read = ["~/vendor/sdk"]` makes
the agent's own read work while `cat` through the Shell stays refused.

<a id="the-runtime-minimum-is-two-sets-and-the-agent-takes-the-smaller-one"></a>
### The runtime minimum is two sets, and the agent takes only the smaller one

Kernel reach comes from two runtime sets plus the process's own `filesystem` lists, and from nothing
else. The `agent` set states the reach every process gets regardless of configuration. It grants
read and write on the null device, access to local time and time-zone data, an entry-only cell for
`/`, and metadata cells for a few system directories. On macOS, it also includes the system library
tree and `/usr/lib/libffi-trampolines.dylib`, which Apple's libffi loads for callbacks. Without it,
a Python linked against that libffi aborts on its first C callback. The `tool` set states what a
host toolchain reaches in addition: the entropy devices, locale and terminal data, framework and
linker-cache trees, the certificate-authority bundle directory, and the loader's library
directories. The active developer directory is in neither set: a tool that runs an Apple `/usr/bin`
stub states `read` on it in its own `filesystem` lists, which
`os_paths.rs::no_containment_reaches_the_developer_directory` pins.

The agent takes only the first set, and every tool takes both. A harness reads its own configuration
and talks to a model. It does not need a compiler toolchain, while an attacker could use that extra
reach. Neither set grants an exec cell or states a denial, and the only write in either is the null
device, which `os_paths.rs::a_set_has_no_list_for_an_exec_grant_a_denial_or_a_write_tree` and
`os_paths.rs::only_the_null_device_is_written` pin.

Box refuses a list entry that encloses a credential store, such as `~/.aws`, `~/.ssh`, a keychain, or
a browser profile, and the box does not start. A read or write entry that names the store itself or
a path inside it grants access with a disclosure. The named path states deliberate access, while an
enclosing tree can include the store by accident. **That floor covers the process's own syscalls and
nothing else.** A read through an interpreter is a policy decision, and no credential floor sits
beneath it. See [no credential floor
sits beneath the interpreters](#no-credential-floor-sits-beneath-the-interpreters).

<a id="the-agent-gets-one-exec-rule-per-grant"></a>
### The agent gets one exec rule per grant, and Box follows a script's interpreter chain

The agent gets one exec rule for its own `command` and one more for each `exec` entry, a literal for
a file and a subpath for a directory, each paired with a metadata read and never with a broad file
read. The agent never renders the broad exec form, which
`the_agent_profile_never_carries_broad_exec` pins. On macOS, Box grants the interpreter chain of the
declared program. It reads the program's first bytes and follows its `#!` line to the real
interpreter. If that interpreter is a script, Box repeats the check. It grants exec at file scope on
each hop.

On Linux, every interpreter in a declared script's chain needs coverage from the process's original
filesystem grants. An agent needs `exec` coverage. A declared tool or local server can use its own
read or writable grants where those grants permit execution. System paths have no exemption.
Discovery follows `env` and its selected command, and checks every nested script's interpreter.
Script contents select the programs to check; they grant no authority to those programs. Box
preserves required path spellings only for files already authorized, without adding a new source for
library dependency discovery. A tool's readable interpreter can still need separate grants for
non-system libraries.

A workload-selected program without a declared tool table needs existing `exec` coverage for its
interpreter chain on either platform. Box derives no wider exec closure, so a program that runs a
helper needs that helper's directory in its own `exec` list.

Two residual risks remain. Write and exec on one path produce a warning but do not refuse startup,
so the workload can run code it writes there. A granted shell can also interpret workload-authored
input inside its parent's boundary because native descendants raise no new decision.

<a id="ca-trust-is-a-per-process-environment-value"></a>
### CA trust is a per-process environment value, not a system trust store

Box composes six CA environment names for each process and sets each one to the gateway's CA:
`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CODEX_CA_CERTIFICATE`, `AWS_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, and `GIT_SSL_CAINFO`. The general alternative is one system trust store, which
on macOS is the keychain, and a contained process can neither reach nor change it. Most runtimes
honour `SSL_CERT_FILE`. `botocore` instead reads `AWS_CA_BUNDLE`, and the libcurl in Apple git reads
only `GIT_SSL_CAINFO`. Setting a name a runtime ignores costs nothing, so the rule is "every name a
supported runtime reads", and the list grows when a runtime is added. Box reserves each name and
refuses a table that states one at startup. Letting the workload choose a CA bundle would let it
choose a trust root. A CA name is trust and never authorization, and the gateway stays the one
outbound boundary.

<a id="an-mcp-server-is-one-configuration-table"></a>
### Every MCP server is one `[mcp.<name>]` table, and its start is a policy decision

Each MCP server is one `[mcp.<name>]` table in the selected configuration, and `type` selects the
transport: `type = "stdio"` names a local server and carries `command`, and `type = "http"` names a
remote server and carries `destinations` and an optional `secret.ref`. There is no second MCP file,
and the older `[egress.<name>] protocol = "mcp"` spelling is refused with a message that names the
new one. A table header states the name once, in the operator's file. The box never reads a server
name from a frame because the agent could choose another server's name. Before a stdio server
exists, Box decides `shell:spawn` on its declared program and arguments. Only a permit starts the
server. A forbid or an absent permit leaves it unstarted, as
`absent_start_permit_refuses_the_server_and_it_never_runs` checks. A remote credential is always a
`secret.ref` locator and never a literal token, and the box never parses a harness's own
configuration file to find one.

<a id="a-stdio-mcp-server-runs-contained"></a>
### Every stdio MCP server runs contained, in its own sandbox

Every stdio MCP server requires a sandbox. A `type = "stdio"` entry carries the same grant fields as
any other process, `workspace`, `env`, and `filesystem`. Box builds one process spec from the entry
and uses the shared translator, so the same floors apply. Box approves and discloses every server's
direct filesystem grants before the agent starts. A server's command resolves only when the agent
requests that server. Box then prints the full boundary disclosure before launching it, including
its runtime and environment. This preserves lazy server startup without hiding direct filesystem
reach. `a_box_declaring_many_mcp_servers_still_runs` pins unused declarations without installed
server programs. A server that declares no grants still runs contained, on the baseline every tool's
and MCP server's sandbox gets. One setting bypasses only network mediation:
`[mcp.<name>.network] contain_egress = false` gives that server's sandbox direct egress instead of
the gateway-routed default, for a trusted client that cannot honour `HTTPS_PROXY`. See [native
egress is an operator-declared escape from a tool's or server's
sandbox](#native-egress-is-an-operator-declared-leaf-escape) for its cost. The server's sandbox
stays filesystem-contained and Box records the downgrade explicitly. Both platforms honour the key.
On Linux, it also gives the sandbox the surrounding OS network namespace, including the private
network, the machine's loopback services, and the instance metadata endpoint.
`native_egress_translates_on_linux` pins that translation. The cost is that a server needs its reach
stated.

<a id="mcp-tool-schemas-are-discovered-from-the-live-server"></a>
### Box discovers an MCP tool schema from the live server's own list, for both kinds of server

`run` starts no MCP process for discovery. A declared MCP open starts its live child at that moment,
and the MCP client initializes the child through the broker. Box then reads the replies to the MCP
client's own `tools/list`, through the broker for a stdio server and through the gateway for an http
server, into one tool catalog per server. Box sends no `tools/list` of its own. A list is captured
only when its first request names no cursor and each later request names the cursor that the
previous page returned on the same connection. Box holds the reply to the last page until it stages
the schema. The client therefore cannot see a tool before Box enforces its rules. A list that does
not change the catalog commits nothing. A list that changes it replaces it, and a refused list keeps
a stdio server's accepted catalog. We replaced discovery that made Box page the server itself. That
approach made the broker an MCP client and required two discovery models. If the client stops
paging, Box never stages the server and refuses its tool calls. A server the MCP client never lists
stays undiscovered, and a terminal server failure stops a later open from starting another process
in that run. The broker accepts four MCP protocol revisions during `initialize`, refuses any other,
and forwards accepted initialization frames unchanged. See [discovery serves the schema-independent
subset](#discovery-serves-the-schema-independent-subset) for what a box decides while discovery is
pending.

<a id="a-client-reply-to-a-server-request-is-decided"></a>
### The client's reply to a stdio server's own request is decided as `mcp:call`

A stdio server can send its own request, such as `roots/list`, `sampling/createMessage`,
`elicitation/create`, or `ping`. The broker forwards the request to the MCP client and records its
id. The broker decides the client's one reply to that id as `mcp:call`, using the server and method
from the request. A server permit admits the reply, and a `forbid` can refuse it. A refused reply
reaches the server as a JSON-RPC error. A reply to `ping` crosses with no decision, as `ping` does,
and the server receives an empty result whatever the client put in it. Any other response from the
client is refused. Forwarding the reply with no decision was rejected, because it opens a path from
the agent to the server that no rule can close. The cost is that a policy that permits only named
methods must also name these. An http server's own requests are not supported yet; streaming its
response bytes does not add the broker's request/reply correlation.

<a id="remote-mcp-schemas-are-generated-through-a-direct-client"></a>
### `policy generate-schema` covers a remote MCP server through its own discovery client

`policy generate-schema` uses a Streamable-HTTP discovery client for remote MCP servers. For each
`type = "http"` server, it runs `initialize`, captures the session id, sends the initialized
notification, and reads a paginated `tools/list`. A remote server's credential resolves directly
through the credentials backend at generation time, not through the runtime vault and phantom path,
because generation has no workload to protect and the egress gateway is not running. Generation
makes a real network call to each remote server. Each server must be reachable and have credentials
available at generation time. A credential placement that the discovery path does not support
produces a named error.

<a id="a-harness-hook-runs-only-in-exec-form"></a>
### A harness hook runs only in exec form, and Box rewrites nothing

Box rewrites no harness configuration. The operator keeps the harness configuration in a directory
that a list in `[agent.filesystem]` names, points the harness at it with `[agent] env`, and either
removes the hooks or rewrites each one to exec `<box_dir>/bin/zsh -c "<command>"`. A shell-form hook
fails with `EPERM: operation not permitted, posix_spawn '/bin/sh'` for every hook event. Nothing
reaches stderr, and `run` exits 0, so the operator sees no failure. Granting `process-exec` on
`/bin/sh` would make it work, but the commands the hook issues would then raise no decision, so an
authored `forbid` would never see them. Once rewritten, each hook command reaches the mediated Shell
and raises `shell:exec`, and each file it touches raises its own `fs:*`. Two limits remain. A hook
that reads its payload on stdin sees nothing because the alias forwards no input. Plugin hooks
remain broken because most of them exec a script.

## Policy

<a id="the-authored-policy-is-the-only-decision-authority"></a>
### The authored policy is the only decision authority

On both mediated paths, the interpreters and egress, only the policy engine decides authorization.
The enforcement points reach it through `EffectInterceptor`. Every other mechanism on those paths
either imposes a deny-only floor or mutates a request without authorizing it. The floor runs before
policy on the network path and after policy on the interpreter path. Policy cannot widen it. We
deleted code paths that could return "allowed" without asking the engine. The types enforce this
restriction. A capability returns `Result<Vec<Mutation>, String>`, containing edits or a refusal,
never an allow. `egress-gateway` keeps no dependency on `policy` at all. Do not add a second allow
path, and do not give a mechanism its own verdict to save a round trip.

<a id="no-connection-is-opaque-to-the-boundary"></a>
### The gateway terminates every connection, so no tunnel is opaque

An interceptor must see each request and each response effect, so the gateway always terminates TLS.
Box no longer supports opaque tunnelling, splicing, or raw byte copying. A connection whose
plaintext the boundary cannot read cannot raise `http:request` and would bypass that authorization.
The box cannot reach a plaintext or non-HTTP upstream over `CONNECT`.

<a id="the-ssrf-and-metadata-floor-is-compiled-beneath-policy"></a>
### Cloud-metadata protection is policy, and the gateway holds no destination list

Core has no compiled metadata or link-local deny list and chooses no destinations to refuse. An
ordinary `forbid` on `net:connect`'s `context.input.ip4` or `context.input.ip6` refuses a metadata
address. The gateway decides on each resolved, pinned address before opening its socket. It dials
that same address, so a DNS name cannot bypass the rule. Rules can express every range from the
former floor exactly, with one clause per address family. `169.254.0.0/16` becomes
`ip4 like "169.254.*"`. `fe80::/10` uses four `ip6` prefixes, `fe8`, `fe9`, `fea`, and `feb`, whose
first group runs from `fe80` to `febf`. EC2's IPv6 endpoint uses the single `ip6` address
`fd00:ec2::254`, without the surrounding unique-local range.

A box has this protection only if its policy contains the forbids. A policy without them can reach
metadata. A new metadata endpoint is a policy change, not a Core release, and it reaches an existing
box only when that box's policy is edited.

<a id="deny-overrides-composition-with-no-compiled-rule-tier"></a>
### Composition is deny-overrides, and no rule tier is compiled into the engine

The authored sources compose into one policy set under deny-overrides. A `forbid` always beats a
`permit`, and an empty set denies everything. Every rule the engine evaluates comes from authored
policy. Prepending a compiled `forbid` would put a floor beside policy rather than beneath it, so
Box compiles no rule tier into the engine. What no policy may open is refused below the engine by a
deny-only floor. The reachable paths check refuses every interpreter operation on the `box.toml` and
policy loaded by this run, including reads. It also refuses changes to their parent directories. The
sandbox subtracts those directories from native grants. A sibling box's directory under the
reachable set is policy's to decide, which
`a_sibling_boxs_authority_passes_the_floor_and_policy_decides` pins. Express a restriction as a
`forbid`. Adding a narrower permit can only widen access, never remove it.

<a id="no-credential-floor-sits-beneath-the-interpreters"></a>
### No credential floor sits beneath the interpreters, so one broad rule reaches the operator's secrets

The interpreters see the whole operator home, and the authored policy is the only thing that decides
each access. The deny floor beneath them refuses the box's own product directories and the policy
and configuration this run loaded, and nothing else. It does not name `~/.aws`, `~/.ssh`, a
keychain, or a browser profile. The credential floor that does name those paths belongs to the
sandbox, and it governs the syscalls a process makes itself. A mediated read goes through the box's
trusted process instead, so it never meets that floor. One `permit fs:read` with no path condition
therefore lets the workload read the operator's cloud credentials, SSH keys, and source through the
Shell or through Python.

This is the widest exposure in the product, and it has no compensating control today. Treat a
path-unconditional `fs:read` or `fs:write` permit as a grant of everything the operator can read.
Write every filesystem rule with a path condition, and prefer a `forbid` on the credential paths in
any policy you author. Closing this needs a deny-only floor beneath policy that carries the
credential list that the sandbox uses, which is not built.

<a id="every-decision-is-local-and-in-process"></a>
### Every decision is local and in-process

The box's trusted process decides every governed request locally. No network call and no signature
check sits on a decision path, because a remote call for each decision fails open during an outage
and exceeds the latency budget. Box has no control plane for signed bundle distribution, signature
verification, an organizational ceiling tier, quarantine pushes, or remote authorization. The
operator distributes the policy file and handles fleet-wide changes or revocations outside the box.

<a id="the-engine-is-dogwood"></a>
### The policy language is Dogwood, a superset of Cedar

Operators write policies in Dogwood, a strict superset of Cedar with history-aware rules. One engine
runs in the box's trusted process per run, with no network call per decision. The placement is
fixed, but the engine behind the facade can change. The Cedar crate stays pinned at an exact
version, because the schema and the request gate are Cedar types. The engine comes from the
published `dogwood-language` and `dogwood-local-engine` crates, each pinned at an exact version, so
the policy engine builds from registry dependencies alone.

<a id="a-policy-computes-no-fact-from-a-provider"></a>
### A policy computes no fact from an external provider

A policy states its conditions over the request's own typed context, and nothing else. A
`Provider::Name(args)` call aborts box startup, because this build registers no information
provider. A provider-free `guardrails { … }` clause is a tag, and the engine evaluates its condition
without calling any classifier. The box also scans no source text, because the earlier scanners
produced both false positives and false negatives. A rule cannot access a computed or model-derived
fact.

<a id="one-principal-one-resource-and-the-action-scopes-the-rule"></a>
### One principal, one resource, and the action scopes the rule

Every request and every history event uses `Box::Agent::"self"` and `Box::Resource::"unused"`. We
replaced three principals with one because the action already identifies the boundary that raised
the request: `net:connect` and `http:request` come from the gateway, `shell:exec` and `shell:spawn`
from the shell, `mcp:call` from an MCP stream, and `fs:*` from either interpreter. One private
action identity builds the request UID, the history event, and the observed value from one variant,
so a rule and a temporal predicate cannot name different namespaces. A policy is therefore portable
and cannot depend on a box name, but a rule also cannot discriminate by box name. Isolation comes
from one engine and one history file per box, not from an identity.

<a id="the-action-vocabulary-is-closed-and-strict-validated-at-load"></a>
### The action vocabulary is closed and strict-validated at load

The actions are `fs:read`, `fs:write`, `fs:delete`, `fs:move`, `fs:other`, `net:connect`,
`http:request`, `shell:exec`, `shell:spawn`, and `mcp:call`, plus one generated action per
discovered MCP tool. A policy names one; it cannot add one. Each action declares its own typed
`context.input`, and the resource holds no attributes, so rules distinguish requests through the
action and context alone. There is no `context.system` and no `now`. The engine strict-validates the
whole bundle at load. An unknown action or a mistyped attribute causes a hard load error,
`PolicyError::UnknownAction`, and aborts startup. It cannot leave a loaded rule that silently never
matches. The per-request schema gate stays in `decide` even though no caller can build a
non-conforming request today. Keep this check even if it appears unreachable.

<a id="a-rule-that-cannot-fire-is-refused-at-load-and-an-uncertain-one-warns"></a>
### A rule that cannot fire is refused at load, and a rule that might is a warning

Strict validation catches a name the schema does not declare, and nothing else. A well-typed rule
could load and pass review even when no request could match it. Examples included: a path literal
spelled absolute under the operator's home when every reported path is `~/…`, a directory spelled
with a trailing slash, one `@id` on two rules, or a rule whose only action is the reserved
`fs:other`. The loader now refuses every rule it can prove inert and names the spelling to use. When
the loader cannot prove that a rule is inert, it prints a warning on stderr. The operator may intend
the rule: a `program` literal spelled as a path matches one spelling of the first word, and a `like`
pattern that names the home after a wildcard may match nothing.

We rejected two alternatives. Refusing the uncertain class too would turn a deliberate rule into a
startup failure. Warning for the provable class too, as [write plus execute
warns](#write-plus-execute-warns-and-does-not-refuse) does for a configuration that is wider than
intended, was rejected because an inert rule provides no protection. A `forbid` the operator relies
on would protect nothing while the box runs, and a warning in the startup disclosure would not stop
the run.

The cost has three parts. A policy that loaded yesterday stops the box when a check is added. The
home check judges a literal against this operator's home, so one policy text loads on one machine
and refuses on another. Some inert rules remain unprovable and still load: a comparison across two
enum types, and a `has`-guarded read of `context.output` outside a temporal clause.

The loader judges a cap written as a `permit` against the other rules. It refuses the cap if another
permit admits the same action without a condition because one permit cannot narrow another. It warns
if another conditioned permit covers the same action because the cap is inert for requests that
permit admits. Alone, the permit loads because it widens access rather than capping it.

<a id="a-rule-that-reads-the-input-names-one-action-family"></a>
### A rule that reads `context.input` names actions of one family

The action determines an input attribute's meaning: `path` is a filesystem path on `fs:*` and a URL
path on `http:request`, and `host` is a destination on `net:connect` and any argument a generated
tool action declares. So the load refuses a rule that reads `context.input` and does not constrain
its action to one family, and names the actions to write. The check covers reads in `when` or
`unless` conditions. A `when temporal` clause names its own action, so the check does not inspect
it. A family is the prefix before `:` in a `Box::Action` name, such as `fs`, `shell`, `net`, `http`,
or `mcp`. Each generated tool action is a separate family. The check needs no action schema, so it
runs before strict validation and before a box with an MCP server stages a tool schema: the loader
refuses a rule that reads input across a tool action and another family without waiting for
discovery. A rule scoped to one tool action loads. This is wider than [refusing a rule that cannot
fire](#a-rule-that-cannot-fire-is-refused-at-load-and-an-uncertain-one-warns): it refuses a rule
that is ambiguously authored, not one proven inert, so it refuses some rules that fire correctly
today.

We rejected three alternatives. Judging the literal under an unconstrained scope refused a valid
rule that compared a tool argument, and the spelling it suggested changed what the rule matched. A
warning in the startup disclosure would not stop the run, and no shipped policy has this shape. The
schema cannot decide it, because it records a type and not a meaning, and `path` is a `String` on
both `fs:*` and `http:request`. An operator must split a rule that reads input across families into
one rule per family. This includes `net:connect` and `http:request` rules on `host`, even though the
meaning agrees. The rule starts strict because loosening it later loads every policy that loads
today, and tightening it would refuse some. A blanket `permit` or `forbid` with no condition still
loads.

<a id="the-enforced-surface-is-the-whole-vocabulary"></a>
<a id="the-enforced-surface-is-the-whole-vocabulary-so-there-are-no-harness-actions-and-no-risk-tags"></a>
### Every declared action has an enforcement point

The vocabulary holds only what a real enforcement point raises. There is no `tool:invoke`,
`model:invoke`, `agent:invoke`, or credential action, and naming one is an `UnknownAction` load
error. There is no `tool_risk` context field, so no rule can gate on a declared risk level.
Declaring an action without enforcing it would give an operator a control that does nothing. Govern
a tool through `mcp:call` and its generated per-tool action instead.

<a id="filesystem-authorization-uses-four-verbs-and-a-catch-all"></a>
### Filesystem authorization uses four verbs and a fail-closed catch-all

The actions are `fs:read`, `fs:write`, `fs:delete`, and `fs:move`, with `fs:other` as a catch-all
that no rule written against the named set matches. The kernel's exact verb appears in
`context.input.operation`, so a rule can narrow an action by operation. There are no group actions
and no `fs:exec`: running a program is a shell decision, and a test of an executable bit is a
metadata read on `fs:read`. The `PATH` walk's candidate test maps to no action at all, so a rule
that counts `fs:read` counts programs and not directory entries. A coarse permit is broad, because
`fs:write` covers `set_permissions` and `symlink`, so a precise operator adds an `operation` guard.
`every_declared_kernel_verb_rides_a_named_action_and_none_rides_fs_other` pins the mapping.

<a id="an-overwriting-rename-also-deletes-the-destination"></a>
### An overwriting rename also raises a delete on the destination

A rename requires several decisions. The source and destination each raise `fs:move`. The source
also raises `fs:read` because its bytes become reachable under the new name. A rename onto an
already bound name raises `fs:delete` on the destination. Every decision must permit the rename. The
first refusal names its path. So a rule that protects a file's content must forbid `fs:delete` on
that file as well as `fs:write`: a `forbid` on `fs:write` alone does not stop a rename over it. An
atomic save writes a temporary file and renames it into place, so it needs `fs:delete` on the
original. A dangling symlink counts as a bound name, and on a host bind a rename onto a symlink is
refused beneath policy. `an_overwriting_rename_is_refused_by_a_forbid_on_deleting_the_destination`
pins the Shell, and `a_python_rename_onto_an_existing_file_is_refused_by_a_forbid_on_deleting_it`
pins Python.

<a id="a-credential-binding-is-configuration-not-a-policy-action"></a>
### A credential binding is configuration, not a policy action

There is no credential action in the schema. An operator declares a binding in `box.toml`, and that
binding says only which secret is attached to a request the policy already permits. Reachability
stays the policy's decision alone, so a binding never opens a destination, and the two must name the
same host. There is no spelling for ambient credentials: an empty `aws://` body does not parse,
because Box must not silently use credentials from the environment. A secret travels over TLS only.
See [credentials require TLS](#a-secret-rides-only-tls).

<a id="temporal-rules-ride-the-closed-context"></a>
<a id="a-temporal-rule-rides-the-same-closed-context-as-an-ordinary-rule"></a>
### Temporal and ordinary rules use the same closed context

A history-aware rule is an ordinary `permit` or `forbid` with a `temporal { … }` block in its `when`
or `unless` condition. The block contains past-only formulas that the engine evaluates over recorded
history at the decision point. A predicate reads only the fields the action's `context.input` and
`context.output` already declare, projected onto past events by the event schema, and the event
kinds are `::request`, `::response`, and `::error`. Adding a temporal clause gives a rule history
without changing the action schema. One motivating rule remains impossible to write. "No egress
after the workload reads sensitive data" needs a `sensitive` tag on a filesystem path, and no such
tag exists. A temporal predicate also has no prefix or `like` operator, so a sensitive subtree
cannot be matched on the path instead.

<a id="temporal-rules-are-enforced-against-recorded-history"></a>
### Temporal rules are enforced, against recorded history, with no tamper claim

A `when temporal { … }` clause loads, evaluates, and denies. The engine enforces rules against
recorded history. This is not a tamper-resistance guarantee. A `::request` predicate is satisfied by
a denied attempt, because the request event carries no verdict, so a step-up rule keyed on
`::request` is defeated by asking and being refused. Key a precondition on `::response` instead;
`a_denied_attempt_satisfies_a_request_keyed_precondition` pins the failure mode, which is known and
open. A missing outcome event also makes a counting rule undercount and fail open.

A metadata read that got an answer, in the Shell or in Python, records `::response` even when the
answer is "no", so a `read_metadata` budget counts a probe of a missing file in an existing folder,
which `a_read_metadata_budget_counts_probes_of_absent_paths` and
`a_read_metadata_budget_counts_stats_of_missing_paths` pin. A metadata read of a path that can't be
resolved, such as one under a missing folder or under a folder the surrounding OS won't let Box
search, also records `::response`, although the reachable paths check refuses it, which
`a_metadata_read_under_a_missing_folder_meets_a_response_precondition`,
`a_metadata_read_under_a_missing_folder_spends_the_budget`, and
`a_metadata_read_under_an_unsearchable_folder_spends_the_budget` pin. Box records that `::response`
only for a path inside the reachable paths and outside Box's own state. The path must have no `.` or
`..` component and cross no symbolic link in a folder Box can see.
`only_a_plain_path_under_a_missing_folder_is_unresolved` and
`a_stat_outside_the_reachable_set_spends_nothing` check these conditions. The event kind doesn't
depend on what a symbolic link, a `.` or `..` component, or Box's own state holds, so those refusals
stay `::error`.

Other refused reads remain `::error`.
`a_metadata_read_the_floor_refuses_meets_no_response_precondition` checks reach-floor refusals. The
Shell's admission-window guard refuses any namespace change, as
`a_probe_the_admission_window_refuses_reports_a_failure` checks. Python's walk refuses a symbolic
link swapped into the path, as `a_predicate_refused_by_an_ancestor_swap_records_failed` and
`a_metadata_read_of_a_leaf_swapped_for_a_link_records_failed` check.

We rejected recording a "no" as `::error` because the workload still learns the answer. Python and
the Shell record that outcome alike. The cost is that no event kind separates a "yes" from a "no",
so a `::response` precondition on a metadata read is met by learning that a path is missing, also
when the reachable paths check refused the read. A `::response` budget doesn't count a refused probe
through a symbolic link, with a `.` or `..` component, or into Box's own state. A cap on attempts
counts `::request`, which counts every probe.

The engine prunes history to the deepest authored window, which the workload itself fills. Window
depth therefore bounds availability and does not establish enforcement strength. A counting rule
also evaluates against recorded history and not against requests in flight, so each request in a
parallel burst can pass while the burst exceeds the limit.

<a id="box-carries-an-opaque-request-token-into-each-outcome"></a>
### Box carries an opaque request token into each outcome

Box owns request correlation because its callers know which admitted effect produced each outcome.
`PolicyEngine::decide` returns an opaque `RequestId`, and `record` requires that token to reuse the request's declared identifier.
A gateway exchange identifier cannot substitute for it because one exchange can require several policy decisions.
The token uses the durable log offset and belongs to one opened engine; reload preserves it, but reopening requires new tokens.
Callers must retain each token until its effect ends, and existing unlabeled events remain unchanged.
`durable_http_history_preserves_one_identifier_for_each_operation` pins request/result pairing.

<a id="history-is-durable-per-box-and-has-no-rewind"></a>
### History is durable per box, and it offers no rewind and no audit record

One box owns one engine, one policy source set, and one history file, and a restart reuses that
file. `open` recovers a decision-equivalent history before returning an authority. If recovery
fails, it returns an error. The box never falls back to empty or partial history. The engine
timestamps each event from the trusted system wall clock. Callers cannot supply timestamps. If the
clock steps backwards, each append advances one nanosecond until it catches up. This can keep a
restriction active longer than the apparent interval. A policy edit applies prospectively. A
temporal identity that still matches keeps its state, and an unmatched identity starts empty. The
contract excludes checkpoint, rewind, branch, tamper evidence, an audit record, atomic commit across
an external effect, and any history shared between boxes.

<a id="a-temporal-rule-names-one-action"></a>
### A temporal rule names one action, so a budget does not span a family

A temporal predicate cannot name an action group, and it has no `or` and no wildcard. Covering a
family therefore costs one clause per action. "At most N writes in five minutes" written over
`fs:write` is not consumed by `fs:move`, `fs:delete`, or `fs:other`, so the rule loads and passes
review while those other actions remain uncounted. An exfiltration guard has the same limitation:
one keyed on reading content does not fire when the data leaves through a metadata read or a
directory listing. Write one clause per action, and say in the policy which actions the budget
covers. A cap must also be a `forbid`, never a second `permit`: permits combine by permit-overrides,
so a capped `permit` scoped to a whole action grants everything the narrow rules excluded.

<a id="only-trusted-enforcement-points-submit-history"></a>
### Only trusted enforcement points submit history

A trusted policy enforcement point submits the requests it evaluates. The workload never submits a
history event. Each MCP transport owns its own tool enforcement point, so the local broker and the
remote gateway must keep parsing, attribution, refinement, and history behaviour equivalent in two
trusted components. The gateway cannot detect when a remote provider replays an authorized request
or performs extra work for it.

<a id="there-is-no-approval-verdict"></a>
### There is no approval verdict, so no rule pauses for a human

`Decision` carries `Allow` and `Deny` only, so no rule can pause a request for a person. Any future
human-review mechanism must fail closed: a timeout, a backend error, an explicit refusal, and a
missing backend all resolve to deny. A backend may resolve only an approval the engine already
emitted. It must never turn a deny into an allow. Until then, gate a risky action with a `forbid`
and a second run.

<a id="mcp-authorization-is-two-gates"></a>
### An MCP tool call passes two gates, and the second is not default-deny

Coarse `mcp:call` is the MCP-layer gate, and its permit covers every method and tool on that server.
One request variant carries every method, with the server, the method, and the optional tool,
prompt, or resource identity, so a rule can gate any method on its own name. For a tool call, a
generated per-tool action refines that grant through `refine_tool_call`, at the local broker and the
remote gateway alike. Refinement is not default-deny. If the per-tool rule does not match, gate 1's
allow stands. If the tool has no generated action, Box skips gate 2. So a coarse grant is broad by
design, and a precise operator writes a `forbid` per risky tool.

<a id="four-mcp-methods-are-never-gated"></a>
<a id="the-protocol-floor-is-narrow-and-the-two-doors-do-not-hold-the-same-floor"></a>
### The stdio broker and remote gateway exempt different protocol methods

A few methods run without a decision because a connection needs them before rules can run. The local
stdio path lists four in `UNDECIDED_METHODS`: `initialize`, `server/discover`, `ping`, and
`subscriptions/listen`. The remote gateway holds three of those and **decides `initialize`**, so the
two paths differ and a rule can gate a remote handshake. Both paths also forward notifications
without a decision because a frame with no `id` has no reply channel for a refusal. Every other
method is decided through coarse `mcp:call`, including `tools/list`, `prompts/list`, and
`resources/list`, so an operator can gate discovery and a server cannot enumerate tools a policy
hides. Keep the floor limited to connection-critical methods. Omitting a method the protocol needs
denies the whole connection.

<a id="one-namespace-per-mcp-server-carries-its-generated-actions"></a>
### Each MCP server owns one namespace that carries its generated actions and types

A server's configured name normalizes into one namespace: keep ASCII letters, digits, and `_`,
replace every other character with `_`, prefix a leading digit with `_`, and append `_` to a
reserved keyword. That namespace holds the server's generated actions and its input, common, and
entity types. Tool arguments stay typed under `context.input`. Staging refuses a fragment whose
declarations reach outside its own namespace, and refuses any fragment that claims `Box`, which is
reserved for the built-in schema. Two different server names can normalize to the same namespace, so
generation and composition refuse the collision. The authored server name and its namespace can
differ in punctuation.

<a id="generated-argument-types-are-lowered-so-a-rule-compares-plain-values"></a>
### Generated argument types are lowered, so a rule compares plain values

The generator lowers JSON schema types that the policy language cannot represent directly: an `enum`
field drops the enum and keeps its base type, a number or float becomes an integer, and a nullable
`["X","null"]` collapses to `X`. The runtime then types the raw JSON against the lowered fragment,
so a rule writes a normal comparison on a plain value. Wrapping the value into an enum entity at
runtime was rejected, because an enum entity cannot be compared to a string. Lowering loses
information. The schema no longer enforces an enum's allowed-value set, so a rule must restrict
those values. Union types and a standalone `null` are not lowered and cannot take a bare value.

<a id="discovery-serves-the-schema-independent-subset"></a>
### While MCP discovery is pending, the box serves the schema-independent subset

`open_staged` parses the authored bundle once and installs every rule that validates without a
discovered schema, which covers `net:connect`, `http:request`, the filesystem and shell actions,
coarse `mcp:call`, and name-level or method-level MCP rules. The box decides normally in that state,
so there is no deny-all startup window and the model stays reachable while catalogs load. Only a
tool call whose per-tool typed action is still pending is held. It returns a transient pending
denial that the caller may retry. It never silently allows the call, so an out-of-band call cannot
bypass an argument constraint. Each accepted schema installs more of the rule set. The last schema
makes the authority ready. Every install retains unchanged policy identities and their temporal
state, so an incremental install replays no history.

<a id="a-server-whose-discovery-a-policy-denies-degrades-alone"></a>
### A denied tool list leaves its dependent rules unloaded until recovery

A policy can deny `tools/list` for a server and still carry a per-tool rule that needs its discovered
catalog. Box starts with that rule unloaded and refuses the tool calls it can identify as subject to
it. A later permitted list can load the rule and clear those refusals only when the complete policy
validates and commits. Until then, the rule stays inert, and a diagnostic on stderr and a telemetry
record name the servers it still needs. Refusing the whole policy at load was rejected because one
server's mistake would also block the model, shell, and other servers. The cost is that `validate`
does not report the contradiction, so the operator learns of it from the startup warning.

<a id="the-policy-crate-exposes-one-facade"></a>
### The policy crate exposes one facade

`PolicyEngine` is the one public authority, with the lifecycle `open`, `decide`, `record`, and
`effective`. The engine, the event mapping, the request gate, the staged-authority transition, and
every engine-library type stay private, so an enforcement adapter cannot skip parsing, composition,
or strict validation. The authorizer moved from Cedar to Dogwood without changing a consumer
signature. An adapter may narrow a verdict and must never manufacture an allow. A new engine or
loading profile needs a change inside the crate, and a public extension point needs a named external
consumer before it is added.

<a id="the-observation-seam-is-write-only"></a>
<a id="the-one-observation-seam-is-write-only"></a>
### The observer receives decisions and cannot change them

`DecisionObserver` is public and `observed_by` installs one, as a consuming setter, so one observer
sees the authority's whole life. Four properties keep the observer on the decision's output path:
`observed` returns nothing, it runs after the operation has already selected its verdict, it
receives the action and resource already extracted instead of the request, and it receives no
principal. An observer therefore cannot alter, veto, or delay a verdict. A failing observer cannot
fail a decision. An observer must not block, await, or perform input or output, because it runs
inside a decision operation; the type cannot enforce those restrictions, so the observer
implementation must honour them. An enforcement point can still narrow the value an observer saw, so
do not treat the observer as the box's audit source.

<a id="the-effective-policy-report-is-diagnostic-not-an-attestation"></a>
### The effective-policy report is diagnostic, not an attestation

`EffectivePolicy` reports the engine identity and a policy label. The label is diagnostic. It is
neither a content hash nor a verified bundle revision, so the report cannot prove which policy text
ran. Any run gate of the form "refuse to run unless registered and baseline-satisfied" belongs to
the caller, because only the caller sees every input the gate needs. A security evaluator should
read this report as a label and verify the policy file itself.

<a id="a-reviewed-example-library-is-the-authoring-floor"></a>
<a id="a-maintained-library-of-reviewed-example-policies-is-the-authoring-floor"></a>
### Reviewed example policies support human and agent authors

The box is deny-by-default, so an operator must state every allowed action before the workload can
act, and authoring that allowlist is part of using the product. The box ships and maintains a
library of reviewed example policies, and it supports both authoring modes: a human reads and edits
from it, and a local agent uses it as source material to turn an intent into a policy. Documentation
alone was rejected, because it leaves every author to start with a blank file. Agent generation
alone was rejected, because an operator without an agent could not use it, and reviewers would have
no trusted reference. The cost is a standing maintenance burden: the examples and the authoring
skill must track the action vocabulary as it moves.

<a id="a-tool-grammar-is-data-never-code"></a>
### A tool grammar is data, never code

A tool grammar is TOML that describes one tool: its actions, its effects, and the rules Box uses to
recognize those actions. It holds no code, so loading a grammar runs no external code in the trusted
process. Authors and reviewers work with TOML data. Parsers written as Python code that runs in
Monty were rejected. The cost is that a grammar can describe only what its rules can express.

<a id="box-owns-the-tool-grammar-format"></a>
### Box owns the tool grammar file format, and it is separate from the grammar's own version

A tool grammar file declares two versions. `format` is the version of the grammar file language. Box
owns it and bumps it when new or changed keys cannot be read by an older Box. `version` is the major
version of the grammar's content, and the grammar author owns it. Box refuses a file with no
`format`, or with a `format` it does not read, and a missing `format` does not default to 1. The
cost is that every grammar file must state `format = 1`.

<a id="a-grammar-action-replaces-shell-spawn"></a>
### One gate: a tool grammar action replaces `shell:spawn` for a bound program

When a tool grammar binds a program, Box decides each spawn of it that the Shell raises as the
grammar action alone, such as `Tool::git::Action::"push"`, or `unmodeled` when the grammar can't
read the command. It doesn't decide `shell:spawn` as well. A grammar action follows the ordinary
rules. It requires a permit, absent policy is default-deny, and a forbid wins. To allow every git
command the grammar reads, you write:

```dw
permit (principal, action in Tool::git::Action::"*", resource);
```

We rejected two gates with `shell:spawn` first and the grammar action second. The second gate could
only narrow the first, so a grammar-action permit would not authorize anything by itself. A command
the grammar could not read would be allowed whenever `shell:spawn` permitted it. When the team
reviewed it, everyone found that confusing. Once a grammar binds a program, `shell:spawn` rules stop
applying to it. A `shell:spawn` permit no longer admits `git`, and a `shell:spawn` forbid no longer
refuses it. An operator who installs a grammar must move those rules to the grammar's actions. A
`when temporal` rule that reads `shell:spawn` history also stops seeing a bound program, because
each spawn of it enters history as its grammar action.

<a id="a-grammar-action-names-no-enforcement-point"></a>
### A tool grammar action doesn't name where Box enforces it

A tool grammar action names what the tool does, not where Box sees it happen. To deny a git force
push, you forbid `Tool::git::Action::"push"` when
`context.input.effects.contains(Tool::git::Effect::"force_push")`, and the rule doesn't say whether
the push arrives as a shell command or as an HTTP request. The rule uses the tool's actions and
effects. Box determines where and how to enforce it. An action per enforcement point, such as a
separate shell push and HTTP push, was rejected, because you'd have to write each rule once for each
enforcement point, and a rule written for one would silently miss the others. The action name cannot
distinguish enforcement points. Every enforcement point the grammar covers must map a request to the
same fields and effects, or the same rule will have different meanings.

<a id="an-unmodeled-command-is-denied-by-default"></a>
### A request the grammar can't read is the `unmodeled` action, and it's denied by default

When a tool grammar can't read a request, Box raises `Tool::<name>::Action::"unmodeled"`, and your
policy decides it like any other action. With no rule that permits it, it's denied. `unmodeled` sits
outside the tool grammar's `"*"` group, so a permit on `action in Tool::git::Action::"*"` never
allows a command the grammar can't read. To allow one, a rule must name
`Tool::git::Action::"unmodeled"` itself. We rejected putting `unmodeled` inside `"*"`. A permit over
the whole tool would then allow every command the grammar cannot read, including a spelling intended
to bypass it, such as `git push --dele origin main`. The cost is that a forbid over `"*"` also skips
`unmodeled`. Under a policy that permits everything, a rule that denies all of git must name both:

```dw
forbid (principal, action in [Tool::git::Action::"*", Tool::git::Action::"unmodeled"], resource);
```

<a id="a-tool-grammar-binds-on-the-program-file-and-the-called-name"></a>
### A tool grammar binds by its program name, on the program file's identity and the name it was called by, and any other name of that file is a `shell:spawn`

A tool grammar names one program, and it binds every `[tool]` whose command calls that program name.
A grammar on `[tool.git]` with `program = "git"` at `/usr/bin/git` also covers `[tool.brew_git]` at
`/opt/homebrew/bin/git`, because both run `git`. One program name therefore has at most one grammar.
Box refuses a second grammar with the same `program` and names both tables. Letting two grammars
share a program was rejected, because both would match the same tools. Table order would then select
which grammar reads a command. A stdio `[mcp.<name>]` whose command calls that program name binds
the same way, so its start is decided as the grammar's action.

For each tool, Box binds the grammar to a pair: the identity of the resolved program file, and the
name the program was called by. The identity is the file's device and inode on the surrounding OS. A
hard link or symbolic link to a bound file therefore refers to the same identity. A command is
parsed with a tool grammar only when both halves match one binding. The file identity alone isn't
enough, because several programs can share one binary. mise runs every tool it manages through one
shim binary, so `cargo`, `node`, and `npm` all resolve to the same file, and `cargo` and `rustc` can
be links to one binary. The name alone isn't enough, because the caller picks the name, so any file
called `git` would claim the git grammar. We rejected binding on file identity alone. It needs one
lookup but would parse `npm install` through the mise shim binary as a cargo command.

Several grammars can bind one file, each under its own program name. So a cargo grammar binds the
mise shim binary as `cargo`, and an npm grammar binds the same file as `npm`. One grammar per file
was rejected, because then only one tool that mise manages could have a grammar.

A spawn of a bound file by a name that no grammar binds is decided as `shell:spawn`, whether or not a
`[tool]` declares that name. macOS `/usr/bin/git` is one developer-tool launcher
file with about 78 names, such as `make` and `clang`, and it runs the tool its called name selects.
A git grammar on it decides `git`, and the `shell:spawn` rules decide `make`. We rejected refusing an
undeclared name outright, before any rule decides it. On a file with several names, such as that
launcher, every other name would become a spawn that no policy can permit, so a git grammar on
`/usr/bin/git` would refuse `make` and `clang`. Reading an undeclared name as the grammar's
`unmodeled` action was also rejected. When several grammars bind one file, no single grammar owns
the name, and a rule that permits `unmodeled` would admit a program that the operator never named.

Box refuses a spawn of a bound file before the policy decision in three cases, and no rule can
permit any of them. The first is a replaced file: the bound path or link now leads to another file,
for example after an update while the box runs. The second is a bare name whose bound file is gone
or replaced, so `PATH` would find another file. A new file therefore cannot claim a grammar's
permits under a bound name. The third is an agent spawn under a name that only a stdio
`[mcp.<name>]` declares for that file. An `[mcp]` server's name counts only for that server's
start, because the start and an agent spawn under the same spelling make the same `shell:spawn`
request, and the permit the server needs would otherwise let the agent skip the grammar. Box also
refuses bindings that another policy engine issued, so the bindings that decide a spawn are always
those of the engine that decides it.

The cost has four parts. Two binaries of one program can't have different grammars: `/usr/bin/git`
and `/opt/homebrew/bin/git` both read with the one git grammar. A bound file called by a name that no
grammar binds is governed only by `shell:spawn`. That includes `make` through the macOS launcher,
`python` through the mise shim binary, and a link `g` to a bound `git` that the workload can create
where it can write. A `shell:spawn` permit that matches the bound file's `program_path` therefore
admits each other name of it, so pin each `shell:spawn` permit on both `program` and `program_path`.
An update that replaces a bound binary while the box runs refuses its bound names until the box
restarts. A grammar also covers only the files that a `[tool]` or a stdio `[mcp.<name>]` runs. A copy
of a bound binary at another path, or the same program reached through an unbound shim binary, is
decided by the `shell:spawn` rules and not by its grammar.

## Containment

<a id="box-owns-its-containment-code"></a>
### Box owns its containment code

Box writes and owns its containment crate. It takes no runtime dependency on an external sandbox
project, and it does not fork one. The cost is that Box owns platform correctness, conformance
coverage, and incident response for a security boundary. Owning the crate lets Box remove behaviour
it cannot enforce and patch enforcement directly.

<a id="containment-is-fixed-and-built-without-running-a-program"></a>
### Box builds the sandbox grants without running a program, and fixes them for the box's life

Box reads its configuration inputs and writes the sandbox grants. It runs no program to author one.
Box does not run the operator's named runtime to learn its version or location. Inspecting a program
that way would execute it before the boundary exists. A tampered runtime would then have the
operator's full reach. The operator states every path and version up front. The configuration then
never changes while the box runs, and no process inside or outside it can make it less strict. A
wrongly stated path fails startup inside the boundary rather than producing an earlier warning. The
contract also leaves unspecified what happens if a mechanism detaches while the box runs.

<a id="the-closed-choice-is-the-default"></a>
### An omitted field keeps the closed default

A new set of sandbox grants carries no filesystem grants, no socket grants, blocked network,
isolated signals and process information, inter-process communication limited to shared memory, and
no backend override. An omitted field keeps that baseline. Forgetting a field therefore cannot widen
access.

<a id="every-failed-or-unsupported-apply-refuses-the-workload"></a>
### Every unsupported or failed apply refuses the workload

One call detects the surrounding OS, selects the backend, checks support, validates the request, and
applies it to the kernel. If any step fails, the workload does not run. There is no warning-only
mode, no automatic weaker backend, and no uncontained fallback. Box also refuses to run when it
cannot verify that the sandbox is in place for this box. The [dependency startup
design](containment.md#dependency-read-startup-design) requires grouped missing-read reports before
the affected workload launches. The reports suggest configuration additions and state the limits of
discovery. That guidance preserves existing entries and never suggests overriding explicit denials
or protected paths. Operators must review additional access and retry, while platforms Box cannot
enforce remain unsupported.

<a id="the-linux-boundary-is-namespaces-not-landlock"></a>
### The Linux boundary is namespaces and a syscall filter, and never Landlock

On Linux, Box builds the boundary from namespaces, a mount view, and a syscall permit filter. Box
rejects Landlock as the baseline, because no Landlock right denies all network at any ABI version,
so a contained child would keep unrestricted network. Box does not probe the kernel ABI version. A
gate based on that probe once refused every kernel Box ships on. Platform and architecture alone
select the mechanism. macOS uses Seatbelt, and Linux on ARM64 uses the namespace launcher. Box
refuses every other Linux architecture by name.

<a id="containment-ends-with-the-contained-process"></a>
### The sandbox ends with the contained process

Apply is one irreversible transition on the calling process. It lasts until that process exits, and
the process's descendants inherit it. There is no lifecycle handle, no teardown call, no checkpoint,
and no recovery call. The caller must supply a supervisor to own the working directory, environment,
termination, and durable state. The sandbox owns none of them.

<a id="children-inherit-the-boundary"></a>
### Children inherit the boundary, and no call widens it

Every descendant of a process with a successfully applied sandbox inherits at least the same
restrictions. Replacing the program preserves them. No call elevates a child. A process that needs
different reach needs a different configuration and a fresh contained process, and applying twice
widens nothing. Process creation is granted with no limit, so the sandbox does not bound fork bombs,
disk fill, or CPU consumption.

<a id="one-private-backend-enforces-the-whole-configuration"></a>
### One private backend enforces the whole configuration

A caller declares one set of sandbox grants and selects no mechanism. Apply detects the surrounding
OS privately, chooses one backend, and requires that backend to enforce the whole request. The
backend traits, the backends, and the detection stay crate-private, so no caller can ask for a
weaker mechanism or a partial apply. A product that needs visible protection tiers must define them
above operating system enforcement. The containment crate offers no such tiers.

<a id="containment-evaluates-no-policy"></a>
### The sandbox applies its grants and evaluates no policy

The containment crate enforces a caller-supplied configuration. It evaluates no authorization
policy, and it imports no policy engine, no principal, and no product identifier. The dependency
runs in one direction. A policy layer builds a configuration and calls containment. Two authorities
would give two answers to one question, so the authored policy stays the only authorizer, and
containment stays a deny-only floor beneath it.

<a id="one-trampoline-spawns-every-contained-process"></a>
### One owned, process-agnostic trampoline spawns every contained process

One small program applies the sandbox and execs the target. Every caller supplies the same grammar:
a configuration file, a digest over it, the target environment as JSON, optional status and control
descriptors, and then the command. It is process-agnostic, so nothing about a particular workload
lives inside it. Its exit codes separate three failures: a setup error before the sandbox applies, a
failed apply, and a contained process whose environment decode or exec failed.

<a id="installed-box-programs-resist-workload-writes"></a>
### Installed Box programs resist workload writes

Box protects its installed programs from workload changes, even when policy or a filesystem grant
permits the write. The protected programs are the main executable, containment trampoline,
socket-alias image, and the macOS package launcher when present. These programs start containment or
route workload operations through it. Box therefore protects them like configured tool programs.

`TrustedInstallation` retains their identities and refuses grants and broker mutations that can
replace the files or their paths. The cost is that writable development trees must exclude the
running installation and its verified alternative names. The operator owns initial contents and
updates between runs, and the public build marker identifies artifact kind rather than
authenticating contents.
`every_process_table_refuses_writes_to_installed_executables_and_their_ancestors` and
`the_hosted_shell_cannot_rename_installed_executables_or_their_ancestors` pin the direct-grant and
broker checks.

<a id="the-configuration-crosses-exec-as-digest-bound-json"></a>
### The configuration crosses the exec boundary as an inherited descriptor, bound by a digest

Box serializes the complete request, writes it to a file the target is not granted, computes a
digest over those exact bytes, and passes the open descriptor to the trampoline. The trampoline
reads the inherited descriptor rather than opening the filename. Replacing or truncating the file
after Box opens it therefore does not change the configuration it applies. A digest failure or a
load failure stops apply and exec, so a swapped configuration becomes a refusal rather than a weaker
boundary. `config_load_returns_exact_bytes_and_keeps_the_caller_owned_file` and
`inherited_config_read_uses_the_opened_file_after_a_path_swap` pin the two halves.

<a id="a-grant-is-one-operation-at-one-scope"></a>
### A grant is one operation at one scope, and eight combinations are unrepresentable

A grant states one operation at one scope. The operations are exec, read, write, connect, list,
metadata, and deny. The scopes are one file, one directory, and a whole tree. The model cannot
represent eight combinations, so a backend never receives a pair it cannot render. A directory has
no bytes to execute, a file has no entries to enumerate, and a socket grant must name one existing
file. Metadata is the cell for a path the workload stats and never reads, and exec at whole-tree
scope authorizes every program in a named toolchain directory. Read plus write requires membership
in two lists. Write alone does not imply read. A grant states what it authorizes and never who asked
for it.

<a id="the-configuration-is-its-own-wire-format"></a>
### The configuration is the wire format, and there is no mirror type

The configuration type serializes and deserializes directly. Each field revalidates its invariants
on load. A path grant reruns its validated constructor and refuses a changed resolved path. The
network field reruns the builder's port checks. Unknown keys are refused at every level, and a
missing key is an error except for one additive field that only a tool's or MCP server's sandbox
sets. Its default is the closed value. An older trampoline reading a newer configuration therefore
applies the agent restrictions rather than the wider tool and server grants. We rejected parallel
spec types because they would duplicate the model and could silently drift from it. A refusal
reaches the operator as the serializer's parse-error text, reported verbatim.

<a id="localhost-names-the-ports-the-workload-reaches"></a>
### Loopback network access names the ports the workload reaches, and no count bounds them

The loopback network mode carries two lists, one for outbound connect and one for listen. Only
`connect` renders. Both backends refuse a non-empty `listen`, so the field does not yet support
inbound binds. Box refuses an empty connect list because it would select loopback access without
granting any. It also refuses repeated entries. No count bounds the lists, because a limit there
would refuse a composition the caller authorized, at a layer that cannot see what was asked for.
Every entry is loopback and policy still decides each request, so this list cannot become a
destination allowlist.

<a id="a-denial-is-an-operation-not-a-second-list"></a>
### A denial is an operation, not a second list

A caller that must grant a directory holding something it does not own states two entries: the
grant, and a denial on the same path type, in the same list. There is no second type and no second
wire key. A denial wins over every path grant, in any order the caller stated them, and it is exempt
from the bounding floors because it grants no access. It is the only entry that may name a path that
does not exist, because a harness configuration directory is commonly absent and a grant enclosing
its future location must still be subtracted. It is legal at file scope and whole-tree scope and
refused at directory scope, because a directory's own entry alone would leave its contents
reachable. The guarantee covers the denials known at launch, so a hard link to a refused object, and
a box state directory created after launch, stay residual risks.

<a id="an-opened-file-can-require-identity-or-write-protection"></a>
### An opened file can require identity, or write protection, and the two are separate

A caller can load authority before the sandbox applies, for example a certificate bundle. It passes
the opened regular file and its canonical path to one of two configuration methods. Both record the
device and inode, require the file to have one filesystem name, and revalidate path and identity at
each backend's last safe point. One method also subtracts writes, for a file that sits below a wider
writable grant; the other grants no access at all, for a file outside every writable grant.

A third method pins a configured tool's program. It records the file's link count and requires the
same count during revalidation. Box accepts a program with several names only when the user running
Box cannot write it through any name, or when every name is in the program's own folder, which no
write grant may reach. A backend may make the file non-executable if it cannot preserve both write subtraction and
write-xor-execute. Callers must not rely on write protection to preserve an execute grant.

<a id="the-deny-only-floors-run-beneath-every-backend"></a>
### The deny-only floors run beneath every backend, in one module

One module holds every check that judges a grant set, and one function is its only caller, so each
check runs beneath every backend instead of inside some of them. The checks run in cost order: the
pure checks read only recorded values and run first, and the check that re-resolves a path on the
filesystem runs last. A grant naming the root is therefore refused without a single
canonicalization, which matters because a grant's path can be workload-influenced, and refusing it
must not require acting on it first. Three refusals enforce these limits. A grant may not reach a
forbidden path. Two nested writable entries are refused because the inner grant imposes no
additional restriction. An `Exec` grant on a setuid or setgid file is also refused. At root scope,
that check walks the whole tree without following links. It is the only code-level check that
prevents escalation through an exec grant.

<a id="write-plus-execute-warns-and-does-not-refuse"></a>
### Write plus execute on one path warns, and does not refuse

This rule applies to workload programs outside the files Box protects from writes. An operator who
names one directory in both a write list and an exec list gets a warning at startup, and the box
still runs. A refusal was wrong for a real build, which loads and runs what it compiles. The warning
names the executable and the write grant that reaches it. If the operator continues after the
warning, the workload can replace that program.

<a id="a-write-root-sets-file-attributes-only-when-selected"></a>
<a id="a-macos-write-root-sets-file-times-through-utimensat-and-setattrlist-only-when-file-attributes-selects-it-and-then-setattrlist-reaches-more"></a>
### `file-attributes` enables timestamp changes and broader `setattrlist` access

A macOS write root names six write operations. `utimes` works, but `utimensat` and `setattrlist`,
which `touch` and `cp -p` use, check the bare `file-write*` family, and no rule grants the times
alone. The top-level `file-attributes = true` adds `file-write*` over each process's write roots. It
denies the four leaf operations the root withholds, `chflags`, `chown`, `acl_set_file`, and Finder
information. Every protection and refusal renders after this grant and still wins. The key is part
of the workload input. It widens only access from the workload's own `write` lists, and each process
discloses it. It is off by default because tenet 1 takes precedence over tenets 3 and 7. `touch`
fails until the author of `box.toml` selects it. A box running as root [also accepts
it](#file-attributes-is-accepted-when-the-box-runs-as-root).

Linux accepts the key without rendering a grant. `utimensat` already works there, and Linux
continues to refuse set-ID bits and ACLs. One `box.toml` therefore stays portable without widening
Linux access. It is an ordinary key, not an experimental feature, because it is opt-in and changes
only what the workload already reaches. Box stores a record that selects the key at version 25,
or at a newer version when a Shell timeout is explicit. A build that predates the key therefore
refuses the box, as
`the_file_attributes_key_cannot_hide_in_a_legacy_record` checks.

A grant operation per folder would confine the residual risk to named folders, but it would add an
operation to the frozen grant model.

The workspace and its temporary folder need file times and are also where the residual risk matters
most. A per-process selection like `native-filesystem-policy` would still need to cover the agent.
The agent sets times itself through `touch` and Kiro CLI's lock refresh, and its workspace is where
the residual risk matters most. An MCP server that needs file times only in its cache therefore
requires the switch for every process. That wider selection carries the residual risk.
`with_the_switch_setattrlist_reaches_the_setuid_bit_the_group_and_the_owner_as_known_residuals`
checks that `setattrlist` stores a set-ID bit, changes the group, and reaches the owner in a write
root. It also stores an ACL, which measurements confirm but no test pins. In a box that runs as
root, a set-user-ID file that the workload leaves would run as root for whoever starts it, so
[host-backed effects](#host-backed-effects-refuse-what-a-write-cannot-produce) no longer bound what
the workload writes to real disk while the switch is on.

<a id="file-attributes-is-accepted-when-the-box-runs-as-root"></a>
### A box that runs as root accepts `file-attributes`, and the writer of `box.toml` decides

Box applies `file-attributes = true` whatever its effective user ID, and it does not refuse the
switch at startup when `geteuid()` is 0. Refusing startup at euid 0 would keep the profile unchanged
and block the case where the residual becomes privilege escalation. We rejected that refusal because
the author of `box.toml` knows whether the root workload needs file times. That author can leave the
switch off for a root box until its user opts in. With the switch on, a box running as root can
leave a root-owned set-user-ID file on real disk. Any local user who can reach that folder can run
the file outside the sandbox. The startup disclosure and [file attributes on
macOS](../user/security.md#file-attributes-on-macos) are the only guards.

<a id="one-forbidden-path-list-and-each-row-states-its-rule"></a>
### One forbidden-path list, and each row states its own match rule

One list states every path no grant may reach. Each row has four fields. Its anchor is absolute or
relative to the operator's home. The other fields are the match rule, the cells it permits, and a
class that supplies the refusal reason. The class also controls exemptions. An operator can exempt
only a credential store by naming it exactly. `only_a_credential_store_row_is_exemptible` checks
that restriction. The match rule has no default because the two choices fail differently. An
incorrect exact match silently permits too much. An incorrect overlap match refuses too much with an
error. A row's permitted cells let a workload stat paths it cannot read. Every new row refuses all
cells until an author names one. This one list replaced a second credential-path list another crate
held, because separate owners can each omit a protected path from their list. A misclassified row is
a residual risk that only one case table over the whole list can catch.

<a id="a-caller-adds-a-floor-anchor-and-never-moves-one"></a>
### A caller adds a floor anchor and can never move one

The floor anchors every home-relative row at the account database home, and a caller resolves its
own grants against the environment's home. The two can differ, under a preserved-environment `sudo`,
a container, a CI runner, or a test fixture. So the configuration carries the home the caller
resolved its grants against, and the floor resolves every row over the union of that home and the
account database home, which is always present. Adding an anchor adds refusals and removes none. A
wrong or hostile home can therefore widen the refusal set but cannot narrow it. A caller that
declines to state its home gets the account database anchor alone, and the floor cannot detect that.

<a id="the-operating-system-states-its-own-paths-as-data"></a>
### The operating system states its own paths as data, not as code

The paths every process needs from the surrounding OS, and the paths no grant may reach, live in
data files in the containment crate. One file per platform states two grant sets: what any process
needs to load and run, and what a host toolchain needs in addition. A third file states every
forbidden row. The grant sets are per platform, because one cross-platform list would grant paths on
Linux that a Linux workload must not receive. The forbidden rows carry both platform spellings on
every host, because a configuration authored on one platform can be applied on another. A malformed
file panics at first use because malformed compiled data is a programming error.

<a id="a-direct-grant-replaces-the-policy-decision"></a>
### A direct grant replaces the policy decision, and does not add to it

An operator can expose a surrounding-OS file or directory tree to the workload directly. The
workload then reaches it with its own syscalls, so no policy decision fires for that access and no
record of it exists. Box has no second positive allowlist for paths an operator may grant. The
deny-only floors impose the full limit and still refuse protected paths. Both sets start empty, and
each entry needs explicit operator action. A broad read grant can expose source, configuration, or a
credential the floor does not name, and a broad write grant can corrupt host state or alter an input
another process reads.

<a id="resolve-the-path-once-then-act-on-the-object"></a>
### The box's trusted process resolves a path once, then acts on the object it resolved

The box's trusted process resolves any path the box supplies before it decides, and then acts on the
object it resolved, holding that object across the decision. It refuses a symlink met during
resolution, and it refuses any component that leaves the set it resolved within. It never walks a
path a second time after deciding. A name is not an object, and two walks of one name can reach two
objects, so deciding on one string and acting on another can make the trusted process bypass its own
boundary. "A path the box supplies" means every path derived from anything the box controls,
including argv, the working directory, an environment value, and a path inside a file the box wrote.

<a id="a-denial-names-the-rule-that-refused-it"></a>
### A refusal names the component, the reason, and the rule that decided

A denied request tells the workload which component rejected it, why, and which rule decided. The
alternative was one generic refusal, so a workload could not probe operations and rebuild the policy
from which ones fail differently. We chose diagnostic detail and accept that the workload can use
refusal differences to infer policy.

<a id="box-does-not-filter-workload-output"></a>
### Box does not filter workload output

An interactive agent receives the operator's terminal directly, and Box passes its output through
unchanged. Filtering that stream added no protection for the surrounding OS under a hostile-workload
assumption, and it broke terminal compatibility. The terminal emulator interprets control sequences
in workload output. The workload controls those bytes.

### Sandboxes for tools and MCP servers

Box starts a separate sandbox for each operator-declared host program: a toolchain binary that a
`shell:spawn` permit admits, or a stdio MCP server. Each is contained separately from the agent's
sandbox, and each exception below applies to that sandbox alone. The configuration and rendered
profile of the agent's sandbox stay byte-identical whether or not any such sandbox exists.

<a id="a-leaf-discovers-existence-and-metadata-content-stays-gated"></a>
#### A tool or MCP server discovers existence and metadata across the operator home, and content stays gated

A permitted host binary probes for optional configuration it may never read: a version control tool
looks for its own configuration file in the home. The agent's sandbox denies existence checks under
the home. There, the probe fails with a fatal permission error instead of reporting not-found. A
tool or MCP server receives different sandbox grants to support those probes. It can test existence
and read metadata across the operator home, and content stays gated behind that sandbox's own read
grants. Box renders two subtractions last so discovery rules cannot override them: the box state
namespace is denied existence and metadata except for the exact paths a grant already names beneath
it, and the credential floor is refused existence and metadata even under discovery.
`a_leaf_discovers_the_operator_home_and_the_main_box_does_not` pins it. A tool or MCP server
therefore learns which paths exist across the operator home. These discovery grants render only on
macOS.

<a id="a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds"></a>
#### A tool or MCP server runs its whole toolchain, and loads what it builds

A tool or MCP server must run helpers and load programs or libraries that it builds. After policy
admits the top-level program, its sandbox permits execution from its readable and writable grants.
macOS uses process-execution rules and executable mappings. Linux makes the corresponding file and
directory mounts executable. Requiring every helper or build output to be listed would prevent
toolchains from selecting their own programs.

The cost is that a tool can execute code it changes within its writable grants, while the agent
retains its existing execution restrictions. Linux keeps automatic temporary mounts, refused paths,
and protected files non-executable. `cn_x_04` tests execution and library loading from tool output,
with agent denials on both platforms.

<a id="native-egress-is-an-operator-declared-leaf-escape"></a>
#### Native egress is an operator-declared escape from a tool's or server's sandbox, recorded as a downgrade

A trusted tool or MCP server may run a client that cannot honour a proxy setting, so gateway-routed
egress blocks its calls. An operator can declare native egress for one stdio MCP server with
`[mcp.<name>.network] contain_egress = false`, or one tool with
`[tool.<name>.network] contain_egress = false`. That program's sandbox then reaches the network
directly. Its traffic bypasses gateway mediation, per-request network policy, credential injection,
and connection-level journaling. The agent refuses the key, so it and every tool or server that does
not opt in keep the gateway, including a program that runs under an `exec` grant rather than a tool
table. The box's trusted process emits an `egress:native` decision naming the server or the tool
whose traffic will not appear, after its sandbox starts. A tool adds a risk beyond a server because
the agent chooses the tool's arguments. The agent can therefore direct a native tool's network
calls. Declaring a general client such as `curl` or an interpreter native gives the agent unmediated
reach. The platforms grant different reach. On Linux, the program's sandbox joins the surrounding OS
network namespace. It reaches the public and private networks, the machine's loopback services, and
the instance metadata endpoint. Treat this flag as a host-network trust grant for one named tool or
server, never a default.

<a id="a-leaf-reaches-the-host-startup-runtime-services"></a>
#### Agents get account lookup; tool and MCP server sandboxes can also request network startup services

On macOS, agent profiles allow lookup of `com.apple.system.opendirectoryd.libinfo` because Codex
requires it to load managed preferences. Tool and MCP server processes already receive this lookup
through their sandbox's runtime-services option; agent profiles now expose that existing capability
directly. A TOML option adds configuration without limiting service requests once enabled, so
account lookup belongs in the agent runtime minimum. The grant does not limit service messages to
read-only queries or the current user's record; service-side authorization remains outside this
sandbox rule. `agent_account_lookup_does_not_grant_leaf_network_runtime_services` proves the agent
gains neither `net.*` reads nor a routing socket, while tool and MCP server sandboxes that don't opt
in gain no lookup. `account_lookup_is_allowed_but_preferences_services_remain_denied` checks live
account lookup and preference-service denials against successful outside controls.

## Interpreters

Box runs two interpreters for the workload: the vendored Strands Shell, and Monty, which is the
Python interpreter.

<a id="interpreters-are-vendored-not-the-host-shell"></a>
### Box runs a vendored interpreter, never the host OS's shell

Box runs every shell command the agent issues through Strands Shell, an open-source interpreter that
Box vendors at a pinned revision. It never runs `bash` or `zsh` from the surrounding OS for the
agent's sandbox. A tool's or MCP server's sandbox runs programs of the surrounding OS, a shell
included, inside that sandbox. A harness runs a real shell for its command tool, so Box gives it
something with the same exit codes, the same stdout and stderr shape, and the same argument
conventions. Each filesystem operation is a Rust method call that Box intercepts before acting. The
Shell does not make that operation as a syscall on its own authority. Box vendors the interpreter
instead of writing one, because upstream already holds the parser, the pipelines, the control flow,
and more than fifty builtins. Box must keep every builtin on the interception path. Updating the
vendored interpreter requires a merge, and Box must fix upstream defects it encounters.

<a id="the-interpreters-run-in-the-trusted-process"></a>
### Both interpreters run in the box's trusted process, and that is stated residual risk

The Shell and Monty run in the `run` process. That process is outside the sandbox boundary, and it
holds the policy engine, the interception CA key, and the resolved secrets. The vendored Shell
always embeds a Lua 5.4 C interpreter, which the workload reaches through the `lua` builtin. The
Shell is therefore not a small interpreter with no `unsafe` code. Monty has weaker memory-safety
guarantees. The pinned version contains 46 `unsafe` blocks, including a custom raw-pointer heap. We
accept the placement because Box mediates effects, despite the memory-safety risk. Neither
interpreter performs I/O of its own. Each effect suspends the interpreter so the box's trusted
process can perform it on a policy-approved canonical path. The deny-only floors apply regardless of
the interpreter's internal work. A security evaluator must treat a memory defect in either
interpreter as code execution in the box's trusted process. Stronger isolation would move each
interpreter into a separate process and require it to request decisions over a channel. Box does not
do that today.

<a id="the-shell-checks-policy-at-two-levels"></a>
### The Shell asks policy at two levels, on the resolved effect, above a deny-only floor

The Shell asks policy twice. The command level asks whether the agent may run the program at all:
`shell:exec` for a program the Shell implements, and `shell:spawn` for a host binary. It asks once,
before the program starts. The effect level asks whether each filesystem operation of the running
command is allowed, as an `fs:*` action. For each effect, the Shell resolves the path, checks
policy, executes the operation, and reports the result. Policy judges the resolved path rather than
the name the agent typed. A deny-only floor sits beneath policy, and no rule widens it. The command
check stops a forbidden program before it starts, and the effect check stops a permitted program
from reaching a path that no rule granted. Each filesystem verb must go through one kernel method,
so a re-implemented command calls that method rather than the OS.

<a id="one-admission-point-after-resolution"></a>
### One admission point judges every route that evaluates command text, after resolution

Command admission happens in one function that every command-text route reaches, and it happens
after resolution, not at the outer entry points. Routes such as the Lua `io.popen` and `os.execute`
builtins, `find -exec`, `xargs`, `sh <file>`, the `.` and `source` builtins, an `EXIT` trap body,
and command substitution all re-enter the executor from inside the crate. A gate on the public entry
points misses each of them, so a permitted command could start many commands without decisions.
`lua_popen_is_judged_by_policy` and `find_exec_and_xargs_are_judged_per_nested_command` pin the
rule. Admission also happens after parsing, expansion, and resolution of the first word, because
only then is the real program known. A nested command is its own decision, so `find -exec` over N
matches raises N decisions plus the outer one. Do not add a second admission call at an entry point,
because it counts one submission twice. A `forbid` on command text is a weak control because one
effect has many spellings. Write a rule on the resolved `program` or use path-scoped `fs:*` rules.

<a id="a-resolved-token-binds-the-object-it-names"></a>
### A resolved token binds the object it names, so a symlink swap cannot divert an effect

The token that a path check produces carries a device and inode identity, captured when the path
resolves. A host-backed effect re-derives that identity immediately before it acts, and it refuses
on any mismatch. A host path whose identity Box cannot derive fails closed, for a read as well as
for a write. An in-memory effect re-resolves the token path under the same lock as the mutation.
`a_background_symlink_swap_cannot_beat_the_admission_window` and
`a_host_effect_with_an_unbindable_identity_fails_closed` pin the two halves. A host write holds the
opened file across the check and flushes through that descriptor, so a directory swapped inside the
admission window cannot divert it, which
`in_mount_admission_window.rs::a_directory_swapped_inside_the_admission_window_cannot_divert_a_host_write`
pins. The token is taken on the path with every symbolic link followed, and Box refuses it when the
identity it pins is not that path, which
`a_pin_whose_host_identity_is_not_the_spelling_is_unavailable` pins. The pin and the effect both
reach the parent directory from the bind root one component at a time, refusing a symbolic link at
every component, which `a_symlinked_ancestor_is_neither_pinned_nor_opened` pins. Listing, metadata,
`cd`, `readlink`, and `glob` still act on the path again after the check. A swap there can reveal
names and metadata, and the check does not refuse a swap of two real directories.

<a id="host-backed-effects-refuse-what-a-write-cannot-produce"></a>
### On a shared inode, a host-backed effect is stricter than a write

A host `chmod` applies the ordinary permission bits and refuses an explicit request to set setuid,
setgid, or the sticky bit. A host `ln -s` refuses a target that is absolute, or that leaves the
bind. The Shell acts on inodes that a writable bind shares with the operator's real filesystem, from
outside the sandbox. A set-user-ID bit written there persists on real disk, where a process outside
the box honours it. A symlink also stores its target as given, so a reader outside the box would
follow it. Each refusal is a deny-only limit beneath policy. A script that runs `chmod 4755` or
links to an absolute path fails with an error. An ordinary `chmod +x` also drops an existing setgid
or sticky bit. This does not cover the workload's own syscalls inside the sandbox. The sandbox
refuses a `chmod` of a set-ID bit, but `setattrlist` stores one on macOS when
[`file-attributes`](#a-write-root-sets-file-attributes-only-when-selected) is on, and `symlinkat` is
not covered.

<a id="shell-network-goes-through-the-egress-gateway"></a>
### Box's kernel wrapper sends the Shell's HTTP through the egress gateway

Box owns the Shell's HTTP step. `CallKernel::http_request` does not hand a request to the vendored
backend. The wrapper refuses every request when the box has no gateway. Otherwise, it runs the private-address floor and sends the request with its own client. That client dials the box's egress gateway on loopback,
trusts only the gateway's interception CA, and follows no redirect, so each `curl -L` hop is a new
request through the wrapper. It ignores `curl -k`. The backend keeps its own network off, so the
vendored client can't dial even if a call skips the wrapper. The gateway stays the one authority for
`net:connect` and `http:request`, and the Shell resolves no credential and attaches no secret.

The alternative was proxy fields on the vendored `VfsKernel`, set through
`ShellBuilder::egress_proxy`. Upstream Shell doesn't have that feature and Box won't propose it, and
the builder calls did nothing once Box supplied its own kernel.

The wrapper governs only requests that reach the kernel's HTTP step. A future Shell network command
that builds its own client would skip it. A test in `shell_egress_client_guard.rs` fails if a client
is built in the Shell sources outside `vfs_kernel.rs` and `shell.rs`, but that check is a lint and
not a guarantee.

<a id="a-gateway-refusal-never-reports-success"></a>
### A gateway refusal never reaches the workload as a successful response

The gateway issues the origin's leaf certificate when it intercepts a request. A refusal inside that
tunnel would reach the Shell as an ordinary HTTP status. `curl` exits 0 for any status unless the
caller passes `-f`. The gateway therefore adds a header to each response it writes. Box's kernel
wrapper converts that response to a permission-denied error. `curl` then prints one reason line and
exits 1. The marker identifies who wrote the refusal. It does not authorize the request, which the
gateway already refused. `kernel.rs::a_marked_refusal_fails_curl` pins it.

**The conversion is the kernel wrapper's alone, and Monty does not have it.** A Monty `fetch` builds
its own client and never reads the marker, so a denied request reaches the script as an ordinary
response carrying a `403` status. A script that does not check the status reads a refusal as an
answer. This remains an open residual risk.

<a id="python-in-the-shell-is-monty"></a>
### A workload reaches Monty two ways, and Box judges both on its one policy

The workload reaches Monty by running the `python3` alias directly through the broker or by typing
`python` or `python3` in the hosted Shell. The Shell forwards source to Monty through a script
interface. Both routes run one Monty VM per request, and Box judges both as the same principal under
its one policy engine, so no route reaches an interpreter that policy does not see. Without the
second route a `python` typed in the Shell exited 127, so an agent that reaches interpreters only
through its shell never reached Monty.

The direct route adds an outer request timeout. A script file argument through the Shell can also
reach a bind, while the direct alias cannot.

<a id="a-bare-python-name-always-means-monty"></a>
### A bare `python` name always means Monty, so a host interpreter needs its absolute path

The Shell's registered `python` and `python3` commands win over any host interpreter on `PATH`, and
over a declared `[tool.<name>]` table that names a host interpreter. So `python --version` returns a
Monty identifying string, and `python3 -m venv` fails. That precedence prevents a declared tool from
taking over the bare name. This is a known gap. A workload that runs an interpreter by its own
absolute path, or runs a virtual environment's `python` by absolute path, reaches the host OS's
Python under the `[tool.<name>]` table whose `command` names that path. Monty is stateless and
refuses the interactive frames, so a `python` with no `-c` and no script file refuses instead of
opening a REPL.

<a id="monty-is-judged-at-the-effect-level-alone"></a>
### Monty is judged at the effect level alone, above two deny-only floors

Each OS call a Monty script makes suspends the VM. The box's trusted process admits the call against
the box's one policy engine, and performs it only when policy permits. Monty has no command-level
decision. The whole script arrives as one call, and running it is not itself an effect. So a rule
for Monty always names an `fs:*` action on a path. Two deny-only floors sit beneath policy. Box sets
Monty's working directory to the box's own, and Monty roots a relative path under it before policy
sees it, which `a_bare_name_resolves_under_the_working_directory` pins. Then the approval step
checks the canonical path after policy allows, and returns the canonical path that the host must act
on. The floors prevent two demonstrated escapes. Keep both tests:
`a_dangling_symlink_cannot_be_written_through` and
`an_intra_home_symlink_cannot_launder_a_scoped_read`. A refusal names the absolute path, because
Monty joins a relative path to its working directory before the host receives the call, so the host
never sees the spelling the script used.

<a id="monty-performs-only-effects-the-box-can-govern"></a>
### Monty performs an effect only when policy can govern it and it leaks no host detail

Monty performs an effect only if policy can name and decide it, and its result contains neither a
resolved host path nor a host identity value. Directory listing, rename, stat, binary read and
write, append, and the symlink test meet both, so Monty performs them. Path resolution and
absolute-path construction fail the second, because each returns a path to the script, so both stay
refused with a "not supported" error. A stat result normalizes the user ID, group ID, and link
count, which are host account identity. A rename requires a policy decision and floor check on both
endpoints. The clock reads real system time in UTC, never the operator's local zone, which diverges
from CPython on purpose. `time.time()`, the monotonic clocks, and `os.urandom` are answered without
a policy decision, because none of them names a resource that a rule can name. `time.sleep()` and
`asyncio.sleep()` both block, because the broker has no event loop, so two concurrent sleeps take
the sum of their delays. `the_clock_and_entropy_are_answered_without_a_policy_decision` and
`both_sleeps_block_and_concurrent_sleeps_take_the_sum` pin both.

<a id="monty-is-per-request-and-buffers-its-output"></a>
### Monty handles one request per VM, holds no state, buffers its output, and bounds each allocation

Monty builds one VM per call and keeps no state between calls. It buffers the script's output and
returns it once, under a size cap. It refuses the interactive frames, so a script has no stdin and
`input()` cannot read. Status 0 means completion. Status 1 means the script raised an error, and 125
means a broker or interpreter fault.

The interpreter stops a script after 2 minutes of execution time, from inside its own run loop, so
`while True: pass` stops even when the script makes no OS call. Time suspended on the surrounding OS
does not count against that budget. Box adds a fixed outer wall-clock limit to direct Python calls,
plus limits of 60 seconds for each `fetch`, 3 minutes for all sleeps, 10,000 suspensions, and 1 MiB
for each `os.urandom` call.

Python invoked through Shell shares the enclosing call's configured deadline and broker grace
period. It does not receive a separate five-minute allowance. Monty's limits also apply. A shorter
Shell deadline can expire first, although synchronous execution can delay its check. Box never
shortens a sleep. A sleep that would exceed the total raises `TimeoutError` before waiting, as
`a_sleep_longer_than_the_total_raises_at_once` checks. `a_script_stops_at_its_suspension_limit` and
`urandom_above_its_cap_is_a_catchable_python_error` pin two of them. Monty refuses one allocation
above 128 MiB and stops the script with a `MemoryError`, which
`an_oversized_allocation_stops_the_script_and_not_the_box` pins. A script has no limit on its total
memory, because Monty enforces one only through a global allocator that counts the whole trusted
process and ends it on an overrun.

A worker process per script would restore that limit. We rejected it because it changes the box's
process layout. There is no interactive session, and a long script shows nothing until it ends. A
script that grows memory in small steps can also consume all memory in the box's trusted process.
This remains a residual risk.

<a id="a-monty-script-reaches-the-network-through-one-fetch-function"></a>
### A Monty script reaches the network through one `fetch` function, and only that

Box exposes one host function to a script, `fetch(url, method, headers, body)`. A call suspends the
VM, and the box's trusted process services it with a client that dials this box's egress gateway,
never the origin. The gateway raises `net:connect` and `http:request` against the box's one policy
engine, so Monty adds no second decision site. No egress routing means the network stays off. The
client offers no TLS-relax option, and it reuses the Shell's URL safety check, so the two share one
list. Three limits apply. Only one synchronous `fetch` works. Python packages such as `requests`,
`boto3`, `urllib`, and `socket` require the surrounding OS's Python as the contained workload, so
Monty cannot use them. This function also adds network work to the filesystem work that the box's
trusted process performs, through its weakest memory-safety component.

<a id="an-unserviced-suspension-is-a-python-error"></a>
### A suspension that Box does not service reports an honest Python error, not a broker failure

An unknown name resumes as undefined and an unknown function call resumes as not found, so the VM
raises a catchable `NameError` at status 1. An async resolution raises a `RuntimeError` that names
async as unsupported. Status 125 identifies a Box failure. Script typos therefore report a different
status from Box faults. The suspension enum is closed, so a future interpreter version that adds a
variant is a compile error and never a silent 125. Box cannot tell a typo from a real CPython
builtin that Monty lacks, such as `memoryview`, so every unresolved callable reports `NameError`.

<a id="a-host-binary-runs-in-a-contained-leaf-box"></a>
### A tool's sandbox reuses the policy engine and egress gateway of the box's trusted process

A command the Shell does not implement runs in its own sandbox. The same trampoline applies a second
set of sandbox grants, and `run` supervises the process. `shell:spawn` decides whether the binary
starts, once, before Box builds that sandbox. A tool's sandbox builds no second trusted process. The
box's trusted process starts it, and the sandbox uses that process's one policy engine and one
egress gateway. So one temporal history governs the whole box tree, and a rule that spans `fs:*` and
`net:*` still enforces. The sandbox has no alias and cannot connect to `run/box.sock`, so it has no
route to the broker. A tool's sandbox is ephemeral, one per `shell:spawn`. A program that a
`[tool.<name>]` table names gets its reach from that table. A program that no table names, but that
lies under one of the caller's own `exec` entries, runs in its own sandbox with the caller's path
lists, which `a_program_under_the_callers_exec_grant_runs_in_the_callers_boundary` pins. A binary
can therefore run without a table. It holds the caller's path lists rather than a narrower set, and
its sandbox has no route to the broker either.

<a id="the-box-runs-a-host-binary-through-the-spawn-host-seam"></a>
<a id="box-runs-a-host-binary-through-a-spawn-seam-that-the-shell-names-and-box-implements"></a>
### The Shell declares the spawn hook, and Box implements it

The Shell declares the `spawn_host` hook and calls the implementation its embedder installs. Box installs an implementation that selects a tool, translates its process spec into a boundary, and runs the program. The split
exists because the Shell crate depends on neither the containment crate nor the policy crate, so the
Shell owns the interpreter boundary and Box owns operating system enforcement. The interface returns
buffered stdout and stderr plus a status. A long operation such as a large `git clone` therefore
does not stream. This hook differs from the upstream Shell, as recorded in `UPSTREAM.md`.

<a id="the-spawn-host-seam-fails-closed"></a>
### With no contained spawner installed, a host binary is refused and not run uncontained

The spawn hook defaults to unsupported. With no hook installed there is no contained path, so a host
binary is refused rather than run with the crate's built-in fork and exec inside the box's trusted
process. An embedder must install that built-in explicitly to opt in to uncontained execution, and
nothing installs it by default. `a_host_binary_is_refused_when_no_spawn_hook_is_installed` pins it.
Forgetting to install the hook therefore refuses the binary instead of running it without a sandbox.

<a id="a-tool-reaches-only-the-paths-its-own-lists-name"></a>
### A tool reaches the project only where its own filesystem lists say so, raw and ungoverned by `fs:*`

A tool makes raw filesystem syscalls. Its sandbox grants bound that reach without per-operation
policy decisions. Box grants no blanket project read and write. A tool's `filesystem` table holds
six lists, `read`, `write`, `read_file`, `write_file`, `list`, and `deny`. Box refuses `metadata`
and `exec` lists on a tool. macOS supplies metadata discovery, and both platforms permit execution
through the tool's readable and writable grants. A sandbox grant raises no `fs:*` decision and
enters no temporal history. Inside a granted tree, a tool can therefore touch a file that the
operator's per-path policy denies to the agent. Box discloses each grant at startup, and the
operator must read that disclosure. No tool grant can name the box directory, which
`a_tool_grant_cannot_expose_the_box_directory` pins.

<a id="a-host-binary-resolves-on-the-operator-path"></a>
### A host binary resolves against the operator's real `PATH`, and the longest command prefix selects the tool

The Shell resolves a host binary against the operator's real host `PATH`, with `/usr/bin:/bin` as
the fallback, so Box finds a tool under Homebrew, nvm, or mise. Each process searches its table's
`env.PATH` if present. Otherwise, it uses the operator's real `PATH`, then the fallback if neither
exists. Selection compares the canonical resolved path of each tool's program with the program the
workload invoked, and compares the tool's fixed leading arguments with the head of the argv. The
longest matching `command` wins, so `[tool.git-read]` and `[tool.git-push]` can differ only in their
fixed arguments, which `the_longest_matching_command_prefix_selects_the_tool` pins. Box names a
program by its canonical identity for the `shell:spawn` decision, for selection, and for
credentials, and the spawn hook runs only an identity that was bound to an existing file when the decision was made. `shell:spawn` stays the one control on whether a program runs; a larger `PATH` changes
only where Box finds a permitted program.

<a id="the-caller-spelling-becomes-argument-zero"></a>
### The identity selects the program, and the caller's spelling becomes `argv[0]`

Box runs the canonical identity, but it passes the caller's own spelling as `argv[0]`, because an
interpreter reads `argv[0]`. A workload that ran a virtual environment's `.venv/bin/python` once ran
the canonical system interpreter under the system name, so the virtual environment was discarded
with no error. Box records the caller's spelling only when its own canonicalization produced that
file identity. It never resolves the spelling again. A workload that can write a directory can put a
link to a declared interpreter there and place `pyvenv.cfg` beside it. It can then make the
interpreter load modules from that directory. This is a residual risk. Supporting virtual
environments requires this behaviour.

## Egress

<a id="plain-http-takes-the-same-governed-path-as-https"></a>
### The gateway forwards plain HTTP through the same governed path as HTTPS

The gateway reads the request head and selects the `CONNECT` or plain `http://` path. Both paths use
the same network controls and request and response processing. Plain HTTP therefore adds no second
authorization path, and the same policy judges it. Refusing plain HTTP outright would close every
cleartext hazard at once, but it also blocks a legitimate local `http://` endpoint. Plain HTTP can
reach any host the policy permits, including hosts beyond loopback. The accepted residual risk is
that the box carries cleartext to a permitted host, so anything on that path can read the traffic.

<a id="a-secret-rides-only-tls"></a>
### Credentials require TLS

A bare-host credential pattern matches port 80 as well as 443, and a target carries no scheme, so a
cleartext request to a credential-bound host would otherwise receive the real secret. The plain-HTTP
path therefore refuses with `403` when any credential control matches the destination, before the gateway applies request controls. The destination determines this refusal. Request content cannot opt out of it. An
operator cannot bind a credential to a plain `http://` upstream, not even a local one.

<a id="the-plain-path-binds-its-own-destination-and-reports-its-transport"></a>
### The plain path binds its own destination and reports its transport truthfully

The plain path has no `CONNECT` authority to check an inner `Host` against, so it rewrites `Host` to
the URL authority before request checks, credential edits, and forwarding. The destination the box authorized is then the destination
the upstream routes on, so a virtual-host name cannot bypass the decision. The request's
`intercepted` flag is true on the TLS path and false on the plain path. A rule that permits only
TLS-terminated traffic therefore continues to refuse cleartext. The parser drops a URL fragment,
because a fragment is client-only and must never reach an origin server.

<a id="a-remote-mcp-tool-call-passes-a-second-gate"></a>
### A remote MCP tool call passes a second gate after the transport gate

The gateway classifies each JSON-RPC frame, then raises `mcp:call { server, tool }` after
`http:request`, and a deny at either gate wins. A `tools/call` reuses the same per-tool refinement
the local stdio path uses, so per-argument policy behaves the same on both. `initialize` and the
`*/list` discovery methods carry the server, so a rule can gate them. The gateway terminates TLS and
parses request frames before forwarding. Responses stream, except that `tools/list` retains bounded
capture for schema staging. The credential controls stay deny-only beneath policy, so the classifier
adds no allow authority.

<a id="remote-tool-schemas-are-discovered-at-runtime-in-memory"></a>
### The box discovers a remote MCP server's tool schemas at runtime, in memory

The gateway captures the catalog from the workload's own `tools/list` response, and the box's tool
catalogs stage the per-tool schema in memory, as they do for a stdio server. Nothing is written to
disk, and the runtime never reads the offline `policy generate-schema` output, which stays an
authoring aid. Pages accumulate per `Mcp-Session-Id`, and a request that carries no session id
continues only the cursor chain it names. A catalog parse failure is terminal. A broken remote
server therefore produces an error instead of hanging the box.

<a id="a-pending-authority-bootstraps-a-handshake-and-never-an-act"></a>
### A pending verdict holds one tool call, and the gateway's bootstrap arms are dead code

A per-tool rule can name an action whose schema is not yet staged. That tool call returns a
transient pending denial the caller may retry. Only an MCP tool identity can raise a pending
verdict. `net:connect` and `http:request` cannot carry one. The box decides every other request
against the schema-independent subset. See [discovery serves the schema-independent
subset](#discovery-serves-the-schema-independent-subset).

The egress adapter still carries three arms that would admit a handshake frame while a verdict is
pending. They cannot fire, because no non-tool request reaches that state. They remain from a design
that denied everything during discovery. They should be deleted and do not provide a capability. Do
not build on those arms. They provide no pre-policy admission path.

<a id="the-box-coordinates-discovery-completion"></a>
### The box coordinates discovery completion, and the policy facade does not

Two paths stage into one policy engine, through one set of tool catalogs: the stdio broker and the
egress gateway. A coordinator owned by `run` tracks the paths whose discovery results are still
pending. Each path reports once every server of its kind has an accepted, refused, or failed tool
list, and the one that empties the set finishes discovery exactly once. A per-tool rule that never
resolved degrades that one server, with a warning on stderr, exactly as [a server whose discovery a
policy denies](#a-server-whose-discovery-a-policy-denies-degrades-alone) describes. Only a durable
fault is fatal to the box. Putting that orchestration inside the policy engine was rejected, because
it would change the policy facade to perform coordination the box already owns.

## Credentials

<a id="the-workload-holds-a-phantom-and-the-gateway-holds-the-secret"></a>
### The workload holds one phantom token for each credential, and the gateway swaps in the real secret at that credential's destinations

For an `env://` binding, the box generates a random phantom token and places it in the workload's
environment. The real secret stays out of that environment. The gateway holds the real secret and
swaps the phantom for it only on a request to a destination that one of the credential's routes
names. The phantom is a 256-bit random value, unique to one credential across the vault. At a bound
destination the gateway clears the harness's own credential location before it writes the real
secret, so the request does not send the phantom alongside the real secret. A phantom sent elsewhere
remains unchanged. It is random and authenticates nothing, so it gives the receiving upstream no
credential. The box opens one vault per provisioned variable. Every route naming that variable
shares the vault's one phantom because the variable can hold only one value.
`one_variable_for_two_hosts_provisions_one_phantom_accepted_at_both` checks this. We rejected one
phantom per destination because the variable retained only the last phantom and strict checks
refused every other host. We also rejected caller-chosen phantoms because the vault must generate
every phantom itself. A phantom works at every destination for its credential. It separates
credentials but does not separate hosts. Routes that name one variable must also share one
`phantom_prefix`. The loader refuses a mismatch, as
`one_variable_with_two_phantom_prefixes_is_refused` checks. The vault refuses ambiguous matches
within it. The gateway catches overlaps between vaults by denying mutation collisions and refusing
mismatches at the strict phantom check. The workload can read the phantom and learn that a
credential exists.

<a id="the-box-is-the-credential-boundary"></a>
### The box is the credential boundary, so every process in a box gets every route

The box here is the whole of what one `box.toml` declares: the agent's sandbox, the box's trusted
process, and every sandbox it starts for a tool or an MCP server. Every request and response flows
inside it. Every process in the box gets every egress route that `box.toml` declares: the agent,
each tool, and each MCP server hold every route's phantom or placeholder. Every process in the box
shares one gateway, and the gateway cannot tell which process made a call. An `aws://` route
generates no phantom. Every process gets the same public placeholder keys, and the gateway signs
matching requests with the real credentials. An `env://` route with `secret.inject = "always"`
attaches the real secret with or without the phantom. An `env://` route with
`secret.inject = "phantom"`, the default, refuses a caller without the phantom, and every process in
the box holds the phantom, so it does not separate processes inside the box. The box is therefore
the credential boundary. Keep a process outside a box if it must not get that box's credentials. A
stdio MCP server runs in its own sandbox inside the box, so it gets every egress route like a tool
does. Future request attribution would let the gateway identify whether the agent, a tool, or an MCP
server made a call.

The cost is that a `phantom` route, the default, does not keep a credential from a tool or a
third-party stdio MCP server: either can use every route the box declares.

<a id="an-unusable-secret-value-is-unrepresentable"></a>
### An unusable secret value is unrepresentable, not validated

A resolved secret is a newtype whose only constructor refuses an empty value, a value that is empty
after a trim, and a value that holds a byte below `0x20` or equal to `0x7f`. Every credential source
returns that type, so no source can deliver a value that skipped the check. The type implements
`Debug` redaction and zeroize on drop once for all sources. The box cannot hold a deliberately empty
credential.

<a id="the-operator-selects-the-credential-placement"></a>
### The operator selects the credential placement, and `url_path` is refused at the box boundary

An egress target takes `secret.placement`, with `header` as the default. The other choices are
`basic_auth` and `query_param`. For `query_param`, `secret.param` names the parameter. A fourth
placement, `url_path`, is **refused when the configuration loads**, because it splices the secret
into the request path. The gateway already records the path from before it adds the credential,
which `attempts_carry_the_pre_mutation_path_for_a_path_spliced_credential` pins, so the audit record
does not carry the secret. Exposing `url_path` requires a decision. It does not depend on first
fixing that audit behaviour.

The box refuses the setting even though the mechanism exists. The credentials crate carries a
working `InjectMode::UrlPath` that the box's trusted process uses on its own paths, so path-splicing
injection code does run in that process and an evaluator should read it. The box also keeps its own
`Placement` enum and its placement strings, which map onto `InjectMode`, so two spellings exist and
must agree.

A residual risk remains. The gateway holds the spliced path as a plain string, so secret bytes
remain in its heap without wiping.

<a id="an-undeliverable-credential-is-refused-at-load"></a>
### A credential the box cannot deliver is refused when the config loads

A box egress entry may name the `env://` or `aws://` credential scheme. Every other scheme is
refused when the config loads, and the message names the accepted set. The credentials crate also
resolves `file://` and `op://`. Box cannot deliver those credentials, so egress entries cannot name
those schemes. `an_undeliverable_credential_scheme_is_refused` pins the refusal.

<a id="endpoint-breadth-is-refused-by-the-parsed-pattern"></a>
### Endpoint breadth is refused by the parsed pattern, and never by its text

Validation asks the parsed destination pattern whether it matches every host, and refuses that
entry. A text comparison could miss new authority forms supported by the parser. The two checks
would then disagree. A suffix wildcard such as `*.example.com` stays valid.

<a id="a-refusal-stays-in-the-phase-that-holds-its-input"></a>
### A refusal stays in the phase that holds its input

The box and credentials crate validate different inputs at different phases. The box checks the
operator's environment and the config text when it configures a box. The credentials crate checks
the resolved secret and the sealed placement when the vault opens, which is later and on a different
input. Deleting a box-side check moves its refusal one phase later, so the operator learns about a
broken config after the box starts. Do not delete one because the other exists.

<a id="a-provider-refuses-an-identity-it-cannot-honour"></a>
### A credential provider refuses an identity it cannot honour, instead of substituting one

The environment-backed AWS provider reads the ambient `AWS_*` variables, so it cannot resolve a
named profile. It never falls back to the ambient identity, because a credential that is not the one
the operator named is a silent authority change. A named profile resolves through the AWS profile
chain, with one exception refused by name: `credential_process`. Honouring it would make the box's
trusted process run a program that `~/.aws/config` names, and no floor defends that file, so it
would violate the rule against running workload-named programs in the trusted process.

<a id="a-route-may-set-the-phantom-check-to-advisory"></a>
### A route may attach its secret always, not only against the phantom

`secret.inject` takes `phantom`, the default, or `always`, and it is valid only on an `env://`
route. `phantom` fails closed and refuses a request with an absent or mismatched phantom. `always`
warns and attaches the real secret anyway, for a harness that writes its own credential file and
that the box therefore cannot seed the phantom into, or a client that sends its first request with
no credential. `always` relaxes only the phantom check. Destination matching, ambiguity refusal, and
stripping at foreign locations remain unchanged. An `always` route drops the one check that proves a
request came from the box's own binding, and the only signals are a per-request warning on stderr
and a journalled allow record. The key names what happens to the secret, not how the phantom is
checked; it replaces `secret.phantom`, whose `strict` and `advisory` are `phantom` and `always`.

<a id="a-route-may-set-the-minted-phantoms-prefix"></a>
### A route may set the minted phantom's prefix

`secret.phantom_prefix` replaces the default `strands_box_` prefix, and it is valid only on an
`env://` route. A harness that validates its key format then accepts the injected phantom. The
prefix changes the leading literal only. The box validates the prefix once. It must be nonempty,
contain at most 64 characters, and use only the RFC 3986 unreserved set. A custom-prefixed phantom
looks like a real key, so a reader of a log or a bug report can no longer recognize it as a
placeholder.

## Telemetry

<a id="one-collector-per-box-in-the-trusted-process"></a>
### One collector per box, inside that box's own trusted process

Each box runs its own collector in its own `run` process. There is no sidecar to deploy and no
buffer that two boxes share. A shared local collector would hold N boxes' records in one address
space, so one compromise would reach every box's audit trail. A collector the box spawns is worse,
because the box's trusted process may never run a program that a config file names. Records belong
to one box. To use one store, the operator points several boxes at the same destination and
identifies their records by `strands.box.name`.

<a id="opentelemetry-owns-the-schema-and-the-box-owns-its-queues"></a>
### OpenTelemetry owns the schema, and the box owns its queues and its transport

The crate gets its OTLP types from `opentelemetry-proto`. One typed representation writes OTLP-JSON
file lines and protobuf endpoint bodies, and reads both encodings from a harness. A typed walk is
exhaustive, so the reserved-namespace strip cannot miss a level. Each target wraps the SDK's batch
processor. Its bounded queue supports the audit-suppression control. We rejected the OTLP exporter
crate because it requires a newer major version of an HTTP client that two other crates already use.
That dependency would put two TLS stacks in the process holding the CA key.

<a id="a-target-is-a-file-or-an-otlp-endpoint"></a>
### A target is a file or an OTLP endpoint, and no other type parses

`box.toml` accepts `file` and `otlp`. Any other exporter name is refused when the config loads, and
the refusal names the two that exist. For a vendor this build does not support directly, run a
separate OTLP collector with that vendor's exporter. Point an `otlp` target at the collector's port.

<a id="every-box-records-by-default"></a>
### Every box records by default, to a file the workload cannot reach

An absent `telemetry` key means one `file` target that takes every signal: every effective denial
and permit, the box's own control-plane records, and the harness's relayed spans, logs, and metrics.
A box that makes a thousand decisions without recording any cannot be audited. The default provides
those records even when the operator has configured nothing. The file sits in the box's own private
tree, which a deny-only floor refuses to the workload whatever a permit says. A declared target
replaces the default instead of adding to it. The file has no size bound or rotation.

<a id="a-target-names-a-set-of-signals"></a>
### A target names a set of signals, and an absent list takes every signal

`[telemetry.<label>] include` takes five words: `deny` and `permit` name the two effective verdicts,
`trace` names the agent's relayed spans and the box's own control-plane records, and `logs` and
`metrics` name the agent's relayed log and metric records. A target names a set, with no ordering,
and no signal contains another. A target that names no `include` receives every signal, which
`an_absent_include_takes_every_signal` pins. An empty list, a repeated word, and a misspelled word
are each refused before the box exists. The box relays harness signals without producing them. The
harness's exporter settings determine whether those records exist.

<a id="the-strands-box-namespace-is-reserved"></a>
### `strands.box.` is reserved, and the collector strips it from an agent's payload at every level

Before routing an agent's payload, the collector removes every attribute with a `strands.box.`
prefix at every level. It also renames any scope that claims the box's `strands-box.` namespace. The
collector then sets `strands.box.source = "agent"` on each resource. The box's own records carry
`strands.box.source = "box"`. The collector walks the payload recursively instead of checking a
fixed list of locations. An earlier version changed only the resource, which let an agent post a
record that appeared to be a box-granted permit. Box reserves only `strands.box.` because the
Strands Agents SDK writes its own attributes under `strands.`. Any future box-owned key must sit
under `strands.box.`.

<a id="the-collector-listens-on-a-second-loopback-port"></a>
### The collector listens on a second loopback port

The workload reaches the collector on `127.0.0.1:<port>`, pinned per box exactly as the gateway port
is, so an unmodified agent SDK exports with one environment variable and no code change. A Unix
socket was rejected, because the OTLP exporter specification requires an HTTP endpoint. The proxy
exemption for that port is `127.0.0.1,localhost` and nothing else. Every process at the operator's
uid can reach the port because the loopback listener has no peer check. Access is not limited to the
contained workload. Such a process cannot forge a box record, but it can inject noise attributed to
the agent.

<a id="the-agents-lane-and-the-boxs-lane-share-no-queue"></a>
<a id="the-agents-lane-and-the-boxs-lane-share-no-queue-and-the-agents-lane-holds-one-permit"></a>
### Workload telemetry bypasses Box record queues and uses one relay slot

The box's decisions go through one bounded queue per target. The collector relays an agent's span inline through one relay slot, which it claims without waiting. One shared queue would let a workload that
posts continuously fill the queue so the box dropped its own refusal records. The collector claims the relay slot before decoding. A resource-count limit on every route refuses bodies that would amplify
processing work. A slow target delays the agent's own spans, and nothing bounds the connection count
on that port.

<a id="delivery-is-best-effort"></a>
### Delivery is best effort, and a record can be lost

When delivery to a target fails, the collector prints to stderr and loses the record. A relayed
agent span does not take part in the shutdown drain, so a shutdown can lose one in flight; a refusal
cannot be lost that way. A record that the SDK's own queue refuses is not counted. Every exit runs
the same drain. A box that fails before its workload starts therefore still records its stop.

<a id="the-effective-decision-is-the-canonical-record"></a>
### The effective decision from the enforcement point is the canonical record

The enforcement point submits one record after all policy gates and deny-only floors finish. It
records a permit before starting the effect, or a denial before returning the refusal. The box does
not record the raw engine verdict, because a floor can refuse what policy permitted and a bootstrap
pass can permit what policy denied. The record names every policy that determined it, in
`strands.box.policy.determining.ids`, and a cause in `strands.box.policy.cause`, one of `permitted`,
`forbidden`, `no_match`, `policy_pending`, `internal_fault`, and `enforcement`.

<a id="every-box-record-is-both-a-span-and-a-log-record"></a>
### Every box record is both a span and a log record

Each effective decision produces one internal span and one audit log record that share a trace ID
and a span ID. The span marks the instant the enforcement point submits the decision, so it measures
no evaluation latency. The collector creates one trace ID and root span when it opens. Every
control-plane operation names that root as its parent, so one trace covers the box's lifetime. A
decision is exported even when the caller's parent is unsampled, because a sampling flag must not
suppress policy evidence. `decisions_export_spans_and_matching_logs_with_request_parentage` pins the
contract.

<a id="correlation-context-is-a-hint-and-never-authority"></a>
### Correlation context is a hint, and never evidence of authority

A decision uses caller-supplied context to join the caller's trace: the alias environment for a
Shell or Monty call, the request headers for HTTP egress, and `params._meta` for an MCP frame. Every
box record carries `strands.box.run.id`, generated once per `run`. The box copies named fields only,
bounds their size, and validates before it retains anything. Tool arguments, prompts, authorization
headers, and arbitrary baggage are excluded, and a caller-supplied identifier is never evidence of
caller identity. Roughly half of all decisions arrive unparented and join by `strands.box.run.id`
alone.

<a id="the-policy-attribute-names-are-this-products-own"></a>
### The policy attribute names are this product's own, and the set is fixed

A decision carries `strands.box.policy.action`, `.resource`, `.verdict`, `.cause`, `.reason` on a
deny, `.principal`, `.rule`, `.description`, and `.category`. No OpenTelemetry convention covers
authorization, so this namespace is authoritative here, and the set is fixed because a backend
indexes on these keys. Standard keys identify the operation where one exists: `server.address`,
`server.port`, `http.request.method`, `file.path`, `process.command`, `process.command_args`, and
`process.working_directory`. `url.full` and `process.command_line` stay excluded, because each
routinely carries a secret.

`.cause` is mandatory and must agree with `.verdict`. `DecisionRecord` holds a `DecisionCause`
rather than an option. A permit defaults to `Permitted`, a deny defaults to `Forbidden`, and
`caused_by` refuses an impossible pair. An optional cause would rely on every call site setting it.
A new enforcement point could then omit the cause without a build failure. The verdict does not
derive from the cause because `Enforcement` can produce either verdict.

<a id="a-span-omits-what-a-span-field-states"></a>
### A decision span omits only what one of its own fields already states

The span carries every attribute of its log record except `strands.box.trace.parent_span_id`, which
the span states as `parentSpanId`. Duplicating the key makes a consumer store, index, and pay for
both copies without giving the trace reader new information. The log record keeps the key because it
has no equivalent field. The span and log record share trace and span ids, so a reader can use those
ids to find either record. `SPAN_OMITS` is the list, and it holds that one key.

The span omits no other attributes. Two keys were removed from both records.
`strands.box.trace.parent_sampled` and `strands.box.trace.state` are no longer emitted: no consumer
read either, and each costs about two lines to restore, which is the test [emit only what a consumer
reads today](#the-policy-attribute-names-are-this-products-own) applies. Deleting `trace.state` also
removed the span's `traceState` field. The box still propagates the caller's `tracestate`
downstream, so only the record changed. The whole decision tuple remains, `principal`, `action`,
`resource`, and `verdict`. Omitting the principal would leave a span describing a decision without
its subject of authority. `strands.box.policy.determining.ids` remains so a trace-only consumer can
see when a permit depended on more than one policy. Removing it would lose that fact to save a copy.

A reader that needs the caller's parent as an attribute must read the log record.

<a id="a-shell-record-names-only-a-literal-argument"></a>
### A shell record names an argument only when the script stated it literally

The record reports an argument whose word was literal in the submitted script, and for an expanded
word reports it only when it is a path or a plain flag. Every other argument becomes `<redacted>`,
because the Shell holds arguments after expansion, so `echo $(cat secret.txt)` would otherwise write
the file's contents into the record. A shape test alone cannot distinguish `pipefail` from
`hunter2`. Provenance distinguishes them because the literal word already appears in a file the
operator can read. The policy engine never receives provenance, because a decision is about what
runs and not about how a word was spelled.
