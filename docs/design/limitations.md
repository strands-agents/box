# Limits of Box's protection

A box narrows what the agent can reach, and policy decides each request the agent sends to Box.
Neither one decides whether an allowed action is one you wanted. This page covers what's still at
risk once the box and the policy do their jobs, and what Box doesn't protect at all.

It uses the terms from [How Box contains a process](containment.md): **operating system enforcement** bounds a
process's own system calls, **policy** decides each request that reaches Box, and each tool or local MCP
server the agent starts runs in **its own sandbox**, separate from the agent's.

## Allowed actions can still cause harm

Suppose `hello.txt` holds your notes, and the agent has a grant to write it. The agent replaces the
notes with an empty file. The write succeeds, because it's allowed, even though you wanted the notes
kept. Box restricts what a process can do. It can't tell whether an allowed action matches your
intent.

That plays out in three ways:

- **Allowed writes change real files:** Box doesn't undo them when the agent exits. A broad write
  grant can also change files that other programs read later
  ([a direct grant replaces the policy decision](decisions.md#a-direct-grant-replaces-the-policy-decision)).
- **An allowed destination can receive anything the program can read:** permitting a destination
  doesn't limit what's sent there, so private data the program can read can leave through it. The
  [security tenets](tenets.md) name this risk.
- **An interpreter runs whatever it's handed:** if the agent's `command` is an interpreter such as
  `python3`, the box still bounds what it reaches, but nothing checks that the script does what you
  meant.

## Policy sees only requests that reach it

Policy can make one decision depend on an earlier one. For example, a rule can make the egress
gateway refuse a connection after Strands Shell reads a private file. That only works when the
earlier event reaches the policy engine and enters its history.

Many file reads never do:

- **The agent's own reads:** when the agent reads a file with its own system call, operating system enforcement
  decides, and policy never sees it. The [two paths to a file](containment.md#two-kinds-of-enforcement)
  show the difference.
- **A tool's or a local MCP server's file operations:** inside its sandbox, they raise no policy
  decision.

So a history rule can't account for a read that took one of those routes. The kernel's own refusals
are recorded only in part: on Linux a call the syscall filter refuses leaves a `kernel_refused`
record, but a path absent from a view, a write to a read-only mount, and an unroutable connection
leave none, macOS records none yet, and a host whose ptrace policy refuses a parent its child (Yama
scope 2 or 3) or whose kernel predates `pidfd_getfd` records none either. A box tracks 256 kinds of
refusal, and a kind includes the arguments a rule reads. Past that a refusal is counted under its call
alone, so a workload that makes 256 distinct refused calls on purpose still leaves a record of each
later call, though not of the arguments its repeats used. Each refused
call now waits about 60 µs for the box's answer, so a program that keeps retrying a refused call pays
for it; glibc's `realloc` of a large block tries `mremap` first, which the filter refuses. The
[policy page](policy.md#durable-history) explains why policy history isn't a complete audit record.

The other direction matters too. Strands Shell and Monty run outside every box, so a broad
filesystem permit lets them reach paths the agent's own grants never could, including credential
stores ([no credential floor sits beneath the interpreters](decisions.md#no-credential-floor-sits-beneath-the-interpreters)).
Keep filesystem permits to the paths the task needs.

## How access choices change the risk

Seven configuration choices widen what a program can reach without a policy decision for each
access. Review each one before you run:

| Choice | Why you'd make it | What it allows |
|---|---|---|
| Read access to a directory tree | Read a project and its dependencies. | The program reads any file in the tree, with no policy decision for each read. |
| Write access to a directory tree | Produce build output or edit source. | The program changes any file in the tree, including inputs other programs use later. |
| A filesystem permit that doesn't restrict paths | Let Strands Shell or Monty work across many paths. | The interpreters reach beyond the agent's own grants, with no credential floor beneath them. |
| A tool, on macOS | Let a compiler or version control tool run its helpers. | Its sandbox runs any helper, loads code from its writable grants, and sees which paths exist across the home ([a tool's sandbox](containment.md#a-tools-leaf-box)). |
| The same path under `exec` and `write` | Let a build run what it compiles. | Box warns and starts anyway, so the workload can replace that program ([write plus execute warns](decisions.md#write-plus-execute-warns-and-does-not-refuse)). |
| A program with no tool table | Run a program under one of the agent's `exec` entries. | It gets the agent's grants plus the wider reach of a tool's sandbox, and the startup report doesn't show the wider part. |
| `contain_egress = false` on a local MCP server or a tool | Support a client that can't use the gateway. | Its traffic bypasses the gateway and its policy checks. Its filesystem restrictions still apply. A tool's arguments come from the agent, so a native tool is direct egress the agent can aim ([native egress](decisions.md#native-egress-is-an-operator-declared-leaf-escape)). |

## Protections Box doesn't provide

Box doesn't provide seven protections:

- **Resource limits:** a box doesn't bound process creation, CPU, or disk use, so a program can
  exhaust them while staying inside its grants
  ([children inherit the boundary](decisions.md#children-inherit-the-boundary)).
- **Isolation between tenants:** separating tenants on a shared machine is the hosting platform's
  job ([non-goals](tenets.md#non-goals)).
- **Protection from operating system exploits:** Box relies on the kernel to enforce the sandbox, so
  an exploit that defeats the kernel defeats the box. The same tenets exclude kernel exploits.
- **Isolation of remote servers:** Box decides the requests it forwards to a remote MCP server, but
  it can't contain the server or control what it does with an allowed request.
- **Defects in the box's trusted process:** Strands Shell, Monty, the gateway, and
  Dogwood run outside every box. No sandbox contains their defects.
  Box still owns failures of its enforcement
  ([responsibility for enforcement](security.md#box-owns-enforcement)).
- **Protection from side channels:** hardware and timing side channels never reach operating system enforcement or
  policy ([some channels never reach enforcement](decisions.md#some-channels-never-reach-enforcement)).
- **A tamper-proof audit trail:** a box records every decision it makes, but nothing signs a record or
  chains one to the next, so anything that can write the records file can edit it afterwards. A record
  can also be lost without notice ([delivery is best effort](decisions.md#delivery-is-best-effort)).
  [Telemetry](telemetry.md#limits) states what a box does keep out.

## Programs can need access a box refuses

A legitimate program can fail because its box refuses a file or a system service it needs, and the
failure alone doesn't tell you which rule refused it. Some operations also succeed with wrong
results. [macOS enforcement](macos-enforcement.md#file-timestamps-may-not-be-preserved) covers a
known case where file timestamps aren't preserved. Test the operations your application depends on,
including their output.

## Check whether Box meets your needs

Review the configuration against the consequences that matter for your application:

- **Files the agent can read:** include everything a directory grant exposes, not only the files the
  task names.
- **Files the agent can change:** include files other programs read after the agent exits.
- **Requests through Box:** check the paths and actions each policy rule permits.
- **Rules that depend on history:** identify which component records each event the rule needs.
- **Tools and servers:** review each program's own grants, and any exception that bypasses the
  gateway.
- **Operational requirements:** check the resource limits you set outside Box, and the results of
  representative workloads.

The startup report lists the grants for the agent and each declared tool, including the system
paths Box adds. [How you check a box's reach](containment.md#how-you-check-a-boxs-reach) lists what
it leaves out.

The [getting-started guide](../user/getting-started.md) explains how to configure and run Box. For a
refused operation, the [macOS troubleshooting section](macos-enforcement.md#understanding-a-refused-operation)
explains which process and access path to check.
