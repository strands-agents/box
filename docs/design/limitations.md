# Limits of Box's protection

A box narrows what the agent can reach, and policy decides each request the agent sends to Box.
Neither one decides whether an allowed action is one you wanted. This page covers what's still at
risk once the box and the policy do their jobs, and what Box doesn't protect at all.

[How Box contains a process](containment.md) defines the two kinds of enforcement. Operating system
enforcement restricts a process's own system calls, and policy decides each request that reaches
Box. Each tool or local MCP server the agent starts runs in its own sandbox, separate from the agent's.

## Allowed actions can still cause harm

Suppose `hello.txt` holds your notes, and the agent has a grant to write it. The agent replaces the
notes with an empty file. The write succeeds, because it's allowed, even though you wanted the notes
kept. Box restricts what a process can do. It can't tell whether an allowed action matches your
intent.

Consider these consequences:

- Allowed writes change real files. Box doesn't undo them when the agent exits. A broad write
  grant can also change files that other programs read later. See [a direct grant replaces the policy decision](decisions.md#a-direct-grant-replaces-the-policy-decision).
- An allowed destination can receive anything the program can read. Permitting a destination
  doesn't limit what's sent there, so readable private data can leave through it. The
  [security tenets](tenets.md) name this risk.
- An interpreter runs the code it receives. If the agent's `command` is an interpreter such as
  `python3`, the box still restricts what it reaches. Nothing checks that the script does what you
  meant.

## Policy sees only requests that reach it

Policy can make one decision depend on an earlier one. For example, a rule can make the egress
gateway refuse a connection after Strands Shell reads a private file. That only works when the
earlier event reaches the policy engine and enters its history.

These file operations do not enter policy history:

- When the agent reads a file with its own system call, operating system enforcement decides,
  and policy never sees it. The [two paths to a file](containment.md#two-kinds-of-enforcement)
  show the difference.
- A tool's or a local MCP server's file operations inside its sandbox produce no policy decision.

So a history rule can't account for a read that took one of those routes. The
[policy page](policy.md#durable-history) explains why policy history isn't a complete audit record.

Strands Shell and Monty run outside every sandbox, so a broad
filesystem permit lets them reach paths the agent's own grants never could, including credential
stores. See [no credential floor sits beneath the interpreters](decisions.md#no-credential-floor-sits-beneath-the-interpreters).
Keep filesystem permits to the paths the task needs.

## How access choices change the risk

Seven configuration choices widen what a program can reach without a policy decision for each
access. Review each one before you run:

| Choice | Why you'd make it | What it allows |
|---|---|---|
| Read access to a directory tree | Read a project and its dependencies. | The program reads any file in the tree, with no policy decision for each read. |
| Write access to a directory tree | Produce build output or edit source. | The program changes any file in the tree, including inputs other programs use later. |
| A filesystem permit that doesn't restrict paths | Let Strands Shell or Monty work across many paths. | The interpreters reach beyond the agent's own grants, with no credential floor beneath them. |
| A tool, on macOS | Let a compiler or version control tool run its helpers. | Its sandbox runs any helper, loads code from its writable grants, and sees which paths exist across the home. See [a tool's sandbox](containment.md#a-tools-leaf-box). |
| The same path under `exec` and `write` | Let a build run what it compiles. | Box warns and starts anyway, so the workload can replace that program. See [write plus execute warns](decisions.md#write-plus-execute-warns-and-does-not-refuse). |
| A program with no tool table | Run a program under one of the agent's `exec` entries. | It gets the agent's grants plus the wider reach of a tool's sandbox, and the startup report doesn't show the wider part. |
| `contain_egress = false` on a local MCP server or a tool | Support a client that can't use the gateway. | Its traffic bypasses the gateway and its policy checks. Its filesystem restrictions still apply. A tool's arguments come from the agent, so the agent can direct that tool's network access. See [native egress](decisions.md#native-egress-is-an-operator-declared-leaf-escape). |

## Protections Box doesn't provide

Box does not provide the following protections:

- A box does not limit process creation, CPU, or disk use. A program can exhaust those resources
  while staying inside its grants. See [children inherit the boundary](decisions.md#children-inherit-the-boundary).
- The hosting platform must isolate tenants on a shared machine. See [non-goals](tenets.md#non-goals).
- Box relies on the kernel to enforce the sandbox. An exploit that defeats the kernel defeats the box. The same tenets exclude kernel exploits.
- Box decides the requests it forwards to a remote MCP server. It can't contain the server or
  control what it does with an allowed request.
- Strands Shell, Monty, the gateway, and Dogwood run outside every sandbox. Their defects have
  no sandbox protection.
  Box still owns failures of its enforcement. See [responsibility for enforcement](security.md#box-owns-enforcement).
- Hardware and timing side channels never reach operating system enforcement or policy. See [some channels never reach enforcement](decisions.md#some-channels-never-reach-enforcement).
- A box records every decision it makes, but it does not sign records or chain them together.
  Anything that can write the records file can edit it afterwards. A record can also be lost
  without notice. See [delivery is best effort](decisions.md#delivery-is-best-effort).
  [Telemetry](telemetry.md#limits) states what a box does keep out.

## Programs can need access a box refuses

The [platform comparison](platform-differences.md) explains Linux configuration differences and their consequences.
Linux requires explicit read access across every write grant because its writable mounts also permit reads.
It refuses directory-list grants and absent deny paths, and silently omits metadata-only tree grants.
Linux tools can execute from their readable and writable mounts.
Agent content grants alone permit execution only in recognized loader directories.
The [Linux enforcement explanation](linux-enforcement.md) explains these mechanisms and separates them from release qualification.

A legitimate program can fail because its box refuses a file or a system service it needs, and the
failure alone doesn't tell you which rule refused it. Some operations also succeed with wrong
results. [macOS enforcement](macos-enforcement.md#file-timestamps-may-not-be-preserved) covers a
known case where file timestamps aren't preserved. Test the operations your application depends on,
including their output.

## Check whether Box meets your needs

Review the configuration against the consequences that matter for your application:

- Check every file the agent can read, including everything a directory grant exposes beyond the
  files the task names.
- Check every file the agent can change, including files other programs read after the agent exits.
- Check the paths and actions each policy rule permits on requests through Box.
- For each history rule, identify which component records the events it needs.
- Review each tool's and server's own grants, and any exception that bypasses the gateway.
- Check the resource limits you set outside Box and the results of representative workloads.

The startup report lists the grants for the agent and each declared tool, including the system
paths Box adds. [How you check a box's reach](containment.md#how-you-check-a-boxs-reach) lists what
it leaves out.

The [getting-started guide](../user/getting-started.md) explains how to configure and run Box. For a
refused operation, the [macOS troubleshooting section](macos-enforcement.md#understanding-a-refused-operation)
explains which process and access path to check.
