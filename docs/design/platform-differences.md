# Filesystem and runtime differences by operating system

Linux and macOS enforce the same configuration through different kernel mechanisms.
The resulting access and startup behavior differ in the cases below.

Linux uses a restricted mount view and [seccomp](linux-enforcement.md#terms).
macOS uses [Seatbelt](macos-enforcement.md), its process sandbox mechanism.

<a id="access-modes-and-overlap"></a>

## Access modes and overlap

Read-only means content reads without writes.
Write-only means content writes without reads.
Read-write means both.
The filesystem lists express these access modes.

Content and execution grants must name existing paths and pass Box's protected-path checks.
Use the [canonical path spelling](../user/config.md#agentfilesystem-and-toolnamefilesystem) that names the path without symbolic links.
In `[agent.filesystem]`, combine `read = ["~/project"]` with `write = ["~/project/output"]`.

This configuration requests read-only access across `project`, with read-write access under `project/output`.
A write grant at the parent and a read grant at one child requests write-only access elsewhere.
Linux refuses that configuration because the read grant does not cover the entire write scope.

For one file, combine `read_file = ["~/results/output.txt"]` with `write_file = ["~/results/output.txt"]` in `[agent.filesystem]`.

This pair requests read-write access to one file.
It does not grant content access to sibling files.
A parent directory's `read` entry can provide read access to a child named in `write_file`.
A `read_file` entry cannot provide read access throughout a directory named in `write`.
An execute grant does not satisfy Linux's explicit read requirement.

For write-only access, macOS permits a `write` or `write_file` grant without overlapping read access.
Linux refuses that configuration before the workload starts.
If the task requires write-only direct access, Linux cannot meet that requirement.
Use macOS or redesign the operation around file requests through Strands Shell or Monty.
These are [mediated operations](containment.md#two-kinds-of-enforcement): policy decides each request in the box's trusted process.
Mediated operations have different semantics and need their own validation.

<a id="behavior-and-configuration"></a>

## Behavior and configuration

`filesystem` below means the agent's table or an explicitly declared tool's table unless the row limits it.
An accepted configuration can still fail later setup.

| Feature | Behavior and rationale | Configuration | Startup result | Available alternative |
|---|---|---|---|---|
| Read-only content | Both platforms refuse writes. Linux uses read-only mounts. | `read` or `read_file` | Accepts valid entries. | Use exact files to reduce content exposure. |
| Write-only content | macOS separates reads and writes. Linux writable mounts also expose reads. | `write` or `write_file`, without full explicit read coverage | Linux refuses before the agent, tool, or local server starts. | Use explicit read-write grants only when read access is acceptable. Otherwise use macOS or a mediated operation. |
| Read-write overlap | Both platforms combine grants. A narrower write affects the read tree only within that write scope. | Parent `read` plus child `write`, or matching exact-file grants | Accepts valid overlapping grants. | Use the smallest write subtree or exact file. |
| Directory names without content | macOS supports `list`. Linux mounts cannot provide this separation. | `filesystem.list` | Linux refuses: `cannot be listed without its contents on Linux`. | Grant `read` only if content access is acceptable, or use mediated directory access. |
| Deny an absent path | macOS can express a future-path refusal. Box's Linux configuration requires an existing deny target. | `filesystem.deny` | Linux refuses: `does not exist yet`. | Create the target first, or deny an existing ancestor that does not invalidate the whole grant. |
| Deny an existing file | Linux places an empty file over the denied target. Reads can return empty output while writes fail. macOS applies a refusal rule. | `deny` for a file within a broader grant | Accepts valid entries. A successful read does not mean the original content is accessible. | Omit the broader content grant when empty-file substitution breaks the workload. |
| Metadata-only tree | macOS exposes file properties without content. Linux omits this mount to avoid exposing content. | Agent `filesystem.metadata` | Linux accepts the entry but supplies no metadata-only tree. Tools refuse the field. | Use content reads only if acceptable, or mediated metadata access. |
| Helper execution | Tools can run helpers and load built code. Linux makes their read/write mounts executable. The agent retains explicit execution grants. | Tool content grants and agent `exec` | Accepts valid entries and discloses wider tool execution. | Grant the tool only the files and directories its task requires. |
| Loader directory reads | Linux makes the [listed ARM64 loader directories](linux-enforcement.md#programs-and-shared-libraries) executable when granted read access because libraries require executable mappings. Ordinary agent read trees remain non-executable. | Agent `read` on a recognized loader directory | Accepts valid entries. Programs in that directory can also execute. | Grant exact executable files with their discovered transitive dependencies, then validate later library loads. |
| Unreachable paths and workspace | Linux omits ungranted paths and can provide an empty initial directory. macOS refuses access through Seatbelt. | `workspace`, plus explicit content grants | Workspace alone grants no content. Runtime errors need not match across platforms. | Declare the required content grants or use mediated access. |
| Symbolic-link entries | Box validates the actual path identity on both platforms. | Any authored content or execution grant | Refuses symbolic links and noncanonical grant spellings. | Name the resolved target. |
| Direct network exception | Tools or local Model Context Protocol (MCP) servers with this setting bypass gateway policy. Linux shares the surrounding OS network namespace. | Tool network or MCP `contain_egress = false` | Accepts the exception. The agent refuses a network table. Other sandbox restrictions remain. | Keep gateway mode when policy must decide network requests. |
| IPv6 and socket families | Linux permits UNIX and IPv4 sockets and rejects other socket families, including IPv6. The network exception keeps this filter. | No field enables Linux IPv6. | Startup can succeed. An IPv6 socket request fails during execution. | Use a validated IPv4 destination or gateway route. |
| Process information | Linux provides `/proc` within the workload's process namespace. This differs from macOS process restrictions. | No field grants the agent surrounding-OS process visibility. | Linux constructs the isolated view or fails startup. | Observe the workload from the supervisor. |
| Executable memory | Linux refuses writable-executable mappings and [`mprotect`](linux-enforcement.md#terms) requests whose permissions include executable access, including retained access. It refuses every `pkey_mprotect` request. Tool file execution does not remove these filters. | No field disables these filters. | Startup can succeed. A runtime can fail when it requests executable memory or calls `pkey_mprotect`. | Use an independently validated runtime mode that does not require those operations. |
| Native filesystem policy | The experimental feature supports macOS and Linux ARM64 with different kernel prerequisites and coverage. See the [native policy guide](../user/native-filesystem-policy.md). | `[experimental-features] native-filesystem-policy = true` | A missing build feature or required kernel mechanism refuses startup. Linux also requires loader capabilities. | Use mediated file operations through Strands Shell or Monty. A declared tool uses its own filesystem grants. |
| Namespace setup | Linux requires successful namespace creation and mount setup. A capability probe does not test every setup operation. | Deployment identity and surrounding OS settings | Reports unsupported namespace creation or fails during setup. | Qualify an environment that permits the complete setup sequence. |

## Write-only refusal

For a Linux `write` or `write_file` entry without covering read access, the error includes:

```text
Linux cannot enforce write-only access for `<list>` at <path>. Add an explicit `read` or `read_file` grant covering the entire write scope to request read-write access, or remove the write grant
```

`<list>` is the authored list name, and `<path>` is the resolved path.
Add read access only when the workload may read the entire writable path.

## Directory-list refusal

For `list = ["~/project"]`, the current Linux error includes:

```text
cannot be listed without its contents on Linux: the namespace backend has no lowering for `list`; grant `read` instead
```

That suggested change grants file contents.
It changes access, so it is not a neutral portability fix.

## Remaining qualification

These differences describe source behavior rather than an accepted Linux package.
A release needs installation and workload checks on each selected deployment configuration.
Setup privileges and successful workloads from one environment do not qualify another.
See [Linux startup and qualification](linux-enforcement.md#startup-failures-and-qualification) for that boundary.
