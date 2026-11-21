# Design: Mount event forwarding

**Author**: Kevin Orellana

**Date**: November 21, 2026

## Overview

This proposal makes storage mounts accessible to a running box while preserving the filesystem rules in `box.toml`.

## 1. Background

Box creates a *private mount namespace,* which isolates the host's filesystem from the sandboxed workload. Host-mounted storage, like AgentCore Runtime’s *Bring Your Own Storage* (BYOS), can propagate new mounts into the customer’s application. However, those mounts do not automatically reach Box’s private filesystem view after box initialization.

While starting Box *after* storage arrives avoids this ordering problem, it does not support a Box workload already running. This proposal builds on Ravi Kandury’s mount-propagation [prototype](https://github.com/rvkandury/box-public/commit/5816878c44741ac6ee681cba937049b84ac6196d).

This type of *direct propagation* into the Box workload would expose incoming mounts before Box applied its filesystem restrictions. Box must therefore prepare its filesystem restrictions before making the storage mounts accessible.

## 2. Filesystems and mounts

**A filesystem** organizes data into files and directories in a tree structure. It provides the operations (read, write, etc) that programs need. The data can live on your computer’s disk, a USB drive, or remote storage.

**A mount** tells the operating system which filesystem to use at a particular path.

For example, your computer may have an empty `/data` directory, while a USB drive’s filesystem contains `report.txt` at its top level. If we mount the USB drive’s filesystem at `/data`, processes that can see this mount can request the file through `/data/report.txt`.

![Before mounting, /data is empty. After mounting the USB filesystem at /data, a process can read report.txt through /data/report.txt without copying the file.](https://github.com/user-attachments/assets/fd16f52c-1d15-4df0-a028-3ab6a2a61a50)

[Editable diagram](https://github.com/user-attachments/files/35204839/mount-before-after.drawio)

## 3. How mounts are used to enforce Box Core filesystem perms today

On Linux, Strands Box builds a restricted filesystem view before starting the sandboxed process. It uses the filesystem permissions in `box.toml` to decide what appears in that view. Box exposes permitted paths through mounts and sets whether those mounts allow writes and direct program execution.

For example, Box can expose `/data` as read-only while making `/data/output` writable through a separate mount. Denied contents are omitted or covered with empty mounts. Linux enforces these restrictions while the process runs.

This mechanism cannot express every permission independently. Write access requires read access, and list-only grants prevent sandbox startup.

***Table 1: Mapping box.toml permissions to mount operations***

| Permission | Operator configures in Box Core box.toml | Mount behavior |
| --- | --- | --- |
| **Read without write** | `read` | Remounts using `mount()` **with** `MS_RDONLY`. |
| **Write** | Both `read` and `write` | Remounts using `mount()` **without** `MS_RDONLY`. |
| **Execute** | `exec` | Remounts using `mount()` **without** `MS_NOEXEC`. |
| **Alternative to list-only access** | Remove `list`; use `read` if reading contents is acceptable. | Same as read. This permits reading contents, not just listing filenames. |
| **Alternative to metadata-only access** | Use `read` if reading contents is acceptable. | Same as read. This permits reading contents, not just file details. |
| **Deny** | `deny` | Leaves contents out or covers the path with an empty, read-only mount. |

## 4. Why Box can miss Runtime storage

In [AgentCore CLI](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-cli-way-to-interact.html) deployments that start Box during AgentCore Runtime Agent container initialization, Box builds the agent’s restricted filesystem view before session storage is available. If Runtime snapshots the host's filesystem at this stage, the sandbox's filesystem preserves that earlier view.

Runtime Agent storage follows the agent's session lifecycle. When a new session starts, Runtime mounts the configured bring-your-own filesystem inside that session’s host. Critically, the mounted path is available at session creation, not during Runtime agent initialization (which is snapshotted).

Box makes its mounts **private**, which means that new mounts added outside the sandbox do not automatically appear inside it. The restored Runtime agent snapshot (snapshot is restored for a new session VM) can therefore retain its earlier filesystem view even after Runtime successfully mounts the storage.

To support this agent init -> session creation + new mounted filesystem startup sequence, Box must make the new mount visible inside the sandbox and apply the `box.toml` restrictions before the agent accesses its contents.

## 5. Going forward, how can Box expose new mounts via mount event forwarding?

### 5.1 At Box startup

Box starts a (new) trusted helper that monitors configured `box.toml` mount sources. The sandboxed workload keeps its private mount namespace. An empty filesystem covers each pending mount path.

### 5.2 When a new mount arrives

Linux notifies the Box helper when the mounts visible in its namespace change. Box observes these changes through `/proc`. The helper uses `open_tree()` to create a private *inspection* and *preparation* views. These views reference the same files; they do not copy the data.

### 5.3 Before the workload receives the mount

1. Box evaluates the existing `box.toml` rules against the inspection view.
2. The helper prepares restricted file and directory attachments, applies mount attributes with `mount_setattr()`, then attaches the completed view with `move_mount()`. The helper retains mount-administration privileges within Box’s user namespace.

For example, Box can expose `/mnt/data` as read-only, permit writes under `/mnt/data/output`, and cover `/mnt/data/private`. The workload receives the completed arrangement without exposure to the unprotected source mount.

Each agent, tool, and local Model Context Protocol (MCP) server receives its own protected view.

## 6. Key decisions

### D1. Declaring a mount grants no access

`storage.mounts` names storage sources. Existing `read`, `write`, `exec`, file-specific grants, `deny`, and `deny_write` rules remain authoritative. Linux’s existing rule limitations still apply.

### D2. Source restrictions remain

1. Access is the intersection of Box’s rules and the source mount’s restrictions. For example, Box cannot make a read-only source writable.
2. Runtime owns storage authentication and mounting. Box applies its own filesystem rules. Runtime does not interpret `box.toml`.

### D3. Storage does not block Strands Box workload execution

The Box workload and Runtime continue while storage is pending. Early file operations may fail and require workload retries.

## 7. Limitations

1. Linux comes first to unblock Runtime. The macOS design remains pending.
2. Paths needed for permission exceptions must exist when Box prepares the mount. A missing deny target fails preparation. Files created later inside admitted directories remain subject to their existing protections.

   This first version supports the initial arrival of each configured storage mount. Box trusts the external storage manager, such as AgentCore Runtime, to mount the intended filesystem. Replacing or removing an admitted mount, or adding new mounts beneath it, remains follow-up work.

## 8. References

[Detailed design and diagrams](https://chorus.aws.dev/doc/Lfn1GdTjHZI6)

[Runtime filesystem configurations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html)
