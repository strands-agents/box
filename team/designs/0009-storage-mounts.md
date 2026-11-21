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

Box starts a (new) trusted helper that monitors the source paths listed in each agent, tool, and local server's filesystem `mounts` array in `box.toml`. Each sandbox keeps its private mount namespace. An empty filesystem covers each source path in that sandbox's list while its mount is pending.

For paths under a source in a sandbox's `mounts` list, Box no longer requires the source paths to exist at startup. It defers existence, file-type, and filesystem-object identity checks until the mount arrives. Configuration syntax, mount path syntax, conflicting grants, and restrictions on Box state and credentials remain checked at startup. Paths outside that sandbox's listed mount sources retain their existing startup checks.

### 5.2 When a new mount arrives

Linux notifies the Box helper when the mounts visible in its namespace change. Box observes these changes through `/proc`. The helper uses `open_tree()` to create a private *inspection* and *preparation* views. These views reference the same files; they do not copy the data.

### 5.3 Before the workload receives the mount

1. Box checks the required paths in the inspection view, records their filesystem-object identities, and evaluates the existing `box.toml` rules. It repeats these checks against the arriving filesystem even if placeholder directories existed at startup.
2. The helper prepares restricted file and directory attachments, applies mount attributes with `mount_setattr()`, then attaches the completed view with `move_mount()`. The helper retains mount-administration privileges within Box’s user namespace.

For example, Box can expose `/mnt/data` as read-only, permit writes under `/mnt/data/output`, and cover `/mnt/data/private`. The workload receives the completed arrangement without exposure to the unprotected source mount.

A source mount that has not arrived remains pending while the workload runs. Once a mount arrives, a missing required permission target or another preparation failure keeps it covered and stops Box with an error. Deferring startup checks does not remove the checks required before exposing storage.

Each agent, tool, and local Model Context Protocol (MCP) server receives its own protected view.

## 6. Key decisions

### D1. Listing a mount path grants no access

The proposed Box Core `box.toml` interface adds a `mounts` array to `[agent.filesystem]`, `[tool.<name>.filesystem]`, and `[mcp.<name>.filesystem]`. Each array contains absolute directory paths where that recipient expects externally supplied filesystems whose mounts can arrive after startup. A recipient lists only the mount paths it needs to receive.

```toml
[experimental-features]
linux-storage-mounts = true

# Forward both mounts to the agent; allow reading both directories.
[agent.filesystem]
mounts = ["/mnt/data", "/mnt/shared"]
read = ["/mnt/data", "/mnt/shared"]

# Forward only /mnt/data to the indexer; allow reading that directory.
[tool.indexer.filesystem]
mounts = ["/mnt/data"]
read = ["/mnt/data"]
```

Each recipient declares its own mount paths and does not inherit another recipient's list. An omitted or empty `mounts` list enables no mount event forwarding for that sandbox. A malformed or non-absolute mount path fails configuration validation at startup. Listing a path does not create a filesystem or tell Runtime to mount one; the external storage manager still owns mounting.

In this example, the agent receives both mounts, while `indexer` receives only `/mnt/data`. Listing a mount enables forwarding; it grants no filesystem access. Existing `read`, `write`, `exec`, file-specific grants, `deny`, and `deny_write` rules remain authoritative for the recipients that support them. Linux's existing rule limitations still apply. Each source is prepared when its mount arrives; the listed sources do not need to arrive together.

Box CLI already uses `[storage]` in profiles and packs for persistent directories, copied files, and hooks. For example, `[storage] directories = ["config"]` makes the CLI create a profile storage directory and grant the agent read and write access to it. The [CLI storage reference](../../docs/cli/packs-reference.md#storage) describes that existing feature. This proposal keeps external mount paths in each recipient's filesystem configuration instead of adding them to `[storage]`.

Named groups are an alternative, not part of the first version. Although `[egress.<name>]` provides a naming precedent, direct paths let readers see each recipient's mount sources without resolving another configuration table. Groups could become useful if several tools or local servers repeatedly select the same bundle of mount paths. They would not remove the need to configure each recipient's filesystem permissions using actual paths.

Declaring mount paths requires the `linux-storage-mounts` experimental flag and Linux; otherwise Box rejects startup. Box CLI profiles expose the same per-recipient lists and Linux-only opt-in. The feature remains experimental until regression and security testing qualify the supported environments.

### D2. Source restrictions remain

1. Access is the intersection of Box’s rules and the source mount’s restrictions. For example, Box cannot make a read-only source writable.
2. Runtime owns storage authentication and mounting. Box applies its own filesystem rules. Runtime does not interpret `box.toml`.

### D3. Storage does not block Strands Box workload execution

The Box workload and Runtime continue while storage is pending. Early file operations may fail and require workload retries.

## 7. Limitations

1. Linux is the only platform explored so far. We will focus on macOS after AgentCore Runtime is unblocked.
2. Paths needed for permission exceptions must exist when Box prepares the mount. A missing deny target fails preparation. Files created later inside admitted directories remain subject to their existing protections.
3. This first version supports the initial arrival of each configured storage mount. Box trusts the external storage manager, such as AgentCore Runtime, to mount the intended filesystem. Replacing or removing an admitted mount, or adding new mounts beneath it, remains follow-up work.
4. **P1 (deferred hardening): concurrent directory changes.** The first version assumes that paths requiring different permissions remain stable while Box checks and prepares storage. Another application or a writable alias can rename or replace those directories during preparation. Box could then apply restrictions to a different directory from the one it checked. Hardening against this edge case remains follow-up work; trusting the storage manager does not prevent other writers from changing directories.

## 8. Frequently asked questions

### 8.1 Why not start Box after storage becomes available?

That works when the application can delay sandbox startup. This proposal also supports applications that start Box before storage arrives, including sandboxes preserved in a Runtime snapshot.

### 8.2 Why not propagate mounts directly, and how does forwarding reach agents and tools?

Direct propagation could expose storage before Box applies its restrictions. The helper receives the mount separately, prepares the permitted filesystem view, and then exposes that view to the workload.

The proposed hierarchy has one helper per box watching the distinct source paths listed across the recipients' filesystem `mounts` arrays. Each recipient can list multiple paths. A box has one agent sandbox and can run multiple separate tool and local MCP server sandboxes. Forwarding serves those sandboxes independently; it does not pass storage through the agent sandbox to reach a tool.

| Recipient | Filesystem configuration in Box Core's `box.toml` | Application of mount forwarding |
| --- | --- | --- |
| Agent sandbox | `[agent.filesystem]` | Lists source paths in `mounts` and receives a view restricted by the agent's rules. |
| Each sandboxed tool execution | `[tool.<name>.filesystem]` | Lists its own source paths in `mounts` and receives a view restricted by that tool's rules. Calling a tool does not give it the agent's mount list or grants. |
| Each local MCP server sandbox | `[mcp.<name>.filesystem]` | Lists its own source paths in `mounts` and receives a view restricted by that server's rules. Remote MCP servers are outside this local mount mechanism. |

One source mount can therefore supply several differently restricted views, one for each sandbox that lists that source path and has permission to access its contents. These views reference the same stored data. For example, the agent can receive read-only access to `/mnt/data`, while a tool receives read and write access only to `/mnt/data/output`. Both list `/mnt/data` in `mounts`, but their permission lists differ. A tool without a storage grant receives no access to that storage's contents.

For an already running sandbox, Box attaches its prepared view after storage arrives. For a tool or server started after storage arrives, Box prepares the view under that recipient's rules before starting its process.

### 8.3 Why does Box currently reject paths that do not exist?

Box cannot inspect a missing path or apply restrictions to it. For sources in a sandbox's `mounts` list, the proposal moves those checks from startup to mount preparation. Configuration checks remain at startup, and storage must pass the deferred checks before exposure.

### 8.4 What happens if the agent accesses storage too early?

The storage path remains covered, so file operations may fail until preparation finishes. The agent can retry. If storage arrives but Box cannot apply the configured restrictions, Box keeps it covered and stops with an error.

### 8.5 Does Box copy the filesystem or scan every S3 object?

The design does not require either operation. Preparation works with mounts and paths referenced by filesystem rules. Remote lookups for those paths can still add latency; preparation cost does not depend simply on the total object count.

### 8.6 What happens when files or directories appear later?

Ordinary files created within an exposed directory become subject to that directory's existing protections. A configured permission exception, such as a denied subdirectory, must exist during preparation. Adding another filesystem mount underneath an exposed directory remains outside the initial scope.

### 8.7 Which permissions win: Runtime's or Box's?

Both must permit the operation. Box cannot make a read-only source writable or grant storage access that the underlying service refuses. Runtime manages storage authentication and mounting; Box applies the filesystem rules from `box.toml`.

### 8.8 What remains experimental or requires further hardening?

The feature remains experimental because testing is ongoing and we do not yet have sufficient confidence in its behavior and containment. Linux is the only platform explored so far, so the current implementation proposal requires a Linux opt-in. We will focus on macOS after AgentCore Runtime is unblocked. The initial version supports mount arrival. Mount replacement, removal, and later nested mounts remain follow-up work. Concurrent directory renames or replacements during preparation are a documented P1 hardening item.

## 9. References

[Detailed design and diagrams](https://chorus.aws.dev/doc/Lfn1GdTjHZI6)

[Runtime filesystem configurations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html)

## 10. Feedback

Following feedback from siwabhi, AgentCore Runtime Principal Engineer, we clarified that ongoing testing and incomplete confidence in containment keep the feature experimental. Linux is the only platform explored so far; macOS work follows after Runtime is unblocked. The first version uses absolute paths directly in each recipient's filesystem `mounts` list, without named groups or a separate `[storage]` mount declaration. Agents, tools, and local MCP servers declare their mount paths independently. Listing a mount enables forwarding; each recipient's existing filesystem rules still determine access.
