# Strands Box storage mounts

**Author**: Kevin Orellana

**Date**: November 21, 2026

## Question

AgentCore Runtime can attach storage after Strands Box starts. Box must make that storage accessible without weakening Strands Box’s filesystem rules.

## Background

Box creates a *private* mount namespace, which isolates the sandboxed workload’s filesystem. Runtime’s *Bring Your Own Storage* (BYOS) feature propagates new storage mounts into the customer's container. Those mounts do not automatically reach Box’s private namespace today.

While starting Box **after** storage arrives avoids the ordering problem, it does not support a Box workload already running. This proposal builds on Ravi’s mount-propagation [prototype](https://github.com/rvkandury/box-public/commit/5816878c44741ac6ee681cba937049b84ac6196d).

Unfortunately, direct propagation into the workload would expose incoming mounts **before** Box applied its filesystem restrictions from `box.toml` (read/write/execute allow-lists). Mount visibility and permission enforcement therefore need design and implementation.

## Solution for Linux

> We prioritize reviewing the Linux solution to unblock the Runtime story. macOS design remains pending.

### Step 1: Create an empty filesystem where the mount would be

Add a trusted Box helper that monitors a configured mount source. The workload would retain its private namespace. Each pending storage mount remains covered by an empty filesystem.

### Step 2: Listen for new mounts

Linux notifies the helper when its mount table changes through `/proc`, which the box’s trusted process already has access to. The helper uses `open_tree()` to create private "inspection" and "preparation" views of the incoming mount. These views reference the same stored files. They do not copy the data.

### Step 3: Inspect new mounts, apply Strands Box restrictions and mount them into the workload's view

Box evaluates the existing `box.toml` rules against the "inspection" view. The helper prepares restricted file/directory attachments in a separate preparation view. It applies mount attributes with `mount_setattr()` and finally attaches the completed view to the workload with `move_mount()`.

For example, Box can expose `/mnt/data` as read-only, permit writes under `/mnt/data/output`, and cover `/mnt/data/private`. The workload receives the completed arrangement. It never receives the unprotected source mount.

### Interface update in Box Core and Box CLI profiles

The proposed interface stays in Box Core’s `box.toml`:

```toml
[experimental-features]
linux-storage-mounts = true

[storage]
mounts = ["/mnt/data", "/mnt/shared"]
```

`storage.mounts` grants no access. Existing `read`, `write`, `exec`, file-specific grants, `deny`, and `deny_write` rules remain authoritative. Linux’s existing rule limitations still apply.

For Box CLI and profiles, this will similarly be exposed as an experimental, Linux-only feature flag at first. The initial release prioritizes unblocking Runtime. Full regression and penetration testing remain incomplete, so the feature is experimental and should not be treated as production-ready.

### Agent, tool and tool server containment updates

Each agent, tool, and local Model Context Protocol (MCP) server receives its own protected view.

Access is the intersection of Box’s rules and the source mount’s already present restrictions. Box **cannot** make a read-only source writable. For example, Runtime continues to own storage authentication and mounting. Runtime does not interpret `box.toml`.

The Box workload and Runtime continue while storage is pending. Early file operations to the mount may fail and require workload retries.

Paths needed for permission exceptions must exist when Box prepares the mount. A missing deny target fails preparation. Files created later inside admitted directories remain subject to their existing protections.

The helper retains mount-administration privileges within Box’s user namespace.

## References

[Runtime filesystem configurations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html)
