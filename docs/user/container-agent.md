# Run an agent in a container PID namespace

The experimental `container-agent` mode runs the agent in a container's private
PID namespace. It is for Linux ARM64 installations where the container runtime
masks `/proc` and a nested PID namespace cannot mount a fresh procfs. The default
namespace backend remains unchanged.

Set the feature in the Box configuration:

```toml
[experimental-features]
container-agent = true
```

Linux also requires `EXPERIMENTAL_LINUX_SUPPORT=TRUE`. This mode accepts one
`[agent]` and refuses hosted `[tool]` and `[mcp]` declarations. It writes record
version 24, which older binaries refuse.

The installer starts the trusted `strands-box run` process separately from the
workload container. Both use the same non-root UID and a shared Box directory.
The workload container starts this command directly as PID 1:

```sh
strands-box-contain-trampoline --receive-container /absolute/box_dir/private/container.sock
```

Do not share its PID namespace with another container. The receiver must be its
only process and have one thread, no capabilities, and `NoNewPrivs` set. Its
`/proc/self` must identify PID 1 in that namespace. Box refuses startup if these
checks fail. The socket's parent must be private and owned by the receiver.
The container runtime must permit the setup calls that create the user, mount,
IPC, UTS, and network namespaces. Do not disable its security policy to do so.

Box binds the container's existing procfs into the filesystem view, keeps its
masked submounts, and makes it read-only. Filesystem grants, executable-memory
restrictions, and mediated network access still apply. The workload cannot
import descriptors with `recvmsg`. It may use `renameat2` only with
`RENAME_NOREPLACE`. Signal delivery remains inside the private PID namespace;
`kill` refuses PID 1, process group 0, and the all-process target -1. This is not
a parent-child relationship check or a restriction on signal numbers.

The trusted processes exchange one bounded launch request and descriptors before
the workload starts. The PID 1 reaper holds a lifetime connection to the trusted
supervisor. If that connection closes, PID 1 exits and the kernel terminates its
remaining namespace members. Do not use this mode in a shared or host PID namespace.
