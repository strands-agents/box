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

This mode accepts one
`[agent]` and refuses hosted `[tool]` and `[mcp]` declarations. It writes record
version 38, which older binaries refuse. Recreate earlier experimental container-agent records from the original configuration.

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
restrictions, and mediated network access still apply. The workload uses the normal Linux syscall policy. PID 1 handles its filesystem
queries after dropping capabilities.

Mount granted application files, executables, libraries, and time zone data
from the same objects in both containers. Separate root filesystems built from
the same image can assign different device and inode numbers to these paths.
Use read-only shared mounts for immutable runtime files. Keep private credentials
on their intended container.

The trusted processes exchange a bounded launch request and descriptors. PID 1
opens and pins its own root entry, the entry-only directories `/etc` and `/var`,
and the kernel null device. The supervisor checks the original grants and
confirms the digest of the exact workload configuration. All data-bearing
application grants retain their original object identity checks. The PID 1 reaper holds a lifetime connection to the trusted
supervisor. If that connection closes, PID 1 exits and the kernel terminates its
remaining namespace members. Do not use this mode in a shared or host PID namespace.
