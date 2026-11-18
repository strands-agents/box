# Linux requirements

Box needs compatible executables and libraries, plus permission to create its Linux sandboxes.
These requirements apply when you run Box directly on Linux, in a virtual machine, or inside a container.
Check them under the same operating system identity and container settings that will start Box.

## Builds and architectures

Linux release binaries use Amazon Linux 2023 as their build baseline.
Another distribution must provide the libraries and setup permissions below; its name alone does not establish compatibility.
Box does not specify a minimum kernel version. Check the required operations and your actual workload.

ARM64 is supported. Linux x86-64 is experimental and requires the
[`EXPERIMENTAL_X86_SUPPORT=TRUE` startup opt-in](./getting-started.md#linux).
A release may omit an architecture. Check its archive and checksum before downloading, or
[build from source](./getting-started.md#build-from-source).
The [tested configurations](#tested-configurations) below record specific checks, not a promise about every distribution or container runtime.

## Requirements

A namespace gives a process a separate view of resources such as process IDs, mounts, or networking.
A Linux capability grants a specific privilege. A seccomp filter restricts the system calls a process can use.
Box must be able to create its namespaces, then remove setup privileges and install its workload restrictions.

| Requirement | Required value or operation | How to check | What failure means |
| --- | --- | --- | --- |
| Architecture | A matching ARM64 or experimental x86-64 build for Box and the workload. | Run `uname -m`; expect `aarch64` or `x86_64`, matching the archive. | A mismatched executable cannot start natively. |
| GNU C library (glibc) and loader | For release binaries, glibc 2.34 or newer and the matching loader. | Follow [Check the installed binaries](#check-the-installed-binaries). | The main executable or a helper cannot load. |
| GCC runtime library | `libgcc_s.so.1` for the executable's architecture. | Check that `ldd` resolves every library for all three executables. | An executable with a missing library cannot load. |
| Namespaces | User, mount, process, interprocess communication, and hostname namespaces; a network namespace for default networking. | [Start the intended workload](#check-sandbox-startup) under its deployment identity. | Box cannot create the sandbox and does not start the workload. |
| Identity and mounts | Identity mapping, bind mounts, private temporary filesystems, a process filesystem at `/proc`, and root replacement. | Check sandbox startup inside the actual runtime or container. | Box cannot construct the workload's filesystem and process view. |
| Workload restrictions | Capability removal, `no_new_privs` to prevent privilege gains on execution, and seccomp filter installation. | Check sandbox startup; inspect any setup error. | Box refuses to start without the required restrictions. |
| Box executables | Keep all three executables from the same build together on storage that allows execution. Helpers must be regular executable files. | Check file permissions and storage mounts. | Box refuses helper symlinks and helpers without execution permission. |
| Private storage | Writable temporary storage and separate directories for Box state and task workspaces. | Check [state-directory ownership and permissions](./config.md#keys), temporary storage, and workspace permissions. Keep Box state outside paths the workload can write. | Box cannot prepare its private state or workspace. |
| System interfaces | `/dev/urandom`, `/dev/null`, process and identity information in `/proc`, and Unix-domain sockets for local communication. | Check sandbox startup and the workload's required operations. | Setup or local communication fails. |
| Application dependencies | The workload's interpreters, libraries, certificates, and tools, with access permitted by `box.toml`. | Run the workload and its tools inside Box. | Box can start while an application operation still fails. |

The kernel must implement these operations, and the surrounding operating system must permit Box to use them.
Installing packages cannot override an operating system or container permission restriction.

## Check the installed binaries

First [download Box and verify its release checksum](./getting-started.md#step-1-download-box).
The commands here use the guide's `./box-core` directory.
Release packages contain `box`, `strands-box-contain-trampoline`, and `strands-box-sock-alias`.
An unrenamed source build calls the main executable `strands-box`.

Record the architecture, kernel, and C library separately:

```sh
uname -m
uname -r
getconf GNU_LIBC_VERSION
```

`uname -m` must match the build. `getconf` must report `glibc 2.34` or newer for release binaries.
`uname -r` identifies the kernel being tested; it does not establish that sandbox setup is permitted.
In a container, the Linux machine or virtual machine supplies the kernel, while the image supplies the libraries.

Check library resolution for each executable:

```sh
ldd ./box-core/box
ldd ./box-core/strands-box-contain-trampoline
ldd ./box-core/strands-box-sock-alias
```

No required library should report `not found`.
The release loader is `/lib/ld-linux-aarch64.so.1` on ARM64 or `/lib64/ld-linux-x86-64.so.2` on x86-64.
These commands are diagnostic tools; they are not additional Box runtime dependencies.
For a custom source build, inspect that build's loader and library requirements.

Finally, run `./box-core/box --version`. It should print `strands-box` and the release version.
This checks that the main executable loads. It does not create a sandbox or test helper execution.

## Check sandbox startup

Run Box with the configuration and operating system identity you intend to deploy.
Use `box run --config` with your configuration file, as shown in the
[Linux installation instructions](./getting-started.md#linux) and [configuration reference](./config.md).
On x86-64, set the experimental startup opt-in first.

Check that the workload starts, performs a permitted operation, and cannot perform a file operation outside its configured access.
A version check or a standalone user-namespace probe does not test Box's complete setup.
A probe can also run under a different executable-specific security policy from Box's launcher.
For deployment checks that include cancellation, timeouts, and cleanup, use
[Check the deployment](./cloud-deployments.md#check-the-deployment).

## Operating system and container permissions

AppArmor profiles restrict what a Linux program may do.
Where the operating system restricts unprivileged user namespaces, its policy must permit Box's
`strands-box-contain-trampoline` launcher to create them.
A permission for an unrelated diagnostic program does not establish that Box has that permission.

When Box runs inside a container, the container's own seccomp and AppArmor policies apply before Box installs its restrictions.
They must permit namespace and filesystem setup, including `unshare`, `mount`, `umount2`, and `pivot_root`.
Container rules that hide paths under `/proc` or mount them read-only can also prevent Box from mounting its own process filesystem.
Check these restrictions inside the deployed container, not only in its image definition.
Box's workload policy does not grant these operating system permissions.
The [Amazon EKS example's container settings](./tutorials/eks.md#cluster-baseline) show one tested configuration.
Those settings are not minimum permissions for every container runtime.

Use the failed setup operation to identify what needs configuration:

| Error fragment | What failed | What to check |
| --- | --- | --- |
| `cannot run the Linux package` | The downloader could not execute the staged main binary. | Read the preceding loader error. Check architecture, libraries, and execution permission on the installation filesystem. |
| `this identity may not create a user namespace` | The namespace availability check failed. | Check operating system namespace policy and the container's system-call filter under the intended identity. |
| `denying setgroups`, `writing the UID map`, or `writing the GID map` | Box could not prepare user and group ID mappings. | Check the launcher's namespace permission and access to the new namespace's identity files in `/proc`. |
| `mounting a fresh proc at` | Box could not mount its process filesystem. | Check mount permissions and outer masked or read-only `/proc` mounts. These restrictions were one cause in the container test below. |
| `installing the namespace permit filter` | Box could not install a required system-call filter. | Check kernel filter support and restrictions imposed by the outer runtime. |

`EPERM` means an operation was not permitted; it does not identify which policy layer refused it.
Check the surrounding operating system or container diagnostics before changing a permission.

## Tested configurations

These examples record settings and results for specific Box revisions and environments:

- [Amazon Linux 2023 ARM64 on Amazon EKS](../../examples/cloud-deployments/eks/README.md#tested-configuration).
- [Debian 12 ARM64 on Google Compute Engine](../../examples/cloud-deployments/gcp/README.md#tested-configuration).

Each record identifies the configuration and checks that passed. Repeat the checks for your Box build and deployment.

### Ubuntu and Colima compatibility checks

The following compatibility checks used Box v0.2.3 without changes to its binaries.
This table summarizes observed results; it does not provide a complete setup procedure or test harness.
Both configurations used the same Ubuntu 24.04.4 ARM64 virtual machine, Linux `6.8.0-117-generic`,
and Colima `0.10.3`. Colima provides the Linux virtual machine on the Mac used for these checks.

| Execution environment | Configuration needed for startup | Observed result |
| --- | --- | --- |
| Directly in the Ubuntu virtual machine | An executable-specific AppArmor permission for Box's launcher to create user namespaces. | Startup, Bash, the host OS's Python, file access controls, and isolation between consecutive runs passed. |
| Ubuntu 24.04 ARM64 container using Docker `29.5.2` in the same virtual machine | Adjusted Docker's system-call filter, AppArmor profile, and system-path restrictions to permit Box's setup operations. AppArmor remained enforced, with restrictions on setup-call arguments and mount destinations. | The same checks passed without privileged mode or added container capabilities. |

Both default configurations refused sandbox startup. The configured runs allowed granted file operations,
refused private reads and writes to read-only paths, and left the original files unchanged.
These checks did not cover Claude, Codex, interactive sessions, networking, long-running workloads, or other kernels.
They establish compatibility for the listed configurations, not a minimum kernel version or a complete deployment test.
