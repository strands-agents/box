# Access storage that arrives after Box starts

This experimental Linux ARM64 example starts a sandboxed file-operation workload before AgentCore Runtime attaches storage. It verifies that the same process can later read the mounted filesystem while its read-only grant still prevents writes. The workload is a small C program; no model access is required.

Follow [Use experimental storage mounts on AgentCore Runtime](../../../../docs/cli/experimental-runtime-storage.md) for build prerequisites, configuration, image publication, managed session storage deployment, invocation, and cleanup. The guide keeps the availability-dependent S3 bucket mount procedure separate from S3 Files.

## Files

| File | Purpose |
| --- | --- |
| `prepare.py` | Copy matching Box binaries and compile the workload. |
| `Dockerfile` | Build the ARM64 Runtime image with container user ID zero. |
| `server.py` | Start Box before the HTTP listener and perform trusted source controls during invocation. |
| `workload.c` | Perform the corresponding file operations inside the existing sandbox. |
| `verify-local.py` | Exercise delayed arrival in a disposable local container with a FUSE mount. |
| `role.yaml` | Define a scoped Runtime execution role through CloudFormation. |
| `deploy.py` | Create, inspect, invoke, stop, and delete the runtime using saved receipts. |

## Coverage

The reduced example requires both source-side positive controls and sandboxed outcomes. It distinguishes a missing file from a Box restriction, and it does not qualify a delayed arrival when the provider was already mounted at startup. Generated configurations, binaries, and receipts remain outside Git.

This example does not qualify every filesystem list, hosted Shell or Monty access, configured tools, local Model Context Protocol (MCP) servers, a non-root Runtime image, other architectures, or macOS. Mount replacement and removal are outside the experiment's guarantees. Keep those limits when adapting the configuration to an agent.
