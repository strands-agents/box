# Examples

These examples run Box Core directly. To run a coding agent with the Box CLI instead, follow
[Get started with Box](../docs/cli/getting-started.md).

Run an agent with project operations through Strands Shell, where Box applies the policy.
Each example states its dependencies and run commands.

[Strands CLI](./strands-cli/): runs the Strands CLI under a policy on macOS, with Shell and
`web_fetch` as its tools. It holds the finished files from
[getting started](../docs/user/getting-started.md).

[Strands Python SDK](./strands-box/strands-sdk-agent/): a small agent with three tools,
each a command through Shell. Follow its [tutorial](../docs/user/tutorials/strands-sdk-agent.md)
to observe permitted operations and policy denials.

[Claude Code](./claude-code/): runs Claude Code under a policy on macOS with none of the
project's files in its own reach, so each read, write, and delete goes through its Bash tool and
the policy decides it.

[Codex CLI](./codex-cli/): runs Codex CLI under a policy on macOS
with the project out of its own reach, so each file it reads, writes, or deletes goes through the
box's shell.

[pi](./pi/): runs pi under a policy on macOS with the project out of its own reach, so each file
it reads, writes, or deletes goes through the box's shell.

Agent runs require model access.
For Box installation and configuration, follow [getting started](../docs/user/getting-started.md).

[Linux cloud deployments](./cloud-deployments/): run workloads on Amazon EKS, AgentCore Runtime, or Google Compute Engine.
The samples include source, deployment commands, expected refusals, and tested-platform limits.

For Linux environment requirements and deployment checks, read the [cloud deployment profiles](../docs/user/cloud-deployments.md).

[Runtime storage](./cloud-deployments/agentcore-runtime/storage/): start Box before provider storage arrives, then compare real file operations inside and outside its sandbox.
