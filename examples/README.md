# Examples

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
the policy decides it. The [tutorial](../docs/user/tutorials/claude-code.md) walks through five
tasks, three permitted and two refused.

[Codex CLI](./codex-cli/): runs Codex CLI under a policy on macOS
with the project out of its own reach, so each file it reads, writes, or deletes goes through the
box's shell. The [tutorial](../docs/user/tutorials/codex-cli.md) walks through it with the output
of five tasks.

[pi](./pi/): runs pi under a policy on macOS with the project out of its own reach, so each file
it reads, writes, or deletes goes through the box's shell. The
[tutorial](../docs/user/tutorials/pi.md) walks through it with the output of six tasks.

Agent runs require model access. Each tutorial states its platform requirements.
For Box installation and configuration, follow [getting started](../docs/user/getting-started.md).
