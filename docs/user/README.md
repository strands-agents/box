# Box user guide

Box runs an agent, or another command, under an operator's policy, with operating system enforcement.

- [`getting-started.md`](./getting-started.md): download Box, then write and run a box for an agent.
  Start here.
- [`egress.md`](./egress.md): the `[egress.<name>]` table, which gives the agent a credential for a service.
- [`mcp.md`](./mcp.md): the `[mcp.<name>]` table, for a stdio or an http MCP server.
- [`mcp-policy.md`](./mcp-policy.md): write the rules that let the agent use an MCP server.
- [`monty.md`](./monty.md): the Python that a box runs, its file operations, `fetch()`, and the rules to write.
- [`shell.md`](./shell.md): Strands Shell, the agent's shell, with what runs where, the fields a rule reads, and the exit statuses.
- [`shell-policy.md`](./shell-policy.md): write policy for the agent's shell commands, the programs it runs, and the files they touch.
- [`telemetry.md`](./telemetry.md): the `[telemetry.decisions]` keys, what each record carries, and how to read a records file.
- [`policy.md`](./policy.md): what a policy is, when the box asks it, the ten actions, the six
  common rules, and what to do when a policy fails to load. Start here for policy.
- [`security.md`](./security.md): what `box.toml` governs, what `policy.dw` governs, the one rule
  Box always enforces, and the policy limitations.

## Tutorials

- [`tutorials/first-policy.md`](./tutorials/first-policy.md): write a policy, run it, read a denial,
  and read the decision log.
- [`tutorials/strands-cli-telemetry.md`](./tutorials/strands-cli-telemetry.md): add the Strands
  CLI's own traces and metrics to the records file from getting started, and read both together.
- [`tutorials/strands-sdk-agent.md`](./tutorials/strands-sdk-agent.md): put an agent you wrote with
  the Strands Agents SDK in a box, and watch the policy permit two tasks and refuse two.
- [`tutorials/claude-code.md`](./tutorials/claude-code.md): put Claude Code in a box with none of
  the project's files in its own reach, and watch its Bash tool route every read, write, and delete
  through the policy.
- [`tutorials/codex-cli.md`](./tutorials/codex-cli.md): put Codex CLI in a box with the project out
  of its own reach, so its shell tool is its only way to a project file, and watch the policy permit
  three tasks and refuse two.
- [`tutorials/pi.md`](./tutorials/pi.md): put pi in a box with the project out of its own reach,
  so its `bash` tool is its only way to a project file, and watch the policy permit three tasks and
  refuse two.

## Reference

- [`config.md`](./config.md): the `box.toml` reference: every key and table, its type and default,
  and what the loader refuses.
- [`policy/actions.md`](./policy/actions.md): every action, its fields, and which part of the box
  raises it.

For how Box works and why it is safe, read the [design guide](../design/).
