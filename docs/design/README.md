# Box design guide

How Box works, and why you can trust it with an untrusted agent.

Audience: a security evaluator who decides whether to run untrusted agents under Box, a
contributor who changes it, and anyone who is curious how it works. For how to configure
and run a box, read [getting started](../user/getting-started.md).

This guide also states how we think an agent sandbox should work. The principles and the
decisions are meant to hold for any agent sandbox. Box is the example that follows them.

## Pages

New here? Read [`architecture.md`](./architecture.md) for the parts, then
[`security.md`](./security.md) for responsibilities, [`containment.md`](./containment.md) for
enforcement, [`policy.md`](./policy.md) for decisions, and
[`limitations.md`](./limitations.md) for residual risk.

| Page | Answers |
|---|---|
| [`architecture.md`](./architecture.md) | What the parts of a box are, where each one runs and what it decides, how one command travels from the agent to the file it touches, and the order a run brings the parts up. |
| [`security.md`](./security.md) | Which responsibilities belong to Box, the operator, and the surrounding environment, and how to distinguish configuration risk from an enforcement defect. |
| [`binaries.md`](./binaries.md) | What each of the three binaries is, where it runs, and why a box needs all three. |
| [`mcp.md`](./mcp.md) | How a box starts its MCP servers, turns each server's tool list into policy actions, and decides each tool call. |
| [`mcp-discovery.md`](./mcp-discovery.md) | How a box learns each MCP server's tools while it runs, stages their schemas, and finishes discovery. |
| [`decisions.md`](./decisions.md) | Why the design is the way it is. A historical record, so the code is the authority where the two disagree. |
| [`policy.md`](./policy.md) | Where policy sits beside operating system enforcement, how one engine per box decides each mediated request, and what the durable history does and doesn't guarantee. |
| [`egress.md`](./egress.md) | How traffic reaches the egress gateway, how it decides each connection and request, and how it adds credentials. |
| [`credentials.md`](./credentials.md) | How Box keeps each real secret in the box's trusted process, how the gateway swaps or signs it onto a permitted request, and what a tool or local MCP server gets. |
| [`monty.md`](./monty.md) | How Box runs a Python script in Monty, decides each file operation it makes, and sends its `fetch()` through the egress gateway. |
| [`macos-enforcement.md`](./macos-enforcement.md) | How Seatbelt enforces each sandbox on macOS, how the profile for a tool or local MCP server differs from the agent's, and where the restrictions end. |
| [`containment.md`](./containment.md) | What a box guarantees, where its reach comes from, how the agent's sandbox differs from a tool's or a local MCP server's sandbox, and what sits outside operating system enforcement. |
| [`shell.md`](./shell.md) | How Strands Shell decides each command and file operation, and where a program it doesn't implement runs. |
| [`telemetry.md`](./telemetry.md) | What a box records, which process writes it, and why an agent can neither forge a record nor suppress one. |
| [`limitations.md`](./limitations.md) | What allowed actions can still affect, which requests Dogwood can check, which protections Box does not provide, and the residual risk. |
| [`terminology.md`](./terminology.md) | The word to use for each thing, and the words not to use. |
| [`tenets.md`](./tenets.md) | How an agent sandbox should work, in priority order, and what is out of scope. |

These pages are still to come: operating system enforcement on Linux, and the platform differences.
