# Security: what Box governs, and what you own

A box has two enforcement tiers: operating system enforcement, and policy enforcement.
`box.toml` sets which paths the workload's own processes can open. The operating system enforces
that, and it is fixed before the first process starts. `policy.dw` decides each request the workload
sends through the box's trusted process (its shell, its Python, its egress gateway, and its MCP
broker), and the policy engine enforces that. This page says which tier governs what, what Box
always enforces, and what a policy cannot do today.

Audience: an operator deciding what to put in `box.toml` and what to put in `policy.dw`.
[Policy](policy.md) introduces the rules, and the [design guide](../design/policy.md) holds the
reasoning.

For ownership of enforcement, configuration, and the surrounding environment, read the
[shared responsibility model](../design/security.md). This page covers the operator's
configuration choices and policy limitations.

## The two tiers

**`box.toml` governs the workload's own system calls, and the operating system enforces it.** The
workload reaches each of these directly. Policy is not asked, and the decision log shows nothing:

- A path in `[agent.filesystem]`. The box prints each one at startup under
  `no policy decision over these paths`.
- A tool's own files. A program under `[tool.<name>]` runs in its own sandbox and reaches the
  paths named in its own `filesystem` lists. Policy sees none of its file operations or child
  processes.
- A program of the surrounding OS that a `shell:spawn` permit admits. Policy decides once: whether
  the program runs. Its file operations are not decided.

You own what `box.toml` grants. Review each path in `[agent.filesystem]` and each `[tool.<name>]`
table, because direct reach raises no decision.

On Linux a call the syscall filter refuses (a raw socket, writable and executable memory, `ptrace`,
`bpf`, and the like) still leaves a `kernel_refused` record in the box's telemetry, though no decision
([a kernel refusal is observed, not decided](../design/decisions.md#a-kernel-refusal-is-observed-not-decided)).
A path absent from the agent's view, a write to a read-only path, and an unroutable connection leave
none.

**`policy.dw` governs each request through the box's trusted process, and the policy engine enforces
it:** each command line and file operation in Strands Shell (the box's shell), each file operation
in Monty (the box's Python), each connection and HTTP request through the egress gateway, and each
MCP request. [When the box asks policy](policy.md#when-the-box-asks-policy) lists them, and
[policy limitations](#policy-limitations) says what a broad permit reaches. An
[`[egress.<name>]`](egress.md) credential is attached to a request only after policy permits it. The
table binds the credential, and the policy's permits open the destination.

Two things pass with no decision from either tier:

- The reply to an HTTP request. Its status is recorded as `output.status`, so a temporal rule can
  read it.
- A few MCP protocol methods, and every notification. [MCP](policy/actions.md#mcp) lists them by
  transport.

## What Box always enforces

One rule holds whatever a policy permits. No request reaches the box directory. No request reads
or changes the `box.toml` and `policy.dw` this run loaded, or changes the directory that holds them.
A `permit` on these paths has no effect. When this rule refuses a request, the shell command or the
Python call fails with the path and a reason, and the decision log entry carries
`strands.box.policy.cause` set to `enforcement` and `strands.box.policy.rule` set to
`enforcement:reach-floor`. For the box directory and the files this run loaded, the reasons are:

```text
resolves into trusted Box state, which no policy may open
```

```text
resolves to an authority source that this run loaded, which no policy may open or change
```

**Cloud metadata protection is two `forbid` rules in your policy.** `metadata_hosts` refuses the
metadata services by name. `metadata_addresses` refuses link-local and metadata addresses, checked
on the address the gateway dials. Add both to the policy you wrote in
[getting started](getting-started.md), and to any policy you write by hand. The example policies in
the Box repository, under `examples/strands-box/`, carry both:

```dw
@id("metadata_hosts")
@description("Refuse the cloud metadata services by name, before resolution.")
forbid (principal, action == Box::Action::"net:connect", resource)
when {
  context.input.host == "metadata.google.internal" ||
  context.input.host == "metadata.azure.internal"
};

@id("metadata_addresses")
@description("Refuse link-local and cloud metadata addresses, on the address resolution pinned.")
forbid (principal, action == Box::Action::"net:connect", resource)
when {
  context.input has ip && (
    context.input.ip like "169.254.*" ||
    context.input.ip == "fd00:ec2::254" ||
    context.input.ip like "fe8*" || context.input.ip like "fe9*" ||
    context.input.ip like "fea*" || context.input.ip like "feb*")
};
```

[Cloud instance metadata](../design/egress.md#cloud-instance-metadata) in the design guide states
that these two rules are the only check on the metadata endpoints.

## Policy limitations

Each item is something a policy cannot do today, with what to do about it. Where a design page
records why, the item links it.

- **A broad read permit reaches your secrets.** Strands Shell and Monty can name any path under
  your home, including `~/.aws` and `~/.ssh`. A `permit` on `fs:read` with no path condition grants
  all of them. Write every filesystem rule with a path condition. See
  [where policy sits](../design/policy.md#where-policy-sits).
- **Box does not check that the rules of a policy agree with one another.** Two permits that admit
  the same requests load without a word. Write every cap as a `forbid`.
  [A cap written as a permit](policy.md#a-cap-written-as-a-permit) describes what the load does
  catch. See [what refuses to load](../design/policy.md#what-refuses-to-load).
- **A rule that requires an earlier event sees refused attempts too.** A `::request` event is
  recorded for every attempt, permitted or refused. Key the condition on `::response`, which is
  recorded only for an operation that ran. See
  [what a history rule sees](../design/policy.md#what-a-history-rule-sees).
- **A budget keyed on `::response` can be overspent by requests in flight.** A `::response` is
  recorded when the operation ends, so several requests in flight pass the same count. A budget
  keyed on `::request` is exact, and a refused attempt spends from it. See
  [what a history rule sees](../design/policy.md#what-a-history-rule-sees).
- **A rule that calls a temporal macro, such as `count_within`, loses its count when any text
  before the call changes**, even a comment. A rule that writes its `when temporal` clause inline
  keeps its count until that clause changes. Every rule in this guide is written inline. See
  [residual risk](../design/policy.md#residual-risk).
- **Monty judges a path as the script spelled it.** When a path the script names goes through a
  symlink, policy decides on the link's spelling, and the decision log records that spelling. The
  operation is then refused, because Monty acts on the canonical path only. Name the target
  directly. See
  [how Box decides a file operation](../design/monty.md#how-box-decides-a-file-operation).
- **The decision log records the rule and the path, and not the operation.** A `cat` and an `ls`
  of one file produce the same entry.
- **A long temporal window slows every decision on that action.** Each decision recounts the events
  in the window, so a `24h` window on a busy action costs more than a `1m` one. Pick the shortest
  window the rule needs. See [residual risk](../design/policy.md#residual-risk).

## See also

- [Policy](policy.md): what a policy is, the actions, common rules, and load failures.
- [Write a policy and read what it decided](tutorials/first-policy.md): a first policy, a denial,
  and the decision log.
- [The action vocabulary](policy/actions.md): every action, its fields, and which part of the box
  raises it.
- [Policy in the design guide](../design/policy.md): how each tier is enforced, and why.
