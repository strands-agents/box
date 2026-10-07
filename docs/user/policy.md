# Policy

A policy is the `policy.dw` file of `permit` and `forbid` rules that decides each request the
workload makes through the box's trusted process (the part of Box that runs outside the box and
answers its requests). `box.toml` sets what the workload's own system calls can reach, and the
operating system enforces that. Inside that reach, policy decides each request the workload sends
through the box's trusted process.

Audience: an operator who wants to write or change a policy. [Write a policy and read what it
decided](tutorials/first-policy.md) walks through a first one, and [the action
vocabulary](policy/actions.md) lists every field a rule can read.

> **Status.** The action vocabulary and the context fields can change before 1.0.0. Pin the Box
> build you install (`./box-core/box --version`).

## When the box asks policy

Four parts of the box ask policy, each about its own boundary:

- **Strands Shell**, the box's own shell, which the agent's shell tool runs. It asks once per
  command line, as `shell:exec` or `shell:spawn`, and once per file operation a command makes, as
  `fs:*`.
- **Monty**, the Python interpreter the box runs for the agent's scripts. It asks once per file
  operation, as `fs:*`.
- **The egress gateway.** It asks once per connection, as `net:connect`, once per HTTP request, as
  `http:request`, and once per MCP request over HTTP, as `mcp:call`.
- **The MCP broker.** It asks once per request to a local MCP server, as `mcp:call`. On a
  `tools/call` it asks a second time, as the tool's own generated action. At startup it asks once
  for each declared server, as `shell:spawn`.

Three facts decide every request:

- **The box denies by default.** With no matching `permit`, a request is refused. A `box.toml` with
  no `policy` key, or a `policy.dw` with no rules, refuses every request that reaches policy.
- **A `forbid` beats a `permit`.** Write an exception to a broad permit as a `forbid`.
- **A `permit` only widens.** A restriction such as a budget is a `forbid`.

The agent's own system calls reach a path in `[agent.filesystem]` with no decision and no record.
[Security](security.md) states where each tier governs.

## How a rule reads

```text
@id("no_env")
@description("The .env file holds credentials the agent must not read.")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/project/.env" };
```

From the top:

- **`@id("no_env")`** names the rule. A denial and the decision log name the rule by this id, so
  give each rule its own.
- **`@description("…")`** is the error message returned when the rule denies.
- **`forbid`** is the effect. The other effect is `permit`.
- **`principal`** is always the agent. Write it as `principal`, with no condition.
- **`action == Box::Action::"fs:read"`** names the one action this rule decides.
- **`resource`** is always the same fixed resource. Write it as `resource`, with no condition.
- **`when { … }`** is the condition. It reads the request's `context.input` fields, and `path` is
  one of the fields `fs:read` carries.

A rule with a `when temporal { … }` clause also reads the box's recorded history, so it can count
earlier events or require one. [A budget over time](#a-budget-over-time) and [commit only after
the tests passed](#commit-only-after-the-tests-passed) show the two shapes.

## How a denial reads

A denial names the path, program, or host the rule saw, then the rule, then its description:

```text
strands-shell: cat: policy denied this operation on '~/project/.env' [policy: no_env]: The .env file holds credentials the agent must not read.
```

The agent reads the same text, so write each `@description` for the agent. The tail has one of
these shapes:

- `[policy: <id>]: <description>`: a `forbid` with that `@id` matched.
- `[policy: <id>]`: a `forbid` matched, and it has no `@description`.
- `[default-deny]: No permit policy matched this request.`: no `permit` matched. Add one if the
  operation is intended.
- `[policy-pending]: The complete policy bundle is not installed.`: an MCP tool's schema is still
  being discovered. The call can be retried.
- `because the request could not be evaluated.`: the engine hit an internal fault, and it denied
  the request.

Each caller shows the text in its own form:

- **A shell command** prints it on stderr. A command the policy refused exits `126`. When policy
  refuses a file operation inside a command it permitted, the command fails with its own status
  (`1` for `cat`).
- **Python in the box** raises a `PermissionError` whose message is the text. The script can catch
  it.
- **An HTTP request** receives a `403` response whose body is the text. The request never leaves
  the box.
- **An MCP call** receives a JSON-RPC error with code `-32001` and the text, followed by the method
  in parentheses.

Two refusals look like a denial, and no `permit` lifts them:

- **A path inside the box directory, or the `box.toml` or `policy.dw` this run loaded, is refused
  whatever the policy says.** The decision log records the cause as `enforcement`, and
  [step 4 of the tutorial](tutorials/first-policy.md#step-4-read-the-decision-log) shows how to read
  it. [What Box always enforces](security.md#what-box-always-enforces) states the rule.
- **A file tool of the harness itself fails with "operation not permitted" on macOS, or "no such
  file or directory" on Linux, and the decision log holds no record.** The path is outside every
  `[agent.filesystem]` list. Add it to a list in `box.toml` if the agent is meant to reach it.

## The actions

The box ships ten actions in four categories, and generates one more for each MCP tool it
discovers. [The action vocabulary](policy/actions.md) lists the fields of each one.

- **[Filesystem](policy/actions.md#filesystem)**: a file operation in Strands Shell or Monty.
  `fs:read`, `fs:write`, `fs:delete`, `fs:move`, and the reserved `fs:other`.
- **[Network](policy/actions.md#network)**: an outbound call through the egress gateway. Each call
  is two decisions: `net:connect` for the connection, before TLS, and `http:request` for each
  request inside it, after TLS on an HTTPS connection.
- **[Shell](policy/actions.md#shell)**: a command line in Strands Shell, judged once after the
  shell resolves its first word to a program. `shell:exec` for a program the shell implements, such
  as `cat` or `grep`, and `shell:spawn` for a program of the surrounding OS, such as `git`, and for
  the start of each stdio MCP server `box.toml` declares.
- **[MCP](policy/actions.md#mcp)**: a request to an MCP server. `mcp:call` for each request, on
  every method, and one generated `<server>::Action::"<tool>"` for each discovered tool, decided
  on a `tools/call` after `mcp:call` permitted it.

## Common rules

Six rules an operator writes often. Each one is a working rule. Copy it beside the permits from
[your first policy](tutorials/first-policy.md), replace `~/project` with your project directory, and
run the box. Two of them say what else `box.toml` needs. The first five are `forbid` rules. The last
is a pair of `permit` rules that replace two from the tutorial.

### A budget over time

At most twenty writes of file content in one hour. The twenty-first is refused until the oldest
counted write is more than an hour old.

```text
@id("write_budget")
@description("At most 20 content writes completed in one hour.")
forbid (principal, action == Box::Action::"fs:write", resource)
when { context.input.operation == Box::FsWriteOperation::"write_content" }
when temporal {
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content", output.result: Box::FsResponseResult::"completed" } && tp(t)
      )
    )) == total && total >= 20
  )
};
```

```text
strands-shell: tee: policy denied this operation on '~/project/notes.md' [policy: write_budget]: At most 20 content writes completed in one hour.
```

- The rule counts `fs:write::response` events with result `completed`, which the box records when a
  content write finishes. A refused write does not count, and a write still in flight does not count
  yet, so a burst of writes started together can exceed the budget by the size of the burst.
- The `when` clause limits the `forbid` to content writes. A `mkdir` is `fs:write` with operation
  `create_dir`, so the budget leaves it alone. A rename is `fs:move`, and a delete is `fs:delete`;
  each needs its own rule.
- The count persists across a restart of the box and across an edit to another rule.

For an exact count of attempts, including refused ones, replace the predicate inside
`formerly within 1h ( … )` with:

```text
Box::Action::"fs:write"::request{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
```

Write a budget as a `forbid`. [A cap written as a permit](#a-cap-written-as-a-permit) shows what
happens at load when a budget is written as a `permit`.

### A rate limit on one host

At most sixty completed requests to one host in ten minutes. The sixty-first is refused until the
oldest counted request is more than ten minutes old. Write it beside a `permit` for `api.github.com`
on `http:request`, such as the `github_request` rule in
[the `[egress.<name>]` table](egress.md#example).

```text
@id("github_rate_limit")
@description("At most 60 requests to api.github.com completed in 10 minutes.")
forbid (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.github.com" }
when temporal {
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 10m (
        Box::Action::"http:request"::response{ input.host: "api.github.com" } && tp(t)
      )
    )) == total && total >= 60
  )
};
```

- The rule counts `http:request::response` events for the host, which the box records when the
  reply arrives. A refused request does not count, and one still in flight does not count yet.
- The `when` clause scopes the `forbid` to the one host, so a request to any other host is
  unaffected. The same shape on `net:connect` limits connections rather than requests.
- The agent receives a `403` whose body names the rule, as `[policy: github_rate_limit]`, and its
  description. [How a denial reads](#how-a-denial-reads) shows the form.

### Deny a program and its aliases

`rm` is refused under every spelling that resolves to the shell's `rm`: `"rm" x`, `\rm x`,
`X=rm; $X x`, and `alias safe=rm; safe x` are each judged as `rm`. Every other command the shell
implements still runs.

```text
@id("no_rm")
@description("Nothing is removed from the command line.")
forbid (principal, action == Box::Action::"shell:exec", resource)
when { context.input.program == "rm" };
```

```text
strands-shell: effect denied: policy denied this operation on 'rm' [policy: no_rm]: Nothing is removed from the command line.
```

A path spelling such as `/bin/rm` names a binary of the surrounding OS, which is a `shell:spawn`.
A rule on a spawned binary compares `program_path`, the resolved path of the binary:

```text
@id("no_host_git")
forbid (principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program_path == "/usr/bin/git" };
```

### Read files, keep listings closed

A file the agent names is readable, and every directory listing is refused. `cat
~/project/src/main.rs` succeeds. `ls ~/project/src` is refused, and so is a pattern such as
`~/project/src/*.rs`, because expanding it lists the directory.

```text
@id("no_listing")
@description("Directory listings stay closed.")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"enumerate" };
```

```text
strands-shell: ls: policy denied this operation on '~/project/src' [policy: no_listing]: Directory listings stay closed.
```

Every filesystem request carries `operation`, the exact verb, so a rule can single out one verb of
an action.
[The action vocabulary](policy/actions.md#filesystem) lists the verbs of each action.

### Commit only after the tests passed

`git commit` runs only when a `cargo test` exited `0` in the last hour. Before the first pass, after
a failure with no later pass, or once the last pass is more than an hour old, it is refused.

```text
@id("test_before_commit")
@description("Run the tests first.")
forbid (principal, action == Box::Action::"shell:spawn", resource)
when {
  context.input.program == "git" &&
  context.input has arg1 && context.input.arg1 == "commit"
}
unless temporal {
  formerly within 1h (
    Box::Action::"shell:spawn"::response{ input.program: "cargo", input.arg1: "test", output.status: 0 }
  )
};
```

```text
strands-shell: effect denied: policy denied this operation on '/usr/bin/git' [policy: test_before_commit]: Run the tests first.
```

- The rule needs a `shell:spawn` permit for `git` and one for `cargo`, and a
  [`[tool.<name>]`](shell.md#toolname) table in `box.toml` for each of the two programs. The policy
  in [your first policy](tutorials/first-policy.md) has no `shell:spawn` permit, so add these two:

  ```text
  @id("spawn_git")
  permit (principal, action == Box::Action::"shell:spawn", resource)
  when { context.input.program_path == "/usr/bin/git" && context.input.program == "git" };

  @id("spawn_cargo")
  permit (principal, action == Box::Action::"shell:spawn", resource)
  when { context.input.program_path == "~/.cargo/bin/cargo" && context.input.program == "cargo" };
  ```

- `arg1` is optional, because a command can have no arguments, so the rule guards it with
  `context.input has arg1`.
- The condition is keyed on `::response`, the event the box records when `cargo test` finishes,
  with the exit status as `output.status`. A `::request` event exists for a refused attempt too, so
  a rule keyed on it would pass after a refused `cargo test`.

### Bind a credential to one host and one method

A `POST` to the Bedrock host on port 443 goes out with the key the box holds. Every other method on
that host, and every other host, is refused.

The credential is bound in `box.toml`, and the policy permits the request. The two name the same
host. Edit the `[egress.model]` table in `box.toml`; [the `[egress.<name>]` table](egress.md) lists
its keys:

```toml
[egress.model]
destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
secret.ref = "env://AWS_BEARER_TOKEN_BEDROCK"
```

Replace the `model_connect` and `model_request` rules of [your first
policy](tutorials/first-policy.md) with these two. Replace rather than add: a second rule with the
same `@id` refuses to load, and a renamed copy leaves the broad `model_request` permit in force.

```text
@id("model_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "bedrock-runtime.us-west-2.amazonaws.com" && context.input.port == 443 };

@id("model_request")
permit (principal, action == Box::Action::"http:request", resource)
when {
  context.input.host == "bedrock-runtime.us-west-2.amazonaws.com" &&
  context.input.port == 443 &&
  context.input.method == "POST"
};
```

The agent receives a `403` response whose body is the denial, and the request never leaves the
box:

```text
http:request gate: policy denied this operation on 'bedrock-runtime.us-west-2.amazonaws.com:443/model/anthropic.claude/invoke' [default-deny]: No permit policy matched this request.
```

A connection to another host is refused before TLS:

```text
policy denied this operation on 'example.com:443' [default-deny]: No permit policy matched this request.
```

A `[egress.<name>]` table with no matching permit leaves the host unreachable. A permit with no
binding sends the request with a placeholder in place of the secret, which the provider rejects.

## Troubleshooting load failures

The box validates `policy.dw` before it starts. It refuses to start on a policy it cannot read, or
on a policy with a rule it can prove will never match (the refusals call such a rule inert).
`box run` prints the refusal on stderr and exits with status `1`. No workload starts, and a box that
has run before keeps its state.

```text
strands-box: error: policy file /Users/you/box-tutorial/my-box/policy.dw will not load: <refusal>
```

Each refusal below is the text after `will not load: `. Two numberings appear. `rule N` counts from
`1` in file order. `policy_N` is the engine's own name and counts from `0`, so `policy_0` is rule
1. A rule with no `@id` is named by its effect and position, as
`the permit rule with no @id (rule 1)`.

When the box suspects a rule is inert but cannot prove it, it prints a warning and starts:

```text
strands-box: warning: <finding>
```

### The rule does not parse

A rule ends with `;`, or continues with `when` or `unless`. This one ends with neither:

```text
permit (principal, action == Box::Action::"fs:read", resource)
```

```text
failed to parse policy source: dogwood parse: unexpected end of input; expected `;` to end the policy, or `when`/`unless` to add a condition
```

A rule reads the request's own fields and the recorded history. This one calls out to an external
function (an information provider, in the engine's words), which does not parse:

```text
permit (principal, action == Box::Action::"shell:exec", resource)
when { Scanner::classify(context.input.command) == "safe" };
```

```text
failed to parse policy source: dogwood: information providers are not enabled in this build
```

### A name the vocabulary does not have

An action name is one of [the actions](#the-actions), spelled exactly. This one misspells
`fs:read`:

```text
permit (principal, action == Box::Action::"fs:raed", resource);
```

```text
policy references unknown action: for policy `policy_0`, unrecognized action `Box::Action::"fs:raed"`; for policy `policy_0`, unable to find an applicable action given the policy scope constraints
```

A field name is one the action carries, and [the action vocabulary](policy/actions.md) lists them.
This one misspells `path`:

```text
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.paht like "~/project/*" };
```

```text
policy fails schema validation: for policy `policy_0`, attribute `input.paht` in context for Box::Action::"fs:read" not found
```

An `operation` value is one of the fixed set its action has. The value for a listing is
`enumerate`, and this one writes `list`:

```text
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"list" };
```

```text
policy fails schema validation: for policy `policy_0`: entity `Box::FsReadOperation::"list"` is of an enumerated entity type, but `"list"` is not declared as a valid eid
```

### An optional field read without a guard

An optional field (marked `?` in [the action vocabulary](policy/actions.md)) is read behind a
guard, as `context.input has arg1 && context.input.arg1 == "-rf"`. This one reads `arg1` with no
guard:

```text
forbid (principal, action == Box::Action::"shell:exec", resource)
when { context.input.program == "rm" && context.input.arg1 == "-rf" };
```

```text
policy fails schema validation: for policy `policy_0`, unable to guarantee safety of access to optional attribute `input.arg1` in context for Box::Action::"shell:exec"
```

### A temporal clause the engine cannot evaluate

A temporal predicate names one action, so a rule covers a family with one clause per action. This
one names the family `fs`:

```text
forbid (principal, action == Box::Action::"fs:write", resource)
when temporal {
  formerly within 60s ( Box::Action::"fs"::request{ input.path: _ } )
};
```

```text
policy fails schema validation: predicate `Box::Action::"fs"::request` does not name a declared event (no event kind `request` derived for action `fs`)
```

The longest window is `24h`. The refusal offers to raise `max_window`, but that schema ships inside
the box, so shorten the window:

```text
forbid (principal, action == Box::Action::"fs:write", resource)
when temporal {
  formerly within 48h ( Box::Action::"fs:write"::response{ input.path: _ } )
};
```

```text
policy fails schema validation: temporal window `48h` exceeds the maximum allowed window `24h` set by the event schema's `max_window`; shorten this window to at most `24h`, or raise `max_window` in the event schema
```

### A literal that nothing can match

A path under the operator's home is reported `~/…`, and a directory is reported without a trailing
slash. The refusal names the spelling to write:

```text
@id("project_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "/Users/dev/project/*" };
```

```text
policy compares an inert literal: rule @id("project_read") compares context.input.path with the pattern "/Users/dev/project/*", and a path under the operator home is spelled ~/…; write "~/project/*"
```

```text
@id("project_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "~/project/" };
```

```text
policy compares an inert literal: rule @id("project_read") compares context.input.path with the pattern "~/project/", and a directory is spelled without a trailing slash; write "~/project"
```

Two spellings load with a warning. The first compares `program` with a path. `program` holds the
name the first word resolved to; a binary of the surrounding OS is a `shell:spawn`, and its resolved
path is in `program_path`:

```text
@id("no_bin_rm")
forbid (principal, action == Box::Action::"shell:exec", resource)
when { context.input.program == "/bin/rm" };
```

```text
rule @id("no_bin_rm") compares context.input.program with "/bin/rm", which matches only a first word spelled that way; compare context.input.program_path to match the resolved binary
```

A pattern that names the operator's home after a wildcard may match nothing:

```text
@id("later_home")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "*/Users/dev/project/*" };
```

```text
rule @id("later_home") compares context.input.path with the pattern "*/Users/dev/project/*", which names the operator home after a wildcard; a path under the operator home is spelled ~/…, so the pattern may match nothing
```

### One `@id` on two rules

The duplicate check covers each rule that carries an `@id`:

```text
@id("project_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "~/project/*" };
@id("project_read")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "~/project/*" };
```

```text
policy gives one @id to more than one rule: @id("project_read") is on rules 1, 2; a denial and a telemetry record name a rule by its @id, so give each rule its own @id
```

### A rule that names only the reserved action

`fs:other` loads beside an action that some operation raises, as
`action in [Box::Action::"fs:read", Box::Action::"fs:other"]`:

```text
@id("other_only")
permit (principal, action == Box::Action::"fs:other", resource);
```

```text
policy names only a reserved action: rule @id("other_only") (rule 1) names only the reserved action "fs:other"; no operation raises it, so the rule cannot match; name fs:read, fs:write, fs:delete, or fs:move, alone or beside fs:other
```

### A cap written as a permit

A permit cannot narrow another permit. Write a cap as a `forbid`, as in [a budget over
time](#a-budget-over-time) and [a rate limit on one host](#a-rate-limit-on-one-host). A cap written
as a `permit` with a `when temporal` clause has one of three outcomes, decided by the other permits
for the same action.

**Refused**, when another permit for the action has no condition. The refusal names both rules, and
the box does not start:

```text
@id("writes")
permit (principal, action == Box::Action::"fs:write", resource);

@id("write_budget")
permit (principal, action == Box::Action::"fs:write", resource)
when temporal { … };
```

```text
policy writes a cap as a permit: rule @id("write_budget") (rule 2) carries a temporal clause beside rule @id("writes") (rule 1), which permits the same action with no condition; a permit cannot narrow another permit, so write the cap as a forbid
```

**Warned**, when the other permit has a `when` condition. The box starts, and prints this at
startup:

```text
strands-box: warning: rule @id("write_budget") (rule 2) carries a temporal clause beside rule @id("project_writes") (rule 1), which also permits that action; the budget is inert for every request the other rule admits, so write a cap as a forbid
```

**Loads**, with no warning, when the temporal `permit` is the only permit for its action, or when
every other permit for the action is temporal too. Alone, it admits the action whenever its clause
holds.

The check reads only whether the other permit has a condition. Whether two conditions overlap is
outside it, and [Policy limitations](security.md#policy-limitations) states what this means for a
cap.

### A rule that loads and never matches

The box refuses what it can prove inert. Two shapes load and decide nothing:

- `context.input.operation == Box::FsWriteOperation::"write_content"` on `fs:read`. Each action
  has its own set of operation values, and a value from another action's set never matches.
- `context has output && context.output.status == 200` outside `when temporal`. A decision carries
  no `output`; only a `::response` event does.

### A reused box whose history and record disagree

A box keeps its decision history in `<box_dir>/private/dogwood.redb`. The box record, a file under
`<box_dir>/private` that says whether this box has run, must agree with the history file. The run
refuses when the record says the box has run but the history is missing or empty, and when the
record says it has not run but the history holds events:

```text
strands-box: error: policy staging failed: the box record is committed, but the history /Users/dev/.box/<name>/private/dogwood.redb is absent. Wipe the box directory to start again.
```

The text varies: the record `is committed` or `is not committed`, and the history `is absent`,
`is empty`, or `holds <n> bytes`. The run also refuses when the engine cannot read the history
file, with `policy staging failed: ` and the engine's own reason, and the file is left as found.
Remove the box directory to start again, as [getting started](getting-started.md#clean-up)
describes.

## See also

- [Write a policy and read what it decided](tutorials/first-policy.md): a first policy, a denial,
  and the decision log.
- [The action vocabulary](policy/actions.md): every action, its fields, and which part of the box
  raises it.
- [Security](security.md): what `box.toml` governs, what `policy.dw` governs, and what a policy
  cannot do today.
- [Policy in the design guide](../design/policy.md): how one engine per box decides, and why.
