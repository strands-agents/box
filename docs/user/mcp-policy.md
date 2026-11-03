# Write policy for an MCP server

Policy decides each request the agent makes to an MCP server. Two permits let the agent use every
tool on a server, and a `forbid` takes a tool, or one value of a tool's argument, away.

Audience: an operator who has declared a server in [the `[mcp.<name>]` table](./mcp.md) and
writes its rules in `policy.dw`.

## Before you start

- A box from [getting started](./getting-started.md).
- An `[mcp.<name>]` table for the server in its `box.toml`.

## Step 1. Allow the server

To allow a `stdio` server, permit `shell:spawn` for its program and `mcp:call` for its name:

```cedar
@id("fetch_start")
permit (principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "mcp-server-fetch" };

@id("fetch_calls")
permit (principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "fetch" };
```

To allow an `http` server, permit `net:connect` and `http:request` for its host, and `mcp:call`
for its name:

```cedar
@id("github_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "api.githubcopilot.com" && context.input.port == 443 };

@id("github_request")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.githubcopilot.com" };

@id("github_calls")
permit (principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "github" };
```

The `mcp:call` permit covers every method and every tool on the server. One permit can name
several servers:

```cedar
@id("mcp_servers")
permit (principal, action == Box::Action::"mcp:call", resource)
when { ["fetch", "github"].contains(context.input.server) };
```

| Action | Field | Value |
|---|---|---|
| `shell:spawn` | `context.input.program` | Element 0 of the server's `command`. |
| | `context.input.program_path` | The program's file, with every link resolved. `~` is the operator's home. |
| | `context.input.arg1`, `arg2`, `arg_count` | The server's arguments. |
| | `context.input.command` | The server's full `command` as written in `box.toml`: the program and its arguments, joined by spaces. Use it with `like` to match an argument past the second. An argument that holds `${OTEL_EXPORTER_OTLP_*}` is the name here, and the value the box puts in its place in `arg1` and `arg2`. |
| `mcp:call` | `context.input.server` | The `[mcp.<name>]` table's name. |
| | `context.input.method` | The MCP method, such as `tools/list` or `tools/call`. For the harness's reply to a stdio server's own request, the method of that request, such as `roots/list`. |
| | `context.input.tool` | The tool name, on `tools/call`. |

## Step 2. Connect the harness

Add each server to the harness's own MCP configuration.

- **A `stdio` server:** set its command to the server's full `command` from `box.toml`: the
  program, then every argument, in the same order. The harness runs the alias with those arguments,
  and the box starts the server whose `command` matches.
- **An `http` server:** set its URL. For a server with `secret.ref = "env://NAME"`, send the
  placeholder from `NAME` in the header, or set `secret.inject = "always"` and send no header.

Use your client's configuration format for these settings. For this `box.toml` table:

```toml
[mcp.playwright]
type    = "stdio"
command = ["npx", "-y", "@playwright/mcp"]
```

a client that takes a command and its arguments apart gets:

```json
{ "mcpServers": { "playwright": { "command": "npx", "args": ["-y", "@playwright/mcp"] } } }
```

A harness entry that sets only the program, `"command": "npx"` with no `args`, is refused for this
server with `no MCP server declares "npx"; servers on npx: playwright`. Add the
arguments to the harness entry. The same applies to every `stdio` server whose `command` has
arguments.

The server URL must match the server declared in `box.toml`.

## Step 3. Find the tool and argument names

A per-tool rule names a tool as `<server>::Action::"<tool>"`, and reads that tool's arguments as
`context.input.<argument>`. The namespace is the server name with each character other than a
letter, a digit, or `_` changed to `_`, so `my-server` becomes `my_server`.

`policy generate-schema` starts each declared server, reads its `tools/list`, and writes the
per-tool actions and their argument types:

```sh
./box-core/box policy generate-schema --config my-box/box.toml --output-dir /tmp/schema
```

`/tmp/schema/actions.cedarschema` holds one `namespace` per server, one `action` per tool, and the
arguments of each tool. A JSON `integer` or `number` is a `Long`, and an `enum` is its base type.

## Step 4. Narrow the server

Each rule below sits beside the server's `mcp:call` permit.

| Goal | Rule |
|---|---|
| Block one tool | `forbid (principal, action == github::Action::"get_me", resource);` |
| Block one argument value | `forbid (principal, action == github::Action::"search_repositories", resource) when { context.input has perPage && context.input.perPage > 5 };` |
| Allow one argument value only | `forbid (principal, action == my_server::Action::"query", resource) when { !(context.input has mode && context.input.mode == "read") };` |
| Hide a server's tools | `forbid (principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "deepwiki" && context.input.method == "tools/list" };` |

To allow only some tools, name them in the server's `mcp:call` permit:

```cedar
@id("github_calls")
permit (principal, action == Box::Action::"mcp:call", resource)
when {
  context.input.server == "github" &&
  (context.input.method != "tools/call" ||
   (context.input has tool &&
    ["search_repositories", "get_file_contents"].contains(context.input.tool)))
};
```

A per-tool rule works the same for a `stdio` server and an `http` server.

- Narrow a tool with a per-tool `forbid`, or with the tool list in the `mcp:call` permit. A
  per-tool `permit` leaves the verdict as the `mcp:call` permit set it.
- Test an optional argument with `has` before you compare it. A rule that allows one value only,
  like the third row above, also refuses a call that omits the argument.
- A tool name and an argument name match the server's `tools/list` spelling exactly.

## Step 5. Cap how often the agent calls a server

A `forbid` with a `when temporal` clause caps calls. This rule refuses a third `tools/call` to
`github` within five minutes:

```cedar
@id("cap_github_calls")
forbid (principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "github" && context.input.method == "tools/call" }
when temporal {
  exists (n: Long). (
    (count for (t: Timepoint). where (
      formerly within 300s (
        Box::Action::"mcp:call"::request{ input.server: "github", input.method: "tools/call" } && tp(t)
      )
    )) == n
    && n >= 2
  )
};
```

`::request` counts every attempt, including a refused one. `::response` counts calls that reached
the server.

## Result

Restart the box. The decision log records each decision with the rule's `@id`. A call the server
permit allows names that permit, such as `github_calls`. A call a per-tool `forbid` refuses names
that `forbid` and the per-tool action. The agent gets each refusal as an MCP error.

## Troubleshooting

| Refusal | Cause |
|---|---|
| `MCP server "<name>" may not start` | No `shell:spawn` permit for the program. |
| `no MCP server declares "<command>"` | The harness's command or arguments differ from every `command` on that program. Copy the `command` of one of the listed servers from `box.toml` into the harness, as in [step 2](#step-2-connect-the-harness). The run's records hold the same refusal, as a `shell:spawn` denial with the rule `enforcement:mcp-command`. |
| The harness shows the server with zero tools | A rule refuses `tools/list` for the server. |
| `the MCP tool catalog is not accepted` | The agent called a tool before the server's `tools/list` succeeded. |
| `the tool is not in the accepted MCP catalog` | The server's `tools/list` does not name the tool, spelled exactly. |
| A refusal that says `[default-deny]` | No `mcp:call` permit names the server. |
| A refusal that says `[default-deny]`, and the startup warning `a per-tool rule never loaded` printed | A per-tool rule never loaded, so each call it decides is refused — for a rule that names its tool in the head, or pins one server and one tool in a `when` condition ([which rules get refused](#when-a-rule-cannot-load)). The permit is there; the rule is the problem. Do not expect the refused tool's server to be one the warning names — the warning names the servers the rule waits for, and a rule can wait for one server while deciding a tool on another. |
| `a file URI that carries a query is refused` | The agent asked for a `file:` resource with a `?` in it. A `file:` URI has no query, so the box cannot say which file it names. The agent must ask for the path alone. |
| `a resource URI that holds a space, a control character, or a backslash is refused` | The agent asked for a `file:`, `http:`, or `https:` resource whose URI holds a space, a tab, another control character, or a `\`. A URI allows none of these, and a URL parser gives each its own meaning, so the box and the server would read two different resources. |
| `a resource URI whose hier-part is neither an absolute path nor an authority is refused` | The agent asked for something like `file:etc/passwd` or `https:notes/page`. A URL parser supplies the missing slashes and opens a resource no rule judged. Write `file:///etc/passwd` or `https://notes/page`. |
| `an http or https URI with no authority is refused` | The agent asked for something like `http:/etc/passwd` or `https:///notes/page`. An `http` or `https` URI needs a host, and a parser reads the first path segment as one. Write `http://host/path`. |
| `a resource URI whose authority is not RFC 3986 is refused` | The agent asked for a resource whose host is not a host: it holds a character outside the URI grammar, a non-ASCII or invisible character, a `%` that starts no escape, an IPv6 address without its brackets, a second `@`, or a port that is not digits. A URL parser maps such a host to a different one, so the box and the server would read two resources. Write the host in plain ASCII, and write a non-ASCII name as its `xn--` form. |
| A refusal that names an `@id` | That `forbid` matched, on `mcp:call` or on the per-tool action. |

### When a rule cannot load

When a per-tool rule cannot load, the box starts and that rule never takes effect. Where Box can
work out which calls that rule would have decided, it refuses each of them with `[default-deny]`,
so an unenforceable rule costs the agent that tool rather than letting the call through. Where it
cannot, those calls run on the `mcp:call` permit — [which rules Box can refuse
for](#which-rules-box-can-refuse-for) says which is which, and it is worth reading, because the
difference decides whether your rule fails closed or open. stderr names the servers the rule was
waiting for in either case: `a per-tool rule never loaded for ["<server>"]`. Three things cause it.
A rule refuses `tools/list` for the server, so the server has no tools at all — permit its
`tools/list`. Or the server's catalog does not offer the tool the rule names, because the name is
misspelled or the server dropped it — correct the tool name. Or the rule reads an argument the
server names differently, or compares it against another type — correct the argument. Removing the
per-tool rule also clears the warning.

The warning names every server the rule was waiting for, so when a rule reads one server's tool from
history it names that server too, even when that server is answering correctly.

### Which rules Box can refuse for

Box works out which calls an inert rule would have decided in two ways: from the tool the rule names
in its head, and from a `when` condition that pins `context.input.server` and `context.input.tool`
to one quoted name each. Those two rules **fail closed** — their calls get refused.

A pin still counts when other tests sit beside it, as in `context.input.server == "svc" &&
context.input.tool == "approve" && context.input.method != "tools/list"`, because each test joined
by `&&` has to hold. A pin does not count when it sits inside a `||`, a negation, or an `if`, or in
an `unless` condition, because there the rule may reach some other tool instead.

Every other rule **fails open**: its calls run on the `mcp:call` permit while the rule enforces
nothing. These are the shapes, and each is worth checking your own policy against:

| An inert rule on `mcp:call` whose condition … | Why Box holds nothing |
|---|---|
| pins the server alone | Every tool on that server is in reach, and the rule names none of them. |
| picks tools with `["approve", "reject"].contains(context.input.tool)` | A set membership is not an equality, so neither name is a pin. |
| matches with `context.input.tool like "appro*"` | A pattern is not an equality. |
| offers a choice, as in `context.input.server == "svc" && (context.input.tool == "a" \|\| context.input.tool == "b")` | The server pin counts, because it still has to hold; the two tool names do not, because only one of them need hold. One pin alone names no tool. |
| narrows on `context.input.method`, or on an argument | Those reach tools the rule never names. |
| does not narrow at all | Every tool call is in reach. |

Read the startup warning as the signal that a rule went inert, then check it against the table
above to learn whether its calls are being refused or allowed. To get the refusal, name the tool in
the rule's head, or pin the server and the tool to one name each in a `when` condition — writing one
rule per tool where you need several.

## See also

- [The `[mcp.<name>]` table](./mcp.md): the keys for a `stdio` and an `http` server.
- [MCP servers in the design guide](../design/mcp.md): how the box starts a server and decides each
  call.
- [Policy in the design guide](../design/policy.md): how the engine decides, and what refuses to
  load.
