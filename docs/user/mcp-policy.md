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
| `mcp:call` | `context.input.server` | The `[mcp.<name>]` table's name. |
| | `context.input.method` | The MCP method, such as `tools/list` or `tools/call`. For the harness's reply to a stdio server's own request, the method of that request, such as `roots/list`. |
| | `context.input.tool` | The tool name, on `tools/call`. |

## Step 2. Connect the harness

Add each server to the harness's own MCP configuration.

- **A `stdio` server:** set its command to the program, the first element of `command`. The
  harness runs the alias, and the box starts the server.
- **An `http` server:** set its URL. For a server with `secret.ref = "env://NAME"`, send the
  placeholder from `NAME` in the header, or set `secret.inject = "always"` and send no header.

Use your client's configuration format for these settings. The server command or URL must match the
server declared in `box.toml`.

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
| The harness shows the server with zero tools | A rule refuses `tools/list` for the server. |
| `the MCP tool catalog is not accepted` | The agent called a tool before the server's `tools/list` succeeded. |
| `the tool is not in the accepted MCP catalog` | The server's `tools/list` does not name the tool, spelled exactly. |
| A refusal that says `[default-deny]` | No `mcp:call` permit names the server. |
| A refusal that names an `@id` | That `forbid` matched, on `mcp:call` or on the per-tool action. |

When a rule refuses `tools/list` for a server that a per-tool rule names, the box starts and that
server has no tools. Each call to its tools is refused, and stderr names the server:
`discovery denied tools/list for ["<server>"]`. Permit the server's `tools/list`, or remove its
per-tool rule.

## See also

- [The `[mcp.<name>]` table](./mcp.md): the keys for a `stdio` and an `http` server.
- [MCP servers in the design guide](../design/mcp.md): how the box starts a server and decides each
  call.
- [Policy in the design guide](../design/policy.md): how the engine decides, and what refuses to
  load.
