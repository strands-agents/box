# The `[mcp.<name>]` table

Each MCP server the agent uses is one `[mcp.<name>]` table in `box.toml`. A stdio server is a
program that the box starts in its own sandbox. An http server
runs somewhere else, and the agent reaches it through the box's egress gateway.

Audience: an operator with a working box from [getting started](./getting-started.md) who adds an
MCP server to it. To let the agent use the server, write its rules as in [write policy for an MCP
server](./mcp-policy.md).

## Example

A stdio server and an http server:

```toml
[mcp.fetch]
type    = "stdio"
command = ["mcp-server-fetch"]

[mcp.fetch.filesystem]
read = ["~/.local/share/uv/tools/mcp-server-fetch", "~/.local/share/uv/python"]

[mcp.github]
type         = "http"
destinations = ["api.githubcopilot.com"]
secret.ref   = "env://GITHUB_MCP_TOKEN"
```

The table's name, `fetch` or `github`, is the server name. Policy reads it as
`context.input.server`.

## `[mcp.<name>]`, `type = "stdio"`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `type` | string | required | `"stdio"`. |
| `command` | string array | required | Element 0 is the program, and the rest are its arguments. The box places an alias named for the program in its `bin/`, on the agent's `PATH`, unless `alias` names it. |
| `alias` | string | the program | The name of the server's alias in the box's `bin/`. The harness runs this name to reach the server. See [Servers that share a launcher](#servers-that-share-a-launcher). |
| `workspace` | path | the agent's workspace | The server's initial working directory. |
| `env` | table | empty | Variables the server receives. The server also receives `PATH` and `HOME` from the host OS's shell that runs `box run`, unless `env` sets them, and a placeholder for each `env://` credential. |
| `filesystem` | table | empty | The paths the server's own system calls reach. See [Filesystem](#filesystem). |
| `network.contain_egress` | bool | `true` | How the server reaches the network. See [Network](#network). |

The box starts the server when the agent's harness runs its alias, and only when policy permits
`shell:spawn` for it. The box runs the `command` and arguments from `box.toml`.

The program, the alias, and the server name hold only letters, digits, `.`, `_`, and `-`. Each
server has its own name and its own alias. A server with no `alias` key uses its program as its
alias, so two servers without one can't share a program. A program or an alias cannot be `zsh`,
`bash`, `sh`, `python3`, or `python`. An alias also cannot be `strands-box-sock-alias`,
`.alias-image`, or `.alias-image.pending`, the names the box keeps in `bin/` for itself. Box
compares an alias with these names, and with every other server's alias or program, without regard
to letter case, so `NPX` and `npx` count as one name. Setting an `alias` doesn't change the rules for
the program.

### Servers that share a launcher

Many servers start through a package launcher, such as `npx`, `uvx`, or `bunx`. Give each one an
`alias`, so that each server has its own name on the agent's `PATH`:

```toml
[mcp.github]
type    = "stdio"
alias   = "github-mcp"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]

[mcp.filesystem]
type    = "stdio"
alias   = "filesystem-mcp"
command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]
```

In the harness's MCP configuration, set each server's command to its alias, `github-mcp` or
`filesystem-mcp`. The box then runs the table's `command`. Without an alias, a server whose program
is `npx` gets an alias named `npx`, so the agent's own `npx` commands reach that server instead of
`npx`.

The alias changes only the name the harness runs. Policy decides `shell:spawn` on the program,
`npx` here, and its arguments, and never on the alias. So a `shell:spawn` permit that names only
`npx` starts both servers. To permit one server, match its whole command line, as in [allow a server
that shares a launcher](./mcp-policy.md#allow-a-server-that-shares-a-launcher). Give each permit its own `@id`,
because the decision log names the rule and the program, not the server.

A box whose `box.toml` sets an `alias` writes a box record that an older `strands-box` refuses. To
go back to an older `strands-box`:

1. Remove every `alias` from `box.toml`.
2. Keep at most one server for each program. Remove the others, or start them through programs of
   their own.
3. In the harness's MCP configuration, set each server's command back to its program.
4. Run the box once with the newer `strands-box`, which writes a record the older one reads.

### Filesystem

`[mcp.<name>.filesystem]` holds six lists. Each entry is a path, and `~` is the operator's home.

| List | Entry | The server can |
|---|---|---|
| `read` | directory or file | Read it, and everything under a directory. |
| `write` | directory or file | Write it, and everything under a directory. `write` does not grant `read`. |
| `read_file` | file | Read the file. |
| `write_file` | existing file | Write the file. |
| `list` | directory | List the directory's entries. |
| `deny` | file, directory, or absent path | Reach nothing there, even under a path another list grants. |

A server with no `filesystem` table reaches its own program and the runtime minimum. On macOS, a
server that runs on an interpreter, such as Node or Python, needs `read` for that interpreter's
install directory.

The table takes no `metadata` or `exec` list, and `box run` refuses either one by name. On macOS,
a server can test whether a path exists and read its metadata across the operator's home, and it
can run any program it can read. On Linux, it can run only its own program, the interpreter its
first line names, and code in the system library directories. So on Linux, a server installed under
the home that loads native code at run time, such as a Python extension module, can't start.

A credential store, such as `~/.aws` or `~/.ssh`, is reachable only from an entry that names it
exactly. `box run` prints each credential store a server's lists name.

A grant in this table is direct access, outside every `fs:*` decision.

### Network

`[mcp.<name>.network]` holds one key, `contain_egress`.

| Value | The server's own connections |
|---|---|
| `true` | Go through the egress gateway. The box sets `HTTPS_PROXY` for the server. Policy decides each `net:connect` and `http:request`, the gateway attaches credentials, and the decision log records each one. |
| `false` | Go straight to the network. The gateway attaches no credential, and the decision log records one `egress:native` entry when the server starts. |

`false` applies to a server whose client does not read `HTTPS_PROXY`, such as a client that signs
in through single sign-on:

```toml
[mcp.sso-tools]
type    = "stdio"
command = ["sso-tools-mcp"]
env     = { PATH = "~/.local/share/sso-tools/bin:/usr/bin:/bin" }

[mcp.sso-tools.network]
contain_egress = false

[mcp.sso-tools.filesystem]
read  = ["~/.local/share/sso-tools", "~/.config/sso-tools"]
write = ["~/.config/sso-tools"]
```

`contain_egress` sets the server's own connections. Policy decides every request the agent sends
to the server in both modes.

## `[mcp.<name>]`, `type = "http"`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `type` | string | required | `"http"`. |
| `destinations` | string array | required | The server's hosts. Each is a host, `host:port`, a host with a path prefix, or a `*.` wildcard host. |
| `secret.ref` | string | none | The credential the gateway attaches to each request to the server: `env://NAME` or `aws://PROFILE`. |
| `secret.header` | string | `Authorization` | The header the credential goes in. |
| `secret.prefix` | string | `Bearer ` on `Authorization` | The text before the credential. |
| `secret.placement` | string | `header` | `header`, `basic_auth`, or `query_param`. |
| `secret.param` | string | none | The query parameter's name, for `placement = "query_param"`. |
| `secret.inject` | string | `phantom` | For `env://`: `phantom` attaches the credential to a request that carries the placeholder, and `always` attaches it to every request to the destinations. |
| `secret.phantom_prefix` | string | `strands_box_` | For `env://`: the start of the placeholder value. |

With `secret.ref = "env://NAME"`, `box run` reads `NAME` from its own environment. The agent gets
a placeholder in `NAME`, and the gateway swaps in the real value on each request to the server.

## Errors and exit codes

`box run` exits with an error before the agent starts when a table breaks a rule on this page.

| Message | Cause |
|---|---|
| A configuration error that names `[mcp.<name>]` | A key is unknown, a required key is missing, or the name, the program, or the alias breaks a rule on this page. An `http` table that sets `alias` is refused as an unknown key. |
| `no MCP server declares the alias "<alias>" in box.toml` | The harness ran a name that is no server's alias. A server's alias is its `alias`, or its program when the table sets no `alias`. |
| `MCP server "<name>" failed during <step>` | The server failed while the box read its tool list. stderr names the step. |

For a request the policy refuses, see [troubleshooting](./mcp-policy.md#troubleshooting).

## See also

- [Write policy for an MCP server](./mcp-policy.md): the rules that let the agent start, list, and
  call a server, and how to connect the harness.
- [MCP servers in the design guide](../design/mcp.md): how the box starts a server and decides
  each call.
- [Local MCP servers in the design guide](../design/containment.md#local-mcp-servers): what a
  stdio server's sandbox reaches.
- [macOS network restrictions](../design/macos-enforcement.md#network-connections-and-local-services):
  how the sandbox limits a server's connections.
