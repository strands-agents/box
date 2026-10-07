# The `[egress.<name>]` table

An `[egress.<name>]` table in `box.toml` binds a credential to a set of destinations. The box's
egress gateway adds the credential to each request to those destinations. Policy decides whether
each request goes out.

Audience: an operator with a working box from [getting started](./getting-started.md) who gives
the agent a credential for a service. For how the gateway decides and forwards each request, read
[how Box controls outbound traffic](../design/egress.md).

## Example

A bearer token for GitHub, and an AWS profile for Bedrock:

```toml
[egress.github]
destinations = ["api.github.com"]
secret.ref   = "env://GITHUB_TOKEN"

[egress.bedrock]
destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
secret.ref   = "aws://my-profile"
```

`box run` reads `GITHUB_TOKEN` from its own environment. The agent gets a placeholder in
`GITHUB_TOKEN`, and sends it as it would send the token. The gateway replaces the placeholder with
the real token on each request to `api.github.com`.

> **Every process in the box can use every route.** The agent, each tool, and each stdio MCP server
> in the box get the same placeholders, and the gateway adds the real credential to a request from
> any of them. The gateway can't tell which process sent a request, so no setting limits a route to
> one process. To keep a credential away from a tool or a server, run it in a separate box.
> [The box is the credential boundary](../design/decisions.md#the-box-is-the-credential-boundary)
> explains why.

To let the requests out, permit them in `policy.dw`:

```cedar
@id("github_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "api.github.com" && context.input.port == 443 };

@id("github_request")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.github.com" };
```

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `destinations` | string array | required | The destinations the credential goes to. See [Destinations](#destinations). |
| `secret.ref` | string | required | Where the credential comes from: `env://NAME`, `aws://PROFILE`, or `credsd://NAME`. See [Credential sources](#credential-sources). |
| `secret.placement` | string | `header` | For `env://`: where the credential goes. `header`, `basic_auth`, or `query_param`. |
| `secret.header` | string | `Authorization` | For `env://` with `placement = "header"`: the header name. |
| `secret.prefix` | string | `Bearer ` on `Authorization`, empty on any other header | For `env://` with `placement = "header"`: the text before the credential. |
| `secret.param` | string | none | For `env://` with `placement = "query_param"`: the query parameter name. Required for that placement. |
| `secret.inject` | string | `phantom` | For `env://`: `phantom` adds the credential only to a request that carries the placeholder, and refuses any other request to the destinations. `always` adds it to every request to the destinations. |
| `secret.phantom_prefix` | string | `strands_box_` | For `env://`: the start of the placeholder, such as `sk-ant-` for a client that checks the key's format. 1 to 64 letters, digits, `-`, `_`, `.`, or `~`. |

### Placement

| `placement` | The request carries | The agent sends the placeholder as |
|---|---|---|
| `header` | `<header>: <prefix><credential>` | `<header>: <prefix><placeholder>` |
| `basic_auth` | `Authorization: Basic <base64 of the credential>`. The credential is `user:password`. | The password, in `Authorization: Basic <base64 of user:placeholder>` |
| `query_param` | `<param>=<credential>` in the query string | `<param>=<placeholder>` |

## Destinations

Each entry in `destinations` is a host, with an optional port and path.

| Entry | Matches |
|---|---|
| `api.github.com` | That host, on port 443 or 80 |
| `api.github.com:8443` | That host, on port 8443 |
| `*.example.com` | Every subdomain of `example.com`, on port 443 or 80. `example.com` itself needs its own entry. |
| `api.example.com/v1` | Paths under `/v1` on that host, by whole segment |
| `api.example.com/*/upload` | Paths on that host that end in `/upload` |

A host is matched in lowercase. A path is matched case-sensitively, against the path in the
gateway's canonical form. Two routes, or two entries in one route, can't match the same
destination, and an http MCP server's host can't appear in a route.

## Credential sources

| `secret.ref` | Read from | When |
|---|---|---|
| `env://NAME` | The variable `NAME` in the environment of `box run` | Once, when the box starts. The agent and each tool and MCP server get a placeholder in `NAME`. |
| `aws://PROFILE` | The static access keys of `PROFILE` in the operator's AWS configuration | On each request. The gateway signs the request with SigV4. |
| `credsd://NAME` | The credsd environment `NAME`, over the credsd socket: `CREDSD_SOCKET`, or the platform default | On each request. `box run` checks the credsd daemon at startup. The gateway signs each request with the material it receives. |

An `aws://` or `credsd://` route takes no placement, `header`, `prefix`, `param`, `inject`, or
`phantom_prefix`. The agent gets placeholder `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
values, and the gateway signs each request to the destinations. The service and region come from
the host, which ends in `.amazonaws.com` or `.api.aws`.

The gateway adds a credential only over HTTPS. A plain `http://` request to a destination a route
names is refused.

## Errors and exit codes

`box run` exits with an error before the agent starts when a route breaks a rule on this page.

| Cause | Fix |
|---|---|
| A route has no `destinations`, or an entry is empty, `*`, or has port `0` | Name each host the credential goes to. |
| Two routes, or two entries in one route, match the same destination | Narrow one of them, for example by path or port. |
| A route names an http MCP server's host | Put the credential on the `[mcp.<name>]` table. |
| `secret.ref` has a scheme other than `env`, `aws`, or `credsd` | Use one of the three schemes. |
| `env://NAME` names a variable that is unset, blank, or reserved by the box | Set `NAME` in the host OS's shell that runs `box run`, or choose another name. |
| A `credsd://` route names no environment, or the credsd daemon does not answer | Name the environment, and start the daemon. |
| An `aws://` or `credsd://` route sets a placement, `header`, `prefix`, `param`, `inject`, or `phantom_prefix` | Remove the key. A signed route takes none. |
| `placement` is not `header`, `basic_auth`, or `query_param`, or is set with a key it does not take | Use one of the three, with only its own keys. |
| `placement = "query_param"` has no `param` | Name the query parameter. |
| `header` is not a valid header name, or `prefix` holds a control character or a brace | Use a plain header name and prefix. |
| `inject` is a value other than `phantom` or `always` | Use `phantom` or `always`. |
| `phantom_prefix` is empty, longer than 64 characters, or holds another character | Use 1 to 64 letters, digits, `-`, `_`, `.`, or `~`. |

A request the gateway refuses while the box runs gets an HTTP 403 with the header
`x-strands-box-egress: refused`. The body says why:

| Body | Cause |
|---|---|
| The policy decision, naming the rule | `net:connect` or `http:request` refused the request. |
| `blocked by egress control` | A request to a route's destinations lacks the placeholder, carries a different value, or can't be signed. |
| `credential not permitted on a plaintext request` | A plain `http://` request went to a route's destination. |
| `request authority rejected` | The request inside a `CONNECT` named a different host. |
| `response blocked by egress control` | The server sent a compressed response to a credentialed request. |

A 502 with no `x-strands-box-egress` header means the gateway couldn't resolve or reach the server.

## See also

- [How Box controls outbound traffic](../design/egress.md): routing, the connect and request
  decisions, and how the gateway adds a credential.
- [The `[mcp.<name>]` table](./mcp.md): a credential for an http MCP server.
