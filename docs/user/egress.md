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
| `secret.ref` | string | required | Where the credential comes from: `env://NAME` or `aws://PROFILE`. See [Credential sources](#credential-sources). |
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

The canonical form keeps repeated slashes, and a path prefix matches by whole segment. So
`api.example.com/v1` covers `/v1//chat`, and `api.example.com/v1/chat` doesn't cover `/v1//chat`.
[Forbid one URL path on a host](policy.md#forbid-one-url-path-on-a-host) shows rules for these
paths in policy.

## Credential sources

| `secret.ref` | Read from | When |
|---|---|---|
| `env://NAME` | The variable `NAME` in the environment of `box run` | Once, when the box starts. The agent and each tool and MCP server get a placeholder in `NAME`. |
| `aws://PROFILE` | The static access keys of `PROFILE` in the operator's AWS configuration | On each request. The gateway signs the request with SigV4. |

An `aws://` route takes no placement, `header`, `prefix`, `param`, `inject`, or
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
| `secret.ref` has a scheme other than `env` or `aws` | Use one of the two schemes. |
| `env://NAME` names a variable that is unset, blank, or reserved by the box | Set `NAME` in the host OS's shell that runs `box run`, or choose another name. |
| An `aws://` route sets a placement, `header`, `prefix`, `param`, `inject`, or `phantom_prefix` | Remove the key. A signed route takes none. |
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
| `WebSocket requires TLS` | A WebSocket handshake came on a plain `http://` request. Use `wss://`. |
| `WebSocket refused for an MCP server` | A WebSocket handshake went to the host of an http MCP server. |

A request that names `websocket` in its `Upgrade` header and is not a valid WebSocket handshake
gets an HTTP 400 with the same header and the body `malformed WebSocket handshake`. A valid
handshake is a `GET` over HTTP/1.1 with `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, one
`Sec-WebSocket-Key`, and no body. The gateway removes `Sec-WebSocket-Extensions` from each
handshake, so no message is compressed.

A WebSocket handshake past the session limit gets an HTTP 503 with the same header and the body
`WebSocket session limit reached`. When the server's `101` does not answer the handshake (a wrong
`Sec-WebSocket-Accept`, an extension, or a subprotocol that the request did not offer), the
workload gets an HTTP 502 with the same header and the body `WebSocket upgrade response refused`.

A 502 with no `x-strands-box-egress` header means the gateway couldn't resolve or reach the server.

The gateway closes a connection when the client sends nothing for 60 seconds while the gateway
reads from it. When the client stops reading a reply, the gateway closes the connection 60 to 120
seconds later. The gateway also closes a connection when the client takes longer than 60 seconds to
send the request line and headers of its first request, the `CONNECT` or a plain `http://` request.
A plain `http://` request whose body stops for 60 seconds gets a 400 with no `x-strands-box-egress`
header.

## WebSocket

A workload can open a `wss://` WebSocket through the gateway. The policy decides the handshake as
an ordinary `http:request` `GET` on its path; there is no other action. After the `101`, the gateway
reads every frame in both directions, checks it, and frames it again. Ping, pong, and close pass
from one peer to the other.

What a policy decides for a WebSocket:

- A `GET` permit now also admits a WebSocket. A permit for `GET` to a host and path admits a
  handshake there, and the session then carries any number of messages in both directions with no
  more decisions.
- A permit for `GET` only, or for `body_bytes == 0`, becomes a two-way channel. The handshake has
  no body, so it matches such a permit, and the workload can then send any number of messages to
  the server.
- A byte budget counts only the handshake. History records one `http:request` event for the
  session, with status 101 and the bytes of the handshake request. No rule counts the messages.
- A temporal rule that matches later does not close an open WebSocket. The decisions of the
  session are made at the handshake. The rule refuses the next request and the next handshake.
- To refuse a WebSocket, `forbid http:request` on its path or its host. A `forbid` on the path
  also refuses a plain `GET` there, because the policy cannot tell a handshake from a `GET`.

When a credential route matches the destination, the gateway adds the credential to the handshake,
as it does to any request. It then removes the secret from each message and control frame that the
server sends, before the workload gets it. A ping or a pong that held the secret arrives with no
payload, and a close that held it arrives with its code only. The gateway reads one message at a
time, so it does not find a secret that the server splits across two messages.

The gateway frames each message again in the largest fragment size that its sender used, and never
in fragments below 1 KiB. Each message is at most 16 MiB. The gateway closes a session with code
1001 when no byte moves in either direction for 300 seconds, and when the box stops. When a peer
breaks a rule, the gateway closes that peer with a code and the other peer as this table shows,
and records one denial:

| Fault | Code to the peer at fault | Code to the other peer |
|---|---|---|
| The workload sent a frame that breaks RFC 6455 | 1002 | 1001 |
| The workload sent text or a close reason that is not UTF-8 | 1007 | 1001 |
| The workload sent a message above 16 MiB | 1009 | 1001 |
| The server sent a frame that breaks RFC 6455 | 1002 | 1014 |
| The server sent text or a close reason that is not UTF-8 | 1007 | 1014 |
| The server sent a message above 16 MiB | 1009 | 1014 |
| The secret removal refused a server message | 1008 | 1014 |

Any other close that a peer sends passes to the other peer with its code and reason. Open
WebSockets hold at most three quarters of the gateway's connections.

## See also

- [How Box controls outbound traffic](../design/egress.md): routing, the connect and request
  decisions, and how the gateway adds a credential.
- [The `[mcp.<name>]` table](./mcp.md): a credential for an http MCP server.
