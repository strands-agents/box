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

<a id="websockets"></a>

## WebSockets

The workload can open a WebSocket through the gateway to a `wss://` URL. A WebSocket starts with a
handshake: a `GET` with `Upgrade: websocket`, which the server answers with `101 Switching
Protocols`. The connection then stays open, and each side sends messages on it. A message travels
in one or more frames.

The gateway handles the handshake as it handles any request:

- Policy decides it as `http:request`, after `net:connect` for the connection.
  [WebSockets](policy.md#websockets) in the policy guide states what a rule sees.
- The credential goes on the handshake, as on any request to a route's destinations: the gateway
  replaces the placeholder, or signs the handshake with SigV4.
- The gateway removes the `Sec-WebSocket-Extensions` header, and with it an offer of
  `permessage-deflate`, from the handshake. Each message travels uncompressed.
- When the server answers with another status, such as `401`, the workload gets that reply as an
  ordinary response, and no WebSocket opens.

After the `101`, the gateway forwards each frame in both directions:

- It checks the frame's header against RFC 6455, then forwards the frame as it came. The workload
  and the server check the payload, such as the UTF-8 of a text message.
- A message is at most 16 MiB, in each direction.
- When no byte moves in either direction for 5 minutes, the gateway closes the WebSocket.
- While the WebSocket is open, the gateway asks policy again before it forwards more of the
  workload's frames. Each of these decisions is a check.

When a route's destinations match the handshake, the gateway also removes the route's credential
from each message the server sends. It reads the whole message, puts `[REDACTED]` in place of the
credential, and forwards the message as one frame. A Ping or a Pong frame that holds the credential
is forwarded with an empty payload, and a Close frame that holds it keeps only its close code. The
gateway reads one message at a time, so a credential that the server splits across two messages
reaches the workload in two parts.

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

A WebSocket handshake can also get one of these refusals, with the same header:

| Status | Body | Cause |
|---|---|---|
| `403` | `WebSocket requires TLS` | A plain `http://` request names `websocket` in its `Upgrade` header, as a `ws://` URL does. The gateway refuses it before any decision. Use `wss://`. |
| `400` | `malformed WebSocket handshake` | The request names `websocket` in its `Upgrade` header, and it is not a valid RFC 6455 handshake. For example, it is not a `GET`, or its `Sec-WebSocket-Version` is not `13`. |
| `403` | `WebSocket refused for an MCP server` | The host is an http MCP server's host. |
| `503` | `WebSocket session limit reached` | The box already has 192 WebSockets open. |
| `502` | `WebSocket upgrade response refused` | The server's `101` does not answer the handshake. It lacks `Upgrade: websocket` or `Connection: upgrade`, carries the wrong `Sec-WebSocket-Accept`, or names an extension in `Sec-WebSocket-Extensions`. |

The gateway closes an open WebSocket when one of these happens, and sends a Close frame with a
code to each side:

| Cause | The workload gets | The server gets |
|---|---|---|
| Policy refused a check | `1008` | `1001` |
| The workload sent a frame whose header breaks RFC 6455 | `1002` | `1001` |
| The workload sent a message of more than 16 MiB | `1009` | `1001` |
| The server sent a frame whose header breaks RFC 6455 | `1014` | `1002` |
| The server sent a message of more than 16 MiB | `1014` | `1009` |
| No byte moved in either direction for 5 minutes | `1001` | `1001` |

The frame that caused the close goes no further. The
[decision log](getting-started.md#step-7-read-the-decision-log) holds a `deny` for each refused
handshake and for each of these closes, with the reason. A Close frame that the workload or the
server sends ends the WebSocket with no `deny`.

A 502 with no `x-strands-box-egress` header means the gateway couldn't resolve or reach the server.

## See also

- [How Box controls outbound traffic](../design/egress.md): routing, the connect and request
  decisions, and how the gateway adds a credential.
- [The `[mcp.<name>]` table](./mcp.md): a credential for an http MCP server.
