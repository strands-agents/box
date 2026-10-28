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

## WebSocket

A `wss://` WebSocket goes through the egress gateway like an HTTPS request. The client sends
`CONNECT` to the gateway through `HTTPS_PROXY`, and the gateway terminates TLS and reads the
handshake. Policy decides the handshake as `http:request`, then as `http:upgrade`, and both must
permit. A route adds its credential to the handshake.

For example, an agent that opens a WebSocket to an agent hosted on AgentCore Runtime, with the
handshake signed by an AWS profile:

```toml
[egress.runtime]
destinations = ["bedrock-agentcore.us-west-2.amazonaws.com"]
secret.ref   = "aws://my-profile"
```

```cedar
@id("runtime_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "bedrock-agentcore.us-west-2.amazonaws.com" && context.input.port == 443 };

@id("runtime_handshake")
permit (principal, action == Box::Action::"http:request", resource)
when {
  context.input.host == "bedrock-agentcore.us-west-2.amazonaws.com" &&
  context.input.method == "GET" &&
  context.input.path like "/runtimes/*/ws"
};

@id("runtime_websocket")
permit (principal, action == Box::Action::"http:upgrade", resource)
when {
  context.input.host == "bedrock-agentcore.us-west-2.amazonaws.com" &&
  context.input.protocol == "websocket"
};
```

The agent connects to the runtime's URL, with the runtime ARN URL-encoded in the path, and sends no
`Authorization` header:

```text
wss://bedrock-agentcore.us-west-2.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-west-2%3A111122223333%3Aruntime%2Fmy_agent-a1b2c3d4e5/ws?qualifier=DEFAULT
```

The gateway signs the handshake with SigV4 for the service `bedrock-agentcore` and the region
`us-west-2`, and the server answers `101 Switching Protocols`. An `env://` route works the same way:
the handshake carries the placeholder where the secret goes, and the gateway swaps in the secret.

### What the gateway does with a WebSocket

| Item | Behavior |
|---|---|
| Transport | `wss://` through `CONNECT`. A `ws://` handshake is refused. |
| Extensions | The gateway removes `Sec-WebSocket-Extensions` from the handshake, so every message travels uncompressed. A `101` that names an extension is refused. |
| Subprotocol | `Sec-WebSocket-Protocol` passes. The server must select a subprotocol the client offered. |
| Messages | The gateway reads every frame and reassembles each message. It sends a message on in fragments the size of the largest fragment the sender used, but at least 1 KiB, or in one frame when the sender sent one, so a server that limits its frame size still accepts a message the client split to fit. Pings, pongs, and close frames pass end to end. |
| Largest message | 16 MiB, the same limit as a response body. A larger message closes the WebSocket with code `1009`. |
| Idle timeout | 300 seconds with no bytes in either direction. Both sides then get close code `1001`. A ping counts as traffic. |
| Lifetime | Unlimited while traffic flows. |
| Connection slots | Each open WebSocket holds one of the gateway's 256 connection slots until it closes. When all 256 are held, a new connection from the box waits for a slot. |
| Credentials in a message | A route acts on the handshake only. A placeholder inside a message reaches the server as the placeholder. |
| Secrets in a server message | When the handshake carried an `env://` credential, each copy of the secret in a server message reaches the client as `[REDACTED]`. A ping or pong that carries it loses its payload, and a close frame keeps only its code. The gateway checks one message at a time, so a secret that the server splits across two messages reaches the client in two parts. |
| MCP servers | A WebSocket to the host of an http MCP server in `box.toml` is refused. |
| Policy | Policy decides the handshake. Each message after it crosses with no policy decision and adds nothing to history. |

Because policy decides only the handshake, a rule that reads history stops new WebSockets and
leaves an open one running. A byte budget or a rate limit over `http:request` counts none of the
messages, and a rule that starts to refuse after the handshake, such as one that closes egress
after a secret read, refuses each new request while the open WebSocket keeps carrying messages
until it closes. [Policy limitations](security.md#policy-limitations) says what to do about it.

The decision log records a WebSocket handshake under `http:upgrade`, with the `http:upgrade` rule
that decided it. A handshake that `http:request` refused is recorded under `http:request`. When the
gateway closes a WebSocket, for example for a frame that breaks the protocol or a message above the
limit, the decision log gets a deny under `http:request` with the rule `enforcement:egress` and the reason,
such as `websocket: client message exceeds the size limit`. A `101` that the gateway refuses also
gets one. A close by the agent or the server is not recorded,
and the decision log does not hold how long the WebSocket stayed open or how many bytes it carried.

### WebSocket errors

A handshake the gateway refuses gets an HTTP response with the header
`x-strands-box-egress: refused`. The client library reports the status:

| Status | Body | Cause |
|---|---|---|
| `403` | The policy decision, starting `http:upgrade gate:` | No `http:upgrade` permit matched, or a `forbid` on `http:upgrade` matched. |
| `403` | The policy decision, starting `http:request gate:` | `http:request` refused the handshake `GET`. |
| `403` | `WebSocket requires TLS` | The handshake was a `ws://` request. Use `wss://`. |
| `403` | `WebSocket refused for an MCP server` | The host is an http MCP server in `box.toml`. |
| `400` | `malformed WebSocket handshake` | The request names `Upgrade: websocket` and is not a valid RFC 6455 handshake, for example a version other than `13`. |
| `502` | `WebSocket upgrade response refused` | The server answered `101` with a wrong `Sec-WebSocket-Accept`, an extension, or a subprotocol the client did not offer. |

A server that answers the handshake with another status, such as `401`, returns that response to
the client unchanged.

After the `101`, the gateway closes a WebSocket with one of these codes:

| Code | Sent to | When |
|---|---|---|
| `1001` | Both sides | No bytes moved in either direction for 300 seconds. |
| `1001` | The server | The gateway closed the client with a code below. |
| `1014` | The client | The gateway closed the server with a code below. A client library such as Python `websockets` reports `1014` as an error, so the client learns that a server message was dropped. |
| `1002` | The side that broke the rule | A frame breaks RFC 6455, for example an unmasked frame from the client. |
| `1007` | The side that broke the rule | A text message or a close reason is not UTF-8. |
| `1009` | The side that sent the message | A message is larger than 16 MiB. |

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
| The policy decision, naming the rule | `net:connect`, `http:request`, or `http:upgrade` refused the request. |
| `blocked by egress control` | A request to a route's destinations lacks the placeholder, carries a different value, or can't be signed. |
| `credential not permitted on a plaintext request` | A plain `http://` request went to a route's destination. |
| `request authority rejected` | The request inside a `CONNECT` named a different host. |
| `response blocked by egress control` | The server sent a compressed response to a credentialed request. |

A 502 with no `x-strands-box-egress` header means the gateway couldn't resolve or reach the server.

## See also

- [How Box controls outbound traffic](../design/egress.md): routing, the connect and request
  decisions, and how the gateway adds a credential.
- [The `[mcp.<name>]` table](./mcp.md): a credential for an http MCP server.
- [The action vocabulary](./policy/actions.md#network): the fields of `http:request` and
  `http:upgrade`.
