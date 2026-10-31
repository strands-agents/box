# Feature - WebSocket

## 1. Background

Agents need WebSocket for work that keeps one connection open in both directions. A realtime model API streams audio and text over one socket, and a browser automation protocol, such as the Chrome DevTools Protocol, keeps a socket open for a whole session. None of this works in a box today.

A WebSocket starts as an HTTP request, the handshake: a `GET` with `Upgrade: websocket`. The server answers `101 Switching Protocols`. After that, the connection stays open, and both sides send messages at any time, for as long as they want. Each message travels in one or more frames.

This doc uses these words:

- **Decision.** Before the box does something, it asks policy whether it may happen. The gateway asks `net:connect` for the host and for each address that it connects to, and `http:request` once for each HTTP request.
- **Record.** After the action, the box adds a record of what happened to the box's history. An HTTP request adds one `http:request::response` record, with the bytes that really left and the reply status.
- **Temporal rule.** A rule with a `when temporal` or `unless temporal` clause. It reads earlier records, for example "nothing leaves after the SSH key is read" or "at most 60 requests in 10 minutes".
- **Placeholder.** The workload never holds a real credential. It sends a placeholder token, and the gateway puts the real credential in its place, or signs the request with SigV4.
- **Scrub.** The gateway replaces each copy of an attached credential in a reply with `[REDACTED]`, so the real secret never reaches the workload.
- **Deny record.** The gateway's `EgressDecision` record of a refusal, which the box writes with its other egress decisions. It is not part of the policy history.

Today the egress gateway has no WebSocket support. It decides the handshake as an ordinary `http:request` `GET`. It removes `Upgrade` and `Connection`, because they are hop-by-hop fields, and it sends a plain `GET` with `Connection: close`. If the server still answers `101`, the gateway refuses the answer, so no WebSocket opens.

A prototype, #230, relayed WebSockets and decided their traffic as more `http:request` decisions. This doc reuses its relay and its measurements. It settles two questions that #230 left open: how a WebSocket shows up in policy, and the limits of an open socket.

## 2. How does a WebSocket pass through the gateway?

```text
 workload              egress gateway                                    upstream
 1. CONNECT host:443   net:connect, then dial ──────────────────────────────►
 2. TLS                ends TLS with a certificate from the box's CA
 3. GET + Upgrade      checks the handshake, decides it, swaps the
                       placeholder for the secret ───────── GET ────────────►
                       checks that the 101 answers this handshake ◄── 101 ───
    ◄──── 101 ────────
 4. frames ◄─────────► checks each frame header, decides what the      ◄────► frames
                       workload sends, scrubs server messages
```

Steps 1 to 3 are the same as for any HTTPS request, with these rules:

- **`wss://` only.** A handshake on plain HTTP gets 403 and a Deny record, before any decision. On plain HTTP, every message would cross in clear text, and the gateway reads messages only inside the TLS tunnel.
- **A valid handshake only.** It must be a `GET` on HTTP/1.1 with `Connection: upgrade`, version 13, a key that decodes to 16 bytes, and no body. Anything else that names `websocket` gets 400.
- **No WebSocket to a remote MCP server.** A handshake to a configured remote MCP server gets 403, because its frames would skip the `mcp:call` decision.
- **Credentials go on the handshake.** The handshake takes the same request path as any HTTPS request, so the placeholder swap and SigV4 signing work on it. A credential is never put into a message.
- **No compression.** The gateway removes `Sec-WebSocket-Extensions` from the handshake and refuses a `101` that names an extension. `permessage-deflate` would compress a message before the scrub can read it.
- **The `101` must answer this handshake.** hyper's client takes any `101` as an upgrade, so the gateway checks `Upgrade`, `Connection`, and `Sec-WebSocket-Accept`. If one is wrong, the workload gets 502.

Step 4 is new. Each frame starts with a small header that gives its type, its length, and, for a frame from the workload, a masking key. For example, the workload sends the text "hello" as these 11 bytes, and the server sends it back as 7 bytes:

```text
 from the workload:  81 85 37 fa 21 3d 5f 9f 4d 51 58
                     81 = last frame of the message, text
                     85 = masked, length 5
                     37 fa 21 3d = masking key, then "hello" masked with it
 from the server:    81 05 68 65 6c 6c 6f
                     81 = last frame, text;  05 = not masked, length 5;  then "hello"
```

The relay reads each header and enforces the rules of RFC 6455:

- the reserved bits are zero, and the opcode is known
- a control frame (Close, Ping, or Pong) is final and holds at most 125 bytes
- a frame from the workload is masked, and a frame from the server is not
- the frames of a message arrive in order
- a frame, and the message so far, stay under the size cap

The relay forwards a frame from the workload as it came, except the control frames of L5. When a credential applies to the host, the relay collects each server message, runs the same scrub as for an HTTP reply, and sends the message as one frame.

A fault closes the socket. The side that broke a rule gets a close code: 1002 for a broken protocol rule, 1009 for a message over the cap, 1008 for a policy refusal, or 1011 if policy cannot be asked. The other side gets 1001 after a fault of the workload, or 1014 after a fault of the server. The gateway writes one Deny record.

## 3. How does policy see a WebSocket?

### 3.1 An HTTP policy today

This policy lets an agent call a model API and read from GitHub. Every rule uses the syntax that the box loads today.

```text
@id("connect")
permit (principal, action == Box::Action::"net:connect", resource)
when {
  context.input.port == 443 &&
  (context.input.host == "api.github.com" ||
   context.input.host == "bedrock-runtime.us-west-2.amazonaws.com")
};

@id("model_request")
permit (principal, action == Box::Action::"http:request", resource)
when {
  context.input.host == "bedrock-runtime.us-west-2.amazonaws.com" &&
  context.input.method == "POST"
};

@id("github_read")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "api.github.com" && context.input.method == "GET" };

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

@id("byte_budget")
@description("At most 10 MiB sent in 10 minutes.")
forbid (principal, action == Box::Action::"http:request", resource)
when temporal {
  exists (total: Long). (
    (sum b for (b: Long), (t: Timepoint). where (
      formerly within 10m (
        Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b } && tp(t)
      )
    )) == total && total >= 10485760
  )
};

@id("none_after_key")
@description("Nothing leaves after the SSH key is read.")
forbid (principal, action == Box::Action::"http:request", resource)
when temporal {
  formerly within 24h (
    Box::Action::"fs:read"::response{ input.path: "~/.ssh/id_ed25519",
                                      input.operation: Box::FsReadOperation::"read_content" }
  )
};
```

For `GET https://api.github.com/repos/o/r`, the box makes these decisions and adds this record. The `net:connect` record is not shown:

```json
{ "event": "net:connect::request",
  "input": { "host": "api.github.com", "port": 443, "ip": "203.0.113.7" } }

{ "event": "http:request::request",
  "input": { "host": "api.github.com", "port": 443, "method": "GET",
             "path": "/repos/o/r", "body_bytes": 0, "intercepted": true } }

{ "event": "http:request::response",
  "input": { "host": "api.github.com", "port": 443, "method": "GET",
             "path": "/repos/o/r", "body_bytes": 0, "intercepted": true },
  "output": { "status": 200 } }
```

`connect` and `github_read` permit the request. `github_rate_limit` counts the records of earlier requests to the host, and `byte_budget` adds up their `body_bytes`. `none_after_key` looks for a record of the key read. Each request gets its own decision, so each rule sees the newest history.

### 3.2 The problem

A handshake sends no data, so one decision at the handshake is not enough. After the `101`, the workload could send any amount of data for as long as it likes, and no rule would see it. So the gateway must ask policy again while the socket is open. The question is which action it asks about.

### 3.3 Option A: more `http:request` (#230)

The handshake is an `http:request` with a new optional field, `upgrade: "websocket"`. While the socket is open, the gateway asks again as `http:request`, with the handshake's method and path, and with `body_bytes` set to the bytes it allows next:

```json
{ "event": "http:request::request",
  "input": { "host": "api.github.com", "port": 443, "method": "GET", "path": "/socket",
             "body_bytes": 65536, "intercepted": true, "upgrade": "websocket" } }
```

Each allowed check adds one `http:request::response` record, with the bytes that really left and `output.status` set to `101`.

With the policy of section 3.1, option A has these effects:

- **`github_read` admits a WebSocket to `api.github.com`.** The handshake and every check are `GET`s, so the agent can upload through the socket to a host that the policy calls read-only. Only a permit with `context.input.body_bytes == 0` stays read-only.
- **`byte_budget` and `none_after_key` cover WebSocket bytes with no edit.**
- **`github_rate_limit` also counts the checks of an open socket.** One record for each exchange is no longer true, and the rate limit can close a socket.

### 3.4 Option B: `websocket:open` and `websocket:send`

The handshake is a new action, `websocket:open`. Each later check is a second new action, `websocket:send`, with `body_bytes` set to the bytes it allows next. `http:request` never sees a WebSocket. Neither action exists yet. Their proposed schema, in short form, uses the field names of `http:request`:

```json
"websocket:open": { "context": { "input":  { "host": "String", "port": "Long", "path": "String",
                                             "intercepted": "Bool" },
                                 "output": { "status": "Long" } } },
"websocket:send": { "context": { "input":  { "host": "String", "port": "Long", "path": "String",
                                             "body_bytes": "Long", "intercepted": "Bool" } } }
```

A handshake has no `method` and no `body_bytes`, because it is always a `GET` with no body. Both actions keep `intercepted`, so their fields match `http:request`. It is always `true` today, because the gateway accepts only `wss://`, and a rule that reads it keeps working if `ws://` comes later. A send has a `::response` record, with the bytes that really left, but no `output`. In HTTP, `output.status` is the server's answer to one request, and on a WebSocket the server does not answer a frame. Two open points for the policy PR: an `output` on the send record, with the bytes that the server sent during the batch (for a download budget) and the close code when the batch ended with a close; and the subprotocols that the client offers.

With the policy of section 3.1, option B opens no WebSocket, because no rule permits `websocket:open`. Every rule keeps the meaning it has today. To let the agent use a realtime API, the author adds these rules:

```text
@id("connect_realtime")
permit (principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "realtime.example.com" && context.input.port == 443 };

@id("realtime_open")
permit (principal, action == Box::Action::"websocket:open", resource)
when { context.input.host == "realtime.example.com" && context.input.path == "/v1/realtime" };

@id("realtime_send")
permit (principal, action == Box::Action::"websocket:send", resource)
when { context.input.host == "realtime.example.com" };

@id("ws_byte_budget")
@description("At most 10 MiB sent over WebSockets in 10 minutes.")
forbid (principal, action == Box::Action::"websocket:send", resource)
when temporal {
  exists (total: Long). (
    (sum b for (b: Long), (t: Timepoint). where (
      formerly within 10m (
        Box::Action::"websocket:send"::response{ input.host: _, input.body_bytes: b } && tp(t)
      )
    )) == total && total >= 10485760
  )
};

@id("ws_none_after_key")
@description("Nothing leaves after the SSH key is read.")
forbid (principal, action == Box::Action::"websocket:send", resource)
when temporal {
  formerly within 24h (
    Box::Action::"fs:read"::response{ input.path: "~/.ssh/id_ed25519",
                                      input.operation: Box::FsReadOperation::"read_content" }
  )
};
```

`ws_byte_budget` and `ws_none_after_key` repeat `byte_budget` and `none_after_key` for the new action. Without them, the WebSocket has no byte budget, and it stays open after the key is read. The two budgets are separate: HTTP can send 10 MiB, and WebSocket can send another 10 MiB.

For a socket to `wss://realtime.example.com/v1/realtime` that sends "hello" and then two frames of 8 KiB, the box makes these decisions and adds these records. The `net:connect` record is not shown:

```json
{ "event": "net:connect::request",
  "input": { "host": "realtime.example.com", "port": 443, "ip": "203.0.113.9" } }

{ "event": "websocket:open::request",
  "input": { "host": "realtime.example.com", "port": 443, "path": "/v1/realtime",
             "intercepted": true } }

{ "event": "websocket:open::response",
  "input": { "host": "realtime.example.com", "port": 443, "path": "/v1/realtime",
             "intercepted": true },
  "output": { "status": 101 } }

{ "event": "websocket:send::request",
  "input": { "host": "realtime.example.com", "port": 443, "path": "/v1/realtime",
             "body_bytes": 65536, "intercepted": true } }

{ "event": "websocket:send::response",
  "input": { "host": "realtime.example.com", "port": 443, "path": "/v1/realtime",
             "body_bytes": 16411, "intercepted": true } }
```

One `websocket:send` decision covers all three frames, because together they are less than 64 KiB (section 4.1). Its record comes when the batch ends, and `body_bytes` counts frame headers: 11 + 8,200 + 8,200 = 16,411.

### 3.5 Compare the two options

| | A: `http:request` | B: `websocket:open`, `websocket:send` |
|---|---|---|
| Which existing permits admit a WebSocket | Every permit for a `GET` to the host, such as `github_read`. The checks are `GET`s too, so the permit admits uploads. | None that names its actions. The author must permit the new actions. A catch-all permit is the exception (next row). |
| A catch-all policy: `permit (principal, action, resource);` with `forbid` rules on `http:request` | The forbids still refuse the handshake and each check. | The permit admits both new actions, and no `http:request` forbid applies to them. A socket can send to a host that a forbid names. |
| A byte budget, such as `byte_budget` | Counts WebSocket bytes, with no edit | Does not count them. It needs a second rule, such as `ws_byte_budget`. |
| A temporal rule, such as `none_after_key` | Stops an open socket before its next frame, with no edit | Needs a second rule, such as `ws_none_after_key` |
| A rate limit, such as `github_rate_limit` | Also counts the checks of open sockets | Unchanged |
| A host or path rule | One rule covers both | One rule for each family. A family is the part of an action name before `:`, so `websocket:` is a new family. A rule that reads `context.input` on actions of two families refuses to load. |
| A rule that singles out WebSocket | `context.input has upgrade` | The action name |

The cost of A falls on every existing policy. It widens what existing permits admit, and it changes what existing counting rules count, with no edit and no warning.

The cost of B falls on the author who adds a WebSocket permit, and on a catch-all policy. Each guard written for `http:request` must be written again for `websocket:send`. An action group does not help either. Box's schema has no action group, and since #232 a temporal clause that names one refuses to load, because the history records each member action and never the group.

### 3.6 The proposal

We propose B. Every existing rule keeps its meaning, and a box whose permits name their actions still opens no WebSocket.

For a catch-all policy, the policy PR adds a warning at load. For example:

```text
@id("all")
permit (principal, action, resource);

@id("no_paste")
forbid (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "paste.example.com" };
```

What counts as a counterpart depends on the clauses of the `http:request` forbid:

- **No temporal clause.** A forbid on `websocket:open`, `websocket:send`, or `net:connect` for the same host counts. A forbid on `net:connect` counts, because it stops every connection to the host.
- **A temporal clause.** Only a forbid that applies to `websocket:send` counts, and its temporal clause must be one of these two:
  - The same clause. `ws_none_after_key` covers `none_after_key` this way.
  - For a sum or a count, the same clause with `websocket:send` records in place of `http:request` records. A budget or a rate limit counts the records of the action that it forbids. `ws_byte_budget` covers `byte_budget` this way.

  An event in a plain `formerly` guard must match exactly. Take `none_after_internal`, the `http:request` form of `ws_none_after_internal` (section 4.3). `ws_none_after_internal` keeps its `http:request` event, so it covers `none_after_internal`. The same guard on `websocket:send` records does not cover it. Any other forbid on `websocket:send` does not count. For example, `ws_byte_budget` does not cover `none_after_key`, because it watches a different event. The warning only compares rules. It never changes a rule, and the author writes each WebSocket rule. A forbid on `websocket:open` or `net:connect` is decided once, when the socket or the connection opens. For example, a socket opens at 0 s, and the key is read at 2 s. Policy decides the next send at 3 s, but a forbid on `websocket:open` does not apply to that decision, so the frame leaves.
- **No host.** A forbid with no host condition, such as `none_after_key` under a catch-all, needs a forbid with no host condition, and the rules above still apply to it.

Here the warning names `no_paste`, because it has no counterpart. The warning compares the clauses after the policy parses them. The policy PR tests each of the three cases. It also tests that `ws_byte_budget` does not cover `none_after_key`, that `byte_budget` with `ws_byte_budget` loads with no warning, and that `none_after_internal` with a guard on `websocket:send` records warns. This is a proposal for the reviewers to settle (D1).

## 4. How often does policy decide?

### 4.1 One send decision covers a batch

The gateway does not ask policy before each frame. One `websocket:send` decision allows a batch: the next 64 KiB that the workload sends, or one frame if that frame is larger. Before each frame from the workload, except the control frames of L5, the gateway asks again if one of these is true:

- the frame does not fit in what is left of the batch
- 30 s have passed since the decision
- the history version moved (section 4.2)

A frame of 100 KiB gets one decision for its whole size, 102,414 bytes with its header. A frame that is exactly 64 KiB of data is 65,550 bytes with its header, so it also gets its own decision.

The 64 KiB comes from #230. It is close to the first flow-control window of HTTP/2, 65,535 bytes (RFC 9113). The 30 s also comes from #230. The gateway checks the time when the next frame arrives, and no timer runs.

### 4.2 How a later rule stops an open socket

A batch can last 30 s, but `ws_none_after_key` must stop the socket as soon as the key is read. For this, the gateway uses the history version. This is a counter in the policy engine. It goes up on a policy reload, and on each decision or record of an action other than the network actions (section 4.3 adds one exception). The gateway notes the counter at each decision. Before each frame, it compares the counter with that note, and if the counter moved, it asks policy again, even if the batch has bytes and time left.

```text
 time   the workload does                     version   the gateway does
 0 s    opens wss://realtime.example.com      7         websocket:open, allowed
 0 s    sends "hello" (11 B)                  7         websocket:send, allowed: 64 KiB
 1 s    sends 8 KiB of audio                  7         same batch, no decision
 2 s    reads ~/.ssh/id_ed25519               9         (the fs:read decision and record move it)
 3 s    sends "key=..."                       9 ≠ 7     websocket:send, refused: close 1008
```

The frame at 3 s never leaves. Without the version, the batch from 0 s would still be open, and the frame would go out.

In #230, the version moves on a policy reload, and on each decision or record of an action other than `net:connect` and `http:request`. Those two are left out because they happen all the time. If each one moved the version, every open socket would ask again before almost every frame. We keep this rule, with the change in section 4.3. The WebSocket actions also do not move the version, for the same reason. If they did, each send decision would end the batch of every other open socket.

### 4.3 When the trigger is a network action

This rule reacts to an HTTP request, not to a file read:

```text
@id("ws_none_after_internal")
forbid (principal, action == Box::Action::"websocket:send", resource)
when temporal {
  formerly within 24h (
    Box::Action::"http:request"::response{ input.host: "internal.corp" }
  )
};
```

With #230's rule, an `http:request` record does not move the version. So an open socket sees the request to `internal.corp` only when its batch ends, up to 64 KiB or 30 s later.

We propose this fix. At load, the policy finds every rule that can apply to `websocket:send`, including a rule with an unscoped `action` and a rule with an `action in [...]` list that holds it. If the temporal clause of such a rule names `net:connect` or `http:request`, as `ws_none_after_internal` does, then that action also moves the version. A policy with no such rule keeps the rule of section 4.2, so `net:connect` and `http:request` never move the version.

The WebSocket actions still never move the version, even when a rule names them. So a byte budget on `websocket:send` is checked only at batch boundaries, and each open socket can pass it by one batch (L4).

### 4.4 What a decision costs

#230 measured the cost through a real box on macOS with `box-bench`, against the same relay with no checks. It measured option A's `http:request` checks. A `websocket:send` decision does the same work, but nobody has measured it yet. The policy PR measures it.

| WebSocket scenario | No checks | With checks |
|---|---|---|
| 64 B messages, one socket: round trip p50 | 0.139 ms | 0.140 ms |
| 64 KiB messages, one socket: round trip p50 | 0.698 ms | 6.877 ms |
| New sockets that send one message each | 72.9 per s | 54.1 per s |

Small messages share one decision, so they show no change. A 64 KiB message needs its own decision, so it is about 10 times slower. A decision for each message would put that cost on every message.

Messages from the server are not decided, in the same way that an HTTP reply is not (D4).

## 5. What are the limits?

| Case | What the gateway does | Number | Does a library give it? |
|---|---|---|---|
| A huge message | Reads each frame header, and closes with 1009 when the frame is over the cap, before it reads the payload. It also closes when the message so far is over the cap. | `response_limits.max_body_bytes`, 16 MiB | Yes. tungstenite and fastwebsockets check the frame size from the header. |
| Memory for one socket | Each direction holds one whole frame before it forwards it. With a scrub, it also holds the whole message. | At least 16 MiB for each direction. For 192 sockets, at least 192 × 2 × 16 MiB = 6 GiB. The relay also makes a copy of each frame, so the real peak is higher. | No. tungstenite also buffers the whole frame. |
| The destination stops reading | The write to it waits. That direction stops reading from the workload, so TCP pushes back on the workload. The other direction keeps going. | No write deadline | Partly. A library gives the backpressure, not a deadline. |
| The workload stops reading | The same, in the other direction | No write deadline | Partly, as above |
| A connection that never closes | Closes both sides with 1001, and writes a Deny record, when no byte arrives in either direction. A socket that sends is decided again at least every 30 s. A socket that only receives is never decided again. | `upstream_read_deadline`, 300 s. No lifetime cap. | No. No library owns these timers. |
| Too many sockets | 503 after `net:connect`, before the handshake decision | 3/4 of `max_connections`, so 192 of 256 | No |
| Shutdown | The gateway stops accepting. Open relays run until the process exits, then end with no Close frame and no record of their last bytes. | None | No |
| A fault | Sends a close code to each side that is between frames, writes one Deny record, and shuts both sides. The slot is freed, and the open batch records the bytes it let out. | None | Partly. A library reports the fault, and the gateway picks the codes and writes the records. |

Four points stay open. We propose to settle them in the plumbing PR:

1. **A write deadline.** The idle timer counts only reads. So a write to a peer that does not read can wait without end, while the other direction keeps moving. The final Close frame and the TLS shutdown also have no limit. We propose to close a socket when one write has waited for `upstream_read_deadline`.
2. **A drain at shutdown.** Send 1001 both ways, record the last bytes, and wait a short, fixed time.
3. **Memory.** 16 MiB is the cap for an HTTP response body. With 192 sockets, it allows at least 6 GiB of frames. A lower cap for a frame, or forwarding a large frame in parts when no scrub applies, would bound it. We have no number to propose yet.
4. **A lifetime cap.** We propose none. A socket that sends is decided again at least every 64 KiB or 30 s, and a quiet socket closes after 300 s.

## 6. Do we write the protocol code ourselves?

Only the frame codec is a choice. The rest is either already a library or code that no library has:

- **hyper**, already in the gateway, gives the upgrade on both legs and the raw stream after the `101`. It knows nothing of frames.
- **The frame codec**, the header parser and the frame writer, is about 75 lines in #230. This is the part that a library would replace.
- **The gateway's own rules** are the handshake and `101` checks, the extension removal, the policy decisions, the scrub, the control frames that need no decision, the close codes and Deny records, the timers, the slot cap, and the drain. No library has a hook for policy or for a scrub, so the gateway writes these with or without a library.

What the two candidate libraries give:

- **tungstenite and tokio-tungstenite** (0.30). The message API collects messages, and answers every Ping and every Close by itself, with no switch to turn it off. So the gateway would answer for the workload, and a Pong or a Close reason from the workload would never reach a decision. It also turns a server's close code 1014 into 1002. The frame API does not unmask, and its unmask helper is private. The client does not check an extension in the `101`, and the source has a TODO there. It checks the frame size from the header, 16 MiB by default, and its write buffer has no cap by default.
- **fastwebsockets** (0.8). Its frame API fits better. It reads one frame at a time, lets the caller turn off the automatic Pong and Close, refuses reserved bits, and checks the size from the header. But it does not check which side masks, and it checks the 125-byte limit only on a Ping. So the gateway would still write those rules.

We propose to keep our own codec on hyper's upgrade, as #230 did (D5). A library saves about 75 lines. In return, it either speaks for the workload or still needs our own checks. For scale, #197 wrote the protocol and its own I/O loop by hand, 1,273 lines before tests. #230 moved the I/O to hyper and tokio, and its whole relay is 593 lines.

## 7. How do we deliver it?

1. **This doc.** Settle D1 to D3.
The gateway asks policy through one interface, `EffectInterceptor`. Each thing that it asks about is an effect, an `EffectAttempt`. In a real box, the box's policy adapter maps each effect to an action. A frozen surface is an interface that changes only with an approved design.

2. **The plumbing PR.** It holds the relay, the frame rules, the refusals, the scrub, the limits, the open points of section 5, and the gateway tests. The gateway raises two new effects through `EffectInterceptor`, one for a handshake and one for a send, and asks again as section 4 says. The box's policy adapter does not map them yet, and it already refuses an effect it does not know. So in a real box, every handshake gets 403 and a Deny record, and the policy history gets no record. No permit admits a WebSocket, and no rule changes meaning. The gateway tests use their own `EffectInterceptor`, so they still cover the whole relay.
3. **The policy PR.** It holds the actions `websocket:open` and `websocket:send` in the schema, the adapter that maps the two effects to them, the history version of section 4.2, the load warning of section 3.6, the user docs, the policy tests, and the end-to-end tests and bench through a real box. A WebSocket works in a box only after this PR.

This order lands the plumbing with no policy question open, and the box refuses every WebSocket until the policy lands.

Both PRs change frozen surfaces. Accepting this design approves these changes:

| Frozen surface | PR | Change |
|---|---|---|
| The egress gateway's `pub use` set | Plumbing | Two new `EffectAttempt` variants, for a handshake and for a send. The enum has four variants today (`Resolve`, `Connect`, `HttpRequest`, `ResponseRelease`) and gets six. `crates/egress-gateway/AGENTS.md` and its README say "three attempt kinds", and they change to six. |
| The egress gateway's `pub use` set | Plumbing | A history version query on `EffectInterceptor`, so that an open socket asks again when the version moves |
| The policy action vocabulary | Policy | `websocket:open`, `websocket:send`, and their `::response` records |
| What `when temporal` observes | Policy | The new `::response` records, and the version that moves on the network actions that a rule for `websocket:send` names |
| Load checks | Policy | The warning for a catch-all permit with forbids on `http:request` only |

**Rejected alternative:** the plumbing PR decides only the handshake, as `http:request`. Then, until the policy PR lands, every permit for a `GET` to a host admits an upload channel to it, with no rule that sees the bytes. **Also rejected:** the plumbing PR admits sockets but refuses every send. It is safe, but no realtime API can use a socket that only receives.

## 8. Key decisions

### D1. A WebSocket has its own actions, not `http:request` (proposal)

The handshake is `websocket:open`, and the workload's traffic is `websocket:send` (section 3.4). After the upgrade, a message is not an HTTP request, and a policy should not have to read it as one. With B, every existing rule keeps its meaning, and no WebSocket opens until an author permits one. A catch-all permit is the exception, and the load warning of section 3.6 names each `http:request` forbid that has no counterpart. The price is that an author who permits WebSocket must write each budget and temporal guard again for `websocket:send`, as `ws_byte_budget` and `ws_none_after_key` do. **Rejected alternative:** option A, the checks as more `http:request`. It covers existing budgets and temporal rules with no edit, but it lets every `GET` permit, such as `github_read`, carry uploads, and it changes what every counting rule on `http:request` counts.

### D2. The handshake is one decision, `websocket:open`

The handshake is not also decided as `http:request`. `net:connect` still decides the host and each address, as for any connection. This follows the tool packs design, where a tool pack action replaces `shell:spawn` instead of a second gate. A `forbid` written on `http:request` does not stop a handshake, so write it on `net:connect` or on `websocket:open`. **Rejected alternative:** two gates, `http:request` and then `websocket:open`, in the same way that an MCP frame over HTTP is decided as `http:request` and then `mcp:call`. It keeps `http:request` rules on the handshake, but a new socket then needs one more decision before its first message.

### D3. One send decision covers a batch of bytes

The gateway does not ask policy before each frame. One `websocket:send` decision allows the next 64 KiB that the workload sends, or one frame if that frame is larger. The gateway asks again before the next frame when the batch is used up, when 30 s have passed, or when the history version moved. The version is a counter in the policy engine (section 4.2), and it goes up on these events:

- **It moves** on a policy reload, and on each decision or record of any action other than `net:connect`, `http:request`, `websocket:open`, and `websocket:send`. For example, a file read moves it, so `ws_none_after_key` stops the socket before its next frame.
- **It also moves** on `net:connect` and `http:request`, but only when a rule that can apply to `websocket:send` names them in its temporal clause, as `ws_none_after_internal` does (section 4.3). A rule can apply when its scope names `websocket:send`, when it has an unscoped `action`, or when its `action in [...]` list holds `websocket:send`.
- **It never moves** on `websocket:open` or `websocket:send`. If it did, each send decision would end the batch of every other open socket.

So small messages go at the speed of a relay with no checks. A rule whose trigger moves the version stops an open socket before its next frame. A byte budget on `websocket:send` can be passed by one batch for each socket (L4). **Rejected alternatives:** a decision for each frame, which makes 64 KiB messages about 10 times slower (section 4.4); and one decision for each socket, which lets the workload send without limit after the handshake.

### D4. Server messages are not decided

There is no `websocket:receive`. Policy decides what leaves the box, and an HTTP reply is not decided either. A server message is scrubbed when a credential applies to the host.

### D5. Our own frame codec, on hyper's upgrade

The codec is about 75 lines. tungstenite answers Pings and Closes for the workload, and fastwebsockets still needs our mask and control-frame checks. Neither has a hook for policy or for the scrub, which are most of the code. **Rejected alternative:** tokio-tungstenite's message API.

### D6. The plumbing lands first and fails closed

The plumbing PR adds no policy action and changes the meaning of no rule, but it changes the gateway's frozen interface (section 7). A real box refuses every handshake until the policy PR maps the new effects to `websocket:open` and `websocket:send`.

## 9. Limitations

### L1. The scrub reads one message at a time

It does not find a secret split across two messages, or a secret that the server encodes again, for example in base64.

### L2. No WebSocket over HTTP/2

The handshake must be HTTP/1.1. RFC 8441, WebSocket over HTTP/2, is not supported.

### L3. No compression

`permessage-deflate` is removed from every handshake, so messages travel uncompressed.

### L4. Each open socket can pass a byte budget by one batch

A budget adds up the records from before a decision, and a batch adds its record only when it ends. So when a budget is reached, each open socket can still use up its current batch, within 30 s. A batch is 64 KiB, or one frame of up to 16 MiB. With 192 sockets of 64 KiB batches, the total past the budget is about 12 MiB. If each sends one frame of 16 MiB, it is up to 3 GiB. One HTTP request can pass a budget in the same way today, by the size of its body.

### L5. A few control frames leave with no decision

These are a Close with no payload, a Close with only its 2-byte code, and a Pong to the latest Ping from the server. The gateway sends them under its own masking key. So the workload can send 2 bytes once for each socket in the close code, and it picks when it answers a Ping.

### L6. The relay does not check payloads

For example, it does not check that a text message is UTF-8. The endpoints do.

### L7. A new socket needs three decisions before its first message

These are `net:connect` (for the host and for each address), `websocket:open`, and the first `websocket:send`. In #230's bench, the handshake was a decision in both columns, so the first check was the one extra decision. It took new sockets from 72.9 to 54.1 per second, about 4.8 ms more for each socket. Nobody has measured option B yet.

### L8. A later rule reaches an open socket only at its next frame

The rule stops a socket before its next frame only when its trigger moves the history version (D3). A socket that only receives keeps receiving until it closes. Nothing leaves through it, apart from the control frames of L5.
