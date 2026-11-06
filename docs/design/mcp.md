# How Box runs MCP servers

Box supports two types of MCP server. A **stdio server** is a program Box starts on the operator's
machine, and an **http server** runs somewhere else. Either way, the agent reaches the server only
through Box, and policy decides each request it makes.

This page follows a server from `box run` to its first tool call. It starts with what a rule can
control, then shows how a server starts and how Box learns its tools, and ends with how Box decides
each tool call.

| | stdio server | http server |
|---|---|---|
| Declared as | `[mcp.<name>]` with `type = "stdio"` | `[mcp.<name>]` with `type = "http"` |
| Runs in | Its own sandbox, which Box starts | Somewhere else. Box checks its requests, not the server. |
| Reached through | The alias for the server's program, then the MCP broker, then the server's stdin | The egress gateway |
| Starting or connecting | `shell:spawn` | `net:connect` and `http:request` |
| Each MCP request | `mcp:call` | `mcp:call` |

Box starts each stdio server in a sandbox of its own, separate from the agent's
([local MCP servers](./containment.md#local-mcp-servers)). The MCP broker is the part of Box that
receives the agent's requests over a local socket, and the egress gateway checks and forwards every
outbound network request.

**Two permissions cover a server.** A server needs `shell:spawn`, or `net:connect` and
`http:request`, plus `mcp:call`. Together they allow every tool on the server ([an MCP tool call
takes two decisions](decisions.md#mcp-authorization-is-two-gates)). Every other MCP rule narrows
that.

**The server's name comes from `box.toml`.** A rule reads the `[mcp.<name>]` table's name, never a
value from the request ([every MCP server is one configuration
table](decisions.md#an-mcp-server-is-one-configuration-table)).

## Policy levels

Two actions decide MCP requests, and a rule can narrow either one.

| Level | Action | What the rule reads | Example rule |
|---|---|---|---|
| Server | `Box::Action::"mcp:call"` | `context.input.server` | `forbid (principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "deepwiki" };` |
| Method | `Box::Action::"mcp:call"` | `context.input.method` | `forbid (principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "deepwiki" && context.input.method == "tools/list" };` |
| Tool, prompt, or resource | `Box::Action::"mcp:call"` | `context.input.tool`, `.prompt`, or `.uri` | `forbid (principal, action == Box::Action::"mcp:call", resource) when { context.input has tool && context.input.tool == "get_me" };` |
| Tool | `github::Action::"get_me"`, one per tool | The action itself | `forbid (principal, action == github::Action::"get_me", resource);` |
| Tool arguments | `github::Action::"search_repositories"`, one per tool | `context.input.<argument>` | `forbid (principal, action == github::Action::"search_repositories", resource) when { context.input has perPage && context.input.perPage > 5 };` |
| History | Either action, in a `when temporal` clause | Earlier `::request` or `::response` events | `forbid (principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "github" && context.input.method == "tools/call" } when temporal { … };` |

**`mcp:call` is built in.** It's decided on every MCP request, so one rule can combine the server,
the method, and the item. `tool`, `prompt`, and `uri` are present only on the method that carries
them, so a rule tests them with `has` first.

**A `file`, `http`, or `https` resource URI reaches a rule in one canonical form**, so that the
respellings below can't get two decisions. The scheme and the host are lowercased, a
trailing dot on the host is dropped, percent-escapes of unreserved characters are decoded, the hex
digits of every escape that stays **in the path** are uppercased, `.` and
`..` and empty path segments are resolved, a default port is dropped, and `file:/x` and
`file://localhost/x` both become `file:///x`. A fragment is dropped, because a fragment never
reaches the server. An empty query is dropped only for a `file:` URI.

HTTP and HTTPS queries keep the `?`, even when the query is empty. Thus `https://notes/report?`
and `https://notes/report` remain distinct resource addresses. A URI under any other scheme is left
exactly as the workload wrote it. The server is then sent the canonical form, so it reads the resource the rule
decided on. Write each `uri` literal in that form: a rule compares text exactly, so a literal in
any other spelling never matches.

**The URI must spell its own shape**, because a URL parser supplies any delimiter it omits and then
opens something the box never judged. A `file:` URI needs an absolute path, which RFC 8089 spells
`local-path = path-absolute`, so `file:etc/passwd` is refused — a parser reads it as
`file:///etc/passwd`. An `http` or `https` URI needs an authority with a host, which RFC 9110
requires, so `http:/etc/passwd` and `https:///notes/page` are refused too: a parser reads the first
path segment as the host, which makes `http:/etc/passwd` into the host `etc`. `file:/x` is the one
shape the box completes itself, because RFC 8089 makes an absent authority the local one.

**The authority must be an authority**, which is the one grammar it had no check against. RFC 3986
§3.2 spells it `[userinfo@]host[:port]`, with the host an IP literal, an IPv4 address, or a
registered name. Normalization here is string surgery — lowercase, decode the unreserved escapes,
drop a default port — while a URL parser maps a host through IDNA and its own forbidden-code-point
rules. So a spelling the grammar refuses reaches the server as one host and a rule as another:
`https://no<zero-width space>tes/page` is a host a parser resolves to `notes`, and
`file://localhost<soft hyphen>/home/op/.env` opens the same file as `file:///home/op/.env`. The box
refuses the request instead. That reaches a raw non-ASCII or ignorable character, a character no host
may hold (`"`, `|`, `<`, `>`, `^`, a backquote, a brace), a `%` that starts no escape, an unbracketed
IPv6 literal, a second `@`, and a port that is not digits. A path outside RFC 3986 §3.3 is refused
the same way.

**A host written as an escape is refused too, except where the escape decodes away.** The grammar
allows a percent-escape in a host, so §3.2 alone reaches
`file://localhost<soft hyphen>/home/op/.env` and not `file://localhost%C2%AD/home/op/.env`, which
opens the same file because a parser decodes the host before it resolves it. The box decodes the
escapes of unreserved characters first, which is what makes `file://%6C%6Fcalhost/x` and
`https://%6Eotes/page` fold. Every escape still left after that decodes to a reserved character or
to a non-ASCII byte, and a host name holds neither, so the box refuses it. Write a non-ASCII host as
its `xn--` form.

**The host is not folded to one spelling, only checked.** Checking the grammar is not IDNA, so every
form the grammar allows is kept as the workload wrote it, and two spellings of one host still reach
a rule as two strings. This is the gap the check does not close, and it has three parts, each
measured in Node, Python `urlsplit`, and the Rust `url` crate:

| What stays unfolded | One origin, two strings |
|---|---|
| A non-ASCII host written as its `xn--` form against the same name written in Unicode | the Unicode spelling is refused rather than folded, so a rule must name the `xn--` form |
| An IPv4 literal in any form but dotted-quad | `https://127.1/page` and `https://2130706433/page` each reach `127.0.0.1` |
| An IPv6 literal under `http`/`https` that compresses its zeros or maps an IPv4 address | `https://[::0001]/page` reaches `[::1]`; `https://[::FFFF:127.0.0.1]/page` reaches `[::ffff:7f00:1]`. A loopback literal under `file:` does fold, because the local authority is parsed rather than compared as text |

**A port spelling is not folded, and under `http`/`https` that is a gap you must write around.** A
URL parser reads a port as a number, so it treats `:0443` as `443` and drops it as the `https`
default, and it drops a bare `:` the same way. It drops an empty
userinfo with it, though the box now refuses a userinfo outright. The box keeps whichever port the
workload wrote. So `https://notes:0443/page`, `https://notes:08080/page`, and `https://notes:/page`
each reach the same origin as a shorter spelling while reaching a rule as a different string, and a
rule that names the shorter spelling does not match. All three parsers accept every one of them.
Percent-escape hex case inside a query (`?a=%2e` against `?a=%2E`) is unfolded the same way. A
`file:` URI carrying a userinfo or an empty port is the same residual with a smaller cost: Node and
the Rust `url` crate reject such a URI outright, so reaching the file needs a server on Python's
lenient `urlsplit`.

**Under `file:` the authority is not load-bearing, and on one resolver any host reaches the local
path.** None of the three implements a remote `file:` URI. Node's `fileURLToPath` and the Rust `url`
crate's `to_file_path` open an empty host or `localhost` and refuse every other host outright,
`[::1]` included. Python's `url2pathname` reads the path and **ignores the host entirely**, so
`file://notes/home/op/.env`, `file://[::2]/home/op/.env`, and `file://127.1/home/op/.env` each open
`/home/op/.env`. The box keeps a non-local authority as the workload wrote it, so against a server
built on `urlsplit` a `forbid` naming `file:///home/op/.env` is dodged by **any** host, not only by
a respelling of a local one.

Until that is settled, a **`forbid`** can cover the host spellings with
`uri like "file://*/home/op/.env"`. It does not have to carry an encoded slash, which is refused at
the door. Read
that as a suffix match and not as "this path at any authority": `*` matches a `/` too, so the same
pattern refuses `file:///srv/backup/home/op/.env` and any other path ending in those characters. In
a `forbid` that refuses more than you named, which is the safe direction.

**Do not use the same shape in a `permit`**, where it widens instead:
`uri like "file://*/srv/public/readme"` also permits `file:///home/op/srv/public/readme`. No `like`
pattern can say "any authority, exactly this path", because nothing stops `*` at the first `/`. So a
`permit` on a `file:` path names the authority it expects — in practice the folded empty one,
`file:///srv/public/readme` — and the same file asked for through another host is then refused by the
absence of a permit.

The loopback fold above is therefore a narrowing and not a claim about which host a resolver opens:
folding `[::0001]` to the empty authority makes a path-anchored rule match more spellings, never
fewer.

**An `http` or `https` URI that carries userinfo is refused.** RFC 9110 §4.2.4 deprecates it: a
sender may not generate one, and a recipient of a URI from an untrusted source is asked to treat its
presence as an error, because it obscures the authority. The workload is that untrusted source, and
the obscuring was measurable here — the canonical form spells the userinfo before the host, so no
rule written against a host reached `https://user@notes/page`, while all three parsers read it as
host `notes` and path `/page`. An empty one was worse again, because a parser drops it and the box
did not. **A `file:` URI keeps its userinfo**, because RFC 9110 does not govern that scheme, and it
stays the residual below.

**No `uri` pattern names one origin and only that origin while those spellings are unfolded.** A
pattern that keeps the path separator, `uri like "https://notes/*"`, matches none of them, because
the canonical form puts the port and the userinfo before the `/`. A pattern that ends at the host's
last character, `uri like "https://notes*"`, matches every port spelling — and also every host that
starts with those characters, such as `notes.example.com` and `notes-staging`, which is a rule wider
than the one you wrote. A userinfo no longer needs a pattern at all, because one is refused. So
write the longest host prefix you can, check what else that prefix reaches, and use a rule on `context.input.server` or
`context.input.method` where you need a boundary that does not depend on the host's spelling.
`admission.rs::a_uri_like_pattern_cannot_name_one_origin_and_only_that_origin` pins each half.

**A query is treated by scheme, because only one scheme sends it anywhere.** Under `http` or
`https` the query is part of the request the origin server receives, so it is part of what the URI
names and is kept as written — a credential can live there. A `file:` URI has no query at all: RFC
8089 spells `file-URI = file-scheme ":" file-hier-part`, and a resolver opens the hier-part and
ignores anything after a `?`. So the box cannot say which resource such a URI asks for, and it
**refuses the request** rather than give it a canonical form the resolver would not agree with. That
keeps a rule on `file:///home/op/.env` holding for `file:///home/op/.env?x`, which otherwise reads
the same file under a string no rule matches.

**An encoded slash in a `file:` path is refused.** No POSIX or Windows file name holds a `/`, so a
segment that spells one with `%2F` names no file. A resolver that decodes the escape reads a
different path: Python's `url2pathname` and the Rust `url` crate both turn it into a separator, so
`file:///home/op%2F.env` opens `/home/op/.env`, and `file:///tmp/%2e%2e%2Fetc/passwd` traverses to
`/tmp/../etc/passwd`. Node refuses the URI outright. So the box refuses it too, rather than emit a
form a resolver reads as something else. **The `http`/`https` twin keeps the escape**, because the
origin server receives it and a segment there may legitimately spell one. An encoded backslash is
not refused with it: all three resolvers decode `%5C` to a literal `\`, which a POSIX name may
hold, so it names a file of its own and both ends agree on which.

**A space, a control character, or a backslash is refused**, anywhere in a URI under these three
schemes. RFC 3986 allows none of them, and a URL parser gives each one a meaning of its own — so a
single URI would name two things. The box reads a tab inside `file` as part of a custom scheme and
leaves the URI alone, while the server reads `file:` and opens the path. A space the box keeps on
the end of a query is one the server drops. And a backslash, which the box reads as one more
character of a name, is a path separator to the server, so `file://localhost\home\op\.env` opens
`/home/op/.env`. Each would let the two ends disagree about which resource a rule judged, so the box
refuses the request instead.

**A per-tool action is generated** for each tool a server lists. It's decided only for a
`tools/call`, after `mcp:call` allows the call. A rule on it can refuse the whole tool, or only the
calls whose arguments match a condition.

**A history rule** adds a `when temporal` clause to a rule at any level, for example to cap how
often the agent calls a server ([what a history rule sees](./policy.md#what-a-history-rule-sees)).

**Each level narrows with a `forbid`.** A server's `mcp:call` permit already allows every method
and every tool. A `permit` on a per-tool action changes no verdict, though the decision log then
names it as the deciding rule.

The `mcp:call` levels work as soon as the box starts. The per-tool levels can't:
`github::Action::"search_repositories"` and its typed `perPage` exist only once Box has learned the
server's tools, and that happens while the server starts.

## How a server starts

Box builds a server's per-tool actions while the server starts, from the server's own
`tools/list`. Startup is five steps, and step 4 is where the actions are made. The agent starts at
once, and each server becomes callable on its own schedule.

```mermaid
flowchart TD
    run["box run"] --> load["1. Policy loads"]
    load --> agent["The agent starts"]

    agent --> open["The harness opens a stdio server"]
    open --> spawn{"2. shell:spawn"}
    spawn -->|"deny"| none["The server never starts"]
    spawn -->|"allow"| leaf["The server starts in its own sandbox"]

    agent --> connect{"2. net:connect and http:request<br/>to an http server"}
    connect -->|"deny"| refused["Refused by the gateway"]

    leaf --> list{"3. tools/list<br/>mcp:call"}
    connect -->|"allow"| list
    list -->|"deny"| zero["The server has zero tools"]
    list -->|"allow"| stage["4. The tool list becomes<br/>per-tool actions"]

    stage --> done["5. Startup is complete"]
    zero --> done
```

1. **Policy loads,** in one commit, or in stages when it has a per-tool rule. See [staged policy
   commits](#staged-policy-commits).
2. **The server starts, or the agent connects to it.** See [starting the
   server](#starting-the-server).
3. **The harness lists the tools,** as an `mcp:call` request. See [starting the
   server](#starting-the-server).
4. **The tool list becomes per-tool actions.** See [per-tool actions and their
   arguments](#per-tool-actions-and-their-arguments).
5. **Startup is complete** when every server has reported. See [when startup is
   complete](#when-startup-is-complete).

### Starting the server

**A stdio server starts on demand.** It starts when the agent's harness runs the server's full
command through the alias in the box's `bin/`, not when `box run` starts. The alias is named for
the program, so servers that share a program, such as `npx`, share one alias. The alias sends its
name and its arguments to the broker, and the broker picks the one server whose `command` in
`box.toml` is those words, in that order, with the arguments all as written in `box.toml` or all
as the server receives them, with `${OTEL_EXPORTER_OTLP_*}` tokens expanded.
A harness with a fixed configuration relies on the written form, because an endpoint token expands to
a port that is new on each run. When
no `command` matches, the broker refuses the launch and starts no server, so a launch never reaches
a server it didn't name. The refusal names the servers on that program and never their commands,
because the agent cannot read `box.toml`. The broker also records the refusal as a `shell:spawn`
denial with the rule `enforcement:mcp-command`, so an operator finds a mistyped command in the run's
records. By default, the arguments only select among the servers the operator declared.

With `argument_wildcards = true` on a stdio MCP entry, a configured argument equal
to `*` skips that position's comparison. The executable, argument count, and other arguments
still match. Each entry defaults to literal argument matching. Exact commands, including literal
stars on entries without the opt-in, take priority. Otherwise, exactly one wildcard command
must match. Box refuses overlapping wildcard entries before the workload starts, checking both
the authored and expanded forms. The launcher expands the configured arguments,
then replaces only the star positions with received values. Received text is not expanded again.
Policy sees the effective command and arguments before the existing contained launch starts.
Any workload process can call the MCP alias. Each operator-declared `*` therefore gives that
caller control of one argument to a server with its own configured permissions. A permit that
checks only the program does not restrict that value. If the argument selects a package or a
destination, the caller selects the code or destination used under the server's permissions.

The broker then decides `shell:spawn` on the configured program and effective arguments, before the
process exists. If it's allowed, the server starts in its own sandbox.

**An http server is already running.** The gateway decides `net:connect` before DNS, again for
each resolved address, and `http:request` for each request. Each MCP request to the server is one
of those HTTP requests.

**The harness lists the tools.** `tools/list` is an `mcp:call` request, so a server's `mcp:call`
permit also lets the agent list its tools, and a rule can refuse it to hide a server's tools. A few
protocol methods a connection needs cross with no decision ([the protocol floor is
narrow](decisions.md#four-mcp-methods-are-never-gated)).

### Per-tool actions and their arguments

Each tool a server lists becomes its own action, such as `github::Action::"search_repositories"`.
Take the rule from the tool arguments row:

```cedar
forbid (principal, action == github::Action::"search_repositories", resource)
when { context.input has perPage && context.input.perPage > 5 };
```

To load, this rule needs an action named `github::Action::"search_repositories"` and a typed
`perPage` under that action's `context.input`. Neither is built in. Both come from the server.

**The server describes its tools.** Each tool in a `tools/list` reply carries its name and an
`inputSchema`, the JSON Schema of its arguments. Box reads the replies to the harness's own
`tools/list`, through the broker for a stdio server and through the gateway for an http server, and
sends no request of its own. It follows the harness's pages from the first, and holds the reply to
the last page until the schema stages ([Box discovers an MCP tool schema from the live server's own
list](decisions.md#mcp-tool-schemas-are-discovered-from-the-live-server)).

**Box turns the reply into a schema,** for every server, whether or not a rule names its tools:

```text
tools/list reply                                  generated schema (abridged)
-------------------------------------------       ---------------------------------------------
{ "name": "search_repositories",                  action "search_repositories" appliesTo {
  "inputSchema": {                                  context: { input: {
    "properties": {                                   query: String,
      "query":   { "type": "string" },                perPage?: Long
      "perPage": { "type": "integer" } },           } }
    "required": ["query"] } }                     };
```

The server name becomes a namespace, with each character other than a letter, a digit, or `_`
changed to `_`, so `my-server` becomes `my_server`. Each tool becomes one action, spelled as the
server spells it. Argument types are simplified so a rule compares plain values: a JSON `integer`
becomes `Long`, and an optional argument becomes an optional field, which is why the rule tests
`has perPage` first.

**Staging makes the rule enforce.** Box adds the schema to the policy engine and validates the
policy against it. From that moment, the rule above loads and enforces. A later list that changes the
tools replaces them, and a list that does not change them commits nothing. No schema file is written,
so each run learns the tools again. To read a server's action names and argument types before
writing a rule, run `strands-box policy generate-schema`, which does the same generation offline.

For the pages, the limits, and what happens when a server lists again, see [how Box discovers MCP
tools](./mcp-discovery.md).

### Staged policy commits

A rule on a per-tool action can't load until its server's schema stages. A policy with no such rule
loads in one commit, and the engine is `Ready` at once. A policy with one is committed in stages
([while discovery is pending, the box serves the schema-independent
subset](decisions.md#discovery-serves-the-schema-independent-subset)):

1. **The first commit, at load,** holds every rule that validates against the built-in schema: each
   `net:*`, `http:*`, `shell:*`, `fs:*`, and `mcp:call` rule. The per-tool rules are held back, and
   the engine is `Discovering`.
2. **One more commit for each server whose schema stages** adds that server's per-tool rules, so
   they enforce from that moment.
3. **The last commit** comes when the whole policy validates, and the engine is `Ready`. If startup
   completes first, a per-tool rule still held back belongs to a server that will never stage, so
   that server is degraded and the engine is `Ready`.

[How Box discovers MCP tools](./mcp-discovery.md) follows one server from its first `tools/list` to
its commit.

```mermaid
stateDiagram-v2
    [*] --> Ready: No per-tool rule
    [*] --> Discovering: First commit, per-tool rules held back
    Discovering --> Discovering: A schema stages, its rules committed
    Discovering --> Ready: The last schema stages
    Discovering --> Ready: Startup completes, a server degraded
    Ready --> Ready: A schema stages
```

**While `Discovering`,** every request is decided by the committed rules, so the agent, the model,
the shell, and every server's `tools/list` work from the start. A tool call can't reach a server
before its tool list is accepted, and that server's per-tool rules commit at the same moment, so a
call is never allowed before its rule enforces.

### When startup is complete

Two parts of Box report on their servers, and the box coordinates them ([the box coordinates
discovery completion](decisions.md#the-box-coordinates-discovery-completion)):

- **The broker reports for the stdio servers,** once every one of them has an accepted, refused, or
  failed tool list.
- **The gateway reports for the http servers** in the same way, and only when `box.toml` declares
  one.
- **The last report completes startup,** once, whichever part sends it.

Each server is then in one of four states:

| State | Its tools | Its per-tool rules |
|---|---|---|
| Ready | Its tool list was accepted, and its tools are callable. | Enforced from the moment its schema staged. |
| No tools | Policy refused its `tools/list`, so it has zero tools. | It has none. |
| Degraded | Policy refused its `tools/list`, so it has zero tools, and a call to a tool that one of those rules decides is refused. | A rule decides one of its tools, and it can never load. stderr names the server ([a server whose discovery a policy denies degrades alone](decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone)). |
| Failed | Box couldn't read or stage its tool list. | Never enforced. stderr names the step that failed. |

The engine is then `Ready` for the rest of the run, and every rule that can load has.

The refusal on a degraded server is per tool, not per server. Box holds back exactly the tools that
an inert rule decides, so a call to another tool of the same server is still decided by the rules
that did load — usually the coarse `mcp:call` permit. A rule that only reads a tool from history
decides no call to it, so that tool is not held.

**Which tools are held and which servers are named are different questions, and Box answers them
separately.** It holds the tools an inert rule decides. It names, per rule, the servers that rule
still waits for. One rule can therefore hold a tool on one server and name a different server, and
that is the honest pair.

A rule waits for every tool it mentions — in its head, in a condition, or in a history reference —
to be declared, so an undeclared tool names its own server. That covers a catalog that never
arrived, because a rule refused the server's `tools/list` and it declares nothing, and a catalog
that arrived without that tool, because the rule misspells the name or the server dropped it.

A rule can also stay pending while every tool it mentions is declared, when it compares an argument
the server names differently or declares with another type. Then Box names every server that rule
mentions. That is a weaker statement — one of those servers may be answering correctly — and it is
the deliberate trade, because the alternative is a rule that never loads and says nothing. Box
parks a rule only when it names at least one tool, so no inert rule is silent.

A rule's head is not the only place it can say which tool it decides. A head can be the coarse
`mcp:call` while a condition pins `context.input.server` and `context.input.tool` to one name each,
and such a rule decides exactly that one call. Box reads those pins and holds that tool, so the
narrowing an operator wrote in a condition counts for as much as one written in the head.

A pin counts when the rule cannot fire without it. Box reads a `when` condition as the list of
tests it joins with `&&`, because every one of those has to hold, and takes a pin from any test
that is exactly `context.input.server` or `context.input.tool` against a quoted name. Other tests
in the same condition make no difference, so a second guard beside the pins — `&&
context.input.method != "tools/list"`, or a choice between two methods — leaves the pins standing.
What does not count is a pin *inside* something else: under a `||`, under a negation, under an `if`,
or compared against another comparison. There the pinned pair may be the one pair the rule does not
decide, and holding it would refuse exactly the wrong call. An `unless` condition gives no pin
either, because it says what stops the rule rather than what the rule reaches.

A head that already names a tool gives no pin either. Such a head states that rule's whole reach, so
a pin beside it can only disagree with it, and reading one would hold a tool on a server the rule
can never decide a call to.

One limit remains. A rule whose head names no tool, and whose condition does not pin one server and
one tool, holds no call. stderr names the server it waits for, so the operator learns the rule is
inert, but no call is held on its behalf.

The reason differs by shape, and only one of them is a real impossibility. A condition that narrows
on something unbounded — `context.input.method`, or an argument value — or that does not narrow at
all, reaches tools whose names the rule never spells, so there is no set of tools to refuse. The
other two shapes do name a refusable set, and Box still does not read them: a condition that pins
the server alone decides every call to that server, and the box knows a call's server when it
decides it; and `["a", "b"].contains(context.input.tool)` names a fixed set of pairs. Reading either
needs a hold that is coarser than a `(server, tool)` pair, or one that expands a set, so each is a
widening of this mechanism rather than a correction to it.

## How Box decides a tool call

Each `tools/call` to a server whose tool list was accepted passes four checks, and stops at the
first that refuses it. This can start for one server while others are still starting.

### Example: limit a GitHub search

Suppose `box.toml` declares `[mcp.github]` as an http server, and `policy.dw` holds the server's
`net:connect`, `http:request`, and `mcp:call` permits, plus the `perPage` rule from [per-tool
actions and their arguments](#per-tool-actions-and-their-arguments).

```mermaid
flowchart LR
    call["Agent calls<br/>search_repositories<br/>perPage 10"] --> transport{"1. net:connect<br/>and http:request"}
    transport -->|"permit"| coarse{"2. mcp:call"}
    coarse -->|"permit"| catalog{"3. Is the tool in<br/>the accepted tool list"}
    catalog -->|"yes"| tool{"4. github::Action::<br/>search_repositories"}
    tool -->|"forbid matches"| refused["Refused<br/>names the perPage rule"]
    tool -->|"no forbid matches"| allowed["Sent to the server"]
```

1. **Connect.** The gateway checks `net:connect` and `http:request` for `api.githubcopilot.com`.
   Both permit.
2. **Server.** `mcp:call` checks the server, the method, and the tool. The server's permit allows
   it.
3. **Tool list.** The gateway checks that `search_repositories` is in GitHub's accepted tool list,
   by its exact name. It is.
4. **Arguments.** `github::Action::"search_repositories"` checks the typed arguments. `perPage` is
   10, so the `forbid` matches.
5. **Result.** The gateway refuses the call with an HTTP 403 whose body is an MCP error naming the
   rule's `@id`, and the decision log records that rule as the decider.

**If `perPage` is 5:** no `forbid` matches, the `mcp:call` permit stands, and the call goes to the
server. The decision log names the server's permit.

For a stdio server, the broker runs the same checks without the first, checks the tool list before
`mcp:call`, and refuses with an MCP error. A stdio server's own requests, such as `roots/list`, reach
the harness, and the harness's reply is decided as `mcp:call` on the method of the request it answers
([the client's reply to a server's own request is
decided](decisions.md#a-client-reply-to-a-server-request-is-decided)). For each refusal message and its cause, see
[troubleshooting](../user/mcp-policy.md#troubleshooting).

## See also

- [How Box discovers MCP tools](./mcp-discovery.md): the states a server moves through, and how its
  tool list becomes enforced rules.
- [Local MCP servers](./containment.md#local-mcp-servers): what a stdio server's sandbox
  can reach, and what `contain_egress` changes.
- [Policy](./policy.md): how the engine decides each request, and what refuses to load.
- [The `[mcp.<name>]` table](../user/mcp.md) and [write policy for an MCP
  server](../user/mcp-policy.md): configuring a server and writing its rules.
