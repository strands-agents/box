# Strands Box Policy

`strands-box-policy` opens an in-process policy authority for the trusted
enforcement points of a box. It validates policy at startup, returns fail-closed
decisions for typed requests, and keeps a history of completed effects so a rule can
decide on what already happened.

The package is `strands-box-policy` and the library is `policy`. The product crate is
`strands-box`.

Audience: Rust developers integrating policy into a trusted box composition or an
enforcement point.

> **Status.** The engine uses the published `dogwood-language` and `dogwood-local-engine` crates. The
> authority stores history in a caller-supplied redb file and recovers it on restart.
> Dogwood evaluates each `when temporal { … }` clause against recovered and newly
> recorded history.

## Public Interface

The façade exports **35 names with `--all-features`, and 31 by default.** The adapter features add
the four names in the last row.

`PrincipalKind` left on 2026-08-18. The three enforcement-point principals collapsed into one
`Agent`, so a kind enum named a distinction that no longer exists.

| Item | Role |
|---|---|
| `Policy` | One authored policy document: caller-trusted text with a diagnostic origin. |
| `PolicyEngine` | One loaded, strict-validated authority. It carries the lifecycle. |
| `Principal` | Integration metadata for the fixed `Box::Agent::"self"` identity. |
| `GovernedBox` | Integration metadata for the box that owns the authority. |
| `Request`, `FsAccess`, `FsOperation` | Typed authorization request. |
| `ApprovedPath`, `PathResolver`, `PathRefusal` | The resolved path a `Request::Fs` demands, the only public minter of one, and why a mint fails. |
| `Decision`, `DenyReason`, `RuleId` | Authorization verdict and determining rule. |
| `Outcome`, `Delivery`, `FsResult` | One completed effect, submitted as history. |
| `EffectivePolicy`, `ENGINE_ID` | Active engine and source identity. |
| `PolicyError` | Startup and history-recording errors. |
| `SchemaStage`, `PolicyDiagnostic`, `PolicyStagingError` | Runtime MCP schema staging results and errors. |
| `generate_mcp_schema`, `validate_mcp_schema_composition`, `compose_action_schema`, `McpSchemaError` | MCP schema generation, validation, composition, and errors. |
| `event_schema_source` | The embedded Dogwood event schema text. |
| `DecisionObserver` | A synchronous sink for each policy verdict. |
| `EgressPolicyInterceptor` (`egress-adapter`), `ShellPolicyInterceptor` (`shell-adapter`), `ScriptPolicyInterceptor` + `ScriptPermit` (`script-adapter`) | One adapter per enforcement point, each behind its own feature. |

The lifecycle is:

```text
PolicyEngine::open(Vec<Policy>, &Path) -> Result<PolicyEngine, PolicyError>
PolicyEngine::decide(&GovernedBox, &Principal, &Request<'_>) -> Decision
PolicyEngine::record(&GovernedBox, &Principal, &Outcome<'_>) -> Result<(), PolicyError>
PolicyEngine::effective() -> &EffectivePolicy
```

`decide` and `record` each take the box that owns the authority. Construct one with
`GovernedBox::assigned("<box name>")` from the endpoint you own. The value remains
integration metadata and does not change the policy resource.

`decide` observes the request into temporal history before it answers. Two identical
calls can return different verdicts. A denied request still advances history.
`open` validates the sources, recovers the store, and installs the current source set.
`validate` checks source text in memory. `effective` returns the engine and source identity.

One call sits off the lifecycle:

```text
PolicyEngine::validate(&[Policy]) -> Result<(), PolicyError>
```

`validate` answers "would `open` accept this text", and returns no authority. Use it
when you must refuse bad policy text *before* writing it, and you must not open a
second `PolicyEngine` to find out. `open` and `validate` share one private composition,
so a validator that accepts text the authority would refuse is not expressible. Its
caller is `strands-box`'s configuration step, which the `run` and `init` verbs both
reach. A policy the engine cannot load is refused there, before the box stores it.

## Minimal Example

```rust
use std::path::{Path, PathBuf};

use policy::{
    Decision, GovernedBox, Policy, PolicyEngine, PolicyError, Principal, Request,
};

fn open_policy(database_path: &Path) -> Result<PolicyEngine, PolicyError> {
    let policy = PolicyEngine::open(vec![Policy {
        origin: PathBuf::from("example.cedar"),
        text: r#"
            permit(
                principal == Box::Agent::"self",
                action == Box::Action::"net:connect",
                resource
            )
            when {
                context.input.host == "api.github.com" &&
                context.input.port == 443
            };
        "#
        .to_owned(),
    }], database_path)?;

    Ok(policy)
}

fn decide(policy: &PolicyEngine) {
    let decision = policy.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Connect {
            host: "api.github.com",
            ip: None,
            port: 443,
        },
    );
    assert!(matches!(decision, Decision::Allow { .. }));
}
```

## Policy Sources

Each `Policy` contains owned policy text and a path used in diagnostics.
The language is a Cedar superset: Cedar `permit`/`forbid` text loads unchanged,
and `when temporal { … }` is available on top of it.

`PolicyEngine::open` composes and validates the supplied sources before it opens history.
It opens or creates the supplied redb file and recovers its monitor state. It then
durably installs the current source set. Unchanged temporal formulas retain their state.
New or changed formulas start with empty state.

Place the file in a daemon-only directory. The path's parent directory must exist.

No compiled-in policy loads before the sources. The Box runtime protects the configuration
and policy files that it loads by filesystem identity, beneath policy.

`PolicyEngine::validate` accepts the same sources and reports the same errors, and
produces no authority.

An empty source vector creates a deny-by-default authority.

## Principals

| Constructor | Principal |
|---|---|
| `Principal::agent()` | `Box::Agent::"self"` |

**There is one principal.** It was three — `AgentShell`, `AgentScript`, and `AgentGateway` —
and the action already said which boundary raised a request, so the second name decided nothing
a rule could not read off the action.

`with_id` stores a trusted integration identifier. Policy evaluation still uses
`Box::Agent::"self"`.

Every action accepts `Box::Agent`, so the principal narrows nothing and a rule that leaves it
unconstrained is the same rule as one naming it. The **action** is what scopes a rule. The egress
gateway raises `Box::Action::"net:connect"` and `Box::Action::"http:request"`. The shell raises
`Box::Action::"shell:exec"` and `Box::Action::"shell:spawn"`. An MCP stream raises
`Box::Action::"mcp:call"`, and a generated tool refinement raises
`<normalized-server>::Action::"<tool>"`. Either interpreter raises `fs:*`.

For example, server `issues-mcp` and tool `SearchIssues` use
`issues_mcp::Action::"SearchIssues"`. Run `strands-box policy generate-schema` and copy the
exact UID from `.strands-box/actions.cedarschema`.

## Fixed Resource

The schema declares one resource entity, `Box::Resource`. Every request and temporal event
uses `Box::Resource::"unused"`.

```text
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read",
       resource == Box::Resource::"unused");
```

A bare `resource` scope also matches. Rules discriminate with the action and
`context.input`.

Each `run` process opens one `PolicyEngine` for one box. This ownership gives each box
its own policy text and temporal history. The authored policy cannot discriminate on a
box name.

The removed `Filesystem`, `Network`, `Process`, and `Box` entity types fail strict
validation. Rewrite those scopes as an action or `context.input` guard. For example,
every `fs:*` action carries `operation`, while network and shell inputs do not.

## Requests And Decisions

`Request` borrows its inputs:

| Variant | Action | Fields |
|---|---|---|
| `Fs` | one `Box::Action` selected by `operation` | `path: &ApprovedPath`, `operation: FsOperation` |
| `Connect` | `Box::Action::"net:connect"` | `host: &str`, `ip: Option<IpAddr>`, `port: u16` |
| `Http` | `Box::Action::"http:request"` | `host: &str`, `port: u16`, `method: &str`, `path: &str`, `body_bytes: usize`, `intercepted: bool` |
| `ShellExec` | `Box::Action::"shell:exec"` | `command`, `program`, `args`, `cwd` |
| `ShellSpawn` | `Box::Action::"shell:spawn"` | the same, plus `program_path` |
| `McpCall` | `Box::Action::"mcp:call"`, or `<normalized-server>::Action::"<tool>"` when `tool` and `arguments` are present | `server`, `method`, `tool`, `prompt`, `uri`, `arguments` |

There is no response-leg variant. `ResponseRelease` was one. The response leg raises no
decision and records no event, so a rule cannot read a response's attributes.

`PolicyEngine::decide` returns `Decision::Allow` for a clean explicit permit. Explicit
forbids, unmatched requests, representation faults, and evaluation faults return
`Decision::Deny`. Treat every verdict other than `Allow` as denial.

| Deny reason | Meaning |
|---|---|
| `Forbidden` | An explicit `forbid` matched. |
| `NoMatch` | No `permit` matched. |
| `InternalFault` | Request construction or policy evaluation failed. |

`RuleId::as_str` returns the determining rule identifier. Default denials use
`RuleId::DEFAULT_DENY`.

`context.input.ip` is the pinned address after resolution, as a string, and it is absent before
resolution. An IPv6 address that carries an IPv4 address reads as that IPv4 address, and other IPv6
uses its compressed lowercase form. Match it with `==` or `like`, for example
`context.input.ip like "169.254.*"`, and guard it with `context.input has ip`. Permit on `host` and
`port`, and use `ip` in a `forbid`: an `ip`-only permit never passes the decision before resolution.

### Shell actions

`shell:exec` and `shell:spawn` are two actions. They are mutually exclusive: one resolved
command line raises exactly one of them. A command line is judged **once**, after the Shell
parses it, expands it, and resolves its first word to a program.

There is no `shell` group. A rule names each action directly, so a clause covering both
commands names both — `permit … shell:exec` and `permit … shell:spawn` — and a temporal
predicate names one action.

`program` is what the first word resolved to, never how it was spelled. When nothing
resolves, it carries the first word as written. Write a rule on `program` rather than on
`command`: an alias makes the two differ, and the `alias` builtin raises no decision of its
own. A `program` literal that contains a path separator matches only a first word spelled that
way, so the load warns; compare `program_path` to match the resolved binary.

`args` reaches a rule as three attributes rather than as a collection, because Cedar's only
collection is an unordered `Set` with no index operator:

| Attribute | Presence | Meaning |
|---|---|---|
| `arg1` | optional | the first argument after the program |
| `arg2` | optional | the second argument after the program |
| `arg_count` | always | how many arguments follow the program |

**A rule reading `arg1` or `arg2` must guard it with `has`.** An unguarded read is a load
error, not a rule that quietly matches nothing:

```text
forbid (principal, action == Box::Action::"shell:exec", resource)
when { context.input.program == "rm" &&
       context.input has arg1 && context.input.arg1 == "-rf" };
```

`arg_count` is what a rule uses to refuse a line longer than the two positions this schema
exposes, rather than missing it silently.

`cwd` is always present, because most arguments are relative. `shell:spawn` adds a required
`program_path`, the resolved absolute path of the host binary. Neither shell action declares
`path`, so `context.input has path` is false for both.

**`shell:spawn` is raised when a host binary runs through the passthrough path.** The Shell
adapter maps the attempt, and `spawn_host_program` acts on the permit. The two are separate
actions rather than one action with a flag for that reason: an unconditional `permit` on
`shell:exec` is the ordinary way to grant commands, and a flag would have made every such policy
also permit host binaries.

### Filesystem actions

The filesystem has four actions, named for what an operator reasons about, plus a
reserved `fs:other` that no kernel verb maps to today. A rule names one directly, and the
kernel's exact verb rides `context.input.operation` for narrowing within an action.

```text
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
```

| Action | Raised by |
|---|---|
| `fs:read` | reading content, reading metadata, listing a directory, reading a symlink target, changing the working directory, testing a path for execution |
| `fs:write` | opening a file to write, creating a directory, replacing permission bits, creating a symlink |
| `fs:delete` | removing a file or an empty directory |
| `fs:move` | renaming or moving a path, authorized on both paths |
| `fs:other` | no kernel verb today; reserved for a verb upstream has not yet added |

There are no group actions. A removed name — a fine per-verb name like
`fs:read_content`, or an old group like `fs:exec` — fails to load with
`PolicyError::UnknownAction` rather than matching nothing.

`FsOperation` selects the action; `FsOperation::access` reports the customer verb.
Every request also carries the kernel operation on `context.input.operation`, typed by
a per-action enum, so a rule scoped to a coarse action narrows within it:

```text
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"enumerate" };
```

The enums are `Box::FsReadOperation` (`read_content`, `read_metadata`, `enumerate`,
`read_link`, `change_dir`, `exec`), `Box::FsWriteOperation` (`write_content`, `create_dir`,
`set_permissions`, `symlink`), `Box::FsDeleteOperation` (`remove_file`, `remove_dir`),
`Box::FsMoveOperation` (`rename`), and `Box::FsOtherOperation` (`other`). A verb the enum does
not declare — a misspelling, or a verb from another action spelled with this action's
enum — is a load error, not a rule that quietly never matches. One caveat: comparing
against another enum's value (`Box::FsWriteOperation::"write_content"` in an `fs:read`
rule) loads and is statically false, because Cedar permits `==` across entity types.

A temporal predicate names the coarse action and may bind `operation` to keep the fine
distinction: `Box::Action::"fs:read"::response{ input.path: …, input.operation: Box::FsReadOperation::"read_content" }`.

How an effect ended is carried by the event kind: an effect that happened or may
have happened records a `::response`, and one that definitely did not happen records
a `::error`. Every filesystem response also carries `output.result`, one of three
`Box::FsResponseResult` values: `"completed"`, `"descriptor_issued"` (an open issued a
descriptor whose bytes move later), or `"indeterminate"` (a permit was dropped
without reporting). A rule that counts certain completions matches
`output.result: Box::FsResponseResult::"completed"`, which excludes the other two.

`fs:other` is its own action, so a permit for `fs:read`, `fs:write`, `fs:delete`, or
`fs:move` does not reach it: an operation added upstream must be granted by name rather
than inheriting a permit meant for another verb.

### Minting the path a `Request::Fs` demands

`Request::Fs` takes `path: &ApprovedPath`, not a `&Path`. `ApprovedPath` has no public
constructor, so a raw spelling fails to compile. `PathResolver` is the only public
minter:

```rust
use std::path::{Path, PathBuf};

use policy::{ApprovedPath, PathRefusal, PathResolver};

fn approve(target: &Path) -> Result<ApprovedPath, PathRefusal> {
    let resolver = PathResolver::over([PathBuf::from("/workspace")])?;
    resolver.approve_host(target)
}
```

`PathResolver::over` declares the reachable set — the box home first, then each bind
destination. Every root must be absolute.

| Method | Namespace | Symlinks |
|---|---|---|
| `approve_host` | the host filesystem | followed, and a non-canonical spelling is refused |
| `approve_virtual` | an interpreter's own namespace, no I/O | not followed; `.` and `..` close lexically |

`PathRefusal` says why a mint failed. `approve_virtual` exists because a script path
lives in the interpreter's namespace, and `std::fs::canonicalize` answers about the
host's — the wrong one.

The path is the **resolved** absolute path, after the kernel applied the working
directory and normalization. For the **Shell** a symlink therefore cannot redirect a
denied read: policy sees the target.

For the **Script** boundary (Monty) it can. That adapter's `resolve()` is lexical — it
closes `.` and `..` and requires an absolute path, but performs no I/O and so does not
follow symlinks. With `/workspace/link -> /secret`, a rule permitting `/workspace/*`
permits reading `/secret` through the link. Containment — a subtree with no links leading
out — is the only control covering this today. See the crate's `AGENTS.md` for why
`std::fs::canonicalize` is the wrong fix.

## History And Temporal Rules

A `when temporal { … }` rule reads the history of completed effects. Submit each
one with `PolicyEngine::record` after the effect happens:

```rust
use policy::{Delivery, GovernedBox, Outcome, PolicyEngine, PolicyError, Principal};

fn submit(policy: &PolicyEngine) -> Result<(), PolicyError> {
    policy.record(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Outcome::Http {
            host: "api.github.com",
            port: 443,
            method: "POST",
            path: "/v1/items",
            delivery: Delivery::Completed { bytes: 512 },
            status: Some(200),
        },
    )
}
```

| Variant | Records |
|---|---|
| `Connect` | `host`, `port`, `address`, `connected` |
| `Http` | `host`, `port`, `method`, `path`, `delivery`, `status` |
| `ShellRun` | `command`, `program`, `args`, `cwd`, `status` |
| `ShellSpawn` | the same, plus `program_path` |
| `Fs` | `path`, `operation`, `result` |

One HTTP exchange records exactly one `http:request::response`, at reply time. Its
`input.body_bytes` is the delivered request, and its `output.status` is the reply. A request
that got no reply records the same event with no `output`, so a rule on `output.status`
does not match it. A rule reads `status` in a temporal predicate over `::response`; a decision
carries no `output`.

A response names the same action whose request was authorized, so a rule joins a
`shell:exec::request` to its own response and to no other.

`FsResult` reports how a filesystem operation ended: `Completed`,
`DescriptorIssued`, `Failed`, or `Indeterminate`. `DescriptorIssued` is distinct on
purpose — an open issues a descriptor, and the transfer it enables happens outside the
admitted call, so a rule counting completed writes must exclude it.

`Delivery` reports how much of a message left: `Completed { bytes }`,
`Partial { accepted_bytes }`, `Failed`, or `Indeterminate { accepted_bytes }`.
`accepted_bytes` counts bytes the operating system took, so a partial or
indeterminate write reports its prefix.

Call `record` before the next `decide` on that authority. Timestamps are assigned
while the durable engine serializes each append. The stored trace follows append order.

`record` returns an error when history cannot be written. A caller that discards
it leaves later verdicts computed on incomplete state.

`decide` appends its request before evaluation. A failed append returns an internal-fault
denial. `open` refuses a store when recovery cannot reconstruct complete monitor state.

**Key a precondition on `::response`, never `::request`.** The engine observes an
event into history before it decides, and the event carries no verdict, so a
`::request` predicate matches an attempt that was **refused**. A rule of the form "you
may write only after reading the approval" written against `::request` is satisfied by
asking for the approval and being denied. A `::response` exists only for an effect
that happened, because only `PolicyEngine::record` emits one.

Rules written against history:

- Each request event carries `body_bytes` as offered; each response event
  carries it as delivered. Pin the event kind (`::request` or `::response`) in
  a predicate so a sum reads one quantity.
- A window measures elapsed seconds. A rule over `net:connect` counts one event
  per pinned address; a rule over `http:request` counts one per exchange.
- A `Connect` outcome records `host` and `port`. `connected`, the `status` on a `ShellRun`
  or `ShellSpawn` outcome, and the failure category of a `Delivery` reach no event, so a
  failure-rate rule over them matches nothing. An `Fs` outcome is the exception: it records
  `result`.
- Every window is bounded because each temporal operator carries an interval. The monitor
  drops state outside each rule's window. After each 10,000 submitted events, the durable
  engine attempts a checkpoint. A successful checkpoint snapshots monitor state and removes
  the covered log records. A failed checkpoint increases the durable log replay depth.

## Effective Policy

`PolicyEngine::effective` returns:

| Field | Meaning |
|---|---|
| `engine` | Engine identity and pinned version. |
| `policy_id` | Comma-separated source origins, or `<deny-by-default>`. |

`policy_id` is a diagnostic label.

## Errors

| Variant | Cause |
|---|---|
| `Parse` | Parsing or source composition failed. |
| `Schema` | A policy value, attribute, or entity type violates the schema. A deleted resource entity lands here. |
| `UnknownAction` | A policy names an action outside the schema. |
| `UnsupportedClause` | Reserved for API compatibility. |
| `Evaluation` | The durable engine could not open or recover the database, install sources, or submit an event. |

`open` returns `Parse`, `Schema`, `UnknownAction`, or `Evaluation`. `record` returns
`Evaluation` if durable submission fails after the effect.
No current method constructs `UnsupportedClause`.

An information-provider invocation aborts startup with `Parse`.

`PolicyEngine::validate` reports the same three load errors and never reports `Evaluation`.

## Egress Effect Interceptor

Enable the `egress-adapter` feature and bind a trusted egress principal:

```rust
use std::sync::Arc;

use policy::{EgressPolicyInterceptor, GovernedBox, PolicyEngine, Principal};

fn egress_interceptor(policy: Arc<PolicyEngine>) -> Arc<dyn egress_gateway::EffectInterceptor> {
    EgressPolicyInterceptor::into_handle(
        policy,
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    )
}
```

`into_handle` takes three arguments: the policy, the egress principal, and the box
this boundary serves. The interceptor holds all three and passes the box into every
`decide` and `record` it makes.

The interceptor maps connect and HTTP request attempts to `Request::Connect` and
`Request::Http`. A response release raises **no request and no decision**, and its permit
records nothing. The gateway consumes the request permit at reply time with
`EffectOutcome::Replied`, so the one `http:request::response` an exchange records carries
the reply as `output.status`, which only a `when temporal { … }` rule reads.

1. `intercept` evaluates the typed attempt with `PolicyEngine::decide`.
2. A denial returns `io::ErrorKind::PermissionDenied`.
3. An allow returns one opaque permit for that exact attempt.
4. The proxy consumes the permit with `record_outcome` or `mark_indeterminate`,
   and the permit submits the matching `Outcome` through `PolicyEngine::record`.

Each exact pinned socket attempt has its own connect decision and permit. An HTTP
request decision includes the destination port and the body length. There is no
response decision.
