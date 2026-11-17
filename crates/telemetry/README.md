# `strands-box-telemetry`

Where one box's decisions, control operations, and MCP routing diagnostics go.

## Known limitations

- **Delivery is best-effort.** A failing target loses the record. The loss is counted, and the drain
  prints the count on one stderr line when the run ends. Each failure also prints with its cause
  when the caller sets `TelemetryConfig::reporting_failures`. A full
  queue drops records and does not count them, because the SDK reports that number only through a
  `tracing` subscriber this workspace does not install.
- **Targets flush in sequence.** Each target has its own queue, but one slow or unreachable
  endpoint delays shutdown by its export deadline.
- **A box can hang on exit inside this crate.** It was seen twice and is not fixed.
  [AGENTS.md](AGENTS.md) records what was measured.

Do not put this on a path where losing a record matters.

## What it does

A box decides thousands of times per run. This crate is where those decisions go: one lane per box,
inside that box's own trusted process. There is no sidecar to deploy and two boxes share no queue.

```rust
let collector = telemetry::open(
    telemetry::TelemetryConfig::for_box("my-box").with_target(
        telemetry::Target::new(telemetry::TargetKind::File, "/path/records.jsonl").receiving(
            vec![
                telemetry::Signal::PolicyDenied,
                telemetry::Signal::PolicyPermitted,
                telemetry::Signal::AgentTrace,
            ],
        ),
    ),
)?;

collector.record(telemetry::DecisionRecord::deny(
    r#"Box::Action::"fs:read""#,
    "~/.ssh/id_rsa",
    "rule-7",
    "a forbid rule matched",
));

collector.drained().await;
```

`open` must be called inside a Tokio runtime. It is synchronous, so a caller can open it beside its
other mechanisms rather than at an `await`.

## Signals

A target names a **set**. No signal contains another, and there is no ordering.

| Signal | What it is |
|---|---|
| `policy_denied` | an effective denial |
| `policy_permitted` | an effective permit |
| `agent_trace` | one span the agent's own instrumentation exported |
| `agent_logs` | one log record the agent's own instrumentation exported |
| `agent_metrics` | one metric the agent's own instrumentation exported |
| `control_plane` | one change to the authority this box holds |
| `mcp_unmatched` | one MCP alias invocation that matches no declared command |

**A target naming none receives every one of the seven.** An empty set is refused.

These seven are this crate's own vocabulary and the spelling a record carries. They are not what an
operator writes: `box.toml` takes `include`, whose words are `deny`, `permit`, `trace`, `logs`, and
`metrics`, and the box expands each word into this set. `trace` names both `agent_trace` and
`control_plane`. `logs` names both `agent_logs` and `mcp_unmatched`.

## What a record carries

Each decision record names the principal, action, resource, policy rule or enforcement gate, and
verdict. A refusal also carries its reason. The shape is OTLP: `resourceLogs` for the box's own
records and `resourceSpans` for an agent trace.

`Collector::mcp_unmatched` accepts `McpUnmatched::new(program, arguments)` and records it as an
informational log in scope `strands-box.mcp`, with event name `strands.box.mcp.unmatched`.
The constructor bounds the program and redacts expanded arguments. `correlated` attaches the
caller's available request context. This record has no policy verdict or execution outcome and
produces no span.

## The agent's own signals

The collector binds one loopback port and the box hands the agent its address in
`OTEL_EXPORTER_OTLP_ENDPOINT`, with no credential. It serves three routes and answers `404` on every
other one:

| Route | Signal |
|---|---|
| `/v1/traces` | `agent_trace` |
| `/v1/logs` | `agent_logs` |
| `/v1/metrics` | `agent_metrics` |

Three properties are intended:

- **It reads nothing back.** Every route and every status answers a fixed `{}`, so the agent cannot
  tell whether a target kept its payload.
- **It cannot forge a box record.** The `strands.box.` attribute namespace is stripped from every level
  each payload nests, and a scope claiming `strands-box.` is renamed. Each resource is then stamped
  `strands.box.source = "agent"`, and the strip and the stamp are one function, so no route can do one
  without the other.
- **It cannot suppress a refusal.** The agent is a producer. No route removes a record.

**Shape no longer distinguishes a box record from an agent's.** The box writes `resourceLogs` for
every decision, and `/v1/logs` now accepts `resourceLogs` from the agent. So a consumer must select on
`strands.box.source`, or on the `strands-box.policy`, `strands-box.control`, and `strands-box.mcp`
scopes. Severity is the box's own routing and is not a filter for a reader.

The box **relays** each of these and produces none of them, so a harness that exports no metric
delivers no metric, whatever `include` names.

## Exporter types

`TargetKind` selects the exporter. Two are built:

| Kind | Destination |
|---|---|
| `File` | a path; one OTLP-JSON request per line |
| `Otlp` | a URL; OTLP over HTTP with protobuf |

The box's vendor kinds (`langfuse`, `langsmith`, `cloudwatch_logs`, `cloudwatch_traces`) are not
exporters here. The box expands each one into the `Otlp` target it stands for, with its path, its
headers, and its payloads, before this crate sees it.

An `Otlp` target can also name:

- **The payloads it accepts** (`Target::accepting`), from `Payload::Traces`, `Logs`, and `Metrics`.
  The exporter sends no batch of a payload the list leaves out, because a vendor that takes only
  spans answers `404` on the other routes.
- **Fixed headers** (`Target::with_header`). A header the exporter writes itself is refused.

## The credential

An `Otlp` target carries its credential in one of two ways. The caller resolves a `TargetSecret`
and hands over the header and value. Or the caller opens a `credentials::Vault` for the destination
alone, and hands it over with `Target::with_vault`. The exporter then asks the vault to attach the
credential to each request, as a header, as Basic auth, or as a SigV4 signature. A target takes one
or the other, never both. A credential needs an `https://` destination unless the destination is
loopback.

This crate never reads the environment. The caller turns on the stderr line for each failed batch
with `TelemetryConfig::reporting_failures`.
