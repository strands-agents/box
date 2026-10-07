# `strands-box-telemetry`

Where one box's decision records go.

## Known limitations

- **Delivery is best-effort.** A failing target prints to stderr and the record is gone. A full
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

**A target naming none receives every one of the six.** An empty set is refused.

These six are this crate's own vocabulary and the spelling a record carries. They are not what an
operator writes: `box.toml` takes `include`, whose words are `deny`, `permit`, `trace`, `logs`, and
`metrics`, and the box expands each word into this set. `trace` names both `agent_trace` and
`control_plane`.

## What a record carries

Each decision record names the principal, action, resource, policy rule or enforcement gate, and
verdict. A refusal also carries its reason. The shape is OTLP: `resourceLogs` for the box's own
records and `resourceSpans` for an agent trace.

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
`strands.box.source`, or on the `strands-box.policy` and `strands-box.control` scopes. Severity is the
box's own routing and is not a filter for a reader.

The box **relays** each of these and produces none of them, so a harness that exports no metric
delivers no metric, whatever `include` names.

## Exporter types

`type` selects the exporter. Two are built:

| Type | Built | Destination |
|---|---|---|
| `file` | yes | a path; one OTLP-JSON request per line |
| `otlp` | yes | a URL; OTLP over HTTP with protobuf |

Those are the two types. Any other table name is refused when the config loads, naming these two, so
no box starts believing it records. A vendor exporter is reached through a collector — see below.

## The credential

An `otlp` target names a `secret.ref` and a `secret.header`. The caller resolves the reference and
hands over the value; this crate never reads the environment. A secret needs an `https://`
destination unless the destination is loopback.
