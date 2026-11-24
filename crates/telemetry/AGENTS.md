# Telemetry guidance

The workload can reach this receiver. Changes to decoding, resource stamping, or route walks need
hostile-input tests. Read the [telemetry design](../../docs/design/telemetry.md) before changing
lanes or shutdown: forged box records and agent floods suppressing decisions have both occurred.

## Trust and routing traps

- Strip `strands.box.*` at every payload level before stamping provenance. A resource-only strip
  leaves forged verdicts on nested records. Preserve the typed exhaustive metric walk, including
  metadata, data points, and exemplars. Reserving all `strands.*` deletes real agent SDK fields.
- Take the relay permit before decoding and enforce resource count on every route. A measured
  4 MiB payload amplified to about 937 MB after stamping. One concurrent relay also prevents a
  flood of file writes from starving the SDK's separate decision queue.
- The SDK owns box-record queues and batching; agent payloads relay separately. Keep one compatible
  `reqwest` version with Shell. Adding a second exporter stack can duplicate TLS dependencies in
  the process holding secrets.
- Lane filtering uses severity, so signals need distinct severities. Test routing with two targets:
  a one-target test can stop at the acceptance union and never exercise the lane filter.
- `agent_logs` and `agent_metrics` are always selected at start, while payload `accepts` can still
  exclude them. Preserve the authored signal list for validation. MCP tool-call values are clear
  text and require explicit opt-in in both target constructors; they are logs, not spans.
- Expanded Shell arguments can contain file contents or secrets even on a denial. Report literal
  words only with provenance; otherwise use the bounded plain-flag rule. Path-shaped text is not
  safe: `/$SECRET` leaked under that shortcut. Box's hosted Shell currently supplies no literal
  mask, so its paths redact too. A bounded lowercase secret can still resemble a flag.
- `Zeroizing` prints its contents through `Debug`. Exporter secrets need their own redacted wrapper.
  Parse endpoint authority with the same URL parser the client uses; hand-splitting userinfo or
  backslashes previously sent credentials to the wrong host.
- Preserve determining-policy order from the engine; sorting changes which rule the record names.
  Attribution on an evaluator fault does not make an authored rule the cause. `caused_by` asserts
  in release because mislabelling that record has no safe fallback.
- Read parent span ID before removing its redundant attribute. Control-plane parents are local;
  only policy-plane parents get remote flags. Select records by scope, never `scopeLogs[0]` or
  resource-attribute order.

## File writes and teardown

- Acquire the async file lock before moving it into `spawn_blocking`. Cancelling a started write
  must not tear a JSON line; cancelling while waiting must leave no delayed write behind.
  Failed appends roll back only their own fragment. Separate boxes sharing a destination can
  still tear lines; prefer one destination per box.
- `Collector::record` must not wait on export. `drained` belongs on every run exit, including
  startup failures before a hosted box exists. `Drop` does not flush reliably.
- Bound shutdown above the SDK. Its async batch processor has ignored its shutdown timeout.
  `Drop` starts shutdown on a detached `std::thread` and waits for nothing: a blocking-pool task
  can deadlock runtime teardown, and even a bounded wait can starve the worker it awaits.
  Keep `the_drain_returns_when_the_batch_worker_cannot_answer`.
- A detached shutdown thread can remain blocked until process exit. Lanes flush sequentially,
  so the overall deadline can cut later lanes. This is best-effort delivery, not durable audit.
- The loss counter counts failed export batches, not records, queue overflow, or refused agent
  payloads. Distinguish a failed final export from an unanswered shutdown, and report loss once
  at drain without changing the workload's exit status.

## Test traps

A `zsh` alias reports the hosted Shell's environment, not the workload's. Probe the workload
itself and account for its exec grants. Keep route-level forgery tests and
`a_flood_of_relayed_payloads_loses_no_decision`; private helper tests cannot prove every route calls
the helper. The flood test covers relay contention, not arbitrary SDK queue overflow.
