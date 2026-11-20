# CLI telemetry

`box run` captures the CLI version, system, profile, packs, and saved MCP configuration.
The snapshot keeps what was collected before success or failure and stays unchanged afterward.

`strands-box-cli-telemetry` [owns collection and serialization](decisions.md#telemetry-owns-observation-and-payload-construction). The CLI passes loaded sources
and resolved targets at the preparation steps. The fields follow the pinned schema, which the repository holds as
[`crates/cli/telemetry/tests/fixtures/box.schema.json`](../../../crates/cli/telemetry/tests/fixtures/box.schema.json),
copied from the telemetry service's `schema/box.schema.json` at revision `f8b2541`, and the telemetry
tests check each payload against it.
The schema describes startup latency from invocation start. The CLI uses the narrower
launch-preparation boundary below; the schema's validation rules are unchanged.
The executable collects and sends run, polling, and shutdown events through one background worker.
Library callers can supply their own capture callback. Ordinary library preparation skips
context construction and identity persistence.

## Delivery

`Session::delivering` connects event capture to `Delivery`. Each event is one compact JSON
`POST` to `https://telemetry.strandsagents.com/box/ping`, with
`Content-Type: application/json`. The request has no authentication header or cookies.
The service accepts the existing envelope and returns 204. It does not deduplicate requests,
so delivery makes one attempt per event, with no retries or redirects.

The session worker owns journal observation, event construction, and the HTTP client.
`Delivery` serializes one event in at most 12,288 bytes and a batch in at most 32 KiB, the
service's request limit, and drops an oversized body. It sends each event
before the worker resumes collection. There is no event queue or separate sender worker.
Each request during the run has a two-second timeout, so a slow request can delay observation.
The client keeps an idle connection for later requests in the same invocation.
`Delivery::send_all` sends the events that become ready together in one request: one event
alone, or several as one JSON array, which the service accepts. Sends during the run use the pooled
connection. The final send at exit uses a separate client that keeps no idle connection, so it never
rides a connection that died without notice during the run, and it is limited to the time left
before the deadline.
Client construction, encoding, and network errors produce no diagnostic and preserve the
command result. A panic in the worker stops telemetry without propagating to the caller;
the process's panic hook remains unchanged.

`Session::finish` waits for final collection and the final send attempts. The worker signals
completion before it drops the HTTP client, so client cleanup does not extend the caller's wait.

The CLI ends every run with `Session::finish_with_timeout` and `COMPLETION_BUDGET`, two seconds,
including normal exits, Ctrl+C, and preparation failures. The budget starts after execution
and terminal cleanup return, or when preparation fails. It includes a request already in
progress, final collection, and the final send attempt. The final events go out in one
request, so they share the rest of the budget.
The worker checks the deadline before the final read and before sending. Work already in
progress can finish later. The worker retains a clone of the instance lock until observation
ends, even if the caller returns first. A request already in progress when the run ends can
use the whole budget. There is no disk queue, and a crash or process exit can lose events.

The `test-transport` feature replaces the service destination with
`BOX_TEST_TELEMETRY_ENDPOINT`. It accepts only HTTP URLs with a literal loopback address
and no credentials, and bypasses HTTP proxies. A missing or invalid value disables delivery.
Production builds ignore the variable. The CLI dev dependency enables this feature during
Cargo tests. CI checks, the corpus, and the nightly agent workloads build with the production
transport and set `BOX_TELEMETRY=0`; downloadable trial builds send events, and so does a
package built for release, though no workflow in this repository releases `box` yet. Local
package smoke checks use the
[caller's installation identity](decisions.md#smoke-telemetry-follows-the-callers-identity).
Their temporary homes receive the developer's saved metadata.
See [manual testing](../../dev/manual-testing.md#check-telemetry-delivery) for a local receiver.

## Consent

`Consent::resolve` decides whether a run sends telemetry, in order: `BOX_TELEMETRY` (`1`, `true`,
or `on` turns it on, and any other nonempty value turns it off, including one that is not UTF-8),
then `DO_NOT_TRACK` (`1` or `true` turns it off), then the `telemetry` key in `~/.strands/box/installation.toml`, else on. An empty variable counts as unset. Consent reads the
raw environment value, so a `BOX_TELEMETRY` that is not UTF-8 cannot read as unset. It reports
which of these decided. An unreadable metadata file turns telemetry off. The CLI resolves consent
before it loads the installation ID, so a run with telemetry off creates no ID and starts no
session. `save_telemetry_choice` writes the key under the same lock and atomic rename as ID
creation, and keeps every other key, including the ID. Like the ID, the choice lives in
`~/.strands/box` whatever `BOX_HOME` names.

On a first install, `install.sh` reads `telemetry status` from the installed launcher.
It prints the usage notice only when the command succeeds and reports that telemetry is on.
A failed or unrecognized status leaves the notice out and installation succeeds.

## Installation identity

`InstallationId::load_or_create` reads `~/.strands/box/installation.toml` or creates it with one random
UUIDv4. The ID [survives changes to `BOX_HOME`](decisions.md#installation-identity-survives-box-home-changes).

```toml
installation_id = "12345678-90ab-4cde-8f01-234567890abc"
```

An existing ID is reused without rewriting the file. An absent ID is added to existing valid
TOML or written to a new file. Creation is atomic, concurrent callers reuse one ID, and other
metadata is preserved. Invalid or unreadable files leave the ID unavailable. The reader refuses
symbolic links and nonregular files.

`Launcher::prepare_with_context` returns the ID separately from `RunContext`, including on
preparation failure. Identity errors give `None` and disable event capture without failing the
run. `Launcher::failed_preparation` supplies baseline context for errors before profile loading.

## Invocation and run event

`Invocation` creates a fresh UUIDv4 and holds the installation ID, immutable context, and
monotonic invocation start and wall-clock launch-preparation start. Its event constructors
reuse those IDs and that context. If the OS random source fails, `Invocation::new` returns
`None` and the CLI skips telemetry without changing the run.
`Event` serializes the complete envelope with version `1` and a fixed event name.
The top-level fields are `v`, `event`, `installation_id`, `run_id`, `context`, and `data`,
in that order.

`run_event` accepts launch evidence. A confirmed launch gives `true`, a known absence of launch
gives `false`, and an unknown launch gives `null`. A preparation failure always gives `false`
and a fixed failure category. `Error::telemetry_failure` maps CLI variants without reading their
diagnostic text. `ProfileMissing`, and a `ProfilePath` whose file is not found, map to
`profile_missing`. `Profile`, `ProfileName`, any other `ProfilePath`, `ProfileFileUnnamed`,
`ProfileNameTaken`, `ProfileNameOwned`, `ProfileNameOwnerGone`, `ProfileFileShared`, and
`ProfileInWorkspace` map to `profile_invalid`. `Policy` maps to `policy_rejected`. Other variants
map to `unknown`.
`NotOnHost` does not distinguish the agent from another missing host input.

The current invocation's `box_started` control record with outcome `ok` confirms that the Core
box run started. It gives `box_launched: true` and `failure_reason: null`. Core emits this
record after its initial preparation and before workload spawn. Later workload failures do not
reverse the launch result. An error during Core's initial preparation can leave no lifecycle
records.
A nonzero Core exit does not establish a preparation failure.

`startup_latency_ms` measures from launch preparation to the source `timeUnixNano` of that
record. Its wall-clock origin follows optional profile creation on every run, before guide
refresh and run preparation. It excludes profile creation and its prompts, and includes
resolution, compilation, storage preparation, and Core startup. It ends at Core's startup
milestone, before the agent is ready. Export and reader delays do not affect it. It rounds down to
milliseconds and saturates at the schema's maximum integer. A missing, invalid, or pre-start
timestamp gives `null` without reversing confirmed launch evidence. Wall-clock changes can
affect this measurement.

After command and Box-home validation, the executable captures the monotonic start at entry
to `box run` and the wall-clock startup origin after optional profile creation. After
preparation, it creates a `Session` with one invocation and the collected
context. A preparation failure's run event goes out with shutdown, without waiting for launch
evidence. Successful preparation waits for that evidence.
If observation ends without that evidence, the session emits `null` for all three run fields.
Preparation failures also give `startup_latency_ms: null`. Every field is required; unavailable
values serialize as `null`.
Missing records alone do not establish that no box started.

Core writes records to the box instance's `records.jsonl`. Repeated runs of the same instance
append to that file. Each new instance has its own file. `Journal` reads this existing stream.

`Launch::run_with_telemetry` calls `Journal::start` before it calls Core, while it holds the
instance lock. The reader gets the opened file's byte length from its metadata and seeks to
that exact offset. It reads only bytes appended after that boundary. If the file does not
exist yet, the reader starts at offset zero when the file appears.

The parser starts empty at that offset, even if the existing file ends with an unfinished
line. Core appends new JSON batches for this run, so the old fragment cannot hide the first
new record. The reader retains partial lines appended after the boundary until they are complete.

Lifecycle observation accepts only `strands-box.control` logs with the Core service and source
attributes.
It reads `box_started` with outcome `ok` and `box_stopped` with outcome `ok` or `refused`.
Old records and relayed agent records cannot supply evidence for this invocation. Missing or
unreadable records leave the corresponding observations unknown.

The session reads on a one-second timer between send attempts. After Core returns, the worker
reads the remaining records before sending the final events, subject to the
[completion budget](#delivery). Capture stops before the instance lock is released. The session
attempts at most one run event. Library callbacks must bound their own work, and capture errors
preserve the command result.

## Shutdown event

`shutdown_event` accepts a monotonic completion instant, a zero or nonzero CLI exit outcome,
and an optional `CoreOutcome`.
The elapsed time starts at the invocation's supplied start instant, so it includes profile
creation, its prompts, and launch preparation.
The caller captures completion before journal observation finishes. Durations round down to
milliseconds and saturate at the schema's maximum integer. An instant before the start gives zero.

`Launch::run_with_telemetry` captures completion after Core returns. `Session::finish` asks
the worker to read the final records. The worker then sends a pending run event, the final
complete polling interval, and shutdown in one request, in that order, subject to the
[completion budget](#delivery).
The worker retains the instance lock through final collection.
Preparation errors capture shutdown before the executable returns the same error.

The observer retains the current invocation's `box_stopped` outcome through the final read.
`core_outcome` is `ok` when Core completes with an exit code, including a nonzero workload exit.
It is `refused` when Core reports an error. It is `null` when no valid stop record is available.
The field is required. Preparation failures give `null` because Core has not run.
The event contains no raw refusal reason.

| CLI `exit_outcome` | Observed `core_outcome` | Meaning |
| --- | --- | --- |
| `zero` | `ok` | Core returns an exit code and the CLI succeeds. |
| `nonzero` | `ok` | Core returns an exit code and the CLI fails. The workload or CLI wrapper can cause the failure. |
| `nonzero` | `refused` | Core reports an error and the CLI fails. |
| `zero` or `nonzero` | `null` | The CLI result is known; Core's stop outcome is unavailable. |

The schema permits `zero` with `refused`, but the current Core error path produces a
nonzero CLI result. These fields do not expose a workload exit code, signal, or specific Core
error category.

The shutdown event retains the invocation's IDs and context. A crash or force-kill can prevent
it. Its absence does not establish a crash, and its exit outcome does not establish that the
agent finished its task.

## Polling events

`Journal` reads decisions appended after its starting offset. It accepts only Core policy
decision logs with the Core service and source attributes. It ignores spans, metrics, and
relayed agent records. It checks the source before the service name and skips resources with
missing or invalid Core service names. Each read consumes at most one MiB, and selected
attributes hold at most 1024 bytes. A Core batch occupies one JSON line and can span several reads. The reader
retains that line until its newline arrives, without a batch-size limit. Buffer memory and
JSON parse work depend on the batch size.

Partial lines wait for the next read. A malformed journal envelope or Core record invalidates
its interval. At an interval boundary, unread policy decisions and incomplete decision records are excluded from
later counts. The reader keeps its position and pending bytes so that startup and shutdown
evidence in those records remains observable. A missing journal is unavailable until it appears.
File replacement, removal, detected truncation, or a read failure makes the reader unavailable
for the rest of the invocation.

`DecisionInterval` maps each observed decision to one action and outcome pair. `ActionCatalog`
converts configured MCP names to the namespace spelling that Box Core emits.
Non-ASCII characters and punctuation become underscores, names that start with a digit gain
an underscore prefix, and Cedar reserved words gain an underscore suffix.
Exact service action names with a matching category keep their action; other filesystem
actions under `fs` map to `fs:other`. A category that matches a configured MCP namespace maps
to `mcp_tool`, unless that namespace also names a service action group.
These collisions, unknown evidence, and tool grammar actions map to `unknown`.
Permits always map to `permitted`. Denials map by their fixed cause, with unknown causes
mapped to `unknown`. Raw action names and diagnostic text are absent from the event.

The interval returns one nonzero row per pair and resets its counters after each boundary.
Counts saturate at the schema's maximum integer. An observed empty interval gives an empty
array; an incomplete interval gives no event. The nominal interval is 60 seconds, and the
caller supplies each actual boundary, including the final partial interval. `Session` captures
each elapsed 60-second interval between send attempts. Completion reads until the journal ends
or three seconds have elapsed, subject to the [completion budget](#delivery). It checks this
allowance between byte-bounded reads, so a slow filesystem operation or JSON parse can extend
the read time.

Collection uses the existing journal while the instance lock is retained. The worker finishes
the final reads before sending the final events. An incomplete interval omits the final polling
event and keeps any Core stop outcome already observed. No event follows shutdown.
Direct Core access against CLI-owned state is outside this coordination.
Counts describe decisions observed in the journal; Core can drop records without exposing a
loss marker.

## Capture points

| Field | Source and timing |
| --- | --- |
| `box_version` | CLI package version as `MAJOR.MINOR.PATCH`. |
| `os_family` | Binary target OS from `std::env::consts::OS`. Unrecognized targets give `other`. |
| `os_version` | Host operating system version from the `sysinfo` crate, trimmed and cut to 64 characters. Unavailable or empty gives `null`. |
| `build_arch` | Binary target architecture from `std::env::consts::ARCH`. |
| `profile_hash` | SHA-256 of the saved profile bytes before parsing, including comments and whitespace. |
| `profile_policy_present` | Saved profile's `policies` list: a nonempty list gives `true`, an omitted or empty list gives `false`, and unreadable TOML or a malformed list gives `null`. Policy files are not inspected. |
| `builtin_packs`, `has_custom_packs` | Contributing pack graph, checked against the shipped catalog. |
| `mcp_configured` | Saved harness MCP sections, read after imports. |

Unavailable observations serialize as `null`. The snapshot contains no source text, paths,
custom pack names, or configuration values.

## Bundled provenance

The telemetry crate builds its catalog from `resources/packs`, independently of `BOX_RESOURCES`.
A built-in pack must match a catalog ID, its `pack.toml` and optional `grammar.toml` bytes,
and its location under the selected resource directory. Added or changed definition files
count as custom. Other files in the pack folder are outside this comparison.

Pack graph loading goes through the CLI telemetry adapter and retains origin evidence with the
loaded bytes, even when no context is requested. Pack locations are verified without following
links below the resource directory; the directory itself can be an alias. Later edits cannot
change the classification. Matching bytes with an unverified location leave both pack fields `null`.

The graph includes transitive dependencies and accepted MCP launcher chains. IDs are sorted
and unique. A complete empty graph gives `[]` and `false`; an incomplete graph gives `null`.
Graphs without MCP declarations are available before host resolution.

## Stored MCP configuration

The collector reads saved target sections, including settings preserved when import is disabled.
A nonempty server table gives `true`. An absent file or section, or an empty table, gives `false`.
Invalid, unreadable, or linked targets give `null`.

Across targets, any nonempty table gives `true`; all must be known empty to give `false`.
With no target, the field is `false`.
