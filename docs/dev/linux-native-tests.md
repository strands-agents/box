# Linux native filesystem tests

Choose tests by the behavior they exercise. The workload suites run Box with native policy selected;
the broker and forwarding tests isolate particular kernel interactions.

## Native workload suites

Run native tests on a Linux system with the required kernel hooks and loader capabilities. The C workload fixtures support ARM64 and x86-64 Linux.

```sh
RUSTFLAGS="--cfg box_native_kernel_tests" cargo build -p strands-box -p strands-box-containment --all-features
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --lib --all-features run::native_enforcement:: -- --test-threads=1
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --all-features --test linux_native_paths --test linux_native_directories --test linux_native_research --test linux_native_policy_semantics --test linux_native_failures -- --test-threads=1
```

The runner needs CAP_BPF and CAP_PERFMON. Use a dedicated test process. Guard preparation removes these capabilities from that process. Set `NATIVE_TEST_ROOT` to a short writable directory.

The tests use actual notification listeners and kernel hooks. A missing prerequisite is a test failure, not evidence of support. The root and callback regressions use the separate `linux_native_root` executable and require a root runner.

Rebuild with fault controls before running failure injection and replacement races:

```sh
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_test_faults" cargo build -p strands-box -p strands-box-containment --all-features
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_test_faults" cargo test -p strands-box --all-features --test linux_native_failures --test linux_native_entry_races -- --test-threads=1
```

Keep fault-enabled binaries separate from release artifacts. Product builds do not require these private test switches. Native filesystem policy remains an explicit experimental selection.

The `box_native_kernel_tests` switch selects the private Rust tests. It can be supplied only to a
test crate when reusing ordinary product binaries. That does not enable fault injection in Box.
For injected failures, rebuild the Box product and the test harness with `box_native_test_faults`;
the fault-build commands above pass both private switches through `RUSTFLAGS`. Adding fault flags
only to the test crate does not change the executable that it launches.

The ordinary `cargo test --workspace --all-features` command does not enable
`box_native_kernel_tests` or `box_native_test_faults`. A private integration target that reports zero
tests has not exercised these workloads. The forwarding and after-effect broker tests below run
without either private switch.

## Choose tests by failure mode

Use file effects, caller results, and durable policy history together when checking enforcement.
These test families cover different boundaries; one family's result does not establish the others.

The directory suite also checks the [narrower Linux operations](../user/native-filesystem-policy.md#linux-arm64):
`renameat2_without_flags_uses_native_move_policy` requires both an allowed move and a policy refusal.
Unsupported rename flags, sticky-bit creation, and existing-directory replacement require an
explicit native refusal, no policy decision, and unchanged source and destination identities or bytes.
Set-group-ID and set-user-ID creation instead require the baseline filter's `EPERM` result and no native event.
This distinguishes baseline containment from a native-policy refusal.

The path suite checks hard-link reads and writes through an allowed name, a policy-denied alias,
and an alias outside the filesystem grant. The tests require the exact decision resource, file
contents, and shared file identity. An allowed write changes the shared contents through every
link; it does not make a denied or ungranted name accessible. The tests are
`hard_link_access_uses_the_allowed_name_and_preserves_shared_inode_semantics`,
`a_policy_denied_hard_link_alias_cannot_read_or_write_the_shared_inode`, and
`a_hard_link_alias_outside_the_grant_cannot_read_or_write_the_shared_inode`.

| Family | Required behavior | Test pointers |
| --- | --- | --- |
| Selection and startup | Keep native policy off by default. Respect each local process's selection. Refuse selected startup before workload execution when required setup fails. | [Configuration tests](../../crates/box/src/record/config/mod.rs): `experimental_selection_is_explicit_and_strict` and `native_setup_includes_inherited_stdio_servers_and_respects_every_opt_out`. [Failure tests](../../crates/box/tests/linux_native_failures.rs): `selected_native_checks_refuse_without_loader_capabilities` and `registration_refusal_prevents_the_workload_from_starting`. |
| Allowed and denied effects | Perform permitted changes; preserve denied files, destination entries, and symbolic-link targets. Return only permitted file bytes or directory entries. | [Operation tests](../../crates/box/tests/linux_native_research.rs): `agent_write_allow`, `agent_write_deny`, and the create, delete, move, append, and truncation pairs. [Directory tests](../../crates/box/tests/linux_native_directories.rs): `policy_can_deny_directory_creation` and `unlink_removes_the_link_and_preserves_its_target`. |
| Filesystem grants and handles | A policy permit must not expand filesystem grants. A directory handle must not bypass the next file-operation check. | [Operation tests](../../crates/box/tests/linux_native_research.rs): `a_policy_permit_cannot_write_through_a_read_only_mount`, `a_policy_permit_cannot_open_a_file_outside_workload_grants`, and `a_directory_descriptor_does_not_bypass_policy`. Existing-handle access retains the documented limits below. |
| Paths and replacement races | Resolve symbolic links to the checked object; check hard links by their requested name. Preserve replacement entries at the controlled race points. | [Path tests](../../crates/box/tests/linux_native_paths.rs): `a_permitted_link_name_cannot_hide_a_denied_target`. [Race tests](../../crates/box/tests/linux_native_entry_races.rs): `rename_must_not_overwrite_a_replacement_destination_after_final_verification` and `path_truncate_changes_the_pinned_file_and_preserves_a_replacement`. |
| History and outcomes | Share the intended history across native tools and Shell. Count one completed rename once. Keep abandoned checks request-only and retain actual operating-system failures. | [Operation tests](../../crates/box/tests/linux_native_research.rs): `native_tool_observes_the_hosted_shells_request_history`. [Policy semantics tests](../../crates/box/tests/linux_native_policy_semantics.rs): `one_rename_counts_as_one_completed_move`, `denied_rename_leaves_earlier_checks_request_only`, and `failed_rename_keeps_actual_failure_history`. Use the [paired comparison](#compare-shell-and-native-policy-events) for adapter differences. |
| Request flow and failure stage | Preserve queued requests and reject invalid frames. Distinguish failure before an effect from cancellation after an effect. | [Forwarding tests](#forwarding-buffer-tests), [registration tests](../../crates/box/src/run/linux_enforcement/notify.rs), and [after-effect controls](#after-effect-cancellation). [Failure tests](../../crates/box/tests/linux_native_failures.rs): `a_request_storage_failure_stops_box_before_the_write` and `cancelling_a_request_keeps_box_available_for_the_next_request`. |
| Shutdown and process lifetime | Stop the tested process chain when Box ends. Check pending requests separately from workloads that already received a handle. | [Failure tests](../../crates/box/tests/linux_native_failures.rs): `sigkill_of_box_stops_descendants_in_separate_process_groups`, `killing_box_with_a_pending_read_open_returns_no_file_bytes`, and `killing_box_with_an_open_read_handle_stops_the_waiting_workload`. |
| Workflows and packages | Exercise agents, declared tools, and local Model Context Protocol (MCP) servers. Validate the installed artifact with its matching helper executables. | [Operation tests](../../crates/box/tests/linux_native_research.rs): agent/tool selection controls, `local_mcp_server_native_write_reaches_the_policy_engine`, and `local_mcp_server_continues_after_a_denied_native_write`. Repeat the intended workflow from the installed package; a source-build test does not establish package qualification. |

Apply the [feature's coverage limits](../user/native-filesystem-policy.md#coverage-and-limits) when
interpreting these results. Existing handles can carry later access without another policy check.
Controlled replacement tests do not establish atomic identity for every directory-entry race.
An allowed effect can remain after cancellation or reply failure. Linux process-lifetime tests do
not establish the macOS failure contract. Cloud support and performance need their own validation.

## Forwarding buffer tests

Run the three containment supervisor tests on Linux:

```sh
cargo test --locked -p strands-box-containment --lib --all-features backend::linux::namespace::filesystem_queries::forwarding_tests:: -- --test-threads=1
```

These tests create their own kernel notification listener. They do not need the kernel loader
capabilities required by the operation suites. The tests check that a full forwarding buffer pauses
request delivery, preserves the pending request, and still lets the supervisor detect workload exit.
The ordinary all-features workspace run includes these tests. Linux CI also runs this focused
command in a separate step and requires all three tests to pass.

## After-effect cancellation

Run the three broker controls on Linux with kernel notification support:

```sh
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo test --locked -p strands-box --lib --all-features run::native_enforcement::broker::outcome_tests:: -- --test-threads=1
```

These [unit tests](../../crates/box/src/run/linux_enforcement/outcome_tests.rs) start a child that
calls `truncate`, which shortens a file. They use a real kernel notification listener and the
Box code that checks policy and performs the file operation. They do not load the separate kernel
hooks used by the operation suites or require their loader capabilities. The ordinary all-feature library suite includes them.

The controls independently check the file bytes, the caller's result, child cleanup, and durable
history after reopening the policy engine:

- `a_delivered_truncation_records_its_completed_effect` requires a successful reply, shortened bytes,
  and a completed outcome.
- `cancellation_before_truncation_preserves_bytes_and_has_no_completed_outcome` requires unchanged
  bytes and no completed outcome after the caller is cancelled.
- `cancellation_after_truncation_keeps_changed_bytes_and_completed_outcome` cancels the caller only
  after verifying shortened bytes and a still-pending request. The reply must fail because the
  caller is gone; the shortened bytes and completed outcome must remain.

The synchronization callback exists only in unit-test builds. It runs at the existing outcome stage,
after the filesystem effect and before outcome recording. These tests check the broker's reply
boundary; use the failure suite above for complete Box launch and process-lifetime behavior.

## Shared filesystem listener

Selected native workloads use one kernel notification listener for both file-policy operations and
filesystem-information queries. The existing containment supervisor receives every notification.
It answers `statfs` queries locally, preserving filesystem type information while removing host
capacity counters and filesystem identifiers. It forwards native file operations to Box for policy
evaluation and execution.

The supervisor is the client in this private exchange. Box's native policy worker is the server.
The version-two startup handoff transfers the listener, a path-only handle to the workload root,
and the private forwarding socket. Box uses the listener to validate and answer requests; only the
supervisor receives notifications from it. The trusted launcher closes its copies before executing
the workload. The forwarding socket is local to this workload and is not a public API.

The `filesystem_queries_remain_sanitized_beside_an_allowed_native_read` and
`filesystem_queries_remain_sanitized_beside_a_denied_native_read` tests query filesystem information
before and after a native read. They require the expected file-policy result and zero host counters.
The component tests cover malformed registration, wrong descriptor kinds, truncated requests,
connection closure, and a forwarding buffer whose reader has stopped. When the buffer is full,
the supervisor retains the pending request and waits for space while checking for workload exit.
A closed connection, invalid forwarding descriptor, or partial send terminates supervision.
These conditions never allow the intercepted system call to continue unchecked.

## Compare Shell and native policy events

The comparison suite runs equivalent file operations through Strands Shell and direct Linux system calls.
It checks the stored Dogwood events, policy decisions, command output, and final filesystem contents for each adapter.
A passing run confirms the checked expectations for each adapter; it does not claim identical event streams.

Use ARM64 or x86-64 Linux with the [native interception prerequisites](../user/native-filesystem-policy.md#linux-arm64-requirements),
Python 3.9 or later, the repository's Rust toolchain, and a C compiler.
Run as an ordinary user with passwordless access to `sudo setpriv` for `CAP_BPF` and `CAP_PERFMON`.
These capabilities let the trusted Box process load its kernel checks.
Missing prerequisites fail the run; the runner does not skip unsupported cases.

Reserve a build directory and choose a new evidence directory for each run.
Replace `BUILD_DIRECTORY` and `EVIDENCE_DIRECTORY` with absolute paths:

```sh
python3 scripts/test_shell_native_policy_events.py -v
python3 scripts/shell_native_policy_events.py --build-dir BUILD_DIRECTORY --output EVIDENCE_DIRECTORY
```

The runner builds with ordinary `--all-features`, including `test-support` diagnostics.
It clears inherited Rust flags and requires no private test configuration switches.
Cargo's JSON output must identify Box and both helper executables; the runner copies and hashes those exact binaries before launch.
The manifest records the source revision, local changes, build settings, and input and executable hashes.
This comparison executes real native workloads even though the private Rust integration tests require their separate `box_native_kernel_tests` switch.

The matrix contains 33 pairs, or 66 workloads: directory rename, file rename, replacement, directory listing, and file reading.
Targeted rules deny source reads, directory listing, either rename endpoint, destination writes, or destination deletes.
Six pairs test history-based rules with and without a preceding rename.
They verify path-specific source-read history, wildcard source-read history, and a rule that denies reads after two completed moves.
One successful rename records one completed move, so that last rule must still permit the read after one rename.
A later policy denial leaves earlier checks without outcomes.

Each workload has a 60-second deadline and a separate fixture under `/var/tmp/sn-*`.
The runner retains those fixtures for diagnosis; clean them only after saving the required evidence.
Native cases require diagnostic proof that the policy mechanism handled the operation.
Denial cases require the authored forbid, the expected refusal marker, unchanged protected content, and no denied bytes in output.
The event reader checks the entire durable history, including contiguous record offsets from the beginning.

`history.snapshot.redb` retains an immutable copy of the original durable history.
The reader opens a separate `history.redb` copy because opening the database can change its metadata.
The runner verifies the snapshot hash after reading.
`records.stdout` and `filesystem-events.raw.json` retain the decoded original events and request identifiers.
For comparison, the runner replaces only the temporary absolute fixture prefix with `/<ROOT>` and renames opaque request identifiers in first-request order.
Before renaming identifiers, it verifies unique requests, matching request/outcome identities, and at most one outcome for each request.
A denied or abandoned request may have no outcome.
This removes identifier allocation differences caused by non-filesystem traffic while preserving correlation relationships.
It does not change path spelling, event order, action, operation, event kind, or result.
For example, `~/workspace/source` remains distinct from `/<ROOT>/workspace/source`.

The checked fixture is `crates/box/tests/fixtures/shell_native_events.json`.
Each row declares action, event kind, operation, path, result, and request number.
The runner expands these rows into complete expected event objects and compares every field.
It never updates expectations automatically.
Fault controls verify that missing, duplicated, reordered, mistyped, or incorrectly correlated events fail the assertions.

Read `summary.json` for case failures and decision, effect, and event disagreements.
Each pair's `comparison.json` retains the full event diff and its characterization.
The suite preserves these differences instead of asserting complete parity:

| Difference | Meaning |
| --- | --- |
| Shell metadata checks | Shell checks metadata before commands such as `mv` and `ls`; direct native operations omit those command-level checks. |
| Replacement write permission | Native replacement requires destination delete and write permission, as documented in the [operation meanings](../user/native-filesystem-policy.md#filesystem-operation-meanings). Shell replacement does not request destination write, so the destination-write denial pair has different decisions and file effects. |
| Directory-open outcome | Native interception records delivery of a directory descriptor. Shell records completed enumeration. The workload separately verifies the returned entries. |

These cases do not qualify macOS, cloud environments, performance, or every supported filesystem operation.
