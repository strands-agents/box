# Linux native filesystem tests

Compile the kernel tests independently of product activation. Ordinary Linux builds still refuse native filesystem policy.

Run component tests on a Linux system with the required kernel hooks and loader capabilities:

```sh
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --lib --all-features run::native_enforcement:: -- --test-threads=1
```

The runner needs CAP_BPF and CAP_PERFMON. Use a dedicated test process. Guard preparation removes these capabilities from that process.

The tests use actual notification listeners and kernel hooks. A missing prerequisite is a test failure, not evidence of support.

The operation suites use the shared launcher under a private build switch. This avoids a separate implementation of workload setup.

```sh
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_adapter_tests" cargo build -p strands-box -p strands-box-containment --all-features
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_adapter_tests" cargo test -p strands-box --all-features --test linux_native_paths --test linux_native_directories --test linux_native_policy_semantics -- --test-threads=1
```

Set `NATIVE_TEST_ROOT` to a short writable directory. The C fixtures require ARM64 Linux. Rebuild with `--cfg box_native_test_faults` added, then select the race suite explicitly:

```sh
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_adapter_tests --cfg box_native_test_faults" cargo test -p strands-box --all-features --test linux_native_entry_races -- --test-threads=1
```

Keep test binaries separate from release artifacts. Without `box_native_adapter_tests`, the Linux product adapter remains unavailable, including with all Cargo features enabled.

## Forwarding buffer tests

Run the three containment supervisor tests on Linux:

```sh
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg box_native_adapter_tests" cargo test --locked -p strands-box-containment --lib --all-features backend::linux::namespace::filesystem_queries::forwarding_tests:: -- --test-threads=1
```

These tests create their own kernel notification listener. They do not need the kernel loader
capabilities required by the operation suites. The tests check that a full forwarding buffer pauses
request delivery, preserves the pending request, and still lets the supervisor detect workload exit.
Linux CI runs this command separately from the workspace tests and requires all three tests to pass.
The ordinary workspace command does not enable the private `box_native_adapter_tests` switch.

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
