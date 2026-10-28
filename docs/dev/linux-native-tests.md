# Linux native filesystem tests

The kernel tests compile separately from product activation. Ordinary Linux builds still refuse native filesystem policy.

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
