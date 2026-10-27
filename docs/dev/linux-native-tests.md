# Linux native filesystem tests

Run native tests on a Linux system with the required kernel hooks and loader capabilities. Use ARM64 Linux for the C workload fixtures.

```sh
RUSTFLAGS="--cfg box_native_kernel_tests" cargo build -p strands-box -p strands-box-containment --all-features
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --lib --all-features run::native_enforcement:: -- --test-threads=1
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --all-features --test linux_native_paths --test linux_native_directories --test linux_native_research --test linux_native_failures -- --test-threads=1
```

The runner needs CAP_BPF and CAP_PERFMON. Use a dedicated test process. Guard preparation removes these capabilities from that process. Set `NATIVE_TEST_ROOT` to a short writable directory.

The tests use actual notification listeners and kernel hooks. A missing prerequisite is a test failure, not evidence of support. The root and callback regressions use the separate `linux_native_root` executable and require a root runner.

Rebuild with fault controls before running failure injection and replacement races:

```sh
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_test_faults" cargo build -p strands-box -p strands-box-containment --all-features
RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_test_faults" cargo test -p strands-box --all-features --test linux_native_failures --test linux_native_entry_races -- --test-threads=1
```

Keep fault-enabled binaries separate from release artifacts. Product builds do not require these private test switches. Native filesystem policy remains an explicit experimental selection.
