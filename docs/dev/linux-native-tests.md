# Linux native filesystem tests

The kernel tests compile separately from product activation. Ordinary Linux builds still refuse native filesystem policy.

Run component tests on a Linux system with the required kernel hooks and loader capabilities:

```sh
RUSTFLAGS="--cfg box_native_kernel_tests" cargo test -p strands-box --lib --all-features run::native_enforcement:: -- --test-threads=1
```

The runner needs CAP_BPF and CAP_PERFMON. Use a dedicated test process. Guard preparation removes these capabilities from that process.

The tests use actual notification listeners and kernel hooks. A missing prerequisite is a test failure, not evidence of support.
