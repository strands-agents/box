#!/usr/bin/env bash
# Run Linux kernel tests with privileges confined to the test processes.
set -euo pipefail
if [[ $(uname -s) != Linux || $(uname -m) != aarch64 ]]; then
    echo "Linux native filesystem tests require an ARM64 Linux host." >&2
    exit 1
fi
repo=$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]}")")")
cd "$repo"
sudo -n true
export NATIVE_TEST_ROOT=${NATIVE_TEST_ROOT:-$(mktemp -d /var/tmp/box-native-tests.XXXXXXXX)}
mkdir -p "$NATIVE_TEST_ROOT"
echo "Native test fixtures: $NATIVE_TEST_ROOT"
# Cargo invokes this runner for tests, while builds retain the caller's privileges.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="sudo -n setpriv --reuid=$(id -u) --regid=$(id -g) --clear-groups --bounding-set=-all,+bpf,+perfmon --inh-caps=-all,+bpf,+perfmon --ambient-caps=-all,+bpf,+perfmon --no-new-privs env EXPERIMENTAL_LINUX_SUPPORT=TRUE NATIVE_TEST_ROOT=$NATIVE_TEST_ROOT"
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="--cfg box_native_kernel_tests"
cargo build --locked --target aarch64-unknown-linux-gnu -p strands-box -p strands-box-containment --all-features
cargo test --locked --target aarch64-unknown-linux-gnu -p strands-box --all-features --lib run::native_enforcement:: -- --nocapture --test-threads=1
cargo test --locked --target aarch64-unknown-linux-gnu -p strands-box --all-features --test linux_native_research --test linux_native_paths --test linux_native_directories --test linux_native_failures -- --nocapture --test-threads=1
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="sudo -n env EXPERIMENTAL_LINUX_SUPPORT=TRUE NATIVE_TEST_ROOT=$NATIVE_TEST_ROOT" \
  cargo test --locked --target aarch64-unknown-linux-gnu -p strands-box --all-features --test linux_native_root
export RUSTFLAGS="--cfg box_native_kernel_tests --cfg box_native_test_faults"
cargo build --locked --target aarch64-unknown-linux-gnu -p strands-box -p strands-box-containment --all-features
cargo test --locked --target aarch64-unknown-linux-gnu -p strands-box --all-features --test linux_native_failures --test linux_native_entry_races -- --nocapture --test-threads=1
