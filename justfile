# Build and test Strands Box.

# Show the recipe list when run with no arguments.
default:
    @just --list

# ── Everything ───────────────────────────────────────────────────────────────

# Run the Rust suites and box examples, and report skipped tests.
test-all:
    ./scripts/test-all.sh

# Build the independently resolved Dogwood 1.0.0 migration validator.
legacy-helper:
    cargo build --locked --manifest-path crates/dogwood-legacy-migration/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"

# Build the CLI, runtime helpers, and history migration validator together.
build: legacy-helper
    cargo build -p strands-box -p strands-box-containment --all-features

# Build the release binaries into target/release, where they run in place.
release:
    cargo build --release --locked --manifest-path crates/dogwood-legacy-migration/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"
    cargo build --release -p strands-box -p strands-box-containment

# The full pre-push gate for the Rust crates: format check, clippy, and tests.
check: fmt-check clippy test

# ── Rust ───────────────────────────────────────────────────────────────────────

# Test the whole Rust workspace.
test: legacy-helper
    cargo test --locked --manifest-path crates/dogwood-legacy-migration/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"
    cargo test --workspace --all-features

# Lint every crate/target; warnings are errors.
clippy:
    cargo clippy --locked --manifest-path crates/dogwood-legacy-migration/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}" --all-targets -- -D warnings
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format all Rust code in place.
fmt:
    cargo fmt --manifest-path crates/dogwood-legacy-migration/Cargo.toml
    cargo fmt --all

# Check formatting without modifying files (CI gate).
fmt-check:
    cargo fmt --manifest-path crates/dogwood-legacy-migration/Cargo.toml --check
    cargo fmt --all --check

# ── Test-harness crates (excluded from the workspace) ──────────────────────────

# The verdict layer's gate, mirroring .github/workflows/verdict-hermetic.yml.
#
# `check` above cannot cover these: `test-common` and `test-workload/verdict` are
# excluded from the root workspace (see Cargo.toml) because they read the BUILT box's
# artefacts as data and must not be pulled into `cargo build --workspace`. They each
# carry their own lockfile, so there is no single `--workspace` invocation that reaches
# them, and the CI leg that does is BLOCKING — run this before pushing a change to
# either, or the first signal you get will be a red PR.
verdict:
    cd test-common && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --locked --all-features
    cd test-workload/verdict && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --locked --all-features

