# Build and test Strands Box.

# Show the recipe list when run with no arguments.
default:
    @just --list

# ── Everything ───────────────────────────────────────────────────────────────

# Run the Rust suites and box examples, and report skipped tests.
test-all:
    ./scripts/test-all.sh

# Build every binary the box needs: the CLI, the alias image, and the containment
# trampoline. Two packages, because the trampoline is containment's own contract and
# `cargo build -p strands-box` builds containment's library but not its binaries.
build:
    cargo build -p strands-box -p strands-box-containment --all-features

# Build the release binaries into target/release, where they run in place.
release:
    cargo build --release -p strands-box -p strands-box-containment

# The full pre-push gate for the Rust crates: format check, clippy, and tests.
check: fmt-check clippy test

# ── Rust ───────────────────────────────────────────────────────────────────────

# Test the whole Rust workspace.
test:
    cargo test --workspace --all-features

# Lint every crate/target; warnings are errors.
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format all Rust code in place.
fmt:
    cargo fmt --all

# Check formatting without modifying files (CI gate).
fmt-check:
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

