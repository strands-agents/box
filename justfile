# Build and test Strands Box.

# Show the recipe list when run with no arguments.
default:
    @just --list

# ── Everything ───────────────────────────────────────────────────────────────

# Run the Rust suites and box examples, and report skipped tests.
test-all:
    ./scripts/test-all.sh

# Build Box Core's binaries: `strands-box`, the alias image, and the containment
# trampoline. `build-cli` builds the box CLI. Two packages, because the trampoline is
# containment's own contract and `cargo build -p strands-box` builds containment's
# library but not its binaries.
build:
    cargo build -p strands-box -p strands-box-containment --all-features

# Build the box CLI (`box`) and the Box Core binaries it runs, into target/debug.
build-cli:
    cargo build --locked -p strands-box-cli -p strands-box -p strands-box-containment --bin box --bin strands-box --bin strands-box-sock-alias --bin strands-box-contain-trampoline

# Build the release binaries into target/release, where they run in place.
release:
    cargo build --release -p strands-box -p strands-box-containment

# The full pre-push gate: format check, clippy, the CLI prose check, and tests.
check: fmt-check clippy prose test

# ── Rust ───────────────────────────────────────────────────────────────────────

# Test the whole Rust workspace. The CLI's tests run the built `box` and Box Core binaries.
test: build-cli
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

# ── box CLI ────────────────────────────────────────────────────────────────────

# Check the prose in the CLI's user docs, design docs, and pack, plugin, and policy READMEs for dashes, emoji, and filler words.
prose:
    git ls-files -z --cached --others --exclude-standard 'docs/cli/*.md' 'docs/design/cli/*.md' 'resources/packs/*/README.md' 'resources/plugins/*/README.md' 'resources/policies/*/README.md' | xargs -0 scripts/check-prose.sh

# Build the CLI, then run its suite that drives a real engine.
test-engine: build-cli
    cargo test -p strands-box-cli --all-features --test engine -- --nocapture

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

