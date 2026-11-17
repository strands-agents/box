#!/usr/bin/env bash
# Run the Rust workspace tests and the box examples.
# Usage: scripts/test-all.sh [rust | box-examples ...]

set -uo pipefail
cd "$(dirname "$0")/.."

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$1"; }
err()  { printf '\033[31m✗ %s\033[0m\n' "$1"; }

failures=0

# Which sections to run. No argument means every one.
if [ "$#" -eq 0 ]; then
  sections="rust box-examples"
else
  sections="$*"
fi
for section in $sections; do
  case "$section" in
    rust | box-examples) ;;
    *) err "unknown test section: $section"; exit 2 ;;
  esac
done
want() { case " $sections " in *" $1 "*) return 0;; *) return 1;; esac; }
bold "== Sections: $sections =="
log_dir=$(mktemp -d "${TMPDIR:-/tmp}/strands-tests.XXXXXX") || exit 1
printf 'Logs: %s\n' "$log_dir"

# --- 1. Rust workspace -------------------------------------------------------
if want rust; then
bold "== Rust workspace (cargo test --workspace --all-features) =="
# Report skipped tests from their captured output.
rust_log="$log_dir/rust.log"
if cargo test --workspace --all-features --no-fail-fast -- --nocapture 2>&1 | tee "$rust_log"; then
  ok "Rust workspace passed"
else
  err "Rust workspace FAILED"; failures=$((failures + 1))
fi
if grep -q "skipping:" "$rust_log"; then
  warn "The Rust suite skipped tests:"
  grep "skipping:" "$rust_log" | sort -u | sed 's/^/    /'
fi
fi

# --- Box examples ----------------------------------------------------------
if want box-examples; then
bold "== Shipped examples =="
if cargo build -p strands-box -p strands-box-containment --all-features >"$log_dir/build.log" 2>&1; then

  # Each `examples/strands-box/*` example owns its own script and its own assertions.
  for script in examples/strands-box/*/run.sh; do
    if [ ! -f "$script" ]; then
      warn "No scripted examples remain. Run the SDK tutorial manually."
      continue
    fi
    name=$(basename "$(dirname "$script")")
    # Retain each example's output and continue through failures.
    ( cd "$(dirname "$script")" && ./run.sh ) >"$log_dir/example-$name.log" 2>&1
    status=$?
    if [ "$status" -eq 0 ]; then
      ok "example $name"
    else
      err "example $name FAILED (exit $status) — $log_dir/example-$name.log"
      failures=$((failures + 1))
    fi
  done

else
  err "the examples build failed — $log_dir/build.log"
  failures=$((failures + 1))
fi
fi

# --- summary -----------------------------------------------------------------
echo
if [ "$failures" -eq 0 ]; then
  bold "All suites that ran passed. Re-check the ⚠ warnings above — a skipped suite is untested, not passing."
  exit 0
else
  err "$failures suite(s) failed."
  exit 1
fi
