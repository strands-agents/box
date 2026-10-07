#!/bin/bash
# deterministic/run.sh — run the Rust deterministic suite and emit verdict.json.
#
# Each #[test] under tests/ writes its own row; emit-verdict reduces them into
# $DET_RESULTS_DIR/verdict.json (default ~/det-results) — the pipeline contract.
# Drop-in for the old bash run.sh; the bootstrap calls this unchanged.
#
# Usage:
#   ./run.sh                 # whole suite
#   ./run.sh PO-9            # cargo test filter (substring match on test names)
#   ./run.sh --list          # list case files
#
# Exit status: 0 GREEN, 1 RED, including when cargo could not build or run the
# suite — the verdict is then RED with the reason under integrity.problems, and a
# filtered run (a subset of cases) is RED because the manifest's other cases have
# no row.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HOME/.cargo/env" 2>/dev/null || true

if [ "${1:-}" = "--list" ]; then
  find "$HERE/tests" -mindepth 2 -name '*.rs' 2>/dev/null | sort | sed "s#$HERE/tests/##"
  exit 0
fi

export DET_RESULTS_DIR="${DET_RESULTS_DIR:-$HOME/det-results}"
mkdir -p "$DET_RESULTS_DIR"
find "$DET_RESULTS_DIR" -maxdepth 1 -name '*.jsonl' -delete 2>/dev/null || true
rm -f "$DET_RESULTS_DIR/verdict.json" "$DET_RESULTS_DIR/cargo-test.log" 2>/dev/null || true

# Each case keeps its box directory until the suite ends (see README.md), so the
# run's boxes go under one directory that is removed on exit.
mkdir -p "$HOME/.det-harness-boxes"
DET_BOX_ROOT="$(mktemp -d "$HOME/.det-harness-boxes/run-XXXXXX")" || exit 1
export DET_BOX_ROOT
trap 'rm -rf "$DET_BOX_ROOT"' EXIT

# Tests self-record rows even on failure. --no-fail-fast so BOTH test binaries
# (policy, containment) run and record every row even when one has failures;
# otherwise cargo stops at the first failing binary and verdict.json is partial.
# Cargo's own exit status is kept and handed to emit-verdict: a build error, a
# crashed test binary, or a failure no row explains must not reduce to GREEN.
( cd "$HERE" && cargo test --release --no-fail-fast "$@" ) 2>&1 | tee "$DET_RESULTS_DIR/cargo-test.log"
CARGO_STATUS=${PIPESTATUS[0]}
echo "[run.sh] cargo test exit status: $CARGO_STATUS"

# Reduce rows -> verdict.json; exit code mirrors GREEN(0)/RED(1). If emit-verdict
# itself cannot build or run, write a RED verdict so no caller reads silence as a pass.
( cd "$HERE" && DET_CARGO_STATUS="$CARGO_STATUS" cargo run --release --quiet --bin emit-verdict )
status=$?
if [ "$status" -ne 0 ]; then
  if [ ! -f "$DET_RESULTS_DIR/verdict.json" ]; then
    printf '{"platform":"%s","box_commit":"unknown","verdict":"RED","counts":{"total":0,"pass":0,"fail":0,"error":0,"skip":0},"integrity":{"cargo_status":%s,"expected":0,"recorded":0,"problems":["emit-verdict did not run (exit %s)"]},"results":[]}\n' \
      "${PLATFORM:-$(uname | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')}" "$CARGO_STATUS" "$status" > "$DET_RESULTS_DIR/verdict.json"
  fi
  exit 1
fi
