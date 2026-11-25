#!/usr/bin/env bash
# Run one corpus bench job's cells on the scripted layer. .github/workflows/corpus.yml calls this.
# Usage: bench-cells.sh OUT. Reads SECTION, and IDS, SHARD and NO_SKIP when they are set.
set -euo pipefail
out=$1
mkdir -p "$out"
args=(--layer scripted --install-profiles --timeout 900 --out "$out")
if [ -n "${SECTION:-}" ]; then args+=(--section "$SECTION"); fi
if [ -n "${SHARD:-}" ]; then args+=(--shard "$SHARD"); fi
if [ "${NO_SKIP:-false}" = true ]; then args+=(--no-skip); fi
# Split IDS on commas and spaces, with no globbing. macOS's bash 3.2 has no safe empty array.
set -f
ids=$(printf '%s' "${IDS:-}" | tr ',' ' ')
for id in $ids; do
  case $id in [A-Z]*-[0-9]*) ;; *) echo "not a cell id: $id" >&2; exit 2 ;; esac
done
if [ -n "${ids// /}" ]; then args+=(--ids $ids); fi
set +f
python3 "$(dirname "$0")/run_corpus.py" "${args[@]}" 2>&1 | tee "$out/run.log"
