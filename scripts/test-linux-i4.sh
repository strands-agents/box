#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-${root}/target}"
containment_log="${target_dir}/linux-i4-containment.log"
production_log="${target_dir}/linux-i4-production.log"

mkdir -p "${target_dir}"

cargo build \
  --manifest-path "${root}/Cargo.toml" \
  -p strands-box-containment \
  --bin strands-box-contain-trampoline \
  --all-features

cargo test \
  --manifest-path "${root}/Cargo.toml" \
  -p strands-box-containment \
  --test inherited_handles_linux \
  --all-features \
  -- \
  --nocapture 2>&1 | tee "${containment_log}"

cargo test \
  --manifest-path "${root}/Cargo.toml" \
  -p strands-box \
  --test box_inherited_handles \
  --all-features \
  -- \
  --nocapture 2>&1 | tee "${production_log}"

if grep -Fq "skipping:" "${containment_log}" "${production_log}"; then
  echo "Linux I4 proof skipped on this host." >&2
  exit 1
fi
