#!/bin/zsh
# Drive every write-xor-exec route through one contained process, and print the raw kernel outcome.
#
# Write-xor-exec means no path a box can reach is both write-accessible and execute-accessible.
# "Execute" means three things, and each has its own section below — running a file, loading it as a
# library, and running it through a permitted interpreter. Each case rebuilds the fixture and runs ONE
# probe under `expect-ok`, so the exit code reports what the kernel did rather than a pass or a fail:
#
#   PERMITTED     the operation succeeded
#   REFUSED       the kernel refused it
#   INCONCLUSIVE  the probe could not attempt it, so it measures no rule
#   HANG          the call did not return inside 30 seconds
#
# Every deny case has its uncontained control beside it, because macOS refuses an image for its own
# reasons: code signing answers EPERM as readily as the profile does, and a refusal inside a box means
# the profile only when the same route is PERMITTED outside one.
#
# Usage: PROBE=<path to containment-test-probe> zsh run-i1-matrix.sh
set -u
PROBE=${PROBE:-$(pwd)/target/debug/containment-test-probe}
LOG=${LOG:-/tmp/i1-matrix.log}
: > "$LOG"

# The home the config's grants resolve against, which `ContainmentConfig` requires. `boundary.rs`
# states it in production, so stating it here renders the profile shape a real box renders. The
# fixture below sits outside it, so the home's own rules reach none of these cases.
OPERATOR_HOME=${OPERATOR_HOME:-$(cd -- "$HOME" && pwd -P)}

# A probe that could not attempt its operation measures no rule, so the script fails rather than
# printing INCONCLUSIVE beside a zero exit.
UNMEASURED=0

if [[ ! -x $PROBE ]]; then
  print -u2 "no probe at $PROBE; build it with --all-features first, or set PROBE"
  exit 2
fi
PROBE=$(cd "${PROBE:h}" && print -r -- "$(pwd -P)/${PROBE:t}")

# An on-disk dynamic library to seed the load cases with. Most of `/usr/lib` lives only in the dyld
# shared cache, so the first candidate that is a real file wins, and none being present is a reason to
# skip those sections rather than to report a refusal.
DYLIB=""
for candidate in /usr/lib/libffi-trampolines.dylib /usr/lib/libobjc-trampolines.dylib /usr/lib/libRPAC.dylib; do
  if [[ -f $candidate ]]; then DYLIB=$candidate; break; fi
done

ROOT=$(mktemp -d)
ROOT=$(cd "$ROOT" && pwd -P)
trap 'rm -rf "$ROOT"' EXIT

rebuild() {
  rm -rf "$ROOT/home"
  # `.tmp` is `TMPDIR`, and it is inside the home rather than a grant of its own, so a case that
  # writes there measures the same rule at a deeper path.
  mkdir -p "$ROOT/home/.tmp"
  # The seeds live in the home, because the home is the one tree the box can read AND write. An exec
  # grant renders `file-read-metadata` and never `file-read*`, so the probe cannot read its own image.
  cp "$PROBE" "$ROOT/home/seed.bin"
  if [[ -n $DYLIB ]]; then cp "$DYLIB" "$ROOT/home/seed.dylib"; fi
  print -- '-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----' > "$ROOT/proxy-ca.pem"
  mkdir -p "$ROOT/runner"
  if [[ -n $DYLIB ]]; then cp "$DYLIB" "$ROOT/runner/library.dylib"; fi
  python3 - "$ROOT" "$PROBE" "$OPERATOR_HOME" <<'PY'
import json, sys, os
root, probe, operator_home = sys.argv[1], sys.argv[2], sys.argv[3]
def grant(path, operation, scope):
    return {"original": path, "resolved": os.path.realpath(path),
            "operation": operation, "scope": scope}
json.dump({
    "operator_home": operator_home,
    "paths": [
        grant(probe, "exec", "file"),
        grant(root + "/proxy-ca.pem", "read", "file"),
        grant(root + "/home", "read", "root"),
        grant(root + "/home", "write", "root"),
        # A read-only root, which is where every runtime library a workload needs comes from. It is
        # the control for section B: the executable-mapping deny must not reach it.
        grant(root + "/runner", "read", "root"),
    ],
    "write_protections": [],
    "identity_requirements": [],
    "network": {"localhost": {"connect": [43123], "listen": []}},
    "process": {"signals": "isolated", "info": "isolated", "ipc": "shared_memory_only"},
    "backend_override": "none",
}, open(root + "/containment.json", "w"))
PY
}

# `run <id> <spec>` measures inside a box; `control <id> <spec>` measures with no containment at all.
measure() {
  local id="$1" spec="$2" mode="$3"
  rebuild
  local out="$ROOT/case.out"
  : > "$out"
  if [[ $mode == control ]]; then
    "$PROBE" --uncontained "expect-ok:$spec" > "$out" 2>&1 &
  else
    "$PROBE" "$ROOT/containment.json" "expect-ok:$spec" > "$out" 2>&1 &
  fi
  local pid=$! waited=0 code=""
  while (( waited < 60 )); do
    if ! kill -0 $pid 2>/dev/null; then wait $pid; code=$?; break; fi
    sleep 0.5
    (( waited += 1 ))
  done
  local verdict
  if [[ -z $code ]]; then
    kill -9 $pid 2>/dev/null
    verdict="HANG"
  else
    case $code in
      0) verdict="PERMITTED" ;;
      1) verdict="REFUSED" ;;
      2) verdict="INCONCLUSIVE" ;;
      3) verdict="APPLY-FAILED" ;;
      *) verdict="code=$code" ;;
    esac
  fi
  printf '%-26s %-14s %s\n' "$id" "$verdict" \
    "$(grep -v '^probe ok:\|^probe FAILED:\|^uncontained:' "$out" | tr '\n' ' ' | cut -c1-100)"
  { print "### $id  $verdict  ($mode: $spec)"; cat "$out"; print; } >> "$LOG"
  # PERMITTED and REFUSED are both data. Everything else means the case measured no rule.
  case $verdict in
    PERMITTED | REFUSED) ;;
    *) (( UNMEASURED += 1 )) ;;
  esac
}

run()     { measure "$1" "$2" boxed; }
control() { measure "$1" "$2" control; }

print "host: $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)  euid=$(id -u)"
print "fixture: $ROOT   probe: $PROBE"
print "dylib seed: ${DYLIB:-none found; sections B and C skip}"
print

print "== A. run a file the box wrote into its own write root"
control A0-control          "exec-written:$ROOT/home/seed.bin|$ROOT/home/a0.bin"
run     A1-write-root       "exec-written:$ROOT/home/seed.bin|$ROOT/home/a1.bin"
run     A2-write-root-tmp   "exec-written:$ROOT/home/seed.bin|$ROOT/home/.tmp/a2.bin"

if [[ -n $DYLIB ]]; then
  print "== B. load a library the box wrote into its own write root"
  control B0-control        "dlopen-written:$ROOT/home/seed.dylib|$ROOT/home/b0.dylib"
  run     B1-write-root     "dlopen-written:$ROOT/home/seed.dylib|$ROOT/home/b1.dylib"
  # The bound. A read-only root must keep loading libraries, or the deny is a refuse-all: this is
  # the CPython-stdlib case, and it must stay PERMITTED. It loads without writing, because a
  # read-only root refuses the write and a written destination would measure that instead.
  run     B2-read-only-root "dlopen:$ROOT/runner/library.dylib"
  # And the same library inside the WRITE root must be refused, so the difference between B2 and B3
  # is the cell rather than the library.
  run     B3-write-root-copy "dlopen:$ROOT/home/seed.dylib"

  print "== C. map a written file executable directly, without dyld"
  control C0-control        "map-exec:$ROOT/home/seed.dylib|$ROOT/home/c0.dylib"
  run     C1-write-root     "map-exec:$ROOT/home/seed.dylib|$ROOT/home/c1.dylib"
fi

print "== D. reach an executable through the write root by another name"
# The floor refuses an exec grant inside a write root, so these ask whether a name the box creates
# inside the root reaches one anyway. Both are expected REFUSED: the profile names no exec literal
# under the home, and a link does not create one.
run     D1-symlink-to-host  "symlink-escape:$ROOT/home/host.link|/bin/zsh"
run     D2-hardlink-probe   "link:$PROBE|$ROOT/home/probe.hard"

print
print "residue: $(ls -A "$ROOT/home" | tr '\n' ' ')"
print "log:     $LOG"

if (( UNMEASURED > 0 )); then
  print -u2 "$UNMEASURED case(s) measured no rule. Read $LOG."
  exit 1
fi
