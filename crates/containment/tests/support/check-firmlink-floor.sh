#!/bin/zsh
# What does a grant authored in the firmlink spelling do?
#
# `FORBIDDEN_PATHS` compares a grant's canonical path against each anchor. `realpath` collapses a
# symbolic link and does NOT collapse a firmlink, so `/System/Volumes/Data/Users/<user>/.ssh` and
# `/Users/<user>/.ssh` are two canonical names for one directory. Two questions follow, and they
# have different answers:
#
#   1. Does the deny-only floor refuse the firmlink spelling of a credential store?
#   2. Does a rule rendered from a firmlink-spelled grant match anything in the kernel?
#
# Usage: PROBE=<path to containment-test-probe> zsh check-firmlink-floor.sh
set -u
PROBE=${PROBE:-$(pwd)/target/debug/containment-test-probe}
STORE=${STORE:-$HOME/.ssh}
SECRET=${SECRET:-$HOME/.ssh/id_ecdsa}
# The home the config's grants resolve against, which `ContainmentConfig` requires. This script
# grants paths under the operator's own home, so the stated home is that home.
OPERATOR_HOME=${OPERATOR_HOME:-$(cd -- "$HOME" && pwd -P)}
# A probe that could not attempt its read measures no rule, so the script fails rather than printing
# INCONCLUSIVE beside a zero exit.
UNMEASURED=0

if [[ ! -x $PROBE ]]; then
  print -u2 "no probe at $PROBE"
  exit 2
fi
PROBE=$(cd "${PROBE:h}" && print -r -- "$(pwd -P)/${PROBE:t}")

ROOT=$(mktemp -d)
ROOT=$(cd "$ROOT" && pwd -P)
trap 'rm -rf "$ROOT"' EXIT
FIRM="/System/Volumes/Data$ROOT"
print -r -- '-----BEGIN CERTIFICATE-----' > "$ROOT/proxy-ca.pem"

# $1 is the read-write root the config names, $2 an extra read root or the empty string.
write_config() {
  python3 - "$ROOT" "$PROBE" "$1" "$2" "$OPERATOR_HOME" <<'PY'
import json, sys, os
root, probe, home, extra = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
operator_home = sys.argv[5]
def grant(path, operation, scope):
    return {"original": path, "resolved": os.path.realpath(path),
            "operation": operation, "scope": scope}
paths = [grant(probe, "exec", "file"),
         grant(root + "/proxy-ca.pem", "read", "file"),
         grant(home, "read", "root"),
         grant(home, "write", "root")]
if extra:
    paths.append(grant(extra, "read", "root"))
json.dump({"operator_home": operator_home,
           "paths": paths,
           "write_protections": [],
           "identity_requirements": [],
           "network": {"localhost": {"connect": [43123], "listen": []}},
           "process": {"signals": "isolated", "info": "isolated",
                       "ipc": "shared_memory_only"},
           "backend_override": "none"}, open(root + "/c.json", "w"))
PY
}

# $1 label, $2 read-write root, $3 extra read root, $4 path the probe reads
attempt() {
  rm -rf "$ROOT/home"
  mkdir -p "$ROOT/home"
  print -r -- "inner" > "$ROOT/home/inner.txt"
  write_config "$2" "$3"
  local out="$ROOT/out.txt"
  "$PROBE" "$ROOT/c.json" "expect-ok:read-errno:$4" > "$out" 2>&1
  local code=$?
  local verdict
  case $code in
    0) verdict="PERMITTED" ;;
    1) verdict="REFUSED by the kernel" ;;
    2) verdict="INCONCLUSIVE" ;;
    3) verdict="REFUSED before apply (a floor or a validation)" ;;
    *) verdict="exit $code" ;;
  esac
  print -r -- "$1"
  print -r -- "   verdict: $verdict"
  print -r -- "   $(tail -1 "$out")"
  # Codes 0, 1 and 3 are all answers: permitted, refused by the kernel, refused by a floor. Code 2
  # and anything else mean the case measured no rule.
  case $code in
    0 | 1 | 3) ;;
    *) (( UNMEASURED += 1 )) ;;
  esac
}

print -r -- "realpath of both spellings:"
python3 -c "import os,sys; [print('  ', p, '->', os.path.realpath(p)) for p in sys.argv[1:]]" \
  "$STORE" "/System/Volumes/Data$STORE" "$ROOT/home" "$FIRM/home"
print

print -r -- "Q1. the floor, on a credential store"
attempt "  control: grant read root on $STORE" "$ROOT/home" "$STORE" "$SECRET"
attempt "  test:    grant read root on /System/Volumes/Data$STORE" \
  "$ROOT/home" "/System/Volumes/Data$STORE" "/System/Volumes/Data$SECRET"
attempt "  test:    the same grant, read by the ORDINARY spelling" \
  "$ROOT/home" "/System/Volumes/Data$STORE" "$SECRET"
print

print -r -- "Q2. what a firmlink-spelled grant renders, on a path no floor covers"
attempt "  control: grant the fixture home canonically, read inside it" \
  "$ROOT/home" "" "$ROOT/home/inner.txt"
attempt "  test:    grant the fixture home by its firmlink spelling, read inside it" \
  "$FIRM/home" "" "$FIRM/home/inner.txt"

if (( UNMEASURED > 0 )); then
  print -u2 "$UNMEASURED case(s) measured no rule."
  exit 1
fi
