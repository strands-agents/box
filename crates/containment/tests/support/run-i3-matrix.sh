#!/bin/zsh
# Drive every second-view route through one contained process, and print the raw kernel outcome.
#
# Each case rebuilds the fixture and runs ONE probe under `expect-ok`, so the exit code reports
# what the kernel did rather than a pass or a fail:
#
#   PERMITTED     the operation succeeded
#   REFUSED       the kernel refused it, with EPERM or EACCES
#   INCONCLUSIVE  the probe could not attempt it, so it measures no rule
#   HANG          the call did not return inside 30 seconds
#
# Usage: PROBE=<path to containment-test-probe> zsh run-i3-matrix.sh
set -u
PROBE=${PROBE:-$(pwd)/target/debug/containment-test-probe}
# An ungranted file the operator owns, inside the home the box's own syscalls cannot reach. It is
# NOT a secret by default: a real key would be hard-linked into the fixture by section H, and on the
# HANG path the script kills the probe and the link outlives it until the EXIT trap. Point SECRET at
# a key only when that is what you mean to measure.
SECRET=${SECRET:-$HOME/.zshrc}
LOG=${LOG:-/tmp/i3-matrix.log}
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
if [[ ! -r $SECRET ]]; then
  print -u2 "no readable ungranted file at $SECRET; set SECRET to one this user owns"
  exit 2
fi

ROOT=$(mktemp -d)
ROOT=$(cd "$ROOT" && pwd -P)
trap 'rm -rf "$ROOT"' EXIT
FIRM="/System/Volumes/Data$ROOT"
# 12 is more than the fixture's depth. A `..` at `/` stays at `/`, so an over-count is harmless
# and an under-count answers ENOENT instead of measuring a rule.
UP="../../../../../../../../../../../.."

rebuild() {
  rm -rf "$ROOT/home"
  mkdir -p "$ROOT/home"
  print "inner" > "$ROOT/home/inner.txt"
  print -- '-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----' > "$ROOT/proxy-ca.pem"
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
    ],
    "write_protections": [],
    "identity_requirements": [],
    "network": {"localhost": {"connect": [43123], "listen": []}},
    "process": {"signals": "isolated", "info": "isolated", "ipc": "shared_memory_only"},
    "backend_override": "none",
}, open(root + "/containment.json", "w"))
PY
}

run() {
  local id="$1" spec="$2"
  rebuild
  local out="$ROOT/case.out"
  : > "$out"
  "$PROBE" "$ROOT/containment.json" "expect-ok:$spec" > "$out" 2>&1 &
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
  printf '%-24s %-14s %s\n' "$id" "$verdict" \
    "$(grep -v '^probe ok:\|^probe FAILED:' "$out" | tr '\n' ' ' | cut -c1-110)"
  { print "### $id  $verdict  ($spec)"; cat "$out"; print; } >> "$LOG"
  # PERMITTED and REFUSED are both data. Everything else means the case measured no rule.
  case $verdict in
    PERMITTED | REFUSED) ;;
    *) (( UNMEASURED += 1 )) ;;
  esac
}

print "host: $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)  euid=$(id -u)"
print "fixture: $ROOT   probe: $PROBE"
print

print "== A. a granted read, reached through another spelling of the same object"
run A1-canonical     "read-errno:$ROOT/proxy-ca.pem"
run A2-firmlink      "read-errno:$FIRM/proxy-ca.pem"
run A3-case          "read-errno:$ROOT/PROXY-CA.PEM"
run A4-dotdot        "read-errno:$ROOT/home/../proxy-ca.pem"
run A5-doubleslash   "read-errno:$ROOT//proxy-ca.pem"

print "== B. a write inside the granted root, through another spelling"
run B1-canonical     "write:$ROOT/home/b1.txt"
run B2-firmlink      "write:$FIRM/home/b2.txt"
run B3-case          "write:$ROOT/HOME/b3.txt"
run B4-dotdot        "write:$ROOT/home/../home/b4.txt"

print "== C. remove the granted root itself, through another spelling"
run C1-canonical     "rmdir:$ROOT/home"
run C2-firmlink      "rmdir:$FIRM/home"
run C3-case          "rmdir:$ROOT/HOME"
run C4-dotdot        "rmdir:$ROOT/home/../home"
run C5-trailing      "rmdir:$ROOT/home/"

print "== D. leave a symbolic link at the granted root, through another spelling"
run D1-canonical     "create-over:$ROOT/home"
run D2-firmlink      "create-over:$FIRM/home"
run D3-case          "create-over:$ROOT/HOME"
run D4-dotdot        "create-over:$ROOT/home/../home"

print "== E. set a BSD file flag inside the granted root, through another spelling"
run E1-canonical     "chflags-uf:$ROOT/home/inner.txt"
run E2-firmlink      "chflags-uf:$FIRM/home/inner.txt"
run E3-case          "chflags-uf:$ROOT/HOME/inner.txt"
run E4-dotdot        "chflags-uf:$ROOT/home/../home/inner.txt"
run E5-root-firmlink "chflags-uf:$FIRM/home"

print "== F. an ungranted object, reached through another spelling"
run F1-etc           "read-errno:/private/etc/hosts"
run F2-etc-firmlink  "read-errno:/System/Volumes/Data/private/etc/hosts"
run F3-secret        "read-errno:$SECRET"
run F4-secret-firm   "read-errno:/System/Volumes/Data$SECRET"
run F5-raw-disk      "read-errno:/dev/disk0"

print "== G. apply a second, permissive profile"
run G1-loosen-etc    "sandbox-loosen:/private/etc/hosts"
run G2-loosen-secret "sandbox-loosen:$SECRET"

print "== H. hard-link an ungranted file into the granted root"
run H1-etc           "link:/private/etc/hosts|$ROOT/home/hosts.hard"
run H2-secret        "link:$SECRET|$ROOT/home/key.hard"
run H3-secret-firm   "link:/System/Volumes/Data$SECRET|$ROOT/home/key2.hard"
run H4-granted       "link:$ROOT/proxy-ca.pem|$ROOT/home/ca.hard"

print "== I. read through a symbolic link the box created inside the granted root"
run I1-etc           "symlink-escape:$ROOT/home/etc.link|/private/etc/hosts"
run I2-secret        "symlink-escape:$ROOT/home/key.link|$SECRET"
run I3-parent        "symlink-escape:$ROOT/home/up.link|$ROOT"
run I4-granted       "symlink-escape:$ROOT/home/ca.link|$ROOT/proxy-ca.pem"

print "== J. resolve a relative name from a descriptor on the granted root"
run J1-inside        "openat-escape:$ROOT/home|inner.txt"
run J2-parent        "openat-escape:$ROOT/home|../proxy-ca.pem"
run J3-etc           "openat-escape:$ROOT/home|$UP/private/etc/hosts"
run J4-secret        "openat-escape:$ROOT/home|$UP$SECRET"
run J5-secret-firm   "openat-escape:$ROOT/home|$UP/System/Volumes/Data$SECRET"

print "== K. ask a root daemon to change the view"
run K1-diskarb       "mach-lookup:com.apple.DiskArbitration.diskarbitrationd"
run K2-notify        "mach-lookup:com.apple.system.notification_center"
run K3-directory     "mach-lookup:com.apple.system.opendirectoryd.api"

print "== L. change the view directly. As an ordinary user the privilege check answers first"
run L1-mount-root    "mount:$ROOT/home"
run L2-mount-slash   "mount:/"
run L3-unmount-data  "unmount:/System/Volumes/Data"
run L4-chroot        "chroot:$ROOT/home"

print
print "residue: $(ls -A "$ROOT/home" | tr '\n' ' ')"
print "flags:   $(stat -f '%Xf %N' "$ROOT/home" "$ROOT/home/inner.txt" | tr '\n' ' ')"
print "log:     $LOG"

if (( UNMEASURED > 0 )); then
  print -u2 "$UNMEASURED case(s) measured no rule. Read $LOG."
  exit 1
fi
