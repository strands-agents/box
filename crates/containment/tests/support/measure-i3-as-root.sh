#!/bin/zsh
# The `chroot(2)` measurement, which needs root and therefore no test.
#
# `chroot` reaches the privilege check BEFORE the profile, so as an ordinary user it returns EPERM
# whether or not the profile refuses it. Run as root the privilege check passes and the profile is
# what answers.
#
#   cargo build -p strands-box-containment --all-features --bins
#   sudo crates/containment/tests/support/measure-i3-as-root.sh
#
# Every probe must print `probe ok` and the script must exit 0. Record the macOS build, the
# architecture and the result in crates/containment/AGENTS.md.
#
# `--control` is the other half, and it also needs root. Refused-as-root alone does not say WHAT
# refused, so the control runs `chroot(2)` as root OUTSIDE any box: it must succeed there.
#
# **`mount` and `unmount` are deliberately not here, and the `mount`/`unmount` probe verbs stay
# script-only.** Neither has a root probe that is both safe and conclusive:
#
#   - `mount_probe` passes a NULL `data` pointer, so as root the privilege check passes and the apfs
#     VFS rejects the arguments. The probe reports that as an error, correctly, because an argument
#     rejection is not the profile refusing. Building a valid apfs mount argument would mount a real
#     filesystem over a live path on the operator's machine.
#   - `unmount` of a live volume returns EBUSY, which is again not the profile. Forcing it would tear
#     down the running system.
#
# So `the_rendered_profile_grants_exactly_these_operations_and_no_others` is what closes `file-mount`
# and `file-unmount` for root, and this script does not claim to cover them.
set -e

if [[ ${1:-} == --control ]]; then
  if [[ $(id -u) -ne 0 ]]; then
    print -u2 "the control needs root as well"
    exit 2
  fi
  # The control asks one question: does `chroot(2)` succeed for root with no containment applied? A
  # yes attributes the boxed refusal to the profile. Two things make it unanswerable on a
  # SIP-enabled host, and both were measured 2026-08-31 on macOS 26.6.2 arm64.
  #
  # It ran `cp /usr/bin/true` into a fresh root and chroot'd to the copy. A copied Apple platform
  # binary is SIGKILLed for a failed signature, which this repository's own AGENTS.md records as a
  # trap, so the exit 137 said nothing about chroot.
  #
  # And the target is not the cause. `/usr/sbin/chroot / /usr/bin/true` — the binary at its own
  # path, signature intact — exits 137 as well, and so does `/bin/sh -c`. SIP refuses `chroot` to
  # root outright, and it does so by killing the caller.
  #
  # So report that rather than exiting 137 with no statement. The probe's `--uncontained` mode
  # cannot answer it either: `CONTROL_VERBS` excludes `chroot`, because the verb changes the
  # calling process's own view.
  print "uncontained chroot as root:"
  ROOT=$(mktemp -d)
  trap 'rm -rf "$ROOT"' EXIT
  # `|| code=$?` rather than a bare call, because `set -e` would abort at the failing command and
  # the script would exit 137 having stated nothing — which is what it did before this fix.
  code=0
  /usr/sbin/chroot / /usr/bin/true 2>/dev/null || code=$?
  if (( code == 0 )); then
    print "chroot(2) succeeds as root outside a box, so a refusal inside one is the profile."
    exit 0
  fi
  if (( code == 137 )); then
    print "UNAVAILABLE: SIP kills the caller of chroot(2), so no uncontained control exists here."
    print "  Partial attribution: the boxed probe returns EPERM and survives, where an uncontained"
    print "  caller is SIGKILLed. The two refusals differ in mechanism, so the boxed EPERM is"
    print "  consistent with the profile and not with SIP. That is weaker than a control."
    print "  Re-run with SIP disabled to attribute the boxed refusal outright."
    exit 0
  fi
  print -u2 "the control exited $code, which is neither a success nor SIP's kill"
  exit 1
fi

PROBE=${PROBE:-$(pwd)/target/debug/containment-test-probe}
if [[ ! -x $PROBE ]]; then
  print -u2 "no probe at $PROBE; build it first, or set PROBE"
  exit 2
fi
# Canonical, because `require_live_path_identities` compares identities: a symlinked repo path
# fails `apply` with exit 3 rather than measuring anything.
PROBE=$(cd "${PROBE:h}" && print -r -- "$(pwd -P)/${PROBE:t}")

if [[ $(id -u) -ne 0 ]]; then
  print -u2 "this measurement needs root, or the chroot leg passes on the privilege check alone"
  exit 2
fi

print "host: $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
print "euid: $(id -u)"

# The home the config's grants resolve against, which `ContainmentConfig` requires. Under `sudo` this
# is root's home, and the fixture sits outside it either way, so the home's own rules reach no case
# here. Set OPERATOR_HOME to measure a stated home that diverges from the passwd one.
OPERATOR_HOME=${OPERATOR_HOME:-$(cd -- "$HOME" && pwd -P)}
print "stated home: $OPERATOR_HOME"

ROOT=$(mktemp -d)
ROOT=$(cd "$ROOT" && pwd -P)
trap 'rm -rf "$ROOT"' EXIT

mkdir "$ROOT/home"
print -- '-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----' > "$ROOT/proxy-ca.pem"
print "ok" > "$ROOT/home/f.txt"

# The wire shape is `ContainmentConfig`'s own serde form. `measure-sf-flags-as-root.sh` states
# why it is written out here rather than built by a helper.
python3 - "$ROOT" "$PROBE" "$OPERATOR_HOME" <<'PY'
import json, sys
root, probe, operator_home = sys.argv[1], sys.argv[2], sys.argv[3]
def grant(path, operation, scope):
    return {"original": path, "resolved": path, "operation": operation, "scope": scope}
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

# The write proves the profile applied and the home is usable, so a refusal after it is the profile
# and not a broken fixture.
"$PROBE" "$ROOT/containment.json" \
  "expect-ok:write:$ROOT/home/f.txt" \
  "expect-deny:chroot:$ROOT/home"

print "chroot is refused as root: the profile is the closure, not the privilege check."
