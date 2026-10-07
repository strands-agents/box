#!/bin/zsh
# The super-user-flag measurement, which needs root and therefore no test.
#
# As an ordinary user the kernel refuses every SF_ bit at the privilege check, BEFORE the
# profile is consulted, so `expect-deny:chflags-sf` passes whether or not the rule exists.
# Run as root the privilege check passes and the profile is what answers. That is the only
# condition under which this measures the deny rather than `euid`.
#
#   cargo build -p strands-box-containment --all-features --tests
#   sudo crates/containment/tests/support/measure-sf-flags-as-root.sh
#
# Every probe must print `probe ok` and the script must exit 0. Record the macOS build, the
# architecture, and kern.securelevel beside the result in crates/containment/AGENTS.md.
#
# `--control` inverts the two flag expectations to `expect-ok`, and it is the other half of the
# measurement. Refused-as-root on its own does not say WHAT refused: the volume, securelevel, or
# some other policy would look identical to the profile. Delete the two
# `(deny file-write-flags …)` lines from the renderer, rebuild, and run with `--control`; every
# probe must still print `probe ok`, which says the kernel and the filesystem permit these flags
# as root and the deny is therefore the only thing refusing them. Then restore and rerun without
# the flag.
set -e

FLAGS=deny
if [[ $1 == --control ]]; then
  FLAGS=ok
  shift
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
  print -u2 "this measurement needs root, or the SF_ legs pass on the privilege check alone"
  exit 2
fi

# `--control` makes the flags stick on purpose. At securelevel 1 or higher neither the probe's
# restore nor the trap below can clear an SF_ bit, so the run would leave a root-owned tree that
# needs a reboot to remove. Refuse rather than print and hope.
SECURELEVEL=$(sysctl -n kern.securelevel)
if [[ $SECURELEVEL -gt 0 ]]; then
  print -u2 "kern.securelevel is $SECURELEVEL; an SF_ bit set here cannot be cleared without a reboot"
  exit 2
fi

print "host: $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
print "kern.securelevel: $SECURELEVEL"
print "euid: $(id -u)"

# The home the config's grants resolve against, which `ContainmentConfig` requires. Under `sudo` this
# is root's home, and the fixture sits outside it either way, so the home's own rules reach no case
# here. Set OPERATOR_HOME to measure a stated home that diverges from the passwd one.
OPERATOR_HOME=${OPERATOR_HOME:-$(cd -- "$HOME" && pwd -P)}
print "stated home: $OPERATOR_HOME"

ROOT=$(mktemp -d)
ROOT=$(cd "$ROOT" && pwd -P)
trap 'chflags -R nouchg,nouappnd,noschg,nosappnd,nosunlnk "$ROOT" 2>/dev/null; rm -rf "$ROOT"' EXIT

mkdir "$ROOT/home"
print -- '-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----' > "$ROOT/proxy-ca.pem"
print "ok" > "$ROOT/home/f.txt"

# The wire shape is `ContainmentConfig`'s own serde form: snake_case operation and scope,
# `signals`/`info`/`ipc` inside `process`, and no `is_file` key. Written out here because
# every other spelling is a parse error rather than a hint.
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

# The write proves the profile applied and the home is usable, so a refusal below is the one
# rule and not a broken fixture. Then both flag classes, on a file and on the root itself.
# Braces are required. Bare `$FLAGS:c` makes zsh apply its `:c` history modifier to the
# parameter, so the spelling reached the probe as `expect-okhflags-uf` and it refused the
# argument rather than measuring anything.
print "flag expectation: expect-${FLAGS}"
"$PROBE" "$ROOT/containment.json" \
  "expect-ok:write:$ROOT/home/f.txt" \
  "expect-${FLAGS}:chflags-uf:$ROOT/home/f.txt" \
  "expect-${FLAGS}:chflags-sf:$ROOT/home/f.txt" \
  "expect-${FLAGS}:chflags-uf:$ROOT/home" \
  "expect-${FLAGS}:chflags-sf:$ROOT/home"

if [[ $FLAGS == deny ]]; then
  print "SF_ and UF_ are both refused as root: the deny is the box's own closure."
else
  print "SF_ and UF_ are both settable as root with the deny removed: nothing else refuses them."
fi
