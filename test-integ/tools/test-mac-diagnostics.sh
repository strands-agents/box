#!/bin/bash
# deterministic/tools/test-mac-diagnostics.sh — local checks for the macOS diagnostic capture.
#
# Runs mac_diagnostics.py (and the mac-diagnostics.sh wrapper) against a verdict shaped like the
# real macOS run cr1-review-20260922065611-repeat1 (CN-F1-01: "/bin/bash: line 1:  2298 Killed: 9
# zsh -c '…'") with STUBBED macOS tools, on any host. Checks, per the parent's bounds review:
#   1. a successful capture with ZERO diagnostic errors writes summary.json that parses and says 0;
#   2. a per-command timeout terminates the command's OWN descendant (a sleeping child) and reaps it;
#   3. the global deadline cuts an otherwise long lookup, skips the remaining steps, and is recorded;
#   4. byte caps: a flooding command's output is truncated, a large report copy is truncated;
#   5. a malformed verdict still yields valid JSON and exit 0;
#   6. the no-python wrapper path still yields valid JSON and exit 0;
#   plus extraction of pid/argv0/case/alias paths, matching a real-home record and its terminating
#   process, INCONCLUSIVE wording when nothing matches, shell syntax and Python compilation.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$HERE/mac_diagnostics.py"
WRAPPER="$HERE/mac-diagnostics.sh"
PY="$(command -v python3)"
FAILED=0
ok() { echo "  ok: $*"; }
fail() { echo "  FAILURE: $*"; FAILED=1; }

echo "== syntax"
bash -n "$WRAPPER" && ok "mac-diagnostics.sh parses" || fail "mac-diagnostics.sh syntax"
bash -n "$HERE/../../test-workload/common/bootstrap.sh" && ok "bootstrap.sh parses" || fail "bootstrap.sh syntax"
bash -n "$HERE/fault-inject.sh" && ok "fault-inject.sh parses" || fail "fault-inject.sh syntax"
"$PY" -m py_compile "$HELPER" && ok "mac_diagnostics.py compiles" || fail "mac_diagnostics.py compile"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$WRAPPER" && ok "shellcheck clean" || fail "shellcheck findings"
else
  echo "  (shellcheck not installed; skipped)"
fi

W="$(mktemp -d "${TMPDIR:-/tmp}/macdiag-XXXXXX")"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/results" "$W/bin" "$W/realhome/Library/Logs/DiagnosticReports" "$W/fakehome"

cat > "$W/isolated-helper.py" <<'PYEOF'
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location("diagnostics", sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
original_report_dirs = helper.Capture.report_dirs
fixture = os.path.realpath(os.path.dirname(__file__)) + os.sep

def fixture_report_dirs(capture):
    return [path for path in original_report_dirs(capture)
            if os.path.realpath(path).startswith(fixture)]

helper.Capture.report_dirs = fixture_report_dirs
sys.exit(helper.main(sys.argv[1:]))
PYEOF
printf '#!/bin/bash\nexec "%s" "%s" "$@"\n' "$PY" "$W/isolated-helper.py" > "$W/bin/python3"
chmod +x "$W/bin/python3"

"$PY" - "$W/results/verdict.json" <<'PYEOF'
import json, sys
note = ("F1 needs the box at c7d0f41d or later: ...; out=[DET_ENTERED\n"
        "strands-box: [agent] HOME=/var/tmp/det-home PATH=/private/var/tmp/det-home/.det-harness-boxes/det-box-0RE7me/state/bin:/var/tmp/det-home/box/target/release:/usr/bin\n"
        "/bin/bash: line 1:  2298 Killed: 9               zsh -c '/private/var/tmp/det-home/.det-harness-boxes/det-box-0RE7me/workspace/out/free-hello from-the-agent'\n]")
json.dump({"platform": "macos", "box_commit": "4c915da4", "verdict": "RED",
           "counts": {"total": 28, "pass": 24, "fail": 1, "error": 0, "skip": 3},
           "integrity": {"cargo_status": 101, "expected": 28, "recorded": 28, "problems": ["cargo test exited 101"]},
           "results": [{"id": "CN-E-02", "category": "containment", "description": "d", "result": "PASS", "note": ""},
                       {"id": "CN-F1-01", "category": "containment", "description": "d", "result": "FAIL", "note": note}]},
          open(sys.argv[1], "w"))
PYEOF
printf 'alias-image-bytes\n' > "$W/alias-image"

# Well-behaved stubs (case 1 baseline).
stub() { printf '#!/bin/bash\n%s\n' "$2" > "$W/bin/$1"; chmod +x "$W/bin/$1"; }
stub log 'echo "STUB log $*"; echo "2026-09-22 07:20:00 kernel: stub line"'
stub codesign 'echo "Identifier=strands-box-sock-alias"; echo "CodeDirectory v=20400 flags=0x2(adhoc)"'
stub sw_vers 'echo "ProductName: macOS"; echo "ProductVersion: 26.0"'
stub csrutil 'echo "System Integrity Protection status: enabled."'
stub dscacheutil "echo \"name: \$(id -un)\"; echo \"dir: $W/realhome\""
stub file 'echo "$1: Mach-O 64-bit executable arm64"'
cat > "$W/realhome/Library/Logs/DiagnosticReports/zsh-2026-09-22-072010.ips" <<'EOF'
{"app_name":"zsh","timestamp":"2026-09-22 07:20:10.00 +0000","bug_type":"309","os_version":"macOS 26.0"}
{"pid":2298,"procName":"zsh","procPath":"/private/var/tmp/det-home/.det-harness-boxes/det-box-0RE7me/state/bin/zsh","exception":{"type":"EXC_CRASH","signal":"SIGKILL"},"termination":{"namespace":"SIGNAL","code":9,"indicator":"Killed: 9","byProc":"stub-sender","byPid":4242}}
EOF
cat > "$W/realhome/Library/Logs/DiagnosticReports/other-2026-09-22-070000.ips" <<'EOF'
{"app_name":"other","timestamp":"2026-09-22 07:00:00.00 +0000"}
{"pid":99,"procName":"other","termination":{"namespace":"SIGNAL","code":9}}
EOF

run_helper() { # <outdir> [env assignments...]
  local out="$1"; shift
  env HOME="$W/fakehome" PATH="$W/bin:$PATH" DIAG_FORCE=1 DIAG_PLATFORM=Darwin DIAG_ALIAS_IMAGE="$W/alias-image" "$@" \
    "$PY" "$W/isolated-helper.py" "$HELPER" "$W/results" "$out" "$(( $(date +%s) - 3600 ))"
}
json_ok() { "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" 2>/dev/null; }

echo "== 1. successful capture, zero diagnostic errors"
run_helper "$W/o1"; status=$?
[ "$status" -eq 0 ] && ok "exit 0" || fail "exit $status"
json_ok "$W/o1/summary.json" && ok "summary.json is valid JSON" || fail "summary.json invalid"
"$PY" - "$W/o1" <<'PYEOF' || FAILED=1
import json, os, sys
out = sys.argv[1]
s = json.load(open(os.path.join(out, "summary.json")))
assert s["diagnostic_errors"] == 0, s["diagnostic_errors"]
assert os.path.getsize(os.path.join(out, "errors.txt")) == 0
assert s["incomplete"] is False and s["skipped_steps"] == []
assert s["alias_image_codesign_verify"] == "ok"
c = json.load(open(os.path.join(out, "cases.json")))
assert [x["id"] for x in c["failed_cases"]] == ["CN-F1-01"]
assert c["killed"] == [{"case": "CN-F1-01", "pid": 2298, "argv0": "zsh",
    "command": "zsh -c '/private/var/tmp/det-home/.det-harness-boxes/det-box-0RE7me/workspace/out/free-hello from-the-agent'"}]
assert any(p.endswith("/state/bin/zsh") for p in c["alias_paths_named"])
assert s["crash_reports"]["matched"] == 1 and s["crash_reports"]["candidates_in_window"] == 2
assert os.path.exists(os.path.join(out, "crash-reports", "zsh-2026-09-22-072010.ips"))
assert not os.path.exists(os.path.join(out, "crash-reports", "other-2026-09-22-070000.ips"))
ex = json.load(open(os.path.join(out, "crash-reports", "extracted.json")))
assert ex[0]["pid"] == 2298 and ex[0]["termination"]["byProc"] == "stub-sender"
assert "processID == 2298" in open(os.path.join(out, "log-pid-2298.txt")).read()
assert "UNAVAILABLE" in open(os.path.join(out, "image", "alias-paths.txt")).read()
assert os.path.exists(os.path.join(out, "image", "source-sha256.txt"))
print("  ok: errors 0; pid 2298/zsh/CN-F1-01 extracted; real-home record matched with byProc; alias paths UNAVAILABLE; image identity captured")
PYEOF

echo "== 2. per-command timeout terminates and reaps the command's own descendant"
stub log "sleep 300 & echo \$! > '$W/sleeper.pid'; wait"
run_helper "$W/o2" DIAG_CMD_TIMEOUT=1 >/dev/null 2>&1
sleeper=$(cat "$W/sleeper.pid" 2>/dev/null || echo "")
if [ -n "$sleeper" ] && ! kill -0 "$sleeper" 2>/dev/null; then ok "descendant sleep $sleeper is gone after the timeout"; else fail "descendant sleep ${sleeper:-?} survived"; kill -9 "$sleeper" 2>/dev/null; fi
grep -q 'timed out after 1s (partial output kept; process group terminated)' "$W/o2/errors.txt" && ok "timeout recorded" || fail "timeout not recorded: $(cat "$W/o2/errors.txt")"
grep -q 'still alive after SIGKILL' "$W/o2/errors.txt" && fail "group reported still alive" || ok "group confirmed gone"
json_ok "$W/o2/summary.json" && ok "summary valid" || fail "summary invalid"
stub log 'echo "STUB log $*"'

echo "== 3. global deadline cuts a long lookup and skips the rest, recorded, without hanging"
stub dscacheutil 'sleep 30'
t0=$(date +%s); run_helper "$W/o3" DIAG_TOTAL_TIMEOUT=2 >/dev/null 2>&1; t1=$(date +%s)
[ $((t1 - t0)) -le 12 ] && ok "returned in $((t1 - t0))s with a 2s global deadline" || fail "took $((t1 - t0))s"
"$PY" - "$W/o3" <<'PYEOF' || FAILED=1
import json, os, sys
s = json.load(open(os.path.join(sys.argv[1], "summary.json")))
assert s["incomplete"] is True, s
assert s["skipped_steps"], s
e = open(os.path.join(sys.argv[1], "errors.txt")).read()
assert "dscacheutil user lookup: timed out after 2s" in e, e
print("  ok: lookup cut at the global deadline; %d later step(s) skipped and recorded; incomplete=true" % len(s["skipped_steps"]))
PYEOF
stub dscacheutil "echo \"dir: $W/realhome\""

echo "== 4. byte caps on command output and on copied reports"
stub log 'head -c 5000000 /dev/zero | tr "\0" "x"; echo'
{ echo '{"app_name":"zsh","timestamp":"2026-09-22 07:21:00.00 +0000"}'; printf '{"pid":2298,"procName":"zsh","filler":"'; head -c 2000000 /dev/zero | tr '\0' 'y'; echo '"}'; } > "$W/realhome/Library/Logs/DiagnosticReports/zsh-2026-09-22-072100.ips"
run_helper "$W/o4" DIAG_OUTPUT_CAP=100000 DIAG_REPORT_CAP=50000 >/dev/null 2>&1
sz=$(stat -c %s "$W/o4/log-pid-2298.txt" 2>/dev/null || stat -f %z "$W/o4/log-pid-2298.txt")
[ "$sz" -le 100000 ] && ok "flooding command output capped at $sz bytes" || fail "output $sz bytes exceeds cap"
grep -q 'output exceeded 100000 bytes' "$W/o4/errors.txt" && ok "output cap recorded" || fail "output cap not recorded"
rsz=$(stat -c %s "$W/o4/crash-reports/zsh-2026-09-22-072100.ips" 2>/dev/null || stat -f %z "$W/o4/crash-reports/zsh-2026-09-22-072100.ips")
[ "$rsz" -le 50200 ] && grep -q 'truncated by mac_diagnostics' "$W/o4/crash-reports/zsh-2026-09-22-072100.ips" && ok "large report copy truncated at the report cap ($rsz bytes)" || fail "report copy $rsz bytes"
json_ok "$W/o4/crash-reports/extracted.json" && ok "extracted.json still valid (truncated body recorded as parse_error)" || fail "extracted.json invalid"
rm -f "$W/realhome/Library/Logs/DiagnosticReports/zsh-2026-09-22-072100.ips"; stub log 'echo "STUB log $*"'

echo "== 5. malformed verdict"
mkdir -p "$W/bad"; printf '{not json' > "$W/bad/verdict.json"
HOME="$W/fakehome" PATH="$W/bin:$PATH" DIAG_FORCE=1 DIAG_PLATFORM=Darwin DIAG_ALIAS_IMAGE="$W/alias-image" "$PY" "$HELPER" "$W/bad" "$W/o5" >/dev/null 2>&1; status=$?
[ "$status" -eq 0 ] && json_ok "$W/o5/summary.json" && json_ok "$W/o5/cases.json" && grep -q 'malformed' "$W/o5/errors.txt" && ok "malformed verdict → valid JSON, error recorded, exit 0" || fail "malformed-verdict path"

echo "== 6. no matching record → INCONCLUSIVE"
rm -f "$W/realhome/Library/Logs/DiagnosticReports/zsh-2026-09-22-072010.ips"
run_helper "$W/o6" >/dev/null 2>&1
grep -q 'INCONCLUSIVE' "$W/o6/summary.json" && grep -q 'INCONCLUSIVE' "$W/o6/README.txt" && ok "INCONCLUSIVE stated in summary and README" || fail "INCONCLUSIVE missing"

echo "== 7. wrapper: normal path, and the no-python path"
HOME="$W/fakehome" PATH="$W/bin:$PATH" DIAG_FORCE=1 DIAG_PLATFORM=Darwin DIAG_ALIAS_IMAGE="$W/alias-image" bash "$WRAPPER" "$W/results" "$W/o7" >/dev/null 2>&1; status=$?
[ "$status" -eq 0 ] && json_ok "$W/o7/summary.json" && ok "wrapper with python3: exit 0, valid summary" || fail "wrapper normal path"
mkdir -p "$W/nopy"; for t in bash grep sed sort paste tr wc date sleep kill printf cat mkdir; do p=$(command -v $t) && ln -sf "$p" "$W/nopy/$t"; done
PATH="$W/nopy" bash "$WRAPPER" "$W/results" "$W/o8" >/dev/null 2>&1; status=$?
[ "$status" -eq 0 ] && json_ok "$W/o8/summary.json" && json_ok "$W/o8/cases.json" && grep -q '"killed_pids":\[2298\]' "$W/o8/cases.json" && grep -q 'python3 unavailable' "$W/o8/errors.txt" && ok "no-python wrapper: exit 0, valid JSON, pid 2298 via grep, gap recorded" || fail "no-python path: $(cat "$W/o8/summary.json" 2>/dev/null)"

echo "== 8. non-macOS without DIAG_FORCE, and missing verdict"
HOME="$W/fakehome" DIAG_PLATFORM=Linux "$PY" "$HELPER" "$W/results" "$W/o9" >/dev/null 2>&1; status=$?
[ "$status" -eq 0 ] && grep -q '"applicable": false' "$W/o9/summary.json" && ok "non-Darwin: cases parsed, capture skipped, exit 0" || fail "non-Darwin path"
mkdir -p "$W/empty"; HOME="$W/fakehome" DIAG_PLATFORM=Linux "$PY" "$HELPER" "$W/empty" "$W/o10" >/dev/null 2>&1; status=$?
[ "$status" -eq 0 ] && json_ok "$W/o10/summary.json" && grep -q 'no verdict.json' "$W/o10/errors.txt" && ok "missing verdict: error recorded, valid JSON, exit 0" || fail "missing-verdict path"

echo
if [ "$FAILED" -eq 0 ]; then echo "MAC-DIAGNOSTICS CHECKS: all passed"; else echo "MAC-DIAGNOSTICS CHECKS: FAILURES ABOVE"; fi
exit "$FAILED"
