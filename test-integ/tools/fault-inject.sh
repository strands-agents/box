#!/bin/bash
# deterministic/tools/fault-inject.sh — prove the suite cannot pass for the wrong reason.
#
# Runs the real suite (run.sh, the real test binaries, the real reducer) against a FAKE
# `strands-box` on PATH, in a throwaway HOME, and checks the verdict each fault produces.
# No real box is needed, so this runs on any host with cargo, rustc, bash and python3 —
# including hosts where a box cannot launch at all (x86_64 Linux). It proves nothing about
# containment; it proves that the harness cannot report containment it did not observe.
#
# Faults:
#   permissive   the "box" runs every workload on the host, unconfined, with no journal, and
#                `chmod` on PATH exits 126 without changing any mode (the parent review's
#                reproduction of the old CN-X-02 false PASS): every deny case must be FAIL or
#                ERROR (never PASS) and the verdict RED. This is the wrong-interpreter case too:
#                host `python3 --version` is CPython, not Monty; and CN-X-02 must fail because
#                the ungranted exec RAN, not because a chmod failed.
#   no-entry     the "box" launches the preflight but never the Shell: every hosted case
#                is ERROR (no DET_ENTERED), never a deny, and the verdict RED — even though
#                the fake prints `effect denied` / `Operation not permitted` and exits 126.
#   usage        the "box" is the wrong CLI (usage error, exit 2): every case ERROR, RED.
#   subset       a filtered run (one case) is RED because the other cases have no row.
#   cargo-fails  `cargo test` fails before any row is written: RED, cargo status recorded.
#   unreported   emit-verdict without run.sh (no cargo status): RED.
#
# Usage: tools/fault-inject.sh [fault ...]     (default: all)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HOME/.cargo/env" 2>/dev/null || true
REAL_CARGO="$(command -v cargo)"
REAL_PATH="$PATH"
REAL_HOME="$HOME"
FAULTS=("$@")
[ ${#FAULTS[@]} -eq 0 ] && FAULTS=(permissive no-entry usage subset cargo-fails unreported)

# Cases whose assertion is a refusal. Under a permissive box none may PASS.
DENY_CASES=(MO-4 MO-11 PO-9 SH-3 PO-4a PO-4b PO-12 CN-C-01 CN-C-03 CN-X-02 CN-I-07 CN-V-01 CN-W-07 CN-H-01 CN-W-02 CN-R-01 CN-R-02 CN-R-03 CN-V-02 CN-FS-01 CN-F-03 CN-X-03)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/det-fault-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SHIM="$WORK/bin"; mkdir -p "$SHIM"
FAILED=0
fail() { echo "  FAULT-INJECTION FAILURE: $*"; FAILED=1; }
ok() { echo "  ok: $*"; }

# A fake strands-box. $1 = mode. Parses `run --config FILE -- ARGV...` like the real CLI.
write_box() {
  cat > "$SHIM/strands-box" <<EOF
#!/bin/bash
MODE="$1"
if [ "\$MODE" = usage ]; then
  echo "error: the following required arguments were not provided:" >&2
  echo "  --config <FILE>" >&2
  echo "Usage: strands-box run --config <FILE> [WORKLOAD]..." >&2
  exit 2
fi
[ "\${1:-}" = run ] || { echo "strands-box: error: unknown subcommand" >&2; exit 1; }
shift
CONFIG=""; while [ \$# -gt 0 ]; do case "\$1" in --config) CONFIG="\$2"; shift 2;; --) shift; break;; *) shift;; esac; done
[ -f "\$CONFIG" ] || { echo "strands-box: error: no --config" >&2; exit 1; }
# The stored [agent] command program, as the real box appends the trailing argv to it.
PROG=\$(sed -n 's/^command = \\["\\(.*\\)"\\]/\\1/p' "\$CONFIG" | head -1)
case "\$MODE" in
  permissive)
    # Unconfined: run it on the host. No network, so IMDS/example.com probes fail fast.
    export http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
    exec "\$PROG" "\$@" ;;
  no-entry)
    # The preflight (/bin/echo) launches; the Shell never does, but the box "denies" loudly.
    if [ "\$PROG" = /bin/echo ]; then exec /bin/echo "\$@"; fi
    echo "strands-shell: effect denied: policy denied this operation [default-deny]: No permit policy matched this request." >&2
    echo "bash: Operation not permitted" >&2
    exit 126 ;;
esac
EOF
  chmod +x "$SHIM/strands-box"
}

# Run the suite under the shim. $1 = fault label; remaining args go to run.sh.
run_suite() {
  local label="$1"; shift
  local home="$WORK/home-$label"; mkdir -p "$home/box"
  echo "fake-$label" > "$home/box/COMMIT"
  export DET_RESULTS_DIR="$WORK/results-$label"
  # The shim dir first, then the real PATH (rustc for the fixture's probes, real cargo).
  # HOME moves, so the rustup proxies (rustc, cargo) are told where the toolchains really are.
  HOME="$home" PATH="$SHIM:$REAL_PATH" CARGO_TARGET_DIR="$HERE/target" \
    RUSTUP_HOME="${RUSTUP_HOME:-$REAL_HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$REAL_HOME/.cargo}" \
    bash "$HERE/run.sh" "$@" > "$WORK/run-$label.log" 2>&1
  echo "  run.sh exit: $?  (log: $WORK/run-$label.log)"
}

# verdict.json field helpers.
verdict() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$1"; }
result_of() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((r["result"] for r in d["results"] if r["id"]==sys.argv[2]),"MISSING"))' "$1" "$2"; }
problems() { python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["integrity"]["problems"]))' "$1"; }
count() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["counts"][sys.argv[2]])' "$1" "$2"; }

echo "== building the suite once =="
( cd "$HERE" && "$REAL_CARGO" test --release --no-run >/dev/null 2>&1 ) || { echo "cannot build the suite"; exit 1; }

for fault in "${FAULTS[@]}"; do
  echo; echo "== fault: $fault =="
  case "$fault" in
    permissive)
      write_box permissive
      printf '#!/bin/bash\necho "chmod refused" >&2; exit 126\n' > "$SHIM/chmod"; chmod +x "$SHIM/chmod"
      run_suite permissive
      rm -f "$SHIM/chmod"
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      for id in "${DENY_CASES[@]}"; do
        r="$(result_of "$V" "$id")"
        case "$r" in PASS) fail "$id PASS under an unconfined box";; MISSING) fail "$id has no row";; *) ok "$id $r";; esac
      done
      # The Monty cases must have failed on the interpreter's identity, not on a marker.
      # The identity control asks the hosted Shell; a host zsh never reaches the broker, so the
      # control errors before any script runs.
      for id in MO-4 MO-11; do
        grep -Eq 'no shell:exec decision was journaled|is not Monty' "$DET_RESULTS_DIR/$id.jsonl" && ok "$id rejected the host interpreter route" || fail "$id did not reject the host interpreter route"
      done
      # Under a host zsh the probe reaches the host pid (SIGNAL_REACHED is in the captured output),
      # and the case must still be refused on the route, not read as isolation.
      grep -q 'no shell:exec decision was journaled' "$DET_RESULTS_DIR/CN-I-07.jsonl" && ok "CN-I-07 rejected the host zsh route" || fail "CN-I-07 did not reject the host zsh route"
      # A host cat follows the escape link and prints the secret; the case must not read that as
      # anything but a route failure (and never as the refusal it looks for).
      grep -Eq 'no shell:exec decision was journaled|unexpectedly contained' "$DET_RESULTS_DIR/CN-V-01.jsonl" && ok "CN-V-01 rejected the uncontained read" || fail "CN-V-01 did not reject the uncontained read"
      # The credential probe must be able to print the planted marker (it sits on line 2): under
      # an unconfined read the marker line appears in the captured output and the case fails.
      grep -q 'CRED=det_planted_marker = DET_SECRET_' "$DET_RESULTS_DIR/CN-C-01.jsonl" && ok "CN-C-01 probe reached and printed the planted marker" || fail "CN-C-01 probe never reached the planted marker"
      grep -q "no shell:exec decision was journaled" "$DET_RESULTS_DIR/PO-9.jsonl" && ok "PO-9 rejected a host zsh (no broker)" || fail "PO-9 did not reject the host zsh route"
      # CN-X-02 must fail on the ungranted binary having RUN, with its control having passed —
      # not on the chmod shim, which the case never calls.
      grep -q "unexpectedly contained 'BUILD_OUTPUT_RAN'" "$DET_RESULTS_DIR/CN-X-02.jsonl" && ok "CN-X-02 saw the ungranted exec run" || fail "CN-X-02 did not fail on the ungranted exec running"
      grep -q "chmod refused" "$DET_RESULTS_DIR/CN-X-02.jsonl" && fail "CN-X-02 attributed a chmod failure" || ok "CN-X-02 never depended on chmod"
      # The failing assertion is step 2 (its note quotes the ungranted run), so step 1's control
      # assertions passed first: the probe was reached only through a working positive control.
      grep -q "BUILD_OUTPUT_RAN ungranted" "$DET_RESULTS_DIR/CN-X-02.jsonl" && ok "CN-X-02 failed at the ungranted probe, after its control passed" || fail "CN-X-02 did not fail at the ungranted probe"
      ;;
    no-entry)
      write_box no-entry
      run_suite no-entry
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      [ "$(count "$V" pass)" = 0 ] && ok "no case passed" || fail "$(count "$V" pass) cases passed without entering the box"
      for id in PO-9 SH-3 CN-C-01 CN-X-02; do
        r="$(result_of "$V" "$id")"
        [ "$r" = ERROR ] && ok "$id ERROR (never entered)" || fail "$id $r, expected ERROR"
        grep -q 'never printed DET_ENTERED' "$DET_RESULTS_DIR/$id.jsonl" || fail "$id did not name the missing entry sentinel"
      done
      ;;
    usage)
      write_box usage
      run_suite usage
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      [ "$(count "$V" pass)" = 0 ] && ok "no case passed" || fail "$(count "$V" pass) cases passed under a usage error"
      [ "$(count "$V" error)" -ge 20 ] && ok "$(count "$V" error) cases ERROR" || fail "only $(count "$V" error) ERROR rows"
      ;;
    subset)
      write_box usage
      run_suite subset po_9
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      n="$(problems "$V" | grep -c 'no row recorded')"
      [ "$n" -ge 20 ] && ok "$n missing cases named" || fail "only $n missing cases named"
      ;;
    cargo-fails)
      write_box usage
      cat > "$SHIM/cargo" <<EOF
#!/bin/bash
if [ "\${1:-}" = test ]; then echo "error: could not compile strands-det-harness (test policy)" >&2; exit 101; fi
exec "$REAL_CARGO" "\$@"
EOF
      chmod +x "$SHIM/cargo"
      run_suite cargo-fails
      rm -f "$SHIM/cargo"
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      problems "$V" | grep -q 'cargo test exited 101' && ok "cargo status recorded" || fail "cargo status not recorded"
      [ "$(count "$V" total)" = 0 ] && ok "no rows, still a verdict" || fail "unexpected rows"
      ;;
    unreported)
      export DET_RESULTS_DIR="$WORK/results-unreported"; mkdir -p "$DET_RESULTS_DIR"
      ( cd "$HERE" && env -u DET_CARGO_STATUS "$REAL_CARGO" run --release --quiet --bin emit-verdict ) > "$WORK/run-unreported.log" 2>&1
      echo "  emit-verdict exit: $?"
      V="$DET_RESULTS_DIR/verdict.json"
      [ "$(verdict "$V")" = RED ] && ok "verdict RED" || fail "verdict $(verdict "$V"), expected RED"
      problems "$V" | grep -q 'exit status not reported' && ok "unreported status named" || fail "unreported status not named"
      ;;
    *) fail "unknown fault $fault" ;;
  esac
done

echo
if [ "$FAILED" -eq 0 ]; then echo "FAULT INJECTION: all faults produced RED for the right reason"; else echo "FAULT INJECTION: FAILURES ABOVE"; fi
exit "$FAILED"
