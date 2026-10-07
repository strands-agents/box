#!/bin/bash
# common/workload-agent-b.sh — compose ONE workload case's verdict row.
#
# Agent B's job in the network-egress dimension is to reconcile the oracle's
# ground truth with the run's validity and emit the final verdict. It is the same
# here, and it is deliberately not a model call: the inputs are two JSON files
# written by the host, so the reconciliation is a rule rather than a judgement.
#
#   run_status INVALID  -> FAIL, residual `run-invalid`, carrying the first error
#                          the run produced. A case that could not run must fail
#                          with a named cause, never be skipped.
#   any check failed    -> FAIL, residual = the failed check ids
#   otherwise           -> PASS
#
# A case that PASSES may still carry residual ids: those are the known, accepted
# deviations the pair works around (a Linux link failure, npm under --jitless),
# recorded so a row's shape stays honest about what it did not prove.
#
# Usage: workload-agent-b.sh <run-dir>
set -uo pipefail
RUN_DIR="${1:?}"

python3 - "$RUN_DIR" "${WL_DIMENSION:-?}" "${WL_AGENT:-?}" "${WL_PLATFORM:-?}" <<'PY'
import json
import os
import sys

run, dim, agent, plat = sys.argv[1:5]


def load(name, default):
    try:
        return json.load(open(os.path.join(run, name)))
    except Exception:
        return default


a = load("agent-a.json", {})
o = load("oracle/verdict.json", {})
gen = load("generated.json", {})
residuals = list(gen.get("residuals", []))
checks = o.get("checks", [])
failed = o.get("failed", [])

if not a:
    verdict, why = "ERROR", "agent A wrote no result (harness fault)"
elif a.get("run_status") == "INVALID":
    verdict = "FAIL"
    residuals.append("run-invalid")
    why = a.get("first_error") or "agent made no model-backed attempt"
elif os.path.exists(os.path.join(run, "timed_out")):
    verdict = "FAIL"
    residuals.append("case-timeout")
    why = "case exceeded its per-case budget (%ss)" % a.get("duration_s")
elif not checks:
    verdict, why = "ERROR", "oracle recorded no checks"
elif failed:
    verdict = "FAIL"
    residuals.extend(failed)
    # The first error the run produced is named alongside the failed assertion:
    # a check that says "the test output is missing" is far less useful than the
    # refusal or crash that stopped the command from producing it.
    why = "; ".join(c["evidence"] for c in checks if not c["ok"])[:300]
    if a.get("first_error"):
        why += " | first error: " + a["first_error"][:200]
else:
    verdict, why = "PASS", "all %d host checks passed" % len(checks)

row = {"mode": "workload", "platform": plat, "dimension": dim, "agent": agent,
       "verdict": verdict, "residuals": residuals, "note": why,
       "run_status": a.get("run_status"), "exit_code": a.get("exit_code"),
       "duration_s": a.get("duration_s"), "tool_uses": a.get("tool_uses"),
       "events": a.get("events"), "model_host": gen.get("model_host"),
       "tools": gen.get("tools", []),
       "checks": [{"id": c["id"], "ok": c["ok"], "evidence": c["evidence"]} for c in checks]}
json.dump(row, open(os.path.join(run, "verdict.json"), "w"), indent=1)
print("%s/%s %s [%s] %s" % (dim, agent, verdict, ",".join(residuals), why[:160]))
PY
