#!/usr/bin/env python3
"""Verify repeated cooldowns against generated policy through real Box."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

from deployment_demo import configure, decisions, execute
from deployment_service import DeploymentService
from deployment_tools import request

FAILURE_WINDOW_SECONDS = 30
COOLDOWN_SECONDS = 3
EXPIRY_MARGIN_SECONDS = 1


class AlwaysFailingService(DeploymentService):
    """Return failed deployments and available diagnostics without a retry guard."""

    def _response(self, method, path, body, error):
        with self._lock:
            payload = {"synthetic": True, "deployment": "checkout"}
            if error:
                status, payload["error"] = 400, error
            elif method == "POST" and path == "/deployments/checkout":
                self._deployment_attempts += 1
                status = 503
                payload.update(attempt=self._deployment_attempts, status="failed")
            elif method == "GET" and path == "/deployments/checkout/status":
                status, payload["diagnostics"] = 200, "The synthetic deployment service is reachable."
            else:
                status, payload["error"] = 404, "Unknown synthetic deployment operation"
            self._receipts.append({"method": method, "path": path, "status": status,
                                   "monotonic_ns": time.monotonic_ns(),
                                   "body_sha256": hashlib.sha256(body).hexdigest()})
            return status, payload


def probe(url):
    steps = []
    def call(label, method="POST", path="/deployments/checkout"):
        row = {"label": label, "started_ns": time.monotonic_ns()}
        row.update(request(url, method, path))
        row["completed_ns"] = time.monotonic_ns()
        steps.append(row)
        return row
    def diagnostics(label):
        call(label, "GET", "/deployments/checkout/status")
    def wait_after(row):
        deadline = row["completed_ns"] + (COOLDOWN_SECONDS + EXPIRY_MARGIN_SECONDS) * 1_000_000_000
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1_000_000_000))
    call("failure_one")
    call("failure_two")
    third = call("failure_three")
    call("first_cooldown_retry")
    diagnostics("diagnostics_first_cooldown")
    wait_after(third)
    fourth = call("failure_four_after_expiry")
    call("retry_after_fourth_failure")
    diagnostics("diagnostics_after_fourth_failure")
    wait_after(fourth)
    call("failure_five_after_expiry")
    call("retry_after_fifth_failure")
    diagnostics("diagnostics_after_fifth_failure")
    print(json.dumps({"steps": steps}), flush=True)


def verify(steps, arrivals, audit, malformed):
    labels = {row["label"]: row for row in steps}
    expected = ["failure_one", "failure_two", "failure_three", "first_cooldown_retry",
                "diagnostics_first_cooldown", "failure_four_after_expiry", "retry_after_fourth_failure",
                "diagnostics_after_fourth_failure", "failure_five_after_expiry", "retry_after_fifth_failure",
                "diagnostics_after_fifth_failure"]
    failures = ["failure_one", "failure_two", "failure_three", "failure_four_after_expiry", "failure_five_after_expiry"]
    retries = ["first_cooldown_retry", "retry_after_fourth_failure", "retry_after_fifth_failure"]
    posts = [row for row in arrivals if row["method"] == "POST"]
    diagnostics = [row for row in arrivals if row["method"] == "GET"]
    denies = [row for row in audit if row["action"] == "http:request" and row["verdict"] == "deny"
              and row["rule"] == "deployment_cooldown"]
    def status(label, value, refused=False):
        row = labels.get(label, {})
        return row.get("status") == value and row.get("box_refused") is refused
    checks = {"complete_sequence": [row["label"] for row in steps] == expected,
              "five_failed_responses": all(status(label, 503) for label in failures),
              "first_cooldown_retry_refused": status(retries[0], 403, True),
              "retry_after_fourth_failure_refused": status(retries[1], 403, True),
              "retry_after_fifth_failure_refused": status(retries[2], 403, True),
              "diagnostics_remain_available": all(status(label, 200) for label in expected if "diagnostics" in label),
              "only_five_deployments_reached_service": len(posts) == 5 and all(
                  row["status"] == 503 and row["path"] == "/deployments/checkout" for row in posts),
              "diagnostics_reached_service": len(diagnostics) == 3 and all(
                  row["status"] == 200 and row["path"] == "/deployments/checkout/status" for row in diagnostics),
              "three_cooldown_rule_denials": len(denies) == 3,
              "audit_readable": malformed == 0 and bool(audit)}
    if checks["complete_sequence"]:
        elapsed = lambda later, earlier: (labels[later]["started_ns"] - labels[earlier]["completed_ns"]) / 1_000_000_000
        in_window = lambda label: (labels[label]["completed_ns"] - labels["failure_one"]["started_ns"]) / 1_000_000_000 < FAILURE_WINDOW_SECONDS
        checks.update(fourth_failure_after_cooldown=elapsed(failures[3], failures[2]) > COOLDOWN_SECONDS,
                      fifth_failure_after_second_cooldown=elapsed(failures[4], failures[3]) > COOLDOWN_SECONDS,
                      fourth_failure_inside_failure_window=in_window(failures[3]),
                      fifth_failure_inside_failure_window=in_window(failures[4]),
                      refused_retries_never_reached_service=all(not any(
                          labels[retry]["started_ns"] <= row["monotonic_ns"] <= labels[retry]["completed_ns"]
                          for row in posts) for retry in retries),
                      retries_inside_each_cooldown=all(0 <= elapsed(retry, failure) < COOLDOWN_SECONDS
                          for retry, failure in zip(retries, failures[2:])))
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--box-binary", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--probe", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe:
        probe(args.probe)
        return 0
    if args.box_binary is None or args.evidence_dir is None:
        parser.error("--box-binary and --evidence-dir are required")
    box, evidence = args.box_binary.resolve(), args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = evidence / "fixture"
    with AlwaysFailingService() as service:
        command = [str(Path(sys.executable).resolve()), str(Path(__file__).resolve()), "--probe", service.url]
        configure(root, command, service.url, failure_window=FAILURE_WINDOW_SECONDS, cooldown=COOLDOWN_SECONDS)
        code, expired, stdout, stderr = execute(box, root, 30)
        arrivals = service.receipts
    audit, malformed = decisions(root)
    try:
        steps = json.loads(stdout)["steps"]
    except (ValueError, KeyError, TypeError):
        steps = []
    checks = verify(steps, arrivals, audit, malformed)
    checks["process_exit"] = code == 0 and not expired
    receipt = {"passed": all(checks.values()), "checks": checks,
               "failure_window_seconds": FAILURE_WINDOW_SECONDS, "cooldown_seconds": COOLDOWN_SECONDS,
               "expiry_margin_seconds": EXPIRY_MARGIN_SECONDS, "default_durations": False,
               "box_sha256": hashlib.sha256(box.read_bytes()).hexdigest(),
               "policy_sha256": hashlib.sha256((root / "policy.dw").read_bytes()).hexdigest(),
               "kernel": platform.release(), "architecture": platform.machine(), "uid": os.getuid(),
               "python": platform.python_version(), "steps": steps, "service_receipts": arrivals,
               "decisions": audit, "returncode": code, "timed_out": expired, "stderr": stderr}
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": receipt["passed"], "checks": checks, "receipt": str(evidence / "receipt.json")}, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
