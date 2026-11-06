#!/usr/bin/env python3
"""Verify the deployment cooldown through a real Box without a model."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys

from deployment_demo import configure, decisions, execute
from deployment_service import DeploymentService


def verify(steps, arrivals, audit, malformed, failure_window, cooldown):
    by_label = {row["label"]: row for row in steps}
    expected = ["initial_diagnostics", "failure_one", "diagnostics_between_failures", "failure_two",
                "unrelated_path", "failure_three", "immediate_retry", "diagnostics_during_cooldown",
                "after_failure_window", "diagnostics_after_failure_window", "near_expiry",
                "diagnostics_near_expiry", "after_cooldown"]
    posts = [row for row in arrivals if row["method"] == "POST"]
    denied = [row for row in audit if row["action"] == "http:request" and row["verdict"] == "deny"
              and row["rule"] == "deployment_cooldown"]
    def status(label, value, refused=False):
        row = by_label.get(label, {})
        return row.get("status") == value and row.get("box_refused") is refused
    checks = {"complete_sequence": [row["label"] for row in steps] == expected,
              "three_failed_responses": all(status(label, 503) for label in
                  ("failure_one", "failure_two", "failure_three")),
              "three_cooldown_refusals": all(status(label, 403, True) for label in
                  ("immediate_retry", "after_failure_window", "near_expiry")) and len(denied) == 3,
              "diagnostics_remain_available": all(status(label, 200) for label in expected if "diagnostics" in label),
              "unrelated_path_refused": status("unrelated_path", 403, True),
              "retry_after_cooldown": status("after_cooldown", 201),
              "only_permitted_deployments_reached_service": len(posts) == 4 and
                  [row["status"] for row in posts] == [503, 503, 503, 201] and
                  all(row["path"] == "/deployments/checkout" for row in posts),
              "audit_readable": malformed == 0 and bool(audit)}
    if checks["complete_sequence"]:
        trigger = by_label["failure_three"]["completed_ns"]
        elapsed = lambda label: (by_label[label]["started_ns"] - trigger) / 1_000_000_000
        checks.update(failure_window_observed=(trigger - by_label["failure_one"]["started_ns"])
                      / 1_000_000_000 <= failure_window,
                      cooldown_outlasts_failure_window=elapsed("after_failure_window") > failure_window,
                      near_expiry_probe_in_cooldown=0 < cooldown - elapsed("near_expiry") < 3,
                      retry_waited_full_cooldown=elapsed("after_cooldown") > cooldown,
                      denied_retry_did_not_extend_cooldown=elapsed("after_cooldown") - elapsed("near_expiry") < cooldown)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--box-binary", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--quick", action="store_true", help="Use 3-second and 9-second windows; does not verify the default durations.")
    args = parser.parse_args()
    box, evidence = args.box_binary.resolve(), args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    failure_window, cooldown = (3, 9) if args.quick else (300, 600)
    root = evidence / "fixture"
    with DeploymentService() as service:
        command = [str(Path(sys.executable).resolve()), str(Path(__file__).with_name("deployment_probe.py")),
                   service.url, str(failure_window), str(cooldown)]
        configure(root, command, service.url, failure_window=failure_window, cooldown=cooldown)
        code, expired, stdout, stderr = execute(box, root, cooldown + 90)
        arrivals = service.receipts
    audit, malformed = decisions(root)
    try:
        steps = json.loads(stdout)["steps"]
    except (ValueError, KeyError, TypeError):
        steps = []
    checks = verify(steps, arrivals, audit, malformed, failure_window, cooldown)
    checks["process_exit"] = code == 0 and not expired
    receipt = {"passed": all(checks.values()), "checks": checks,
               "failure_window_seconds": failure_window, "cooldown_seconds": cooldown,
               "default_durations": not args.quick, "box_sha256": hashlib.sha256(box.read_bytes()).hexdigest(),
               "kernel": platform.release(), "architecture": platform.machine(), "uid": os.getuid(),
               "python": platform.python_version(), "steps": steps, "service_receipts": arrivals,
               "decisions": audit, "returncode": code, "timed_out": expired, "stderr": stderr}
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": receipt["passed"], "checks": checks, "receipt": str(evidence / "receipt.json")}, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
