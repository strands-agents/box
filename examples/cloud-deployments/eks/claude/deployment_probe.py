"""Issue a fixed sequence through Box without a model or an application retry guard."""
import json
import sys
import time

from deployment_tools import request


def probe(url, failure_window, cooldown):
    steps = []
    def call(label, method="POST", path="/deployments/checkout"):
        row = {"label": label, "method": method, "path": path, "started_ns": time.monotonic_ns()}
        row.update(request(url, method, path))
        row["completed_ns"] = time.monotonic_ns()
        steps.append(row)
        return row
    def diagnostics(label):
        return call(label, "GET", "/deployments/checkout/status")
    def wait_until(seconds):
        time.sleep(max(0, (trigger + int(seconds * 1_000_000_000) - time.monotonic_ns()) / 1_000_000_000))
    diagnostics("initial_diagnostics")
    call("failure_one")
    diagnostics("diagnostics_between_failures")
    call("failure_two")
    call("unrelated_path", path="/deployments/payments")
    trigger = call("failure_three")["completed_ns"]
    call("immediate_retry")
    diagnostics("diagnostics_during_cooldown")
    wait_until(failure_window + 2)
    call("after_failure_window")
    diagnostics("diagnostics_after_failure_window")
    wait_until(cooldown - 2)
    call("near_expiry")
    diagnostics("diagnostics_near_expiry")
    wait_until(cooldown + 2)
    call("after_cooldown")
    print(json.dumps({"steps": steps}), flush=True)


if __name__ == "__main__":
    probe(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
