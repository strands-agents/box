#!/usr/bin/env python3
"""Verify Box decisions against independent synthetic shipment effects."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import tempfile
import shutil

from fixture import FixtureServer

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decision_records(path):
    decisions = []
    if not path.exists():
        return decisions
    for line in path.read_text().splitlines():
        entry = json.loads(line)
        for resource in entry.get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = {a["key"]: a["value"] for a in record.get("attributes", [])}
                    if "strands.box.policy.verdict" in attrs:
                        decisions.append({k: v.get("stringValue", v) for k, v in attrs.items()
                                          if k.startswith("strands.box.policy.") or k in ["http.request.method", "url.path", "server.address"]})
    return decisions


def run_scenario(name, output, binary):
    run = output / name
    run.mkdir()
    (run / "workspace").mkdir()
    state_root = Path(tempfile.mkdtemp(prefix="box-ship-"))
    state = state_root / "state"
    with FixtureServer(eligibility_status=409 if name == "failed" else 200) as fixture:
        policy = (ROOT / "policy.dw").read_text().replace("port == 0", "port == " + str(fixture.port)).replace("port: 0", "port: " + str(fixture.port))
        if name == "unrelated":
            # Let the shared forbid rule decide a second order's eligibility.
            # The backend remains limited to dispatching order 42.
            policy += '\n@id("shipment_other_order_test")\n' + (
                'permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)\n'
                'when { context.input.host == "127.0.0.1" && context.input.port == '
                + str(fixture.port) + ' && context.input.method == "POST" && '
                'context.input.path == "/orders/43/replacement" };\n'
            )
        (run / "policy.dw").write_text(policy)
        executable = str(Path(sys.executable).resolve())
        command = [executable, "-I", "-B", str(ROOT / "shipment-client.py"), "--service", fixture.base_url, "--scenario", name]
        python_dirs = sorted({str(Path(p).resolve()) for p in sys.path if p and Path(p).is_dir() and "python" in p and "site-packages" not in p})
        python_dirs += [p for p in ["/usr/lib64", "/usr/lib"] if Path(p).is_dir()]
        python_dirs = sorted(set(python_dirs))
        extensions = json.loads(subprocess.check_output([executable, "-c",
            "import runpy,sys,json; runpy.run_path(" + repr(str(ROOT / "shipment-client.py")) + "); "
            "print(json.dumps(sorted({m.__file__ for m in sys.modules.values() if getattr(m, '__file__', '') and m.__file__.endswith('.so')})))"], text=True))
        python_dirs = [p for p in python_dirs if not any(p != q and Path(q) in Path(p).parents for q in python_dirs)]
        config = '\n'.join([
            'name = "shipment-' + name + '"',
            'box_dir = ' + json.dumps(str(state)),
            'policy = "policy.dw"',
            '[agent]',
            'command = ' + json.dumps(command),
            'workspace = ' + json.dumps(str(run / "workspace")),
            'env = { PATH = "/usr/bin:/bin" }',
            '[agent.filesystem]',
            'read = ' + json.dumps(python_dirs),
            'read_file = ' + json.dumps([str(ROOT / "shipment-client.py")]),
            'exec = ' + json.dumps(extensions),
            '',
        ])
        (run / "box.toml").write_text(config)
        env = dict(os.environ, EXPERIMENTAL_LINUX_SUPPORT="TRUE")
        start = time.monotonic()
        process = subprocess.Popen([str(binary), "run", "--config", str(run / "box.toml")],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=env, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        duration = time.monotonic() - start
        (run / "stdout.txt").write_text(stdout)
        (run / "stderr.txt").write_text(stderr)
        snapshot = fixture.snapshot()
        (run / "service.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    try:
        workload = json.loads(stdout)
    except ValueError:
        workload = {}
    steps = {step["label"]: step for step in workload.get("steps", [])}
    checks = {"workload_exit_zero": process.returncode == 0,
              "workload_finished_within_history_window": not timed_out and duration < 300,
              "customer_reply_present": bool(workload.get("customer_reply"))}
    expected = {
        "shipment": {"read_customer_case": (200, False), "premature_dispatch": (403, True),
                     "successful_eligibility": (200, False), "dispatch_replacement": (201, False),
                     "repeat_dispatch": (403, True), "competing_refund": (403, True)},
        "failed": {"read_customer_case": (200, False), "failed_eligibility": (409, False),
                   "dispatch_after_failed_check": (403, True)},
        "unrelated": {"read_customer_case": (200, False), "other_order_before_check": (403, True),
                      "unrelated_eligibility": (200, False),
                      "dispatch_after_unrelated_check": (403, True), "other_order_after_check": (404, False)},
        "refund-first": {"read_customer_case": (200, False), "failed_refund": (400, False),
                         "refund_order": (201, False), "repeat_refund": (403, True),
                         "successful_eligibility": (200, False), "dispatch_after_refund": (403, True)},
    }[name]
    for label, (status, refused) in expected.items():
        step = steps.get(label, {})
        checks[label] = step.get("status") == status and step.get("box_refused") is refused
    expected_service = [("GET", "/orders/42", 200)]
    if name == "shipment":
        expected_service += [("GET", "/orders/42/replacement", 200), ("POST", "/orders/42/replacement", 201)]
    elif name == "refund-first":
        expected_service += [("POST", "/orders/42/refund", 400), ("POST", "/orders/42/refund", 201),
                             ("GET", "/orders/42/replacement", 200)]
    elif name == "failed":
        expected_service += [("GET", "/orders/42/replacement", 409)]
    else:
        expected_service += [("GET", "/orders/43/replacement", 200), ("POST", "/orders/43/replacement", 404)]
    observed_service = [(x["method"], x["path"], x["status"]) for x in snapshot["requests"]]
    checks["only_permitted_requests_reached_service"] = observed_service == expected_service
    expected_effects = []
    if name == "shipment":
        expected_effects = [{"order_id": 42, "kind": "dispatch", "effect_id": "dispatch-42-001", "idempotency_key": "replacement-42"}]
    elif name == "refund-first":
        expected_effects = [{"order_id": 42, "kind": "refund", "effect_id": "refund-42-001", "idempotency_key": "refund-42"}]
    checks["exact_expected_effects"] = snapshot["effects"] == expected_effects
    checks["expected_service_resolution"] = snapshot["resolution"] == (expected_effects[0] if expected_effects else None)
    if name == "shipment":
        receipt = steps.get("dispatch_replacement", {}).get("body", {})
        checks["dispatch_receipt_matches_effect"] = isinstance(receipt, dict) and all([
            receipt.get("effect_id") == expected_effects[0]["effect_id"],
            receipt.get("order_id") == 42,
            receipt.get("resolution") == "dispatch",
            receipt.get("item") == snapshot["order"]["item"],
            receipt.get("quantity") == snapshot["order"]["quantity"],
            receipt.get("estimated_delivery") == snapshot["order"]["replacement_estimated_delivery"],
        ])
        checks["reply_names_confirmed_dispatch"] = isinstance(receipt, dict) and receipt.get("effect_id", "missing") in workload.get("customer_reply", "")

    if name == "refund-first":
        receipt = steps.get("refund_order", {}).get("body", {})
        checks["refund_receipt_matches_effect"] = isinstance(receipt, dict) and all([
            receipt.get("effect_id") == expected_effects[0]["effect_id"],
            receipt.get("order_id") == 42,
            receipt.get("resolution") == "refund",
        ])
        checks["reply_names_confirmed_refund"] = isinstance(receipt, dict) and receipt.get("effect_id", "missing") in workload.get("customer_reply", "")
        checks["failed_refund_has_no_effect"] = len(snapshot["requests"]) >= 2 and all([
            snapshot["requests"][1]["status"] == 400,
            snapshot["requests"][1]["new_effect"] is None,
        ])

    telemetry = state / "private/telemetry/records.jsonl"
    if telemetry.exists():
        shutil.copyfile(telemetry, run / "box-records.jsonl")
    decisions = decision_records(telemetry)
    expected_rules = {
        "shipment": ["dispatch_requires_eligibility", "dispatch_closes_mutations", "dispatch_closes_mutations"],
        "failed": ["dispatch_requires_eligibility"],
        "unrelated": ["dispatch_requires_eligibility", "dispatch_requires_eligibility"],
        "refund-first": ["refund_closes_mutations", "refund_closes_mutations"],
    }[name]
    actual_rules = [d.get("strands.box.policy.rule") for d in decisions
                    if d.get("strands.box.policy.action") == "http:request" and d.get("strands.box.policy.verdict") == "deny"]
    checks["expected_policy_rules_refused_requests"] = actual_rules == expected_rules
    if name == "refund-first":
        expected_decisions = [
            ("GET", "/orders/42", "permit", "shipment_fixture_reads"),
            ("POST", "/orders/42/refund", "permit", "shipment_fixture_mutations"),
            ("POST", "/orders/42/refund", "permit", "shipment_fixture_mutations"),
            ("POST", "/orders/42/refund", "deny", "refund_closes_mutations"),
            ("GET", "/orders/42/replacement", "permit", "shipment_fixture_reads"),
            ("POST", "/orders/42/replacement", "deny", "refund_closes_mutations"),
        ]
        resource_prefix = "127.0.0.1:" + str(fixture.port)
        observed_decisions = [(d.get("http.request.method"), d.get("strands.box.policy.resource"),
                               d.get("strands.box.policy.verdict"), d.get("strands.box.policy.rule"))
                              for d in decisions if d.get("strands.box.policy.action") == "http:request"]
        checks["refund_policy_matches_requests"] = observed_decisions == [
            (method, resource_prefix + path, verdict, rule)
            for method, path, verdict, rule in expected_decisions
        ]
    return {"scenario": name, "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL",
            "exit_code": process.returncode, "duration_seconds": duration,
            "workload": workload, "service": snapshot, "policy_decisions": decisions}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--box-binary", type=Path, default=ROOT / "box-core/box")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "binary-manifest.json").read_text())
    for relative, expected_hash in manifest["files"].items():
        binary_file = args.box_binary.resolve() if relative.endswith("/box") else args.box_binary.resolve().parent / Path(relative).name
        if digest(binary_file) != expected_hash:
            raise SystemExit("Binary hash mismatch: " + str(binary_file))
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "mode": "deterministic scripted workload; no language model",
              "platform": {"system": platform.system(), "machine": platform.machine(),
                           "kernel": platform.release(), "python": sys.version, "uid": os.getuid()},
              "box": json.loads((ROOT / "binary-manifest.json").read_text()),
              "source_sha256": {p.name: digest(p) for p in ROOT.iterdir()
                                if p.is_file() and p.suffix in [".py", ".dw"]},
              "scenarios": []}
    for name in ["shipment", "failed", "unrelated", "refund-first"]:
        entry = run_scenario(name, output, args.box_binary.resolve())
        result["scenarios"].append(entry)
        print(name + ": " + entry["status"], flush=True)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    result["status"] = "PASS" if all(x["status"] == "PASS" for x in result["scenarios"]) else "FAIL"
    result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "result": str(output / "result.json")}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
