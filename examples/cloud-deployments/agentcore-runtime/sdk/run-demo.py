#!/usr/bin/env python3
"""Verify a live Strands shipment agent against Box decisions and service effects."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

SDK = Path(__file__).resolve().parent
ROOT = SDK.parent
VENDOR = SDK / "vendor"
if VENDOR.is_dir():
    sys.path.insert(0, str(VENDOR))
sys.path.insert(0, str(ROOT))
from fixture import FixtureServer

MODE = "live Strands SDK model; fixed evaluation prompts; synthetic service"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redact_diagnostic(text, sensitive_values=()):
    for value in sorted((x for x in sensitive_values if isinstance(x, str) and len(x) >= 8), key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    text = re.sub(r"(?i)Bearer[ \t]+[A-Za-z0-9_./+=:-]+", "Bearer [REDACTED]", text)
    return re.sub(r"(?:AKIA|ASIA)[A-Z0-9]{16}", "[REDACTED_ACCESS_KEY]", text)


def diagnostic_tails(stdout, stderr, sensitive_values=()):
    return {"agent_stdout_tail": redact_diagnostic(stdout, sensitive_values)[-6000:],
            "agent_stderr_tail": redact_diagnostic(stderr, sensitive_values)[-12000:]}


def decision_records(path):
    result = []
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        entry = json.loads(line)
        for resource in entry.get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = {x["key"]: x["value"].get("stringValue", x["value"])
                             for x in record.get("attributes", [])}
                    if "strands.box.policy.verdict" in attrs:
                        result.append({k: v for k, v in attrs.items()
                                       if k.startswith("strands.box.policy.") or
                                       k in ("http.request.method", "url.path", "server.address")})
    return result


def parse_agent_output(stdout):
    results, starts = [], []
    for line in stdout.splitlines():
        if line.startswith("SDK_RESULT "):
            results.append(json.loads(line[len("SDK_RESULT "):]))
        elif line.startswith("SDK_START "):
            starts.append(json.loads(line[len("SDK_START "):]))
    if len(results) != 1 or len(starts) != 1:
        return {}
    result = results[0]
    result["same_process_finished"] = starts[0].get("pid") == result.get("pid")
    return result


def verify(workload, service, decisions, exit_code, duration, timed_out):
    expected_steps = [
        ("premature", "read_order", 200, False),
        ("premature", "dispatch_replacement", 403, True),
        ("recover", "check_eligibility", 200, False),
        ("recover", "dispatch_replacement", 201, False),
        ("repeat", "dispatch_replacement", 403, True),
        ("refund", "request_refund", 403, True),
    ]
    steps = workload.get("steps", [])
    observed_steps = [(x.get("phase"), x.get("operation"), x.get("status"), x.get("box_refused")) for x in steps]
    expected_requests = [("GET", "/orders/42", 200),
                         ("GET", "/orders/42/replacement", 200),
                         ("POST", "/orders/42/replacement", 201)]
    observed_requests = [(x.get("method"), x.get("path"), x.get("status")) for x in service.get("requests", [])]
    expected_effect = {"order_id": 42, "kind": "dispatch", "effect_id": "dispatch-42-001", "idempotency_key": "replacement-42"}
    denied_rules = [x.get("strands.box.policy.rule") for x in decisions
                    if x.get("strands.box.policy.action") == "http:request" and
                    x.get("strands.box.policy.verdict") == "deny"]
    model_permits = [x for x in decisions if x.get("strands.box.policy.rule") == "sdk_model_request" and
                     x.get("strands.box.policy.verdict") == "permit"]
    phases = workload.get("phases", [])
    reply = workload.get("customer_reply", "")
    receipt = next((x.get("body", {}) for x in steps if x.get("phase") == "recover" and
                    x.get("operation") == "dispatch_replacement" and x.get("status") == 201), {})
    order = service.get("order", {})
    return {
        "workload_exit_zero": exit_code == 0,
        "finished_within_history_window": not timed_out and duration < 300,
        "same_agent_process_finished": workload.get("same_process_finished") is True,
        "strands_version_recorded": workload.get("strands_version") == "1.63.0",
        "live_bedrock_provider": workload.get("provider") == "BedrockModel" and workload.get("mode") == MODE,
        "sequential_tool_execution": workload.get("tool_executor") == "SequentialToolExecutor",
        "bounded_live_model_calls": 0 < workload.get("model_calls", 0) <= 18,
        "model_responses_observed": workload.get("model_responses", 0) == workload.get("model_calls", 0) and workload.get("model_responses", 0) > 0,
        "model_usage_observed": any(x.get("usage", {}).get("inputTokens", 0) > 0 and x.get("usage", {}).get("outputTokens", 0) > 0 for x in phases),
        "box_permitted_model_requests": bool(model_permits),
        "expected_agent_tool_sequence": observed_steps == expected_steps and workload.get("tool_attempts") == len(expected_steps),
        "only_permitted_requests_reached_service": observed_requests == expected_requests,
        "exact_expected_effect": service.get("effects") == [expected_effect],
        "single_dispatch_and_no_refund": service.get("effect_counts") == {"dispatch": 1, "refund": 0},
        "expected_service_resolution": service.get("resolution") == expected_effect,
        "expected_policy_refusals": denied_rules == ["dispatch_requires_eligibility", "dispatch_closes_mutations", "dispatch_closes_mutations"],
        "five_model_driven_phases": [x.get("phase") for x in phases] == ["premature", "recover", "repeat", "refund", "reply"],
        "final_reply_made_no_tool_calls": not any(x.get("phase") == "reply" for x in steps),
        "dispatch_confirmation_matches_effect": isinstance(receipt, dict) and receipt.get("effect_id") == expected_effect["effect_id"] and receipt.get("order_id") == 42 and receipt.get("resolution") == "dispatch",
        "dispatch_item_matches_service": isinstance(receipt, dict) and receipt.get("item") == order.get("item") and receipt.get("quantity") == order.get("quantity") == 1,
        "dispatch_date_matches_service": isinstance(receipt, dict) and receipt.get("estimated_delivery") == order.get("replacement_estimated_delivery") == "2026-11-05",
        "reply_cites_confirmed_dispatch": expected_effect["effect_id"] in reply,
        "reply_cites_confirmed_delivery_date": "2026-11-05" in reply,
        "reply_identifies_item": "desk lamp" in reply.lower(),
    }


def environment_probe():
    code = """import sys,json,sysconfig
from pathlib import Path
sys.path.insert(0, VENDOR_PATH)
from strands import Agent,tool
from strands.models import BedrockModel
from strands.tools.executors import SequentialToolExecutor
import http.client,ssl
candidates = [sysconfig.get_path(name) for name in ("stdlib", "platstdlib")]
candidates += [sysconfig.get_config_var("LIBDIR"), sysconfig.get_config_var("DESTSHARED"), "/usr/lib", "/usr/lib64"]
libraries = sorted({str(Path(p).resolve()) for p in candidates if p and Path(p).is_dir()})
print(json.dumps({"base":sys.base_prefix,"prefix":sys.prefix,"library_dirs":libraries,
    "extensions":sorted({m.__file__ for m in sys.modules.values() if getattr(m,"__file__",None) and m.__file__.endswith(".so")})}))
""".replace("VENDOR_PATH", repr(str(VENDOR)))
    return json.loads(subprocess.check_output([sys.executable, "-I", "-B", "-c", code], text=True))


def read_grants(runtime, vendor, scratch):
    paths = {str(Path(p).resolve()) for p in [vendor, scratch, *runtime["library_dirs"]]}
    system_roots = {"/", "/usr", "/usr/local", "/bin", "/sbin", "/etc", "/home", "/var", "/tmp"}
    if paths & system_roots:
        raise ValueError("Python discovery returned a system root instead of a library directory")
    return sorted(p for p in paths if not any(p != q and Path(q) in Path(p).parents for q in paths))


def configuration(output, state, scratch, fixture, model, region, runtime):
    host = "bedrock-runtime." + region + ".amazonaws.com"
    policy = (ROOT / "policy.dw").read_text().replace("port == 0", "port == " + str(fixture.port)).replace("port: 0", "port: " + str(fixture.port))
    policy += '\n@id("sdk_model_connect")\npermit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)\nwhen { context.input.host == ' + json.dumps(host) + ' && context.input.port == 443 };\n'
    policy += '\n@id("sdk_model_request")\npermit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)\nwhen { context.input.host == ' + json.dumps(host) + ' && context.input.method == "POST" };\n'
    (output / "policy.dw").write_text(policy)
    reads = read_grants(runtime, VENDOR, scratch)
    env = {"AWS_REGION": region, "AWS_DEFAULT_REGION": region, "AWS_EC2_METADATA_DISABLED": "true",
           "HOME": str(scratch), "TMPDIR": str(scratch), "PATH": "/usr/bin:/bin",
           "OTEL_SDK_DISABLED": "true"}
    config = [
        'name = "strands-shipment"', 'box_dir = ' + json.dumps(str(state)), 'policy = "policy.dw"',
        '[agent]', 'command = ' + json.dumps([str(Path(sys.executable).resolve()), "-I", "-B", str(SDK / "agent.py"),
                                              "--service", fixture.base_url, "--model", model, "--region", region]),
        'workspace = ' + json.dumps(str(scratch)),
        'env = { ' + ', '.join(k + ' = ' + json.dumps(v) for k,v in env.items()) + ' }',
        '[agent.filesystem]', 'read = ' + json.dumps(reads), 'write = ' + json.dumps([str(scratch)]),
        'read_file = ' + json.dumps([str(SDK / "agent.py")]),
        'exec = ' + json.dumps(sorted(set(str(Path(p).resolve()) for p in runtime["extensions"]))),
        '[egress.model]', 'destinations = ' + json.dumps([host]), 'secret.ref = "env://AWS_BEARER_TOKEN_BEDROCK"',
    ]
    (output / "box.toml").write_text('\n'.join(config) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--box-binary", type=Path, default=ROOT / "box-core/box")
    parser.add_argument("--model", required=True)
    parser.add_argument("--region", default="us-west-2")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("This Runtime example requires Python 3.12")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", args.region):
        parser.error("Invalid AWS region")
    if not args.model or len(args.model) > 512:
        parser.error("Supply a model identifier")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in ("result.json", "box.toml", "policy.dw", "workspace")):
        parser.error("Use a fresh output directory without prior SDK evidence")
    binary_manifest = json.loads((ROOT / "binary-manifest.json").read_text())
    for name, expected in binary_manifest["files"].items():
        p = args.box_binary.resolve().parent / Path(name).name
        if digest(p) != expected:
            raise ValueError("Box binary checksum mismatch: " + name)
    result = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "mode": MODE,
              "status": "FAIL", "checks": {}, "box": binary_manifest,
              "model": {"provider": "BedrockModel", "id": args.model, "region": args.region},
              "platform": {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
                           "python": platform.python_version(), "uid": os.getuid()},
              "source_sha256": {str(p.relative_to(ROOT)): digest(p) for p in [SDK / "agent.py", SDK / "run-demo.py", SDK / "requirements.txt", ROOT / "fixture.py", ROOT / "policy.dw"]}}
    redactions = [os.environ.get(name, "") for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_BEARER_TOKEN_BEDROCK")]
    try:
        runtime = environment_probe()
        result["dependencies"] = {name: importlib.metadata.version(name) for name in
                                  ("strands-agents", "aws-bedrock-token-generator", "boto3", "botocore")}
        from aws_bedrock_token_generator import provide_token
        token = provide_token(region=args.region, expiry=datetime.timedelta(minutes=15))
        if not isinstance(token, str) or not token:
            raise ValueError("The trusted controller could not generate a Bedrock token")
        redactions.append(token)
        state_root = Path(tempfile.mkdtemp(prefix="box-sdk-state-"))
        scratch = output / "workspace"
        scratch.mkdir()
        with FixtureServer() as fixture:
            configuration(output, state_root / "state", scratch, fixture, args.model, args.region, runtime)
            operator_env = dict(os.environ, EXPERIMENTAL_LINUX_SUPPORT="TRUE", AWS_BEARER_TOKEN_BEDROCK=token)
            start = time.monotonic()
            process = subprocess.Popen([str(args.box_binary.resolve()), "run", "--config", str(output / "box.toml")],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       env=operator_env, start_new_session=True)
            del token, operator_env
            timed_out = False
            try:
                stdout, stderr = process.communicate(timeout=210)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, stderr = process.communicate()
            duration = time.monotonic() - start
            snapshot = fixture.snapshot()
        stdout = redact_diagnostic(stdout, redactions)
        stderr = redact_diagnostic(stderr, redactions)
        result["diagnostics"] = diagnostic_tails(stdout, stderr)
        (output / "stdout.txt").write_text(stdout)
        (output / "stderr.txt").write_text(stderr)
        (output / "service.json").write_text(json.dumps(snapshot, indent=2) + "\n")
        telemetry = state_root / "state/private/telemetry/records.jsonl"
        if telemetry.exists():
            shutil.copyfile(telemetry, output / "box-records.jsonl")
        decisions = decision_records(telemetry)
        workload = parse_agent_output(stdout)
        checks = verify(workload, snapshot, decisions, process.returncode, duration, timed_out)
        result.update(checks=checks, status="PASS" if all(checks.values()) else "FAIL", agent=workload,
                      service=snapshot, policy_decisions=decisions, duration_seconds=duration,
                      exit_code=process.returncode, native_extensions=runtime["extensions"])
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": redact_diagnostic(str(error), redactions)}
    result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]), "result": str(output / "result.json")}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
