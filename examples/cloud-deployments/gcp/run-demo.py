#!/usr/bin/env python3
"""Verify Strands and Box on a Google Compute Engine Linux VM."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "eks" / "claude"
VENDOR = HERE / "vendor"
if VENDOR.is_dir():
    sys.path.insert(0, str(VENDOR))
sys.path.insert(0, str(COMMON))
from check_deployment import verify as verify_probe
from deployment_demo import decisions
from deployment_policy import deployment_policy
from deployment_service import DeploymentService


def model_endpoint(project, location, model):
    """Restrict the model permission to one project, location, and model."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project):
        raise ValueError("Provide a Google Cloud project ID")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location):
        raise ValueError("Invalid model location")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", model):
        raise ValueError("Invalid model ID")
    host = "aiplatform.googleapis.com" if location == "global" else location + "-aiplatform.googleapis.com"
    path = f"/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent"
    return host, path


def configure(root, command, service_url, project, location, model, *, live=False,
              failure_window=300, cooldown=600):
    """Give the workload its runtime, scratch directory, and exact HTTP routes."""
    root.mkdir(parents=True, exist_ok=False)
    scratch = root / "workspace"
    scratch.mkdir()
    service = urlsplit(service_url)
    policy = deployment_policy(service.hostname, service.port, failure_window, cooldown)
    environment = {"HOME": str(scratch), "TMPDIR": str(scratch), "PATH": "/usr/bin:/bin",
                   "LANG": "C.UTF-8", "OTEL_SDK_DISABLED": "true"}
    host, path = model_endpoint(project, location, model)
    if live:
        environment.update(GOOGLE_CLOUD_PROJECT=project, GOOGLE_CLOUD_LOCATION=location,
                           GOOGLE_MODEL_ID=model)
        policy += f'''
@id("google_model_connect")
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == {json.dumps(host)} && context.input.port == 443 }};
@id("google_model_request")
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == {json.dumps(host)} && context.input.port == 443 &&
        context.input.method == "POST" && context.input.path == {json.dumps(path)} }};
'''
    candidates = ["/usr/lib", "/usr/lib64", sysconfig.get_path("stdlib"),
                  sysconfig.get_path("platstdlib"), sysconfig.get_config_var("LIBDIR")]
    libraries = {str(Path(x).resolve()) for x in candidates if x and Path(x).is_dir()}
    libraries = sorted(x for x in libraries if not any(x != y and Path(x).is_relative_to(y) for y in libraries))
    files = sorted({str(Path(x).resolve()) for x in ("/etc/ld.so.cache", "/etc/passwd", "/etc/ssl/certs/ca-certificates.crt",
                                             "/etc/pki/tls/certs/ca-bundle.crt") if Path(x).is_file()})
    probe = ("import sys,json; sys.path[:0]=" + repr([str(VENDOR), str(HERE), str(COMMON)]) +
             "; import " + ("agent" if live else "deployment_probe") +
             "; print(json.dumps(sorted({m.__file__ for m in sys.modules.values() "
             "if (getattr(m, '__file__', '') or '').endswith('.so')})))")
    extensions = json.loads(subprocess.check_output([sys.executable, "-I", "-B", "-c", probe], text=True))
    execution = {str(Path(path).resolve()) if os.access(path, os.X_OK)
                 else str(Path(path).resolve().parent) for path in extensions}
    execution = sorted(path for path in execution if not any(
        path != parent and Path(parent).is_dir() and Path(path).is_relative_to(parent)
        for parent in execution))
    reads = libraries + [str(HERE), str(COMMON), str(scratch)]
    if sys.prefix != sys.base_prefix:
        reads.append(str(Path(sys.prefix).resolve()))
    config = ['name="google-deployment-demo"', "box_dir=" + json.dumps(str(root / "state")),
              'policy="policy.dw"', "[agent]", "command=" + json.dumps(command),
              "workspace=" + json.dumps(str(scratch)),
              "env={" + ",".join(k + "=" + json.dumps(v) for k, v in environment.items()) + "}",
              "[agent.filesystem]", "read=" + json.dumps(reads), "write=" + json.dumps([str(scratch)]),
              "read_file=" + json.dumps(files), "exec=" + json.dumps(execution)]
    if live:
        config += ["[egress.google_model]", "destinations=" + json.dumps([host + path]),
                   'secret.ref="env://GOOGLE_TOKEN"']
    (root / "policy.dw").write_text(policy)
    (root / "box.toml").write_text("\n".join(config) + "\n")
    return root


def metadata_token(minimum_lifetime):
    """Read a short-lived VM token only in the trusted controller."""
    request = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        value = json.load(response)
    token = value.get("access_token")
    if not isinstance(token, str) or not token or value.get("token_type") != "Bearer":
        raise ValueError("The VM metadata service did not return a bearer token")
    if value.get("expires_in", 0) < minimum_lifetime:
        raise ValueError("The VM token expires too soon. Retry after it refreshes.")
    return token


def execute(box, root, timeout, token=None):
    """Run Box without inherited cloud credentials and redact its output."""
    environment = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "EXPERIMENTAL_LINUX_SUPPORT": "TRUE"}
    if token:
        environment["GOOGLE_TOKEN"] = token
    started = time.monotonic()
    process = subprocess.Popen([str(box), "run", "--config", str(root / "box.toml")],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    expired = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        expired = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    if token:
        stdout, stderr = stdout.replace(token, "[REDACTED]"), stderr.replace(token, "[REDACTED]")
    (root / "stdout.txt").write_text(stdout)
    (root / "stderr.txt").write_text(stderr)
    return process.returncode, expired, stdout, stderr, time.monotonic() - started


def verify_agent(stdout, arrivals, audit, malformed, code, expired):
    """Check model-driven calls against Box decisions and backend receipts."""
    records = [json.loads(line.removeprefix("GCP_AGENT_RESULT ")) for line in stdout.splitlines()
               if line.startswith("GCP_AGENT_RESULT ")]
    agent = records[0] if len(records) == 1 else {}
    posts = [row for row in arrivals if row["method"] == "POST"]
    gets = [row for row in arrivals if row["method"] == "GET"]
    denials = [row for row in audit if row["action"] == "http:request" and row["verdict"] == "deny"
               and row["rule"] == "deployment_cooldown"]
    checks = {"agent_exit": code == 0 and not expired,
              "agent_result_recorded": bool(agent),
              "agent_checks_passed": agent.get("passed") is True and bool(agent.get("checks")) and all(value is True for value in agent.get("checks", {}).values()),
              "placeholder_credential": agent.get("credential_is_placeholder") is True,
              "sequential_executor": agent.get("executor") == "SequentialToolExecutor",
              "eight_model_responses": agent.get("model_responses") == 8,
              "model_usage_observed": agent.get("usage", {}).get("inputTokens", 0) > 0 and agent.get("usage", {}).get("outputTokens", 0) > 0,
              "three_failed_deployments": len(posts) == 3 and all(row["status"] == 503 for row in posts),
              "failures_within_five_minutes": len(posts) == 3 and posts[-1]["monotonic_ns"] - posts[0]["monotonic_ns"] <= 300_000_000_000,
              "retries_refused_by_policy": len(denials) >= 2,
              "diagnostics_after_failures": bool(posts) and any(row["status"] == 200 and row["monotonic_ns"] > posts[-1]["monotonic_ns"] for row in gets),
              "model_route_permitted": any(row["rule"] == "google_model_request" and row["verdict"] == "permit" for row in audit),
              "audit_readable": malformed == 0 and bool(audit)}
    return checks, agent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--location", default="global")
    parser.add_argument("--model", default="gemini-3.8-flash")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--box-binary", type=Path, default=os.environ.get("BOX_BIN", "target/release/strands-box"))
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--quick", action="store_true", help="Use 3/9-second probe windows instead of 300/600 seconds")
    args = parser.parse_args()
    model_endpoint(args.project, args.location, args.model)
    if args.quick and not args.probe_only:
        parser.error("--quick applies only to --probe-only")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        parser.error("Use a fresh output filename")
    box = args.box_binary.resolve()
    work = Path(tempfile.mkdtemp(prefix="box-gcp-", dir=output.parent))
    receipt = {"passed": False, "checks": {}, "mode": "probe" if args.probe_only else "Strands SDK with Gemini",
               "platform": {"system": platform.system(), "architecture": platform.machine(),
                            "kernel": platform.release(), "python": platform.python_version(), "uid": os.getuid()},
               "model": {"id": args.model, "location": args.location},
               "box_sha256": hashlib.sha256(box.read_bytes()).hexdigest(), "directory": str(work)}
    token = None
    try:
        if os.getuid() == 0:
            raise ValueError("Run the demo as an ordinary user")
        failure_window, cooldown = (3, 9) if args.quick else (300, 600)
        receipt.update(failure_window_seconds=failure_window, cooldown_seconds=cooldown,
                       expiry_checked=args.probe_only, default_durations=not args.quick)
        if not args.probe_only:
            token = metadata_token(270)
            receipt["dependencies"] = {name: importlib.metadata.version(name) for name in
                                       ("strands-agents", "google-genai", "google-auth", "httpx")}
        with DeploymentService() as service:
            script = COMMON / "deployment_probe.py" if args.probe_only else HERE / "agent.py"
            command = [str(Path(sys.executable).resolve()), "-B", str(script), service.url]
            if args.probe_only:
                command += [str(failure_window), str(cooldown)]
            root = configure(work / "run", command, service.url, args.project, args.location, args.model,
                             live=not args.probe_only, failure_window=failure_window, cooldown=cooldown)
            code, expired, stdout, stderr, duration = execute(box, root, cooldown + 90 if args.probe_only else 210, token)
            arrivals = service.receipts
        audit, malformed = decisions(root)
        if args.probe_only:
            try:
                agent = json.loads(stdout)
                steps = agent["steps"]
            except (ValueError, KeyError, TypeError):
                agent, steps = {}, []
            checks = verify_probe(steps, arrivals, audit, malformed, failure_window, cooldown)
            checks["process_exit"] = code == 0 and not expired
        else:
            checks, agent = verify_agent(stdout, arrivals, audit, malformed, code, expired)
        receipt.update(passed=all(checks.values()), checks=checks, agent=agent,
                       service_receipts=arrivals, decisions=audit, duration_seconds=duration,
                       exit_code=code, timed_out=expired, stderr=stderr[-12000:])
    except Exception as error:
        message = str(error).replace(token, "[REDACTED]") if token else str(error)
        receipt["error"] = {"type": type(error).__name__, "message": message}
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("GCP_BOX_RESULT " + json.dumps({"passed": receipt["passed"], "checks": receipt["checks"], "output": str(output)}), flush=True)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
