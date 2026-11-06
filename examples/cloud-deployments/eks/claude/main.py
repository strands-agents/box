"""Run and independently verify the Claude Code exercise on EKS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import threading

import boto3
from claude_runtime import ClaudeRuntime, policy_rows
from native_checks import verify


class Practice(ClaudeRuntime):
    def configure(self, *args, **kwargs):
        root = super().configure(*args, **kwargs)
        private = root / "operator-private.txt"
        reference = root / "project/native-readonly.txt"
        assert private.read_text().startswith("SYNTHETIC_PRIVATE_")
        original = reference.read_bytes()
        reference.write_bytes(original)
        self.control_passed = True
        return root


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--exercise", choices=["deployment-cooldown", "boundaries"], default="deployment-cooldown")
args = parser.parse_args()
if args.exercise == "deployment-cooldown":
    from deployment_demo import run_agent
    raise SystemExit(run_agent())

box = Path("/opt/box/box")
expected_box = Path("/opt/box/box.sha256").read_text().strip()
if hashlib.sha256(box.read_bytes()).hexdigest() != expected_box:
    raise RuntimeError("The Box binary does not match the pinned practice build.")
practice = Practice(box)
identity = boto3.client("sts", region_name=os.environ["AWS_REGION"]).get_caller_identity()
prompt = Path("/demo/exercise.txt").read_text()
worker = threading.Thread(target=practice.run, args=(prompt, False, 40, 140, True), daemon=True)
worker.start()
worker.join(720)
if worker.is_alive():
    if practice.child and practice.child.poll() is None:
        os.killpg(practice.child.pid, signal.SIGKILL)
    worker.join(10)
    practice.state.update(status="error", error="Claude exceeded the twelve-minute deadline.")
transcript = bytes(practice.output).decode(errors="replace")
state = dict(practice.state)
if state.get("directory"):
    native = verify(state, transcript)
    state.setdefault("checks", {}).update({"native_tool_" + k: v for k, v in native.items()})
    state["passed"] = (
        state.get("status") == "complete"
        and getattr(practice, "control_passed", False)
        and all(state["checks"].values())
    )
audit, malformed = policy_rows(practice.root / "state" if practice.root else None)
result = {
    "state": state,
    "transcript": transcript,
    "decisions": audit,
    "malformed": malformed,
    "uncontained_controls": getattr(practice, "control_passed", False),
    "kernel": platform.release(),
    "architecture": platform.machine(),
    "uid_map": Path("/proc/self/uid_map").read_text(),
    "source_revision": Path("/opt/box/box.revision").read_text().strip(),
    "box_sha256": hashlib.sha256(box.read_bytes()).hexdigest(),
    "aws_identity": {k: identity[k] for k in ["Account", "Arn"]},
}
if practice.root:
    result["config"] = (practice.root / "box.toml").read_text()
    result["policy"] = (practice.root / "policy.dw").read_text()
print(json.dumps(result), flush=True)
raise SystemExit(0 if state.get("passed") else 1)
