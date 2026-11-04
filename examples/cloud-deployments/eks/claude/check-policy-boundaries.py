#!/usr/bin/env python3
"""Check the Claude sample's native and shell file permissions without a model."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def check(box_binary, source, evidence_dir):
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    previous_region = os.environ.get("AWS_REGION")
    os.environ["AWS_REGION"] = "us-west-2"
    try:
        spec = importlib.util.spec_from_file_location("tested_claude_runtime", source)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
    finally:
        if previous_region is None:
            os.environ.pop("AWS_REGION", None)
        else:
            os.environ["AWS_REGION"] = previous_region
    fixture = Path(tempfile.mkdtemp(prefix="box-policy-test-", dir="/var/tmp")) / "fixture"
    controller = runtime.ClaudeRuntime(box_binary)
    controller.configure(Path("/usr/bin/bash"), None, False, False, fixture)
    script = r"""set -eu
zsh -lc 'printf "def add(a, b):\n    return a + b\n" > app.py'
printf 'app_write ALLOWED\n'
printf 'native_scratch_ok\n' > .agent-tmp/native-test.txt
printf 'native_scratch_write ALLOWED\n'
if printf 'NATIVE_CHANGED\n' > native-readonly.txt; then printf 'native_reference_write ALLOWED\n'; else printf 'native_reference_write REFUSED\n'; fi
if zsh -lc 'printf "SHELL_CHANGED\n" > native-readonly.txt'; then printf 'shell_reference_write ALLOWED\n'; else printf 'shell_reference_write REFUSED\n'; fi
if IFS= read -r value < ../operator-private.txt; then printf 'native_private_read ALLOWED\n'; else printf 'native_private_read REFUSED\n'; fi
if zsh -lc 'cat ../operator-private.txt'; then printf 'shell_private_read ALLOWED\n'; else printf 'shell_private_read REFUSED\n'; fi
if zsh -lc 'rm keep.txt'; then printf 'shell_delete ALLOWED\n'; else printf 'shell_delete REFUSED\n'; fi
"""
    configuration = (fixture / "box.toml").read_text().splitlines()
    command = ["/usr/bin/bash", "--noprofile", "--norc", "-c", script]
    configuration = ["command=" + json.dumps(command) if line.startswith("command=") else line
                     for line in configuration]
    (fixture / "box.toml").write_text("\n".join(configuration) + "\n")
    environment = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "EXPERIMENTAL_LINUX_SUPPORT": "TRUE",
                   "AWS_BEARER_TOKEN_BEDROCK": "SYNTHETIC_OFFLINE_TOKEN_1234567890"}
    process = subprocess.Popen([str(box_binary), "run", "--config", str(fixture / "box.toml")],
                               env=environment, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    decisions, malformed = runtime.policy_rows(fixture / "state")

    def decision(action, verdict, suffix):
        return any(row["action"] == action and row["verdict"] == verdict
                   and row["path"].endswith(suffix) for row in decisions)

    checks = {
        "process_exit_zero": process.returncode == 0,
        "source_unchanged_during_test": hashlib.sha256(source.read_bytes()).hexdigest() == source_hash,
        "app_write_permitted": "app_write ALLOWED\n" in stdout
            and (fixture / "project/app.py").read_text() == "def add(a, b):\n    return a + b\n"
            and decision("fs:write", "permit", "/project/app.py"),
        "native_scratch_write_permitted": "native_scratch_write ALLOWED\n" in stdout
            and (fixture / "project/.agent-tmp/native-test.txt").read_text() == "native_scratch_ok\n",
        "native_reference_write_refused": "native_reference_write REFUSED\n" in stdout,
        "shell_reference_write_refused": "shell_reference_write REFUSED\n" in stdout
            and decision("fs:write", "deny", "/project/native-readonly.txt"),
        "reference_unchanged": (fixture / "project/native-readonly.txt").read_text()
            == "NATIVE_REFERENCE_MUST_NOT_CHANGE\n",
        "native_private_read_refused": "native_private_read REFUSED\n" in stdout,
        "shell_private_read_refused": "shell_private_read REFUSED\n" in stdout
            and decision("fs:read", "deny", "/operator-private.txt"),
        "shell_delete_refused": "shell_delete REFUSED\n" in stdout
            and decision("fs:delete", "deny", "/project/keep.txt")
            and (fixture / "project/keep.txt").read_text() == "DO_NOT_DELETE\n",
        "audit_readable": malformed == 0,
    }
    receipt = {"passed": all(checks.values()), "checks": checks, "source": str(source),
               "source_sha256": source_hash, "box_binary": str(box_binary),
               "box_sha256": hashlib.sha256(box_binary.read_bytes()).hexdigest(),
               "platform": platform.platform(), "python": platform.python_version(),
               "uid": os.getuid(), "fixture": str(fixture), "returncode": process.returncode,
               "decisions": decisions, "stdout": stdout, "stderr": stderr}
    evidence_dir.mkdir(parents=True, exist_ok=False)
    (evidence_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (evidence_dir / "stdout.txt").write_text(stdout)
    (evidence_dir / "stderr.txt").write_text(stderr)
    (evidence_dir / "box.toml").write_text((fixture / "box.toml").read_text())
    (evidence_dir / "policy.dw").write_text((fixture / "policy.dw").read_text())
    audit = fixture / "state/private/telemetry/records.jsonl"
    if audit.exists():
        (evidence_dir / "records.jsonl").write_bytes(audit.read_bytes())
    print(json.dumps({"passed": receipt["passed"], "checks": checks,
                      "receipt": str(evidence_dir / "receipt.json")}, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--box-binary", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).with_name("claude_runtime.py"))
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(check(args.box_binary.resolve(), args.source.resolve(), args.evidence_dir.resolve()))
