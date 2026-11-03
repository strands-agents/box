#!/usr/bin/env python3
"""Run Box shipment examples and policy controls through Runtime HTTP invocations."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
RUN_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
STATE = {"status": "idle", "mode": "deterministic scripted workload; no language model"}
APPLICATION = None


def prepare_application():
    manifest = json.loads((ROOT / "deployment-manifest.json").read_text())
    destination = Path(tempfile.mkdtemp(prefix="box-shipment-app-", dir="/var/tmp"))
    for name, expected in manifest["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid packaged path")
        source = ROOT / relative
        if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError("Packaged file checksum mismatch: " + name)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        native_dependency = ((relative.parts[:2] == ("sdk", "vendor") and relative.suffix == ".so")
                             or (relative.parts[:2] == ("langchain-example", "vendor")
                                 and (relative.suffix == ".so" or ".so." in relative.name)))
        target.chmod(0o500 if relative.parts[0] == "box-core" or native_dependency else 0o400)
    return destination


def set_operator_identity(application):
    home = Path(tempfile.mkdtemp(prefix="box-shipment-home-", dir="/var/tmp"))
    if os.getuid() == 0:
        for path in [application, *application.rglob("*"), home]:
            os.chown(path, 991, 991, follow_symlinks=False)
        os.setgroups([])
        os.setgid(991)
        os.setuid(991)
    os.environ["HOME"] = str(home)
    if os.getuid() == 0:
        raise RuntimeError("The demonstration requires a non-root operator")


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[1]), fields[19]
    except (OSError, ValueError, IndexError):
        return None


def stop_process_tree(process):
    processes = {}
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            identity = process_identity(int(path.name))
            if identity:
                processes[int(path.name)] = identity
    selected = {process.pid}
    while True:
        expanded = selected | {pid for pid, (parent, _) in processes.items() if parent in selected}
        if expanded == selected:
            break
        selected = expanded
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in sorted(selected, reverse=True):
            if processes.get(pid) is not None and process_identity(pid) == processes[pid]:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    process.wait(timeout=5)


def run_demo(example="shipment"):
    scripts = {"shipment": "run-demo.py", "research": "research/run-demo.py",
               "shipment-strands": "sdk/run-demo.py", "shipment-langchain": "langchain-example/run-demo.py"}
    live_examples = {"shipment-strands": ("Strands SDK", "Strands", "--with-strands"),
                     "shipment-langchain": ("LangChain", "LangChain", "--with-langchain")}
    mode = (live_examples[example][0] + " with live Bedrock responses and a fixed test conversation"
            if example in live_examples else "deterministic scripted workload; no language model")
    timeout = 240 if example in live_examples else 120
    if example not in scripts:
        return 400, {"error": "Unknown example"}
    if example in live_examples and (
        not (APPLICATION / scripts[example]).is_file()
        or not os.environ.get("BOX_DEMO_MODEL_ID") or not os.environ.get("BOX_DEMO_REGION")
    ):
        return 400, {"error": "This deployment has no " + live_examples[example][1]
                     + " example. Package and deploy with " + live_examples[example][2] + "."}
    if not RUN_LOCK.acquire(blocking=False):
        return 409, {"error": "A demonstration is already running"}
    directory = Path(tempfile.mkdtemp(prefix="box-shipment-run-", dir="/var/tmp"))
    with STATE_LOCK:
        STATE.update(status="running", example=example, mode=mode)
    try:
        stdout_path, stderr_path = directory / "runner.stdout", directory / "runner.stderr"
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            command = [sys.executable, str(APPLICATION / scripts[example]), "--output-dir", str(directory),
                       "--box-binary", str(APPLICATION / "box-core/box")]
            if example in live_examples:
                command += ["--model", os.environ["BOX_DEMO_MODEL_ID"], "--region", os.environ["BOX_DEMO_REGION"]]
            process = subprocess.Popen(
                command,
                stdout=stdout, stderr=stderr, start_new_session=True,
                env=dict(os.environ, EXPERIMENTAL_LINUX_SUPPORT="TRUE"),
            )
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_process_tree(process)
                raise RuntimeError("The demonstration exceeded " + str(timeout) + " seconds")
        result_path = directory / "result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        success = process.returncode == 0 and result.get("status") == "PASS"
        body = {
            "status": "PASS" if success else "FAIL",
            "example": example,
            "mode": mode,
            "runtime": {"uid": os.getuid(), "gid": os.getgid(), "architecture": platform.machine(),
                        "kernel": platform.release(), "python": platform.python_version()},
            "result": result,
            "runner_stdout": stdout_path.read_text()[-16000:],
            "runner_stderr": stderr_path.read_text()[-16000:],
            "evidence_sha256": {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in directory.rglob("*") if p.is_file()
                                and "state" not in p.relative_to(directory).parts},
        }
        with STATE_LOCK:
            STATE.update(status="complete", result_status=body["status"])
        return 200, body
    except Exception as error:
        with STATE_LOCK:
            STATE.update(status="error")
        return 500, {"status": "FAIL", "error": type(error).__name__ + ": " + str(error),
                     "mode": mode}
    finally:
        RUN_LOCK.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/ping":
            return self.reply(404, {"error": "Unknown path"})
        return self.reply(200, {"status": "HealthyBusy" if RUN_LOCK.locked() else "Healthy"})

    def do_POST(self):
        if self.path != "/invocations":
            return self.reply(404, {"error": "Unknown path"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024:
                raise ValueError("Invalid request length")
            payload = json.loads(self.rfile.read(length))
            if payload == {"operation": "status"}:
                with STATE_LOCK:
                    return self.reply(200, dict(STATE))
            if payload not in ({"operation": "run"}, {"operation": "run", "example": "shipment"},
                               {"operation": "run", "example": "research"},
                               {"operation": "run", "example": "shipment-strands"},
                               {"operation": "run", "example": "shipment-langchain"}):
                raise ValueError("Use only the fixed run or status operation")
        except (ValueError, TypeError):
            return self.reply(400, {"error": "Invalid invocation"})
        status, body = run_demo(payload.get("example", "shipment"))
        return self.reply(status, body)


if __name__ == "__main__":
    os.umask(0o077)
    APPLICATION = prepare_application()
    set_operator_identity(APPLICATION)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
