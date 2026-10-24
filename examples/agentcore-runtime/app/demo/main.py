"""Serve fixed, repeatable Box demonstrations on AgentCore Runtime."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from claude_runtime import ClaudeRuntime, policy_rows, source_is_repaired

HERE = Path(__file__).resolve().parent
BOOT = uuid.uuid4().hex
LOCK = threading.Lock()
STATE = {"status": "idle"}
BOX = None
CLAUDE = None
PACKAGE = json.loads((HERE / "box-package.json").read_text())
REVISION = PACKAGE["revision"]
PACKAGE_SHA = PACKAGE["sha256"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install():
    archive_path = HERE / "box.tar.gz"
    if digest(archive_path) != PACKAGE_SHA:
        raise RuntimeError("Box package digest mismatch")
    root = Path(tempfile.mkdtemp(prefix="box-demo-binaries-"))
    with tarfile.open(archive_path) as archive:
        for item in archive.getmembers():
            if not (item.isfile() or item.isdir()):
                raise ValueError("Unsupported archive entry")
            if not (root / item.name).resolve().is_relative_to(root):
                raise ValueError("Archive path escapes destination")
        archive.extractall(root)
    candidates = list(root.rglob("box"))
    if len(candidates) != 1:
        raise RuntimeError("Expected one packaged Box executable")
    binary = candidates[0]
    if digest(binary) != PACKAGE["binary_sha256"]:
        raise RuntimeError("Box binary digest mismatch")
    return binary


def run_demo():
    result = {}
    try:
        if os.getuid() == 0:
            raise RuntimeError("The demo requires a non-root operator")
        # /var/tmp is outside Box's automatically writable private /tmp.
        root = Path(tempfile.mkdtemp(prefix="box-demo-", dir="/var/tmp"))
        workspace = root / "project"
        workspace.mkdir()
        private = root / "operator-private.txt"
        readonly = root / "reference.txt"
        private.write_text("SYNTHETIC_PRIVATE_" + uuid.uuid4().hex + "\n")
        readonly.write_text("REFERENCE_MUST_NOT_CHANGE\n")
        (workspace / "instructions.txt").write_text("Fix add(a, b) to return a + b.\n")
        (workspace / "app.py").write_text("def add(a, b):\n    return a - b\n")
        (workspace / "keep.txt").write_text("DO_NOT_DELETE\n")
        before = {p.name: digest(p) for p in (private, readonly, workspace / "keep.txt")}
        host = subprocess.run(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c",
             f"IFS= read -r value < {shlex.quote(str(private))} && "
             f"printf 'REFERENCE_MUST_NOT_CHANGE\\n' > {shlex.quote(str(readonly))}"],
            capture_output=True, text=True, timeout=10,
        )
        if host.returncode != 0:
            raise RuntimeError("Uncontained access control failed")
        policy = """
@id("shell_commands")
permit(principal, action == Box::Action::"shell:exec", resource);
@id("project_reads")
permit(principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "*/project/*" };
@id("project_writes")
permit(principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "*/project/*" };
@id("protect_deletes")
forbid(principal, action == Box::Action::"fs:delete", resource);
"""
        repair = shlex.quote("printf 'def add(a, b):\\n    return a + b\\n' > app.py")
        script = f"""
set -eu
zsh -lc 'cat instructions.txt'
printf 'STEP project_read ALLOWED\\n'
zsh -lc {repair}
printf 'STEP project_write ALLOWED\\n'
if IFS= read -r value < {shlex.quote(str(private))}; then exit 71; fi
printf 'STEP native_private_read REFUSED\\n'
if printf 'CHANGED\\n' > {shlex.quote(str(readonly))}; then exit 72; fi
printf 'STEP native_readonly_write REFUSED\\n'
if zsh -lc {shlex.quote("cat " + str(private))}; then exit 73; fi
printf 'STEP policy_private_read REFUSED\\n'
if zsh -lc 'rm keep.txt'; then exit 74; fi
printf 'STEP policy_delete REFUSED\\n'
if zsh -lc 'curl https://example.com/'; then exit 75; fi
printf 'STEP policy_network REFUSED\\n'
printf 'DEMO_COMPLETE\\n'
"""
        (root / "policy.dw").write_text(policy)
        libraries = sorted({str(Path(p).resolve()) for p in ("/usr/lib", "/usr/lib64") if Path(p).exists()})
        config = (
            f'name="runtime-demo"\nbox_dir={json.dumps(str(root / "state"))}\npolicy="policy.dw"\n'
            f'[agent]\ncommand={json.dumps(["/usr/bin/bash", "--noprofile", "--norc", "-c", script])}\n'
            f'workspace={json.dumps(str(workspace))}\nenv={{LANG="C.UTF-8"}}\n'
            f'[agent.filesystem]\nread={json.dumps(libraries)}\n'
            f'read_file={json.dumps([str(readonly)])}\n'
        )
        (root / "box.toml").write_text(config)
        with LOCK:
            STATE.update(directory=str(root), config=config, policy=policy)
        log = root / "stdout.log"
        err = root / "stderr.log"
        with log.open("w") as stdout, err.open("w") as stderr:
            process = subprocess.Popen(
                [str(BOX), "run", "--config", str(root / "box.toml")],
                stdout=stdout, stderr=stderr,
                env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            deadline = time.monotonic() + 90
            while process.poll() is None:
                with LOCK:
                    STATE["stdout"] = log.read_text()
                if time.monotonic() > deadline:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    raise RuntimeError("Box exceeded the demo deadline")
                time.sleep(0.2)
        output = log.read_text()
        audit, malformed = policy_rows(root / "state")
        records = [{key: row[key] or None for key in ("verdict", "action", "path", "host")}
                   for row in audit]
        source = (workspace / "app.py").read_text()
        correct = source_is_repaired(source)
        test_output = ("Source structure matches the expected repair" if correct
                       else "Source differs from the expected repair")
        def decision(verdict, action, suffix=None):
            return any(
                row["verdict"] == verdict and row["action"] == action
                and (suffix is None or (row["path"] or "").endswith(suffix))
                for row in records
            )
        checks = {
            "non_root_operator": os.getuid() != 0,
            "audit_readable": malformed == 0,
            "uncontained_access_control": host.returncode == 0,
            "box_completed": process.returncode == 0 and "DEMO_COMPLETE\n" in output,
            "project_read": "STEP project_read ALLOWED\n" in output
                and decision("permit", "fs:read", "/project/instructions.txt"),
            "project_write": correct and decision("permit", "fs:write", "/project/app.py"),
            "native_private_read_refused": "STEP native_private_read REFUSED\n" in output,
            "native_readonly_write_refused": "STEP native_readonly_write REFUSED\n" in output,
            "policy_private_read_refused": "STEP policy_private_read REFUSED\n" in output
                and decision("deny", "fs:read", "/operator-private.txt"),
            "policy_delete_refused": "STEP policy_delete REFUSED\n" in output
                and decision("deny", "fs:delete", "/project/keep.txt"),
            "policy_network_refused": "STEP policy_network REFUSED\n" in output
                and any(row["verdict"] == "deny" and row["action"] in ("net:connect", "http:request")
                        and row["host"] == "example.com" for row in records),
            "protected_files_unchanged": all(
                path.exists() and digest(path) == before[path.name]
                for path in (private, readonly, workspace / "keep.txt")
            ),
        }
        result.update(
            checks=checks, passed=all(checks.values()), exit_code=process.returncode,
            stdout=output, stderr=err.read_text(), decisions=records,
            independent_tests=test_output, repaired_source=source,
            protected_before=before,
            protected_after={p.name: digest(p) if p.exists() else None
                             for p in (private, readonly, workspace / "keep.txt")},
        )
    except Exception as error:
        result.update(passed=False, error=str(error))
    with LOCK:
        STATE.update(result, status="complete")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/ping":
            return self.reply(404, {})
        with LOCK:
            busy = STATE["status"] == "running" or CLAUDE.state["status"] in ("starting", "running")
        self.reply(200, {"status": "HealthyBusy" if busy else "Healthy"})

    def do_POST(self):
        if self.path != "/invocations":
            return self.reply(404, {})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 32768:
                raise ValueError("Invalid payload length")
            payload = json.loads(self.rfile.read(size))
            if isinstance(payload, dict) and payload.get("prompt") == "claude":
                return self.reply(200, CLAUDE.handle(payload))
            if payload == {"prompt": "audit"}:
                audit, malformed = policy_rows(STATE.get("directory"))
                return self.reply(200, {"state": dict(STATE), "decisions": audit, "malformed": malformed,
                                       "source": "Box audit records of Dogwood decisions"})
            if payload not in ({"prompt": "demo"}, {"prompt": "status"}):
                raise ValueError("Only the fixed demo and status prompts are supported")
        except (ValueError, TypeError) as error:
            return self.reply(400, {"error": str(error)})
        with LOCK:
            if payload["prompt"] == "demo":
                if STATE["status"] == "running":
                    return self.reply(409, {"error": "Demo already running"})
                STATE.clear()
                STATE.update(
                    status="running", job_id=uuid.uuid4().hex, boot_id=BOOT,
                    uid=os.getuid(), gid=os.getgid(), architecture=platform.machine(),
                    kernel=platform.release(), revision=REVISION,
                    package_sha256=PACKAGE_SHA, box_sha256=digest(BOX),
                    stdout="", mode=os.environ.get("DEMO_MODE", "local"),
                )
                threading.Thread(target=run_demo, daemon=True).start()
            body = dict(STATE)
            body["runtime_session_id"] = self.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id")
        self.reply(200, body)


if __name__ == "__main__":
    BOX = install()
    from manual_setup import prepare as prepare_manual
    prepare_manual(BOX)
    CLAUDE = ClaudeRuntime(BOX)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
