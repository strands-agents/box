"""Launch two independent Boxes and mediate one parent-to-child delegation."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import uuid
from urllib.parse import quote

from decisions import batch_identity, decisions

APP = Path(__file__).resolve().parent
PROGRAM = APP / "agent_program.py"
ROLES = ("parent", "child")
BROKER_READ_TIMEOUT = 10


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def wait_for_process(process, timeout):
    """Stop the owned process group after a deadline, including surviving descendants."""
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return stdout, stderr, True


def runtime_grants():
    """Resolve the Python runtime and its native extension modules before containment."""
    from strands import Agent
    from strands.models import BedrockModel
    from strands.tools.executors import SequentialToolExecutor
    runtime = {Path(sysconfig.get_path("stdlib")).resolve(), Path("/usr/lib").resolve()}
    if Path("/usr/lib64").exists():
        runtime.add(Path("/usr/lib64").resolve())
    reads = sorted(str(path) for path in runtime if not any(parent in runtime for parent in path.parents))
    extension = Path(sysconfig.get_config_var("DESTSHARED")).resolve()
    execute = [str(extension)] + sorted({str(Path(module.__file__).resolve())
        for module in sys.modules.values() if isinstance(getattr(module, "__file__", None), str)
        and module.__file__.endswith(".so") and extension not in Path(module.__file__).resolve().parents})
    return reads, execute


class Launcher:
    def __init__(self, root, model, region, mode, timeout):
        self.root, self.model, self.region, self.timeout = root, model, region, timeout
        self.box = Path("/usr/local/bin/strands-box").resolve(strict=True)
        self.token = os.environ["AWS_BEARER_TOKEN_BEDROCK"]
        self.state_root = Path(tempfile.mkdtemp(prefix="box-agents-", dir="/var/tmp"))
        self.note = json.loads((APP / "fixtures/release-note.json").read_text())
        if mode == "alternate":
            self.note["release_window"] = "Thursday at 10:00 UTC"
        self.receipt = {"run_id": uuid.uuid4().hex, "mode": mode, "run_root": str(root),
                        "program": str(PROGRAM), "program_sha256": hashlib.sha256(PROGRAM.read_bytes()).hexdigest(),
                        "note_sha256": digest(self.note), "box_binary": str(self.box),
                        "roles": {}, "delegations": [], "started_at": time.time()}
        self.lock = threading.Lock()
        (root / "trusted").mkdir(mode=0o700)
        (root / "trusted/private.txt").write_text("Synthetic trusted application input.\n")
        for role in ROLES:
            (root / role / "in").mkdir(parents=True)
            (root / role / "out").mkdir()
            (root / role / "out/private.txt").write_text("Synthetic private output.\n")
        (root / "parent/in/parent-only.txt").write_text((APP / "fixtures/parent-only.txt").read_text())
        save(root / "child/in/release-note.json", self.note)
        self.protected = {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def probes(self, role):
        other = "child" if role == "parent" else "parent"
        other_input = "release-note.json" if other == "child" else "parent-only.txt"
        own = self.root / role
        return [
            {"name": "own_input", "kind": "read", "path": str(own / "in/job.json"), "allowed": True},
            {"name": "own_output", "kind": "write", "path": str(own / "out/control.txt"), "allowed": True},
            {"name": "other_input", "kind": "read", "path": str(self.root / other / "in" / other_input), "allowed": False},
            {"name": "other_output", "kind": "write", "path": str(self.root / other / "out/private.txt"), "allowed": False},
            {"name": "trusted_input", "kind": "read", "path": str(self.root / "trusted/private.txt"), "allowed": False},
            {"name": "box_execute", "kind": "execute", "path": str(self.box), "allowed": False},
        ]

    def configure(self, role, port):
        work, config_dir = self.root / role, self.root / "trusted" / role
        config_dir.mkdir(mode=0o700)
        state = self.state_root / role / "state"
        state.parent.mkdir()
        host = "bedrock-runtime." + self.region + ".amazonaws.com"
        model_path = "/model/" + quote(self.model, safe="") + "/converse-stream"
        policy = f'''@id("model_connect")
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == {json.dumps(host)} && context.input.port == 443 }};
@id("model_request")
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == {json.dumps(host)} && context.input.port == 443 &&
context.input.method == "POST" && context.input.path == {json.dumps(model_path)} }};
'''
        if role == "parent":
            policy += f'''@id("delegate_connect")
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};
@id("delegate_request")
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {port} &&
context.input.method == "POST" && context.input.path == "/delegate/review" }};
'''
        (config_dir / "policy.dw").write_text(policy)
        reads, execute = runtime_grants()
        command = [str(Path(sys.executable).resolve()), "-I", "-B", str(PROGRAM), "--job", str(work / "in/job.json")]
        environment = {"AWS_REGION": self.region, "AWS_DEFAULT_REGION": self.region,
                       "AWS_EC2_METADATA_DISABLED": "true", "TMPDIR": str(work / "out"),
                       "PATH": "/usr/bin:/bin", "OTEL_SDK_DISABLED": "true"}
        config = config_dir / "box.toml"
        lines = ["name=" + json.dumps("release-" + role), "box_dir=" + json.dumps(str(state)),
                 'policy="policy.dw"', "[agent]", "command=" + json.dumps(command),
                 "workspace=" + json.dumps(str(work)),
                 "env={" + ",".join(key + "=" + json.dumps(value) for key, value in environment.items()) + "}",
                 "[agent.filesystem]", "read=" + json.dumps(reads + [str(work / "in"), str(work / "out")]),
                 "write=" + json.dumps([str(work / "out")]), "read_file=" + json.dumps([str(PROGRAM)]),
                 "exec=" + json.dumps(execute), "[egress.model]", "destinations=" + json.dumps([host]),
                 'secret.ref="env://AWS_BEARER_TOKEN_BEDROCK"']
        config.write_text("\n".join(lines) + "\n")
        save(work / "in/job.json", {"run_id": self.receipt["run_id"], "role": role, "model_id": self.model,
             "region": self.region, "broker_url": "http://127.0.0.1:" + str(port), "probes": self.probes(role)})
        return config, state, command

    def launch(self, role, port):
        config, state, command = self.configure(role, port)
        entry = {"config": str(config), "state": str(state), "command": command,
                 "started_at": time.time(), "probe_targets": {}}
        self.receipt["roles"][role] = entry
        for probe in self.probes(role):
            if probe["allowed"]:
                continue
            target = Path(probe["path"])
            if probe["kind"] == "execute":
                subprocess.run([str(target), "--version"], timeout=5, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                with target.open("rb" if probe["kind"] == "read" else "ab") as stream:
                    if probe["kind"] == "read":
                        stream.read(1)
            entry["probe_targets"][probe["name"]] = {"path": str(target), "kind": probe["kind"],
                                                       "existed": target.exists(), "control": True}
        environment = {"HOME": str(Path.home()), "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                       "EXPERIMENTAL_LINUX_SUPPORT": "TRUE", "AWS_BEARER_TOKEN_BEDROCK": self.token}
        process = subprocess.Popen([str(self.box), "run", "--config", str(config)], cwd=APP,
                                   env=environment, text=True, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr, timed_out = wait_for_process(process, self.timeout if role == "parent" else min(120, self.timeout))
        entry.update(ended_at=time.time(), returncode=process.returncode, timed_out=timed_out)
        (config.parent / "stdout.txt").write_text(stdout.replace(self.token, "[REDACTED]"))
        (config.parent / "stderr.txt").write_text(stderr.replace(self.token, "[REDACTED]"))
        result_path = self.root / role / "out/result.json"
        if result_path.is_file():
            entry["result"] = json.loads(result_path.read_text())
        log = state / "private/telemetry/records.jsonl"
        if log.is_file():
            entry["decisions"] = decisions(log)
            entry["box_id"], entry["box_run_id"] = batch_identity(entry["decisions"], state, "release-" + role, config.parent / "policy.dw")
        if timed_out or process.returncode or entry.get("result", {}).get("status") != "complete":
            raise RuntimeError("The " + role + " agent did not complete")
        return entry["result"]

    def delegate(self, path, payload, delegation_id, port):
        with self.lock:
            if (path != "/delegate/review" or payload != {} or self.receipt["delegations"]
                    or not isinstance(delegation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", delegation_id)):
                raise ValueError("Only one fixed release review is allowed")
            row = {"delegation_id": delegation_id, "started_at": time.time()}
            self.receipt["delegations"].append(row)
        try:
            row["child_started_at"] = time.time()
            result = self.launch("child", port)
            row["child_ended_at"] = time.time()
            from agent_program import parse_final
            final = parse_final(json.dumps(result["final"]))
            if any(final[key] != self.note[key] for key in ("project", "release_window")):
                raise ValueError("The child answer differs from its release note")
            envelope = {"status": "ok", "delegation_id": delegation_id, "child_role": "child",
                        "child_result": final, "child_result_sha256": digest(final)}
        except Exception as error:
            row.setdefault("child_ended_at", time.time())
            envelope = {"status": "error", "delegation_id": delegation_id, "child_role": "child",
                        "error": {"type": type(error).__name__, "message": "The child did not complete"}}
        row.update(ended_at=time.time(), envelope=envelope)
        return envelope

    def run(self):
        launcher = self
        class Handler(BaseHTTPRequestHandler):
            timeout = BROKER_READ_TIMEOUT
            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                    if not 0 <= length <= 4096:
                        raise ValueError("Invalid request length")
                    envelope = launcher.delegate(self.path, json.loads(self.rfile.read(length)),
                        self.headers.get("X-Delegation-Id"), self.server.server_port)
                    status = 200
                except (ValueError, TypeError, OSError):
                    envelope, status = {"status": "error", "error": "Invalid delegation"}, 400
                body = json.dumps(envelope).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.receipt["broker_port"] = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.receipt["parent_final"] = self.launch("parent", server.server_port)["final"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.receipt.update(ended_at=time.time(), protected_unchanged=all(
                Path(path).read_bytes() == content for path, content in self.protected.items()))
        return self.receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--mode", choices=("baseline", "alternate"), default="baseline")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error("Timeout must be between 1 and 600 seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt, launcher = {"passed": False}, None
    try:
        launcher = Launcher(output, args.model, args.region, args.mode, args.timeout)
        receipt = launcher.receipt
        launcher.run()
        from verify import validate
        receipt["verification"] = validate(receipt, expected_program=str(PROGRAM))
        receipt["passed"] = True
    except Exception as error:
        receipt.update(passed=False, error={"type": type(error).__name__, "message": "The example did not complete"})
    finally:
        save(output / "receipt.json", receipt)
    return 0 if receipt.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
