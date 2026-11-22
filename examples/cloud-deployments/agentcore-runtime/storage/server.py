"""Start one Box before listening, then check access when session storage arrives."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
BOX = ROOT / "bin/strands-box"
WORKLOAD = ROOT / "workload"
STORAGE = Path(os.environ.get("STORAGE_PATH", "/mnt/storage"))
LOCK = threading.Lock()
INITIAL = {}
SEEN = set()
FINISHED = False
PROCESS = None
LOGS = []
SCRATCH = None
CONTROL = None
PROTECTED = None
INCARNATION = uuid.uuid4().hex
EXPECTED_ARGV = []
DENIAL_ERRORS = {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT, errno.ENOTDIR}


def error(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None), "message": str(exc)}


def source_snapshot():
    rows = []
    decode = lambda value: re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)
    for raw in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = raw.split(" - ", 1)
        fields, filesystem = left.split(), right.split()
        point = decode(fields[4])
        if str(STORAGE) == point or str(STORAGE).startswith(point.rstrip("/") + "/"):
            rows.append({"mount_id": fields[0], "mountpoint": point, "filesystem": filesystem[0], "raw": raw})
    descriptor = os.open(STORAGE, os.O_PATH | os.O_CLOEXEC)
    try:
        fields = Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines()
        mount_id = next(line.split(":", 1)[1].strip() for line in fields if line.startswith("mnt_id:"))
        stat = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    active = next((row for row in rows if row["mount_id"] == mount_id), None)
    supported = lambda row: row["filesystem"] in {"nfs", "nfs4", "efs", "fuse"} or row["filesystem"].startswith("fuse.")
    storage_rows = [row for row in rows if row["mountpoint"] == str(STORAGE) and supported(row)]
    return {"rows": rows, "mount_id": mount_id, "device": stat.st_dev, "inode": stat.st_ino,
            "supported_mounts": storage_rows, "active_storage_mount": active if active in storage_rows else None}


def process_identity(pid):
    value = {"pid_in_runtime_namespace": pid}
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        value.update(start_ticks=stat[19], state=stat[0], argv=Path(f"/proc/{pid}/cmdline").read_bytes().decode().rstrip("\0").split("\0"))
    except Exception as exc:
        value["error"] = error(exc)
    return value


def native_processes():
    pending, seen, matches = [PROCESS.pid], set(), []
    while pending and len(seen) < 128:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        identity = process_identity(pid)
        if identity.get("argv") == EXPECTED_ARGV:
            matches.append(identity)
        try:
            for task in Path(f"/proc/{pid}/task").iterdir():
                pending.extend(int(value) for value in (task / "children").read_text().split())
        except (FileNotFoundError, ProcessLookupError):
            pass
    return matches


def wait_result(name, request_id=None, timeout=None):
    deadline = None if timeout is None else time.monotonic() + timeout
    while PROCESS.poll() is None:
        try:
            result = json.loads((CONTROL / (name + ".json")).read_text())
            if result.get("incarnation") == INCARNATION and (request_id is None or result.get("request_id") == request_id):
                return result
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("The workload did not publish a matching " + name)
        time.sleep(0.02)
    raise RuntimeError("Box exited before its response: " + str(PROCESS.returncode))


def command(action, path, data="", timeout=10):
    request_id = uuid.uuid4().hex
    fields = [action, request_id, str(path), data]
    if any("\n" in item or "\r" in item for item in fields):
        raise ValueError("A workload command contains a newline")
    temporary = CONTROL / "command.tmp"
    temporary.write_text("\n".join(fields) + "\n")
    os.replace(temporary, CONTROL / "command")
    return wait_result("response", request_id, timeout)


def outside(action, path, data=""):
    request_id = uuid.uuid4().hex
    try:
        completed = subprocess.run([str(WORKLOAD), "--once", action, request_id, str(path), data],
                                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=True)
        response = json.loads(completed.stdout)
        if response.get("request_id") != request_id:
            raise RuntimeError("Outside control returned a different request ID")
        return response
    except Exception as exc:
        return {"error": error(exc)}


def case(name, action, path, allowed, expected="", control_path=None):
    source = outside(action, path if control_path is None else control_path, expected if action == "CREATE" else "")
    source_ok = source.get("rc") == 0 and (action != "READ" or source.get("content") == expected)
    attempts = []
    deadline = time.monotonic() + 15
    while True:
        response = command(action, path, expected if action == "CREATE" else "")
        attempts.append(response)
        matches = response.get("rc") == 0 and (action != "READ" or response.get("content") == expected)
        if not (allowed and action == "READ" and not matches and time.monotonic() < deadline):
            break
        time.sleep(0.05)
    permitted = matches if allowed else response.get("rc") == -1 and response.get("errno") in DENIAL_ERRORS
    result = {"name": name, "path": str(path), "expected": "allow" if allowed else "deny", "source_control": source,
              "source_control_path": str(path if control_path is None else control_path), "native_attempts": attempts,
              "qualified": source_ok, "status": "PASS" if source_ok and permitted else "FAIL"}
    if not source_ok:
        result.update(status="UNQUALIFIED", reason="The matching outside operation failed.")
    if action == "CREATE" and not allowed:
        result["target_after"] = outside("READ", path)
        if result["target_after"].get("errno") != errno.ENOENT:
            result["status"] = "FAIL"
    return result


def inspect():
    return {"initial": INITIAL, "source_now": source_snapshot(), "native_now": native_processes() if PROCESS.poll() is None else [],
            "core_now": process_identity(PROCESS.pid), "core_exit_code": PROCESS.poll(), "finished": FINISHED}


def run_checks():
    deadline = time.monotonic() + 30
    source = source_snapshot()
    while not source["active_storage_mount"] and time.monotonic() < deadline:
        time.sleep(0.05)
        source = source_snapshot()
    if not source["active_storage_mount"]:
        raise TimeoutError("No supported storage mount became visible at STORAGE_PATH")
    request_root = STORAGE / ("box-storage-" + uuid.uuid4().hex)
    request_root.mkdir()
    nonce = uuid.uuid4().hex
    marker = request_root / "fresh.txt"
    marker.write_text(nonce)
    protected_nonce = INITIAL["protected_nonce"]
    cases = [case("fresh_mounted_read", "READ", marker, True, nonce),
             case("mounted_create_denied", "CREATE", request_root / "denied.txt", False, nonce, request_root / "outside-create.txt"),
             case("granted_parent_read", "READ", PROTECTED / "public.txt", True, protected_nonce),
             case("explicit_deny_child_read", "READ", PROTECTED / "denied/secret.txt", False, protected_nonce)]
    current = native_processes()
    identities = lambda rows: {(row["pid_in_runtime_namespace"], row.get("start_ticks")) for row in rows}
    same_native = bool(current) and identities(current) == identities(INITIAL["native_before_listener"])
    ready = INITIAL["native_ready"]
    order = not INITIAL["source_before_box"]["supported_mounts"] and source["mount_id"] != INITIAL["source_before_box"]["mount_id"]
    pending = ready["storage_readonly"] and ready["storage_entries"] == 0 and ready["directory_errno"] == 0
    status = "PASS" if order and pending and same_native and all(item["status"] == "PASS" for item in cases) else "FAIL"
    if order and pending and same_native and all(item["status"] != "FAIL" for item in cases) and any(item["status"] == "UNQUALIFIED" for item in cases):
        status = "UNQUALIFIED"
    return {"status": status, "mount_arrived_after_box_start": order, "initial_empty_readonly_view": pending,
            "same_native_process": same_native, "native_now": current, "source_now": source, "cases": cases,
            "persistent_file": {"path": str(marker), "expected": nonce}, "initial": INITIAL}


def finish():
    global FINISHED
    started = time.monotonic()
    stopped = {"forced": False}
    original = INITIAL["native_before_listener"]
    if PROCESS.poll() is None:
        temporary = CONTROL / "command.tmp"
        temporary.write_text("STOP\n")
        os.replace(temporary, CONTROL / "command")
        try:
            PROCESS.wait(timeout=20)
        except subprocess.TimeoutExpired:
            stopped["forced"] = True
            os.killpg(PROCESS.pid, signal.SIGTERM)
            try:
                PROCESS.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(PROCESS.pid, signal.SIGKILL)
                PROCESS.wait(timeout=3)
    observations = []
    for row in original:
        current = process_identity(row["pid_in_runtime_namespace"])
        gone = current.get("error", {}).get("errno") == errno.ENOENT or ("start_ticks" in current and current["start_ticks"] != row.get("start_ticks"))
        observations.append({"recorded": row, "current": current, "original_process_stopped": gone})
    stopped.update(exit_code=PROCESS.returncode, elapsed_seconds=round(time.monotonic() - started, 6), native=observations)
    for handle in LOGS:
        handle.close()
    FINISHED = True
    stopped["status"] = "PASS" if PROCESS.returncode == 0 and not stopped["forced"] and bool(observations) and all(row["original_process_stopped"] for row in observations) else "FAIL"
    stopped["stderr_tail"] = (SCRATCH / "stderr.log").read_text()[-8000:]
    return stopped


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/ping":
            self.respond(404, {"error": "Unknown path"})
        else:
            self.respond(200 if PROCESS.poll() is None or FINISHED else 503, {"status": "Healthy" if PROCESS.poll() is None or FINISHED else "Unhealthy", "warm_ready": True})

    def do_POST(self):
        if self.path != "/invocations":
            self.respond(404, {"error": "Unknown path"})
            return
        if self.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Warmup-Type"):
            self.respond(200, {"status": "READY"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                raise ValueError("Expected a JSON request smaller than 8193 bytes")
            payload = json.loads(self.rfile.read(length))
            action, request_id = payload.get("action", "run"), payload.get("request_id")
            if action not in {"inspect", "run", "finish"} or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
                raise ValueError("Supply action inspect/run/finish and a fresh request_id")
        except Exception as exc:
            self.respond(400, {"error": error(exc)})
            return
        with LOCK:
            if request_id in SEEN or (FINISHED and action != "inspect"):
                self.respond(409, {"error": "Duplicate request_id or finished session"})
                return
            SEEN.add(request_id)
            try:
                value = {"inspect": inspect, "run": run_checks, "finish": finish}[action]()
                value.update(action=action, request_id=request_id)
            except Exception as exc:
                value = {"status": "FAIL", "action": action, "request_id": request_id, "error": error(exc)}
            self.respond(200, value)


def initialize():
    global SCRATCH, CONTROL, PROTECTED, PROCESS, EXPECTED_ARGV
    if os.geteuid() != 0 or not STORAGE.is_absolute() or STORAGE == Path("/"):
        raise RuntimeError("This example requires UID 0 and an absolute STORAGE_PATH below /")
    STORAGE.mkdir(parents=True, exist_ok=True)
    initial_source = source_snapshot()
    if initial_source["supported_mounts"]:
        raise RuntimeError("Storage is already mounted; start the example before mount attachment")
    placeholder = STORAGE / ("box-underlay-" + INCARNATION + ".txt")
    placeholder.write_text("This underlay file must not enter the pending Box view.")
    SCRATCH = Path(tempfile.mkdtemp(prefix="box-storage-", dir="/var/tmp"))
    CONTROL = SCRATCH / "control"
    PROTECTED = SCRATCH / "protected"
    CONTROL.mkdir()
    (PROTECTED / "denied").mkdir(parents=True)
    (SCRATCH / "home").mkdir()
    nonce = uuid.uuid4().hex
    (PROTECTED / "public.txt").write_text(nonce)
    (PROTECTED / "denied/secret.txt").write_text(nonce)
    EXPECTED_ARGV = [str(WORKLOAD), "--loop", str(CONTROL), str(STORAGE), INCARNATION]
    config = ('name = "runtime-storage-example"\nbox_dir = ' + json.dumps(str(SCRATCH / "state")) + '\n'
              '[experimental-features]\nlinux-storage-mounts = true\n'
              '[agent]\ncommand = ' + json.dumps(EXPECTED_ARGV) + '\nworkspace = ' + json.dumps(str(CONTROL)) + '\n'
              'env = { HOME = ' + json.dumps(str(CONTROL)) + ', PATH = "/usr/bin:/bin" }\n'
              '[agent.filesystem]\nmounts = ' + json.dumps([str(STORAGE)]) + '\n'
              'read = ' + json.dumps([str(STORAGE), str(CONTROL), str(PROTECTED)]) + '\n'
              'write = ' + json.dumps([str(CONTROL)]) + '\n'
              'deny = ' + json.dumps([str(PROTECTED / "denied")]) + '\n')
    config_path = SCRATCH / "box.toml"
    config_path.write_text(config)
    INITIAL.update(started_wall_ns=time.time_ns(), source_before_box=initial_source, protected_nonce=nonce, original_config=config,
                   underlay_control=outside("READ", placeholder), core_sha256=hashlib.sha256(BOX.read_bytes()).hexdigest(), workload_sha256=hashlib.sha256(WORKLOAD.read_bytes()).hexdigest(),
                   binary_manifest=json.loads((ROOT / "binary-manifest.json").read_text()))
    LOGS.extend((SCRATCH / (name + ".log")).open("w") for name in ["stdout", "stderr"])
    PROCESS = subprocess.Popen([str(BOX), "run", "--config", str(config_path)], stdin=subprocess.DEVNULL,
                               stdout=LOGS[0], stderr=LOGS[1], start_new_session=True,
                               env={"HOME": str(SCRATCH / "home"), "PATH": "/usr/bin:/bin", "TMPDIR": str(SCRATCH)})
    INITIAL["core_at_start"] = process_identity(PROCESS.pid)
    INITIAL["native_ready"] = wait_result("ready")
    INITIAL["native_before_listener"] = native_processes()
    if not INITIAL["native_before_listener"]:
        raise RuntimeError("Could not identify the native workload before starting HTTP")
    INITIAL["listener_start_wall_ns"] = time.time_ns()


if __name__ == "__main__":
    initialize()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
