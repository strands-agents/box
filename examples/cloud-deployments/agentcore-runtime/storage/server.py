"""Start Box before HTTP initialization and compare real storage operations at invocation."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
PROVIDER_FILESYSTEMS = {"nfs", "nfs4", "efs", "fuse"}


def error(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None), "message": str(exc)}


def mount_rows(text, storage):
    """Retain the mount records at or above the selected directory."""
    rows = []
    for raw in text.splitlines():
        left, right = raw.split(" - ", 1)
        fields, filesystem = left.split(), right.split()
        point = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        if str(storage) == point or str(storage).startswith(point.rstrip("/") + "/"):
            rows.append({"mount_id": fields[0], "mountpoint": point, "filesystem": filesystem[0],
                         "options": fields[5].split(","), "propagation": fields[6:], "raw": raw})
    return rows


def source_snapshot(storage):
    rows = mount_rows(Path("/proc/self/mountinfo").read_text(), storage)
    descriptor = os.open(storage, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        mount_id = next(line.split(":", 1)[1].strip()
                        for line in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines()
                        if line.startswith("mnt_id:"))
        stat = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    active = next((row for row in rows if row["mount_id"] == mount_id), None)
    dedicated = active is not None and active["mountpoint"] == str(storage)
    connected = dedicated and any(item.startswith(("shared:", "master:")) for item in active["propagation"])
    provider = dedicated and (active["filesystem"] in PROVIDER_FILESYSTEMS or active["filesystem"].startswith("fuse."))
    return {"rows": rows, "mount_id": mount_id, "device": stat.st_dev, "inode": stat.st_ino,
            "active": active, "dedicated_connected_mountpoint": bool(connected), "provider_mounted": bool(provider)}


def require_initial_source(storage, observation):
    if not storage.is_absolute() or storage == Path("/") or storage.resolve(strict=True) != storage:
        raise ValueError("STORAGE_PATH must name an existing canonical directory below /")
    if not observation["dedicated_connected_mountpoint"]:
        raise ValueError("STORAGE_PATH needs an existing dedicated shared or slave mountpoint before Box starts")
    if observation["provider_mounted"]:
        raise ValueError("The provider is already mounted; this example requires Box to start before provider arrival")


def box_config(storage, scratch, workload, incarnation):
    control, protected = scratch / "control", scratch / "protected"
    return (f'name = "runtime-storage-example"\nbox_dir = {json.dumps(str(scratch / "state"))}\n'
            f'[agent]\ncommand = {json.dumps([str(workload), "--loop", str(storage), incarnation])}\n'
            f'workspace = {json.dumps(str(control))}\n'
            f'env = {{ HOME = {json.dumps(str(control))}, PATH = "/usr/bin:/bin" }}\n'
            f'[agent.filesystem]\nreceive_mounts = {json.dumps([str(storage)])}\n'
            f'read = {json.dumps([str(storage), str(control), str(protected)])}\n'
            f'write = {json.dumps([str(storage), str(control)])}\nexec = {json.dumps([str(storage)])}\n'
            f'deny = {json.dumps([str(protected / "denied")])}\n')


class Example:
    def __init__(self, storage):
        self.storage = storage
        self.incarnation = uuid.uuid4().hex
        self.finished = False
        self.seen = set()
        self.lock = threading.Lock()
        source = source_snapshot(storage)
        print(json.dumps({"initial_runtime_source": source}), flush=True)
        require_initial_source(storage, source)
        self.scratch = Path(tempfile.mkdtemp(prefix="box-runtime-storage-", dir="/var/tmp"))
        for path in [self.scratch / "control", self.scratch / "home", self.scratch / "protected/denied"]:
            path.mkdir(parents=True)
        self.nonce = uuid.uuid4().hex
        for name in ["public.txt", "denied/secret.txt"]:
            (self.scratch / "protected" / name).write_text(self.nonce)
        config = box_config(storage, self.scratch, ROOT / "workload", self.incarnation)
        config_path = self.scratch / "box.toml"
        config_path.write_text(config)
        self.log = (self.scratch / "stderr.log").open("w")
        self.process = subprocess.Popen([str(ROOT / "bin/strands-box"), "run", "--config", str(config_path)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                        bufsize=0, start_new_session=True,
                                        env={"HOME": str(self.scratch / "home"), "PATH": "/usr/bin:/bin", "TMPDIR": str(self.scratch)})
        self.output_buffer = b""
        try:
            started = self.read_frame()
            if started.get("kind") != "started" or started.get("incarnation") != self.incarnation:
                raise RuntimeError("The native workload did not report its startup identity")
            if started["capability_masks_or"] != 0 or started["no_new_privs"] != 1 or started["statvfs_rc"] != 0:
                raise RuntimeError("The native workload did not start with the expected containment and filesystem access")
            self.initial = {"runtime_source_before_box": source, "sandbox_before_listener": started,
                            "core_pid": self.process.pid, "runtime_uid": os.getuid(), "runtime_gid": os.getgid(), "config": config,
                            "binary_manifest": json.loads((ROOT / "binary-manifest.json").read_text()),
                            "listener_start_wall_ns": time.time_ns()}
        except Exception:
            self.stop(force=True)
            raise

    def read_frame(self, timeout=20):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.output_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError("The native workload did not answer its pipe")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("Box closed its output: " + (self.scratch / "stderr.log").read_text()[-8000:])
            self.output_buffer += chunk
            if len(self.output_buffer) > 65536:
                raise ValueError("The native workload exceeded the frame size limit")
        line, self.output_buffer = self.output_buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, action, path, data=""):
        request = uuid.uuid4().hex
        fields = [action, request, str(path), data]
        if any("\n" in value or "\r" in value for value in fields):
            raise ValueError("A native command contains a newline")
        self.process.stdin.write(("\n".join(fields) + "\n").encode())
        self.process.stdin.flush()
        response = self.read_frame()
        if response.get("request_id") != request:
            raise RuntimeError("The native workload answered a different request")
        expected = self.initial["sandbox_before_listener"]
        if any(response[key] != expected[key] for key in ["pid", "started_monotonic_ns", "incarnation"]):
            raise RuntimeError("The native workload identity changed after startup")
        return response

    def outside(self, action, path, data=""):
        request = uuid.uuid4().hex
        result = subprocess.run([str(ROOT / "workload"), "--once", action, request, str(path), data],
                                capture_output=True, text=True, timeout=20, check=True)
        response = json.loads(result.stdout)
        if response.get("request_id") != request:
            raise RuntimeError("The Runtime control answered a different request")
        return response

    def inspect(self):
        return {"initial": self.initial, "runtime_source_now": source_snapshot(self.storage),
                "core_exit_code": self.process.poll(), "finished": self.finished}

    def run(self):
        source = source_snapshot(self.storage)
        arrived = source["provider_mounted"] and source["mount_id"] != self.initial["runtime_source_before_box"]["mount_id"]
        if not arrived:
            return {"status": "UNQUALIFIED", "reason": "A provider mount has not replaced the initial connected placeholder",
                    "initial": self.initial, "runtime_source_now": source}
        directory_id = uuid.uuid4().hex
        directory = self.storage / ("box-example-" + directory_id)
        try:
            directory.mkdir(mode=0o700)
            nonce = uuid.uuid4().hex
            marker = directory / "marker.txt"
            seed = self.outside("CREATE", marker, nonce)
            if seed["rc"] != 0:
                raise OSError(seed["errno"], "Runtime could not create the source marker")
            program = directory / "mapping.bin"
            program.write_bytes((ROOT / "workload").read_bytes())
        except OSError as exc:
            return {"status": "UNQUALIFIED", "reason": "The writable-provider fixture could not be prepared",
                    "error": error(exc), "runtime_source_now": source, "initial": self.initial}
        cases = []
        def read_case(name, path, expected, allowed=True):
            outside = self.outside("READ", path)
            sandbox = self.command("READ", path)
            positive = outside["rc"] == 0 and outside["content"] == expected
            accepted = sandbox["rc"] == 0 and sandbox["content"] == expected if allowed else sandbox["rc"] == -1 and sandbox["errno"] in {errno.EACCES, errno.EPERM, errno.ENOENT}
            cases.append({"name": name, "runtime": outside, "sandbox": sandbox,
                          "status": "PASS" if positive and accepted else "FAIL"})
        read_case("read_new_storage", marker, nonce)
        created = self.command("CREATE", directory / "sandbox.txt", nonce)
        observed = self.outside("READ", directory / "sandbox.txt")
        cases.append({"name": "write_new_storage", "sandbox": created, "runtime": observed,
                      "status": "PASS" if created["rc"] == 0 and observed["rc"] == 0 and observed["content"] == nonce else "FAIL"})
        outside = self.outside("EXEC_MAP", program)
        sandbox = self.command("EXEC_MAP", program)
        consistent = (outside["rc"], outside["errno"]) == (sandbox["rc"], sandbox["errno"])
        expected = outside["rc"] == 0 or outside["errno"] in {errno.EACCES, errno.EPERM}
        cases.append({"name": "publisher_execution_options", "runtime": outside, "sandbox": sandbox,
                      "status": "PASS" if consistent and expected else "FAIL"})
        read_case("ordinary_read_grant", self.scratch / "protected/public.txt", self.nonce)
        read_case("unrelated_denied_path", self.scratch / "protected/denied/secret.txt", self.nonce, False)
        return {"status": "PASS" if all(case["status"] == "PASS" for case in cases) else "FAIL",
                "mount_arrived_after_box_start": True, "same_sandbox_process": True,
                "initial": self.initial, "runtime_source_now": source, "cases": cases,
                "persistent_file": {"directory_id": directory_id, "expected": nonce},
                "created_directory": str(directory), "stderr_tail": (self.scratch / "stderr.log").read_text()[-8000:]}

    def read_persistent(self, payload):
        directory_id, expected = payload.get("directory_id"), payload.get("expected")
        if not isinstance(directory_id, str) or not re.fullmatch(r"[0-9a-f]{32}", directory_id) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{32}", expected):
            raise ValueError("Use directory_id and expected from an earlier run's persistent_file receipt")
        path = self.storage / ("box-example-" + directory_id) / "marker.txt"
        outside, sandbox = self.outside("READ", path), self.command("READ", path)
        passed = all(value["rc"] == 0 and value["content"] == expected for value in [outside, sandbox])
        return {"status": "PASS" if passed else "FAIL", "runtime": outside, "sandbox": sandbox,
                "initial": self.initial, "runtime_source_now": source_snapshot(self.storage)}

    def stop(self, force=False):
        forced = force
        if self.process.poll() is None:
            try:
                if force:
                    raise subprocess.TimeoutExpired("startup", 0)
                self.process.stdin.write(b"STOP\n")
                self.process.stdin.flush()
                self.process.wait(timeout=20)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                forced = True
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=3)
        self.finished = True
        self.log.close()
        return {"status": "PASS" if self.process.returncode == 0 and not forced else "FAIL",
                "core_exit_code": self.process.returncode, "forced": forced}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        # Small response writes should not wait for TCP acknowledgements.
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def respond(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        healthy = self.server.example.process.poll() is None
        self.respond(200 if self.path == "/ping" and healthy else 503,
                     {"status": "Healthy" if healthy else "Unhealthy"})

    def do_POST(self):
        if self.path != "/invocations":
            self.respond(404, {"error": "Unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                raise ValueError("Expected a JSON request of 1 to 8192 bytes")
            payload = json.loads(self.rfile.read(length))
            action, request_id = payload.get("action", "run"), payload.get("request_id")
            if action not in {"inspect", "run", "read", "finish"} or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
                raise ValueError("Supply action inspect/run/read/finish and a fresh request_id")
        except Exception as exc:
            self.respond(400, {"error": error(exc)})
            return
        example = self.server.example
        with example.lock:
            if request_id in example.seen or (example.finished and action != "inspect"):
                self.respond(409, {"error": "Duplicate request_id or stopped workload"})
                return
            example.seen.add(request_id)
            try:
                value = {"inspect": example.inspect, "run": example.run,
                         "read": lambda: example.read_persistent(payload), "finish": example.stop}[action]()
                value.update(action=action, request_id=request_id)
            except Exception as exc:
                value = {"status": "FAIL", "action": action, "request_id": request_id, "error": error(exc)}
            self.respond(200, value)


def main():
    example = Example(Path(os.environ.get("STORAGE_PATH", "/mnt/storage")))
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.example = example
    try:
        server.serve_forever()
    finally:
        example.stop()
        server.server_close()


if __name__ == "__main__":
    main()
