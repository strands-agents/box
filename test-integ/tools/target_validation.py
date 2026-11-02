#!/usr/bin/env python3
"""Check an installed Linux Box package without deployment credentials or Cargo."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import tempfile
import time


REFUSALS = (
    "native filesystem interception requires CAP_BPF and CAP_PERFMON",
    "native filesystem setup failed: No such file or directory",
)


def digest(path):
    with path.open("rb") as source:
        value = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
        return value.hexdigest()


def read_text(path):
    try:
        return path.read_text()
    except FileNotFoundError:
        return None


def process(pid):
    try:
        base = Path("/proc") / str(pid)
        fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
        return {"pid": pid, "start": fields[19], "state": fields[0],
                "args": os.fsdecode((base / "cmdline").read_bytes()).split("\0")}
    except (FileNotFoundError, ProcessLookupError):
        return None


def living(root):
    rows = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            row = process(int(entry.name))
        except PermissionError:
            continue
        if row and row["state"] != "Z" and any(
            arg == str(root) or arg.startswith(str(root) + "/") for arg in row["args"]
        ):
            rows.append({key: row[key] for key in ("pid", "start", "state")})
    return rows


def signal_process(row, sig):
    try:
        fd = os.pidfd_open(row["pid"])
    except ProcessLookupError:
        return
    try:
        current = process(row["pid"])
        if current and current["start"] == row["start"]:
            signal.pidfd_send_signal(fd, sig)
    finally:
        os.close(fd)


def cleanup(root):
    rows = living(root)
    for row in rows:
        signal_process(row, signal.SIGKILL)
    return rows


def wait_until(predicate, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.03)
    return bool(predicate())


def heartbeat_changes(path):
    first = read_text(path)
    time.sleep(0.25)
    second = read_text(path)
    return first is not None and second is not None and first != second


def stopped(root):
    wait_until(lambda: not living(root), 5)
    survivors = living(root)
    first = read_text(root / "work/heartbeat")
    time.sleep(0.25)
    second = read_text(root / "work/heartbeat")
    return {"survivors": survivors,
            "heartbeat_stopped": first is not None and second is not None and first == second}


def succeeded(result):
    return (result["exit_code"] == 0 and not result["timed_out"]
            and not result["test_owned_cleanup"] and not result.get("kill_timed_out", False))


def refused(result, marker):
    return (result["exit_code"] not in (None, 0) and not result["timed_out"]
            and not marker.exists() and not result["workload_entered"]
            and "WORKLOAD_ENTERED" not in result["stdout"]
            and any(message in result["stderr"] for message in REFUSALS))


def prerequisites():
    result = {}
    for name in ("/sys/kernel/btf/vmlinux", "/sys/kernel/security/lsm",
                 "/proc/self/uid_map", "/proc/self/status"):
        try:
            path = Path(name)
            value = {"bytes": path.stat().st_size} if name.endswith("vmlinux") else path.read_text()
            if name.endswith("status"):
                value = [line for line in value.splitlines()
                         if line.startswith(("Cap", "Seccomp", "NoNewPrivs"))]
            result[name] = value
        except OSError as error:
            result[name] = {"errno": error.errno}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result["pidfd"] = []
    for name, flag in (("process", 0), ("thread", os.O_EXCL)):
        ctypes.set_errno(0)
        fd = libc.syscall(434, os.getpid(), flag)
        result["pidfd"].append({"kind": name, "success": fd >= 0, "errno": ctypes.get_errno()})
        if fd >= 0:
            os.close(fd)
    return result


class Target:
    def __init__(self, root, binary, probe):
        self.root = root
        self.binary = binary
        self.probe = probe
        self.env = dict(os.environ, PATH=str(binary.parent) + ":" + os.environ.get("PATH", ""))

    def config(self, name, command, *, native=False, grants=None):
        root = self.root / name
        root.mkdir(mode=0o700)
        (root / "work").mkdir()
        (root / "policy.dw").write_text("permit(principal, action, resource);\n")
        text = (f'name="target-validation"\nbox_dir={json.dumps(str(root / "state"))}\n'
                'policy="policy.dw"\n[experimental-features]\n'
                f'native-filesystem-policy={str(native).lower()}\n[agent]\n'
                f'command={json.dumps(command)}\nworkspace={json.dumps(str(root / "work"))}\n')
        if grants:
            text += "[agent.filesystem]\n"
            text += "".join(f"{key}={json.dumps([str(path) for path in paths])}\n"
                            for key, paths in grants.items())
        (root / "box.toml").write_text(text)
        return root

    def launch(self, root):
        with (root / "stdout").open("w") as out, (root / "stderr").open("w") as err:
            return subprocess.Popen(
                [str(self.binary), "run", "--config", str(root / "box.toml")],
                env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                start_new_session=True,
            )

    def result(self, root, child, timed_out=False):
        result = {"exit_code": child.returncode, "timed_out": timed_out, "workload_entered": False}
        for name in ("stdout", "stderr"):
            tail = b""
            with (root / name).open("rb") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    window = tail + chunk
                    if name == "stdout" and b"WORKLOAD_ENTERED" in window:
                        result["workload_entered"] = True
                    tail = window[-24000:]
            result[name] = tail.decode(errors="replace")
        return result

    def run(self, root):
        child = self.launch(root)
        timed_out = False
        kill_timed_out = False
        try:
            child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            survivors = cleanup(root)
            if child.poll() is None:
                child.kill()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_timed_out = True
        result = self.result(root, child, timed_out)
        result["kill_timed_out"] = kill_timed_out
        result["test_owned_cleanup"] = survivors
        return result

    def startup(self, native=False):
        name = "native-startup" if native else "ordinary-startup"
        work = self.root / name / "work"
        marker = work / "entered"
        root = self.config(name, ["/usr/bin/bash", "-c",
                           "printf WORKLOAD_ENTERED; printf yes > " + shlex.quote(str(marker))],
                           native=native, grants={"read": [work], "write": [work]})
        result = self.run(root)
        result["pass"] = refused(result, marker) if native else (
            succeeded(result) and read_text(marker) == "yes"
            and "WORKLOAD_ENTERED" in result["stdout"])
        result["pass"] &= not result["test_owned_cleanup"]
        return result

    def file_effects(self):
        work = self.root / "files/work"
        readonly = self.root / "files/readonly"
        private = self.root / "files/private"
        q = lambda path: shlex.quote(str(path))
        script = (f"set -eu; IFS= read -r value < {q(work / 'allowed')}; "
                  'test "$value" = READ_ALLOWED; '
                  f"printf WRITE_ALLOWED > {q(work / 'output')}; "
                  f"if IFS= read -r value < {q(private)}; then exit 71; fi; "
                  f"if printf MODIFIED > {q(readonly)}; then exit 72; fi; printf FILES_DONE")
        root = self.config("files", ["/usr/bin/bash", "-c", script],
                           grants={"read": [work], "write": [work], "read_file": [readonly]})
        (work / "allowed").write_text("READ_ALLOWED\n")
        readonly.write_text("READONLY_ORIGINAL\n")
        private.write_text("PRIVATE_ORIGINAL\n")
        control = subprocess.run(["/usr/bin/bash", "-c",
                                  f"IFS= read -r value < {q(private)}; "
                                  'test "$value" = PRIVATE_ORIGINAL && '
                                  f"printf CONTROL > {q(readonly)}"],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        control_ok = control.returncode == 0 and readonly.read_text() == "CONTROL"
        readonly.write_text("READONLY_ORIGINAL\n")
        result = self.run(root)
        checks = {"completed": succeeded(result) and "FILES_DONE" in result["stdout"],
                  "allowed_write": read_text(work / "output") == "WRITE_ALLOWED",
                  "readonly_unchanged": read_text(readonly) == "READONLY_ORIGINAL\n",
                  "private_unchanged": read_text(private) == "PRIVATE_ORIGINAL\n",
                  "uncontained_control": control_ok}
        result.update(checks=checks, passed_control=control_ok)
        result["pass"] = all(checks.values()) and not result["test_owned_cleanup"]
        return result

    def workload(self, name, restore=False):
        work = self.root / name / "work"
        command = [str(self.probe), "descendant", str(work)] if restore else [
            str(self.probe), "workload", str(work), str(work / "ready"), str(work / "go"), str(self.probe)]
        root = self.config(name, command,
                           grants={"read": [work], "write": [work], "exec": [self.probe]})
        child = self.launch(root)
        ready = work / ("heartbeat" if restore else "ready")
        try:
            if not wait_until(lambda: ready.exists() or child.poll() is not None, 20):
                raise RuntimeError("workload readiness timed out")
            if child.poll() is not None or not ready.exists():
                raise RuntimeError("workload exited before readiness")
            if not heartbeat_changes(work / "heartbeat"):
                raise RuntimeError("descendant heartbeat did not advance")
            before = living(root)
            if not any(row["pid"] != child.pid for row in before):
                raise RuntimeError("no live workload was observed")
            return root, child, before
        except Exception:
            cleanup(root)
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            raise

    def lifecycle(self, name, sig):
        root, child, before = self.workload(name)
        result = {"before": before}
        try:
            if sig is None:
                (root / "work/go").write_text("go")
            elif name == "deadline-expiry":
                try:
                    child.wait(timeout=0.3)
                    raise RuntimeError("workload exited before the harness deadline")
                except subprocess.TimeoutExpired:
                    child.send_signal(sig)
            else:
                child.send_signal(sig)
            child.wait(timeout=10)
            result.update(self.result(root, child), **stopped(root))
            expected_exit = child.returncode == 0 if sig is None else child.returncode != 0
            result["pass"] = expected_exit and not result["survivors"] and result["heartbeat_stopped"]
            if name == "deadline-expiry":
                result["scope"] = "harness deadline; not the service timeout interface"
        finally:
            result["test_owned_cleanup"] = cleanup(root)
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        result["pass"] &= not result["test_owned_cleanup"]
        return result

    def subsequent(self):
        previous = self.root / "files/work/output"
        if read_text(previous) != "WRITE_ALLOWED":
            raise RuntimeError("previous granted fixture is missing or changed")
        word = shlex.quote(str(previous))
        control = subprocess.run(["/usr/bin/bash", "-c", f"value=$(cat {word}); test \"$value\" = WRITE_ALLOWED"],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        command = ["/usr/bin/bash", "-c",
                   f"if {{ IFS= read -r x || test -n \"$x\"; }} < {word}; then exit 73; fi; "
                   "printf SUBSEQUENT_ISOLATION_PASS"]
        result = self.run(self.config("subsequent-run", command))
        result["uncontained_control"] = control.returncode == 0
        result["pass"] = (succeeded(result) and result["uncontained_control"]
                          and "SUBSEQUENT_ISOLATION_PASS" in result["stdout"])
        return result


def run_cases(target, native):
    cases = [("ordinary-startup", target.startup), ("ordinary-file-effects", target.file_effects)]
    if native:
        cases.append(("native-startup", lambda: target.startup(True)))
    for name, sig in (("ordinary-exit", None), ("cancel-sigterm", signal.SIGTERM),
                      ("forced-stop-sigkill", signal.SIGKILL), ("deadline-expiry", signal.SIGTERM)):
        cases.append((name, lambda name=name, sig=sig: target.lifecycle(name, sig)))
    cases.append(("subsequent-box-isolation", target.subsequent))
    rows = []
    for name, case in cases:
        try:
            row = case()
        except Exception as error:
            row = {"pass": False, "error": str(error)}
        row["name"] = name
        rows.append(row)
        print(json.dumps(row), flush=True)
    return rows


def restoration(target, check):
    root = target.root / "restoration"
    receipt = root / "receipt.json"
    if not check:
        root, child, before = target.workload("restoration", restore=True)
        saved = {"process": process(child.pid), "binary_sha256": digest(target.binary),
                 "probe_sha256": digest(target.probe), "before": before}
        try:
            receipt.write_text(json.dumps(saved, indent=2) + "\n")
        except Exception:
            cleanup(root)
            child.wait(timeout=5)
            raise
        return {"prepared": True, "pid": child.pid, "root": str(root),
                "scope": "perform platform suspend/resume separately before checking"}
    saved = json.loads(receipt.read_text())
    current = process(saved["process"]["pid"])
    checks = {"same_trusted_process": bool(current and current["state"] != "Z"
                                          and current["start"] == saved["process"]["start"]),
              "same_binaries": saved["binary_sha256"] == digest(target.binary)
                               and saved["probe_sha256"] == digest(target.probe)}
    try:
        checks["heartbeat_resumed"] = heartbeat_changes(root / "work/heartbeat")
        checks["fixture_preserved"] = read_text(target.root / "files/work/output") == "WRITE_ALLOWED"
        signal_process(saved["process"], signal.SIGTERM)
        after = stopped(root)
        checks["cleanup_after_restore"] = not after["survivors"]
        checks["writes_stopped"] = after["heartbeat_stopped"]
        marker = target.root / "ordinary-startup/work/entered"
        marker.write_text("stale")
        later = target.run(target.root / "ordinary-startup")
        checks["next_box_run"] = (succeeded(later)
                                  and read_text(marker) == "yes")
        return {"checks": checks, "pass": all(checks.values()), "after": after,
                "scope": "continuity checks; retain separate platform suspend/resume receipts"}
    finally:
        cleanup(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "restore-start", "restore-check"))
    parser.add_argument("--box", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--root", type=Path, help="new fixture directory for run; prior directory for restore")
    parser.add_argument("--revision", required=True, help="operator-recorded source revision of the package")
    parser.add_argument("--expect-native-refusal", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        parser.error("the installed Box containment package requires Linux ARM64")
    binary, probe = args.box.resolve(strict=True), args.probe.resolve(strict=True)
    for path in (binary, probe, binary.parent / "strands-box-contain-trampoline",
                 binary.parent / "strands-box-sock-alias"):
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"missing executable: {path}")
    if args.mode != "run" and args.root is None:
        parser.error("restoration requires --root from a completed run")
    if args.mode != "run" and args.expect_native_refusal:
        parser.error("--expect-native-refusal applies only to run")
    if args.mode == "run":
        if args.root:
            root = args.root.resolve()
            root.mkdir(mode=0o700)
        else:
            root = Path(tempfile.mkdtemp(prefix="tv.", dir="/var/tmp"))
    else:
        root = args.root.resolve(strict=True)
        previous = json.loads((root / "report.json").read_text())
        if not previous["pass"]:
            parser.error("restoration requires a passing initial run")
        for path, expected in previous["sha256"].items():
            if digest(Path(path)) != expected:
                parser.error(f"executable changed after the initial run: {path}")
        if str(binary) not in previous["sha256"] or str(probe) not in previous["sha256"]:
            parser.error("use the executables recorded by the initial run")
    target = Target(root, binary, probe)
    report = {"root": str(root), "operator_revision": args.revision,
              "kernel": platform.release(), "architecture": platform.machine(),
              "uid": os.getuid(), "gid": os.getgid(), "prerequisites": prerequisites(),
              "sha256": {str(path): digest(path) for path in (binary, probe,
                         binary.parent / "strands-box-contain-trampoline",
                         binary.parent / "strands-box-sock-alias")}}
    try:
        if args.mode == "run":
            report["cases"] = run_cases(target, args.expect_native_refusal)
            report["pass"] = all(row["pass"] for row in report["cases"])
        else:
            report.update(restoration(target, args.mode == "restore-check"))
    except Exception as error:
        report.update({"pass": False, "error": str(error)})
    output = root / ("report.json" if args.mode == "run" else args.mode + ".json")
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output), "pass": report.get("pass"),
                      "prepared": report.get("prepared", False)}), flush=True)
    return 0 if report.get("pass") or report.get("prepared") else 1


if __name__ == "__main__":
    raise SystemExit(main())
