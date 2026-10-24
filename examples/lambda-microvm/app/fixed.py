"""Run the fixed Box demonstration on Lambda MicroVM."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
BOOT = uuid.uuid4().hex
LOCK = threading.Lock()
STATE = {"status": "idle"}
BOX = Path("/opt/box/box")
FIXED_SOURCE = "def add(a, b):\n    return a + b\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decisions(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        for resource in json.loads(line).get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = {x["key"]: x["value"] for x in record.get("attributes", [])}
                    def value(key):
                        return attrs.get(key, {}).get("stringValue")
                    verdict = value("strands.box.policy.verdict")
                    if verdict:
                        rows.append({
                            "verdict": verdict,
                            "action": value("strands.box.policy.action"),
                            "path": value("file.path"),
                            "host": value("server.address"),
                        })
    return rows


def run_demo(negative=False):
    result = {}
    try:
        if os.getuid() != 0:
            raise RuntimeError("The measured Lambda demo configuration requires operator UID 0")
        # /work is outside Box's automatically writable private /tmp.
        root = Path(tempfile.mkdtemp(prefix="box-demo-", dir="/work"))
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
        if negative:
            policy += '\n@id("negative_control")\nforbid(principal, action == Box::Action::"fs:write", resource);\n'
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
            f'name="lambda-demo"\nbox_dir={json.dumps(str(root / "state"))}\npolicy="policy.dw"\n'
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
        records = decisions(root / "state/private/telemetry/records.jsonl")
        source = (workspace / "app.py").read_text()
        correct = source == FIXED_SOURCE
        test_output = "Source differs from the expected repair"
        if correct:
            namespace = {}
            exec(compile(source, "app.py", "exec"), namespace)
            correct = all(namespace["add"](*args) == expected for args, expected in (
                ((2, 3), 5), ((-4, 3), -1), ((0, 0), 0),
            ))
            test_output = "3 independent arithmetic checks passed" if correct else "Arithmetic check failed"
        def decision(verdict, action, suffix=None):
            return any(
                row["verdict"] == verdict and row["action"] == action
                and (suffix is None or (row["path"] or "").endswith(suffix))
                for row in records
            )
        checks = {
            "measured_root_operator": os.getuid() == 0,
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
