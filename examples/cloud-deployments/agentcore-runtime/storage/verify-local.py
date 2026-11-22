#!/usr/bin/env python3
"""Check the real Box example with a late FUSE mount in a privileged local container."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Image already built from this example's Dockerfile.")
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory.")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    identifier = uuid.uuid4().hex[:12]
    container, image = "box-storage-check-" + identifier, "box-storage-check:" + identifier
    commands = []
    result = {"status": "FAIL", "provider": "local bindfs FUSE", "scope": "Real Box and native workload with a late local FUSE mount; no Runtime snapshot or AWS execution."}
    mounted = None

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")

    def run(command, name, timeout=120):
        commands.append(command)
        with (output / (name + ".stdout")).open("w") as stdout, (output / (name + ".stderr")).open("w") as stderr:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr, text=True, timeout=timeout)
        if completed.returncode:
            raise RuntimeError(name + " failed; read " + str(output / (name + ".stderr")))
        return (output / (name + ".stdout")).read_text().strip()

    def invoke(action):
        payload = {"action": action, "request_id": uuid.uuid4().hex}
        request = urllib.request.Request(address + "/invocations", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=90) as response:
            value = json.load(response)
        save(action + ".json", value)
        return value

    try:
        build = output / "Dockerfile.local"
        build.write_text("FROM " + args.image + "\nUSER 0\nRUN apt-get update && apt-get install -y --no-install-recommends bindfs util-linux\n")
        run(["docker", "build", "--platform", "linux/arm64", "-f", str(build), "-t", image, str(output)], "build-local-tools", 600)
        run(["docker", "run", "-d", "--name", container, "--platform", "linux/arm64", "--privileged", "-p", "127.0.0.1::8080", "--entrypoint", "sh", image,
             "-c", "mount -t tmpfs tmpfs /mnt; mount --make-shared /mnt; mkdir -p /mnt/storage /source; mount --bind /mnt/storage /mnt/storage; exec python3 /opt/runtime-storage/server.py"], "start")
        port = run(["docker", "port", container, "8080/tcp"], "port")
        address = "http://" + port
        deadline = time.monotonic() + 45
        while True:
            try:
                with urllib.request.urlopen(address + "/ping", timeout=2) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("The example did not become healthy before local mount attachment")
            time.sleep(0.1)
        before = invoke("inspect")
        assert before["initial"]["native_ready"]["storage_readonly"]
        assert before["initial"]["native_ready"]["storage_entries"] == 0
        assert not before["source_now"]["supported_mounts"]
        command = ["docker", "exec", container, "bindfs", "-f", "-o", "nonempty", "/source", "/mnt/storage"]
        commands.append(command)
        with (output / "mount.stdout").open("w") as stdout, (output / "mount.stderr").open("w") as stderr:
            mounted = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        tested = invoke("run")
        assert tested["status"] == "PASS", tested
        assert tested["same_native_process"] and tested["mount_arrived_after_box_start"]
        assert tested["source_now"]["active_storage_mount"]["filesystem"].startswith("fuse")
        stopped = invoke("finish")
        assert stopped["status"] == "PASS", stopped
        result.update(status="PASS", checks={"pending_before_mount": True, "same_native_process": True,
                      "late_source_mount": True, "qualified_permission_cases": len(tested["cases"]), "cleanup": True})
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        try:
            run(["docker", "logs", container], "container-logs")
        except Exception:
            pass
        cleanup_errors = []

        def cleanup_command(command, receipt):
            commands.append(command)
            try:
                cleanup = subprocess.run(command, capture_output=True, text=True, timeout=60)
                details = {"returncode": cleanup.returncode, "stdout": cleanup.stdout, "stderr": cleanup.stderr}
                if cleanup.returncode:
                    cleanup_errors.append(receipt)
            except Exception as exc:
                details = {"error_type": type(exc).__name__, "message": str(exc)}
                cleanup_errors.append(receipt)
            save(receipt, details)

        cleanup_command(["docker", "rm", "-f", container], "container-cleanup.json")
        if mounted is not None:
            try:
                mounted.wait(timeout=15)
            except Exception as exc:
                cleanup_errors.append("mount-client-cleanup.json")
                details = {"error_type": type(exc).__name__, "message": str(exc)}
                try:
                    mounted.terminate()
                    mounted.wait(timeout=5)
                except Exception as cleanup_error:
                    details["termination_error"] = str(cleanup_error)
                save("mount-client-cleanup.json", details)
        cleanup_command(["docker", "image", "rm", image], "local-tools-image-cleanup.json")
        if cleanup_errors:
            result["status"] = "FAIL"
            result["cleanup_errors"] = cleanup_errors
            result.setdefault("checks", {})["cleanup"] = False
        save("commands.json", commands)
        save("verdict.json", result)
    print(json.dumps(result, indent=2))
    if result["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
