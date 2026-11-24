#!/usr/bin/env python3
"""Install a Linux archive in a private directory and verify contained execution."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil
import signal
import subprocess
import tarfile
import tempfile

from smoke_telemetry import prepare_installation

BINARIES = {"box", "strands-box-sock-alias", "strands-box-contain-trampoline",
            "strands-box-storage-compiler"}


def unpack(archive, directory):
    seen = set()
    required = BINARIES | {"release.json", "resources/config.toml", "resources/editing-box-profile.md"}
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if member.isdir() and member.name in (".", "./"):
                continue
            path = PurePosixPath(member.name)
            name = str(path)
            if (
                path.is_absolute() or ".." in path.parts or name in seen
                or not (member.isfile() or member.isdir())
                or (
                    name not in required
                    and path.parts[:1] != ("resources",)
                )
                or (name in required and not member.isfile())
            ):
                raise ValueError(f"unexpected archive entry: {member.name}")
            if name in BINARIES and member.mode & 0o7777 != 0o755:
                raise ValueError(f"{name}: expected executable mode 0755")
            target = directory / name
            seen.add(name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as contents:
                with target.open("xb") as output:
                    shutil.copyfileobj(contents, output)
            target.chmod(member.mode & 0o777)
    if not required <= seen:
        raise ValueError(f"missing package files: {sorted(required - seen)}")
    if not (directory / "resources/packs").is_dir():
        raise ValueError("missing package resources/packs")
    metadata = json.loads((directory / "release.json").read_text())
    if not isinstance(metadata, dict) or metadata.get("storage_compiler") is not True:
        raise ValueError("release.json: storage_compiler must be true")


def check(archive, allow_root_operator=False):
    if os.getuid() == 0 and not allow_root_operator:
        raise ValueError("run the package smoke test as an ordinary user")
    root = Path(tempfile.mkdtemp(prefix="box-package-", dir=Path.home())).resolve()
    bundle = root / "package"
    bundle.mkdir()
    unpack(archive, bundle)
    home = root / "home"
    workspace = home / "project"
    workspace.mkdir(parents=True)
    prepare_installation(home)
    allowed = workspace / "allowed.txt"
    allowed.write_text("allowed\n")
    private = root / "private.txt"
    private.write_text("private\n")
    readonly = root / "readonly.txt"
    readonly.write_text("readonly\n")
    script = f"""set -eu
printf 'PACKAGE_ENTERED\\n'
while IFS= read -r line; do
 case "$line" in Cap*|NoNewPrivs:*|Seccomp:*) printf 'WORKLOAD_STATUS %s\\n' "$line";; esac
done < /proc/self/status
IFS= read -r value < {shlex.quote(str(allowed))}
[ "$value" = allowed ]
printf 'written\\n' > {shlex.quote(str(workspace / "result.txt"))}
if IFS= read -r value < {shlex.quote(str(private))}; then exit 71; fi
printf 'PRIVATE_READ_REFUSED\\n'
if printf 'changed\\n' > {shlex.quote(str(readonly))}; then exit 72; fi
printf 'READONLY_WRITE_REFUSED\\n'
zsh -lc 'echo PACKAGE_BROKER_OK'
printf 'PACKAGE_COMPLETE\\n'
"""
    profile = home / ".strands/box/profiles/probe"
    profile.mkdir(parents=True)
    (profile / "policy.dw").write_text(
        'permit(principal, action == Box::Action::"shell:exec", resource);\n'
    )
    probe = (Path(__file__).resolve().parent.parent / "test-corpus/profiles/probe/profile.toml")
    config = f"""policies = ["policy.dw"]
{probe.read_text()}
[agent.filesystem]
read_file = [{json.dumps(str(readonly))}]
"""
    (profile / "profile.toml").write_text(config)
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    version = subprocess.run(
        [str(bundle / "box"), "--version"], capture_output=True, text=True, timeout=10,
        env=environment,
    )
    starter = subprocess.run(
        [str(bundle / "box"), "profile", "create", "claude", "--with", "bedrock", "--policy", "open"],
        env=environment, cwd=workspace, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=10,
    )
    command = [str(bundle / "box"), "run", "probe", "--no-banner", "--", "-c", script]
    process = subprocess.Popen(
        command, env=environment, cwd=workspace, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    status = dict(
        line.removeprefix("WORKLOAD_STATUS ").split(":", 1)
        for line in stdout.splitlines() if line.startswith("WORKLOAD_STATUS ")
    )
    status = {key: value.strip() for key, value in status.items()}
    checks = {
        "box_starts": version.returncode == 0,
        "shipped_packs_available": starter.returncode == 0
        and (home / ".strands/box/profiles/claude/profile.toml").is_file()
        and (home / ".strands/box/profiles/claude/policy.dw").is_file()
        and "open_connect" in (home / ".strands/box/profiles/claude/policy.dw").read_text(),
        "workload_entered": "PACKAGE_ENTERED\n" in stdout,
        "read_and_write": (workspace / "result.txt").exists()
        and (workspace / "result.txt").read_text() == "written\n",
        "private_read_refused": "PRIVATE_READ_REFUSED\n" in stdout,
        "readonly_write_refused": "READONLY_WRITE_REFUSED\n" in stdout
        and readonly.read_text() == "readonly\n",
        "broker_alias_works": "PACKAGE_BROKER_OK\n" in stdout,
        "completed": not timed_out and process.returncode == 0
        and "PACKAGE_COMPLETE\n" in stdout,
        "capabilities_removed": all(
            status.get(key) == "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        ),
        "no_new_privileges": status.get("NoNewPrivs") == "1",
        "seccomp_filter_active": status.get("Seccomp") == "2",
    }
    result = {
        "archive": str(archive.resolve()), "fixture": str(root),
        "os_release": Path("/etc/os-release").read_text(),
        "kernel": platform.release(), "architecture": platform.machine(),
        "uid": os.getuid(), "version": version.stdout.strip(),
        "exit": process.returncode, "timed_out": timed_out,
        "stdout": stdout, "stderr": stderr, "workload_status": status, "checks": checks,
        "starter_stdout": starter.stdout, "starter_stderr": starter.stderr,
    }
    print(json.dumps(result, indent=2))
    return 0 if all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--allow-root-operator", action="store_true",
        help="test a deployment profile that explicitly uses a root operator",
    )
    args = parser.parse_args()
    try:
        return check(args.archive, args.allow_root_operator)
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
