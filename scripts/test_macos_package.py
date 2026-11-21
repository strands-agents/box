#!/usr/bin/env python3
"""Verify a locally built archive, install it with install.sh, and run it. This does not verify Apple signing."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib

from smoke_telemetry import prepare_installation


ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
TARGET = "aarch64-apple-darwin"
COMMAND_TIMEOUT = 60
# The probe takes the @box/scoped policy starter's copy and its `[project]`, as
# `box profile create --policy scoped` writes them, because `box` writes no rule that lets the
# box's shell run, and a profile without `[project]` gets no project access.
PROFILE = '''packs = ["@box/base"]
policies = ["policy.dw"]

[project]
access = "write"

[agent]
command = ["/bin/bash", "--noprofile", "--norc"]
env.TMPDIR = "${{ workspace }}"
'''
PROBE = """set -eu
echo direct > direct.txt
bash -c 'echo broker > broker.txt'
if bash -c 'echo bad > .box/denied.txt'; then exit 99; fi
echo package-ok
"""


def unpack(archive, destination, record, resources):
    assert archive.name == f"box-cli-v{record['box_version']}-{TARGET}.tar.gz", "archive name"
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    assert (archive.parent / "SHA256SUMS.txt").read_text() == f"{digest}  {archive.name}\n", "checksum"
    files = {*BINARIES, "release.json", *resources}
    directories = {parent.as_posix() for name in files for parent in Path(name).parents}
    with tarfile.open(archive, "r:gz") as tar:
        seen = set()
        for member in tar.getmembers():
            name = member.name.removeprefix("./").rstrip("/") or "."
            assert name not in seen, f"duplicate entry: {name}"
            seen.add(name)
            if member.isdir():
                assert name in directories and member.mode == 0o755, f"directory: {name}"
            else:
                assert member.isfile() and name in files, f"unexpected file or link: {name}"
                mode = 0o755 if name in BINARIES else 0o644
                assert member.mode == mode, f"permissions: {name}"
                if name == "release.json" or name in resources:
                    stream = tar.extractfile(member)
                    assert stream is not None
                    data = stream.read()
                    if name == "release.json":
                        assert json.loads(data) == record, "release metadata differs from source"
                    else:
                        assert data == resources[name], f"shipped bytes differ from source: {name}"
        assert files <= seen, f"missing files: {sorted(files - seen)}"
        destination.mkdir(parents=True)
        tar.extractall(destination, filter="data")
    for path in (destination, *destination.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)


def install(archive, root, home, version):
    """Run install.sh in unsigned mode. Only the local download is replaced."""
    feed = root / "feed"
    (feed / "releases" / version).mkdir(parents=True)
    shutil.copyfile(archive, feed / "releases" / version / archive.name)
    shutil.copyfile(archive.parent / "SHA256SUMS.txt", feed / "releases" / version / "SHA256SUMS.txt")
    tools = root / "tools"
    tools.mkdir()
    gh = tools / "gh"
    gh.write_text(f"""#!{sys.executable}
import pathlib, shutil, sys
args = sys.argv[1:]
assert args[:2] == ["release", "download"]
asset = args[args.index("--pattern") + 1]
source = pathlib.Path({str(feed)!r}) / "releases" / args[2].removeprefix("v") / asset
shutil.copyfile(source, args[args.index("--output") + 1])
""")
    gh.chmod(0o755)
    script = root / "install.sh"
    shutil.copyfile(ROOT / "install.sh", script)
    env = dict(HOME=str(home), SHELL="/bin/zsh", BOX_NO_MODIFY_PATH="1",
               BOX_VERSION=version, BOX_ALLOW_UNSIGNED="1", LC_ALL="C",
               PATH=f"{tools}:/usr/bin:/bin:/usr/sbin:/sbin")
    result = subprocess.run(["/bin/sh", str(script)], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
    assert result.returncode == 0, "install.sh"
    return home / ".strands/box/packages" / f"{version}-{TARGET}"


def run(command, workspace, env):
    arguments = [str(arg) for arg in command]
    with subprocess.Popen(arguments, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT)
        except BaseException:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            # Core puts workloads in separate groups within this session.
            pids = subprocess.check_output(["/bin/ps", "-axo", "pid="], text=True).split()
            for value in pids:
                pid = int(value)
                try:
                    if os.getsid(pid) == process.pid:
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
        result = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
    return result


def policy_writes(value):
    found = set()
    if isinstance(value, dict):
        if value.get("name") == "policy fs:write":
            attributes = {item["key"].rsplit(".", 1)[-1]: item.get("value", {}).get("stringValue")
                          for item in value.get("attributes", [])}
            found.add((attributes.get("path"), attributes.get("verdict")))
        for child in value.values():
            found.update(policy_writes(child))
    elif isinstance(value, list):
        for child in value:
            found.update(policy_writes(child))
    return found


def workload(command, home, workspace, env):
    pack = tomllib.loads((ROOT / "resources/packs/base/pack.toml").read_text())["pack"]
    preview = run([command, "profile", "show", "probe"], workspace, env)
    assert preview.returncode == 0, "profile preview"
    words = preview.stdout.replace(",", " ").split()
    assert (pack["name"], str(pack["version"])) in zip(words, words[1:]), "shipped base pack"
    runs = home / ".strands/box/r"
    before = set(runs.iterdir()) if runs.exists() else set()
    result = run([command, "run", "probe", "--no-banner", "--", "-c", PROBE], workspace, env)
    assert result.returncode == 0 and result.stdout == "package-ok\n", "contained workload"
    assert (workspace / "direct.txt").read_text() == "direct\n", "native workspace write"
    assert (workspace / "broker.txt").read_text() == "broker\n", "broker workspace write"
    assert not (workspace / ".box/denied.txt").exists(), "protected write was allowed"
    created = set(runs.iterdir()) - before
    assert len(created) == 1, "one workload run"
    records = created.pop() / "records.jsonl"
    writes = set()
    for line in records.read_text().splitlines():
        writes.update(policy_writes(json.loads(line)))
    assert ("~/project/broker.txt", "permit") in writes, "recorded allowed write"
    assert ("~/project/.box/denied.txt", "deny") in writes, "recorded denial"
    print(f"PASS: {command}: shipped pack, both helpers, allowed write, and recorded denial", flush=True)
    (workspace / "direct.txt").unlink()
    (workspace / "broker.txt").unlink()


def expected_record(commit):
    manifest = tomllib.loads((ROOT / "crates/cli/app/Cargo.toml").read_text())
    packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    core, containment = ([p for p in packages if p["name"] == name] for name in
                         ("strands-box", "strands-box-containment"))
    assert len(core) == len(containment) == 1, "one Core and one helper package"
    source = core[0].get("source")
    assert containment[0].get("source") == source, "Core and helpers use one Core source"
    # A path dependency has no source in Cargo.lock: Core's commit is the packaged commit.
    core_commit = commit if source is None else source.split("#")[1]
    return dict(box_version=manifest["package"]["version"], box_commit=commit,
                core_version=core[0]["version"], core_commit=core_commit, target=TARGET)


def verify(archive, commit):
    assert platform.system() == "Darwin" and platform.machine() == "arm64", "Apple Silicon Mac required"
    assert re.fullmatch(r"[0-9a-f]{40}", commit), "expected source commit"
    record = expected_record(commit)
    resources = {p.relative_to(ROOT).as_posix(): p.read_bytes()
                 for p in (ROOT / "resources").rglob("*") if p.is_file()}
    starters = [name.rsplit("/", 1)[-1] for name in
                tomllib.loads(resources["resources/config.toml"].decode())["starters"]["only"]]
    with tempfile.TemporaryDirectory(prefix="box-pkg", dir="/var/tmp") as temporary:
        root = Path(temporary).resolve()
        home = root / "home with spaces"
        home.mkdir()
        prepare_installation(home)
        contents = root / "archive"
        unpack(archive, contents, record, resources)
        print("PASS: archive, checksum, file inventory, modes, source revisions, and packs", flush=True)
        print(f"Archive contents: {contents}", flush=True)
        expected = {p.relative_to(contents).as_posix(): p for p in sorted(contents.rglob("*")) if p.is_file()}
        for name, path in expected.items():
            print(f"  {name} ({path.stat().st_size} bytes)", flush=True)
        for name in BINARIES:
            subprocess.run(["/usr/bin/lipo", str(contents / name), "-verify_arch", "arm64"], check=True)
            dependencies = subprocess.check_output(["/usr/bin/otool", "-L", str(contents / name)], text=True)
            for line in dependencies.splitlines()[1:]:
                assert line.strip().startswith(("/usr/lib/", "/System/Library/")), f"external library: {line}"
        print("PASS: arm64 executables use only macOS system libraries", flush=True)
        release = install(archive, root, home, record["box_version"])
        public = home / ".local/bin/box"
        assert (release.parent / "current").readlink() == Path(release.name), "current link"
        assert public.readlink() == release.parent / "current/box", "launcher link"
        assert [p.name for p in public.parent.iterdir()] == ["box"], "launcher directory"
        installed = {p.relative_to(release).as_posix(): p for p in release.rglob("*") if p.is_file()}
        assert installed.keys() == expected.keys(), "installed files"
        for name, path in expected.items():
            assert installed[name].read_bytes() == path.read_bytes(), f"installed bytes: {name}"
            assert installed[name].stat().st_mode & 0o777 == path.stat().st_mode & 0o777, f"installed mode: {name}"
        print(f"PASS: install.sh installed every file, both links, and modes in {release}", flush=True)
        workspace = home / "project"
        (workspace / ".box").mkdir(parents=True)
        profile = home / ".strands/box/profiles/probe"
        profile.mkdir(parents=True)
        (profile / "profile.toml").write_text(PROFILE)
        (profile / "policy.dw").write_text((ROOT / "resources/policies/scoped/policy.dw").read_text())
        env = dict(HOME=str(home), PATH=f"{public.parent}:/usr/bin:/bin", TERM="dumb", LC_ALL="C")
        for command in (release / "box", public):
            version = run([command, "--version"], workspace, env)
            assert version.returncode == 0 and version.stdout == f"box {record['box_version']}\n", "version"
            listing = run([command, "profile", "list"], workspace, env)
            section = listing.stdout.partition("\nStarters:\n")[2]
            shown = [line.split()[0] for line in section.splitlines() if line.strip()]
            assert listing.returncode == 0 and shown == starters and "invalid:" not in section, "built-in starters"
            print(f"PASS: {command}: built-in starters {', '.join(shown)}", flush=True)
            topic = run([command, "help", "agent"], workspace, env)
            assert topic.returncode == 0, "help agent"
            guide = Path(topic.stdout.splitlines()[1].strip())
            assert guide.parts[-2:] == ("resources", "editing-box-profile.md"), "guide path"
            assert guide.read_bytes() == resources["resources/editing-box-profile.md"], "guide bytes"
            assert not (home / ".strands/box/editing-box-profile.md").exists(), "help agent wrote a guide"
            print(f"PASS: {command}: help agent names the shipped guide {guide}", flush=True)
            workload(command, home, workspace, env)
        print("Checking arguments and workload exit status:", flush=True)
        result = run([public, "run", "probe", "--no-banner", "--", "-c",
                      'printf "%s\\n" "$@"; exit 7', "probe", "two words", "*", ""], workspace, env)
        assert result.returncode == 7 and result.stdout == "two words\n*\n\n", "arguments and exit status"
        print("PASS: direct command preserves arguments and workload exit status", flush=True)
        for name in (*BINARIES[1:], "resources"):
            path = release / name
            hidden = release / f"{name}.removed"
            path.rename(hidden)
            try:
                print(f"Checking refusal without {name}:", flush=True)
                result = run([public, "run", "probe", "--no-banner", "--", "-c", PROBE], workspace, env)
                assert result.returncode != 0, f"workload passed without {name}"
            finally:
                hidden.rename(path)
            print(f"PASS: workload refuses missing {name}", flush=True)
        print(f"Global box command would point to: {public} -> {public.readlink()}", flush=True)
        print(f"Native binary: {release / 'box'}", flush=True)
    print("PASS: real package checks complete; temporary home removed. Apple signing was not tested.", flush=True)


if __name__ == "__main__":
    if not __debug__:
        sys.exit("package verification requires Python assertions; remove -O or PYTHONOPTIMIZE")
    if len(sys.argv) != 3:
        sys.exit("usage: test_macos_package.py <archive.tar.gz> <Box source commit>")
    verify(Path(sys.argv[1]).resolve(), sys.argv[2])
