#!/usr/bin/env python3
"""Install the verified native macOS archive through the signed installer path."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile

from smoke_telemetry import prepare_installation

ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
spec = importlib.util.spec_from_file_location("macos_release", ROOT / "scripts/macos-release-cli.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def installer_environment(home, tools, temporary, version):
    return dict(HOME=str(home), SHELL="/bin/zsh", PATH=f"{tools}:{SYSTEM_PATH}",
                TMPDIR=str(temporary), LC_ALL="C", BOX_VERSION=version, BOX_NO_MODIFY_PATH="1")


def install(archive, package, receipt, source_sha, evidence):
    archive, package, receipt, evidence = (path.resolve() for path in (archive, package, receipt, evidence))
    evidence.mkdir(parents=True)
    record = dict(status="failed", archive=str(archive), verified_package=str(package),
                  signing_receipt=str(receipt), source_sha=source_sha)
    try:
        release.require(platform.system() == "Darwin", "The signed installer gate requires macOS")
        signed = release.verify_native_binding(package, archive, receipt, source_sha)
        version = signed["version"]
        release.require(archive.name == f"box-cli-v{version}-aarch64-apple-darwin.tar.gz",
                        "Unexpected signed archive name")
        record["archive_sha256"] = signed["output_sha256"]
        work = Path(tempfile.mkdtemp(prefix="bni-", dir="/var/tmp")).resolve()
        record["work"] = str(work)
        home, tools, temporary = (work / name for name in ("h", "tools", "tmp"))
        for path in (home, tools, temporary):
            path.mkdir()
        prepare_installation(home)
        checksum = work / "SHA256SUMS.txt"
        checksum.write_text(f"{signed['output_sha256']}  {archive.name}\n")
        gh = tools / "gh"
        gh.write_text(f"""#!{sys.executable}
import json, pathlib, shutil, sys
args = sys.argv[1:]
if (len(args) != 9 or args[:5] != {["release", "download", "v" + version, "--repo", "strands-agents/box"]!r}
        or args[5] != "--pattern" or args[7] != "--output"):
    sys.exit("Unexpected installer download request")
assets = {{{archive.name!r}: {str(archive)!r}, "SHA256SUMS.txt": {str(checksum)!r}}}
if args[6] not in assets:
    sys.exit("Unexpected installer asset")
shutil.copyfile(assets[args[6]], args[8])
with pathlib.Path({str(evidence / 'downloads.jsonl')!r}).open("a") as output:
    print(json.dumps(dict(asset=args[6], source=assets[args[6]], destination=args[8])), file=output)
""")
        gh.chmod(0o755)
        environment = installer_environment(home, tools, temporary, version)
        record["environment"] = environment
        command = ["/bin/sh", str(ROOT / "install.sh")]
        record["installer_command"] = command
        result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=120)
        (evidence / "install.stdout").write_text(result.stdout)
        (evidence / "install.stderr").write_text(result.stderr)
        record["installer_returncode"] = result.returncode
        release.require(result.returncode == 0, f"install.sh failed with status {result.returncode}")
        packages = home / ".strands/box/packages"
        installed = packages / f"{version}-aarch64-apple-darwin"
        public = home / ".local/bin/box"
        current = packages / "current"
        release.require(current.is_symlink() and os.readlink(current) == installed.name,
                        "Unexpected installed current link")
        release.require(public.is_symlink() and os.readlink(public) == str(current / "box")
                        and public.resolve() == installed / "box", "Unexpected public launcher link")
        release.verify_native_binding(installed, archive, receipt, source_sha)
        release.require(all(stat.S_IMODE(path.stat().st_mode) == 0o755 for path in
                            [installed, *installed.rglob("*")] if path.is_dir() and not path.is_symlink()),
                        "Unexpected installed directory mode")
        record.update(installed_package=str(installed), public_launcher=str(public),
                      version_command=[str(public), "--version"])
        result = subprocess.run(record["version_command"], env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=30)
        (evidence / "version.stdout").write_text(result.stdout)
        (evidence / "version.stderr").write_text(result.stderr)
        record["version_returncode"] = result.returncode
        release.require(result.returncode == 0 and result.stdout.strip() == f"box {version}",
                        "Public installed box --version failed")
        record["status"] = "passed"
        return installed
    except Exception as error:
        record["error"] = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            for name, output in (("timeout.stdout", error.stdout), ("timeout.stderr", error.stderr)):
                (evidence / name).write_bytes(output if isinstance(output, bytes) else (output or "").encode())
        raise RuntimeError(str(error)) from error
    finally:
        (evidence / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "package", "receipt", "evidence"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        print(install(args.archive, args.package, args.receipt, args.source_sha, args.evidence))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
