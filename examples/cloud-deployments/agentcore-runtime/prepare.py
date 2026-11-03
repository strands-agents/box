#!/usr/bin/env python3
"""Build the pinned Box revision and install one framework for Linux ARM64."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BOX_REVISION = "e4ca8b80359b2213d684de31cd6ef32e0d61478a"
BINARIES = {"strands-box": "box", "strands-box-contain-trampoline": "strands-box-contain-trampoline",
            "strands-box-sock-alias": "strands-box-sock-alias"}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def install_binaries(directory, revision):
    contents = {}
    for source_name, name in BINARIES.items():
        source = directory / source_name
        data = source.read_bytes()
        if source.is_symlink() or data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00":
            raise ValueError("Expected a regular Linux ARM64 executable: " + str(source))
        contents[name] = data
    destination = ROOT / "box-core"
    destination.mkdir(exist_ok=True)
    files = {}
    for name, data in contents.items():
        target = destination / name
        if target.exists() or target.is_symlink():
            raise ValueError("Use a fresh example checkout; a binary already exists: " + name)
        target.write_bytes(data)
        target.chmod(0o755)
        files["box-core/" + name] = hashlib.sha256(data).hexdigest()
    manifest = {"box_revision": revision, "files": files}
    save(ROOT / "binary-manifest.json", manifest)
    save(ROOT / "research/tested-build.json", manifest)
    return manifest


def install_framework(framework):
    if framework == "scripted":
        return
    directory = ROOT / ("sdk" if framework == "strands" else "langchain-example")
    vendor = directory / "vendor"
    if vendor.exists():
        raise ValueError("Use a fresh checkout; dependencies already exist at " + str(vendor))
    subprocess.run([sys.executable, "-m", "pip", "install", "--only-binary=:all:", "--no-compile",
                    "--target", str(vendor), "-r", str(directory / "dependency-lock.txt")], check=True)
    packages = {distribution.metadata["Name"]: distribution.version
                for distribution in importlib.metadata.distributions(path=[str(vendor)])}
    files = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(vendor.rglob("*")) if p.is_file()}
    save(directory / "dependency-manifest.json", {"python_minor": "3.12", "architecture": "aarch64",
                                                 "platform": "Linux", "packages": packages, "files": files})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", choices=("scripted", "strands", "langchain"), default="strands")
    parser.add_argument("--box-source", type=Path, help="Existing clean checkout at the pinned Box revision.")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "aarch64" or sys.version_info[:2] != (3, 12):
        parser.error("Prepare this example on Linux ARM64 with Python 3.12")
    source = args.box_source.resolve() if args.box_source else ROOT / ".build/box"
    if not source.exists():
        if args.box_source:
            parser.error("The supplied Box source checkout does not exist")
        source.mkdir(parents=True)
        subprocess.run(["git", "-C", str(source), "init"], check=True)
        subprocess.run(["git", "-C", str(source), "remote", "add", "origin", "https://github.com/strands-agents/box.git"], check=True)
        subprocess.run(["git", "-C", str(source), "fetch", "--depth", "1", "origin", BOX_REVISION], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"], check=True)
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    changed = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True)
    if revision != BOX_REVISION or changed:
        parser.error("The Box source must be clean at " + BOX_REVISION)
    subprocess.run(["cargo", "build", "--release", "--locked", "--all-features", "-p", "strands-box",
                    "-p", "strands-box-containment", "--target-dir", str(source / "target")], cwd=source, check=True)
    install_binaries(source / "target/release", revision)
    install_framework(args.framework)
    print("Prepared " + args.framework + "; binary and dependency hashes recorded locally.")


if __name__ == "__main__":
    main()
