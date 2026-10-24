#!/usr/bin/env python3
"""Prepare the Runtime example with an operator-selected Box bundle."""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app/demo"


def prepare(args):
    if not re.fullmatch(r"\d{12}", args.account):
        raise ValueError("Account must contain 12 digits")
    if not re.fullmatch(r"[0-9a-f]{40}", args.box_revision):
        raise ValueError("Supply the full source revision from the bundle's build receipt")
    data = args.box_package.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.box_sha256:
        raise ValueError("Box bundle SHA-256 does not match")
    with tarfile.open(args.box_package) as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Box bundle contains an unsupported entry")
        binaries = [member for member in members if member.isfile() and PurePosixPath(member.name).name == "box"]
        if len(binaries) != 1:
            raise ValueError("Box bundle must contain one box executable and its packaged helpers")
        binary = archive.extractfile(binaries[0]).read()
        if binary[:6] != b"\x7fELF\x02\x01" or binary[18:20] != b"\xb7\x00":
            raise ValueError("Box must be a Linux ARM64 executable")
    manifest = json.loads((APP / "claude-package.json").read_text())
    with tempfile.TemporaryDirectory(prefix="box-runtime-package-") as temporary:
        claude = args.claude_package
        if claude is None:
            claude = Path(temporary) / "claude.tar.gz"
            with urllib.request.urlopen(manifest["url"], timeout=120) as response, claude.open("wb") as destination:
                shutil.copyfileobj(response, destination)
        actual = "sha512-" + base64.b64encode(hashlib.sha512(claude.read_bytes()).digest()).decode()
        if actual != manifest["integrity"]:
            raise ValueError("Claude Code package integrity does not match")
        for source, target in ((args.box_package, APP / "box.tar.gz"), (claude, APP / "claude.tar.gz")):
            if source.resolve() != target.resolve():
                shutil.copyfile(source, target)
    (APP / "box-package.json").write_text(json.dumps({
        "revision": args.box_revision, "sha256": digest,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
    }, indent=2) + "\n")
    (ROOT / "agentcore/aws-targets.json").write_text(json.dumps([
        {"name": "default", "account": args.account, "region": "us-west-2"},
    ], indent=2) + "\n")
    print("Prepared both Runtime modes for account " + args.account + " in us-west-2.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--box-package", type=Path, required=True)
    parser.add_argument("--box-sha256", required=True)
    parser.add_argument("--box-revision", required=True)
    parser.add_argument("--claude-package", type=Path)
    prepare(parser.parse_args())
