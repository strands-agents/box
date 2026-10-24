"""Prepare a portable Lambda image archive from verified packages."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent


def box_identity(path, expected, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Supply the full Box source revision from its build receipt")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError("Box bundle SHA-256 does not match")
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        names = set()
        for member in members:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or name in names
                    or not (member.isfile() or member.isdir())):
                raise ValueError("Box bundle contains an unsupported entry")
            names.add(name)
        binaries = [m for m in members if m.isfile() and PurePosixPath(m.name) == PurePosixPath("box")]
        if len(binaries) != 1 or not binaries[0].mode & 0o111:
            raise ValueError("Box bundle must contain an executable box at its root")
        binary = archive.extractfile(binaries[0]).read()
        if binary[:6] != b"\x7fELF\x02\x01" or binary[18:20] != b"\xb7\x00":
            raise ValueError("Box must be a Linux ARM64 executable")
    return {"revision": revision, "sha256": digest, "binary_sha256": hashlib.sha256(binary).hexdigest()}


def prepare(args):
    identity = box_identity(args.box_package, args.box_sha256, args.box_revision)
    manifest = json.loads((ROOT / "app/claude-package.json").read_text())
    build = ROOT / ".build"
    build.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="package-", dir=build) as directory:
        staging = Path(directory)
        for source in (ROOT / "app").iterdir():
            if source.is_file():
                shutil.copyfile(source, staging / source.name)
        claude = args.claude_package
        if claude is None:
            claude = staging / "claude.tar.gz"
            with urllib.request.urlopen(manifest["url"], timeout=120) as source, claude.open("wb") as target:
                shutil.copyfileobj(source, target)
        digest = "sha512-" + base64.b64encode(hashlib.sha512(claude.read_bytes()).digest()).decode()
        if digest != manifest["integrity"]:
            raise ValueError("Claude Code package integrity does not match")
        if claude.resolve() != (staging / "claude.tar.gz").resolve():
            shutil.copyfile(claude, staging / "claude.tar.gz")
        shutil.copyfile(args.box_package, staging / "box.tar.gz")
        # Check the bytes copied into the build, not only the source path.
        if box_identity(staging / "box.tar.gz", args.box_sha256, args.box_revision) != identity:
            raise ValueError("Box package changed during preparation")
        (staging / "box-package.json").write_text(json.dumps(identity, sort_keys=True) + "\n")
        files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(staging.iterdir())}
        fingerprint = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        (staging / "manifest.json").write_text(json.dumps({"fingerprint": fingerprint, "files": files}) + "\n")
        archive = build / (fingerprint + ".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for path in sorted(staging.iterdir()):
                entry = zipfile.ZipInfo(path.name)
                entry.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(entry, path.read_bytes())
    return archive, fingerprint, identity
