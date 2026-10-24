"""Install checksum-verified Box and Claude packages."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

HERE = Path(__file__).resolve().parent


def install():
    package = json.loads((HERE / "box-package.json").read_text())
    bundle = HERE / "box.tar.gz"
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != package["sha256"]:
        raise ValueError("Box package digest mismatch")
    destination = Path("/opt/box")
    destination.mkdir()
    with tarfile.open(bundle) as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsupported Box archive entry")
        archive.extractall(destination)
    binary = destination / "box"
    if hashlib.sha256(binary.read_bytes()).hexdigest() != package["binary_sha256"]:
        raise ValueError("Box executable digest mismatch")
    manifest = json.loads((HERE / "claude-package.json").read_text())
    data = (HERE / "claude.tar.gz").read_bytes()
    if "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode() != manifest["integrity"]:
        raise ValueError("Claude package integrity mismatch")
    agents = Path("/opt/agents")
    agents.mkdir()
    with tarfile.open(HERE / "claude.tar.gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile() and PurePosixPath(m.name).name == "claude"]
        if len(members) != 1:
            raise ValueError("Expected one Claude executable")
        data = archive.extractfile(members[0]).read()
    if data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00":
        raise ValueError("Claude must be a Linux ARM64 executable")
    (agents / "claude").write_bytes(data)
    (agents / "claude").chmod(0o755)
    (agents / "installed.json").write_text(json.dumps({
        "claude": {"version": manifest["version"], "sha256": hashlib.sha256(data).hexdigest()},
    }))


if __name__ == "__main__":
    install()
