#!/usr/bin/env python3
"""Prepare the native workload and four Box executables on Linux ARM64."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
BINARIES = ("strands-box", "strands-box-sock-alias", "strands-box-contain-trampoline", "strands-box-storage-compiler")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True, help="Directory containing the four matching Box executables.")
    parser.add_argument("--source-revision", required=True, help="Revision of the checkout used to build those executables; recorded, not inferred from binaries.")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"aarch64", "arm64"}:
        parser.error("Prepare this example on Linux ARM64")
    destination = ROOT / "bin"
    destination.mkdir(exist_ok=True)
    for name in BINARIES:
        source = args.bin_dir / name
        data = source.read_bytes()
        if data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00":
            parser.error("Expected a Linux ARM64 executable: " + str(source))
        shutil.copyfile(source, destination / name)
        (destination / name).chmod(0o755)
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "workload.c"), "-o", str(ROOT / "workload")], check=True)
    paths = [destination / name for name in BINARIES] + [ROOT / "workload", ROOT / "workload.c"]
    manifest = {"expected_source_revision": args.source_revision, "revision_note": "Verify the source checkout before building; executable hashes alone do not prove its revision.",
                "files": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}
    (ROOT / "binary-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
