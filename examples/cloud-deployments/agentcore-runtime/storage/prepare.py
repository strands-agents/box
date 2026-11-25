#!/usr/bin/env python3
"""Copy matching Box helpers and compile the native workload on Linux ARM64."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
BINARIES = ("strands-box", "strands-box-sock-alias", "strands-box-contain-trampoline")


def arm64_executable(path):
    header = path.read_bytes()[:20]
    return header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\xb7\x00"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--strip-debug", action="store_true", help="Strip debug sections from copies; preserve the original binaries")
    args = parser.parse_args()
    expected = args.source_root.resolve() / "examples/cloud-deployments/agentcore-runtime/storage"
    if ROOT != expected:
        parser.error("Run the preparation script inside the declared source checkout")
    if platform.system() != "Linux" or platform.machine() not in {"aarch64", "arm64"}:
        parser.error("Prepare this image on Linux ARM64")
    revision = subprocess.check_output(["git", "-C", str(args.source_root), "rev-parse", args.source_revision + "^{commit}"], text=True).strip()
    head = subprocess.check_output(["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True).strip()
    if head != revision:
        parser.error("Check out the declared final revision before preparation")
    subprocess.run(["git", "-C", str(args.source_root), "diff", "--exit-code", revision, "--"], check=True)
    untracked = subprocess.check_output(["git", "-C", str(args.source_root), "ls-files", "--others", "--exclude-standard"], text=True)
    if untracked:
        parser.error("The source checkout has untracked files; prepare from the clean final revision")
    tree = subprocess.check_output(["git", "-C", str(args.source_root), "rev-parse", revision + "^{tree}"], text=True).strip()
    for name in BINARIES:
        if not arm64_executable(args.bin_dir / name):
            parser.error("Expected a Linux ARM64 executable: " + str(args.bin_dir / name))
    destination = ROOT / "bin"
    destination.mkdir(exist_ok=True)
    transformations = {}
    for name in BINARIES:
        source = args.bin_dir / name
        if args.strip_debug:
            subprocess.run(["strip", "--strip-debug", "-o", str(destination / name), str(source)], check=True)
        else:
            shutil.copyfile(source, destination / name)
        transformations[name] = {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                 "operation": "strip --strip-debug" if args.strip_debug else "copy"}
        (destination / name).chmod(0o755)
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "workload.c"), "-o", str(ROOT / "workload")], check=True)
    if not arm64_executable(ROOT / "workload"):
        raise RuntimeError("The compiler did not produce a Linux ARM64 workload")
    paths = [destination / name for name in BINARIES] + [ROOT / "workload", ROOT / "workload.c", ROOT / "server.py"]
    manifest = {"expected_source_revision": revision, "source_tree": tree, "tracked_checkout_matches_revision": True,
                "binary_transformations": transformations,
                "revision_note": "The source tree was checked. Retain the preceding all-feature build log; hashes alone do not prove which source built a binary.",
                "files": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}
    (ROOT / "binary-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
