#!/usr/bin/env python3
"""Check the architecture, loader, and glibc requirements of a Linux package."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline",
            "strands-box-storage-compiler")
GLIBC_LIMIT = (2, 34)
DEFAULT_TARGET = "aarch64-unknown-linux-gnu"
TARGETS = {
    DEFAULT_TARGET: ("aarch64", "AArch64", "/lib/ld-linux-aarch64.so.1"),
    "x86_64-unknown-linux-gnu": (
        "x86_64", "Advanced Micro Devices X86-64", "/lib64/ld-linux-x86-64.so.2",
    ),
}


def inspect(binary, target=DEFAULT_TARGET):
    architecture, machine, expected_loader = TARGETS[target]
    output = subprocess.run(
        ["readelf", "--wide", "--file-header", "--program-headers",
         "--dynamic", "--version-info", str(binary)],
        check=True, capture_output=True, text=True,
    ).stdout
    if not re.search(rf"Machine:\s+{re.escape(machine)}\s*$", output, re.MULTILINE):
        raise ValueError(f"{binary.name}: expected an {machine} executable")
    loader = re.search(r"Requesting program interpreter: ([^\]]+)", output)
    if not loader or loader.group(1) != expected_loader:
        raise ValueError(f"{binary.name}: expected loader {expected_loader}")
    names = sorted(set(re.findall(r"Name:\s+(GLIBC_[\w.]+)", output)))
    if not names:
        raise ValueError(f"{binary.name}: no glibc requirements found")
    for name in names:
        if name == "GLIBC_PRIVATE":
            raise ValueError(f"{binary.name}: private glibc interfaces are not supported")
        version = name.removeprefix("GLIBC_")
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)*", version):
            raise ValueError(f"{binary.name}: unknown glibc requirement {name}")
        if tuple(map(int, version.split("."))) > GLIBC_LIMIT:
            raise ValueError(f"{binary.name}: {name} exceeds GLIBC_2.34")
    return {
        "binary": binary.name,
        "architecture": architecture,
        "loader": loader.group(1),
        "needed": re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", output),
        "glibc_requirements": names,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--target", choices=TARGETS, default=DEFAULT_TARGET,
        help="package target (default: %(default)s)",
    )
    parser.add_argument("--require-storage-metadata", action="store_true",
                        help="require the CLI archive storage compiler marker")
    args = parser.parse_args()
    try:
        if args.require_storage_metadata:
            metadata = json.loads((args.directory / "release.json").read_text())
            if not isinstance(metadata, dict) or metadata.get("storage_compiler") is not True:
                raise ValueError("release.json: storage_compiler must be true")
        result = [inspect(args.directory / name, args.target) for name in BINARIES]
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
