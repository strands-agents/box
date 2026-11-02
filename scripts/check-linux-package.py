#!/usr/bin/env python3
"""Check the architecture, loader, and glibc requirements of a Linux package."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
GLIBC_LIMIT = (2, 34)
LOADER = "/lib/ld-linux-aarch64.so.1"


def inspect(binary):
    output = subprocess.run(
        ["readelf", "--wide", "--file-header", "--program-headers",
         "--dynamic", "--version-info", str(binary)],
        check=True, capture_output=True, text=True,
    ).stdout
    if not re.search(r"Machine:\s+AArch64\s*$", output, re.MULTILINE):
        raise ValueError(f"{binary.name}: expected an AArch64 executable")
    loader = re.search(r"Requesting program interpreter: ([^\]]+)", output)
    if not loader or loader.group(1) != LOADER:
        raise ValueError(f"{binary.name}: expected loader {LOADER}")
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
        "architecture": "aarch64",
        "loader": loader.group(1),
        "needed": re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", output),
        "glibc_requirements": names,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result = [inspect(args.directory / name) for name in BINARIES]
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
