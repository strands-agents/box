"""Check that a manual signed test receipt covers the current source."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECEIPT = ROOT / "test-native-filesystem/signed-receipt.json"


def sources():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in sorted(set(names))
        if (ROOT / name).is_file()
        and name != RECEIPT.relative_to(ROOT).as_posix()
        and (
            name.startswith(("crates/", "test-native-filesystem/", ".github/workflows/"))
            or name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
        )
        and not name.endswith(".md")
    }


def tests():
    return sorted(
        re.findall(
            r"#\[test\]\s+fn (\w+)\(",
            (ROOT / "test-native-filesystem/tests/enforcement.rs").read_text(),
        )
    )


def verify(receipt, current_sources, expected_tests):
    if receipt.get("sources") != current_sources:
        raise ValueError("Signed native test receipt is stale; rerun the signed suite.")
    if not expected_tests or receipt.get("passed_tests") != expected_tests:
        raise ValueError("Signed native test receipt does not cover every test.")
    if receipt.get("signature_verified") is not True:
        raise ValueError("Signed native test receipt has no verified signature.")
    if int(receipt.get("macos", "0").split(".")[0]) < 27:
        raise ValueError("Signed native tests require macOS 27 or later.")
    if not re.fullmatch(r"[a-f0-9]{64}", receipt.get("binary_sha256", "")):
        raise ValueError("Signed native test receipt has no executable hash.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--record", type=Path, help="Successful full signed cargo test log")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--before", type=Path, help="Source snapshot taken before the build")
    args = parser.parse_args()
    current = sources()
    if args.snapshot:
        args.snapshot.write_text(json.dumps(current, indent=2) + "\n")
        return
    if args.record:
        if not args.binary or not args.before:
            parser.error("--record requires --binary and --before")
        if json.loads(args.before.read_text()) != current:
            raise ValueError("Sources changed after the snapshot; rebuild and rerun.")
        log = args.record.read_text()
        passed = sorted(re.findall(r"^test (\w+) \.\.\. ok$", log, re.MULTILINE))
        expected = tests()
        summary = f"test result: ok. {len(expected)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
        if passed != expected or summary not in log or "test result: FAILED" in log:
            raise ValueError("The log does not show an unfiltered passing signed suite.")
        subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(args.binary)],
            check=True,
        )
        receipt = {
            "kind": "manual signed-run attestation; CI checks source freshness",
            "sources": current,
            "passed_tests": passed,
            "signature_verified": True,
            "macos": subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip(),
            "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "test_log_sha256": hashlib.sha256(args.record.read_bytes()).hexdigest(),
        }
        verify(receipt, current, expected)
        RECEIPT.write_text(json.dumps(receipt, indent=2) + "\n")
    else:
        verify(json.loads(RECEIPT.read_text()), current, tests())
    print("Signed native test receipt matches the current source.")


if __name__ == "__main__":
    main()
