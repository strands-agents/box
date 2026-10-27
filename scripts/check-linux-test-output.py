#!/usr/bin/env python3
"""Reject unexpected Linux test skips and report existing coverage gaps."""

import argparse
from collections import Counter
from pathlib import Path
import re


MISSING_DAEMON = "no credsd daemon at /run/credsd/credsd.sock"
ALIAS_READ = (
    "the namespace launcher cannot subtract read from an exec grant, so the alias-read "
    "assertion did not run. The write assertions did."
)
EXPECTED_SKIPS = {
    MISSING_DAEMON: "The real credential-daemon fixture remains untested in this job.",
    ALIAS_READ: "The alias test retains its write assertions; its read assertion remains omitted.",
}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def check_output(text):
    text = ANSI_ESCAPE.sub("", text)
    skips = Counter(
        line.split("skipping:", 1)[1].strip()
        for line in text.splitlines()
        if "skipping:" in line
    )
    errors = []
    if "test result:" not in text:
        errors.append("No Rust test result was recorded.")
    if "test result: FAILED." in text:
        errors.append("A Rust test target failed.")
    for reason, count in skips.items():
        if reason not in EXPECTED_SKIPS or count != 1:
            errors.append(f"Unexpected skip ({count}): {reason}")
    report = ["## Linux workspace execution", ""]
    if skips:
        report.append("The following tests omitted some or all assertions:")
        report.extend(f"- {count}: {reason}" for reason, count in sorted(skips.items()))
    else:
        report.append("No test emitted a prerequisite-skip diagnostic.")
    for reason in skips:
        if reason in EXPECTED_SKIPS:
            report.append(EXPECTED_SKIPS[reason])
    report.extend(["", "Rust ignored tests and intentional name filters remain separate from these diagnostics."])
    report.extend(f"ERROR: {error}" for error in errors)
    return not errors, "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    passed, report = check_output(args.log.read_text())
    print(report)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
