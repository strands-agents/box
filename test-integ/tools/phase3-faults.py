#!/usr/bin/env python3
"""Run Phase 3 refusal cases against a test-owned unconfined or non-launching box."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


CASES = {
    "CN-T-01": ("cn_t_01", "no shell:exec decision was journaled"),
    "CN-P-01": ("cn_p_01", "HOST_MARKER_VISIBLE"),
    "CN-I-08": ("cn_i_08", "SIGNAL_REACHED"),
    "CN-I-09": ("cn_i_09", "TRACE_REACHED"),
    "CN-I-10": ("cn_i_10", "ABSTRACT_REACHED"),
    "CN-I-11": ("cn_i_11", None),
    "CN-I-12": ("cn_i_12", "SHM_REACHED"),
    "CN-L-04": ("cn_l_04", "live descendant survived ordinary exit"),
}

SHIM = r"""#!/usr/bin/env python3
import os, sys, tomllib
args = sys.argv[1:]
assert args.pop(0) == "run"
assert args.pop(0) == "--config"
with open(args.pop(0), "rb") as source:
    config = tomllib.load(source)
assert args.pop(0) == "--"
command = config["agent"]["command"]
if os.environ["PHASE3_FAULT"] == "no-entry" and command != ["/bin/echo"]:
    print("Operation not permitted")
    sys.exit(126)
os.execvp(command[0], command + args)
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True, help="compiled containment test binary")
    parser.add_argument("--emitter", type=Path, required=True, help="compiled emit-verdict binary")
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    selections = (
        ("normal-capture", "permissive", {"CN-I-11": CASES["CN-I-11"]}),
        ("permissive", "permissive", CASES),
        ("no-entry", "no-entry", CASES),
    )
    for label, fault, selected in selections:
        with tempfile.TemporaryDirectory(prefix="phase3-fault-") as temp:
            fixture = Path(temp)
            binary_dir = fixture / "bin"
            binary_dir.mkdir()
            shim = binary_dir / "strands-box"
            shim.write_text(SHIM)
            shim.chmod(0o755)
            alias = binary_dir / "zsh"
            # A host shell must fail the mediated journal check even if it prints both sentinels.
            alias.write_text('#!/bin/bash\nexec /bin/bash "$@"\n')
            alias.chmod(0o755)
            operator = fixture / "operator"
            operator.mkdir()
            rows = args.results.resolve() / label
            rows.mkdir(exist_ok=False)
            env = os.environ.copy()
            env.update({
                "HOME": str(operator),
                "PATH": f"{binary_dir}:{env['PATH']}",
                "PHASE3_FAULT": fault,
                "DET_RESULTS_DIR": str(rows),
                "PLATFORM": "linux",
            })
            env.pop("RUST_TEST_NOCAPTURE", None)
            result = subprocess.run(
                [str(args.binary.resolve()), "--test-threads=1",
                 *[f"{name}::{name}" for name, _ in selected.values()]],
                env=env, capture_output=True, text=True, timeout=120,
            )
            (rows / "run.log").write_text(result.stdout + result.stderr)
            if label == "normal-capture":
                assert result.returncode == 0, result.stdout + result.stderr
                assert "CHARACTERIZATION host=" not in result.stdout + result.stderr
            else:
                assert result.returncode != 0, f"{fault}: suite unexpectedly passed"
            recorded = {}
            for case, (_, needle) in selected.items():
                entries = [json.loads(line) for line in (rows / f"{case}.jsonl").read_text().splitlines()]
                assert len(entries) == 1, (fault, case, entries)
                row = entries[0]
                recorded[case] = row
                if fault == "no-entry":
                    assert row["result"] == "ERROR", (case, row)
                    expected_note = ("workload exited before the ready marker"
                                     if case == "CN-L-04" else "never printed DET_ENTERED")
                    assert expected_note in row["note"], (case, row)
                elif needle is None:
                    assert row["result"] == "PASS", (case, row)
                    assert re.match(
                        r"^CN-I-11 CHARACTERIZATION host=(input-injected|input-refused) "
                        r"contained=(input-injected|input-refused);",
                        row["note"],
                    ), row
                    assert "not proof of terminal isolation" in row["note"], row
                else:
                    expected = "ERROR" if case == "CN-T-01" else "FAIL"
                    assert row["result"] == expected, (case, row)
                    assert needle in row["note"], (case, row)
                print(f"{label}: {case} {row['result']} (expected)")
            emission = subprocess.run(
                [str(args.emitter.resolve())],
                env={**env, "DET_CARGO_STATUS": str(result.returncode)},
                capture_output=True, text=True, timeout=30,
            )
            (rows / "emit.log").write_text(emission.stdout + emission.stderr)
            summary = json.loads((rows / "verdict.json").read_text())
            # Each selection is a subset; missing manifest cases must keep the reducer RED.
            assert emission.returncode == 1 and summary["verdict"] == "RED", summary
            assert summary["integrity"]["cargo_status"] == result.returncode, summary
            emitted = {row["id"]: row for row in summary["results"]}
            assert emitted == recorded, (emitted, recorded)
            print(f"{label}: final verdict rows preserve all notes (diagnostic subset is RED)")
    print("Phase 3 harness faults verified; this is not native containment acceptance.")


if __name__ == "__main__":
    main()
