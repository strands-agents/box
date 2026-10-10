#!/usr/bin/env python3
"""Exercise production collection and aggregation with local case fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


SOURCE = Path(os.environ.get("WORKLOAD_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
SCRIPT = SOURCE / "test-workload/common/workload-bootstrap.sh"


class AggregateTests(unittest.TestCase):
    def aggregate(self, contents, collect=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            (root / "runs").mkdir()
            env = {**os.environ, "SUITE_DIR": str(suite), "WL_ROOT": str(root / "runs"),
                   "HARNESS_ROOT": str(root / "cases"), "CASES": "workload-python",
                   "AGENTS": "claude", "PLATFORM": "linux", "DEADLINE_S": "5000",
                   "SUITE_START": str(int(time.time())), "EFFECTIVE_COMMIT": "fixture",
                   "RUN_ID": "fixture", "ROWS": str(suite / "rows.jsonl")}
            source = SCRIPT.read_text()
            end = source.index('DEST="s3://$LEDGER_BUCKET/')
            if collect:
                case = root / "cases/workload-python"
                case.mkdir(parents=True)
                for name in ("oracle.sh", "agent-a.sh"):
                    (case / name).write_text("exit 0\n")
                fixture = root / "cell-verdict.json"
                fixture.write_text(contents)
                (case / "agent-b.sh").write_text('cp "$TEST_VERDICT" "$1/verdict.json"\n')
                env["TEST_VERDICT"] = str(fixture)
                start = source.index('ROWS="$SUITE_DIR/rows.jsonl"')
                helpers = '''
log() { :; }
wl_dimension_agents_known() { return 0; }
wl_dimension_applies() { return 0; }
wl_agent_known() { return 0; }
wl_agent_available() { return 0; }
'''
            else:
                (suite / "rows.jsonl").write_text(contents)
                start = source.index('AGG="$SUITE_DIR/verdict.json"')
                helpers = ""
            result = subprocess.run(["/bin/bash", "-c", helpers + source[start:end]],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((suite / "verdict.json").exists(), result.stderr)
            verdict = json.loads((suite / "verdict.json").read_text())
            if collect:
                self.assertEqual((root / "runs/workload-python-claude/verdict.json").read_text(),
                                 contents, "retain the original invalid cell evidence")
            return verdict

    def test_unknown_cell_verdict_is_an_error(self):
        for status in ("INVALID", "pass", None):
            with self.subTest(status=status):
                verdict = self.aggregate(json.dumps({"verdict": status}))
                self.assertEqual(verdict["verdict"], "ERROR", verdict)
                self.assertEqual(verdict["counts"], {"ERROR": 1})
                self.assertIn("unknown verdict", verdict["cases"][0]["note"])

    def test_malformed_cell_has_an_error_row_and_diagnostic(self):
        for raw, diagnostic in (("[]", "object"), ("null", "object"), ("{", "Expecting"),
                                ("[" * 1200 + "]" * 1200, "no valid verdict.json")):
            with self.subTest(raw=raw):
                verdict = self.aggregate(raw)
                self.assertEqual(verdict["verdict"], "ERROR", verdict)
                self.assertEqual(verdict["total"], 1)
                self.assertIn(diagnostic, verdict["cases"][0]["note"])

    def test_known_cell_verdicts_keep_their_existing_semantics(self):
        for status, expected in (("PASS", "PASS"), ("FAIL", "FAIL"),
                                 ("ERROR", "ERROR"), ("SKIP", "PASS")):
            with self.subTest(status=status):
                row = {"mode": "workload", "platform": "linux", "dimension": "workload-python",
                       "agent": "claude", "verdict": status, "note": "declared fixture",
                       "residuals": ["fixture"]}
                verdict = self.aggregate(json.dumps(row))
                self.assertEqual(verdict["verdict"], expected)
                self.assertEqual(verdict["counts"], {status: 1})
                self.assertEqual(verdict["cases"][0]["note"], "declared fixture")

    def test_invalid_aggregate_rows_cannot_disappear_beside_a_pass(self):
        for raw in ('{"verdict":"INVALID"}', "[]", "not json"):
            with self.subTest(raw=raw):
                verdict = self.aggregate('{"verdict":"PASS"}\n' + raw + "\n", collect=False)
                self.assertEqual(verdict["verdict"], "ERROR", verdict)
                self.assertEqual(verdict["total"], 2)
                self.assertEqual(verdict["counts"], {"PASS": 1, "ERROR": 1})
                self.assertIn("invalid aggregate row 2", verdict["cases"][1]["note"])


if __name__ == "__main__":
    unittest.main()
