#!/usr/bin/env python3
"""Check verdict summary input failures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class VerdictSummaryTests(unittest.TestCase):
    def summarize(self, verdict):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verdict.json"
            path.write_text(json.dumps(verdict))
            return subprocess.run([sys.executable, str(Path(__file__).with_name("summarize-verdict.py")),
                                   str(path)], capture_output=True, text=True)

    def test_wrong_json_shapes_are_reported_without_failing(self):
        for verdict in [[], None, 12, {"counts": [1]}, {"integrity": "bad"},
                        {"verdict": []}, {"results": {}}, {"results": [12]}, {"integrity": {"problems": 12}}]:
            with self.subTest(verdict=verdict):
                result = self.summarize(verdict)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("verdict unreadable", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_valid_summary_keeps_failure_notes(self):
        result = self.summarize({"verdict": "RED", "counts": {"total": 1, "fail": 1},
                                 "results": [{"id": "CN-1", "result": "FAIL", "note": "the cause"}]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CN-1", result.stdout)
        self.assertIn("the cause", result.stdout)


if __name__ == "__main__":
    unittest.main()
