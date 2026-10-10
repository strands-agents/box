#!/usr/bin/env python3
"""Check malformed diagnostic rows."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("diagnostics", Path(__file__).with_name("mac_diagnostics.py"))
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticInputTests(unittest.TestCase):
    def capture(self, verdict, directory):
        root = Path(directory)
        results = root / "results"
        results.mkdir()
        (results / "verdict.json").write_text(json.dumps(verdict))
        return diagnostics.Capture(str(results), str(root / "out"), None)

    def test_a_bad_note_keeps_the_next_rows_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = self.capture({"results": [{"id": "bad", "result": "FAIL", "note": 17},
                                                {"id": "good", "result": "FAIL",
                                                 "note": "bash: line 1: 123 Killed: 9 zsh"}]}, directory)
            cases = capture.read_cases()
            self.assertEqual([row["id"] for row in cases["failed_cases"]], ["good"])
            self.assertEqual(cases["killed"][0]["pid"], 123)
            self.assertEqual(len(capture.errors), 1)
            self.assertIn("note", capture.errors[0])

    def test_wrong_result_container_is_a_recorded_gap(self):
        for rows in (17, "bad", {"id": "case"}):
            with self.subTest(rows=rows), tempfile.TemporaryDirectory() as directory:
                capture = self.capture({"results": rows}, directory)
                cases = capture.read_cases()
                self.assertTrue(cases["malformed"])
                self.assertEqual(cases["killed"], [])
                self.assertEqual(len(capture.errors), 1)


if __name__ == "__main__":
    unittest.main()
