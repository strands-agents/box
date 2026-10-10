#!/usr/bin/env python3
"""Check failed host facts in the workload verdict."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class WorkloadVerdictTests(unittest.TestCase):
    def reduce(self, oracle):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "oracle").mkdir()
            (root / "agent-a.json").write_text(json.dumps({"run_status": "VALID"}))
            (root / "oracle/verdict.json").write_text(json.dumps(oracle))
            subprocess.run(["bash", str(Path(__file__).with_name("workload-agent-b.sh")),
                            str(root)], check=True, capture_output=True)
            return json.loads((root / "verdict.json").read_text())

    def test_passing_check_still_passes(self):
        row = self.reduce({"checks": [{"id": "binary", "ok": True, "evidence": "present"}],
                           "failed": []})
        self.assertEqual(row["verdict"], "PASS")
        self.assertEqual(row["residuals"], [])

    def test_explicit_failed_ids_are_preserved_and_not_duplicated(self):
        row = self.reduce({"checks": [{"id": "binary", "ok": False, "evidence": "absent"}],
                           "failed": ["external-fact", "binary"]})
        self.assertEqual(row["verdict"], "FAIL")
        self.assertEqual(row["residuals"], ["external-fact", "binary"])

    def test_failed_check_is_not_a_pass_without_the_failed_list(self):
        for failed in (None, []):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "oracle").mkdir()
                (root / "agent-a.json").write_text(json.dumps({"run_status": "VALID"}))
                oracle = {"checks": [{"id": "binary", "ok": False, "evidence": "binary absent"}]}
                if failed is not None:
                    oracle["failed"] = failed
                (root / "oracle/verdict.json").write_text(json.dumps(oracle))
                subprocess.run(["bash", str(Path(__file__).with_name("workload-agent-b.sh")),
                                str(root)], check=True, capture_output=True)
                row = json.loads((root / "verdict.json").read_text())
                self.assertEqual(row["verdict"], "FAIL")
                self.assertEqual(row["residuals"], ["binary"])
                self.assertIn("binary absent", row["note"])


if __name__ == "__main__":
    unittest.main()
