#!/usr/bin/env python3
"""Exercise the shell workload checks with local test output fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(os.environ.get("WORKLOAD_SOURCE_ROOT", Path(__file__).resolve().parents[2]))


class TestOutput(unittest.TestCase):
    def assert_output(self, language, output, expected):
        ids = {"python": "py-pytest-output", "node": "node-test-output", "rust": "rust-test-passed"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            (run / "oracle").mkdir(parents=True)
            project = root / "project"
            project.mkdir()
            filename = "pytest-out.txt" if language == "python" else "test-out.txt"
            (project / filename).write_text(output)
            result = subprocess.run(
                ["bash", "-c", '''
source "$1/test-workload/common/workload-oracle-lib.sh"
source "$1/test-workload/workload-$2/case.sh"
wl_assert_journal() { :; }
wl_assert_commits() { :; }
wl_note_codex_arg0() { :; }
wl_checks "$3"
''', "test-output", str(SOURCE), language, str(project)],
                env={**os.environ, "WL_RUN_DIR": str(run), "WL_PLATFORM": "macos"},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (run / "oracle/checks.jsonl").read_text().splitlines()]
            observed = next(row for row in rows if row["id"] == ids[language])
            self.assertEqual(observed["ok"], expected, observed)

    def test_failed_summaries_do_not_pass(self):
        cases = [
            ("python", "=== 1 failed, 1 passed in 0.1s ===\n"),
            ("python", "FAILED (failures=1)\n"),
            ("node", "not ok 1 - broken test\n# pass 0\n# fail 1\n"),
            ("node", "1 passing (2ms)\n1 failing\n"),
            ("node", "ok 1 - first\nnot ok 2 - second\n# pass 1\n# fail 1\n"),
            ("rust", "test result: ok. 1 passed; 0 failed;\ntest result: FAILED. 0 passed; 10 failed;\n"),
        ]
        for language, output in cases:
            with self.subTest(language=language, output=output):
                self.assert_output(language, output, False)

    def test_successful_summaries_still_pass(self):
        cases = [
            ("python", "=== 1 passed in 0.1s ===\n"),
            ("node", "ok 1 - first\n# pass 1\n# fail 0\n"),
            ("node", "1 passing (2ms)\n"),
            ("node", "2 passing (2ms)\n"),
            ("rust", "test result: ok. 1 passed; 0 failed; 0 ignored;\n"),
        ]
        for language, output in cases:
            with self.subTest(language=language):
                self.assert_output(language, output, True)


if __name__ == "__main__":
    unittest.main()
