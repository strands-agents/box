"""Check demo validation and recovery without deploying a Runtime."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DEMO = Path(__file__).resolve().parent / "app" / "demo"
sys.path.insert(0, str(DEMO))
from claude_runtime import policy_rows, source_is_repaired
import manual_setup


class DemoHelpersTests(unittest.TestCase):
    def test_repair_accepts_equivalent_formatting(self):
        self.assertTrue(source_is_repaired("def add(a,b): return a+b\n"))
        self.assertFalse(source_is_repaired("def add(a,b): return a-b\n"))
        self.assertFalse(source_is_repaired("def add("))

    def test_repair_does_not_execute_workload_source(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            source = (
                f"open({str(marker)!r}, 'w').write('executed')\n"
                "def add(a, b): return a + b\n"
            )
            self.assertFalse(source_is_repaired(source))
            self.assertFalse(marker.exists())

    def test_policy_rows_keep_verdict_fields_and_report_bad_records(self):
        with tempfile.TemporaryDirectory() as directory:
            records = Path(directory) / "private" / "telemetry" / "records.jsonl"
            records.parent.mkdir(parents=True)
            attributes = [
                {"key": key, "value": {"stringValue": value}}
                for key, value in {
                    "strands.box.policy.verdict": "deny",
                    "strands.box.policy.action": "fs:read",
                    "file.path": "/operator-private.txt",
                    "server.address": "example.com",
                }.items()
            ]
            batch = {"resourceLogs": [{"scopeLogs": [{"logRecords": [
                {"timeUnixNano": "1", "attributes": attributes}
            ]}]}]}
            records.write_text(json.dumps(batch) + "\ninvalid\npartial")
            rows, malformed = policy_rows(directory)
            self.assertEqual(malformed, 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "deny")
            self.assertEqual(rows[0]["action"], "fs:read")
            self.assertEqual(rows[0]["path"], "/operator-private.txt")
            self.assertEqual(rows[0]["host"], "example.com")

    def test_manual_setup_reports_partial_install_before_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(manual_setup, "DIRECTORY", Path(directory)):
                with patch.object(manual_setup.os, "getuid", return_value=1000):
                    with patch.object(manual_setup.ClaudeRuntime, "install") as install:
                        with self.assertRaisesRegex(RuntimeError, "without an install marker"):
                            manual_setup.prepare(Path("/unused/box"))
                        install.assert_not_called()

    def test_fixture_continues_after_non_object_json(self):
        with tempfile.TemporaryDirectory() as directory:
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            result = subprocess.run(
                [sys.executable, str(DEMO / "mcp_fixture.py"), directory],
                input='5\n"x"\n[]\nnull\n' + json.dumps(request) + "\n",
                text=True, capture_output=True, timeout=10, check=True,
            )
            reply = json.loads(result.stdout)
            self.assertEqual(reply["id"], 1)
            self.assertEqual(len(reply["result"]["tools"]), 3)


if __name__ == "__main__":
    unittest.main()
