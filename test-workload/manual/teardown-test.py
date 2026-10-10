#!/usr/bin/env python3
"""Check teardown control flow with a test-owned AWS command."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class TeardownTests(unittest.TestCase):
    def run_driver(self, mode, instances="", refused=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls.jsonl"
            command = root / "aws"
            command.write_text("#!" + sys.executable + "\n" + r'''import json, os, sys
with open(os.environ["MOCK_CALLS"], "a") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")
operation = sys.argv[2]
if operation == "describe-instances" and "--instance-ids" not in sys.argv:
    print(os.environ["MOCK_INSTANCES"], end="")
elif operation == "describe-hosts":
    print("h-test")
elif operation == "release-hosts":
    print(os.environ["MOCK_REFUSED"], end="")
''')
            command.chmod(0o755)
            env = {**os.environ, "PATH": str(root) + ":" + os.environ["PATH"],
                   "MOCK_CALLS": str(calls), "MOCK_INSTANCES": instances,
                   "MOCK_REFUSED": refused, "AWS_CREDENTIAL_REFRESH": "", "PROJECT_TAG": "box-test"}
            result = subprocess.run(["bash", str(Path(__file__).with_name("teardown.sh")), mode],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_full_teardown_releases_a_host_without_an_instance(self):
        output, calls = self.run_driver("--full")
        release = next((call for call in calls if call[1] == "release-hosts"), None)
        self.assertIsNotNone(release, calls)
        self.assertEqual(release[release.index("--host-ids") + 1], "h-test")
        self.assertIn("Releasing Dedicated Hosts", output)

    def test_full_teardown_terminates_the_instance_before_host_release(self):
        _, calls = self.run_driver("--full", "i-test\tmac-m4.metal\trunning\n")
        operations = [call[1] for call in calls]
        self.assertLess(operations.index("terminate-instances"), operations.index("release-hosts"))
        terminate = next(call for call in calls if call[1] == "terminate-instances")
        self.assertEqual(terminate[terminate.index("--instance-ids") + 1], "i-test")

    def test_stop_keeps_the_host_and_stops_only_instances(self):
        _, calls = self.run_driver("stop", "i-test\tmac-m4.metal\trunning\n")
        self.assertTrue(any(call[1] == "stop-instances" for call in calls))
        self.assertFalse(any(call[1] in ("describe-hosts", "release-hosts") for call in calls))

    def test_host_release_refusal_still_names_the_billing_risk(self):
        output, calls = self.run_driver("--full", refused="h-test OperationNotPermitted minimum 24 hours")
        self.assertTrue(any(call[1] == "release-hosts" for call in calls))
        self.assertIn("keeps billing", output)
        self.assertIn("minimum 24 hours", output)


if __name__ == "__main__":
    unittest.main()
