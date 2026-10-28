"""Reject false containment evidence and keep fixture cleanup scoped."""

import contextlib
import io
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import target_validation as target


class TargetEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="target-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def shim(self, source):
        binary = self.root / "box"
        binary.write_text(f"#!{sys.executable}\n" + source)
        binary.chmod(0o700)
        return target.Target(self.root, binary, binary)

    def test_non_launching_box_cannot_pass_any_case(self):
        runner = self.shim("raise SystemExit(0)\n")
        with contextlib.redirect_stdout(io.StringIO()):
            rows = target.run_cases(runner, True)
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(not row["pass"] for row in rows), rows)

    def test_uncontained_box_fails_the_file_effect_check(self):
        runner = self.shim(
            "import json, os, pathlib, sys\n"
            "text=pathlib.Path(sys.argv[3]).read_text()\n"
            "command=json.loads(next(x.split('=',1)[1] for x in text.splitlines() "
            "if x.startswith('command=')))\n"
            "os.execv(command[0], command)\n")
        row = runner.file_effects()
        self.assertFalse(row["pass"])
        self.assertEqual(row["checks"], {
            "completed": False, "allowed_write": True, "readonly_unchanged": True,
            "private_unchanged": True, "uncontained_control": True,
        })

    def test_timeout_with_a_successful_exit_and_marker_still_fails(self):
        runner = self.shim("raise SystemExit(0)\n")
        def late_exit(root):
            (root / "work/entered").write_text("yes")
            return {"exit_code": 0, "timed_out": True, "stdout": "WORKLOAD_ENTERED",
                    "stderr": "", "test_owned_cleanup": []}
        with patch.object(runner, "run", side_effect=late_exit):
            self.assertFalse(runner.startup()["pass"])

    def test_later_box_must_lose_the_earlier_file_grant(self):
        runner = self.shim(
            "import json, os, pathlib, sys\n"
            "text=pathlib.Path(sys.argv[3]).read_text()\n"
            "command=json.loads(next(x.split('=',1)[1] for x in text.splitlines() "
            "if x.startswith('command=')))\n"
            "command[-1]=command[-1].replace('/files/private', '/files/inaccessible')\n"
            "os.execv(command[0], command)\n")
        prior = self.root / "files/work"
        prior.mkdir(parents=True)
        (prior / "output").write_text("WRITE_ALLOWED")
        private = self.root / "files/private"
        private.write_text("PRIVATE_ORIGINAL\n")
        row = runner.subsequent()
        self.assertTrue(row["uncontained_control"])
        self.assertFalse(row["pass"])
        self.assertEqual(row["exit_code"], 73)

    def test_only_specific_native_setup_refusal_is_evidence(self):
        marker = self.root / "entered"
        row = {"exit_code": 1, "stdout": "", "stderr": target.REFUSALS[0],
               "timed_out": False, "workload_entered": False}
        self.assertTrue(target.refused(row, marker))
        for replacement in ({"exit_code": 0}, {"timed_out": True},
                            {"stdout": "WORKLOAD_ENTERED"}, {"workload_entered": True},
                            {"stderr": "usage error"}):
            with self.subTest(replacement=replacement):
                self.assertFalse(target.refused({**row, **replacement}, marker))
        marker.write_text("entered")
        self.assertFalse(target.refused(row, marker))

    def test_cleanup_timeout_retains_failure_logs(self):
        runner = self.shim("raise SystemExit(0)\n")
        root = runner.config("wedged", ["/usr/bin/bash", "-c", "exit 0"])
        (root / "stdout").write_text("partial output")
        (root / "stderr").write_text("diagnostic")
        child = Mock(returncode=None)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("box", 5)
        with patch.object(runner, "launch", return_value=child), \
             patch.object(target, "cleanup", return_value=[]):
            row = runner.run(root)
        self.assertTrue(row["timed_out"])
        self.assertTrue(row["kill_timed_out"])
        self.assertEqual(row["stdout"], "partial output")
        self.assertEqual(row["stderr"], "diagnostic")
        self.assertFalse(target.succeeded(row))
        child.kill.assert_called_once()

    def test_native_entry_cannot_hide_outside_the_log_tail(self):
        runner = self.shim("raise SystemExit(0)\n")
        for offset in (0, 65530):
            with self.subTest(offset=offset):
                (self.root / "stdout").write_text("x" * offset + "WORKLOAD_ENTERED" + "y" * 40000)
                (self.root / "stderr").write_text(target.REFUSALS[0])
                row = runner.result(self.root, Mock(returncode=1))
                self.assertNotIn("WORKLOAD_ENTERED", row["stdout"])
                self.assertEqual(len(row["stdout"]), 24000)
                self.assertTrue(row["workload_entered"])
                self.assertFalse(target.refused(row, self.root / "missing-marker"))

    def test_missing_heartbeat_is_not_stopped_write_evidence(self):
        with patch.object(target.time, "sleep"), patch.object(target, "living", return_value=[]):
            self.assertFalse(target.stopped(self.root)["heartbeat_stopped"])
            (self.root / "work").mkdir()
            (self.root / "work/heartbeat").write_text("3")
            self.assertTrue(target.stopped(self.root)["heartbeat_stopped"])

    def test_failed_case_does_not_omit_later_results(self):
        runner = self.shim("raise SystemExit(0)\n")
        with patch.object(runner, "startup", side_effect=OSError("setup failed")):
            with contextlib.redirect_stdout(io.StringIO()):
                rows = target.run_cases(runner, False)
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[0]["error"], "setup failed")
        self.assertEqual(rows[-1]["name"], "subsequent-box-isolation")
        self.assertFalse(rows[-1]["pass"])

    def test_changed_process_identity_is_not_signaled(self):
        with patch.object(target.os, "pidfd_open", return_value=10), \
             patch.object(target.os, "close"), \
             patch.object(target, "process", return_value={"start": "new"}), \
             patch.object(target.signal, "pidfd_send_signal") as send:
            target.signal_process({"pid": 123, "start": "old"}, signal.SIGKILL)
            send.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "Linux process handles")
    def test_cleanup_leaves_a_similar_unrelated_fixture_alive(self):
        owned_root = self.root / "owned"
        owned_root.mkdir()
        owned = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)", str(owned_root)])
        other = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)", str(owned_root) + "-other"])
        try:
            self.assertTrue(target.wait_until(lambda: bool(target.living(owned_root)), 2))
            rows = target.cleanup(owned_root)
            self.assertEqual([row["pid"] for row in rows], [owned.pid])
            owned.wait(timeout=2)
            self.assertIsNone(other.poll())
        finally:
            for child in (owned, other):
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
