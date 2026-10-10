#!/usr/bin/env python3
"""Check diagnostic process group cleanup."""
import importlib.util
import os
import signal
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("diagnostics", Path(__file__).with_name("mac_diagnostics.py"))
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticProcessTests(unittest.TestCase):
    def test_an_exited_parent_does_not_leave_its_child_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = diagnostics.Capture(directory, str(root / "out"), None)
            pid_file = root / "child.pid"
            code = ('import subprocess,pathlib; child=subprocess.Popen(["/bin/sleep", "30"]); '
                    'pathlib.Path(' + repr(str(pid_file)) + ').write_text(str(child.pid))')
            try:
                result = capture.run("parent.log", "parent", [sys.executable, "-c", code])
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            self.assertFalse(result)
            self.assertTrue(any("live descendants" in error for error in capture.errors))
            self.assertFalse(any("still alive after SIGKILL" in error for error in capture.errors))


if __name__ == "__main__":
    unittest.main()
