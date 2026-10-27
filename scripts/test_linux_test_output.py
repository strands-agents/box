import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "linux_test_output", Path(__file__).with_name("check-linux-test-output.py")
)
REPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTER)
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"


class LinuxTestOutputTests(unittest.TestCase):
    def test_pass_without_skip_is_accepted(self):
        accepted, report = REPORTER.check_output(PASSED)
        self.assertTrue(accepted)
        self.assertIn("No test emitted", report)

    def test_prerequisite_skip_cannot_hide_in_a_passing_result(self):
        for prefix in ["", "test a_mount_test ... "]:
            with self.subTest(prefix=prefix):
                accepted, report = REPORTER.check_output(
                    prefix + "skipping: namespace permission denied\n" + PASSED
                )
                self.assertFalse(accepted)
                self.assertIn("namespace permission denied", report)

    def test_one_missing_daemon_is_reported_as_untested(self):
        accepted, report = REPORTER.check_output(
            "skipping: " + REPORTER.MISSING_DAEMON + "\n" + PASSED
        )
        self.assertTrue(accepted)
        self.assertIn("remains untested", report)

    def test_known_alias_limit_reports_partial_coverage(self):
        accepted, report = REPORTER.check_output(
            "skipping: " + REPORTER.ALIAS_READ + "\n" + PASSED
        )
        self.assertTrue(accepted)
        self.assertIn("retains its write assertions", report)
        self.assertIn("read assertion remains omitted", report)

    def test_additional_daemon_skips_are_not_silently_allowed(self):
        accepted, _ = REPORTER.check_output(
            ("skipping: " + REPORTER.MISSING_DAEMON + "\n") * 2 + PASSED
        )
        self.assertFalse(accepted)

    def test_missing_result_is_not_execution_evidence(self):
        accepted, _ = REPORTER.check_output("Finished compiling")
        self.assertFalse(accepted)

    def test_a_failed_target_remains_a_failure(self):
        accepted, _ = REPORTER.check_output(PASSED + "\ntest result: FAILED.")
        self.assertFalse(accepted)

    def test_color_does_not_hide_a_skip(self):
        accepted, _ = REPORTER.check_output(
            "\x1b[31mskipping: namespace permission denied\x1b[0m\n" + PASSED
        )
        self.assertFalse(accepted)


if __name__ == "__main__":
    unittest.main()
