import copy
import unittest

from receipt import covered, passed_tests, verify


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.sources = {"crates/box/src/main.rs": "current"}
        self.tests = ["native_denial"]
        self.receipt = {
            "sources": self.sources,
            "passed_tests": self.tests,
            "signature_verified": True,
            "macos": "27.0",
            "binary_sha256": "a" * 64,
        }

    def test_complete_current_receipt_passes(self):
        verify(self.receipt, self.sources, self.tests)

    def test_malformed_macos_version_has_a_clear_error(self):
        for version in ("", None, 27, "macOS 27", "27.beta"):
            with self.subTest(version=version):
                receipt = {**self.receipt, "macos": version}
                with self.assertRaisesRegex(ValueError, "no usable macOS version"):
                    verify(receipt, self.sources, self.tests)

    def test_log_must_cover_every_test_target(self):
        first = "test bridge ... ok\n"
        second = "test enforcement ... ok\n"
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        complete = first + summary + second + summary
        expected = ["bridge", "enforcement"]
        self.assertEqual(passed_tests(complete, expected), expected)
        for log in (
            first + summary,
            complete.replace("0 filtered out", "1 filtered out"),
            complete + "test result: FAILED\n",
            complete + second,
        ):
            with self.subTest(log=log), self.assertRaises(ValueError):
                passed_tests(log, expected)

    def test_stale_missing_and_incomplete_evidence_fail(self):
        for field, value in (
            ("sources", {}),
            ("passed_tests", []),
            ("signature_verified", False),
            ("macos", "26.0"),
            ("binary_sha256", ""),
        ):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt[field] = value
                with self.assertRaises(ValueError):
                    verify(receipt, self.sources, self.tests)

    def test_deleted_and_added_sources_invalidate_receipt(self):
        for sources in ({}, {**self.sources, "crates/box/build.rs": "new"}):
            with self.assertRaises(ValueError):
                verify(self.receipt, sources, self.tests)

    def test_production_dependencies_and_native_test_inputs_are_covered(self):
        packages = ["crates/box", "crates/policy", "crates/shell",
                    "crates/shell/strands-shell-macros", "crates/new-dependency"]
        for name in (
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
            "crates/box/Cargo.toml", "crates/box/build.rs", "crates/box/src/run/mod.rs",
            "crates/policy/schema/events.dwschema",
            "crates/shell/strands-shell-macros/src/lib.rs",
            "crates/new-dependency/assets/runtime.json",
            "crates/box/tests/support/bounded_output.rs",
            "test-native-filesystem/tests/enforcement.rs",
            ".github/workflows/rust-test-lint.yml",
        ):
            with self.subTest(name=name):
                self.assertTrue(covered(name, packages))

    def test_unrelated_tests_and_workflows_do_not_require_a_signed_run(self):
        packages = ["crates/box", "crates/shell", "crates/shell/strands-shell-macros"]
        for name in (
            "crates/box/tests/four_inputs.rs", "crates/shell/tests/admission.rs",
            "crates/shell/strands-shell-macros/tests/expansion.rs",
            "crates/box/benches/startup.rs", "crates/box/examples/simple.rs",
            "crates/box-bench/src/main.rs", ".github/workflows/pr-title.yml",
            ".github/workflows/ci.yml", "docs/user/native-filesystem-policy.md",
            "test-native-filesystem/signed-receipt.json",
        ):
            with self.subTest(name=name):
                self.assertFalse(covered(name, packages))


if __name__ == "__main__":
    unittest.main()
