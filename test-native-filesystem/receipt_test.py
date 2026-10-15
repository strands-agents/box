import copy
import unittest

from receipt import verify


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


if __name__ == "__main__":
    unittest.main()
