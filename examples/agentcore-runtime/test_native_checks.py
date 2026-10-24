"""Require native tool results for the exact protected and permitted paths."""
import json
import unittest

from native_checks import verify


class NativeChecksTests(unittest.TestCase):
    def transcript(self, private_path="../operator-private.txt"):
        rows = []
        operations = [
            ("Read", ".agent-tmp/native-input.txt", False, "NATIVE_READ_OK"),
            ("Edit", ".agent-tmp/native-note.txt", False, "created"),
            ("Read", ".agent-tmp/native-note.txt", False, "NATIVE_WRITE_OK"),
            ("Read", private_path, True, "File does not exist"),
            ("Edit", "native-readonly.txt", True, "EROFS"),
        ]
        for index, (tool, path, error, result) in enumerate(operations):
            identity = str(index)
            rows.append(json.dumps({"message": {"content": [
                {"type": "tool_use", "id": identity, "name": tool, "input": {"file_path": path}},
                {"type": "tool_result", "tool_use_id": identity, "is_error": error, "content": result},
            ]}}))
        return "\n".join(rows)

    def test_all_five_checks_require_matching_results(self):
        self.assertTrue(all(verify({"directory": "/var/tmp/test"}, self.transcript()).values()))

    def test_same_basename_at_wrong_path_is_not_a_refusal_proof(self):
        checks = verify({"directory": "/var/tmp/test"}, self.transcript("operator-private.txt"))
        self.assertFalse(checks["native_private_refused"])
        self.assertTrue(checks["native_read"])

    def test_missing_results_fail(self):
        self.assertFalse(any(verify({"directory": "/var/tmp/test"}, "{}").values()))


if __name__ == "__main__":
    unittest.main()
