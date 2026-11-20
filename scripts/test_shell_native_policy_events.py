#!/usr/bin/env python3
"""Fault controls for the stored-event comparison assertions."""
import copy
from pathlib import Path
import unittest
import tempfile

import shell_native_policy_events as suite


class ComparisonFaults(unittest.TestCase):
    def setUp(self):
        self.expected = suite.load_expectations()["directory_rename/permit/shell"]

    def rejects(self, actual):
        with self.assertRaises(AssertionError):
            suite.compare(actual, self.expected, "injected fault")

    def test_missing_event(self):
        self.rejects(self.expected[:-1])

    def test_duplicate_event(self):
        self.rejects(self.expected + [self.expected[-1]])

    def test_reordered_events(self):
        actual = copy.deepcopy(self.expected)
        actual[0], actual[1] = actual[1], actual[0]
        self.rejects(actual)

    def test_changed_operation(self):
        actual = copy.deepcopy(self.expected)
        for key in ("context", "logged"):
            actual[0][key]["input"][1]["operation"][1][1] = "enumerate"
        self.rejects(actual)

    def test_changed_path_spelling(self):
        actual = copy.deepcopy(self.expected)
        for key in ("context", "logged"):
            actual[0][key]["input"][1]["path"][1] = "/<ROOT>/workspace/destination"
        self.rejects(actual)

    def test_changed_type(self):
        actual = copy.deepcopy(self.expected)
        actual[0]["context"]["input"][1]["operation"] = ["s", "read_metadata"]
        self.rejects(actual)

    def test_changed_principal(self):
        actual = copy.deepcopy(self.expected)
        actual[0]["principal"] = 'Box::Agent::"other"'
        self.rejects(actual)

    def test_changed_result(self):
        actual = copy.deepcopy(self.expected)
        actual[-1]["context"]["output"][1]["result"][1][1] = "descriptor_issued"
        self.rejects(actual)

    def test_changed_resource(self):
        actual = copy.deepcopy(self.expected)
        actual[0]["resource"] = 'Box::Resource::"other"'
        self.rejects(actual)

    def test_roots_normalize_without_losing_absolute_spelling(self):
        root = Path("/var/tmp/example")
        self.assertEqual(suite.normalize("/var/tmp/example/workspace/source", root),
                         "/<ROOT>/workspace/source")
        self.assertEqual(suite.normalize("~/workspace/source", root), "~/workspace/source")
        self.assertEqual(suite.normalize("/var/tmp/example-suffix/workspace/source", root),
                         "/var/tmp/example-suffix/workspace/source")
        actual = suite.normalize(copy.deepcopy(self.expected), root)
        suite.compare(actual, self.expected, "unchanged home-relative path")

    def test_declared_divergence_still_fails_parity(self):
        native = suite.load_expectations()["directory_rename/permit/native"]
        with self.assertRaises(AssertionError):
            suite.compare(native, self.expected, "strict adapter parity")


class RequestCorrelation(unittest.TestCase):
    def setUp(self):
        self.events = suite.load_expectations()["directory_rename/permit/shell"]

    def rejects(self, events):
        with self.assertRaises(AssertionError):
            suite.correlate(events)

    def test_opaque_ids_preserve_pairing(self):
        events = copy.deepcopy(self.events)
        for event in events:
            event["logged"]["requestId"][1] = "opaque-" + event["logged"]["requestId"][1]
        self.assertEqual(suite.correlate(events), self.events)
        self.assertTrue(events[0]["logged"]["requestId"][1].startswith("opaque-"))

    def test_missing_id_is_rejected(self):
        self.events[0]["logged"].pop("requestId")
        self.rejects(self.events)

    def test_wrong_id_type_is_rejected(self):
        self.events[0]["logged"]["requestId"][0] = "l"
        self.rejects(self.events)

    def test_outcome_before_request_is_rejected(self):
        self.rejects(self.events[1:])

    def test_duplicate_request_is_rejected(self):
        self.rejects([self.events[0], self.events[0]])

    def test_duplicate_outcome_is_rejected(self):
        self.rejects(self.events + [self.events[-1]])

    def test_outcome_for_wrong_request_is_rejected(self):
        self.events[-1]["logged"]["requestId"] = self.events[0]["logged"]["requestId"]
        self.rejects(self.events)

    def test_outcome_identity_must_match(self):
        self.events[1]["context"]["input"][1]["path"][1] = "~/workspace/other"
        self.events[1]["logged"]["input"] = copy.deepcopy(self.events[1]["context"]["input"])
        self.rejects(self.events)

    def test_abandoned_request_remains_valid(self):
        self.assertEqual(suite.correlate(self.events[:1]), self.events[:1])

    def test_unclassified_difference_is_retained(self):
        native = suite.load_expectations()["read/permit/native"]
        changed = copy.deepcopy(native)
        changed[0]["resource"] = 'Box::Resource::"other"'
        differences = suite.differences(("read/permit", "read"), {"events": native}, {"events": changed})
        self.assertEqual(differences[0]["classification"], "needs_triage")


class HistoryPreservation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "original.redb"
        self.source.write_bytes(b"original durable history")
        self.snapshot = self.root / "history.snapshot.redb"
        self.working = self.root / "history.redb"

    def test_reader_changes_leave_original_snapshot_unchanged(self):
        expected = suite.copy_history(self.source, self.snapshot, self.working)
        self.working.write_bytes(b"reader updated database metadata")
        self.assertEqual(suite.digest(self.snapshot), expected)
        self.assertEqual(suite.digest(self.source), expected)
        self.assertNotEqual(suite.digest(self.working), expected)

    def test_reader_cannot_share_the_snapshot_path(self):
        with self.assertRaises(AssertionError):
            suite.copy_history(self.source, self.snapshot, self.snapshot)

    def test_reader_cannot_share_the_original_path(self):
        with self.assertRaises(AssertionError):
            suite.copy_history(self.source, self.snapshot, self.source)


class BuildArtifactSelection(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.artifacts = []
        self.expected = []
        for name in ("strands-box", "strands-box-sock-alias", "strands-box-contain-trampoline"):
            fresh = self.root / "aarch64-unknown-linux-gnu" / "debug" / name
            fresh.parent.mkdir(parents=True, exist_ok=True)
            fresh.write_text("fresh")
            stale = self.root / "debug" / name
            stale.parent.mkdir(exist_ok=True)
            stale.write_text("stale")
            self.expected.append(fresh)
            self.artifacts.append({"reason": "compiler-artifact", "target": {"name": name, "kind": ["bin"]},
                                   "executable": str(fresh)})

    def test_emitted_target_paths_win_over_stale_default_paths(self):
        selected = suite.select_binaries(self.artifacts)
        self.assertEqual(selected, self.expected)
        self.assertEqual([p.read_text() for p in selected], ["fresh"] * 3)

    def test_missing_emitted_helper_does_not_fall_back(self):
        with self.assertRaises(AssertionError):
            suite.select_binaries(self.artifacts[:-1])

    def test_duplicate_executable_is_rejected(self):
        with self.assertRaises(AssertionError):
            suite.select_binaries(self.artifacts + [self.artifacts[0]])

    def test_helpers_must_be_beside_box(self):
        self.artifacts[-1]["executable"] = str(self.root / "debug" / "strands-box-contain-trampoline")
        with self.assertRaises(AssertionError):
            suite.select_binaries(self.artifacts)


if __name__ == "__main__":
    unittest.main()
