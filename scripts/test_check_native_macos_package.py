"""Reject false passes in the installed native policy checker."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "native_package", Path(__file__).with_name("check-native-macos-package.py")
)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeStartupTests(unittest.TestCase):
    def test_startup_runs_outside_the_operator_home_and_profile_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            guide = package / "resources/editing-box-profile.md"
            guide.parent.mkdir(parents=True)
            guide.write_text("editing guide")
            calls = []
            evidence = root / ("long-evidence-name-" * 8)

            def run(argv, destination, cwd, environment, timeout=60):
                home = Path(environment["HOME"])
                self.assertTrue(cwd.is_dir())
                self.assertNotIn(evidence, home.parents, "long evidence path leaks into broker socket path")
                self.assertLess(len(str(home).encode()), 60)
                self.assertNotEqual(cwd, home)
                self.assertNotIn(cwd, home.parents, "workspace contains the operator home")
                self.assertNotIn(cwd, (home / ".strands/box/profiles").parents,
                                 "workspace contains the profile store")
                calls.append(argv[1:])
                if argv[1:3] == ["help", "agent"]:
                    return 0, str(guide) + "\n", ""
                if argv[1:3] == ["profile", "create"]:
                    created = home / ".strands/box/profiles/claude"
                    created.mkdir(parents=True)
                    (created / "profile.toml").write_text("profile")
                    (created / "policy.dw").write_text("open_connect")
                return 0, "PACKAGE_BROKER_OK\n" if argv[1] == "run" else "box test\n", ""

            with patch.object(native, "command", side_effect=run), \
                    patch.object(native, "prepare_installation"):
                native.startup(package, evidence)
            self.assertEqual(calls[-1], ["run", "helper-probe", "--no-banner"])
            self.assertEqual(len(calls), 4)


class PythonReadGrantTests(unittest.TestCase):
    def test_framework_and_virtual_environment_roots_do_not_overlap(self):
        python = {"prefix": "/opt/native-probe/venv", "base_prefix": "/Library/Frameworks/Python.framework/Versions/3.12",
                  "stdlib": "/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12"}
        executable = Path("/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12")
        self.assertEqual(native.python_read_roots(python, executable),
                         ["/Library/Frameworks/Python.framework/Versions/3.12", "/opt/native-probe/venv"])

    def test_generated_mcp_profile_omits_files_already_covered_by_a_read_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python_root = root / "python"
            case = {"name": "mcp_deny", "kind": "mcp", "global": True,
                    "override": None, "allow": False}
            for inside in (False, True):
                with self.subTest(server_inside_python_root=inside):
                    server = (python_root if inside else root / "fixtures") / "native-server"
                    fixtures = {"native": root / "native-write", "server": server,
                                "python": str(python_root / "bin/python3"), "python_read": [str(python_root)]}
                    state = native.make_profile(case, root / str(inside), fixtures)
                    profile = native.parse_toml((state["profile"] / "profile.toml").read_text())
                    grants = profile["mcp"]["native"]["filesystem"]
                    self.assertEqual(grants["read_file"], [] if inside else [str(server)])
                    self.assertEqual(grants, state["grants"]["mcp"]["native"])
                    for path in grants["read_file"]:
                        self.assertFalse(Path(path).is_relative_to(python_root))

    def test_system_python_still_refuses_a_broad_read_grant(self):
        python = {"prefix": "/usr", "base_prefix": "/usr", "stdlib": "/usr/lib/python3.12"}
        with self.assertRaisesRegex(native.CheckFailure, "overly broad read grant"):
            native.python_read_roots(python, Path("/usr/bin/python3"))


class NativeRunCollectionTests(unittest.TestCase):
    def test_run_case_collects_the_current_cli_layout_after_installation_setup(self):
        # Current CLI output uses r/<id>, with a private Dogwood database.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            evidence = root / "evidence"
            fixture = root / "fixture"
            case = {"name": "agent_default_off", "kind": "agent", "global": None,
                    "override": None, "allow": True}
            calls = []

            def run(argv, destination, cwd, environment, timeout=60):
                home = Path(environment["HOME"])
                self.assertTrue((home / ".strands/box/installation.toml").is_file())
                self.assertTrue((home / ".strands/box/profiles/probe/profile.toml").is_file())
                calls.append(argv[1:])
                if argv[1] == "run":
                    (cwd / "agent-entered.txt").write_bytes(b"entered")
                    (cwd / "native-target.txt").write_bytes(b"native workload wrote\n")
                    run_dir = home / ".strands/box/r/b-current-run"
                    database = run_dir / "box/private/dogwood.redb"
                    database.parent.mkdir(parents=True)
                    database.write_bytes(b"record database snapshot")
                    (run_dir / "box.toml").write_text("[agent]\n")
                    (run_dir / "policy.dw").write_text("permit(principal, action, resource);\n")
                    (run_dir / "records.jsonl").write_text("{}\n")
                    return 0, "NATIVE_ALLOWED\n", ""
                if argv[1:3] == ["runs", "history"]:
                    self.assertEqual(argv[3:], ["b-current-run", "--action", "fs:write",
                                               "--resource", "native-target.txt", "--format", "json"])
                    return 0, "[]", ""
                return 0, "profile preview", ""

            with patch.object(native, "command", side_effect=run):
                result = native.run_case(package, case, {"native": root / "native-write"},
                                         fixture, evidence)
            self.assertTrue(result["passed"])
            self.assertEqual(len(calls), 3)
            self.assertEqual((evidence / "saved-run-0/dogwood.redb").read_bytes(),
                             b"record database snapshot")
            snapshots = json.loads((evidence / "history-snapshots.json").read_text())
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(snapshots[0]["sha256"], native.digest(evidence / "saved-run-0/dogwood.redb"))


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.home = Path("/private/var/tmp/native-unit/home")
        self.state = {"home": self.home, "target": self.home / "project/native-target.txt"}
        self.case = {"name": "agent_deny", "kind": "agent", "global": True,
                     "override": None, "allow": False}
        self.observed = self.observation(False)

    def observation(self, allowed):
        rule = native.RULE_ALLOW if allowed else native.RULE_DENY
        rules = [native.RULE_ALLOW, "project_write"] if allowed else [native.RULE_DENY]
        attrs = {
            "strands.box.policy.action": "fs:write",
            "strands.box.policy.resource": "~/project/native-target.txt",
            "strands.box.policy.principal": "agent:self",
            "strands.box.policy.verdict": "permit" if allowed else "deny",
            "strands.box.policy.rule": rule,
            "strands.box.policy.determining.ids": {
                "arrayValue": {"values": [{"stringValue": value} for value in rules]}
            },
        }
        raw = [{"format": kind, "attributes": copy.deepcopy(attrs),
                "trace_id": "trace", "span_id": "span", "time": "123"}
               for kind in ("resourceLogs", "resourceSpans")]
        return {"exit": 0, "entered": b"entered", "stderr": "",
                "stdout": "NATIVE_ALLOWED\n" if allowed else "NATIVE_DENIED errno=1\n",
                "target_bytes": b"native workload wrote\n" if allowed else native.ORIGINAL,
                "raw": raw, "public": [{"action": "fs:write", "resource": "~/project/native-target.txt",
                                          "rule": rule, "result": "permit" if allowed else "deny",
                                          "enforced": None}]}

    def verify(self):
        native.verify_case(self.case, self.state, self.observed)

    def test_real_denial_evidence_passes(self):
        self.verify()

    def test_real_allow_evidence_passes(self):
        self.case["allow"] = True
        self.observed = self.observation(True)
        self.verify()

    def test_zero_exit_without_workload_entry_fails(self):
        self.observed["entered"] = None
        with self.assertRaisesRegex(native.CheckFailure, "entered"):
            self.verify()

    def test_denial_with_changed_file_fails(self):
        self.observed["target_bytes"] = b"changed\n"
        with self.assertRaisesRegex(native.CheckFailure, "bytes"):
            self.verify()

    def test_allow_without_actual_write_fails(self):
        self.case["allow"] = True
        self.observed = self.observation(True)
        self.observed["target_bytes"] = native.ORIGINAL
        with self.assertRaisesRegex(native.CheckFailure, "bytes"):
            self.verify()

    def test_missing_native_event_fails(self):
        self.observed["raw"] = []
        with self.assertRaisesRegex(native.CheckFailure, "log and span"):
            self.verify()

    def test_wrong_path_with_same_basename_fails(self):
        for row in self.observed["raw"]:
            row["attributes"]["strands.box.policy.resource"] = "~/other/native-target.txt"
        with self.assertRaisesRegex(native.CheckFailure, "exact target"):
            self.verify()

    def test_wrong_public_action_fails(self):
        self.observed["public"][0]["action"] = "shell:exec"
        with self.assertRaisesRegex(native.CheckFailure, "public decision"):
            self.verify()

    def test_false_enforcement_flag_fails(self):
        self.observed["public"][0]["enforced"] = False
        with self.assertRaisesRegex(native.CheckFailure, "enforced"):
            self.verify()

    def test_wrong_rule_or_verdict_fails(self):
        for key, value in [("strands.box.policy.rule", "other"),
                           ("strands.box.policy.verdict", "permit")]:
            with self.subTest(key=key):
                self.observed = self.observation(False)
                for row in self.observed["raw"]:
                    row["attributes"][key] = value
                with self.assertRaises(native.CheckFailure):
                    self.verify()

    def test_mismatched_log_and_span_fails(self):
        self.observed["raw"][1]["span_id"] = "other"
        with self.assertRaisesRegex(native.CheckFailure, "identity"):
            self.verify()

    def test_duplicate_native_decisions_fail(self):
        self.observed["raw"] += copy.deepcopy(self.observed["raw"])
        with self.assertRaisesRegex(native.CheckFailure, "log and span"):
            self.verify()

    def test_optout_requires_write_and_zero_native_events(self):
        self.case["override"] = False
        self.observed = self.observation(True)
        with self.assertRaisesRegex(native.CheckFailure, "opt-out"):
            self.verify()
        self.observed["raw"] = []
        self.observed["public"] = []
        self.verify()

    def test_missing_authorization_is_failure_for_native_candidate(self):
        self.observed.update(exit=1, entered=None, stderr="Endpoint Security code 4")
        with self.assertRaisesRegex(native.CheckFailure, "exit"):
            self.verify()

    def mcp(self):
        self.case["kind"] = "mcp"
        listing = {"tools": [{"name": "write"}]}
        self.replies = [{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}},
                        {"jsonrpc": "2.0", "id": 2, "result": listing},
                        {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "NATIVE_DENIED"}], "isError": False}},
                        {"jsonrpc": "2.0", "id": 4, "result": copy.deepcopy(listing)}]
        self.observed["stdout"] = "\n".join(json.dumps(row) for row in self.replies)

    def test_mcp_denial_keeps_protocol_usable(self):
        self.mcp()
        self.verify()

    def test_mcp_missing_post_denial_reply_fails(self):
        self.mcp()
        self.observed["stdout"] = "\n".join(json.dumps(row) for row in self.replies[:-1])
        with self.assertRaisesRegex(native.CheckFailure, "MCP response sequence"):
            self.verify()

    def test_mcp_protocol_error_is_not_policy_denial(self):
        self.mcp()
        self.replies[2]["result"]["isError"] = True
        self.observed["stdout"] = "\n".join(json.dumps(row) for row in self.replies)
        with self.assertRaisesRegex(native.CheckFailure, "MCP operation reply"):
            self.verify()

    def test_prerequisite_error_requires_exact_diagnostic_and_no_entry(self):
        self.observed.update(exit=1, entered=None, stdout="", stderr="Endpoint Security code 3", raw=[], public=[])
        native.verify_prerequisite(self.state, self.observed, "unsigned")
        for update in ({"entered": b"entered"}, {"stderr": "Endpoint Security code 4"},
                       {"target_bytes": b"changed"}, {"exit": 0}):
            with self.subTest(update=update):
                observed = dict(self.observed, **update)
                with self.assertRaises(native.CheckFailure):
                    native.verify_prerequisite(self.state, observed, "unsigned")

    def test_compiled_process_selection_must_match(self):
        case = dict(self.case, kind="tool", override=False)
        config = {"experimental-features": {"native-filesystem-policy": True},
                  "agent": {"native-filesystem-policy": False},
                  "tool": {"native": {"native-filesystem-policy": False}}}
        native.verify_compiled(case, config)
        config["tool"]["native"]["native-filesystem-policy"] = True
        with self.assertRaisesRegex(native.CheckFailure, "compiled process"):
            native.verify_compiled(case, config)

    def test_runtime_requires_toml_dependency_without_skipping(self):
        with patch.object(native, "tomllib", None):
            with self.assertRaisesRegex(native.CheckFailure, "Python 3.11"):
                native.parse_toml("[agent]")

    def test_deny_and_optout_have_identical_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {"native": root / "fixtures/native-write", "server": root / "fixtures/native-server",
                        "python_read": ["/test/python"], "python": "/test/python/bin/python3"}
            for kind in ("agent", "tool", "mcp"):
                deny = native.make_profile(dict(self.case, kind=kind), root / (kind + "deny"), fixtures)
                off = native.make_profile(dict(self.case, kind=kind, override=False), root / (kind + "off"), fixtures)
                self.assertEqual(deny["grants"], off["grants"])
                self.assertEqual(deny["grants"]["project"], {"access": "write"})


if __name__ == "__main__":
    unittest.main()
