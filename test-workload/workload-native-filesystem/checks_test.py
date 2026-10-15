#!/usr/bin/env python3
"""Reject false passes without a model, credentials, or a signed executable."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from checks import checks


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name)
        self.project = self.run / "project"
        self.project.mkdir()
        for name, text in (("allowed.txt", "ready\n"), ("protected.txt", "approved\n"),
                           ("continued.txt", "continued after protected edit\n")):
            (self.project / name).write_text(text)
        self.write_json("paths.json", {"HOME": str(self.run)})
        self.write_json("agent-a.json", dict(exit_code=0, run_status="VALID"))
        self.denial = dict(origin="dogwood", verdict="deny", path="~/project/protected.txt",
                           time_unix_ns="20")
        self.write_denial()
        self.events = [dict(type="assistant", message=dict(content=[
            dict(type="tool_use", name="Edit", id="edit-1", input=dict(file_path="protected.txt")),
            dict(type="tool_use", name="Write", id="write-1", input=dict(file_path="continued.txt"))]))]
        self.write_json("turns.jsonl", self.events[0])
        self.journal = [
            self.decision("allowed.txt", "permit", "native_runtime", 10),
            self.decision("protected.txt", "deny", "protected_file", 19),
            self.decision("continued.txt", "permit", "native_runtime", 30),
        ]
        self.write_journal()

    def write_json(self, name, value):
        (self.run / name).write_text(json.dumps(value) + "\n")

    def write_denial(self):
        (self.run / "agent-a.log").write_text("MACOS_FILE_DIAGNOSTIC " + json.dumps(self.denial) + "\n")

    def decision(self, name, verdict, rule, stamp):
        attrs = dict(resource="~/project/" + name, verdict=verdict, rule=rule, action="fs:write")
        return dict(timeUnixNano=str(stamp), attributes=[
            dict(key="strands.box.policy." + key, value=dict(stringValue=value))
            for key, value in attrs.items()])

    def write_journal(self):
        self.write_json("decisions.jsonl", dict(resourceLogs=[
            dict(scopeLogs=[dict(logRecords=self.journal)])]))

    def failed(self, agent="claude"):
        return {row["id"] for row in checks(self.run, agent) if not row["ok"]}

    def test_claude_native_edit(self):
        self.assertEqual(self.failed(), set())

    def test_codex_native_edit(self):
        self.write_json("turns.jsonl", dict(type="item.completed",
                        item=dict(type="file_change", id="edit-1", status="failed",
                                  changes=[dict(path="protected.txt", kind="update")])))
        self.assertEqual(self.failed("codex"), set())

    def test_codex_started_and_completed_count_once(self):
        item = dict(type="file_change", id="edit-1", changes=[dict(path="protected.txt", kind="update")])
        events = [dict(type=kind, item=item) for kind in ("item.started", "item.completed")]
        (self.run / "turns.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
        self.assertEqual(self.failed("codex"), set())

    def test_two_protected_claude_calls_cannot_pass(self):
        self.events[0]["message"]["content"].append(
            dict(type="tool_use", name="Edit", id="edit-2", input=dict(file_path="protected.txt")))
        self.write_json("turns.jsonl", self.events[0])
        self.assertIn("one-protected-attempt", self.failed())

    def test_two_protected_codex_calls_cannot_pass(self):
        events = [dict(type="item.completed", item=dict(
            type="file_change", id=identifier, changes=[dict(path="protected.txt", kind="update")]))
            for identifier in ("edit-1", "edit-2")]
        (self.run / "turns.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
        self.assertIn("one-protected-attempt", self.failed("codex"))

    def test_retry_path_spellings_cannot_hide_second_attempt(self):
        for spelling in (str(self.project) + "/./protected.txt", "./protected.txt",
                         "~/project/../project/protected.txt"):
            with self.subTest(spelling=spelling):
                content = self.events[0]["message"]["content"][:2] + [
                    dict(type="tool_use", name="Edit", id="edit-2", input=dict(file_path=spelling))]
                self.write_json("turns.jsonl", dict(type="assistant", message=dict(content=content)))
                self.assertIn("one-protected-attempt", self.failed())

    def test_rename_destination_is_checked(self):
        self.denial.update(path="~/project/protected.txt.tmp", destination="~/project/protected.txt")
        self.write_denial()
        self.assertEqual(self.failed(), set())

    def test_no_native_interception_cannot_pass(self):
        (self.run / "agent-a.log").write_text("")
        self.assertIn("native-protected-denial", self.failed())

    def test_adapter_denial_is_not_policy_denial(self):
        self.denial["origin"] = "adapter"
        self.write_denial()
        self.assertIn("native-protected-denial", self.failed())

    def test_retry_loop_cannot_pass(self):
        log = self.run / "agent-a.log"
        log.write_text(log.read_text() * 5)
        self.assertIn("native-protected-denial", self.failed())

    def test_protected_file_is_byte_exact(self):
        (self.project / "protected.txt").write_text("approved\n\n")
        self.assertIn("protected.txt", self.failed())

    def test_protected_file_changed(self):
        (self.project / "protected.txt").write_text("changed\n")
        self.assertIn("protected.txt", self.failed())

    def test_missing_continuation(self):
        (self.project / "continued.txt").unlink()
        self.assertIn("continued.txt", self.failed())

    def test_continuation_before_denial_cannot_pass(self):
        self.journal[2]["timeUnixNano"] = "15"
        self.write_journal()
        self.assertIn("continued-after-denial", self.failed())

    def test_neighboring_path_cannot_pass(self):
        self.journal[1] = self.decision("protected.txt.tmp", "deny", "protected_file", 19)
        self.write_journal()
        self.assertIn("protected-policy-denial", self.failed())

    def test_unrelated_rule_cannot_pass(self):
        self.journal[1] = self.decision("protected.txt", "deny", "other_rule", 19)
        self.write_journal()
        self.assertIn("protected-policy-denial", self.failed())

    def test_shell_only_cannot_pass(self):
        self.events[0]["message"]["content"] = [dict(type="tool_use", name="Bash")]
        self.write_json("turns.jsonl", self.events[0])
        self.assertIn("native-agent-tools", self.failed())

    def test_codex_shell_fallback_cannot_pass(self):
        self.write_json("turns.jsonl", dict(type="item.completed", item=dict(type="command_execution")))
        self.assertIn("native-agent-tools", self.failed("codex"))

    def test_codex_mixed_native_and_shell_tools_cannot_pass(self):
        events = [
            dict(type="item.completed", item=dict(type="file_change", id="edit-1",
                 changes=[dict(path="protected.txt", kind="update")])),
            dict(type="item.completed", item=dict(type="command_execution", id="command-1")),
        ]
        (self.run / "turns.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
        self.assertEqual(self.failed("codex"), {"native-agent-tools"})

    def test_missing_and_empty_tool_ids_cannot_pass(self):
        for agent in ("claude", "codex"):
            for identifier in (None, ""):
                with self.subTest(agent=agent, identifier=identifier):
                    if agent == "claude":
                        event = self.events[0]
                        call = event["message"]["content"][0]
                    else:
                        call = dict(type="file_change", changes=[dict(path="protected.txt", kind="update")])
                        event = dict(type="item.completed", item=call)
                    if identifier is None:
                        call.pop("id", None)
                    else:
                        call["id"] = identifier
                    self.write_json("turns.jsonl", event)
                    self.assertEqual(self.failed(agent), {"one-protected-attempt"})

    def test_claim_without_tool_event_cannot_pass(self):
        self.write_json("turns.jsonl", dict(type="result", result="I used Edit and Write."))
        self.assertIn("native-agent-tools", self.failed())

    def test_missing_journal_cannot_pass(self):
        (self.run / "decisions.jsonl").unlink()
        self.assertIn("protected-policy-denial", self.failed())

    def test_agent_error_cannot_pass(self):
        self.write_json("agent-a.json", dict(exit_code=1, run_status="VALID"))
        self.assertIn("agent-completed", self.failed())


class GeneratorTests(unittest.TestCase):
    def generate(self, platform, native=None, agent="claude", direct=False, manifest=""):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        paths = dict(HOME="/work", PLATFORM=platform, CLAUDE="/opt/claude",
                     TOOLS="/opt/tools", NODE="/opt/node/bin/node", NODE_TREE="/opt/node",
                     NODE_FORMULA="/opt/node", NODE_JITLESS="", BREW_READ="",
                     CODEX_SHIM="/opt/tools/codex.js", GIT="/usr/bin/git", TRUE="/usr/bin/true",
                     CLT="/opt/clt", GIT_HELPERS="/opt/git-helpers")
        (root / "paths.json").write_text(json.dumps(paths))
        (root / "manifest").write_text("tools=\n" + (
            "native_filesystem_policy=" + native + "\n" if native is not None else "") + manifest)
        env = os.environ.copy()
        env.pop("WL_CODEX_BINARY", None)
        if direct:
            env["WL_CODEX_BINARY"] = "/opt/codex"
        result = subprocess.run(["python3", str(Path(__file__).resolve().parents[1] / "common/boxgen.py"),
                                 str(root / "manifest"), str(root / "paths.json"), agent,
                                 "/work/project", str(root), "/work/journal", "/work/box"],
                                capture_output=True, text=True, env=env)
        config = (root / "box.toml").read_text() if (root / "box.toml").exists() else ""
        return result, config

    def test_default_leaves_native_disabled(self):
        result, config = self.generate("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("[experimental-features]", config)

    def test_native_opt_in(self):
        result, config = self.generate("macos", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("native-filesystem-policy = true", config)

    def test_linux_refuses_before_writing_config(self):
        result, config = self.generate("linux", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, "")
        self.assertIn("requires macOS", result.stderr)

    def test_invalid_setting_refused(self):
        result, _ = self.generate("macos", "yes")
        self.assertNotEqual(result.returncode, 0)

    def test_codex_default_keeps_node_shim(self):
        result, config = self.generate("macos", agent="codex")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('command = ["/opt/node/bin/node", "/opt/tools/codex.js", "exec"', config)

    def test_explicit_codex_binary_needs_no_node(self):
        result, config = self.generate("macos", "1", "codex", True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('command = ["/opt/codex", "exec"', config)
        self.assertNotIn("/opt/node", config)

    def test_codex_launcher_keeps_its_node_grants(self):
        result, config = self.generate("linux", agent="codex", direct=True,
                                       manifest="agent_program_linux=/opt/tools/launcher\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('command = ["/opt/tools/launcher"]', config)
        self.assertIn('"/opt/node"', config)
        self.assertIn('"/opt/tools"', config)
        self.assertNotIn('"/opt/codex"', config)

    def test_codex_tool_can_resolve_direct_helper(self):
        result, config = self.generate("macos", agent="codex", direct=True, manifest="tools=git\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"/opt/codex"', config.split("[tool.git]")[1].split("[egress.model]")[0])


if __name__ == "__main__":
    unittest.main()
