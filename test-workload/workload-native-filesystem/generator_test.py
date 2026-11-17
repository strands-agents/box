#!/usr/bin/env python3
"""Check generated native workload configuration."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


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
