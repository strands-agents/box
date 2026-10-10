#!/usr/bin/env python3
"""Test production version selection without installing agents or making requests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(os.environ.get("WORKLOAD_SOURCE_ROOT", Path(__file__).resolve().parents[2]))


class VersionSelection(unittest.TestCase):
    def install_block(self, claude="", codex="", sdk="1.57.1", installed_sdk="1.57.1"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bins = root / "bin"
            bins.mkdir()
            tools = root / "tools"
            lib = tools / "strands/lib"
            (lib / "strands").mkdir(parents=True)
            (lib / "strands/__init__.py").write_text("")
            metadata = lib / "strands_agents.dist-info"
            metadata.mkdir()
            (metadata / "METADATA").write_text("Name: strands-agents\nVersion: " + installed_sdk + "\n")
            entry = root / "workload-strands-agent.py"
            entry.write_text("# local fixture\n")
            old_claude = root / "existing-claude"
            old_claude.write_text("#!/bin/sh\nexit 0\n")
            old_claude.chmod(0o755)
            old_codex = root / "existing-codex.js"
            old_codex.write_text("// local fixture\n")
            calls = root / "calls.jsonl"
            stub = "#!" + sys.executable + "\n" + '''
import json, os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
with open(os.environ["TEST_CALLS"], "a") as f:
    f.write(json.dumps([name] + sys.argv[1:]) + "\\n")
if name == "host-python" and sys.argv[1:2] == ["-c"]:
    os.execv(sys.executable, [sys.executable] + sys.argv[1:])
if name == "host-python" and "install" in sys.argv:
    target = Path(sys.argv[sys.argv.index("--target") + 1])
    version = next(arg.split("==", 1)[1] for arg in sys.argv if arg.startswith("strands-agents=="))
    (target / "strands_agents.dist-info/METADATA").write_text("Name: strands-agents\\nVersion: " + version + "\\n")
if name == "curl" and "-o" in sys.argv:
    Path(sys.argv[sys.argv.index("-o") + 1]).write_text("# local installer fixture\\n")
'''
            for command in ("curl", "bash", "npm", "host-python"):
                path = bins / command
                path.write_text(stub)
                path.chmod(0o755)
            script = (SOURCE / "test-workload/common/workload-bootstrap.sh").read_text()
            start = script.index("# --- 2. agents ")
            end = script.index('if [ "$PLATFORM" = macos ]; then\n  # A curl-installed binary', start)
            block = script[start:end]
            # Isolate only fixed log/payload paths. Branches and commands are production code.
            scratch = root / "scratch"
            scratch.mkdir()
            block = block.replace("/tmp/", str(scratch) + "/")
            result = subprocess.run(
                ["/bin/bash", "-c", '''
set -u
log() { :; }
wl_resolve_paths() { WL_PYTHON="$TEST_PYTHON"; }
''' + block],
                env={**os.environ, "PATH": str(bins) + ":/usr/bin:/bin",
                     "TEST_CALLS": str(calls), "TEST_PYTHON": str(bins / "host-python"),
                     "WL_HOME": str(root / "home"), "WL_TOOLS": str(tools),
                     "WL_CLAUDE": str(old_claude), "WL_CODEX_SHIM": str(old_codex),
                     "WL_CLAUDE_VERSION": claude, "WL_CODEX_VERSION": codex,
                     "WL_STRANDS_SDK_VERSION": sdk, "PLATFORM": "linux", "BOOT_DIR": str(root)},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return [json.loads(line) for line in calls.read_text().splitlines()]

    def test_explicit_cli_pins_install_the_requested_versions(self):
        calls = self.install_block(claude="2.1.7", codex="0.9.3")
        claude = [call for call in calls if call[0] == "bash"]
        npm = [call for call in calls if call[0] == "npm"]
        with self.subTest(agent="claude"):
            self.assertEqual(len(claude), 1, calls)
            self.assertEqual(claude[0][-1], "2.1.7")
        with self.subTest(agent="codex"):
            self.assertEqual(len(npm), 1, calls)
            self.assertIn("@openai/codex@0.9.3", npm[0])

    def test_unpinned_existing_clis_are_reused(self):
        calls = self.install_block()
        self.assertFalse(any(call[0] in ("bash", "npm", "curl") for call in calls), calls)

    def test_wrong_sdk_version_is_replaced_with_the_requested_pin(self):
        calls = self.install_block(sdk="1.57.1", installed_sdk="1.56.0")
        installs = [call for call in calls if call[0] == "host-python" and "install" in call]
        self.assertEqual(len(installs), 1, calls)
        self.assertIn("strands-agents==1.57.1", installs[0])

    def test_matching_sdk_version_is_reused(self):
        calls = self.install_block(sdk="1.57.1", installed_sdk="1.57.1")
        self.assertFalse(any("install" in call for call in calls), calls)

    def test_claude_resolver_selects_the_pin_instead_of_the_newest_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            versions = root / ".local/share/claude/versions"
            versions.mkdir(parents=True)
            for name, time in (("2.1.7", 100), ("2.2.0", 200)):
                binary = versions / name
                binary.write_text("#!/bin/sh\nexit 0\n")
                binary.chmod(0o755)
                os.utime(binary, (time, time))
            for pin, expected in (("2.1.7", "2.1.7"), ("", "2.2.0"), ("2.0.0", None)):
                with self.subTest(pin=pin):
                    result = subprocess.run(
                        ["/bin/bash", "-c", 'source "$1"; wl_resolve_paths; printf "%s" "$WL_CLAUDE"',
                         "resolve", str(SOURCE / "test-workload/common/workload-lib.sh")],
                        env={**os.environ, "WL_HOME_DIR": str(root), "WL_CLAUDE_VERSION": pin,
                             "INDET_PLATFORM": "linux"}, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, str((versions / expected).resolve()) if expected else "")

    def test_claude_build_log_names_the_selected_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "2.1.7"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            script = (SOURCE / "test-workload/common/workload-bootstrap.sh").read_text()
            function = next(line for line in script.splitlines() if line.startswith("wl_claude_build() {"))
            result = subprocess.run(["/bin/bash", "-c", function + "\nwl_claude_build"],
                                    env={**os.environ, "WL_CLAUDE": str(binary)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "2.1.7")


if __name__ == "__main__":
    unittest.main()
