"""Check Linux storage-helper builds, archives, and package validation."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_check_linux_package as linux
import test_release_source_cli as release

ROOT = Path(__file__).resolve().parents[1]
COMPILER = "strands-box-storage-compiler"
COMMON = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
TARGETS = ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin")


class StorageBuildTests(unittest.TestCase):
    def test_unit_test_images_follow_the_selected_package_group(self):
        workflow = (ROOT / ".github/workflows/rust-test-lint.yml").read_text()
        step = workflow.split("      - name: Install launcher images beside unit-test binaries\n", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        command = textwrap.dedent(step.split("        run: |\n", 1)[1])
        trampoline = "strands-box-contain-trampoline"
        alias = "strands-box-sock-alias"
        for part, missing in (("others", False), ("box", False), ("box", True)):
            with self.subTest(part=part, missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                debug = root / "target/debug"
                (debug / "deps").mkdir(parents=True)
                images = {trampoline} if part == "others" else {trampoline, alias, COMPILER}
                for name in images - ({COMPILER} if missing else set()):
                    (debug / name).write_bytes(name.encode())
                result = subprocess.run(
                    ["bash", "-e", "-c", command], cwd=root,
                    env={**os.environ, "PART": part}, capture_output=True, text=True, timeout=10,
                )
                if missing:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(COMPILER, result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual({path.name for path in (debug / "deps").iterdir()}, images)
                    for name in images:
                        self.assertEqual((debug / "deps" / name).read_bytes(), name.encode())
                        self.assertEqual((debug / "deps" / name).stat().st_mode & 0o777, 0o755)

    def test_development_build_selects_compiler_only_on_linux(self):
        recipe = (ROOT / "justfile").read_text().split("build-cli:\n", 1)[1].split("\n\n", 1)[0]
        for system in ("Linux", "Darwin"):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "uname").write_text("#!/bin/sh\nprintf '%s\\n' \"$TEST_SYSTEM\"\n")
                (root / "cargo").write_text(
                    f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
                for name in ("uname", "cargo"):
                    (root / name).chmod(0o755)
                result = subprocess.run(
                    ["sh", "-c", textwrap.dedent(recipe).replace("\\\n", "")], cwd=ROOT,
                    env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "TEST_SYSTEM": system},
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                command = json.loads(result.stdout)
                binaries = [command[i + 1] for i, arg in enumerate(command) if arg == "--bin"]
                self.assertEqual(set(binaries), {*COMMON, "strands-box"} | ({COMPILER} if system == "Linux" else set()))
                self.assertIn("--locked", command)


@unittest.skipUnless(shutil.which("jq"), "workflow package metadata uses jq")
class StorageArchiveTests(unittest.TestCase):
    def package(self, target, missing=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        tools = root / "tools"
        tools.mkdir()
        (tools / "cargo").write_text(
            f"#!{sys.executable}\nimport json\nprint(json.dumps(" + repr({"packages": [{
                "name": "strands-box", "version": "0.1.0", "source": "git+https://github.com/strands-agents/box#" + "b" * 40,
            }, {
                "name": "strands-box-containment", "version": "0.1.0",
                "source": "git+https://github.com/strands-agents/box#" + "b" * 40,
            }]}) + "))\n")
        (tools / "cargo").chmod(0o755)
        binaries = root / "target" / target / "release"
        binaries.mkdir(parents=True)
        for name in (*COMMON, COMPILER):
            if name == COMPILER and missing:
                continue
            (binaries / name).write_bytes(b"native fixture")
        resources = root / "resources"
        resources.mkdir()
        (resources / "config.toml").write_text("[starters]\n")
        (resources / "editing-box-profile.md").write_text("# Profile\n")
        for name in ("packs", "plugins", "policies", "starters"):
            (resources / name).mkdir()
        result = subprocess.run(
            ["bash", "-c", release.workflow_command("Package tarball")], cwd=root,
            env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "NEW_TAG": "v0.1.0",
                 "TRIPLE": target, "RELEASE_SHA": "a" * 40},
            capture_output=True, text=True, timeout=10,
        )
        return result, root / "dist" / f"box-cli-v0.1.0-{target}.tar.gz"

    def test_linux_archives_mark_and_include_compiler_while_macos_stays_unchanged(self):
        for target in TARGETS:
            with self.subTest(target=target):
                result, archive = self.package(target)
                self.assertEqual(result.returncode, 0, result.stderr)
                with tarfile.open(archive) as source:
                    files = {entry.name.removeprefix("./"): entry for entry in source if entry.isfile()}
                    expected = set(COMMON) | ({COMPILER} if "-linux-" in target else set())
                    self.assertEqual({name for name in files if not "/" in name and name != "release.json"}, expected)
                    for name in expected:
                        self.assertEqual(files[name].mode & 0o7777, 0o755)
                    with source.extractfile(files["release.json"]) as metadata:
                        record = json.load(metadata)
                    self.assertEqual(record["target"], target)
                    if "-linux-" in target:
                        self.assertIs(record.get("storage_compiler"), True)
                    else:
                        self.assertNotIn("storage_compiler", record)

    def test_missing_linux_compiler_stops_before_archive_creation(self):
        for target in TARGETS[:2]:
            with self.subTest(target=target):
                result, archive = self.package(target, missing=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(COMPILER, result.stderr)
                self.assertFalse(archive.exists())


class StorageBinaryCheckTests(unittest.TestCase):
    def check(self, root):
        output, error = io.StringIO(), io.StringIO()

        def inspect(command, **kwargs):
            if not Path(command[-1]).is_file():
                raise subprocess.CalledProcessError(1, command)
            return SimpleNamespace(stdout=linux.readelf_output(linux.ARM64, "GLIBC_2.34"))

        with patch.object(linux.checker.sys, "argv", ["check-linux-package.py", str(root), "--require-storage-metadata"]), \
             patch.object(linux.checker.subprocess, "run", side_effect=inspect) as readelf, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = linux.checker.main()
        return status, output.getvalue(), error.getvalue(), readelf.call_count

    def test_complete_package_passes_and_missing_compiler_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release.json").write_text('{"storage_compiler": true}')
            for name in (*COMMON, COMPILER):
                (root / name).write_bytes(b"ELF fixture")
            status, output, error, calls = self.check(root)
            self.assertEqual(status, 0, error)
            self.assertEqual(calls, 4)
            self.assertEqual({row["binary"] for row in json.loads(output)}, {*COMMON, COMPILER})
            (root / COMPILER).unlink()
            status, output, error, calls = self.check(root)
            self.assertEqual(status, 1)
            self.assertEqual(output, "")
            self.assertIn(COMPILER, error)

    def test_current_package_marker_must_be_boolean_true_before_binary_checks(self):
        for record in ({}, {"storage_compiler": False}, {"storage_compiler": "true"},
                       {"storage_compiler": 1}, {"storage_compiler": None}, []):
            with self.subTest(record=record), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "release.json").write_text(json.dumps(record))
                status, output, error, calls = self.check(root)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertIn("storage_compiler must be true", error)
                self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
