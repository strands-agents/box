"""Check binary preparation and dependency targeting without a Rust build."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("prepare_example", Path(__file__).with_name("prepare.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "research").mkdir()
        self.source = self.root / "release"
        self.source.mkdir()
        self.elf = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\xb7\x00" + b"test executable"
        for name in prepare.BINARIES:
            (self.source / name).write_bytes(self.elf)
        patcher = mock.patch.object(prepare, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_binaries_have_hashes_revision_and_executable_modes(self):
        manifest = prepare.install_binaries(self.source, prepare.BOX_REVISION)
        self.assertEqual(manifest["box_revision"], prepare.BOX_REVISION)
        self.assertEqual(len(manifest["files"]), 3)
        self.assertEqual(json.loads((self.root / "research/tested-build.json").read_text()), manifest)
        for name, digest in manifest["files"].items():
            path = self.root / name
            self.assertEqual(prepare.hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_wrong_architecture_is_refused_before_install(self):
        (self.source / "strands-box").write_bytes(b"not an ARM64 executable")
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)
        self.assertFalse((self.root / "binary-manifest.json").exists())

    def test_symlink_binary_is_refused(self):
        (self.source / "strands-box").rename(self.source / "saved-box")
        (self.source / "strands-box").symlink_to(self.source / "saved-box")
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)

    def test_existing_binary_is_not_replaced(self):
        prepare.install_binaries(self.source, prepare.BOX_REVISION)
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)

    def test_scripted_variant_installs_no_framework(self):
        with mock.patch.object(prepare.subprocess, "run") as run:
            prepare.install_framework("scripted")
            run.assert_not_called()


    def test_failed_dependency_install_can_retry_the_existing_build(self):
        directory = self.root / "sdk"
        directory.mkdir()
        (directory / "dependency-lock.txt").write_text("retry-fixture==1.0\n")
        source = self.root / ".build/box"
        release = source / "target/release"
        release.parent.mkdir(parents=True)
        self.source.rename(release)
        calls, targets = [], []

        def run(command, **kwargs):
            calls.append(command)
            if "pip" not in command:
                return subprocess.CompletedProcess(command, 0)
            target = Path(command[command.index("--target") + 1])
            targets.append(target)
            target.mkdir(parents=True, exist_ok=True)
            if len(targets) == 1:
                (target / "partial.py").write_text("partial dependency\n")
                raise subprocess.CalledProcessError(1, command)
            (target / "retry_fixture.py").write_text("READY = True\n")
            metadata = target / "retry_fixture-1.0.dist-info"
            metadata.mkdir()
            (metadata / "METADATA").write_text("Name: retry-fixture\nVersion: 1.0\n")
            return subprocess.CompletedProcess(command, 0)

        def check_output(command, **kwargs):
            return prepare.BOX_REVISION + "\n" if "rev-parse" in command else ""

        with mock.patch.object(sys, "argv", ["prepare.py", "--framework", "strands"]), \
                mock.patch.object(sys, "version_info", (3, 12)), \
                mock.patch.object(prepare.platform, "system", return_value="Linux"), \
                mock.patch.object(prepare.platform, "machine", return_value="aarch64"), \
                mock.patch.object(prepare.subprocess, "run", side_effect=run), \
                mock.patch.object(prepare.subprocess, "check_output", side_effect=check_output):
            with self.assertRaises(subprocess.CalledProcessError):
                prepare.main()
            for relative in ("sdk/vendor", "sdk/dependency-manifest.json", "box-core",
                             "binary-manifest.json", "research/tested-build.json"):
                self.assertFalse((self.root / relative).exists(), relative)
            self.assertTrue((release / "strands-box").is_file())
            prepare.main()

        self.assertEqual(sum(command[0] == "cargo" for command in calls), 2)
        self.assertFalse(any(command[0] == "git" for command in calls))
        self.assertEqual(len(targets), 2)
        self.assertTrue(all(target != directory / "vendor" and not target.exists() for target in targets))
        self.assertFalse((directory / "vendor/partial.py").exists())
        manifest = json.loads((directory / "dependency-manifest.json").read_text())
        self.assertEqual(manifest["packages"], {"retry-fixture": "1.0"})
        self.assertEqual(manifest["architecture"], "aarch64")
        self.assertEqual(manifest["python_minor"], "3.12")
        self.assertEqual(manifest["platform"], "Linux")
        self.assertEqual(set(manifest["files"]), {
            "sdk/vendor/retry_fixture.py", "sdk/vendor/retry_fixture-1.0.dist-info/METADATA",
        })
        for relative, digest in manifest["files"].items():
            self.assertEqual(prepare.hashlib.sha256((self.root / relative).read_bytes()).hexdigest(), digest)
        self.assertTrue((self.root / "binary-manifest.json").is_file())
        self.assertFalse(any(directory.glob(".vendor-*")))

    def test_invalid_binaries_are_refused_before_dependency_install(self):
        source = self.root / ".build/box"
        release = source / "target/release"
        release.parent.mkdir(parents=True)
        self.source.rename(release)
        (release / "strands-box").write_bytes(b"not an ARM64 executable")
        with mock.patch.object(sys, "argv", ["prepare.py", "--framework", "strands"]), \
                mock.patch.object(sys, "version_info", (3, 12)), \
                mock.patch.object(prepare.platform, "system", return_value="Linux"), \
                mock.patch.object(prepare.platform, "machine", return_value="aarch64"), \
                mock.patch.object(prepare.subprocess, "run") as run, \
                mock.patch.object(prepare.subprocess, "check_output", side_effect=[prepare.BOX_REVISION, ""]):
            with self.assertRaisesRegex(ValueError, "Linux ARM64 executable"):
                prepare.main()
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(run.call_args.args[0][0], "cargo")
        self.assertFalse((self.root / "box-core").exists())
        self.assertFalse((self.root / "sdk/vendor").exists())

    def test_manifest_publication_failure_removes_staged_dependencies(self):
        directory = self.root / "langchain-example"
        directory.mkdir()
        original_rename = Path.rename

        def run(command, **kwargs):
            target = Path(command[command.index("--target") + 1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "fixture.py").write_text("READY = True\n")
            return subprocess.CompletedProcess(command, 0)

        def rename(path, target):
            if Path(target) == directory / "dependency-manifest.json":
                raise OSError("synthetic manifest publication failure")
            return original_rename(path, target)

        with mock.patch.object(prepare.subprocess, "run", side_effect=run), \
                mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(OSError, "manifest publication failure"):
                prepare.install_framework("langchain")
        self.assertFalse((directory / "vendor").exists())
        self.assertFalse((directory / "dependency-manifest.json").exists())
        self.assertFalse(any(directory.glob(".vendor-*")))

    def test_existing_dependency_manifest_is_not_replaced(self):
        directory = self.root / "sdk"
        directory.mkdir()
        manifest = directory / "dependency-manifest.json"
        manifest.write_text("saved manifest\n")
        with mock.patch.object(prepare.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                prepare.install_framework("strands")
            run.assert_not_called()
        self.assertEqual(manifest.read_text(), "saved manifest\n")


if __name__ == "__main__":
    unittest.main()
