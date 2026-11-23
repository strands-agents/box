"""Exercise the signed installer gate with controlled Apple verification tools."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tarfile
import unittest
from unittest.mock import patch

import test_distribution as distribution

spec = importlib.util.spec_from_file_location(
    "install_native_macos_package", Path(__file__).with_name("install-native-macos-package.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

SOURCE = "a" * 40


class NativeInstaller(unittest.TestCase):
    def setUp(self):
        self.fixture = distribution.Installer()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.native_platform()
        self.root = self.fixture.root
        self.package = self.root / "verified-package"
        self.package.mkdir()
        self.archive = self.fixture.release("0.2.1", native=True)
        with tarfile.open(self.archive) as archive:
            archive.extractall(self.package, filter="data")
        (self.package / "Box.app/Contents/Info.plist").write_bytes(
            plistlib.dumps({"CFBundleVersion": "0.2.1"}))
        self.receipt = self.root / "signing-receipt.json"
        self.evidence = self.root / "evidence"
        self.bind_archive()
        self.addCleanup(self.remove_installation)
        environment = installer.installer_environment

        def controlled_environment(*args):
            result = environment(*args)
            result["PATH"] = f"{args[1]}:{self.fixture.tools}:{installer.SYSTEM_PATH}"
            result.update({key: value for key, value in self.fixture.env.items() if key.startswith("TEST_")})
            return result

        self.addCleanup(patch.stopall)
        patch.object(installer.platform, "system", return_value="Darwin").start()
        patch.object(installer, "installer_environment", side_effect=controlled_environment).start()
        patch.object(installer, "prepare_installation", side_effect=self.prepare_home).start()

    def prepare_home(self, home):
        installation = home / ".strands/box/installation.toml"
        installation.parent.mkdir(parents=True)
        installation.write_text('installation_id = ""\n')

    def remove_installation(self):
        path = self.evidence / "receipt.json"
        if path.exists():
            record = json.loads(path.read_text())
            if record.get("work"):
                shutil.rmtree(record["work"], ignore_errors=True)

    def bind_archive(self):
        for path in self.package.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        with tarfile.open(self.archive, "w:gz") as archive:
            for path in sorted(self.package.iterdir()):
                archive.add(path, arcname=path.name)
        release = installer.release
        resources = self.package / "Box.app/Contents/Resources"
        self.receipt.write_text(json.dumps(dict(
            native_filesystem_policy=True, source_sha=SOURCE, version="0.2.1",
            cargo_features=[release.NATIVE_FEATURE], output_sha256=release.digest(self.archive),
            notarized=True, notarization_id="2efe2717-52ef-43a5-96dc-0797e4ca1041",
            package_files=release.native_inventory(self.package),
            binaries={name: release.digest(self.package / "Box.app/Contents/MacOS" / name)
                      for name in release.BINARIES},
            resources={path.relative_to(resources).as_posix(): release.digest(path)
                       for path in resources.rglob("*") if path.is_file()})))

    def install(self, source=SOURCE):
        return installer.install(self.archive, self.package, self.receipt, source, self.evidence)

    def test_real_installer_keeps_signed_bytes_modes_aliases_and_public_launcher(self):
        with patch.dict(os.environ, {"BOX_ALLOW_UNSIGNED": "1", "BOX_GITHUB_REPO": "wrong/repo"}):
            installed = self.install()
        record = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(record["status"], "passed")
        self.assertEqual(installer.release.native_inventory(installed),
                         installer.release.native_inventory(self.package))
        self.assertEqual(record["archive_sha256"], installer.release.digest(self.archive))
        self.assertTrue(installed.is_dir())
        public = Path(record["public_launcher"])
        self.assertEqual(public.resolve(), installed / "box")
        self.assertIn(str(installed / "Box.app/Contents/MacOS/box"), self.fixture.log.read_text())
        self.assertEqual(record["version_command"], [str(public), "--version"])
        self.assertEqual((self.evidence / "version.stdout").read_text(), "box 0.2.1\n")
        self.assertCountEqual([json.loads(line) for line in
                              (self.root / "gatekeeper-calls").read_text().splitlines()],
                              ["Box.app", *distribution.BINARIES[1:]])
        calls = [json.loads(line) for line in (self.evidence / "downloads.jsonl").read_text().splitlines()]
        self.assertCountEqual([call["asset"] for call in calls], [self.archive.name, "SHA256SUMS.txt"])
        self.assertNotIn("BOX_ALLOW_UNSIGNED", record["environment"])
        self.assertNotIn("BOX_GITHUB_REPO", record["environment"])

    def test_signature_failure_is_reported_and_no_public_version_runs(self):
        self.fixture.env["TEST_BAD_SIGNATURE"] = "1"
        with self.assertRaisesRegex(RuntimeError, "install.sh failed"):
            self.install()
        record = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertNotEqual(record["installer_returncode"], 0)
        self.assertIn("cannot read signing identity: Box.app", (self.evidence / "install.stderr").read_text())
        self.assertFalse((self.evidence / "version.stdout").exists())
        self.assertFalse(self.fixture.log.exists())

    def test_gatekeeper_failure_is_reported(self):
        self.fixture.env["TEST_BAD_GATEKEEPER"] = "1"
        with self.assertRaisesRegex(RuntimeError, "install.sh failed"):
            self.install()
        self.assertFalse((self.evidence / "version.stdout").exists())

    def test_archive_source_mismatch_fails_before_installer(self):
        with patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "source mismatch"):
                self.install("c" * 40)
            run.assert_not_called()

    def test_archive_bytes_mismatch_fails_before_installer(self):
        with self.archive.open("ab") as output:
            output.write(b"changed")
        with patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                self.install()
            run.assert_not_called()

    def assert_installed_change_rejected(self, change, diagnostic):
        original = installer.subprocess.run

        def change_installed_file(command, **kwargs):
            result = original(command, **kwargs)
            if command[0] == "/bin/sh" and result.returncode == 0:
                path = Path(kwargs["env"]["HOME"]) / ".strands/box/packages/0.2.1-aarch64-apple-darwin"
                change(path)
            return result

        with patch.object(installer.subprocess, "run", side_effect=change_installed_file):
            with self.assertRaisesRegex(RuntimeError, diagnostic):
                self.install()
        self.assertFalse((self.evidence / "version.stdout").exists())

    def test_installed_file_mode_change_is_rejected(self):
        self.assert_installed_change_rejected(
            lambda path: (path / "Box.app/Contents/Resources/resources/config.toml").chmod(0o600),
            "differs from its archive")

    def test_installed_file_bytes_change_is_rejected(self):
        self.assert_installed_change_rejected(
            lambda path: (path / "Box.app/Contents/Resources/resources/config.toml").write_text("changed"),
            "differs from its archive")

    def test_installed_alias_change_is_rejected(self):
        def change_alias(path):
            (path / "resources").unlink()
            (path / "resources").symlink_to("Box.app/Contents")
        self.assert_installed_change_rejected(change_alias, "Unexpected native package alias")

    def test_installed_directory_mode_change_is_rejected(self):
        self.assert_installed_change_rejected(
            lambda path: (path / "Box.app/Contents/Resources").chmod(0o700),
            "Unexpected installed directory mode")

    def test_timeout_keeps_failure_output(self):
        with patch.object(installer.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                "install.sh", 120, output=b"partial output", stderr=b"partial error")):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                self.install()
        self.assertEqual((self.evidence / "timeout.stdout").read_bytes(), b"partial output")
        self.assertEqual((self.evidence / "timeout.stderr").read_bytes(), b"partial error")
        self.assertEqual(json.loads((self.evidence / "receipt.json").read_text())["status"], "failed")


class InstallerEnvironment(unittest.TestCase):
    def test_environment_does_not_inherit_unsigned_mode_or_credentials(self):
        with patch.dict(os.environ, {"BOX_ALLOW_UNSIGNED": "1", "GH_TOKEN": "unused-test-value"}):
            environment = installer.installer_environment(Path("/tmp/home"), Path("/tmp/tools"),
                                                          Path("/tmp/work"), "0.2.1")
        self.assertEqual(set(environment), {"HOME", "SHELL", "PATH", "TMPDIR", "LC_ALL",
                                           "BOX_VERSION", "BOX_NO_MODIFY_PATH"})
        self.assertEqual(environment["PATH"], "/tmp/tools:/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(environment["BOX_NO_MODIFY_PATH"], "1")


if __name__ == "__main__":
    unittest.main()
