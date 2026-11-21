"""Execute native signing and verification workflow commands with controlled services."""

import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import test_distribution as distribution
import test_experimental_package as experimental
import test_release_source_cli as release_source


class NativeSigningWorkflow(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-release-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.capture = self.root / "calls.jsonl"
        self.profiles = self.root / "profiles.jsonl"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.context = {
            "inputs.version": "0.2.1",
            "inputs.tag": "v0.2.1",
            "inputs.sha": "a" * 40,
            "inputs.native_filesystem_policy": "true",
            "vars.BOX_TEST_INSTALLATION_ID": "",
        }
        self.recorder = f"""#!{sys.executable}
import json, os, pathlib, sys
with pathlib.Path({str(self.capture)!r}).open("a") as output:
    print(json.dumps(sys.argv[1:]), file=output)
with pathlib.Path({str(self.profiles)!r}).open("a") as output:
    print(json.dumps(os.environ.get("CD_SIGNER_PROFILE_NAME")), file=output)
if sys.argv[1] == "scripts/install-native-macos-package.py":
    if os.environ.get("TEST_INSTALL_FAILURE"): sys.exit(7)
    print("/var/tmp/installed-native/release")
"""
        distribution.executable(self.tools / "python3", self.recorder)
        interpreter = self.runner / "signing-venv/bin/python"
        interpreter.parent.mkdir(parents=True)
        distribution.executable(interpreter, self.recorder)

    def execute(self, step, *, native=True, prefix=None, extra_environment=None):
        self.context["inputs.native_filesystem_policy"] = str(native).lower()
        environment = (experimental.workflow_environment(step, self.context)
                       if "        env:" in experimental.workflow_step(step) else os.environ.copy())
        environment.update(
            PATH=f"{self.tools}:{os.environ['PATH']}", RUNNER_TEMP=str(self.runner),
            CD_SIGNER_PROFILE_NAME="Box CLI distribution", NOTARY_CREDENTIAL_SECRET="test-reference")
        environment.update(extra_environment or {})
        command = release_source.workflow_command(step)
        if prefix:
            command = command.split(prefix, 1)[0]
        result = subprocess.run(["bash", "-c", command], cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=20)
        calls = [json.loads(line) for line in self.capture.read_text().splitlines()] if self.capture.exists() else []
        return result, calls

    def test_native_host_refuses_old_or_unreadable_versions(self):
        distribution.executable(self.tools / "python3", f"#!/bin/sh\nexec {sys.executable} \"$@\"\n")
        for os_version, sdk_version, succeeds in (("27.0", "27.1", True), ("26.3", "27.0", False),
                                                   ("27.0", "26.4", False), ("invalid", "27.0", False)):
            with self.subTest(os=os_version, sdk=sdk_version):
                distribution.executable(self.tools / "sw_vers", f"#!/bin/sh\nprintf '%s\\n' '{os_version}'\n")
                distribution.executable(self.tools / "xcrun", f"#!/bin/sh\nprintf '%s\\n' '{sdk_version}'\n")
                result, _ = self.execute("Check the native macOS host")
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
                if not succeeds:
                    self.assertIn("requires", result.stderr)

    def workflow_value(self, job, section, key, context):
        lines = release_source.CLI_WORKFLOW.read_text().splitlines()
        start = lines.index(f"  {job}:") + 1
        end = next((i for i in range(start, len(lines))
                    if re.match(r"^  [a-z][a-z-]*:$", lines[i])), len(lines))
        block = lines[start:end]
        start = block.index(f"    {section}:") + 1
        end = next((i for i in range(start, len(block))
                    if block[i].startswith("    ") and not block[i].startswith("      ")), len(block))
        value = next(line.removeprefix(f"      {key}: ") for line in block[start:end]
                     if line.startswith(f"      {key}: "))
        match = re.fullmatch(r"\$\{\{\s*([^{}]+?)\s*\}\}", value)
        self.assertIsNotNone(match, value)
        return context.get(match[1].strip(), "")

    def assert_profile_reaches_signing_and_verification(self, context):
        expected = context["vars.CD_SIGNER_PROFILE_NAME"]
        signing = self.workflow_value("sign-macos", "env", "CD_SIGNER_PROFILE_NAME", context)
        result, _ = self.execute("Check native signing configuration",
                                 extra_environment={"CD_SIGNER_PROFILE_NAME": signing})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result, _ = self.execute("Sign and notarize the executables",
                                 extra_environment={"CD_SIGNER_PROFILE_NAME": signing})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.profiles.read_text().splitlines()[-1]), expected)
        context = {"needs.sign-macos.outputs.cli_profile_name":
                   self.workflow_value("sign-macos", "outputs", "cli_profile_name", context)}
        verification = self.workflow_value("verify-macos", "env", "CD_SIGNER_PROFILE_NAME", context)
        (self.root / "signed").mkdir()
        with tarfile.open(self.root / "signed/box-cli-v0.2.1-aarch64-apple-darwin.tar.gz", "w:gz"):
            pass
        result, _ = self.execute("Verify the package and run a box with it",
                                 prefix='"$package/box" --version',
                                 extra_environment={"CD_SIGNER_PROFILE_NAME": verification})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.profiles.read_text().splitlines()[-1]), expected)

    def test_shared_profile_setting_reaches_signing_and_verification(self):
        self.assert_profile_reaches_signing_and_verification(
            {"vars.CD_SIGNER_PROFILE_NAME": "Shared Box distribution"})

    def test_legacy_profile_setting_cannot_override_the_shared_profile(self):
        self.assert_profile_reaches_signing_and_verification(
            {"vars.CD_SIGNER_PROFILE_NAME": "Shared Box distribution",
             "vars.CD_SIGNER_CLI_PROFILE_NAME": "Different legacy CLI profile"})

    def test_native_signing_requires_the_shared_profile_even_with_a_legacy_setting(self):
        profile = self.workflow_value("sign-macos", "env", "CD_SIGNER_PROFILE_NAME",
                                      {"vars.CD_SIGNER_PROFILE_NAME": "",
                                       "vars.CD_SIGNER_CLI_PROFILE_NAME": "Legacy CLI profile"})
        result, calls = self.execute("Check native signing configuration",
                                     extra_environment={"CD_SIGNER_PROFILE_NAME": profile})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CD_SIGNER_PROFILE_NAME", result.stderr + result.stdout)
        self.assertEqual(calls, [])

    def test_native_signing_passes_the_archive_bound_build_record(self):
        result, calls = self.execute("Sign and notarize the executables")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertIn("--native-filesystem-policy", calls[0])
        self.assertEqual(calls[0][calls[0].index("--build-metadata") + 1],
                         "unsigned-features/native-filesystem-policy.json")
        self.assertEqual(calls[0][calls[0].index("--source-sha") + 1], "a" * 40)

    def test_baseline_signing_does_not_request_native_authorization(self):
        result, calls = self.execute("Sign and notarize the executables", native=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--native-filesystem-policy", calls[0])
        self.assertNotIn("--build-metadata", calls[0])

    def test_native_verification_receives_signed_archive_receipt_and_source(self):
        (self.root / "signed").mkdir()
        archive = self.root / "signed/box-cli-v0.2.1-aarch64-apple-darwin.tar.gz"
        with tarfile.open(archive, "w:gz"):
            pass
        result, calls = self.execute("Verify the package and run a box with it",
                                     prefix='"$package/box" --version')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertIn("--native-filesystem-policy", calls[0])
        expected = {"--receipt": "native-receipt/receipt.json", "--archive": str(archive.relative_to(self.root)),
                    "--source-sha": "a" * 40}
        for argument, value in expected.items():
            self.assertEqual(calls[0][calls[0].index(argument) + 1], value)

    def test_native_runtime_gate_executes_the_installed_candidate_and_unsigned_control(self):
        (self.root / "unsigned-control").mkdir()
        archive = self.root / "unsigned-control/box-cli-v0.2.1-aarch64-apple-darwin.tar.gz"
        with tarfile.open(archive, "w:gz"):
            pass
        result, calls = self.execute("Check native filesystem policy in the signed package")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "scripts/install-native-macos-package.py")
        for argument, value in {"--package": str(self.runner / "box-package"),
                                "--archive": "signed/box-cli-v0.2.1-aarch64-apple-darwin.tar.gz",
                                "--receipt": "native-receipt/receipt.json", "--source-sha": "a" * 40,
                                "--evidence": str(self.runner / "package-verification/install")}.items():
            self.assertEqual(calls[0][calls[0].index(argument) + 1], value)
        self.assertEqual(calls[1][0], "scripts/check-native-macos-package.py")
        for argument, value in {"--package": "/var/tmp/installed-native/release",
                                "--unsigned-package": str(self.runner / "unsigned-package"),
                                "--evidence": str(self.runner / "package-verification/native")}.items():
            self.assertEqual(calls[1][calls[1].index(argument) + 1], value)
        self.assertIn("if: inputs.native_filesystem_policy == true",
                      "\n".join(experimental.workflow_step("Check native filesystem policy in the signed package")))

    def test_installer_failure_prevents_native_runtime_checks(self):
        (self.root / "unsigned-control").mkdir()
        with tarfile.open(self.root / "unsigned-control/box-cli-v0.2.1-aarch64-apple-darwin.tar.gz", "w:gz"):
            pass
        result, calls = self.execute("Check native filesystem policy in the signed package",
                                     extra_environment={"TEST_INSTALL_FAILURE": "1"})
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "scripts/install-native-macos-package.py")

    def test_installer_runs_only_after_signed_package_verification(self):
        workflow = release_source.CLI_WORKFLOW.read_text()
        self.assertLess(workflow.index("- name: Verify the package and run a box with it"),
                        workflow.index("- name: Check native filesystem policy in the signed package"))
        verification = release_source.workflow_command("Verify the package and run a box with it")
        self.assertNotIn("install-native-macos-package.py", verification)


if __name__ == "__main__":
    unittest.main()
