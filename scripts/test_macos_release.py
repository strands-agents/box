import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    "macos_release", Path(__file__).with_name("macos-release.py")
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class MacOSReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def build(self, extra=None, missing=None):
        archive = self.root / "build.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name in release.BINARIES:
                if name == missing:
                    continue
                member = tarfile.TarInfo("./" + name)
                member.size = 4
                member.mode = 0o755
                output.addfile(member, io.BytesIO(b"code"))
            if extra is not None:
                output.addfile(extra)
        return archive

    def build_metadata(self, archive, features=None):
        value = {
            "source_sha": "a" * 40,
            "features": features if features is not None else ["native-filesystem-policy"],
            "input_sha256": release.digest(archive),
        }
        path = self.root / "build-metadata.json"
        path.write_text(json.dumps(value))
        return path, value

    @unittest.skipUnless(shutil.which("cargo"), "Cargo is required to read release manifests")
    def test_workflow_records_defaults_from_the_selected_source(self):
        from test_release_source import workflow_command

        command = workflow_command("Record the macOS build features")
        for index, defaults in enumerate([[], ["experimental-idle-flush"]]):
            with self.subTest(defaults=defaults):
                source = self.root / str(index)
                crate = source / "crates/box"
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                manifest = (
                    '[package]\nname = "strands-box"\nversion = "0.1.1"\nedition = "2021"\n'
                    '[features]\nexperimental-idle-flush = []\nnative-filesystem-policy = []\n'
                )
                if defaults:
                    manifest += "default = " + json.dumps(defaults) + "\n"
                (crate / "Cargo.toml").write_text(manifest)
                (source / "dist").mkdir()
                archive = source / "dist/box-v0.1.1-aarch64-apple-darwin.tar.gz"
                archive.write_bytes(b"unsigned archive fixture")
                runner_temp = source / "runner-temp"
                runner_temp.mkdir()
                source_sha = str(index + 1) * 40
                environment = {
                    **os.environ, "NEW_TAG": "v0.1.1", "SOURCE_SHA": source_sha,
                    "RUNNER_TEMP": str(runner_temp),
                }
                result = subprocess.run(["bash", "-c", command], cwd=source, env=environment,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                path = archive.with_name("box-v0.1.1-aarch64-apple-darwin.build-metadata.json")
                metadata = json.loads(path.read_text())
                expected = sorted(defaults + ["native-filesystem-policy"])
                self.assertEqual(metadata, {
                    "source_sha": source_sha, "features": expected,
                    "input_sha256": release.digest(archive),
                })
                self.assertEqual(release.build_features(path, source_sha, archive), expected)

    def test_release_receipt_keeps_selected_build_features(self):
        archive = self.build()
        for index, features in enumerate([
            ["native-filesystem-policy"],
            ["native-filesystem-policy", "experimental-idle-flush"],
        ]):
            with self.subTest(features=features):
                metadata, value = self.build_metadata(archive, features)
                args = release.argparse.Namespace(
                    input=archive, output=self.root / f"signed-{index}.tar.gz",
                    work=self.root / f"work-{index}", version="0.1.1",
                    source_sha=value["source_sha"], build_metadata=metadata,
                    notary_secret=None, notary_keychain_profile="fixture",
                )

                def run(command, **options):
                    if command[0] == "gtar":
                        Path(command[2]).write_bytes(b"signed archive fixture")
                    return subprocess.CompletedProcess(command, 0, "", "")

                with patch.object(release, "Signer") as constructor, \
                        patch.object(release, "verify"), \
                        patch.object(release, "verify_notarization"), \
                        patch.object(release, "notarize", return_value=self.SUBMISSION), \
                        patch.object(release, "notarytool", return_value=
                                     subprocess.CompletedProcess([], 0, "", "")), \
                        patch.object(release.subprocess, "run", side_effect=run):
                    signer = constructor.return_value
                    signer.team = "ABCDE12345"
                    signer.profile = "fixture"
                    signer.sign.side_effect = lambda directory, *unused: directory
                    release.release(args)
                receipt = json.loads((args.work / "receipt.json").read_text())
                self.assertEqual(receipt["features"], sorted(features))
                self.assertEqual(receipt["source_sha"], value["source_sha"])
                self.assertEqual(receipt["input_sha256"], value["input_sha256"])

    def test_build_features_rejects_invalid_or_mismatched_metadata(self):
        archive = self.build()
        path, valid = self.build_metadata(archive)
        cases = [
            None,
            [],
            {key: value for key, value in valid.items() if key != "features"},
            {**valid, "unexpected": True},
            {**valid, "source_sha": "b" * 40},
            {**valid, "source_sha": 123},
            {**valid, "source_sha": "A" * 40},
            {**valid, "input_sha256": "0" * 64},
            {**valid, "input_sha256": 123},
            {**valid, "features": "native-filesystem-policy"},
            {**valid, "features": []},
            {**valid, "features": ["native-filesystem-policy", None]},
            {**valid, "features": ["native-filesystem-policy", ""]},
            {**valid, "features": ["native-filesystem-policy"] * 2},
            {**valid, "features": ["experimental-idle-flush"]},
        ]
        for value in cases:
            with self.subTest(metadata=value):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    release.build_features(path, valid["source_sha"], archive)
        path.write_text("not json")
        with self.assertRaises(ValueError):
            release.build_features(path, valid["source_sha"], archive)

    def test_release_rejects_metadata_before_creating_work_or_signing(self):
        archive = self.build()
        metadata, value = self.build_metadata(archive)
        archive.write_bytes(b"different archive")
        work = self.root / "work"
        args = release.argparse.Namespace(
            input=archive, work=work, source_sha=value["source_sha"], build_metadata=metadata,
        )
        with patch.object(release, "Signer") as constructor:
            with self.assertRaisesRegex(ValueError, "input SHA-256 mismatch"):
                release.release(args)
        constructor.assert_not_called()
        self.assertFalse(work.exists())

    def test_build_extracts_only_the_three_regular_binaries(self):
        target = self.root / "binaries"
        release.unpack_build(self.build(), target)
        self.assertEqual(set(p.name for p in target.iterdir()), set(release.BINARIES))
        self.assertTrue(all(p.stat().st_mode & 0o111 for p in target.iterdir()))

    def test_build_rejects_traversal_symlinks_duplicates_and_unexpected_files(self):
        for name, kind in [
            ("../outside", tarfile.REGTYPE),
            ("box", tarfile.SYMTYPE),
            ("box", tarfile.REGTYPE),
            ("unexpected", tarfile.REGTYPE),
        ]:
            with self.subTest(name=name, kind=kind):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/tmp/outside"
                with self.assertRaises(ValueError):
                    release.unpack_build(self.build(entry), self.root / ("out-" + str(kind)))
                for p in self.root.glob("out-*"):
                    p.rmdir()

    def test_build_rejects_missing_helper(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            release.unpack_build(self.build(missing=release.BINARIES[1]), self.root / "out")

    def zip(self, name, mode=stat.S_IFREG | 0o755, duplicate=False):
        archive = self.root / "signed.zip"
        with zipfile.ZipFile(archive, "w") as output:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = mode << 16
            output.writestr(entry, b"code")
            if duplicate:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    output.writestr(entry, b"other")
        return archive

    def test_signed_archive_rejects_unsafe_paths_and_file_types(self):
        cases = [
            ("../outside", stat.S_IFREG),
            ("/Box.app/file", stat.S_IFREG),
            ("Box.app/../../outside", stat.S_IFREG),
            ("Other.app/file", stat.S_IFREG),
            ("Box.app/link", stat.S_IFLNK),
            ("Box.app/pipe", stat.S_IFIFO),
        ]
        for index, (name, kind) in enumerate(cases):
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                release.unpack_signed(self.zip(name, kind), self.root / str(index), "Box.app")
        self.assertFalse((self.root / "outside").exists())

    def test_signed_archive_rejects_duplicate_files(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            release.unpack_signed(self.zip("Box.app/file", duplicate=True),
                                  self.root / "out", "Box.app")

    def test_signed_archive_preserves_executable_mode(self):
        release.unpack_signed(self.zip("Box.app/Contents/MacOS/box"),
                              self.root / "out", "Box.app")
        target = self.root / "out/Box.app/Contents/MacOS/box"
        self.assertEqual(target.read_bytes(), b"code")
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_bundle_places_real_helpers_beside_main_and_requests_endpoint_security(self):
        binaries = self.root / "bin"
        release.unpack_build(self.build(), binaries)
        app = release.prepare_bundle(binaries, self.root / "artifact", "0.1.1-linux-preview.1")
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        self.assertEqual(info, {
            "CFBundleIdentifier": "com.amazon.strands.box",
            "CFBundleExecutable": "box",
            "CFBundleName": "Box",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "0.1.1",
            "CFBundleShortVersionString": "0.1.1",
        })
        self.assertEqual(set(p.name for p in (app / "Contents/MacOS").iterdir()), set(release.BINARIES))
        entitlement = plistlib.loads((app.parent / "SIGNING_METADATA/Box.entitlements").read_bytes())
        self.assertEqual(entitlement, {release.ENTITLEMENT: True})

    def test_profile_selection_enables_profile_fetching_and_helpers_use_developer_id(self):
        self.assertEqual(release.manifest("ABCDEFGHIJ", "profile"), {
            "type": "app", "os": "osx", "name": "Box",
            "outputs": [{"label": "macos", "path": "Box.app"}],
            "app": {
                "identifier": "com.amazon.strands.box",
                "signing_requirements": {
                    "team_id": "ABCDEFGHIJ",
                    "profile_name": "profile",
                    "profile_type": "distribution",
                    "signing_args": {"entitlements_path": "SIGNING_METADATA/Box.entitlements"},
                },
            },
        })
        self.assertEqual(release.manifest("ABCDEFGHIJ"), {
            "type": "app", "os": "osx", "name": "Box",
            "outputs": [{"label": "macos", "path": "EXECUTABLES_TO_SIGN"}],
            "app": {
                "identifier": "com.amazon.strands.box",
                "signing_requirements": {
                    "team_id": "ABCDEFGHIJ",
                    "certificate_type": "developerIDAppDistribution",
                },
            },
        })

    def test_launcher_preserves_arguments_and_executes_the_real_bundle_path(self):
        app = self.root / "input.app"
        binary = app / "Contents/MacOS/box"
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@"\nexit 17\n')
        binary.chmod(0o755)
        package = self.root / "directory with spaces"
        release.stage_package(app, package)
        result = subprocess.run([str(package / "box"), "two words", "*.txt", ""],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout.splitlines(), [
            str(package / "Box.app/Contents/MacOS/box"), "two words", "*.txt", "",
        ])

    KEY = "-----BEGIN PRIVATE KEY-----\nMIGT\n-----END PRIVATE KEY-----\n"
    SUBMISSION = "2efe2717-52ef-43a5-96dc-0797e4ca1041"

    def test_notary_credential_requires_a_key_id_and_a_private_key(self):
        valid = {"key_id": "ABCDE12345", "private_key": self.KEY}
        self.assertEqual(release.notary_credential(json.dumps(valid)),
                         ("api-key", "ABCDE12345", self.KEY))
        for secret in ["", "not json", "[]", json.dumps({"private_key": self.KEY}),
                       json.dumps({**valid, "key_id": "short"}),
                       json.dumps({**valid, "key_id": "abcde12345"}),
                       json.dumps({"key_id": "ABCDE12345"}),
                       json.dumps({**valid, "private_key": "app-specific-password"})]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                release.notary_credential(secret)

    def test_notary_credential_accepts_an_apple_id_with_an_app_specific_password(self):
        valid = {"apple_id": "notary@example.com", "app_specific_password": "abcd-efgh-ijkl-mnop"}
        self.assertEqual(release.notary_credential(json.dumps(valid)),
                         ("apple-id", "notary@example.com", "abcd-efgh-ijkl-mnop"))
        for secret in [
            {"apple_id": "notary@example.com"},
            {"app_specific_password": "abcd-efgh-ijkl-mnop"},
            {**valid, "apple_id": "notary"},
            {**valid, "apple_id": "-notary@example.com"},
            {**valid, "apple_id": "two words@example.com"},
            {**valid, "app_specific_password": "the account password"},
            {**valid, "app_specific_password": "ABCD-EFGH-IJKL-MNOP"},
            {**valid, "app_specific_password": "abcd-efgh-ijkl"},
            {**valid, "app_specific_password": ["abcd-efgh-ijkl-mnop"]},
            {**valid, "key_id": "ABCDE12345", "private_key": self.KEY},
            {**valid, "key_id": "ABCDE12345"},
        ]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                release.notary_credential(json.dumps(secret))

    def test_api_key_file_is_private_and_removed_after_use(self):
        credential = ("api-key", "ABCDE12345", self.KEY)
        with release.notary_auth(credential=credential, team="ABCDE12345") as auth:
            path = Path(auth.options[1])
            self.assertEqual(auth.options, ["--key", str(path), "--key-id", "ABCDE12345"])
            self.assertIsNone(auth.password)
            self.assertEqual(path.read_text(), self.KEY)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(path.exists())
        with self.assertRaises(RuntimeError):
            with release.notary_auth(credential=credential, team="ABCDE12345") as auth:
                path = Path(auth.options[1])
                raise RuntimeError
        self.assertFalse(path.exists())
        with release.notary_auth("local-profile") as auth:
            self.assertEqual(auth.options, ["--keychain-profile", "local-profile"])

    def test_app_specific_password_goes_only_to_standard_input_and_is_never_printed(self):
        credential = ("apple-id", "notary@example.com", "abcd-efgh-ijkl-mnop")
        calls = []

        def run(command, **options):
            calls.append((command, options))
            return subprocess.CompletedProcess(
                command, 1, "", "Password for notary@example.com: Error: 401 for notary@example.com")

        output = io.StringIO()
        with patch.dict(release.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch("sys.stdout", output), \
                patch.object(release.subprocess, "run", side_effect=run):
            with release.notary_auth(credential=credential, team="ABCDE12345") as auth:
                result = release.notarytool(auth, "history", "--output-format", "json")
        command, options = calls[0]
        self.assertEqual(command, ["xcrun", "notarytool", "history", "--output-format", "json",
                                   "--apple-id", "notary@example.com", "--team-id", "ABCDE12345"])
        self.assertNotIn("abcd-efgh-ijkl-mnop", " ".join(command))
        self.assertEqual(options["input"], "abcd-efgh-ijkl-mnop\n")
        self.assertTrue(options["start_new_session"])
        self.assertEqual(result.stderr, "Error: 401 for <apple-id>")
        self.assertEqual(output.getvalue(), "")
        calls.clear()
        with patch.object(release.subprocess, "run", side_effect=run):
            release.notarytool(release.NotaryAuth(["--keychain-profile", "p"]), "history")
        self.assertNotIn("input", calls[0][1])

    def notarize(self, submission, staple_failures=0):
        calls = []

        def run(command, **options):
            calls.append(command)
            if command[:3] == ["xcrun", "notarytool", "submit"]:
                return subprocess.CompletedProcess(command, 0, submission, "")
            if command[:3] == ["xcrun", "stapler", "staple"]:
                attempts = sum(1 for call in calls if call[:3] == command[:3])
                return subprocess.CompletedProcess(command, int(attempts <= staple_failures), "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        auth = release.NotaryAuth(["--keychain-profile", "test"])
        with patch.object(release.subprocess, "run", side_effect=run), \
                patch.object(release.time, "sleep"):
            try:
                return release.notarize(self.root / "Box.app", auth, self.root / "evidence"), calls
            except ValueError as error:
                return error, calls

    def test_notarization_staples_only_after_apple_accepts(self):
        accepted = json.dumps({"id": self.SUBMISSION, "status": "Accepted", "message": "done"})
        result, calls = self.notarize(accepted)
        self.assertEqual(result, self.SUBMISSION)
        self.assertEqual([call[:3] for call in calls], [
            ["ditto", "-c", "-k"], ["xcrun", "notarytool", "submit"],
            ["xcrun", "notarytool", "log"], ["xcrun", "stapler", "staple"],
        ])
        self.assertIn("--wait", calls[1])
        self.assertEqual(calls[1][calls[1].index("--keychain-profile") + 1], "test")
        saved = json.loads((self.root / "evidence/submission.json").read_text())
        self.assertEqual(saved["status"], "Accepted")
        for status in ("Invalid", "Rejected", "In Progress", None):
            with self.subTest(status=status):
                result, calls = self.notarize(json.dumps({"id": self.SUBMISSION, "status": status}))
                self.assertIsInstance(result, ValueError)
                self.assertNotIn(["xcrun", "stapler", "staple"], [call[:3] for call in calls])

    def test_notarization_keeps_the_apple_id_and_password_out_of_saved_evidence(self):
        auth = release.NotaryAuth(["--apple-id", "notary@example.com", "--team-id", "ABCDE12345"],
                                  "abcd-efgh-ijkl-mnop", "notary@example.com")
        calls = []

        def run(command, **options):
            calls.append((command, options))
            if command[:3] == ["xcrun", "notarytool", "submit"]:
                return subprocess.CompletedProcess(command, 1, "", (
                    "Password for notary@example.com: Error: abcd-efgh-ijkl-mnop "
                    "was refused for notary@example.com"))
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(release.subprocess, "run", side_effect=run), \
                self.assertRaises(ValueError) as raised:
            release.notarize(self.root / "Box.app", auth, self.root / "evidence")
        saved = (self.root / "evidence/submission.json").read_text()
        for value in ("notary@example.com", "abcd-efgh-ijkl-mnop"):
            self.assertNotIn(value, saved)
            self.assertNotIn(value, str(raised.exception))
        submit = next(options for command, options in calls
                      if command[:3] == ["xcrun", "notarytool", "submit"])
        self.assertEqual(submit["input"], "abcd-efgh-ijkl-mnop\n")

    def test_notarization_requires_a_submission_id(self):
        for output in ["", "not json", "[]", json.dumps({"message": "Invalid credentials"}),
                       json.dumps({"id": "../../escape", "status": "Accepted"})]:
            with self.subTest(output=output):
                (self.root / "evidence/submission.json").unlink(missing_ok=True)
                result, calls = self.notarize(output)
                self.assertIsInstance(result, ValueError)
                self.assertEqual(len(calls), 2)
                self.assertTrue((self.root / "evidence/submission.json").exists())

    def test_stapling_retries_then_fails(self):
        accepted = json.dumps({"id": self.SUBMISSION, "status": "Accepted"})
        result, calls = self.notarize(accepted, staple_failures=2)
        self.assertEqual(result, self.SUBMISSION)
        self.assertEqual(sum(call[:3] == ["xcrun", "stapler", "staple"] for call in calls), 3)
        result, calls = self.notarize(accepted, staple_failures=5)
        self.assertIsInstance(result, ValueError)
        self.assertEqual(sum(call[:3] == ["xcrun", "stapler", "staple"] for call in calls), 5)

    def test_secret_arn_accepts_secrets_manager_arns_only(self):
        import re

        for value in [
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:box/notary-AbCdEf",
            "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:notary_key+1=@.-x",
        ]:
            with self.subTest(value=value):
                self.assertTrue(re.fullmatch(release.SECRET_ARN, value))
        for value in [
            "", "notary", "arn:aws:secretsmanager:", "arn:aws:s3:::bucket",
            "arn:aws:secretsmanager:us-west-2:12345:secret:x",
            "arn:aws:secretsmanager:us-west-2:123456789012:other:x",
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:",
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:x y",
        ]:
            with self.subTest(value=value):
                self.assertIsNone(re.fullmatch(release.SECRET_ARN, value))

    def test_sign_requires_exactly_one_notarization_credential(self):
        script = Path(release.__file__)
        base = [sys.executable, str(script), "sign", "--input", "unused", "--output", "unused",
                "--work", str(self.root / "work"), "--version", "0.1.1", "--source-sha", "a" * 40,
                "--build-metadata", "unused"]
        for extra, code in [
            ([], 2),
            (["--notary-secret", "arn:aws:secretsmanager:x", "--notary-keychain-profile", "p"], 2),
            (["--notary-secret", "my-secret"], 1),
            (["--notary-secret", "arn:aws:secretsmanager:"], 1),
            (["--notary-secret", "arn:aws:secretsmanager:us-west-2:123456789012:other:x"], 1),
            (["--notary-secret", ""], 1),
            (["--notary-keychain-profile", ""], 1),
        ]:
            with self.subTest(extra=extra):
                result = subprocess.run(base + extra, capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse((self.root / "work").exists())


class WorkflowGateTests(unittest.TestCase):
    def test_release_source_cannot_select_the_verification_harness(self):
        import re
        import shlex
        from test_release_source import WORKFLOW, workflow_command

        workflow = WORKFLOW.read_text()
        job = workflow.split("\n  verify-macos:\n", 1)[1].split("\n  inspect:\n", 1)[0]
        checkouts = re.findall(r"^\s+ref:\s*(.+)$", job, re.MULTILINE)
        self.assertEqual(checkouts, ["${{ github.sha }}"])
        command = workflow_command("Verify installation and signed native enforcement")
        lines = command.replace("\\\n", "").splitlines()
        cargo = next(line.strip() for line in lines if line.lstrip().startswith("cargo "))
        arguments = shlex.split(cargo.split("2>&1 | tee", 1)[0])
        self.assertEqual(arguments, [
            "cargo", "test", "--manifest-path", "test-native-filesystem/Cargo.toml",
            "--locked", "--", "--test-threads=1",
        ])

    def test_signing_source_guard_refuses_forks_branches_and_unmerged_sources(self):
        from test_release_source import workflow_command
        import os

        command = workflow_command("Validate signing mode and source")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
            env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
                   "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com"}
            subprocess.run(["git", "commit", "--allow-empty", "-qm", "main"], cwd=root, env=env, check=True)
            main = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            subprocess.run(["git", "update-ref", "refs/remotes/origin/main", main], cwd=root, check=True)
            subprocess.run(["git", "commit", "--allow-empty", "-qm", "candidate"], cwd=root, env=env, check=True)
            candidate = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            for repo, ref, sha, success in [
                ("strands-agents/box", "refs/heads/main", main, True),
                ("strands-agents/box", "refs/heads/feature/test", main, False),
                ("someone/box", "refs/heads/main", main, False),
                ("strands-agents/box", "refs/heads/main", candidate, False),
            ]:
                with self.subTest(repo=repo, ref=ref, sha=sha):
                    result = subprocess.run(["bash", "-c", command], cwd=root, env={
                        **env, "REPOSITORY": repo, "WORKFLOW_REF": ref, "RELEASE_SHA": sha,
                        "PREMERGE_TEST": "false", "DRY_RUN": "true", "SIGN_MACOS": "true",
                    }, capture_output=True)
                    self.assertEqual(result.returncode == 0, success)

    def test_premerge_mode_requires_dry_run_branch_upstream_and_main_source(self):
        import os
        from test_release_source import ReleaseSourceTests, workflow_command

        fixture = ReleaseSourceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        command = workflow_command("Validate signing mode and source")
        valid = {
            **os.environ, "PREMERGE_TEST": "true", "DRY_RUN": "true", "SIGN_MACOS": "true",
            "REPOSITORY": "strands-agents/box",
            "WORKFLOW_REF": "refs/heads/feature/macos-release-notarization",
            "RELEASE_SHA": fixture.main,
        }
        changes = [
            ({}, True),
            ({"DRY_RUN": "false"}, False),
            ({"SIGN_MACOS": "false"}, False),
            ({"REPOSITORY": "someone/box"}, False),
            ({"WORKFLOW_REF": "refs/heads/main"}, False),
            ({"WORKFLOW_REF": "refs/heads/feature/other"}, False),
            ({"RELEASE_SHA": fixture.candidate}, False),
            ({"PREMERGE_TEST": "false"}, False),
        ]
        for change, success in changes:
            with self.subTest(change=change):
                result = subprocess.run(["bash", "-c", command], cwd=fixture.root,
                                        env={**valid, **change}, capture_output=True)
                self.assertEqual(result.returncode == 0, success)

    def test_test_commit_pins_refuse_missing_malformed_and_different_commits(self):
        import os
        from test_release_source import workflow_command

        command = workflow_command("Check approved test commits")
        valid = {**os.environ, "APPROVED_WORKFLOW_SHA": "a" * 40, "WORKFLOW_SHA": "a" * 40,
                 "APPROVED_SOURCE_SHA": "b" * 40, "SOURCE_SHA": "b" * 40}
        cases = [({}, True)]
        for key in ("APPROVED_WORKFLOW_SHA", "APPROVED_SOURCE_SHA"):
            for value in ("", "main", "c" * 40):
                cases.append(({key: value}, False))
        for change, success in cases:
            with self.subTest(change=change):
                result = subprocess.run(["bash", "-c", command], env={**valid, **change},
                                        capture_output=True)
                self.assertEqual(result.returncode == 0, success)

    def test_premerge_publication_jobs_are_excluded(self):
        from test_release_source import WORKFLOW

        workflow = WORKFLOW.read_text()
        for name in ("approve-release", "release", "verify-published"):
            job = workflow.split(f"\n  {name}:\n", 1)[1].split("\n  #", 1)[0]
            condition = job.split("    if: |\n", 1)[1].split("    runs-on:", 1)[0]
            self.assertIn("inputs.dry_run != true &&", condition)
            self.assertIn("inputs.premerge_signing_test != true &&", condition)

    def test_signing_notarizes_with_the_environment_credential_secret(self):
        from test_release_source import WORKFLOW, workflow_command

        job = WORKFLOW.read_text().split("\n  sign-macos:\n", 1)[1].split("\n  verify-macos:\n", 1)[0]
        self.assertIn("NOTARY_CREDENTIAL_SECRET: ${{ vars.NOTARY_CREDENTIAL_SECRET }}", job)
        command = workflow_command("Sign, notarize, and staple the application")
        self.assertIn('--notary-secret "$NOTARY_CREDENTIAL_SECRET"', command)
        self.assertNotIn("--notary-keychain-profile", command)

    def test_inspection_refuses_a_macos_package_without_a_stapled_ticket(self):
        import os
        from test_release_source import WORKFLOW, workflow_command

        name = "Assert the macOS package carries its notarization ticket"
        step = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
        self.assertTrue(step.startswith("        if: needs.verify-macos.result == 'success'\n"))
        command = workflow_command(name)
        signature = "./Box.app/Contents/_CodeSignature/CodeResources"
        for members, success in [
            (["./box", signature, "./Box.app/Contents/CodeResources"], True),
            (["./box", signature], False),
            (["./box"], False),
            (None, False),
        ]:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "release").mkdir()
                if members is not None:
                    path = Path(directory) / "release/box-v0.1.1-aarch64-apple-darwin.tar.gz"
                    with tarfile.open(path, "w:gz") as archive:
                        for member in members:
                            archive.addfile(tarfile.TarInfo(member), io.BytesIO(b""))
                result = subprocess.run(["bash", "-c", command], cwd=directory,
                                        env={**os.environ, "NEW_TAG": "v0.1.1"}, capture_output=True)
                self.assertEqual(result.returncode == 0, success)


if __name__ == "__main__":
    unittest.main()
