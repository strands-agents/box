import importlib.util
import io
import json
from pathlib import Path
import plistlib
import stat
import subprocess
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
            "WORKFLOW_REF": "refs/heads/feature/macos-release-signing",
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


if __name__ == "__main__":
    unittest.main()
