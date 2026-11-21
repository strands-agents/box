import argparse
import datetime
import fnmatch
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import types
import unittest
from unittest.mock import call, patch
import zipfile

spec = importlib.util.spec_from_file_location(
    "macos_release", Path(__file__).with_name("macos-release-cli.py")
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/deploy-box-artifact.yml"
# The reusable workflow that WORKFLOW's cli job calls to build, sign, and bundle the CLI.
CLI_WORKFLOW = WORKFLOW.with_name("cli-release.yml")
TEAM = "ABCDE12345"
KEY = "-----BEGIN PRIVATE KEY-----\nMIGT\n-----END PRIVATE KEY-----\n"
SUBMISSION = "2efe2717-52ef-43a5-96dc-0797e4ca1041"
# The files the release build packs beside the programs. Signing must keep them unchanged.
BUILD_FILES = {
    "release.json": b'{"box_version": "0.1.0"}\n',
    "resources/config.toml": b"starters = []\n",
    "resources/editing-box-profile.md": b"# Guide\n",
    "resources/packs/claude/pack.toml": b"[pack]\n",
    "resources/plugins/1password/plugin.toml": b"[plugin]\n",
}


def requirement(identifier):
    return (
        f'=anchor apple generic and identifier "{identifier}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
        f'and certificate leaf[subject.OU] = "{TEAM}"'
    )


# A GitHub job ID at the top of the jobs section, with an optional trailing comment.
JOB = re.compile(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(?:#.*)?$")


def workflow_blocks():
    # The jobs of both release workflow files. Box Core's build, sign-macos, and verify-macos
    # share their IDs with the CLI's, and test_macos_release.py tests Box Core's, so the CLI's
    # job wins here.
    blocks = {}
    for path in (CLI_WORKFLOW, WORKFLOW):
        jobs = path.read_text().split("\njobs:\n", 1)[1]
        starts = [match.start() for match in JOB.finditer(jobs)] + [len(jobs)]
        for start, end in zip(starts, starts[1:]):
            blocks.setdefault(JOB.match(jobs, start).group(1), jobs[start:end])
    return blocks


def workflow_job(name):
    return workflow_blocks()[name]


def workflow_jobs():
    return list(workflow_blocks())


def workflow_command(name):
    # A step that both files have is the CLI's, as in workflow_blocks.
    found = [path for path in (CLI_WORKFLOW, WORKFLOW)
             if f"      - name: {name}" in path.read_text().splitlines()]
    assert found, f"step {name!r} is in no release workflow file"
    lines = found[0].read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    start = lines.index("        run: |", start) + 1
    end = start
    while end < len(lines) and (not lines[end] or lines[end].startswith("          ")):
        end += 1
    return textwrap.dedent("\n".join(lines[start:end]))


def workflow_step(job, name):
    # One step of a job, from its name to the next step.
    block = workflow_job(job)
    start = block.index(f"      - name: {name}\n")
    end = block.find("\n      - ", start)
    return block[start:] if end < 0 else block[start:end + 1]


def signature(identifier=release.IDENTIFIERS["box"], team=TEAM, flags="0x10000(runtime)",
              authority="Developer ID Application: Example (ABCDE12345)", timestamp=True):
    return "\n".join([
        "Executable=/tmp/box", f"Identifier={identifier}", "Format=Mach-O thin (arm64)",
        f"CodeDirectory v=20500 size=100 flags={flags} hashes=1+7 location=embedded",
        f"Authority={authority}", "Authority=Developer ID Certification Authority",
        "Authority=Apple Root CA",
        "Timestamp=Nov 2, 2026 at 01:00:00" if timestamp else "Signed Time=Nov 2, 2026",
        f"TeamIdentifier={team}", "",
    ])


class MacOSReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def build(self, extra=None, missing=None, program_mode=0o755):
        # Shaped like the release build's archive: no top folder, and every folder listed.
        archive = self.root / "build.tar.gz"
        files = {**{name: b"code" for name in release.BINARIES}, **BUILD_FILES}
        folders = [".", "resources", "resources/packs", "resources/packs/claude",
                   "resources/plugins", "resources/plugins/1password"]
        with tarfile.open(archive, "w:gz") as output:
            for name in [*folders, *files]:
                if missing and (name == missing or name.startswith(missing + "/")):
                    continue
                member = tarfile.TarInfo(name if name == "." else "./" + name)
                if name in folders:
                    member.type, member.mode = tarfile.DIRTYPE, 0o755
                    output.addfile(member)
                else:
                    member.size = len(files[name])
                    member.mode = program_mode if name in release.BINARIES else 0o644
                    output.addfile(member, io.BytesIO(files[name]))
            if extra is not None:
                output.addfile(extra)
        return archive

    def binaries(self, name="signed"):
        directory = self.root / name
        directory.mkdir()
        for binary in release.BINARIES:
            (directory / binary).write_bytes(b"code")
            (directory / binary).chmod(0o755)
        return directory

    def test_build_splits_the_programs_from_the_files_to_keep(self):
        programs, kept = self.root / "programs", self.root / "kept"
        release.unpack_build(self.build(program_mode=0o644), programs, kept)
        self.assertEqual(sorted(p.name for p in programs.iterdir()), sorted(release.BINARIES))
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o755 for p in programs.iterdir()))
        self.assertEqual(sorted(p.relative_to(kept).as_posix() for p in kept.rglob("*") if p.is_file()),
                         sorted(BUILD_FILES))
        for name, data in BUILD_FILES.items():
            self.assertEqual(((kept / name).read_bytes(), (kept / name).stat().st_mode & 0o777),
                             (data, 0o644))

    def test_build_refuses_each_unexpected_entry_before_unpacking_any(self):
        for index, (name, kind, message) in enumerate([
            ("../outside", tarfile.REGTYPE, "Unsafe"),
            ("resources/../../outside", tarfile.REGTYPE, "Unsafe"),
            ("/tmp/outside", tarfile.REGTYPE, "Unsafe"),
            (".", tarfile.REGTYPE, "Unexpected"),
            ("box", tarfile.SYMTYPE, "Unexpected"),
            ("release.json", tarfile.SYMTYPE, "Unexpected"),
            ("strands-box", tarfile.REGTYPE, "Unexpected"),
            ("._box", tarfile.REGTYPE, "metadata"),
            ("resources/packs/claude/._pack.toml", tarfile.REGTYPE, "metadata"),
            ("resources/packs/claude/link.toml", tarfile.SYMTYPE, "Unexpected"),
            ("resources/packs/claude/copy.toml", tarfile.LNKTYPE, "Unexpected"),
            ("resources/packs/pipe", tarfile.FIFOTYPE, "Unexpected"),
            ("box", tarfile.REGTYPE, "Duplicate"),
            ("resources//config.toml", tarfile.REGTYPE, "Duplicate"),
        ]):
            with self.subTest(name=name, kind=kind):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/tmp/outside"
                programs, kept = self.root / f"programs-{index}", self.root / f"kept-{index}"
                with self.assertRaisesRegex(ValueError, message):
                    release.unpack_build(self.build(entry), programs, kept)
                self.assertEqual([*programs.iterdir(), *kept.iterdir()], [])

    def test_build_refuses_a_missing_program_release_file_or_packs(self):
        for index, (missing, message) in enumerate([
            (release.BINARIES[1], "Incomplete"),
            ("release.json", "Incomplete"),
            ("resources/packs", "Missing pack resources"),
        ]):
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ValueError, message):
                    release.unpack_build(self.build(missing=missing), self.root / f"programs-{index}",
                                         self.root / f"kept-{index}")

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

    def test_signed_archive_refuses_each_unsafe_entry(self):
        cases = [
            ("../outside", stat.S_IFREG, "Unsafe"),
            ("/EXECUTABLES_TO_SIGN/box", stat.S_IFREG, "Unsafe"),
            ("EXECUTABLES_TO_SIGN/../../outside", stat.S_IFREG, "Unsafe"),
            ("Other/box", stat.S_IFREG, "root"),
            ("EXECUTABLES_TO_SIGN/link", stat.S_IFLNK, "symlink"),
            ("EXECUTABLES_TO_SIGN/pipe", stat.S_IFIFO, "file type"),
        ]
        for index, (name, kind, message) in enumerate(cases):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                release.unpack_signed(self.zip(name, kind), self.root / str(index), release.SIGNED)
        self.assertFalse((self.root / "outside").exists())

    def test_signed_archive_rejects_duplicate_files(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            release.unpack_signed(self.zip("EXECUTABLES_TO_SIGN/box", duplicate=True),
                                  self.root / "out", release.SIGNED)

    def test_signed_archive_refuses_more_than_the_size_limit(self):
        self.assertEqual(release.SIGNED_LIMIT, 1 << 30)
        with patch.object(release, "SIGNED_LIMIT", 3), self.assertRaisesRegex(ValueError, "exceeds"):
            release.unpack_signed(self.zip("EXECUTABLES_TO_SIGN/box"), self.root / "out", release.SIGNED)
        release.unpack_signed(self.zip("EXECUTABLES_TO_SIGN/box"), self.root / "ok", release.SIGNED)

    def test_signed_archive_preserves_executable_mode(self):
        release.unpack_signed(self.zip("EXECUTABLES_TO_SIGN/box"), self.root / "out", release.SIGNED)
        target = self.root / "out/EXECUTABLES_TO_SIGN/box"
        self.assertEqual(target.read_bytes(), b"code")
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_manifest_signs_the_executables_with_developer_id(self):
        self.assertEqual(release.manifest(TEAM), {
            "type": "app", "os": "osx", "name": "Box",
            "outputs": [{"label": "macos", "path": "EXECUTABLES_TO_SIGN"}],
            "app": {"identifier": "com.amazon.strands.box", "signing_requirements": {
                "team_id": TEAM, "certificate_type": "developerIDAppDistribution",
            }},
        })

    def check(self, details=None, failing=None, team=TEAM, identifiers=None, unreadable=None):
        requirements = []

        def run(command, **options):
            name = Path(command[-1]).name
            code = 0
            if command[:2] == ["codesign", "--verify"]:
                requirements.append(command[command.index("-R") + 1])
                code = int(name == failing)
            elif command[:2] == ["codesign", "-dvvv"]:
                code = int(name == unreadable)
            if code and options.get("check"):
                raise subprocess.CalledProcessError(code, command)
            text = details or signature((identifiers or release.IDENTIFIERS)[name])
            return subprocess.CompletedProcess(command, code, "", text)

        with patch.object(release.subprocess, "run", side_effect=run):
            release.verify(self.root / "signed", team, self.root / "evidence")
        return requirements

    def test_verify_accepts_a_hardened_timestamped_developer_id_signature(self):
        self.binaries()
        self.assertEqual(release.IDENTIFIERS, {
            "box": "com.amazon.strands.box-cli",
            "strands-box-sock-alias": "com.amazon.strands.box",
            "strands-box-contain-trampoline": "com.amazon.strands.box",
        })
        self.assertEqual(self.check(),
                         [requirement(release.IDENTIFIERS[name]) for name in release.BINARIES])
        saved = json.loads((self.root / "evidence/verification.json").read_text())
        self.assertEqual(saved["identifiers"], release.IDENTIFIERS)
        self.assertEqual(set(saved["binaries"]), set(release.BINARIES))

    def test_verify_refuses_a_wrong_identity_runtime_or_timestamp(self):
        self.binaries()
        for details, message in [
            (signature(identifier="com.example.other"), "identity"),
            (signature(team="ZZZZZ99999"), "identity"),
            (signature(authority="Apple Development: Someone (ABCDE12345)"), "Developer ID"),
            (signature(flags="0x0(none)"), "hardened runtime"),
            (signature(timestamp=False), "timestamp"),
        ]:
            with self.subTest(details=details), self.assertRaisesRegex(ValueError, message):
                self.check(details)
        for name, other in [("box", release.APPLICATION),
                            ("strands-box-sock-alias", release.IDENTIFIERS["box"])]:
            with self.subTest(swapped=name), self.assertRaisesRegex(ValueError, f"identity: {name}"):
                self.check(identifiers={**release.IDENTIFIERS, name: other})
        with self.assertRaisesRegex(ValueError, "team ID"):
            self.check(team="ZZZ")

    def test_verify_refuses_a_bad_signature_a_symlink_or_a_missing_helper(self):
        signed = self.binaries()
        with self.assertRaises(subprocess.CalledProcessError):
            self.check(failing="strands-box-contain-trampoline")
        with self.assertRaises(subprocess.CalledProcessError):
            self.check(unreadable="box")
        (signed / "strands-box-sock-alias").unlink()
        (signed / "strands-box-sock-alias").symlink_to(signed / "box")
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            self.check()
        (signed / "strands-box-sock-alias").unlink()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            self.check()

    def test_notary_credential_requires_a_key_id_and_a_private_key(self):
        valid = {"key_id": "ABCDE12345", "private_key": KEY}
        self.assertEqual(release.notary_credential(json.dumps(valid)), ("api-key", "ABCDE12345", KEY))
        for secret in ["", "not json", "[]", json.dumps({"private_key": KEY}),
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
            {**valid, "key_id": "ABCDE12345", "private_key": KEY},
            {**valid, "key_id": "ABCDE12345"},
        ]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                release.notary_credential(json.dumps(secret))

    def test_api_key_file_is_private_and_removed_after_use(self):
        credential = ("api-key", "ABCDE12345", KEY)
        with release.notary_auth(credential=credential, team=TEAM) as auth:
            path = Path(auth.options[1])
            self.assertEqual(auth.options, ["--key", str(path), "--key-id", "ABCDE12345"])
            self.assertIsNone(auth.password)
            self.assertEqual(path.read_text(), KEY)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(path.exists())
        with self.assertRaises(RuntimeError):
            with release.notary_auth(credential=credential, team=TEAM) as auth:
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
            with release.notary_auth(credential=credential, team=TEAM) as auth:
                result = release.notarytool(auth, "history", "--output-format", "json")
        command, options = calls[0]
        self.assertEqual(command, ["xcrun", "notarytool", "history", "--output-format", "json",
                                   "--apple-id", "notary@example.com", "--team-id", TEAM])
        self.assertNotIn("abcd-efgh-ijkl-mnop", " ".join(command))
        self.assertEqual(options["input"], "abcd-efgh-ijkl-mnop\n")
        self.assertTrue(options["start_new_session"])
        self.assertEqual(result.stderr, "Error: 401 for <apple-id>")
        self.assertEqual(output.getvalue(), "")
        calls.clear()
        with patch.object(release.subprocess, "run", side_effect=run):
            release.notarytool(release.NotaryAuth(["--keychain-profile", "p"]), "history")
        self.assertNotIn("input", calls[0][1])

    def notarize(self, submission):
        calls = []

        def run(command, **options):
            calls.append(command)
            if command[:3] == ["xcrun", "notarytool", "submit"]:
                return subprocess.CompletedProcess(command, 0, submission, "")
            return subprocess.CompletedProcess(command, 0, "", "")

        auth = release.NotaryAuth(["--keychain-profile", "test"])
        with patch.object(release.subprocess, "run", side_effect=run):
            try:
                return release.notarize(self.root / "signed", auth, self.root / "evidence"), calls
            except ValueError as error:
                return error, calls

    def test_notarization_requires_apple_to_accept_the_submission(self):
        accepted = json.dumps({"id": SUBMISSION, "status": "Accepted", "message": "done"})
        result, calls = self.notarize(accepted)
        self.assertEqual(result, SUBMISSION)
        archive = str(self.root / "evidence/box.zip")
        self.assertEqual(calls[0], ["ditto", "-c", "-k", "--keepParent", str(self.root / "signed"), archive])
        submit = calls[1]
        self.assertEqual(submit[:4], ["xcrun", "notarytool", "submit", archive])
        self.assertIn("--wait", submit)
        for flag, value in [("--timeout", "30m"), ("--output-format", "json"), ("--keychain-profile", "test")]:
            self.assertEqual(submit[submit.index(flag) + 1], value)
        self.assertEqual(calls[2][:3], ["xcrun", "notarytool", "log"])
        self.assertEqual(len(calls), 3)
        saved = json.loads((self.root / "evidence/submission.json").read_text())
        self.assertEqual(saved["status"], "Accepted")
        for status in ("Invalid", "Rejected", "In Progress", None):
            with self.subTest(status=status):
                result, _ = self.notarize(json.dumps({"id": SUBMISSION, "status": status}))
                self.assertIsInstance(result, ValueError)

    def test_notarization_keeps_the_apple_id_and_password_out_of_saved_evidence(self):
        auth = release.NotaryAuth(["--apple-id", "notary@example.com", "--team-id", TEAM],
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
            release.notarize(self.root / "signed", auth, self.root / "evidence")
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

    def notarization_check(self, failures):
        attempts = {}

        def run(command, **options):
            name = Path(command[-1]).name
            attempts[name] = attempts.get(name, 0) + 1
            self.assertEqual(command[:-1], ["codesign", "--verify", "--strict",
                                            "--check-notarization", "-R", "=notarized"])
            return subprocess.CompletedProcess(command, int(attempts[name] <= failures), "", "")

        with patch.object(release.subprocess, "run", side_effect=run), \
                patch.object(release.time, "sleep") as sleep:
            try:
                release.verify_notarization(self.root / "signed", self.root / "evidence")
                return None, attempts, sleep.call_args_list
            except ValueError as error:
                return error, attempts, sleep.call_args_list

    def test_notarization_check_retries_each_binary_then_fails(self):
        error, attempts, sleeps = self.notarization_check(failures=2)
        self.assertIsNone(error)
        self.assertEqual(attempts, {name: 3 for name in release.BINARIES})
        self.assertEqual(sleeps, [call(30)] * 2 * len(release.BINARIES))
        saved = json.loads((self.root / "evidence/notarization.json").read_text())
        self.assertEqual(saved["notarized"], list(release.BINARIES))
        error, attempts, _ = self.notarization_check(failures=5)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(attempts, {"box": 5})

    def test_package_holds_the_signed_programs_beside_the_kept_files(self):
        release.unpack_build(self.build(), self.root / "programs", self.root / "kept")
        signed = self.binaries()
        for name in release.BINARIES:
            (signed / name).write_bytes(b"signed")
        package = self.root / "package"
        release.stage_package(signed, self.root / "kept", package)
        self.assertEqual(sorted(p.name for p in package.iterdir()),
                         sorted([*release.BINARIES, "release.json", "resources"]))
        for name in release.BINARIES:
            self.assertEqual(((package / name).read_bytes(), (package / name).stat().st_mode & 0o777),
                             (b"signed", 0o755))
        for name, data in BUILD_FILES.items():
            self.assertEqual((package / name).read_bytes(), data)

    def run_release(self, refused=False, missing=None):
        signed, created = [], []

        class Signer:
            team = TEAM

            def __init__(self):
                created.append(self)

            def sign(self, artifact, configuration, work, phase):
                signed.append((artifact, configuration, phase))
                # Like the service, return new copies of the programs in a folder of their own.
                output = work / "signer-output"
                shutil.copytree(artifact, output)
                for program in (output / release.SIGNED).iterdir():
                    program.write_bytes(b"signed " + program.read_bytes())
                return output

        def run(command, **options):
            self.assertEqual(command[:2], ["gtar", "-czf"])
            Path(command[2]).write_bytes(b"package")
            return subprocess.CompletedProcess(command, 0, "", "")

        self.signed, self.created, self.checks = signed, created, []

        def check(name, result=None):
            def record(directory, *rest):
                self.checks.append((name, Path(directory).resolve()))
                return result
            return record

        self.args = argparse.Namespace(
            input=self.build(missing=missing),
            output=self.root / "dist/box.tar.gz", work=self.root / "work", version="0.1.0",
            source_sha="a" * 40, notary_secret=None, notary_keychain_profile="local")
        history = subprocess.CompletedProcess(
            [], int(refused), "", "Error: HTTP status code: 401" if refused else "")
        with patch.object(release, "Signer", Signer), \
                patch.object(release, "notarytool", return_value=history) as tool, \
                patch.object(release, "verify", side_effect=check("verify")), \
                patch.object(release, "notarize", side_effect=check("notarize", SUBMISSION)), \
                patch.object(release, "verify_notarization", side_effect=check("verify_notarization")), \
                patch.object(release.subprocess, "run", side_effect=run):
            self.tool = tool
            release.release(self.args)

    def test_release_signs_notarizes_and_records_the_package(self):
        self.run_release()
        self.assertEqual(len(self.signed), 1)
        artifact, configuration, phase = self.signed[0]
        self.assertEqual((configuration, phase), (release.manifest(TEAM), "executables"))
        executables = artifact / release.SIGNED
        self.assertEqual([p.name for p in artifact.iterdir()], [release.SIGNED])
        self.assertEqual(sorted(p.name for p in executables.iterdir()), sorted(release.BINARIES))
        receipt = json.loads((self.root / "work/receipt.json").read_text())
        output = self.root / "work/signer-output" / release.SIGNED
        # The signer's copies are checked: their signatures, then Apple, then each ticket.
        self.assertEqual(self.checks, [(name, output.resolve()) for name in
                                       ("verify", "notarize", "verify_notarization")])
        self.assertEqual(receipt, {
            "source_sha": "a" * 40, "version": "0.1.0",
            "input_sha256": release.digest(self.args.input),
            "output_sha256": release.digest(self.args.output),
            "binaries": {name: release.digest(output / name) for name in release.BINARIES},
            "notarized": True, "notarization_id": SUBMISSION,
        })
        package = self.root / "work/package"
        for name in release.BINARIES:
            self.assertEqual((package / name).read_bytes(), b"signed code")
        for name, data in BUILD_FILES.items():
            self.assertEqual((package / name).read_bytes(), data)

    def test_release_checks_the_notarization_credential_before_any_signing_request(self):
        with self.assertRaisesRegex(ValueError, "credentials were refused"):
            self.run_release(refused=True)
        self.assertEqual(self.tool.call_args.args[1:], ("history", "--output-format", "json"))
        self.assertEqual(self.signed, [])
        self.assertFalse(self.args.output.exists())

    def test_release_and_verify_refuse_a_package_without_packs(self):
        # Release checks the build archive before it calls AWS or Apple.
        with self.assertRaisesRegex(ValueError, "pack resources"):
            self.run_release(missing="resources/packs")
        self.assertEqual((self.created, self.signed), ([], []))
        self.tool.assert_not_called()
        self.assertFalse(self.args.output.exists())
        (self.root / "package").mkdir()
        result = subprocess.run(
            [sys.executable, str(Path(release.__file__)), "verify", "--package",
             str(self.root / "package"), "--evidence", str(self.root / "evidence")],
            capture_output=True, text=True, env={**os.environ, "CD_SIGNER_TEAM_ID": TEAM})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Missing pack resources", result.stderr)

    def sign_with(self, reply, task=SUBMISSION):
        signer = object.__new__(release.Signer)
        signer.bucket = "bucket"
        signer.access_role = "arn:aws:iam::123456789012:role/access"
        uploads, requests = [], []
        signed_zip = self.zip("EXECUTABLES_TO_SIGN/box").read_bytes()

        def request(method, path, body=None):
            requests.append((method, path, body))
            self.assertLessEqual(len(requests), 50, "the signer polled without a deadline")
            return {"signTaskId": task} if method == "POST" else reply(requests[0][2])

        def run(command, **options):
            Path(command[2]).write_bytes(b"archive")
            return subprocess.CompletedProcess(command, 0, "", "")

        signer.s3 = types.SimpleNamespace(
            put_object=lambda **options: uploads.append(
                {key: value for key, value in options.items() if key != "Body"}),
            download_file=lambda bucket, key, path: Path(path).write_bytes(signed_zip))
        signer.request = request
        artifact = self.root / "artifact"
        (artifact / release.SIGNED).mkdir(parents=True, exist_ok=True)
        work = self.root / "work"
        work.mkdir(exist_ok=True)
        phase = f"phase{len(list(work.iterdir()))}"
        clock = types.SimpleNamespace(sleep=lambda seconds: None,
                                      monotonic=itertools.count(0, 100).__next__)
        with patch.object(release.subprocess, "run", side_effect=run), \
                patch.object(release, "time", clock):
            try:
                result = release.Signer.sign(signer, artifact, release.manifest(TEAM), work, phase)
            except (ValueError, TimeoutError) as error:
                result = error
        return result, uploads, requests

    def test_signer_uploads_under_the_boxy_prefix_and_checks_what_the_service_returns(self):
        result, uploads, requests = self.sign_with(lambda body: {"status": "success", **body})
        self.assertTrue((result / "EXECUTABLES_TO_SIGN/box").is_file())
        method, path, body = requests[0]
        self.assertEqual((method, path, body["manifest"]), ("POST", "/v2/sign-tasks", release.manifest(TEAM)))
        location = body["s3ArtifactLocations"]
        self.assertRegex(location["inputKey"],
                         r"^pre-signed/box-release/boxy/[0-9a-f]{32}/phase0/package\.tar\.gz$")
        self.assertRegex(location["outputKey"],
                         r"^signed/box-release/boxy/[0-9a-f]{32}/phase0/package\.tar\.gz$")
        self.assertEqual(uploads, [{"Bucket": "bucket", "Key": location["inputKey"], "IfNoneMatch": "*"}])
        for name, reply, message in [
            ("manifest", lambda body: {"status": "success", **body,
                                       "manifest": {**body["manifest"], "name": "Other"}},
             "manifest mismatch"),
            ("location", lambda body: {"status": "success", **body, "s3ArtifactLocations": {
                **body["s3ArtifactLocations"], "outputKey": "signed/other"}},
             "location mismatch"),
            ("failed", lambda body: {"status": "failed", "errorMessage": "denied"}, "Signing failed"),
        ]:
            with self.subTest(reply=name):
                result, _, _ = self.sign_with(reply)
                self.assertIsInstance(result, ValueError)
                self.assertIn(message, str(result))
        with self.subTest(reply="processing forever"):
            result, _, _ = self.sign_with(lambda body: {"status": "processing"})
            self.assertIsInstance(result, TimeoutError)
            self.assertIn("exceeded 15 minutes", str(result))
        with self.subTest(task="../x"):
            result, _, requests = self.sign_with(lambda body: {"status": "success", **body}, task="../x")
            self.assertIsInstance(result, ValueError)
            self.assertIn("Invalid signing task ID", str(result))
            self.assertEqual(len(requests), 1)

    def test_signer_refuses_an_endpoint_that_is_not_plain_https_and_a_bad_team(self):
        session = types.SimpleNamespace(client=lambda name: None)
        modules = {
            "boto3": types.SimpleNamespace(Session=lambda: session),
            "botocore": types.ModuleType("botocore"),
            "botocore.auth": types.SimpleNamespace(SigV4Auth=object),
            "botocore.awsrequest": types.SimpleNamespace(AWSRequest=object),
            "requests": types.SimpleNamespace(),
        }
        settings = {"AWS_REGION": "us-west-2", "CD_SIGNER_ENDPOINT": "https://signer.example.com/",
                    "CD_SIGNER_BUCKET": "bucket", "CD_SIGNER_BUCKET_ACCESS_ROLE": "role",
                    "CD_SIGNER_TEAM_ID": TEAM}
        with patch.dict(sys.modules, modules), patch.dict(release.os.environ, settings):
            self.assertEqual(release.Signer().endpoint, "https://signer.example.com")
            for endpoint in ["http://signer.example.com", "https://user:pw@signer.example.com",
                             "https://signer.example.com/path", "https://signer.example.com?x=1",
                             "https://signer.example.com#x", "https://"]:
                with self.subTest(endpoint=endpoint), \
                        patch.dict(release.os.environ, {"CD_SIGNER_ENDPOINT": endpoint}), \
                        self.assertRaisesRegex(ValueError, "Invalid signing endpoint"):
                    release.Signer()
            with patch.dict(release.os.environ, {"CD_SIGNER_TEAM_ID": "abcde12345"}), \
                    self.assertRaisesRegex(ValueError, "Invalid Apple team ID"):
                release.Signer()

    def test_secret_arn_accepts_secrets_manager_arns_only(self):
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

    def test_sign_accepts_the_preview_versions(self):
        missing = self.root / "missing.tar.gz"
        for version in ("0.1.1-linux-preview.1", "0.3.0-preview.1"):
            with self.subTest(version=version):
                arguments = [sys.executable, str(release.__file__), "sign", "--input", str(missing),
                             "--output", str(self.root / "output.tar.gz"),
                             "--work", str(self.root / f"work-{version}"),
                             "--version", version, "--source-sha", "a" * 40,
                             "--notary-keychain-profile", "profile"]
                result = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("FileNotFoundError", result.stderr)
                self.assertIn(str(missing), result.stderr)

    def test_sign_refuses_a_bad_source_version_or_credential_before_any_work(self):
        base = [sys.executable, str(Path(release.__file__)), "sign", "--input", "unused",
                "--output", "unused", "--work", str(self.root / "work")]
        valid = ["--version", "0.1.0", "--source-sha", "a" * 40]
        profile = ["--notary-keychain-profile", "p"]
        arn = "Expected a notarization secret ARN"
        for extra, code, message in [
            (valid, 2, "one of the arguments"),
            (valid + ["--notary-secret", "arn:aws:secretsmanager:x"] + profile, 2, "not allowed with"),
            (valid + ["--notary-secret", "my-secret"], 1, arn),
            (valid + ["--notary-secret", "arn:aws:secretsmanager:"], 1, arn),
            (valid + ["--notary-secret", "arn:aws:secretsmanager:us-west-2:123456789012:other:x"], 1, arn),
            (valid + ["--notary-secret", ""], 1, arn),
            (valid + ["--notary-keychain-profile", ""], 1, arn),
            (["--version", "0.1.0", "--source-sha", "abc"] + profile, 1, "full source SHA"),
            (["--version", "0.1", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
            (["--version", "v0.1.0", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
            (["--version", "0.1.0-rc.1", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
            (["--version", "0.1.1-linux-preview.0", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
            (["--version", "0.1.1-linux-preview.01", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
            (["--version", "0.3.0-preview.0", "--source-sha", "a" * 40] + profile, 1, "Invalid release version"),
        ]:
            with self.subTest(extra=extra):
                result = subprocess.run(base + extra, capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertFalse((self.root / "work").exists())



class NativeMacOSReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.profile = "Box CLI Developer ID"
        self.source = "a" * 40
        self.environment = {"CD_SIGNER_TEAM_ID": TEAM, "CD_SIGNER_CLI_PROFILE_NAME": self.profile}
        self.record = {"box_version": "0.1.0", "box_commit": self.source,
                       "core_version": "0.2.5", "core_commit": "b" * 40,
                       "target": "aarch64-apple-darwin"}
        self.files = {**BUILD_FILES, "release.json": json.dumps(self.record).encode()}
        self.input = self.root / "build.tar.gz"
        with tarfile.open(self.input, "w:gz") as archive:
            for name, body in {**dict.fromkeys(release.BINARIES, b"code"), **self.files}.items():
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(body), 0o755 if name in release.BINARIES else 0o644
                archive.addfile(item, io.BytesIO(body))
        self.metadata = self.root / "features.json"
        self.features = {**self.record, "cargo_features": ["strands-box-cli/native-filesystem-policy"],
                         "archive": self.input.name, "archive_sha256": release.digest(self.input),
                         "archive_stage": "unsigned_build", "runtime_qualified": False}
        self.metadata.write_text(json.dumps(self.features))
        self.args = argparse.Namespace(input=self.input, output=self.root / "output.tar.gz",
                                       work=self.root / "work", version="0.1.0", source_sha=self.source,
                                       notary_secret=None, notary_keychain_profile="local",
                                       native_filesystem_policy=True, build_metadata=self.metadata)

    def test_native_preflight_refuses_missing_profile_or_mismatched_build_before_aws(self):
        cases = [("profile", None, "CLI_PROFILE_NAME"), ("metadata", None, "build metadata"),
                 ("box_commit", "c" * 40, "source"),
                 ("archive_sha256", "0" * 64, "SHA-256"),
                 ("cargo_features", [], "native-filesystem-policy"),
                 ("target", "aarch64-unknown-linux-gnu", "target"),
                 ("archive_stage", "signed", "unsigned_build")]
        for field, value, message in cases:
            with self.subTest(field=field):
                environment = self.environment.copy()
                args = argparse.Namespace(**vars(self.args))
                record = self.features.copy()
                if field == "profile":
                    environment.pop("CD_SIGNER_CLI_PROFILE_NAME")
                elif field == "metadata":
                    args.build_metadata = None
                else:
                    record[field] = value
                self.metadata.write_text(json.dumps(record))
                with patch.dict(release.os.environ, environment, clear=True), \
                        patch.object(release, "Signer") as signer, \
                        self.assertRaisesRegex(ValueError, message):
                    release.release(args)
                signer.assert_not_called()
                self.assertFalse(args.output.exists())
                self.assertFalse(args.work.exists())

    def bundle(self):
        programs, kept = self.root / "programs", self.root / "kept"
        release.unpack_build(self.input, programs, kept)
        return release.prepare_native_bundle(programs, kept, self.root / "app-input", "0.1.0")

    def test_native_manifest_and_bundle_keep_cli_identity_helpers_and_resources(self):
        app = self.bundle()
        self.assertEqual(release.manifest(TEAM, self.profile), {
            "type": "app", "os": "osx", "name": "Box",
            "outputs": [{"label": "macos", "path": "Box.app"}],
            "app": {"identifier": "com.amazon.strands.box-cli", "signing_requirements": {
                "team_id": TEAM, "profile_name": self.profile, "profile_type": "distribution",
                "signing_args": {"entitlements_path": "SIGNING_METADATA/Box.entitlements"}}}})
        self.assertEqual(plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleIdentifier"],
                         "com.amazon.strands.box-cli")
        for name in release.BINARIES:
            self.assertEqual((app / "Contents/MacOS" / name).read_bytes(), b"code")
        for name, body in self.files.items():
            self.assertEqual((app / "Contents/Resources" / name).read_bytes(), body)
        self.assertFalse((app / "Contents/MacOS/release.json").exists())
        self.assertEqual(plistlib.loads((app.parent / "SIGNING_METADATA/Box.entitlements").read_bytes()),
                         {"com.apple.developer.endpoint-security.client": True})

    def test_native_launcher_follows_installed_relative_and_absolute_links(self):
        app = self.bundle()
        executable = app / "Contents/MacOS/box"
        executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        executable.chmod(0o755)
        package = self.root / "versions/v0.1.0"
        release.stage_native_package(app, package)
        (self.root / "bin").mkdir()
        (self.root / "current").symlink_to(package)
        entry = self.root / "bin/box"
        entry.symlink_to("../current/box")
        result = subprocess.run([str(entry), "one two", "three"], capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (0, "one two\nthree\n"), result.stderr)
        for name, target in release.NATIVE_LINKS.items():
            self.assertEqual(os.readlink(package / name), target)
        self.assertEqual((package / "resources/config.toml").read_bytes(), self.files["resources/config.toml"])

    def test_native_launcher_ignores_programs_from_an_untrusted_path(self):
        app = self.bundle()
        executable = app / "Contents/MacOS/box"
        executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        executable.chmod(0o755)
        package = self.root / "package with spaces"
        release.stage_native_package(app, package)
        tools = self.root / "untrusted"
        tools.mkdir()
        marker = self.root / "untrusted-command-ran"
        for name in ("dirname", "readlink"):
            program = tools / name
            program.write_text(f'#!/bin/sh\nprintf x > "{marker}"\nexec /usr/bin/{name} "$@"\n')
            program.chmod(0o755)
        entry = self.root / "installed-box"
        entry.symlink_to(package / "box")
        result = subprocess.run([str(entry), "one two"], env={**os.environ, "PATH": str(tools)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (0, "one two\n"), result.stderr)
        self.assertFalse(marker.exists(), "launcher ran a program from the caller's PATH")

    def profile_checks(self, app, mutate=None):
        entitlements = {"com.apple.developer.endpoint-security.client": True,
                        "com.apple.application-identifier": TEAM + ".com.amazon.strands.box-cli",
                        "com.apple.developer.team-identifier": TEAM}
        profile = {"Name": self.profile, "UUID": SUBMISSION, "TeamIdentifier": [TEAM],
                   "ExpirationDate": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                   + datetime.timedelta(days=30), "ProvisionsAllDevices": True,
                   "DeveloperCertificates": [b"certificate"], "Entitlements": dict(entitlements)}
        if mutate:
            mutate(entitlements, profile)
        (app / "Contents/embedded.provisionprofile").write_bytes(b"encoded profile")
        calls = []

        def run(command, **options):
            calls.append(command)
            if command[:2] == ["codesign", "-d"]:
                prefix = next(item.split("=", 1)[1] for item in command if item.startswith("--extract-certificates="))
                Path(prefix + "0").write_bytes(b"certificate")
            name = Path(command[-1]).name
            identifier = release.IDENTIFIERS.get(name, release.IDENTIFIERS["box"])
            return subprocess.CompletedProcess(command, 0, "", signature(identifier))

        def output(command, **options):
            return plistlib.dumps(profile if command[0] == "security" else entitlements)

        with patch.object(release.subprocess, "run", side_effect=run), \
                patch.object(release.subprocess, "check_output", side_effect=output):
            release.verify_native(app, TEAM, self.profile, self.root / "evidence")
        return calls

    def test_native_verification_checks_the_cli_profile_and_every_program(self):
        calls = self.profile_checks(self.bundle())
        requirements = [command[command.index("-R") + 1] for command in calls
                        if command[:2] == ["codesign", "--verify"]]
        self.assertEqual(requirements.count(requirement("com.amazon.strands.box-cli")), 2)
        self.assertEqual(requirements.count(requirement("com.amazon.strands.box")), 2)

    def test_native_verification_refuses_each_missing_or_wrong_authorization(self):
        app = self.bundle()
        cases = [
            (lambda e, p: e.pop("com.apple.developer.endpoint-security.client"), "Endpoint Security"),
            (lambda e, p: p["Entitlements"].update({"com.apple.application-identifier": TEAM + ".com.amazon.strands.box"}), "Application identifier"),
            (lambda e, p: p.update(Name="Core profile"), "provisioning profile"),
            (lambda e, p: p.update(TeamIdentifier=["ZZZZZ99999"]), "provisioning profile"),
            (lambda e, p: p.update(ExpirationDate=datetime.datetime(2020, 1, 1)), "Expired"),
            (lambda e, p: p.update(ProvisionsAllDevices=False, ProvisionedDevices=["one Mac"]), "distribution"),
            (lambda e, p: p.update(DeveloperCertificates=[b"other certificate"]), "certificate"),
        ]
        for mutation, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.profile_checks(app, mutation)

    def run_native_release(self, tamper=None):
        phases = []
        self.phases = phases

        class Signer:
            team = TEAM

            def sign(_, artifact, configuration, work, phase):
                phases.append((phase, configuration))
                output = work / (phase + "-output")
                root = configuration["outputs"][0]["path"]
                shutil.copytree(artifact / root, output / root)
                if phase == "helpers":
                    for path in (output / root).iterdir():
                        path.write_bytes(b"helper " + path.read_bytes())
                else:
                    app = output / root
                    (app / "Contents/MacOS/box").write_bytes(b"app code")
                    (app / "Contents/embedded.provisionprofile").write_bytes(b"profile")
                    if tamper:
                        (app / tamper).write_bytes(b"changed by signer")
                return output

        def run(command, **options):
            if command[:2] == ["gtar", "-czf"]:
                with tarfile.open(command[2], "w:gz") as archive:
                    archive.add(command[4], arcname=".")
            elif command[:3] == ["xcrun", "stapler", "staple"]:
                (Path(command[3]) / "Contents/CodeResources").write_bytes(b"stapled ticket")
            return subprocess.CompletedProcess(command, 0, "",
                signature(release.IDENTIFIERS.get(Path(command[-1]).name, release.IDENTIFIERS["box"])))

        with patch.dict(release.os.environ, self.environment), patch.object(release, "Signer", Signer), \
                patch.object(release, "notarytool", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                patch.object(release, "verify_native"), patch.object(release, "notarize", return_value=SUBMISSION), \
                patch.object(release, "verify_native_notarization"), \
                patch.object(release.subprocess, "run", side_effect=run):
            release.release(self.args)
        return phases, json.loads((self.args.work / "receipt.json").read_text())

    def test_native_release_signs_helpers_then_app_and_records_the_actual_package(self):
        phases, receipt = self.run_native_release()
        self.assertEqual(phases, [("helpers", release.manifest(TEAM)),
                                  ("application", release.manifest(TEAM, self.profile))])
        self.assertTrue(receipt["native_filesystem_policy"])
        self.assertEqual(receipt["source_sha"], self.source)
        self.assertEqual(receipt["cargo_features"], self.features["cargo_features"])
        self.assertEqual(receipt["output_sha256"], release.digest(self.args.output))
        package = self.args.work / "package"
        for name, body in self.files.items():
            self.assertEqual((package / name).read_bytes(), body)
        self.assertEqual((package / "Box.app/Contents/MacOS/box").read_bytes(), b"app code")
        self.assertEqual((package / "Box.app/Contents/CodeResources").read_bytes(), b"stapled ticket")
        with tarfile.open(self.args.output) as archive:
            self.assertEqual(archive.extractfile("./Box.app/Contents/CodeResources").read(), b"stapled ticket")
        for name in release.BINARIES[1:]:
            self.assertEqual((package / name).read_bytes(), b"helper code")

    def test_native_release_refuses_service_changes_to_helpers_or_resources(self):
        for index, target in enumerate(["Contents/MacOS/strands-box-sock-alias",
                                        "Contents/Resources/resources/config.toml",
                                        "Contents/Resources/release.json"]):
            self.args.work = self.root / str(index)
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "changed"):
                self.run_native_release(target)
            self.assertFalse(self.args.output.exists())

    def test_native_receipt_binds_source_archive_and_extracted_bytes(self):
        _, receipt = self.run_native_release()
        package = self.args.work / "package"
        path = self.args.work / "receipt.json"
        release.verify_native_binding(package, self.args.output, path, self.source)
        for field, value, message in [("source_sha", "c" * 40, "source"),
                                       ("output_sha256", "0" * 64, "SHA-256"),
                                       ("native_filesystem_policy", False, "native"),
                                       ("cargo_features", [], "native-filesystem-policy")]:
            with self.subTest(field=field):
                path.write_text(json.dumps({**receipt, field: value}))
                with self.assertRaisesRegex(ValueError, message):
                    release.verify_native_binding(package, self.args.output, path, self.source)
        path.write_text(json.dumps(receipt))
        (package / "Box.app/Contents/Resources/resources/config.toml").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "archive|receipt"):
            release.verify_native_binding(package, self.args.output, path, self.source)

    def test_native_package_rejects_changed_launcher_and_redirected_aliases(self):
        app = self.bundle()
        package = self.root / "package"
        release.stage_native_package(app, package)
        (package / "box").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "launcher"):
            release.native_inventory(package)
        (package / "box").write_text(release.NATIVE_LAUNCHER)
        (package / "resources").unlink()
        (package / "resources").symlink_to("/tmp/outside")
        with self.assertRaisesRegex(ValueError, "alias"):
            release.native_inventory(package)



    def test_native_verify_requires_bound_inputs_and_cannot_fall_back_to_flat_mode(self):
        self.run_native_release()
        args = argparse.Namespace(package=self.args.work / "package", evidence=self.root / "verification",
                                  native_filesystem_policy=True, archive=self.args.output,
                                  receipt=self.args.work / "receipt.json", source_sha=self.source)
        with patch.dict(release.os.environ, self.environment), \
                patch.object(release, "verify_native") as check, \
                patch.object(release, "verify_native_notarization") as ticket:
            release.verify_package(args)
            check.assert_called_once_with(args.package / "Box.app", TEAM, self.profile, args.evidence)
            ticket.assert_called_once_with(args.package / "Box.app", args.evidence)
            for field in ("archive", "receipt", "source_sha"):
                check.reset_mock()
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "requires"):
                    release.verify_package(argparse.Namespace(**{**vars(args), field: None}))
                check.assert_not_called()
            with self.assertRaisesRegex(ValueError, "requires --native-filesystem-policy"):
                release.verify_package(argparse.Namespace(**{**vars(args), "native_filesystem_policy": False}))

    def test_native_receipt_refuses_changed_archive_and_inconsistent_hash_claims(self):
        _, receipt = self.run_native_release()
        package, path = self.args.work / "package", self.args.work / "receipt.json"
        original = self.args.output.read_bytes()
        self.args.output.write_bytes(original + b"extra")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            release.verify_native_binding(package, self.args.output, path, self.source)
        self.args.output.write_bytes(original)
        for field in ("binaries", "resources"):
            with self.subTest(field=field):
                path.write_text(json.dumps({**receipt, field: {}}))
                with self.assertRaisesRegex(ValueError, "hashes differ"):
                    release.verify_native_binding(package, self.args.output, path, self.source)

    def test_native_archive_refuses_unsafe_paths_duplicate_entries_and_unexpected_links(self):
        for index, (name, kind, target, duplicate) in enumerate([
            ("../outside", tarfile.REGTYPE, "", False),
            ("/outside", tarfile.REGTYPE, "", False),
            ("resources", tarfile.SYMTYPE, "/outside", False),
            ("Box.app/Contents/MacOS/box", tarfile.LNKTYPE, "outside", False),
            ("Box.app/file", tarfile.REGTYPE, "", True),
        ]):
            archive = self.root / f"invalid-{index}.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                entry = tarfile.TarInfo(name)
                entry.type, entry.linkname = kind, target
                output.addfile(entry)
                if duplicate:
                    output.addfile(entry)
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                release.archive_inventory(archive)

    def test_native_preflight_refuses_an_implicit_feature_downgrade(self):
        self.args.native_filesystem_policy = False
        with patch.object(release, "Signer") as signer, self.assertRaisesRegex(ValueError, "requires"):
            release.release(self.args)
        signer.assert_not_called()
        self.assertFalse(self.args.work.exists())



    def test_native_release_refuses_a_bad_helper_before_signing_the_application(self):
        with patch.object(release, "verify", side_effect=ValueError("helper signature refused")), \
                self.assertRaisesRegex(ValueError, "helper signature refused"):
            self.run_native_release()
        self.assertEqual([phase for phase, _ in self.phases], ["helpers"])
        self.assertFalse(self.args.output.exists())

    def test_native_notarization_requires_a_stapled_ticket_and_checks_app_and_helpers(self):
        app = self.bundle()
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")) as run, \
                self.assertRaisesRegex(ValueError, "stapled notarization ticket"):
            release.verify_native_notarization(app, self.root / "evidence")
        self.assertEqual(run.call_count, 1)
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            release.verify_native_notarization(app, self.root / "evidence")
        self.assertEqual(run.call_args_list[0].args[0], ["xcrun", "stapler", "validate", str(app)])
        self.assertEqual([Path(item.args[0][-1]) for item in run.call_args_list[1:]],
                         [app, *(app / "Contents/MacOS" / name for name in release.BINARIES)])
        self.assertTrue(all("--check-notarization" in item.args[0] for item in run.call_args_list[1:]))


class WorkflowGateTests(unittest.TestCase):
    # The caller asks for signing only from upstream main. The CLI workflow signs only from main of a
    # strands-agents repository, so it keeps working when another strands-agents repository calls it.
    GUARD = "github.repository == 'strands-agents/box' && github.ref == 'refs/heads/main'"
    CLI_GUARD = "github.repository_owner == 'strands-agents' && github.ref == 'refs/heads/main'"

    def test_only_a_manual_dispatch_starts_it_and_only_upstream_main_signs(self):
        for path, trigger in ((WORKFLOW, "workflow_dispatch"), (CLI_WORKFLOW, "workflow_call")):
            with self.subTest(workflow=path.name):
                triggers = path.read_text().split("\non:\n", 1)[1].split("\n\n", 1)[0]
                self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", triggers), [trigger])
        self.assertIn(f"    if: {self.CLI_GUARD}\n", workflow_job("verify-macos"))
        self.assertIn(f"    if: >-\n      {self.CLI_GUARD} &&\n      inputs.sign == true\n",
                      workflow_job("sign-macos"))
        cli = workflow_job("cli")
        self.assertIn("    uses: ./.github/workflows/cli-release.yml\n", cli)
        # A pre-merge signing test signs only Box Core.
        self.assertIn(f"      sign: >-\n        ${{{{ {self.GUARD} &&\n"
                      "        inputs.premerge_signing_test != true &&\n"
                      "        (inputs.dry_run != true || inputs.sign_macos == true) }}\n", cli)
        # The CLI workflow's sign input defaults to off.
        field = CLI_WORKFLOW.read_text().split("      sign:\n", 1)[1].split("\n    outputs:", 1)[0]
        self.assertIn("        default: false\n", field)

    def test_signing_waits_for_the_tests_and_the_build(self):
        self.assertIn("    uses: ./.github/workflows/rust-test-lint.yml\n", workflow_job("test"))
        cli_test = workflow_job("cli-test")
        self.assertIn("    uses: ./.github/workflows/cli-test.yml\n", cli_test)
        self.assertIn("      ref: ${{ needs.scan.outputs.release_sha }}\n"
                      "      suite: all\n      macos: true\n      package: true\n", cli_test)
        # The cli job starts with always(), so this condition, not needs alone, keeps a failed
        # test job, Box Core's or the CLI's, from signing.
        self.assertIn("    needs: [scan, test, cli-test]\n"
                      "    if: |\n"
                      "      always() &&\n"
                      "      needs.scan.result == 'success' &&\n"
                      "      ((needs.test.result == 'success' && needs.cli-test.result == 'success') ||\n"
                      "        (needs.test.result == 'skipped' && needs.cli-test.result == 'skipped' &&\n"
                      "          inputs.skip_tests == true && github.event.repository.fork == true))\n"
                      "    uses: ./.github/workflows/cli-release.yml\n", workflow_job("cli"))
        self.assertIn("    needs: build\n", workflow_job("sign-macos"))
        ci = (WORKFLOW.parent / "ci.yml").read_text()
        self.assertIn("        run: python3 -m unittest discover -s scripts -p 'test_*.py' -v\n", ci)

    def test_a_real_release_needs_the_signed_and_checked_package(self):
        self.assertIn("      (inputs.dry_run != true || inputs.sign_macos == true) }}\n", workflow_job("cli"))
        bundle = workflow_job("bundle")
        self.assertIn("    needs: [build, sign-macos, verify-macos]\n", bundle)
        self.assertIn(
            "    if: >-\n"
            "      always() && needs.build.result == 'success' &&\n"
            "      (inputs.sign != true ||\n"
            "       (needs.sign-macos.result == 'success' && needs.verify-macos.result == 'success'))\n",
            bundle)
        self.assertIn("      signed: ${{ needs.verify-macos.result == 'success' }}\n", bundle)
        self.assertIn("        value: ${{ jobs.bundle.outputs.signed }}\n", CLI_WORKFLOW.read_text())
        inspect = workflow_job("inspect")
        self.assertIn("    needs: [scan, build, sign-macos, verify-macos, cli]\n", inspect)
        self.assertIn(
            "      needs.cli.result == 'success' &&\n"
            "      ((inputs.dry_run == true && inputs.sign_macos != true) ||\n"
            "       (needs.sign-macos.result == 'success' && needs.verify-macos.result == 'success' &&\n"
            "        (needs.cli.outputs.signed == 'true' || inputs.premerge_signing_test == true)))\n",
            inspect)
        for name in ("approve-release", "release"):
            with self.subTest(job=name):
                job = workflow_job(name)
                self.assertIn("      inputs.dry_run != true &&\n", job)
                self.assertIn("      needs.inspect.result == 'success'", job)
        self.assertIn("      needs.cli.result == 'success' &&\n", workflow_job("approve-release"))
        self.assertIn("      needs.approve-release.result == 'success'\n", workflow_job("release"))

    def test_inspect_publishes_the_signed_package_in_place_of_the_unsigned_one(self):
        sign = workflow_job("sign-macos")
        self.assertIn("          name: cli-${{ inputs.tag }}-aarch64-apple-darwin\n"
                      "          path: unsigned\n", sign)
        command = workflow_command("Sign and notarize the executables")
        self.assertIn('--input "unsigned/box-cli-${NEW_TAG}-aarch64-apple-darwin.tar.gz"', command)
        self.assertIn('--output "signed/box-cli-${NEW_TAG}-aarch64-apple-darwin.tar.gz"', command)
        bundle = workflow_job("bundle")
        pattern = re.search(r"(?m)^          pattern: (.+)$", bundle).group(1).strip("'\"")
        self.assertEqual(pattern, "cli-${{ inputs.tag }}-*")
        uploads = re.findall(r"uses: actions/upload-artifact@.*\n        with:\n          name: (.+)\n", sign)
        self.assertEqual(sorted(uploads), ["cli-macos-native-receipt", "cli-macos-signed-package",
                                           "cli-macos-signing-evidence"])
        self.assertIn("        if: inputs.native_filesystem_policy == true\n",
                      workflow_step("sign-macos", "Retain the native signing receipt"))
        self.assertEqual([name for name in uploads if fnmatch.fnmatch(name, pattern)], [])
        # Every artifact the CLI workflow uploads starts with cli-, so a box-* download skips it.
        for name in re.findall(r"uses: actions/upload-artifact@.*\n        with:\n          name: (.+)\n",
                               CLI_WORKFLOW.read_text()):
            self.assertTrue(name.startswith("cli-"), name)
        # The signed archive has the unsigned one's name, so it gets its own folder and Collect swaps it in.
        step = workflow_step("bundle", "Download the signed macOS package")
        self.assertIn("        if: needs.verify-macos.result == 'success'\n", step)
        self.assertIn("          name: cli-macos-signed-package\n          path: signed\n", step)
        self.assertLess(bundle.index("- name: Download the signed macOS package\n"),
                        bundle.index("- name: Collect the CLI tarballs\n"))
        self.assertIn("          SIGNED: ${{ needs.verify-macos.result == 'success' }}\n"
                      "          SIGNED_SHA256: ${{ needs.sign-macos.outputs.package_sha256 }}\n",
                      workflow_step("bundle", "Collect the CLI tarballs"))
        self.assertIn("      package_sha256: ${{ steps.package.outputs.sha256 }}\n", sign)
        self.assertIn("        id: package\n", workflow_step("sign-macos", "Record the signed package's hash"))
        self.assertIn('shasum -a 256 "signed/box-cli-${NEW_TAG}-aarch64-apple-darwin.tar.gz"',
                      workflow_command("Record the signed package's hash"))
        # The caller publishes the CLI workflow's bundle, and no other CLI artifact.
        self.assertIn("          name: cli-release-bundle\n          path: cli-release\n",
                      workflow_step("inspect", "Download the CLI release bundle"))
        self.assertIn('cp cli-release/box-cli-"${NEW_TAG}"-*.tar.gz release/\n',
                      workflow_command("Collect tarballs and compute SHA256SUMS.txt"))

    def test_inspect_publishes_only_the_archive_that_sign_macos_signed(self):
        tag = "v0.1.1"
        name = f"box-cli-{tag}-aarch64-apple-darwin.tar.gz"
        collect = workflow_command("Collect the CLI tarballs")
        check = workflow_command("Assert the expected tarballs, each carrying box")
        # download-artifact puts one matched artifact straight into assets/, and several into folders.
        for layout in (name, f"cli-{tag}-aarch64-apple-darwin/{name}"):
            for case in ("signed", "wrong hash", "no hash", "unsigned dry run"):
                with self.subTest(
                    layout=layout, case=case
                ), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    linux = f"box-cli-{tag}-aarch64-unknown-linux-gnu.tar.gz"
                    paths = {
                        "unsigned": root / "assets" / layout,
                        "signed": root / "signed" / name,
                        "linux": root / "assets" / linux,
                        "x86": root / "assets" / f"box-cli-{tag}-x86_64-unknown-linux-gnu.tar.gz",
                    }
                    for kind, path in paths.items():
                        path.parent.mkdir(parents=True, exist_ok=True)
                        with tarfile.open(path, "w:gz") as output:
                            member = tarfile.TarInfo("./box")
                            member.size = len(kind)
                            output.addfile(member, io.BytesIO(kind.encode()))
                    recorded = {"signed": release.digest(paths["signed"]),
                                "wrong hash": release.digest(paths["unsigned"])}.get(case, "")
                    environment = {**os.environ, "NEW_TAG": tag, "SIGNED_SHA256": recorded,
                                   "LINUX_PREVIEW": "false", "PUBLISH_LINUX_X86": "false",
                                   "SIGNED": "false" if case == "unsigned dry run" else "true"}
                    result = subprocess.run(["bash", "-c", collect], cwd=root, env=environment,
                                            capture_output=True, text=True)
                    if case in ("wrong hash", "no hash"):
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertFalse((root / "release" / name).exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    published = paths["unsigned" if case == "unsigned dry run" else "signed"]
                    self.assertEqual((root / "release" / name).read_bytes(), published.read_bytes())
                    result = subprocess.run(["bash", "-c", check], cwd=root, env=environment,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_signing_refuses_a_commit_outside_main_before_any_credentials(self):
        sign = workflow_job("sign-macos")
        self.assertLess(sign.index("- name: Refuse a commit outside main\n"),
                        sign.index("configure-aws-credentials"))
        self.assertIn("          SOURCE_SHA: ${{ inputs.sha }}\n",
                      workflow_step("sign-macos", "Refuse a commit outside main"))
        command = workflow_command("Refuse a commit outside main")
        sha = "a" * 40
        for source, status, success in [
            (sha, "identical", True), (sha, "behind", True), (sha, "ahead", False),
            (sha, "diverged", False), ("a" * 39, "identical", False), ("main", "identical", False),
            ("", "identical", False),
        ]:
            with self.subTest(source=source, status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gh = root / "gh"
                gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$GH_ARGS"\nprintf "%s\\n" "$FAKE_STATUS"\n')
                gh.chmod(0o755)
                result = subprocess.run(["bash", "-c", command], cwd=root, env={
                    **os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SOURCE_SHA": source,
                    "FAKE_STATUS": status, "GH_ARGS": str(root / "args"),
                    "GITHUB_REPOSITORY": "strands-agents/box",
                }, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if (root / "args").exists():
                    self.assertIn(f"repos/strands-agents/box/compare/main...{source}",
                                  (root / "args").read_text())

    def test_only_the_signing_job_gets_aws_credentials(self):
        for path in (WORKFLOW, CLI_WORKFLOW):
            self.assertIn("\npermissions:\n  contents: read\n\njobs:\n", path.read_text())
        # The cli job grants id-token to the CLI workflow, where only sign-macos takes it.
        self.assertIn("    permissions:\n      contents: read\n      id-token: write\n", workflow_job("cli"))
        sign = workflow_job("sign-macos")
        self.assertIn("    environment: macos-signing\n", sign)
        self.assertIn("    permissions:\n      contents: read\n      id-token: write\n", sign)
        self.assertIn("          role-to-assume: ${{ vars.CD_SIGNER_CALLER_ROLE }}\n", sign)
        self.assertIn("role-session-name: box-release-${{ github.run_id }}", sign)
        for name in [job for job in workflow_jobs() if job != "sign-macos"]:
            with self.subTest(job=name):
                job = workflow_job(name)
                self.assertNotRegex(job, r"macos-signing(?![-\w])")
                for text in ("id-token", "configure-aws-credentials", "CD_SIGNER_CALLER_ROLE",
                             "NOTARY_CREDENTIAL_SECRET"):
                    if name == "cli" and text == "id-token":
                        continue
                    self.assertNotIn(text, job)

    def test_the_signing_jobs_do_not_read_or_write_the_actions_cache(self):
        for name in ("sign-macos", "verify-macos"):
            with self.subTest(job=name):
                job = workflow_job(name)
                self.assertIn("    cache-mode: none\n", job)
                self.assertNotIn("rust-cache", job)
                self.assertNotIn("actions/cache", job)

    def test_signing_notarizes_with_the_environment_credential_secret(self):
        self.assertIn("      NOTARY_CREDENTIAL_SECRET: ${{ vars.NOTARY_CREDENTIAL_SECRET }}\n",
                      workflow_job("sign-macos"))
        command = workflow_command("Sign and notarize the executables")
        self.assertIn('--notary-secret "$NOTARY_CREDENTIAL_SECRET"', command)
        self.assertNotIn("--notary-keychain-profile", command)

    def test_the_package_check_reads_the_packs_and_runs_a_box_with_the_signed_box(self):
        command = workflow_command("Verify the package and run a box with it")
        self.assertIn('scripts/macos-release-cli.py verify --package "$package"', command)
        self.assertIn('"$package/box" --version | grep -F "$VERSION"', command)
        self.assertIn('cp -R test-corpus/profiles/probe "$home/.strands/box/profiles/probe"', command)
        self.assertTrue((WORKFLOW.parents[2] / "test-corpus/profiles/probe/profile.toml").is_file())
        self.assertIn('"$package/box" profile create claude --with bedrock --policy open', command)
        self.assertIn('"$package/box" run probe', command)
        self.assertEqual(command.count('env -i HOME="$home" PATH=/usr/bin:/bin \\\n  "$package/box" '), 2)
        self.assertEqual(command.count(" < /dev/null\n"), 2)
        self.assertIn('test "$(cat proof.txt)" = signed', command)
        folder = re.search(r'(?m)^package="\$RUNNER_TEMP/([^"]+)"$', command).group(1)
        self.assertNotEqual(folder.lower(), "box")

    def test_the_check_holds_the_package_to_the_team_that_signed_it(self):
        self.assertIn("    outputs:\n      team_id: ${{ vars.CD_SIGNER_TEAM_ID }}\n",
                      workflow_job("sign-macos"))
        check = workflow_job("verify-macos")
        self.assertIn("    needs: sign-macos\n", check)
        self.assertIn("      CD_SIGNER_TEAM_ID: ${{ needs.sign-macos.outputs.team_id }}\n", check)

    def test_the_signing_jobs_have_time_for_the_script_waits(self):
        def limit(name):
            found = re.search(r"(?m)^    timeout-minutes: (\d+)$", workflow_job(name))
            self.assertIsNotNone(found, f"{name} has no time limit")
            return int(found.group(1))
        # The script waits up to 15 minutes for the signer, NOTARY_TIMEOUT for Apple, and 4 x 30 s per ticket.
        tickets = len(release.BINARIES) * 4 * 30 / 60
        self.assertGreaterEqual(limit("sign-macos"), 15 + int(release.NOTARY_TIMEOUT.rstrip("m")) + tickets + 20)
        self.assertGreaterEqual(limit("verify-macos"), tickets + 5)

    def test_the_signing_jobs_run_pinned_tools_from_the_dispatched_commit(self):
        for name in ("sign-macos", "verify-macos"):
            with self.subTest(job=name):
                job = workflow_job(name)
                for action in re.findall(r"(?m)^        uses: (\S+)", job):
                    self.assertRegex(action, r"@[0-9a-f]{40}$")
                checkouts = re.findall(r"uses: actions/checkout@\S+ .*\n        with:\n((?:          .*\n)+)", job)
                self.assertEqual(checkouts, ["          ref: ${{ github.sha }}\n"
                                             "          persist-credentials: false\n"])
        install = workflow_command("Install signing tools")
        packages = re.search(r'(?m)/pip" install (.+)$', install).group(1).split()
        self.assertTrue(packages)
        for package in packages:
            self.assertRegex(package, r"^[A-Za-z0-9_.-]+==\d+(\.\d+)*$")

    def test_the_signing_job_records_the_release_commit_and_requires_its_package(self):
        self.assertIn("          SOURCE_SHA: ${{ inputs.sha }}\n",
                      workflow_step("sign-macos", "Sign and notarize the executables"))
        self.assertIn("          if-no-files-found: error\n",
                      workflow_step("sign-macos", "Upload the signed package"))

    def test_the_build_archive_holds_no_macos_metadata_files(self):
        self.assertIn('COPYFILE_DISABLE=1 tar -C "$stage" -czf "dist/${asset}" .',
                      workflow_command("Package tarball"))

    def test_release_notes_select_latest_or_pinned_version_with_signing_required(self):
        # A prerelease page offers only the pinned install, because the installer's latest
        # release is never a prerelease.
        for prerelease, versions in (("false", ("", "1.2.3")), ("true", ("1.2.3",))):
            with self.subTest(prerelease=prerelease), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                environment = {key: value for key, value in os.environ.items()
                               if not key.startswith("BOX_")}
                environment.update(HOME=str(root), NEW_TAG="v1.2.3", RELEASE_SHA="a" * 40,
                                   LINUX_PREVIEW="false", PRERELEASE=prerelease,
                                   PUBLISH_LINUX_X86="true",
                                   GITHUB_REPOSITORY="strands-agents/box")
                result = subprocess.run(
                    ["bash", "-c", workflow_command("Compose release body (install block)")],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                notes = (root / "body.md").read_text()
                self.assertIn("its macOS programs are signed and notarized.", notes)
                install = notes.split("## Install box\n", 1)[1].split("\n## ", 1)[0]
                commands = re.findall(r"```sh\n(.*?)\n```", install, re.S)
                self.assertEqual(len(commands), len(versions))

                bin_dir = root / "bin"
                bin_dir.mkdir()
                installer = root / "installer"
                installer.write_text(
                    'printf "%s\\n" "${BOX_GITHUB_REPO-}" "${BOX_VERSION-}" '
                    '"${BOX_ALLOW_UNSIGNED-0}" > "$INSTALL_OPTIONS"\n')
                gh = bin_dir / "gh"
                gh.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$GH_ARGS"\ncat "$INSTALLER"\n')
                gh.chmod(0o755)
                environment.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                                   INSTALLER=str(installer), GH_ARGS=str(root / "gh-args"),
                                   INSTALL_OPTIONS=str(root / "install-options"))
                for command, version in zip(commands, versions):
                    with self.subTest(version=version or "latest"):
                        for name in ("gh-args", "install-options"):
                            (root / name).unlink(missing_ok=True)
                        result = subprocess.run(["sh", "-c", command], cwd=root, env=environment,
                                                capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual((root / "gh-args").read_text().splitlines(), [
                            "api", "repos/strands-agents/box/contents/install.sh?ref=main",
                            "-H", "Accept: application/vnd.github.raw"])
                        self.assertEqual((root / "install-options").read_text().splitlines(),
                                         ["strands-agents/box", version, "0"])

if __name__ == "__main__":
    unittest.main()
