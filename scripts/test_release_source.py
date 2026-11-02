"""Check release source selection through the workflow's scan command."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/deploy-box-artifact.yml"


def workflow_input_default(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"      {name}:") + 1
    for line in lines[start:]:
        if not line.startswith("        "):
            break
        if line.startswith("        default: "):
            return line.split(": ", 1)[1]
    raise ValueError(f"workflow input {name} has no default")


def workflow_command(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    start = lines.index("        run: |", start) + 1
    end = start
    while end < len(lines) and (not lines[end] or lines[end].startswith("          ")):
        end += 1
    return textwrap.dedent("\n".join(lines[start:end]))


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("commit", "--allow-empty", "-m", "Baseline")
        self.git("tag", "v0.1.0")
        self.git("commit", "--allow-empty", "-m", "Main source")
        self.main = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.main)
        self.git("checkout", "-b", "candidate")
        self.git("commit", "--allow-empty", "-m", "Package candidate")
        self.candidate = self.git("rev-parse", "HEAD")
        self.scan = workflow_command("Resolve SHA, find previous tag, validate version")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], text=True, stderr=subprocess.DEVNULL
        ).strip()

    def scan_source(self, dry_run, source="", dispatch=None, version="0.1.1", publish_linux="true"):
        output = self.root / "output"
        output.write_text("")
        environment = {
            **os.environ,
            "NEW_VERSION": version,
            "PUBLISH_LINUX": publish_linux,
            "SHA_INPUT": source,
            "DRY_RUN": dry_run,
            "DISPATCH_SHA": dispatch or self.candidate,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(self.root / "summary"),
        }
        result = subprocess.run(
            ["bash", "-c", self.scan],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
        )
        return result, output.read_text()

    def assert_source(self, expected, dry_run, source=""):
        result, output = self.scan_source(dry_run, source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"release_sha={expected}\n", output)

    def test_dry_run_defaults_to_dispatched_candidate(self):
        self.assert_source(self.candidate, "true")

    def test_dry_run_accepts_explicit_dispatched_candidate(self):
        self.assert_source(self.candidate, "true", self.candidate)

    def test_dry_run_can_select_main_history(self):
        self.assert_source(self.main, "true", self.main)

    def test_dry_run_refuses_another_unmerged_commit(self):
        self.git("commit", "--allow-empty", "-m", "Unselected source")
        result, output = self.scan_source("true", self.git("rev-parse", "HEAD"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source must belong to main history", result.stdout)
        self.assertEqual(output, "")

    def test_real_release_refuses_dispatched_unmerged_candidate(self):
        result, output = self.scan_source("false", self.candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source must belong to main history", result.stdout)
        self.assertEqual(output, "")

    def test_real_release_defaults_to_main(self):
        self.assert_source(self.main, "false")

    def test_real_release_accepts_explicit_main(self):
        self.assert_source(self.main, "false", self.main)

    def test_invalid_dry_run_value_does_not_authorize_branch(self):
        result, output = self.scan_source("TRUE", self.candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_unknown_source_refuses_before_outputs(self):
        result, output = self.scan_source("true", "absent-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a valid commit", result.stdout)
        self.assertEqual(output, "")

    def test_preview_sets_channel_and_ignores_preview_tags_as_baseline(self):
        self.git("tag", "v0.1.1-linux-preview.1", self.main)
        result, output = self.scan_source("true", version="0.1.1-linux-preview.2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("linux_preview=true\n", output)
        self.assertIn("prev_tag=v0.1.0\n", output)
        self.assertIn("new_tag=v0.1.1-linux-preview.2\n", output)

    def test_stable_after_preview_stays_stable(self):
        self.git("tag", "v0.1.1-linux-preview.1", self.main)
        result, output = self.scan_source("true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("linux_preview=false\n", output)

    def test_default_platform_selection_keeps_stable_macos_only(self):
        selection = workflow_input_default("publish_linux")
        result, output = self.scan_source("false", publish_linux=selection)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("publish_linux=false\n", output)
        self.assertIn("linux_preview=false\n", output)
        result, output = self.scan_source(
            "true", version="0.1.1-linux-preview.1", publish_linux=selection
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a Linux preview requires publish_linux=true", result.stdout)
        self.assertEqual(output, "")

    def test_stable_can_omit_linux_without_changing_the_channel(self):
        result, output = self.scan_source("false", publish_linux="false")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("publish_linux=false\n", output)
        self.assertIn("linux_preview=false\n", output)
        self.assertIn(f"release_sha={self.main}\n", output)

    def test_preview_cannot_omit_linux(self):
        result, output = self.scan_source(
            "true", version="0.1.1-linux-preview.1", publish_linux="false"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a Linux preview requires publish_linux=true", result.stdout)
        self.assertEqual(output, "")

    def test_invalid_linux_selection_refuses_before_outputs(self):
        for value in ["", "TRUE", "1", "yes"]:
            with self.subTest(value=value):
                result, output = self.scan_source("true", publish_linux=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("publish_linux must be true or false", result.stdout)
                self.assertEqual(output, "")

    def test_preview_cannot_publish_unmerged_source(self):
        result, output = self.scan_source(
            "false", self.candidate, version="0.1.1-linux-preview.1"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_duplicate_preview_refuses(self):
        self.git("tag", "v0.1.1-linux-preview.1", self.main)
        result, output = self.scan_source("true", version="0.1.1-linux-preview.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stdout)
        self.assertEqual(output, "")

    def test_invalid_versions_and_nonincrementing_preview_refuse(self):
        for version in [
            "v0.1.1", "0.1.1-beta.1", "0.1.1-linux-preview.0",
            "0.1.1-linux-preview.01", "00.1.1", "0.1.1+linux",
            "0.1.0-linux-preview.1", "0.1.3-linux-preview.1",
        ]:
            with self.subTest(version=version):
                result, output = self.scan_source("true", version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")


class ReleaseBundleTests(unittest.TestCase):
    def test_published_assets_and_prerelease_state_must_match_the_channel(self):
        for preview, publish_linux, metadata_preview, linux_asset, extra_asset, success in [
            (False, True, False, True, False, True),
            (True, True, True, True, False, True),
            (False, False, False, False, False, True),
            (False, False, False, True, False, False),
            (False, False, True, False, False, False),
            (False, False, False, False, True, False),
            (True, True, False, True, False, False),
            (False, True, True, True, False, False),
            (False, True, False, False, False, False),
            (True, True, True, False, False, False),
            (False, True, False, True, True, False),
            (True, True, True, True, True, False),
        ]:
            with self.subTest(
                preview=preview, publish_linux=publish_linux, metadata=metadata_preview,
                linux=linux_asset, extra=extra_asset
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tag = "v0.1.1-linux-preview.1" if preview else "v0.1.1"
                names = ["SHA256SUMS.txt", f"box-{tag}-aarch64-apple-darwin.tar.gz"]
                if linux_asset:
                    names.append(f"box-{tag}-aarch64-unknown-linux-gnu.tar.gz")
                if extra_asset:
                    names.append(f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz")
                gh = root / "gh"
                gh.write_text(
                    '#!/bin/sh\ncase "$*" in\n'
                    '*isPrerelease*) printf "%s\\n" "$FAKE_PREVIEW";;\n'
                    '*) printf "%s\\n" "$FAKE_NAMES";;\nesac\n'
                )
                gh.chmod(0o755)
                sleep = root / "sleep"
                sleep.write_text("#!/bin/sh\nexit 0\n")
                sleep.chmod(0o755)
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c", workflow_command("Poll the release for its tag and assets")],
                    cwd=root,
                    env={
                        **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                        "NEW_TAG": tag, "LINUX_PREVIEW": str(preview).lower(),
                        "PUBLISH_LINUX": str(publish_linux).lower(),
                        "GITHUB_REPOSITORY": "example/box",
                        "FAKE_NAMES": "\n".join(names),
                        "FAKE_PREVIEW": str(metadata_preview).lower(),
                    },
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_stable_and_preview_bundle_only_their_expected_platforms(self):
        import io
        import tarfile

        for preview, publish_linux in [(False, False), (False, True), (True, True)]:
            with self.subTest(preview=preview, publish_linux=publish_linux), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tag = "v0.1.1-linux-preview.1" if preview else "v0.1.1"
                assets = root / "assets"
                assets.mkdir()
                for triple in [
                    "aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
                    "x86_64-unknown-linux-gnu",
                ]:
                    with tarfile.open(assets / f"box-{tag}-{triple}.tar.gz", "w:gz") as archive:
                        for name in [
                            "box", "strands-box-sock-alias", "strands-box-contain-trampoline",
                        ]:
                            entry = tarfile.TarInfo(name)
                            entry.size = 4
                            entry.mode = 0o755
                            archive.addfile(entry, io.BytesIO(b"test"))
                environment = {
                    **os.environ, "NEW_TAG": tag,
                    "LINUX_PREVIEW": str(preview).lower(),
                    "PUBLISH_LINUX": str(publish_linux).lower(),
                }
                for step in [
                    "Collect tarballs and compute SHA256SUMS.txt",
                    "Assert the expected tarballs, each carrying box",
                    "Compose release body (install block)",
                ]:
                    result = subprocess.run(
                        ["bash", "-c", workflow_command(step)], cwd=root,
                        env=environment, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                release = root / "release"
                expected = {f"box-{tag}-aarch64-apple-darwin.tar.gz", "SHA256SUMS.txt"}
                if publish_linux:
                    expected.add(f"box-{tag}-aarch64-unknown-linux-gnu.tar.gz")
                self.assertEqual({path.name for path in release.iterdir()}, expected)
                checksums = (release / "SHA256SUMS.txt").read_text()
                self.assertEqual(len(checksums.splitlines()), 2 if publish_linux else 1)
                verified = subprocess.run(
                    ["sha256sum", "--check", "SHA256SUMS.txt"], cwd=release,
                    capture_output=True, text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                body = (root / "body.md").read_text()
                self.assertEqual("EXPERIMENTAL_LINUX_SUPPORT=TRUE" in body, publish_linux)
                self.assertEqual(f"box-{tag}-aarch64-unknown-linux-gnu.tar.gz" in body, publish_linux)
                self.assertEqual("sha256sum --check box-linux.sha256" in body, publish_linux)
                self.assertEqual("Package availability does not establish security acceptance" in body, publish_linux)
                self.assertEqual("## Linux ARM64" in body, publish_linux and not preview)
                self.assertEqual("## Experimental Linux preview" in body, preview)
                # Unqualified architectures must fail inspection in both channels.
                extra = release / f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz"
                extra.write_bytes(b"unexpected")
                result = subprocess.run(
                    ["bash", "-c", workflow_command("Assert the expected tarballs, each carrying box")],
                    cwd=root, env=environment, capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
