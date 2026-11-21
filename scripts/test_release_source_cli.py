"""Check release source selection through the workflow's scan command."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/deploy-box-artifact.yml"
# The reusable workflow that builds, signs, and bundles the CLI for WORKFLOW.
CLI_WORKFLOW = WORKFLOW.with_name("cli-release.yml")


def workflow_lines(name):
    """The lines of the CLI release workflow, which has a step with this name."""
    lines = CLI_WORKFLOW.read_text().splitlines()
    assert f"      - name: {name}" in lines, f"step {name!r} is not in {CLI_WORKFLOW.name}"
    return lines


def workflow_command(name):
    lines = workflow_lines(name)
    start = lines.index(f"      - name: {name}")
    start = lines.index("        run: |", start) + 1
    end = start
    while end < len(lines) and (not lines[end] or lines[end].startswith("          ")):
        end += 1
    return textwrap.dedent("\n".join(lines[start:end]))


class ReleaseBundleTests(unittest.TestCase):
    def test_the_bundle_holds_the_qualified_archives_and_x86_only_when_published(self):
        import io
        import tarfile

        for preview, publish_x86 in [(False, True), (False, False), (True, True), (True, False)]:
            with self.subTest(preview=preview, publish_x86=publish_x86), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tag = "v0.3.0-preview.1" if preview else "v0.3.0"
                assets = root / "assets"
                assets.mkdir()
                for triple in [
                    "aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
                    "x86_64-unknown-linux-gnu",
                ]:
                    with tarfile.open(assets / f"box-cli-{tag}-{triple}.tar.gz", "w:gz") as archive:
                        for name in [
                            "box", "strands-box-sock-alias", "strands-box-contain-trampoline",
                        ]:
                            entry = tarfile.TarInfo(name)
                            entry.size = 4
                            entry.mode = 0o755
                            archive.addfile(entry, io.BytesIO(b"test"))
                environment = {
                    **os.environ, "NEW_TAG": tag, "SIGNED": "false",
                    "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                }
                for step in [
                    "Collect the CLI tarballs",
                    "Assert the expected tarballs, each carrying box",
                ]:
                    result = subprocess.run(
                        ["bash", "-c", workflow_command(step)], cwd=root,
                        env=environment, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = {
                    f"box-cli-{tag}-aarch64-apple-darwin.tar.gz",
                    f"box-cli-{tag}-aarch64-unknown-linux-gnu.tar.gz",
                }
                x86 = f"box-cli-{tag}-x86_64-unknown-linux-gnu.tar.gz"
                if publish_x86:
                    expected.add(x86)
                release = root / "release"
                self.assertEqual({path.name for path in release.iterdir()}, expected)
                # An archive the run did not qualify fails the bundle check.
                if not publish_x86:
                    (release / x86).write_bytes(b"unexpected")
                    result = subprocess.run(
                        ["bash", "-c", workflow_command("Assert the expected tarballs, each carrying box")],
                        cwd=root, env=environment, capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_the_bundle_requires_every_built_archive(self):
        for missing in ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "assets").mkdir()
                for triple in ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
                               "x86_64-unknown-linux-gnu"]:
                    if triple != missing:
                        (root / "assets" / f"box-cli-v0.3.0-{triple}.tar.gz").write_bytes(b"x")
                result = subprocess.run(
                    ["bash", "-c", workflow_command("Collect the CLI tarballs")], cwd=root,
                    env={**os.environ, "NEW_TAG": "v0.3.0", "SIGNED": "false",
                         "PUBLISH_LINUX_X86": "false"},
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing.split("-")[0], result.stdout)


class ReleasePackageTests(unittest.TestCase):
    REMOTE = "git+https://github.com/strands-agents/box?branch=main#" + "b" * 40
    RESOURCE_FOLDERS = ("packs", "plugins", "policies", "starters")

    def package(self, core_source, helper_source, core_root=None, triple="aarch64-apple-darwin"):
        """Run the Package tarball step with a fake Cargo and return its result and release.json."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            release = root / "target" / triple / "release"
            release.mkdir(parents=True)
            for name in ("box", "strands-box-sock-alias", "strands-box-contain-trampoline"):
                (release / name).write_text("#!/bin/sh\n")
            for name in self.RESOURCE_FOLDERS:
                (root / "resources" / name).mkdir(parents=True)
            (root / "resources/config.toml").write_text("")
            (root / "resources/editing-box-profile.md").write_text("")
            core = root / core_root if isinstance(core_root, str) else (core_root or root / "crates")
            metadata = {"packages": [
                {"name": "strands-box-cli", "version": "0.1.2", "source": None,
                 "manifest_path": str(root / "crates/cli/app/Cargo.toml")},
                {"name": "strands-box", "version": "0.3.0", "source": core_source,
                 "manifest_path": str(core / "box/Cargo.toml")},
                {"name": "strands-box-containment", "version": "0.3.0", "source": helper_source,
                 "manifest_path": str(core / "containment/Cargo.toml")},
            ]}
            tools = root / "tools"
            tools.mkdir()
            (root / "metadata.json").write_text(json.dumps(metadata))
            cargo = tools / "cargo"
            cargo.write_text(f"#!/bin/sh\ncat {root / 'metadata.json'}\n")
            cargo.chmod(0o755)
            environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "NEW_TAG": "v0.1.2",
                           "TRIPLE": triple, "RELEASE_SHA": "a" * 40}
            result = subprocess.run(["bash", "-c", workflow_command("Package tarball")], cwd=root,
                                    env=environment, capture_output=True, text=True)
            record = root / "stage/package/release.json"
            return result, json.loads(record.read_text()) if result.returncode == 0 else None

    def test_release_json_records_the_core_commit_of_the_core_source(self):
        for name, source, expected in (("git", self.REMOTE, "b" * 40), ("path", None, "a" * 40)):
            with self.subTest(name):
                result, record = self.package(source, source)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(record, dict(box_version="0.1.2", box_commit="a" * 40, core_version="0.3.0",
                                              core_commit=expected, target="aarch64-apple-darwin",
                                              macos_minimum_version="27.0"))

    def test_linux_package_does_not_declare_a_macos_minimum(self):
        result, record = self.package(None, None, triple="aarch64-unknown-linux-gnu")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("macos_minimum_version", record)

    def test_package_holds_each_resource_folder(self):
        result, _ = self.package(None, None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        listed = result.stdout.splitlines()
        for name in self.RESOURCE_FOLDERS:
            self.assertIn(f"./resources/{name}/", listed)

    def test_core_and_helpers_from_different_sources_refuse(self):
        result, _ = self.package(None, None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory() as outside:
            for name, core, helper, core_root in (
                ("git Core, path helpers", self.REMOTE, None, None),
                ("path Core, git helpers", None, self.REMOTE, None),
                ("two revisions", self.REMOTE, self.REMOTE[:-1] + "c", None),
                ("another repository", "git+https://github.com/example/box#" + "b" * 40,
                 "git+https://github.com/example/box#" + "b" * 40, None),
                ("path Core outside the repository", None, None, Path(outside)),
                ("path Core outside crates/", None, None, "vendor"),
            ):
                with self.subTest(name):
                    result, _ = self.package(core, helper, core_root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Core", result.stderr)


class ReleaseBuildTests(unittest.TestCase):
    def test_every_build_leg_checks_the_packaged_version(self):
        name = "Assert the packaged binary reports the stamped version"
        step = CLI_WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("        if:", step)
        for output, expected in (("box 0.1.2", 0), ("box 0.1.1", 1)):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                box = root / "stage/package/box"
                box.parent.mkdir(parents=True)
                box.write_text(f"#!/bin/sh\necho '{output}'\n")
                box.chmod(0o755)
                result = subprocess.run(
                    ["bash", "-c", workflow_command(name)], cwd=root,
                    env={**os.environ, "VERSION": "0.1.2"}, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
