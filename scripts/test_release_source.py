"""Check release source selection through the workflow's scan command."""

import json
import os
import re
from pathlib import Path
import shutil
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


def workflow_step_condition(name):
    step = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
    match = re.search(r"^        if: (.+)$", step, re.MULTILINE)
    return match.group(1) if match else None


def condition_selects_target(condition, target):
    if condition is None:
        return True
    equality = re.fullmatch(r"matrix\.target\.triple (==|!=) '([^']+)'", condition)
    if equality:
        same = target.casefold() == equality.group(2).casefold()
        return same if equality.group(1) == "==" else not same
    suffix = re.fullmatch(r"endsWith\(matrix\.target\.triple, '([^']+)'\)", condition)
    if suffix:
        return target.casefold().endswith(suffix.group(1).casefold())
    raise AssertionError(f"Unsupported target condition: {condition}")


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

    def scan_source(self, dry_run, source="", dispatch=None, version="0.1.1",
                    publish_linux="true", publish_linux_x86="false"):
        output = self.root / "output"
        output.write_text("")
        environment = {
            **os.environ,
            "NEW_VERSION": version,
            "PUBLISH_LINUX": publish_linux,
            "PUBLISH_LINUX_X86": publish_linux_x86,
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
        x86_selection = workflow_input_default("publish_linux_x86")
        self.assertEqual(x86_selection, "false")
        result, output = self.scan_source(
            "false", publish_linux=selection, publish_linux_x86=x86_selection
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("publish_linux=false\n", output)
        self.assertIn("publish_linux_x86=false\n", output)
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
        self.assertIn("publish_linux_x86=false\n", output)
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

    def test_arm64_publication_does_not_require_x86_publication(self):
        for version in ["0.1.1", "0.1.1-linux-preview.1"]:
            for x86 in [workflow_input_default("publish_linux_x86"), "true"]:
                with self.subTest(version=version, x86=x86):
                    (self.root / "summary").write_text("")
                    result, output = self.scan_source("true", version=version, publish_linux_x86=x86)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("publish_linux=true\n", output)
                    self.assertIn(f"publish_linux_x86={x86}\n", output)
                    summary = (self.root / "summary").read_text()
                    self.assertIn("| Publish Linux ARM64 | true |", summary)
                    self.assertIn(f"| Publish Linux x86-64 | {x86} |", summary)

    def test_x86_publication_requires_linux_publication(self):
        for version in ["0.1.1", "0.1.1-linux-preview.1"]:
            with self.subTest(version=version):
                result, output = self.scan_source(
                    "true", version=version, publish_linux="false", publish_linux_x86="true"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("publish_linux_x86=true requires publish_linux=true", result.stdout)
                self.assertEqual(output, "")

    def test_invalid_x86_selection_refuses_before_outputs(self):
        for value in ["", "TRUE", "1", "yes"]:
            with self.subTest(value=value):
                result, output = self.scan_source("true", publish_linux_x86=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("publish_linux_x86 must be true or false", result.stdout)
                self.assertEqual(output, "")

    def test_x86_publication_selection_reaches_each_release_stage(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("      publish_linux_x86: ${{ steps.scan.outputs.publish_linux_x86 }}", workflow)
        stages = {
            "Resolve SHA, find previous tag, validate version": "inputs.publish_linux_x86",
            "Collect tarballs and compute SHA256SUMS.txt": "needs.scan.outputs.publish_linux_x86",
            "Assert the expected tarballs, each carrying box": "needs.scan.outputs.publish_linux_x86",
            "Compose release body (install block)": "needs.scan.outputs.publish_linux_x86",
            "Poll the release for its tag and assets": "needs.scan.outputs.publish_linux_x86",
        }
        for name, source in stages.items():
            with self.subTest(stage=name):
                step = workflow.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
                self.assertIn("          PUBLISH_LINUX_X86: ${{ " + source + " }}", step)

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
        for preview, publish_linux, publish_x86, metadata_preview, arm_asset, x86_asset, extra_asset, success in [
            (False, False, False, False, False, False, False, True),
            (False, True, False, False, True, False, False, True),
            (True, True, False, True, True, False, False, True),
            (False, True, True, False, True, True, False, True),
            (True, True, True, True, True, True, False, True),
            (False, False, False, False, True, False, False, False),
            (False, False, False, False, False, True, False, False),
            (False, False, False, True, False, False, False, False),
            (False, False, False, False, False, False, True, False),
            (False, True, False, False, True, True, False, False),
            (True, True, False, True, True, True, False, False),
            (False, True, False, False, False, False, False, False),
            (True, True, False, True, False, False, False, False),
            (True, True, True, False, True, True, False, False),
            (False, True, True, True, True, True, False, False),
            (False, True, True, False, False, True, False, False),
            (False, True, True, False, True, False, False, False),
            (True, True, True, True, False, True, False, False),
            (True, True, True, True, True, False, False, False),
            (False, True, True, False, True, True, True, False),
            (True, True, True, True, True, True, True, False),
        ]:
            with self.subTest(
                preview=preview, publish_linux=publish_linux, publish_x86=publish_x86, metadata=metadata_preview,
                arm=arm_asset, x86=x86_asset, extra=extra_asset
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tag = "v0.1.1-linux-preview.1" if preview else "v0.1.1"
                names = ["SHA256SUMS.txt", f"box-{tag}-aarch64-apple-darwin.tar.gz"]
                if arm_asset:
                    names.append(f"box-{tag}-linux-arm64.tar.gz")
                if x86_asset:
                    names.append(f"box-{tag}-linux-x86_64.tar.gz")
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
                        "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                        "GITHUB_REPOSITORY": "example/box",
                        "FAKE_NAMES": "\n".join(names),
                        "FAKE_PREVIEW": str(metadata_preview).lower(),
                    },
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_x86_recipe_starts_only_after_a_successful_download(self):
        for fetch_status, download_status in [(17, 0), (0, 19), (0, 0)]:
            with self.subTest(fetch=fetch_status, download=download_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / "tools"
                tools.mkdir()
                curl = tools / "curl"
                curl.write_text(
                    '#!/bin/sh\n[ "$FETCH_STATUS" = 0 ] || exit "$FETCH_STATUS"\n'
                    'while [ "$#" -gt 0 ]; do\n'
                    '  if [ "$1" = -o ]; then cp "$DOWNLOAD_FIXTURE" "$2"; exit 0; fi\n'
                    '  shift\ndone\ncat "$DOWNLOAD_FIXTURE"\n'
                )
                curl.chmod(0o755)
                fixture = root / "downloader-fixture.sh"
                fixture.write_text(
                    '#!/bin/sh\nprintf "%s\\n" "$BOX_VERSION" > "$DOWNLOAD_LOG"\n'
                    'exit "$DOWNLOAD_STATUS"\n'
                )
                box = root / "box-core/box"
                box.parent.mkdir()
                box.write_text(
                    '#!/bin/sh\n[ "$1" = run ] && [ "$EXPERIMENTAL_X86_SUPPORT" = TRUE ] || exit 96\n'
                    'printf "started\\n" >> "$RUN_LOG"\n'
                )
                box.chmod(0o755)
                environment = {
                    **os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                    "NEW_TAG": "v0.1.1", "LINUX_PREVIEW": "false", "PUBLISH_LINUX": "true",
                    "PUBLISH_LINUX_X86": "true",
                    "FETCH_STATUS": str(fetch_status), "DOWNLOAD_STATUS": str(download_status),
                    "DOWNLOAD_FIXTURE": str(fixture), "DOWNLOAD_LOG": str(root / "download.log"),
                    "RUN_LOG": str(root / "run.log"),
                }
                composed = subprocess.run(
                    ["bash", "-c", workflow_command("Compose release body (install block)")],
                    cwd=root, env=environment, capture_output=True, text=True,
                )
                self.assertEqual(composed.returncode, 0, composed.stdout + composed.stderr)
                recipe = re.search(
                    r"### Linux x86-64.*?```sh\n(.*?)```", (root / "body.md").read_text(), re.DOTALL,
                ).group(1)
                result = subprocess.run(
                    ["sh", "-c", recipe], cwd=root, env=environment, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, fetch_status or download_status, result.stdout + result.stderr)
                self.assertEqual((root / "download.log").exists(), fetch_status == 0)
                if fetch_status == 0:
                    self.assertEqual((root / "download.log").read_text(), "v0.1.1\n")
                if fetch_status or download_status:
                    self.assertFalse((root / "run.log").exists())
                else:
                    self.assertEqual((root / "run.log").read_text(), "started\n")

    def test_collection_requires_all_built_archives(self):
        triples = ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
        for publish_linux, publish_x86 in [(False, False), (True, False), (True, True)]:
            for missing in triples:
                with self.subTest(publish_linux=publish_linux, publish_x86=publish_x86, missing=missing), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    assets = root / "assets"
                    assets.mkdir()
                    for triple in triples:
                        if triple != missing:
                            (assets / f"box-v0.1.1-{triple}.tar.gz").write_bytes(b"fixture")
                    result = subprocess.run(
                        ["bash", "-c", workflow_command("Collect tarballs and compute SHA256SUMS.txt")],
                        cwd=root,
                        env={
                            **os.environ, "NEW_TAG": "v0.1.1", "LINUX_PREVIEW": "false",
                            "PUBLISH_LINUX": str(publish_linux).lower(),
                            "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                        },
                        capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("missing", result.stdout)

    def test_stable_and_preview_bundle_only_their_expected_platforms(self):
        import io
        import tarfile

        for preview, publish_linux, publish_x86 in [
            (False, False, False), (False, True, False), (True, True, False),
            (False, True, True), (True, True, True),
        ]:
            with self.subTest(preview=preview, publish_linux=publish_linux, publish_x86=publish_x86), tempfile.TemporaryDirectory() as directory:
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
                            payload = f"{triple}:{name}".encode()
                            entry.size = len(payload)
                            entry.mode = 0o755
                            archive.addfile(entry, io.BytesIO(payload))
                environment = {
                    **os.environ, "NEW_TAG": tag,
                    "LINUX_PREVIEW": str(preview).lower(),
                    "PUBLISH_LINUX": str(publish_linux).lower(),
                    "PUBLISH_LINUX_X86": str(publish_x86).lower(),
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
                    expected.add(f"box-{tag}-linux-arm64.tar.gz")
                if publish_x86:
                    expected.add(f"box-{tag}-linux-x86_64.tar.gz")
                self.assertEqual({path.name for path in release.iterdir()}, expected)
                checksums = (release / "SHA256SUMS.txt").read_text()
                self.assertEqual(len(checksums.splitlines()), 1 + publish_linux + publish_x86)
                verified = subprocess.run(
                    ["sha256sum", "--check", "SHA256SUMS.txt"], cwd=release,
                    capture_output=True, text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                if publish_linux:
                    self.assertEqual(
                        (release / f"box-{tag}-linux-arm64.tar.gz").read_bytes(),
                        (assets / f"box-{tag}-aarch64-unknown-linux-gnu.tar.gz").read_bytes(),
                    )
                if publish_x86:
                    self.assertEqual(
                        (release / f"box-{tag}-linux-x86_64.tar.gz").read_bytes(),
                        (assets / f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz").read_bytes(),
                    )
                    self.assertNotIn("unknown", checksums)
                body = (root / "body.md").read_text()
                self.assertNotIn("unknown-linux", body)
                self.assertNotIn("EXPERIMENTAL_LINUX_SUPPORT", body)
                self.assertEqual(f"box-{tag}-linux-arm64.tar.gz" in body, publish_linux)
                self.assertEqual(f"box-{tag}-linux-x86_64.tar.gz" in body, publish_x86)
                self.assertEqual("EXPERIMENTAL_X86_SUPPORT=TRUE" in body, publish_x86)
                self.assertEqual("sha256sum --check box-linux.sha256" in body, publish_linux)
                self.assertEqual("Package availability does not establish security acceptance" in body, publish_linux)
                self.assertEqual("### Linux ARM64" in body, publish_linux)
                self.assertEqual("## Experimental Linux preview" in body, preview)
                # Raw build names must not leak into the public asset set.
                extra = release / f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz"
                extra.write_bytes(b"unexpected")
                result = subprocess.run(
                    ["bash", "-c", workflow_command("Assert the expected tarballs, each carrying box")],
                    cwd=root, env=environment, capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)



class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "stage/box-core"
        self.package.mkdir(parents=True)
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(
            WORKFLOW.parents[2] / "scripts/check-linux-package.py",
            scripts / "check-linux-package.py",
        )
        for name in ("box", "strands-box-sock-alias", "strands-box-contain-trampoline"):
            self.executable(self.package / name, '#!/bin/sh\nprintf "%s\\n" "$PACKAGE_VERSION"\n')
        self.executable(self.root / "readelf", '#!/bin/sh\nprintf "%s\\n" "$PACKAGE_HEADER"\n')
        self.docker_arguments = self.root / "docker-arguments.json"
        self.executable(self.root / "docker", "#!/usr/bin/env python3\n"
                        "import json, os, sys\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['DOCKER_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
                        "command = sys.argv[sys.argv.index('box-linux-release') + 1:]\n"
                        "os.execvp(command[0], command)\n")

    def executable(self, path, contents):
        path.write_text(contents)
        path.chmod(0o755)

    def run_step(self, name, **environment):
        return subprocess.run(
            ["bash", "-c", workflow_command(name)],
            cwd=self.root,
            env={**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}",
                 "DOCKER_ARGS": str(self.docker_arguments), **environment},
            text=True,
            capture_output=True,
        )

    def header(self, machine="Advanced Micro Devices X86-64", loader="/lib64/ld-linux-x86-64.so.2", version="2.34"):
        return f"Machine: {machine}\nRequesting program interpreter: {loader}]\nName: GLIBC_{version}\n"

    def test_x86_package_step_checks_all_three_executables_in_read_only_container(self):
        result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.docker_arguments.read_text()), [
            "run", "--rm", "--mount", f"type=bind,source={self.root},target=/src,readonly",
            "box-linux-release", "python3", "scripts/check-linux-package.py", "stage/box-core",
            "--target", "x86_64-unknown-linux-gnu",
        ])
        report = json.loads(result.stdout)
        self.assertEqual([item["binary"] for item in report], [
            "box", "strands-box-sock-alias", "strands-box-contain-trampoline",
        ])
        self.assertEqual({item["architecture"] for item in report}, {"x86_64"})

    def test_x86_package_step_propagates_architecture_and_library_failures(self):
        for header in (
            self.header(machine="AArch64", loader="/lib/ld-linux-aarch64.so.1"),
            self.header(version="2.35"),
        ):
            with self.subTest(header=header):
                result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=header)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)

    def test_build_and_package_steps_select_the_required_targets(self):
        arm, x86, mac = "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"
        targets = {arm, x86, mac}
        expected = {
            "Prepare the Amazon Linux 2023 builder": {arm, x86},
            "Build Linux against glibc 2.34": {arm, x86},
            "Build strands-box (release)": {mac},
            "Check the x86-64 Linux package": {x86},
            "Check and run the ARM64 Linux package": {arm},
            "Assert the packaged binary reports the stamped version": targets,
        }
        for name, selected in expected.items():
            with self.subTest(step=name):
                condition = workflow_step_condition(name)
                self.assertEqual({target for target in targets if condition_selects_target(condition, target)}, selected)

    def test_linux_build_uses_the_container_for_each_native_target(self):
        arguments = self.root / "docker-arguments.json"
        self.executable(self.root / "docker", "#!/usr/bin/env python3\n"
                        "import json, os, sys\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['DOCKER_ARGS']).write_text(json.dumps(sys.argv[1:]))\n")
        for target in ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"):
            with self.subTest(target=target):
                result = self.run_step("Build Linux against glibc 2.34", TRIPLE=target,
                                       DOCKER_ARGS=str(arguments))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                actual = json.loads(arguments.read_text())
                command = actual[actual.index("box-linux-release"):]
                self.assertEqual(command, [
                    "box-linux-release", "cargo", "build", "--release", "--locked", "--target", target,
                    "-p", "strands-box", "-p", "strands-box-containment",
                ])

    def test_all_builds_check_the_packaged_version(self):
        name = "Assert the packaged binary reports the stamped version"
        step = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("        if:", step)
        for output, expected in (("box 0.2.3", 0), ("box 0.2.2", 1)):
            with self.subTest(output=output):
                result = self.run_step(name, VERSION="0.2.3", PACKAGE_VERSION=output)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
