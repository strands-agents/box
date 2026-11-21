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
                    publish_linux_x86="true", native_filesystem_policy="false"):
        output = self.root / "output"
        output.write_text("")
        environment = {
            **os.environ,
            "NEW_VERSION": version,
            "PUBLISH_LINUX_X86": publish_linux_x86,
            "NATIVE_FILESYSTEM_POLICY": native_filesystem_policy,
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
        self.assertIn("prerelease=false\n", output)

    def test_each_preview_channel_is_a_prerelease(self):
        for version, linux_preview in [("0.1.1-preview.1", "false"),
                                       ("0.1.1-linux-preview.1", "true")]:
            with self.subTest(version=version):
                result, output = self.scan_source("true", version=version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("prerelease=true\n", output)
                self.assertIn(f"linux_preview={linux_preview}\n", output)
                self.assertIn(f"new_tag=v{version}\n", output)
                self.assertIn("prev_tag=v0.1.0\n", output)

    def test_a_preview_counts_from_the_last_stable_tag_and_never_repeats(self):
        self.git("tag", "v0.1.1-preview.1", self.main)
        result, output = self.scan_source("true", version="0.1.1-preview.2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("prev_tag=v0.1.0\n", output)
        result, output = self.scan_source("true", version="0.1.1-preview.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stdout)
        self.assertEqual(output, "")

    def test_a_preview_number_must_exceed_each_earlier_preview_of_its_channel(self):
        self.git("tag", "v0.1.1-preview.3", self.main)
        self.git("tag", "v0.1.1-linux-preview.5", self.main)
        for version, success in [("0.1.1-preview.2", False), ("0.1.1-preview.4", True),
                                 ("0.1.1-linux-preview.4", False), ("0.1.1-linux-preview.6", True)]:
            with self.subTest(version=version):
                result, output = self.scan_source("true", version=version)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if not success:
                    self.assertIn("is not above", result.stdout)
                    self.assertEqual(output, "")

    def test_native_policy_is_a_dry_run_choice(self):
        for dry_run, native, success in [("true", "true", True), ("true", "false", True),
                                         ("false", "true", False), ("true", "yes", False)]:
            with self.subTest(dry_run=dry_run, native=native):
                result, output = self.scan_source(
                    dry_run, self.main if dry_run == "false" else "", native_filesystem_policy=native)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if not success:
                    self.assertIn("native_filesystem_policy", result.stdout)
                    self.assertEqual(output, "")

    def test_linux_arm64_has_no_switch_and_x86_is_on_by_default(self):
        self.assertNotIn("      publish_linux:", WORKFLOW.read_text().splitlines())
        self.assertEqual(workflow_input_default("publish_linux_x86"), "true")
        for version, preview in [("0.1.1", "false"), ("0.1.1-linux-preview.1", "true")]:
            with self.subTest(version=version):
                result, output = self.scan_source(
                    "true", version=version,
                    publish_linux_x86=workflow_input_default("publish_linux_x86"),
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("publish_linux=", output)
                self.assertIn("publish_linux_x86=true\n", output)
                self.assertIn(f"linux_preview={preview}\n", output)

    def test_x86_publication_accepts_both_selections_on_each_channel(self):
        for version in ["0.1.1", "0.1.1-linux-preview.1"]:
            for x86 in ["false", "true"]:
                with self.subTest(version=version, x86=x86):
                    (self.root / "summary").write_text("")
                    result, output = self.scan_source("true", version=version, publish_linux_x86=x86)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"publish_linux_x86={x86}\n", output)
                    summary = (self.root / "summary").read_text()
                    self.assertIn(f"| Publish Linux x86-64 | {x86} |", summary)

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
            "0.1.1-preview.0", "0.1.1-preview.01", "0.1.1-rc.1", "0.1.3-preview.1",
        ]:
            with self.subTest(version=version):
                result, output = self.scan_source("true", version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")


CLI_TRIPLES = ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu"]
CLI_X86 = "x86_64-unknown-linux-gnu"


def cli_bundle(root, tag, publish_x86):
    """Write the CLI release bundle that inspect downloads, and return its archive names."""
    bundle = root / "cli-release"
    bundle.mkdir()
    names = []
    for triple in CLI_TRIPLES + ([CLI_X86] if publish_x86 else []):
        name = f"box-cli-{tag}-{triple}.tar.gz"
        (bundle / name).write_bytes(f"cli:{triple}".encode())
        names.append(name)
    return names


class ReleaseBundleTests(unittest.TestCase):
    def test_published_assets_and_prerelease_state_must_match_the_channel(self):
        for preview, publish_x86, metadata_preview, arm_asset, x86_asset, extra_asset, success in [
            (False, False, False, True, False, False, True),
            (True, False, True, True, False, False, True),
            (False, True, False, True, True, False, True),
            (True, True, True, True, True, False, True),
            (False, False, False, False, False, False, False),
            (True, False, True, False, False, False, False),
            (False, True, False, False, True, False, False),
            (False, False, False, True, True, False, False),
            (True, False, True, True, True, False, False),
            (False, True, False, True, False, False, False),
            (True, True, True, True, False, False, False),
            (False, False, True, True, False, False, False),
            (True, True, False, True, True, False, False),
            (False, False, False, True, False, True, False),
            (True, True, True, True, True, True, False),
        ]:
            with self.subTest(
                preview=preview, publish_x86=publish_x86, metadata=metadata_preview,
                arm=arm_asset, x86=x86_asset, extra=extra_asset
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tag = "v0.1.1-preview.1" if preview else "v0.1.1"
                names = ["SHA256SUMS.txt", f"box-{tag}-aarch64-apple-darwin.tar.gz",
                         f"box-cli-{tag}-aarch64-apple-darwin.tar.gz"]
                if arm_asset:
                    names += [f"box-{tag}-linux-arm64.tar.gz",
                              f"box-cli-{tag}-aarch64-unknown-linux-gnu.tar.gz"]
                if x86_asset:
                    names += [f"box-{tag}-linux-x86_64.tar.gz",
                              f"box-cli-{tag}-x86_64-unknown-linux-gnu.tar.gz"]
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
                        "NEW_TAG": tag, "PRERELEASE": str(preview).lower(),
                        "LINUX_PREVIEW": "false",
                        "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                        "GITHUB_REPOSITORY": "example/box",
                        "FAKE_NAMES": "\n".join(names),
                        "FAKE_PREVIEW": str(metadata_preview).lower(),
                    },
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_a_release_without_each_cli_archive_is_not_published(self):
        tag = "v0.3.0"
        complete = ["SHA256SUMS.txt"] + [
            f"box-{tag}-{suffix}.tar.gz"
            for suffix in ["aarch64-apple-darwin", "linux-arm64", "linux-x86_64"]
        ] + [f"box-cli-{tag}-{triple}.tar.gz" for triple in CLI_TRIPLES + [CLI_X86]]
        for missing in [name for name in complete if name.startswith("box-cli-")]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gh = root / "gh"
                gh.write_text('#!/bin/sh\ncase "$*" in\n*isPrerelease*) echo false;;\n'
                              '*) printf "%s\\n" "$FAKE_NAMES";;\nesac\n')
                gh.chmod(0o755)
                (root / "sleep").write_text("#!/bin/sh\nexit 0\n")
                (root / "sleep").chmod(0o755)
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c",
                     workflow_command("Poll the release for its tag and assets")],
                    cwd=root, capture_output=True, text=True,
                    env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "NEW_TAG": tag,
                         "PRERELEASE": "false", "LINUX_PREVIEW": "false", "PUBLISH_LINUX_X86": "true",
                         "GITHUB_REPOSITORY": "example/box",
                         "FAKE_NAMES": "\n".join(name for name in complete if name != missing)},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stdout + result.stderr)

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
                    '#!/bin/sh\n[ "$1" = run ] && [ "${EXPERIMENTAL_X86_SUPPORT+x}" != x ] || exit 96\n'
                    'printf "started\\n" >> "$RUN_LOG"\n'
                )
                box.chmod(0o755)
                environment = {
                    **os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                    "NEW_TAG": "v0.1.1", "LINUX_PREVIEW": "false", "PRERELEASE": "false",
                    "PUBLISH_LINUX_X86": "true", "GITHUB_REPOSITORY": "example/box",
                    "FETCH_STATUS": str(fetch_status), "DOWNLOAD_STATUS": str(download_status),
                    "DOWNLOAD_FIXTURE": str(fixture), "DOWNLOAD_LOG": str(root / "download.log"),
                    "RUN_LOG": str(root / "run.log"),
                }
                environment.pop("EXPERIMENTAL_X86_SUPPORT", None)
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
        for publish_x86 in [False, True]:
            for missing in triples:
                with self.subTest(publish_x86=publish_x86, missing=missing), tempfile.TemporaryDirectory() as directory:
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
                            "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                        },
                        capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("missing", result.stdout)

    def test_stable_and_preview_publish_arm64_and_x86_by_default(self):
        x86_default = workflow_input_default("publish_linux_x86")
        self.assertEqual(x86_default, "true")
        for tag, preview in [("v0.1.1", "false"), ("v0.1.1-linux-preview.1", "true")]:
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                assets = root / "assets"
                assets.mkdir()
                for triple in ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]:
                    (assets / f"box-{tag}-{triple}.tar.gz").write_bytes(triple.encode())
                cli = cli_bundle(root, tag, x86_default == "true")
                result = subprocess.run(
                    ["bash", "-c", workflow_command("Collect tarballs and compute SHA256SUMS.txt")],
                    cwd=root, capture_output=True, text=True,
                    env={**os.environ, "NEW_TAG": tag, "LINUX_PREVIEW": preview,
                         "PUBLISH_LINUX_X86": x86_default},
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(
                    {path.name for path in (root / "release").iterdir()},
                    {f"box-{tag}-aarch64-apple-darwin.tar.gz", f"box-{tag}-linux-arm64.tar.gz",
                     f"box-{tag}-linux-x86_64.tar.gz", "SHA256SUMS.txt", *cli},
                )

    def test_stable_and_preview_bundle_only_their_expected_platforms(self):
        import io
        import tarfile

        for channel, publish_x86 in [
            ("stable", False), ("linux-preview", False), ("preview", False),
            ("stable", True), ("linux-preview", True), ("preview", True),
        ]:
            with self.subTest(channel=channel, publish_x86=publish_x86), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                preview = channel != "stable"
                tag = {"stable": "v0.1.1", "linux-preview": "v0.1.1-linux-preview.1",
                       "preview": "v0.1.1-preview.1"}[channel]
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
                cli = cli_bundle(root, tag, publish_x86)
                environment = {
                    **os.environ, "NEW_TAG": tag,
                    "LINUX_PREVIEW": str(channel == "linux-preview").lower(),
                    "PRERELEASE": str(preview).lower(),
                    "PUBLISH_LINUX_X86": str(publish_x86).lower(),
                    "GITHUB_REPOSITORY": "example/box",
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
                expected = {
                    f"box-{tag}-aarch64-apple-darwin.tar.gz", f"box-{tag}-linux-arm64.tar.gz",
                    "SHA256SUMS.txt", *cli,
                }
                if publish_x86:
                    expected.add(f"box-{tag}-linux-x86_64.tar.gz")
                self.assertEqual({path.name for path in release.iterdir()}, expected)
                checksums = (release / "SHA256SUMS.txt").read_text()
                self.assertEqual(len(checksums.splitlines()), len(expected) - 1)
                for name in cli:
                    self.assertEqual((release / name).read_bytes(),
                                     (root / "cli-release" / name).read_bytes())
                verified = subprocess.run(
                    ["sha256sum", "--check", "SHA256SUMS.txt"], cwd=release,
                    capture_output=True, text=True,
                )
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                self.assertEqual(
                    (release / f"box-{tag}-linux-arm64.tar.gz").read_bytes(),
                    (assets / f"box-{tag}-aarch64-unknown-linux-gnu.tar.gz").read_bytes(),
                )
                if publish_x86:
                    self.assertEqual(
                        (release / f"box-{tag}-linux-x86_64.tar.gz").read_bytes(),
                        (assets / f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz").read_bytes(),
                    )
                    self.assertNotIn("box-v0.1.1-x86_64-unknown", checksums)
                body = (root / "body.md").read_text()
                self.assertNotIn("unknown-linux", body)
                self.assertNotIn("EXPERIMENTAL_LINUX_SUPPORT", body)
                self.assertIn(f"box-{tag}-linux-arm64.tar.gz", body)
                self.assertEqual(f"box-{tag}-linux-x86_64.tar.gz" in body, publish_x86)
                self.assertNotIn("EXPERIMENTAL_X86_SUPPORT", body)
                self.assertIn("sha256sum --check box-linux.sha256", body)
                self.assertIn("### Manual Linux ARM64 install", body)
                self.assertEqual("## Linux preview" in body, channel == "linux-preview")
                # The installer's latest release is never a prerelease either.
                self.assertEqual("BOX_GITHUB_REPO=example/box sh" in body, not preview)
                self.assertIn(f"BOX_GITHUB_REPO=example/box BOX_VERSION={tag[1:]} sh", body)
                self.assertLess(body.index("## Install box"), body.index("## Download Box Core"))
                support = "macOS 27 or later on Apple silicon"
                self.assertIn(support + (", ARM64 Linux, and x86-64 Linux" if publish_x86
                                         else " and ARM64 Linux"), body)
                self.assertNotIn("experimental", body.lower())
                download = body.index("download.sh | ")
                self.assertLess(download, body.index("### Manual Linux ARM64 install"))
                # releases/latest never returns a prerelease, so a preview page
                # must not offer the unpinned downloader.
                self.assertEqual("download.sh | sh" in body, not preview)
                self.assertIn(f"download.sh | BOX_VERSION={tag} sh", body)
                # Raw build names, and a CLI archive this run did not qualify, must not leak
                # into the public asset set.
                extras = [f"box-{tag}-x86_64-unknown-linux-gnu.tar.gz"]
                if not publish_x86:
                    extras.append(f"box-cli-{tag}-{CLI_X86}.tar.gz")
                for extra in extras:
                    with self.subTest(extra=extra):
                        (release / extra).write_bytes(b"unexpected")
                        result = subprocess.run(
                            ["bash", "-c", workflow_command("Assert the expected tarballs, each carrying box")],
                            cwd=root, env=environment, capture_output=True, text=True,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        (release / extra).unlink()



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
        self.executable(self.package / "box", "#!/bin/sh\n"
                        'if [ "$1" = run ]; then\n'
                        '  [ "${EXPERIMENTAL_LINUX_SUPPORT+x}" != x ] || exit 95\n'
                        '  [ "${EXPERIMENTAL_X86_SUPPORT+x}" != x ] || exit 96\n'
                        '  printf "Missing configuration: %s\\n" "$3" >&2\n'
                        '  exit 1\n'
                        'fi\n'
                        'printf "%s\\n" "$PACKAGE_VERSION"\n')
        self.executable(self.root / "readelf", '#!/bin/sh\nprintf "%s\\n" "$PACKAGE_HEADER"\n')
        self.smoke_arguments = self.root / "smoke-arguments.json"
        self.sudo_arguments = self.root / "sudo-arguments.json"
        self.executable(scripts / "smoke-linux-package.py", "import json, os, sys\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['SMOKE_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
                        "sys.exit(int(os.environ.get('SMOKE_EXIT', '0')))\n")
        self.executable(self.root / "sudo", "#!/usr/bin/env python3\n"
                        "import json, os, sys\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['SUDO_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
                        "sys.exit(int(os.environ.get('SUDO_EXIT', '0')))\n")
        self.docker_arguments = self.root / "docker-arguments.json"
        self.executable(self.root / "docker", "#!/usr/bin/env python3\n"
                        "import json, os, sys\n"
                        "from pathlib import Path\n"
                        "path = Path(os.environ['DOCKER_ARGS'])\n"
                        "calls = json.loads(path.read_text()) if path.exists() else []\n"
                        "path.write_text(json.dumps([*calls, sys.argv[1:]]))\n"
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
                 "DOCKER_ARGS": str(self.docker_arguments), "RUNNER_TEMP": str(self.root),
                 "SUDO_ARGS": str(self.sudo_arguments), "SMOKE_ARGS": str(self.smoke_arguments),
                 "NEW_TAG": "v0.2.4",
                 "EXPERIMENTAL_LINUX_SUPPORT": "TRUE", "EXPERIMENTAL_X86_SUPPORT": "TRUE",
                 **environment},
            text=True,
            capture_output=True,
        )

    def header(self, machine="Advanced Micro Devices X86-64", loader="/lib64/ld-linux-x86-64.so.2", version="2.34"):
        return f"Machine: {machine}\nRequesting program interpreter: {loader}]\nName: GLIBC_{version}\n"

    def test_x86_package_step_checks_all_three_executables_in_read_only_container(self):
        result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.docker_arguments.read_text())[0], [
            "run", "--rm", "--mount", f"type=bind,source={self.root},target=/src,readonly",
            "box-linux-release", "python3", "scripts/check-linux-package.py", "stage/box-core",
            "--target", "x86_64-unknown-linux-gnu",
        ])
        report = json.loads(result.stdout)
        self.assertEqual([item["binary"] for item in report], [
            "box", "strands-box-sock-alias", "strands-box-contain-trampoline",
        ])
        self.assertEqual({item["architecture"] for item in report}, {"x86_64"})

    def test_x86_package_step_runs_its_archive_without_root_or_host_write_access(self):
        workflow = WORKFLOW.read_text()
        step = workflow.split("      - name: Check the x86-64 Linux package\n", 1)[1].split(
            "      - name:", 1
        )[0]
        self.assertIn("        env:\n          NEW_TAG: ${{ needs.scan.outputs.new_tag }}\n", step)
        self.assertRegex(workflow, r"(?m)^          - triple: x86_64-unknown-linux-gnu\n"
                         r"(?:            [^\n]+\n)*            runner: ubuntu-24\.04$")
        self.assertNotRegex(step, r"(?m)^        continue-on-error: (?!false(?:\s|$))")
        result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = json.loads(self.docker_arguments.read_text())
        self.assertEqual(len(calls), 2, "package validation must be followed by a workload run")
        self.assertEqual(calls[1], [
            "run", "--rm", "--cap-drop", "ALL", "--user", "1000:1000",
            "--security-opt", "seccomp=unconfined",
            "--security-opt", "apparmor=box-package-smoke",
            "--security-opt", "systempaths=unconfined",
            "--env", "HOME=/home/box-test",
            "--mount", f"type=bind,source={self.root},target=/src,readonly",
            "box-linux-release", "python3", "scripts/smoke-linux-package.py",
            "dist/box-v0.2.4-x86_64-unknown-linux-gnu.tar.gz",
        ])
        self.assertEqual(json.loads(self.smoke_arguments.read_text()), [
            "dist/box-v0.2.4-x86_64-unknown-linux-gnu.tar.gz",
        ])
        self.assertEqual(json.loads(self.sudo_arguments.read_text()), [
            "apparmor_parser", "-r", str(self.root / "box-package-smoke.apparmor"),
        ])
        profile = (self.root / "box-package-smoke.apparmor").read_text()
        self.assertRegex(profile, r"(?m)^profile box-package-smoke flags=\(unconfined\) \{$")
        self.assertRegex(profile, r"(?m)^\s*userns,$")

    def test_x86_package_step_propagates_a_packaged_workload_failure(self):
        result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header(),
                               SMOKE_EXIT="23")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)

    def test_x86_package_step_does_not_run_a_workload_without_its_namespace_profile(self):
        result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header(),
                               SUDO_EXIT="24")
        self.assertEqual(result.returncode, 24, result.stdout + result.stderr)
        self.assertFalse(self.smoke_arguments.exists())

    def test_x86_package_step_rejects_a_gated_or_wrongly_successful_startup(self):
        for startup in ("gated", "accepts-missing-config"):
            with self.subTest(startup=startup):
                self.executable(self.package / "box", "#!/bin/sh\n"
                                'if [ "$1" = run ]; then\n'
                                + ('  printf "Experimental opt-in required\\n" >&2; exit 1\n'
                                   if startup == "gated" else '  exit 0\n')
                                + 'fi\nprintf "%s\\n" "$PACKAGE_VERSION"\n')
                result = self.run_step("Check the x86-64 Linux package", PACKAGE_HEADER=self.header())
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("::error::Linux x86-64 startup", result.stdout)
                self.assertFalse(self.docker_arguments.exists())

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
