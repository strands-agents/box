"""Exercise experimental package selection with fake build tools, without signing."""

import hashlib
import fnmatch
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
import test_release_source as caller_source
import test_release_source_cli as release_source


FEATURE = "strands-box-cli/native-filesystem-policy"
TARGETS = ("aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")


def workflow_lines(name):
    # The CLI release workflow's step, or else the caller's, such as its scan.
    for path in (release_source.CLI_WORKFLOW, release_source.WORKFLOW):
        lines = path.read_text().splitlines()
        if f"      - name: {name}" in lines:
            return lines
    raise AssertionError(f"step {name!r} is in no release workflow file")


def workflow_step(name):
    lines = workflow_lines(name)
    start = lines.index(f"      - name: {name}") + 1
    end = start
    while end < len(lines):
        if lines[end].startswith("      - name:") or re.match(r"^  [a-z][a-z-]*:$", lines[end]):
            break
        end += 1
    return lines[start:end]


def step_mapping(name, key):
    lines = workflow_step(name)
    start = lines.index(f"        {key}:") + 1
    result = {}
    for line in lines[start:]:
        if not line.startswith("          "):
            break
        field, value = line.strip().split(": ", 1)
        result[field] = value
    return result


def workflow_environment(name, context):
    # Resolve this step's actual scalar expressions instead of supplying the expected bindings.
    environment = dict(os.environ)
    for key in ("NATIVE_FILESYSTEM_POLICY", "TARGET", "NEW_VERSION", "SHA_INPUT", "DRY_RUN", "DISPATCH_SHA", "NEW_TAG"):
        environment.pop(key, None)
    for key, value in step_mapping(name, "env").items():
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        environment[key] = re.sub(r"\$\{\{\s*([^{}]+?)\s*\}\}",
                                  lambda match: context[match[1].strip()], value)
    return environment


def fake_sdk(root, tools, version="27.1"):
    selected = root / "selected SDK"
    old = root / "old SDK"
    selected.mkdir()
    old.mkdir()
    config = root / "sdk-config.json"
    config.write_text(json.dumps({"default": str(selected), "versions": {
        str(selected): version, str(old): "26.6"}}))
    distribution.executable(tools / "xcrun", f"""#!{sys.executable}
import json, pathlib, sys
config_path = pathlib.Path({str(config)!r})
config = json.loads(config_path.read_text())
with (config_path.parent / "sdk-calls.jsonl").open("a") as output:
    print(json.dumps(sys.argv[1:]), file=output)
if config.get("fail"):
    sys.exit("xcrun: SDK is unavailable")
assert len(sys.argv) == 4 and sys.argv[1] == "--sdk", sys.argv
selected = config["default"] if sys.argv[2] == "macosx" else sys.argv[2]
if selected not in config["versions"]:
    sys.exit("xcrun: SDK is unknown")
if sys.argv[3] == "--show-sdk-path":
    print(config.get("resolved_path", selected))
elif sys.argv[3] == "--show-sdk-version":
    print(config["versions"][selected])
else:
    sys.exit("xcrun: unexpected query")
""")
    return config, selected, old


def build_workflow(root, target=TARGETS[0], native="true", *, version="27.1",
                   explicit_old=False, unavailable=False, missing_path=False):
    tools = root / "tools"
    tools.mkdir()
    config_path, sdk, old = fake_sdk(root, tools, version)
    config = json.loads(config_path.read_text())
    config["fail"] = unavailable
    if missing_path:
        config["resolved_path"] = str(root / "missing SDK")
    config_path.write_text(json.dumps(config))
    capture = root / "commands.jsonl"
    for name in ("cargo", "docker"):
        distribution.executable(tools / name, f"""#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["BUILD_FIXTURE"])
(root / "build-started").touch()
with (root / "commands.jsonl").open("a") as output:
    print(json.dumps(sys.argv), file=output)
with (root / "cargo-sdkroots.jsonl").open("a") as output:
    print(json.dumps(os.environ.get("SDKROOT")), file=output)
with (root / "cargo-deployment-targets.jsonl").open("a") as output:
    print(json.dumps(os.environ.get("MACOSX_DEPLOYMENT_TARGET")), file=output)
""")
    step = "Build Box (release)" if target == TARGETS[0] else "Build Linux against glibc 2.34"
    environment = workflow_environment(step, {
        "matrix.target.triple": target,
        "inputs.native_filesystem_policy": native if native is not None else caller_source.workflow_input_default(
            "native_filesystem_policy", release_source.CLI_WORKFLOW),
    })
    environment.pop("SDKROOT", None)
    if target != TARGETS[0]:
        environment.pop("MACOSX_DEPLOYMENT_TARGET", None)
    if explicit_old:
        environment["SDKROOT"] = str(old)
    output = root / "github-output"
    output.touch()
    environment.update(PATH=f"{tools}:{os.environ['PATH']}", BUILD_FIXTURE=str(root), GITHUB_OUTPUT=str(output))
    result = subprocess.run(["bash", "-c", release_source.workflow_command(step)], cwd=root,
                            env=environment, capture_output=True, text=True, timeout=20)
    def records(name):
        path = root / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return result, dict(commands=records("commands.jsonl"), sdk_calls=records("sdk-calls.jsonl"),
                        cargo_sdkroots=records("cargo-sdkroots.jsonl"), sdk_path=str(sdk),
                        deployment_targets=records("cargo-deployment-targets.jsonl"),
                        old_sdk_path=str(old), outputs=dict(line.split("=", 1) for line in output.read_text().splitlines()))


class ReleaseModeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = caller_source.ReleaseSourceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def scan_source(self, native, dry_run, version="0.1.1"):
        output = self.fixture.root / "output"
        output.write_text("")
        environment = workflow_environment("Resolve SHA, find previous tag, validate version", {
            "inputs.native_filesystem_policy": native if native is not None else caller_source.workflow_input_default(
                "native_filesystem_policy"),
            "inputs.dry_run": dry_run, "inputs.version": version,
            "inputs.publish_linux_x86": "true",
            "inputs.sha": "", "github.sha": self.fixture.candidate,
        })
        environment.update(GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(self.fixture.root / "summary"))
        result = subprocess.run(["bash", "-c", self.fixture.scan], cwd=self.fixture.root, env=environment,
                                capture_output=True, text=True, timeout=20)
        return result, output.read_text()

    def test_native_selection_accepts_every_published_channel(self):
        for version in ("0.1.1", "0.1.1-preview.1", "0.1.1-linux-preview.1"):
            for native in (None, "true", "false"):
                with self.subTest(version=version, native=native):
                    result, output = self.scan_source(native, "false", version=version)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"release_sha={self.fixture.main}\n", output)
                    self.assertIn(f"new_tag=v{version}\n", output)

    def test_native_selection_preserves_dry_run_source_selection(self):
        for native in (None, "false", "true"):
            with self.subTest(native=native):
                result, output = self.scan_source(native, "true")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"release_sha={self.fixture.candidate}\n", output)

    def test_unknown_native_selection_is_rejected(self):
        result, output = self.scan_source("TRUE", "true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native_filesystem_policy must be true or false", result.stdout)
        self.assertEqual(output, "")

    def test_workflow_input_defaults_to_compiled_support(self):
        for path in (release_source.WORKFLOW, release_source.CLI_WORKFLOW):
            with self.subTest(workflow=path.name):
                workflow = path.read_text()
                self.assertIn("      native_filesystem_policy:\n", workflow)
                self.assertEqual(caller_source.workflow_input_default("native_filesystem_policy", path), "true")
                self.assertRegex(workflow, r"(?m)^      native_filesystem_policy:\n(?:        .*\n)*        type: boolean\n")
                self.assertIn("          NATIVE_FILESYSTEM_POLICY: ${{ inputs.native_filesystem_policy }}", workflow)
        caller = release_source.WORKFLOW.read_text()
        self.assertIn("      native_filesystem_policy: ${{ inputs.native_filesystem_policy }}\n", caller)


class BuildFeatureTests(unittest.TestCase):
    def test_actual_build_commands_select_only_supported_targets(self):
        for target in TARGETS:
            for native in (None, "false", "true"):
                with self.subTest(target=target, native=native), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    result, observed = build_workflow(root, target, native)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    commands = observed["commands"]
                    self.assertEqual(len(commands), 1)
                    self.assertEqual(observed["deployment_targets"], ["27.0" if target == TARGETS[0] else None])
                    args = commands[0]
                    self.assertNotIn("--all-features", args)
                    expected = native != "false" and target != TARGETS[2]
                    self.assertEqual("--features" in args, expected, args)
                    self.assertEqual(FEATURE in args, expected, args)
                    if expected:
                        self.assertEqual(args[args.index("--features") + 1], FEATURE)
                    for required in ("--locked", "--release", "strands-box-cli", "strands-box", "strands-box-containment",
                                     "box", "strands-box-sock-alias", "strands-box-contain-trampoline"):
                        self.assertIn(required, args)
                    self.assertEqual(args[args.index("--target") + 1], target)

    def test_workflow_receipt_binds_archive_features_and_selected_sdk(self):
        workflow = release_source.CLI_WORKFLOW.read_text()
        self.assertIn("      - name: Record experimental build features\n", workflow)
        step = workflow.split("      - name: Record experimental build features\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("        if: inputs.native_filesystem_policy == true", step)
        for target in TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build, observed = build_workflow(root, target)
                self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                (root / "stage/package").mkdir(parents=True)
                (root / "dist").mkdir()
                record = dict(box_commit="a" * 40, core_commit="b" * 40, target=target)
                (root / "stage/package/release.json").write_text(json.dumps(record))
                archive = root / f"dist/box-cli-v0.1.1-{target}.tar.gz"
                archive.write_bytes(b"exact built archive")
                result = subprocess.run(["bash", "-c", release_source.workflow_command("Record experimental build features")],
                                        cwd=root, env=workflow_environment("Record experimental build features", {
                                            "inputs.tag": "v0.1.1", "matrix.target.triple": target,
                                            "steps.build_box.outputs.macos_sdk_version": observed["outputs"].get("macos_sdk_version", ""),
                                        }), capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                receipt = json.loads((root / "dist/native-filesystem-policy.json").read_text())
                self.assertEqual(receipt["cargo_features"], [FEATURE] if target != TARGETS[2] else [])
                self.assertEqual(receipt["archive"], archive.name)
                self.assertEqual(receipt["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
                for key, value in record.items():
                    self.assertEqual(receipt[key], value)
                self.assertFalse(receipt["runtime_qualified"])
                self.assertEqual(receipt["archive_stage"], "unsigned_build")
                if target == TARGETS[0]:
                    self.assertEqual(receipt["macos_sdk_version"], "27.1")
                    self.assertEqual(observed["cargo_sdkroots"], [observed["sdk_path"]])
                    self.assertEqual(observed["sdk_calls"], [["--sdk", "macosx", "--show-sdk-path"],
                        ["--sdk", observed["sdk_path"], "--show-sdk-version"]])
                else:
                    self.assertNotIn("macos_sdk_version", receipt)
                    self.assertEqual(observed["sdk_calls"], [])


    def test_native_workflow_refuses_old_default_sdk_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, observed = build_workflow(Path(temporary), version="26.6")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("macOS SDK", result.stderr + result.stdout)
            self.assertEqual(observed["commands"], [])

    def test_native_workflow_refuses_old_explicit_sdkroot_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, observed = build_workflow(Path(temporary), explicit_old=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("macOS SDK", result.stderr + result.stdout)
            self.assertEqual(observed["commands"], [])
            self.assertEqual(observed["sdk_calls"][0],
                             ["--sdk", observed["old_sdk_path"], "--show-sdk-path"])

    def test_native_workflow_refuses_unavailable_or_invalid_sdk_before_build(self):
        cases = [dict(unavailable=True), dict(missing_path=True)]
        cases += [dict(version=value) for value in ("", "unknown", "27beta", "27..1", "27.1.2.3")]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                result, observed = build_workflow(Path(temporary), **case)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("macOS SDK", result.stderr + result.stdout)
                self.assertEqual(observed["commands"], [])

    def test_native_off_and_linux_do_not_probe_or_replace_the_sdk(self):
        for target, native in ((TARGETS[0], "false"), (TARGETS[1], "true"), (TARGETS[2], "true")):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                result, observed = build_workflow(Path(temporary), target, native,
                                                  explicit_old=True, unavailable=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(observed["sdk_calls"], [])
                self.assertEqual(observed["cargo_sdkroots"], [observed["old_sdk_path"]])
                self.assertEqual(observed["outputs"], {})

    def test_workflow_uses_the_sdk27_runner_for_all_macos_packages(self):
        workflow = release_source.CLI_WORKFLOW.read_text()
        matrix = workflow.split("      matrix:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertIn("- triple: aarch64-apple-darwin\n"
                      "            runner: xcode-27", matrix)
        self.assertIn("- triple: aarch64-unknown-linux-gnu\n            runner: ubuntu-24.04-arm", matrix)
        self.assertIn("- triple: x86_64-unknown-linux-gnu\n            runner: ubuntu-24.04", matrix)
        for job in ("sign-macos", "verify-macos"):
            body = workflow.split(f"  {job}:\n", 1)[1].split("    steps:", 1)[0]
            self.assertIn("    runs-on: xcode-27\n", body)
        checks = (release_source.CLI_WORKFLOW.parent / "cli-test.yml").read_text()
        for job in ("macos", "package"):
            body = checks.split(f"\n  {job}:\n", 1)[1].split("    steps:", 1)[0]
            self.assertIn("    runs-on: xcode-27\n", body)
            if job == "macos":
                self.assertIn('      MACOSX_DEPLOYMENT_TARGET: "27.0"\n', body)
        self.assertIn("        os: [xcode-27]\n", checks)

    def test_package_ci_refuses_older_macos_before_building(self):
        checks = (release_source.CLI_WORKFLOW.parent / "cli-test.yml").read_text()
        step = checks.split("      - name: Check build host\n", 1)[1].split("      - name:", 1)[0]
        command = "\n".join(line[10:] for line in step.splitlines() if line.startswith("          "))
        with tempfile.TemporaryDirectory() as temporary:
            tools = Path(temporary)
            distribution.executable(tools / "uname", '#!/bin/sh\nprintf "%s\\n" "$TEST_ARCH"\n')
            distribution.executable(tools / "sw_vers", '#!/bin/sh\nprintf "%s\\n" "$TEST_MACOS"\n')
            for version, architecture, accepted in (("15.0", "arm64", False), ("26.6", "arm64", False),
                                                     ("27.0", "arm64", True), ("28.0", "arm64", True),
                                                     ("27.0", "x86_64", False)):
                with self.subTest(version=version, architecture=architecture):
                    result = subprocess.run(["bash", "-e", "-c", command], env={
                        **os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                        "TEST_MACOS": version, "TEST_ARCH": architecture,
                    }, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_workflow_uploads_each_experimental_receipt_separately(self):
        step = "Upload experimental build features"
        lines = workflow_step(step)
        self.assertIn("        if: inputs.native_filesystem_policy == true", lines)
        self.assertIn("        uses: actions/upload-artifact@v7", lines)
        settings = step_mapping(step, "with")
        self.assertEqual(settings["path"], "dist/native-filesystem-policy.json")
        self.assertEqual(settings["if-no-files-found"], "error")
        self.assertEqual(settings["name"], "cli-native-filesystem-policy-${{ matrix.target.triple }}")
        bundle = step_mapping("Download all build artifacts", "with")["pattern"]
        self.assertEqual(bundle, "cli-${{ inputs.tag }}-*")
        for target in TARGETS:
            name = settings["name"].replace("${{ matrix.target.triple }}", target)
            self.assertEqual(name, f"cli-native-filesystem-policy-{target}")
            for tag in ("v0.1.1", "v0.1.1-linux-preview.1"):
                self.assertFalse(fnmatch.fnmatch(name, bundle.replace("${{ inputs.tag }}", tag)),
                                 "feature evidence must stay outside release bundle selection")
            self.assertFalse(name.startswith("box-"), "a caller's box-* download must not pick it up")


class LocalPackageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = distribution.Package()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        distribution.executable(self.fixture.tools / "uname", "#!/bin/sh\nprintf 'Darwin\n'\n")
        distribution.executable(self.fixture.tools / "shasum", f"""#!{sys.executable}
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[-1])
print(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path))
""")
        self.sdk_config, self.sdk, self.old_sdk = fake_sdk(self.fixture.root, self.fixture.tools)
        self.fixture.env.pop("SDKROOT", None)
        cargo = self.fixture.tools / "cargo"
        original = cargo.read_text()
        cargo.write_text(original.replace('root = pathlib.Path(os.environ["TEST_REPO"])',
            'root = pathlib.Path(os.environ["TEST_REPO"])\n'
            'with (root / "cargo-commands.jsonl").open("a") as output:\n'
            '    output.write(json.dumps(sys.argv[1:]) + "\\n")\n'
            'with (root / "cargo-sdkroots.jsonl").open("a") as output:\n'
            '    output.write(json.dumps(os.environ.get("SDKROOT")) + "\\n")'))

    def run_package(self, *options):
        return subprocess.run(["sh", str(self.fixture.script), *options, str(self.fixture.output)],
                              env=self.fixture.env, capture_output=True, text=True, timeout=20)

    def test_default_package_keeps_feature_and_extra_receipt_absent(self):
        config = json.loads(self.sdk_config.read_text())
        config["fail"] = True
        self.sdk_config.write_text(json.dumps(config))
        self.fixture.env["SDKROOT"] = str(self.old_sdk)
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.fixture.root / "sdk-calls.jsonl").exists())
        commands = [json.loads(line) for line in (self.fixture.root / "cargo-commands.jsonl").read_text().splitlines()]
        self.assertEqual(len(commands), 2)
        self.assertNotIn("--features", commands[1])
        self.assertEqual({p.name for p in self.fixture.output.iterdir()},
                         {f"box-cli-v0.1.0-{distribution.TARGET}.tar.gz", "SHA256SUMS.txt"})

    def test_native_package_passes_feature_and_binds_unchanged_payload(self):
        result = self.run_package("--native-filesystem-policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [json.loads(line) for line in (self.fixture.root / "cargo-commands.jsonl").read_text().splitlines()]
        self.assertEqual(commands[1][commands[1].index("--features") + 1], FEATURE)
        archive = self.fixture.output / f"box-cli-v0.1.0-{distribution.TARGET}.tar.gz"
        receipt = json.loads((self.fixture.output / "native-filesystem-policy.json").read_text())
        with tarfile.open(archive) as source:
            names = {member.name.removeprefix("./") for member in source if member.isfile()}
            self.assertEqual(names, {*distribution.BINARIES, "release.json", "resources/config.toml",
                                    "resources/packs/base/pack.toml", "resources/policies/open/policy.toml",
                                    distribution.STARTER_FILE, distribution.PLUGIN_FILE,
                                    distribution.GUIDE_FILE})
            record = json.load(source.extractfile("./release.json"))
        for key in ("box_commit", "core_commit", "target"):
            self.assertEqual(receipt[key], record[key])
        self.assertEqual(receipt["cargo_features"], [FEATURE])
        self.assertEqual(receipt["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertFalse(receipt["runtime_qualified"])
        self.assertEqual(receipt["archive_stage"], "unsigned_build")
        self.assertEqual(receipt["archive"], archive.name)
        self.assertEqual(receipt["macos_sdk_version"], "27.1")
        sdkroots = [json.loads(line) for line in (self.fixture.root / "cargo-sdkroots.jsonl").read_text().splitlines()]
        self.assertEqual(sdkroots[-1], str(self.sdk))
        calls = [json.loads(line) for line in (self.fixture.root / "sdk-calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["--sdk", "macosx", "--show-sdk-path"],
                                ["--sdk", str(self.sdk), "--show-sdk-version"]])

    def assert_sdk_refusal(self):
        result = self.run_package("--native-filesystem-policy")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("macOS SDK", result.stderr)
        self.assertFalse((self.fixture.root / "build-started").exists())
        self.assertFalse(self.fixture.output.exists())

    def test_native_package_refuses_old_default_sdk_before_build(self):
        config = json.loads(self.sdk_config.read_text())
        config["versions"][str(self.sdk)] = "26.6"
        self.sdk_config.write_text(json.dumps(config))
        self.assert_sdk_refusal()

    def test_native_package_refuses_old_explicit_sdkroot_before_build(self):
        self.fixture.env["SDKROOT"] = str(self.old_sdk)
        self.assert_sdk_refusal()
        calls = [json.loads(line) for line in (self.fixture.root / "sdk-calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls[0], ["--sdk", str(self.old_sdk), "--show-sdk-path"])

    def test_native_package_refuses_unavailable_or_invalid_sdk_before_build(self):
        for case in ("unavailable", "missing-path", "", "unknown", "27beta", "27..1", "27.1.2.3"):
            with self.subTest(case=case):
                config = json.loads(self.sdk_config.read_text())
                config["fail"] = case == "unavailable"
                config.pop("resolved_path", None)
                if case == "missing-path":
                    config["resolved_path"] = str(self.fixture.root / "missing SDK")
                config["versions"][str(self.sdk)] = case
                self.sdk_config.write_text(json.dumps(config))
                self.assert_sdk_refusal()

    def test_native_selection_preserves_clean_source_refusal(self):
        (self.fixture.root / "Cargo.lock").write_text("changed\n")
        result = self.run_package("--native-filesystem-policy")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit changes", result.stderr)
        self.assertFalse((self.fixture.root / "build-started").exists())
        self.assertFalse(self.fixture.output.exists())

    def test_unknown_or_repeated_flag_refuses_before_build(self):
        for options in (("--native-filesystem-policy=false",), ("--native-filesystem-policy", "--native-filesystem-policy")):
            with self.subTest(options=options):
                result = self.run_package(*options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("usage:", result.stderr)
                self.assertFalse((self.fixture.root / "build-started").exists())
                self.assertFalse(self.fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
