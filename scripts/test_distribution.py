#!/usr/bin/env python3
"""Exercise distribution scripts with local downloads and simulated signing tools."""
# pyright: reportUninitializedInstanceVariable=false

import ast
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
POLICY_FILES = tuple(f"resources/policies/{name}/{file}" for name in ("open", "scoped", "locked")
                     for file in ("policy.toml", "policy.dw"))
STARTER_FILE = "resources/starters/claude/starter.toml"
PLUGIN_FILE = "resources/plugins/1password/plugin.toml"
GUIDE_FILE = "resources/editing-box-profile.md"
TARGET = "aarch64-apple-darwin"
TEAM = "94KV3E626L"
NATIVE_ALIASES = {
    "strands-box-sock-alias": "Box.app/Contents/MacOS/strands-box-sock-alias",
    "strands-box-contain-trampoline": "Box.app/Contents/MacOS/strands-box-contain-trampoline",
    "resources": "Box.app/Contents/Resources/resources",
    "release.json": "Box.app/Contents/Resources/release.json",
}


def native_launcher():
    tree = ast.parse((ROOT / "scripts/macos-release-cli.py").read_text())
    return next(ast.literal_eval(node.value).encode() for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "NATIVE_LAUNCHER"
                        for target in node.targets))

FISH = os.environ.get("TEST_FISH_BINARY") or shutil.which("fish")
CATEGORIES = ("Package", "Verification", "Installation", "PATH & shells", "Test reporting")
CATEGORY_WIDTH = max(map(len, CATEGORIES))
TABLE_OVERHEAD = 31 + CATEGORY_WIDTH
MIN_TABLE_COLUMNS = TABLE_OVERHEAD + 15


def category(name):
    def label(method):
        method.category_name = name
        return method
    return label


def category_for(test):
    method = getattr(test, test._testMethodName)
    return getattr(method, "category_name", getattr(test, "category_name", "Test reporting"))


def executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


def tree(directory, indent=""):
    lines = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            lines.append(f"{indent}{path.name} -> {path.readlink()}")
        elif path.is_dir():
            lines.append(f"{indent}{path.name}/")
            lines.extend(tree(path, indent + "  "))
        else:
            lines.append(f"{indent}{path.name}  ({path.stat().st_size} bytes)")
    return lines


class TableResult(unittest.TextTestResult):
    def __init__(self, stream, descriptions, verbosity, **kwargs):
        super().__init__(stream, descriptions, 0, **kwargs)
        self.evidence = []

    def queue(self, cases):
        self.cases = cases
        self.categories = [category_for(case) for case in cases]
        self.labels = [case.shortDescription() or case.id().split(".")[-1].removeprefix("test_").replace("_", " ")
                       for case in cases]
        self.states = ["QUEUED"] * len(cases)
        self.elapsed = ["-"] * len(cases)
        self.notes = []
        self.size = self.terminal_size()
        self.live = self.stream.isatty() and os.environ.get("TERM") != "dumb" and self.size.columns >= MIN_TABLE_COLUMNS
        self.scrolled = len(cases) + 1 >= self.size.lines
        self.draw()

    def terminal_size(self):
        try:
            size = os.get_terminal_size(self.stream.fileno())
            if size.columns > 0 and size.lines > 1:
                return size
        except (OSError, ValueError):
            pass
        return os.terminal_size((120, 40))

    def row(self, index):
        width = max(8, min(62, self.size.columns - TABLE_OVERHEAD - 1))
        label = self.labels[index]
        if len(label) > width:
            label = label[:width - 3] + "..."
        return (f"{index + 1:>2} | {self.categories[index]:<{CATEGORY_WIDTH}} | {label:<{width}} | "
                f"{self.states[index]:<11} | {self.elapsed[index]:>6}")

    def draw(self, update=False):
        size = self.terminal_size()
        resized = size != self.size
        self.size = size
        if self.live and size.columns < MIN_TABLE_COLUMNS:
            self.live = False
            self.scrolled = True
            update = False
        finished = sum(state not in ("QUEUED", "RUNNING") for state in self.states)
        progress = f"Progress: {finished}/{len(self.cases)} complete"
        if "RUNNING" in self.states:
            progress = f"Progress: {finished}/{len(self.cases)} | Running: #{self.states.index('RUNNING') + 1}"
        if self.live:
            progress = progress[:self.size.columns - 1]
        lines = [self.row(index) for index in range(len(self.cases))] + [progress]
        if update and not resized:
            visible = min(len(lines), self.size.lines - 1)
            self.scrolled |= visible < len(lines)
            self.stream.write(f"\033[{visible}F")
            lines = lines[-visible:]
        else:
            if resized:
                self.scrolled = True
                self.stream.writeln()
            width = max(8, min(62, self.size.columns - TABLE_OVERHEAD - 1))
            self.stream.writeln(f" # | {'CATEGORY':<{CATEGORY_WIDTH}} | {'TEST':<{width}} | {'STATUS':<11} |   TIME")
            self.stream.writeln("-" * (width + TABLE_OVERHEAD))
        prefix = "\033[2K\033[1G" if self.live else ""
        self.stream.write("".join(prefix + line + "\n" for line in lines))
        self.stream.flush()

    def startTest(self, test):
        super().startTest(test)
        self.index = next(index for index, case in enumerate(self.cases) if case is test)
        self.started = time.monotonic()
        self.status = "INTERRUPTED"
        self.reason = ""
        self.states[self.index] = "RUNNING"
        if self.live:
            self.draw(update=True)
        else:
            self.stream.writeln(self.row(self.index))
        self.stream.flush()

    def addSuccess(self, test):
        super().addSuccess(test)
        self.status = "PASS"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.status != "ERROR":
            self.status = "FAIL"

    def addError(self, test, err):
        super().addError(test, err)
        self.status = "ERROR"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None and self.status != "ERROR":
            self.status = "FAIL" if isinstance(err[1], test.failureException) else "ERROR"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.status not in ("FAIL", "ERROR"):
            self.status = "SKIP"
        self.reason = reason

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.status = "XFAIL"

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.status = "XPASS"

    def stopTest(self, test):
        self.states[self.index] = self.status
        self.elapsed[self.index] = f"{time.monotonic() - self.started:.1f}s"
        if self.live:
            self.draw(update=True)
        else:
            self.stream.writeln(self.row(self.index))
        if self.reason:
            self.notes.append(f"Test {self.index + 1}: {self.reason}")
        evidence = getattr(test, "evidence", None)
        if self.status == "PASS" and evidence:
            self.evidence.append(evidence)
        self.stream.flush()
        super().stopTest(test)

    def stopTestRun(self):
        if self.scrolled:
            self.stream.writeln("\nFinal results:")
            self.draw()
        for note in self.notes:
            self.stream.writeln(note)
        super().stopTestRun()


class TableRunner(unittest.TextTestRunner):
    resultclass = TableResult

    def _makeResult(self):
        result = super()._makeResult()
        assert isinstance(result, TableResult)
        result.queue(self.cases)
        return result

    def run(self, test):
        def cases(suite):
            if isinstance(suite, unittest.TestSuite):
                for child in suite:
                    yield from cases(child)
            else:
                yield suite

        self.cases = sorted(cases(test), key=lambda case: CATEGORIES.index(category_for(case)))
        self.stream.writeln("Local fixture tests: downloads, Apple signing, and Cargo are simulated.")
        self.stream.writeln("No network downloads, Rust builds, or changes to your installation.\n")
        result = super().run(unittest.TestSuite(self.cases))
        assert isinstance(result, TableResult)
        for evidence in result.evidence:
            self.stream.writeln("\n" + evidence)
        return result


class Reporting(unittest.TestCase):
    category_name = "Test reporting"

    def test_categories_group_the_table_and_execution(self):
        """Category column groups related tests before execution"""
        categories = ["Package", "Verification", "Installation", "PATH & shells", "Test reporting"]
        executed = []
        cases = []
        for name in reversed(categories):
            case = unittest.FunctionTestCase(lambda name=name: executed.append(name), description=f"{name} sample")
            setattr(case, "category_name", name)
            cases.append(case)
        output = io.StringIO()
        result = TableRunner(stream=output).run(unittest.TestSuite(cases))
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertEqual(executed, categories)
        self.assertIn("CATEGORY", output.getvalue())
        queued = [line for line in output.getvalue().splitlines() if "| QUEUED" in line]
        self.assertEqual([line.split("|")[1].strip() for line in queued], categories)

    def test_all_tests_are_queued_before_the_first_test_runs(self):
        """Every test appears as QUEUED before execution starts"""
        output = io.StringIO()
        observer = self

        class Cases(unittest.TestCase):
            def test_first(self):
                queued = [line for line in output.getvalue().splitlines() if "| QUEUED" in line]
                observer.assertEqual(len(queued), 2)
                observer.assertTrue(any("first" in line for line in queued))
                observer.assertTrue(any("second" in line for line in queued))

            def test_second(self):
                pass

        result = TableRunner(stream=output).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
        self.assertTrue(result.wasSuccessful(), output.getvalue())

    def test_failures_errors_and_skips_remain_visible(self):
        """Status table preserves failures, errors, and skip reasons"""
        class Cases(unittest.TestCase):
            def test_failure(self):
                with self.subTest(name="sample"):
                    self.fail("sample failure")
                with self.subTest(name="skipped"):
                    self.skipTest("sample subtest skipped")

            def test_error(self):
                with self.subTest(name="sample"):
                    raise RuntimeError("sample error")
                with self.subTest(name="skipped"):
                    self.skipTest("sample subtest skipped")

            @unittest.skip("sample dependency missing")
            def test_skip(self):
                pass

        output = io.StringIO()
        result = TableRunner(stream=output).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
        self.assertFalse(result.wasSuccessful())
        self.assertEqual((len(result.failures), len(result.errors), len(result.skipped)), (1, 1, 3))
        for status in ("FAIL ", "ERROR ", "SKIP "):
            self.assertIn("| " + status, output.getvalue())
        for message in ("sample failure", "sample error", "sample dependency missing"):
            self.assertIn(message, output.getvalue())


@unittest.skipUnless(platform.system() in ("Darwin", "Linux"), "macOS and Linux installer")
class Installer(unittest.TestCase):
    category_name = "Installation"

    root: Path
    home: Path
    tools: Path
    feed: Path
    log: Path
    script: Path
    env: dict[str, str]
    keep: bool
    target: str

    def setUp(self):
        self.target = TARGET if platform.system() == "Darwin" else "aarch64-unknown-linux-gnu"
        self.root = Path(tempfile.mkdtemp(prefix="box-test-", dir="/var/tmp"))
        self.keep = False
        self.addCleanup(self.cleanup_fixture)
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.feed = self.root / "feed"
        self.feed.mkdir()
        self.log = self.root / "executed"
        self.script = self.root / "install.sh"
        self.script.write_text((ROOT / "install.sh").read_text())
        self.env = dict(os.environ, HOME=str(self.home), SHELL="/bin/zsh",
                        PATH=f"{self.tools}:/usr/bin:/bin:/usr/sbin:/sbin",
                        TEST_OS=platform.system(), TEST_ARCH="aarch64" if platform.system() == "Linux" else "arm64",
                        TEST_FEED=str(self.feed), TEST_LOG=str(self.log),
                        TEST_DOWNLOADS=str(self.root / "downloads"))
        for key in ("BOX_VERSION", "BOX_NO_MODIFY_PATH", "BOX_GITHUB_REPO", "BOX_ALLOW_UNSIGNED",
                    "BOX_TELEMETRY", "DO_NOT_TRACK", "ZDOTDIR", "XDG_CONFIG_HOME"):
            self.env.pop(key, None)
        executable(self.tools / "uname", """#!/bin/sh
case "$1" in
    -s) printf '%s\\n' "$TEST_OS" ;;
    -m) printf '%s\\n' "$TEST_ARCH" ;;
    *) exec /usr/bin/uname "$@" ;;
esac
""")
        executable(self.tools / "getconf", """#!/bin/sh
if [ "${TEST_GLIBC+x}" = x ]; then printf '%s\\n' "$TEST_GLIBC"; else exec /usr/bin/getconf "$@"; fi
""")
        executable(self.tools / "gh", f"""#!{sys.executable}
import hashlib, json, os, pathlib, shutil, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["TEST_FEED"])
with root.parent.joinpath("gh-calls").open("a") as log:
    log.write(json.dumps(args) + "\\n")
if os.environ.get("TEST_GH_FAILURE"): sys.exit(1)
if args[:2] == ["release", "view"]:
    print(os.environ.get("TEST_RELEASE_TAG", "v" + (root / "releases/latest").read_text().strip()))
    sys.exit(0)
assert args[:2] == ["release", "download"], args
if os.environ.get("TEST_GH_DOWNLOAD_FAILURE"): sys.exit(1)
asset = args[args.index("--pattern") + 1]
source = root / "releases" / args[2].removeprefix("v") / asset
destination = pathlib.Path(args[args.index("--output") + 1])
repo = args[args.index("--repo") + 1]
url = f"https://github.com/{{repo}}/releases/download/{{args[2]}}/{{asset}}"
shutil.copyfile(source, destination)
captured = pathlib.Path(os.environ["TEST_DOWNLOADS"])
captured.mkdir(exist_ok=True)
shutil.copyfile(destination, captured / source.name)
with (captured / "transfers.jsonl").open("a") as log:
    log.write(json.dumps(dict(url=url, destination=str(destination),
                             sha256=hashlib.sha256(destination.read_bytes()).hexdigest())) + "\\n")
""")
        executable(self.tools / "codesign", f"""#!{sys.executable}
import os, pathlib, sys
name = pathlib.Path(sys.argv[-1]).name
identifier = "com.amazon.strands.box-cli" if name in ("box", "Box.app") else "com.amazon.strands.box"
if os.environ.get("TEST_BAD_SIGNATURE"): sys.exit(1)
team = os.environ.get("TEST_TEAM", "{TEAM}")
if "--display" in sys.argv:
    print(f"Identifier={{identifier}}\\nAuthority=Developer ID Application: Test ({{team}})\\nTeamIdentifier={{team}}\\nCodeDirectory v=20500 flags=0x10000(runtime)\\nTimestamp=Jan 1, 2026\\ndesignated => identifier")
else:
    requirement = sys.argv[sys.argv.index("--test-requirement") + 1]
    assert f'identifier "{{identifier}}"' in requirement
    assert 'subject.OU] = "{TEAM}"' in requirement
    if team != "{TEAM}": sys.exit(1)
    if os.environ.get("TEST_BAD_REQUIREMENT"):
        print(f"{{sys.argv[-1]}}: code failed to satisfy specified code requirement(s)", file=sys.stderr)
        sys.exit(1)
    print(f"{{sys.argv[-1]}}: valid on disk", file=sys.stderr)
""")
        executable(self.tools / "spctl", f"""#!{sys.executable}
import json, os, pathlib, sys
kind = "execute" if pathlib.Path(sys.argv[-1]).name == "Box.app" else "install"
if len(sys.argv) != 5 or sys.argv[1:4] != ["--assess", "--type", kind]:
    sys.exit(3)
if os.environ.get("TEST_BAD_GATEKEEPER"): sys.exit(1)
with pathlib.Path(os.environ["TEST_FEED"]).parent.joinpath("gatekeeper-calls").open("a") as log:
    log.write(json.dumps(pathlib.Path(sys.argv[-1]).name) + "\\n")
""")
        executable(self.tools / "mv", """#!/bin/sh
case "$*" in
    *current.next*) [ -z "${TEST_FAIL_ACTIVATION-}" ] || exit 1 ;;
    *.box-path*) [ -z "${TEST_FAIL_PATH-}" ] || exit 1 ;;
esac
exec /bin/mv "$@"
""")
        self.release("0.1.0")

    def cleanup_fixture(self):
        if not self.keep:
            shutil.rmtree(self.root)

    def release(self, version, extra=None, missing=None, metadata=None, release_json=None,
                packs="packs", native=False, aliases=None, launcher=None, prefix="box-cli"):
        # Releases name the archive box-cli-v<version>-<triple>.tar.gz; earlier ones used box-.
        directory = self.feed / "releases" / version
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / f"{prefix}-v{version}-{self.target}.tar.gz"
        record = dict(box_version=version, box_commit="a" * 40,
                      core_version="0.1.0", core_commit="b" * 40, target=self.target)
        record.update(metadata or {})
        payload = f"""#!/bin/sh
printf '%s\\n' "$0" >> "$TEST_LOG"
case "$0" in */.local/bin/box|*/.strands/box/packages/*/Box.app/Contents/MacOS/box) [ -z "${{TEST_FAIL_LAUNCH-}}" ] || exit 1 ;; esac
if [ "$*" = "telemetry status" ]; then
    case "${{TEST_TELEMETRY_STATUS-}}" in
        failed)
            printf 'Telemetry is on.\\n'
            printf 'telemetry status failed\\n' >&2
            exit 1 ;;
        unknown) printf 'Unrecognized telemetry status.\\n'; exit 0 ;;
    esac
    if [ -n "${{BOX_TELEMETRY-}}" ]; then
        case "$BOX_TELEMETRY" in
            1|true|on) printf 'Telemetry is on (set by BOX_TELEMETRY).\\n' ;;
            *) printf 'Telemetry is off (set by BOX_TELEMETRY).\\n' ;;
        esac
    elif [ "${{DO_NOT_TRACK-}}" = 1 ]; then
        printf 'Telemetry is off (set by DO_NOT_TRACK).\\n'
    elif grep -q '^telemetry = false$' "$HOME/.strands/box/installation.toml" 2>/dev/null; then
        printf 'Telemetry is off (saved in ~/.strands/box/installation.toml).\\n'
    else
        printf 'Telemetry is on.\\n'
    fi
    exit 0
fi
printf 'box {version}\\n'
""".encode()
        files = {name: payload for name in BINARIES}
        files.update({"release.json": json.dumps(record).encode() if release_json is None else release_json,
                      "resources/config.toml": b'[starters]\nonly = []\n',
                      f"resources/{packs}/base/pack.toml": b'[pack]\nname = "@box/base"\n'})
        if packs == "shared":
            # A release up to v0.1.11: starters inside the agent packs, open and project policies.
            policies = ("open", "project")
        else:
            policies = ("open", "scoped", "locked")
            files[STARTER_FILE] = b'[starter]\nname = "@box/claude"\n'
            files[PLUGIN_FILE] = b'[plugin]\nname = "@box/1password"\n'
            files[GUIDE_FILE] = b"# Profile authoring\n"
        files.update({f"resources/policies/{name}/{file}": b"" for name in policies
                      for file in ("policy.toml", "policy.dw")})
        if native:
            files = {("Box.app/Contents/MacOS/" + name if name in BINARIES
                      else "Box.app/Contents/Resources/" + name): data
                     for name, data in files.items()}
            files.update({
                "box": native_launcher() if launcher is None else launcher,
                "Box.app/Contents/Info.plist": b"native bundle metadata",
                "Box.app/Contents/embedded.provisionprofile": b"native profile",
                "Box.app/Contents/CodeResources": b"stapled ticket",
                "Box.app/Contents/_CodeSignature/CodeResources": b"resource seal",
            })
        if missing:
            name = missing
            if native and not name.startswith("Box.app/"):
                name = ("Box.app/Contents/MacOS/" if name in BINARIES
                        else "Box.app/Contents/Resources/") + name
            del files[name]
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755 if name.removeprefix("Box.app/Contents/MacOS/") in BINARIES else 0o644
                tar.addfile(entry, io.BytesIO(data))
            if native:
                for name, target in (NATIVE_ALIASES if aliases is None else aliases).items():
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.mode, entry.linkname = tarfile.SYMTYPE, 0o777, target
                    tar.addfile(entry)
            if extra:
                entry, data = extra
                tar.addfile(entry, io.BytesIO(data) if data else None)
        (directory / "SHA256SUMS.txt").write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        (self.feed / "releases" / "latest").write_text(version + "\n")
        return archive

    def native_platform(self):
        self.target = TARGET
        self.env.update(TEST_OS="Darwin", TEST_ARCH="arm64")
        executable(self.tools / "sw_vers", '#!/bin/sh\nprintf "27.0\\n"\n')
        if platform.system() != "Darwin":
            executable(self.tools / "stat", f"""#!{sys.executable}
import os, stat, sys
print(stat.filemode(os.lstat(sys.argv[-1]).st_mode))
""")
            executable(self.tools / "plutil", f"""#!{sys.executable}
import json, pathlib, sys
args = sys.argv[1:]
path = pathlib.Path(args[-1])
try:
    if args[0] == "-create": path.write_text("{{}}")
    elif args[0] == "-insert": path.write_text(json.dumps({{"release": json.loads(args[3])}}))
    else:
        value = json.loads(path.read_text())
        for key in args[1].split("."): value = value[key]
        if not isinstance(value, str): raise ValueError("expected string")
        print(value)
except (OSError, ValueError, KeyError, TypeError): sys.exit(1)
""")
            text = (self.tools / "mv").read_text().replace('exec /bin/mv "$@"',
                '[ "$1" != -fh ] || {{ shift; set -- -fT "$@"; }}\nexec /bin/mv "$@"'.replace("{{", "{").replace("}}", "}"))
            (self.tools / "mv").write_text(text)

    def test_native_bundle_installs_through_bin_symlink_and_preserves_aliases(self):
        """A native bundle keeps signed files, exact aliases, and the installed entry point"""
        self.native_platform()
        self.release("0.1.0", native=True)
        self.run_install()
        release = self.home / f".strands/box/packages/0.1.0-{self.target}"
        launcher = self.home / ".local/bin/box"
        self.assertFalse((release / "box").is_symlink())
        self.assertEqual((release / "box").read_bytes(), native_launcher())
        for name, target in NATIVE_ALIASES.items():
            self.assertEqual((release / name).readlink().as_posix(), target)
        self.assertFalse(any(path.is_symlink() for path in (release / "Box.app").rglob("*")))
        self.assertEqual((release / "Box.app/Contents/CodeResources").read_bytes(), b"stapled ticket")
        self.assertTrue((release / "resources/packs/base/pack.toml").is_file())
        self.assertEqual((release / "Box.app/Contents/Resources" / PLUGIN_FILE).read_bytes(),
                         b'[plugin]\nname = "@box/1password"\n')
        self.assertTrue((release / PLUGIN_FILE).is_file())
        self.assertEqual(subprocess.check_output([str(launcher), "--version"], env=self.env, text=True),
                         "box 0.1.0\n")
        self.assertTrue(all("/Box.app/Contents/MacOS/box" in line
                            for line in self.log.read_text().splitlines()))
        self.run_install()
        self.assertEqual(self.current(), release.name)

    @category("Verification")
    def test_native_bundle_rejects_unsafe_aliases_and_launcher_before_execution(self):
        """Only the four exact aliases and fixed launcher are accepted"""
        self.native_platform()
        for name in NATIVE_ALIASES:
            for target in ("/tmp/outside", "../outside", "Box.app/Contents/MacOS/box"):
                with self.subTest(name=name, target=target):
                    self.release("0.1.0", native=True, aliases=NATIVE_ALIASES | {name: target})
                    self.run_install(success=False)
                    self.untouched()
        marker = self.home / "unexpected-launcher-execution"
        launcher = f'#!/bin/sh\nprintf executed > "{marker}"\nexit 0\n'.encode()
        self.release("0.1.0", native=True, launcher=launcher)
        self.run_install(success=False)
        self.assertFalse(marker.exists(), "unrecognized launcher executed before refusal")
        self.untouched()
        entry = tarfile.TarInfo("Box.app/Contents/Resources/resources/packs/link")
        entry.type, entry.mode, entry.linkname = tarfile.SYMTYPE, 0o777, "../base"
        self.release("0.1.0", native=True, extra=(entry, b""))
        self.run_install(success=False)
        self.untouched()

    @category("Verification")
    def test_native_bundle_refuses_missing_aliases_and_payload(self):
        """A missing alias or required signed file stops before execution"""
        self.native_platform()
        for name in NATIVE_ALIASES:
            with self.subTest(alias=name):
                self.release("0.1.0", native=True,
                             aliases={key: value for key, value in NATIVE_ALIASES.items() if key != name})
                self.run_install(success=False)
                self.untouched()
        for name in (*BINARIES, "release.json", "resources/packs/base/pack.toml",
                     "Box.app/Contents/CodeResources"):
            with self.subTest(payload=name):
                self.release("0.1.0", native=True, missing=name)
                self.run_install(success=False)
                self.untouched()

    @category("Verification")
    def test_native_notarization_ticket_must_be_a_regular_file(self):
        """A ticket directory or link is refused before package execution"""
        self.native_platform()
        ticket = "Box.app/Contents/CodeResources"
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                entry = tarfile.TarInfo(ticket)
                entry.type, entry.mode = kind, 0o755
                if kind != tarfile.DIRTYPE:
                    entry.linkname = "_CodeSignature/CodeResources"
                self.release("0.1.0", native=True, missing=ticket, extra=(entry, b""))
                self.run_install(success=False)
                self.untouched()

    @category("Verification")
    def test_native_bundle_signature_and_checksum_failures_stop_before_execution(self):
        """Native package corruption and failed Apple verification stop before execution"""
        self.native_platform()
        archive = self.release("0.1.0", native=True)
        for failure in ("TEST_BAD_SIGNATURE", "TEST_BAD_REQUIREMENT", "TEST_BAD_GATEKEEPER"):
            with self.subTest(failure=failure):
                self.run_install(success=False, **{failure: "1"})
                self.untouched()
        archive.write_bytes(archive.read_bytes() + b"corrupt")
        result = self.run_install(success=False)
        self.assertIn("checksum mismatch", result.stderr)
        self.untouched()

    def test_native_bundle_reinstall_refuses_changed_alias_or_signed_file(self):
        """A repeated install preserves and refuses changed managed bundle contents"""
        self.native_platform()
        self.release("0.1.0", native=True)
        self.run_install()
        release = self.home / f".strands/box/packages/0.1.0-{self.target}"
        alias = release / "resources"
        alias.unlink()
        alias.symlink_to("Box.app/Contents/Resources")
        result = self.run_install(success=False)
        self.assertIn("installed release", result.stderr)
        self.assertEqual(alias.readlink().as_posix(), "Box.app/Contents/Resources")
        alias.unlink()
        alias.symlink_to(NATIVE_ALIASES["resources"])
        payload = release / "Box.app/Contents/Resources/resources/config.toml"
        payload.write_text("modified")
        result = self.run_install(success=False)
        self.assertIn("installed release contents differ", result.stderr)
        self.assertEqual(payload.read_text(), "modified")
        self.assertEqual(self.current(), release.name)

    def test_native_bundle_failed_upgrade_restores_previous_release(self):
        """A failed native activation restores the previous managed bundle"""
        self.native_platform()
        self.release("0.1.0", native=True)
        self.run_install()
        self.release("0.2.0", native=True)
        self.run_install(success=False, TEST_FAIL_LAUNCH="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.run_install(success=False, TEST_FAIL_ACTIVATION="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")

    def run_install(self, success=True, **changes):
        result = subprocess.run(["/bin/sh", str(self.script)], env=self.env | changes,
                                text=True, capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stderr)
        return result

    def current(self):
        return (self.home / ".strands/box/packages/current").readlink().as_posix()

    def untouched(self):
        self.assertFalse(self.log.exists(), "a release executable ran before verification")
        self.assertFalse((self.home / ".strands").exists())
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse((self.home / ".zshrc").exists())

    def test_fresh_install_creates_the_nested_home_and_keeps_other_apps_state(self):
        """A fresh install creates Box's home without changing another app's .box"""
        other = self.home / ".box/settings.json"
        other.parent.mkdir()
        other.write_text('{"app":"other"}\n')
        self.assertFalse((self.home / ".strands").exists())
        self.run_install()
        self.assertTrue((self.home / ".strands/box/packages/current").is_symlink())
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.assertEqual(
            (self.home / ".local/bin/box").readlink(),
            self.home.resolve() / ".strands/box/packages/current/box",
        )
        self.assertEqual(other.read_text(), '{"app":"other"}\n')
        self.assertEqual(list(other.parent.iterdir()), [other])

    @category("Verification")
    def test_unsupported_platforms_refuse_before_download(self):
        """Unsupported hosts stop before downloads or installation"""
        supported = "use macOS on Apple silicon, or Linux on ARM64 or x86-64"
        for host, architecture, message in (
            ("FreeBSD", "aarch64", f"unsupported operating system: FreeBSD; {supported}"),
            ("Linux", "riscv64", f"unsupported Linux architecture: riscv64; {supported}"),
            ("Linux", "i686", f"unsupported Linux architecture: i686; {supported}"),
        ):
            with self.subTest(host=host, architecture=architecture):
                result = self.run_install(success=False, TEST_OS=host, TEST_ARCH=architecture)
                self.assertIn(message, result.stderr)
                self.untouched()
                self.assertFalse((self.root / "gh-calls").exists())

    @unittest.skipUnless(platform.system() == "Darwin", "macOS prerequisites")
    @category("Verification")
    def test_old_macos_and_intel_refuse_before_download(self):
        """Old macOS and Intel Macs stop before downloads"""
        executable(self.tools / "sw_vers", '#!/bin/sh\nprintf "%s\\n" "$TEST_MACOS"\n')
        executable(self.tools / "sysctl", '#!/bin/sh\nprintf "%s\\n" 0\n')
        for os_version, architecture, message in (
            ("14.7", "arm64", "macOS 15 or later"),
            ("15.0", "x86_64", "Intel Macs are unsupported"),
        ):
            with self.subTest(os_version=os_version, architecture=architecture):
                result = self.run_install(success=False, TEST_MACOS=os_version, TEST_ARCH=architecture)
                self.assertIn(message, result.stderr)
                self.untouched()
                self.assertFalse((self.root / "gh-calls").exists())

    @unittest.skipUnless(platform.system() == "Darwin", "Rosetta")
    def test_rosetta_selects_the_arm64_package(self):
        """A translated shell still installs the Apple Silicon package"""
        executable(self.tools / "sysctl", '#!/bin/sh\nprintf "%s\\n" 1\n')
        self.run_install(TEST_ARCH="x86_64")
        self.assertEqual(self.current(), f"0.1.0-{TARGET}")

    @unittest.skipUnless(platform.system() == "Linux", "Linux prerequisites")
    @category("Verification")
    def test_linux_requires_glibc_2_34_before_download(self):
        """Old glibc, musl, and unrecognized libc versions stop before downloads"""
        for architecture, libc in itertools.product(
                ("aarch64", "x86_64"), ("glibc 2.33", "glibc 2.9", "musl 1.2.5", "", "glibc unknown")):
            with self.subTest(architecture=architecture, libc=libc):
                result = self.run_install(success=False, TEST_ARCH=architecture, TEST_GLIBC=libc)
                self.assertIn("glibc 2.34 or later", result.stderr)
                self.untouched()
                self.assertFalse((self.root / "gh-calls").exists())

    @unittest.skipUnless(platform.system() == "Linux", "Linux installation")
    def test_linux_installs_without_apple_tools_or_unsigned_opt_in(self):
        """ARM64 Linux installs without Apple tools or publisher configuration"""
        for tool in ("codesign", "spctl"):
            (self.tools / tool).unlink()
        self.script.write_text(self.script.read_text().replace(f"BOX_TEAM_ID='{TEAM}'", "BOX_TEAM_ID=''"))
        for architecture in ("aarch64", "arm64"):
            with self.subTest(architecture=architecture):
                result = self.run_install(TEST_ARCH=architecture, TEST_GLIBC="glibc 2.34")
                self.assertEqual(self.current(), "0.1.0-aarch64-unknown-linux-gnu")
                self.assertNotIn("Apple", result.stderr)
                self.assertFalse((self.root / "gatekeeper-calls").exists())

    @unittest.skipUnless(platform.system() == "Linux", "Linux installation")
    def test_x86_64_linux_selects_its_own_package(self):
        """x86-64 Linux installs the x86_64-unknown-linux-gnu package"""
        self.target = "x86_64-unknown-linux-gnu"
        self.release("0.1.0")
        for architecture in ("x86_64", "amd64"):
            with self.subTest(architecture=architecture):
                (self.root / "gh-calls").unlink(missing_ok=True)
                self.run_install(TEST_ARCH=architecture, TEST_GLIBC="glibc 2.34")
                self.assertEqual(self.current(), "0.1.0-x86_64-unknown-linux-gnu")
                downloads = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()][1:]
                self.assertEqual([call[call.index("--pattern") + 1] for call in downloads],
                                 ["SHA256SUMS.txt", "box-cli-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"])

    @unittest.skipUnless(platform.system() == "Linux", "Linux shell default")
    @category("PATH & shells")
    def test_linux_defaults_to_bash_when_shell_is_unset(self):
        """An unset Linux shell adds PATH to bash startup files"""
        del self.env["SHELL"]
        self.script.write_text("unset SHELL\n" + self.script.read_text())
        self.run_install()
        for name in (".bash_profile", ".bashrc"):
            self.assertIn("# >>> Box PATH >>>", (self.home / name).read_text())
        self.assertFalse((self.home / ".zshrc").exists())

    @category("Verification")
    @unittest.skipUnless(platform.system() == "Darwin", "Apple verification")
    def test_unconfigured_installer_stops_before_download(self):
        """Missing publisher configuration stops installation"""
        self.script.write_text(self.script.read_text().replace(f"BOX_TEAM_ID='{TEAM}'", "BOX_TEAM_ID=''"))
        self.run_install(success=False)
        self.untouched()
        self.assertFalse((self.root / "gh-calls").exists())

    @category("Verification")
    @unittest.skipUnless(platform.system() == "Darwin", "Apple verification")
    def test_signed_release_checks_each_program(self):
        """Configured publisher and Gatekeeper checks accept all three programs"""
        result = self.run_install()
        calls = [json.loads(line) for line in (self.root / "gatekeeper-calls").read_text().splitlines()]
        self.assertEqual(calls, list(BINARIES))
        self.assertNotIn("valid on disk", result.stderr)
        self.assertEqual(self.current(), f"0.1.0-{self.target}")

    def test_github_release_selects_repository_and_version(self):
        """GitHub downloads select the configured repository and release, and older archive names"""
        self.release("0.1.0", prefix="box")
        self.release("0.2.0")
        for selected, expected in (({}, "0.2.0"), ({"BOX_VERSION": "0.1.0"}, "0.1.0")):
            with self.subTest(selected=selected):
                self.run_install(success=True, BOX_GITHUB_REPO="someone/private-box",
                                 BOX_ALLOW_UNSIGNED="1", **selected)
                self.assertEqual(self.current(), f"{expected}-{self.target}")
        self.assertTrue((self.root / "gh-calls").is_file(), "the installer must call GitHub")
        calls = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()]
        self.assertEqual(calls[0], ["release", "view", "--repo", "someone/private-box",
                                   "--json", "tagName", "--jq", ".tagName"])
        downloads = calls[1:]
        self.assertEqual(len(downloads), 4)
        for call, selected, asset in zip(downloads, ("0.2.0", "0.2.0", "0.1.0", "0.1.0"),
                                       ("SHA256SUMS.txt", f"box-cli-v0.2.0-{self.target}.tar.gz",
                                        "SHA256SUMS.txt", f"box-v0.1.0-{self.target}.tar.gz")):
            self.assertEqual(call[:7], ["release", "download", f"v{selected}", "--repo",
                                       "someone/private-box", "--pattern", asset])
            self.assertEqual(call[7], "--output")
            self.assertIn(Path(call[8]).name, ("archive", "checksums"))

    def test_pinned_preview_installs_and_upgrades_to_stable(self):
        """A pinned preview uses the full version and can be replaced by a stable release"""
        self.release("0.1.1-linux-preview.1")
        (self.feed / "releases/latest").write_text("0.1.0\n")
        for _ in range(2):
            self.run_install(BOX_VERSION="0.1.1-linux-preview.1")
            self.assertEqual(self.current(), f"0.1.1-linux-preview.1-{self.target}")
        self.run_install()
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.release("0.1.1")
        self.run_install(BOX_VERSION="0.1.1")
        self.assertEqual(self.current(), f"0.1.1-{self.target}")

    def test_only_an_exact_version_selects_a_preview(self):
        """The latest stable release installs by default; BOX_VERSION selects a preview"""
        self.release("0.3.0-preview.1")
        (self.feed / "releases/latest").write_text("0.1.0\n")
        self.run_install()
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        calls = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()]
        self.assertEqual(calls[0][:2], ["release", "view"])
        self.assertEqual({call[2] for call in calls[1:]}, {"v0.1.0"})
        self.run_install(BOX_VERSION="0.3.0-preview.1")
        self.assertEqual(self.current(), f"0.3.0-preview.1-{self.target}")

    def test_a_version_may_start_with_the_tag_v(self):
        """BOX_VERSION takes the release tag too, as download.sh does"""
        self.release("0.3.0-preview.1")
        self.run_install(BOX_VERSION="v0.3.0-preview.1")
        self.assertEqual(self.current(), f"0.3.0-preview.1-{self.target}")
        for version in ("vv0.3.0", "V0.3.0", "v"):
            with self.subTest(version=version):
                result = self.run_install(success=False, BOX_VERSION=version)
                self.assertIn("expected a version such as 0.3.0 or 0.3.0-preview.1", result.stderr)

    def test_missing_platform_asset_names_the_requested_archive(self):
        """A release without the host archive fails before installation"""
        asset = f"box-cli-v0.1.0-{self.target}.tar.gz"
        (self.feed / "releases/0.1.0" / asset).unlink()
        result = self.run_install(success=False)
        self.assertIn(f"cannot download {asset}", result.stderr)
        self.untouched()
        # A release whose checksums list no archive for this host stops before any archive download.
        checksums = self.feed / "releases/0.1.0/SHA256SUMS.txt"
        checksums.write_text(checksums.read_text().replace(asset, f"box-cli-v0.1.0-other-target.tar.gz"))
        for selected, message in (
            ({}, f"release v0.1.0 has no box for {self.target}; "
                 "set BOX_VERSION to a release that has one, such as a pre-release"),
            ({"BOX_VERSION": "0.1.0"}, f"SHA256SUMS.txt in release v0.1.0 lists no {asset}"),
        ):
            with self.subTest(selected=selected):
                (self.root / "gh-calls").unlink()
                result = self.run_install(success=False, **selected)
                self.assertIn(message, result.stderr)
                downloads = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()
                             if json.loads(line)[:2] == ["release", "download"]]
                self.assertEqual([call[call.index("--pattern") + 1] for call in downloads], ["SHA256SUMS.txt"])
                self.untouched()

    def test_a_release_with_both_archive_names_installs_box_cli(self):
        """A release that lists both archive names installs the box-cli- one"""
        self.script.write_text((ROOT / "install.sh").read_text())
        self.release("0.1.0")
        checksums = self.feed / "releases/0.1.0/SHA256SUMS.txt"
        checksums.write_text(f"{'0' * 64}  box-v0.1.0-{self.target}.tar.gz\n" + checksums.read_text())
        (self.root / "gh-calls").unlink(missing_ok=True)
        self.run_install(BOX_GITHUB_REPO="someone/private-box", BOX_ALLOW_UNSIGNED="1")
        downloads = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()][1:]
        self.assertEqual([call[call.index("--pattern") + 1] for call in downloads],
                         ["SHA256SUMS.txt", f"box-cli-v0.1.0-{self.target}.tar.gz"])

    def test_box_core_archives_are_never_the_older_name_fallback(self):
        """In strands-agents/box, a box-v archive is Box Core's, so a release without box-cli fails"""
        self.script.write_text((ROOT / "install.sh").read_text())
        self.release("0.1.0", prefix="box")
        for repository, selected, message in (
            ("strands-agents/box", {}, f"release v0.1.0 has no box for {self.target}; set BOX_VERSION"),
            ("Strands-Agents/Box", {}, f"release v0.1.0 has no box for {self.target}; set BOX_VERSION"),
            ("strands-agents/box", {"BOX_VERSION": "0.1.0"}, f"lists no box-cli-v0.1.0-{self.target}.tar.gz"),
        ):
            with self.subTest(repository=repository, selected=selected):
                (self.root / "gh-calls").unlink(missing_ok=True)
                result = self.run_install(success=False, BOX_GITHUB_REPO=repository,
                                          BOX_ALLOW_UNSIGNED="1", **selected)
                self.assertIn(message, result.stderr)
                downloads = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()
                             if json.loads(line)[:2] == ["release", "download"]]
                self.assertEqual([call[call.index("--pattern") + 1] for call in downloads], ["SHA256SUMS.txt"])
                self.untouched()
        self.run_install(BOX_GITHUB_REPO="someone/private-box", BOX_ALLOW_UNSIGNED="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")

    @category("Verification")
    @unittest.skipUnless(platform.system() == "Darwin", "Apple verification")
    def test_unsigned_release_requires_explicit_opt_in(self):
        """Only explicit unsigned mode skips Apple verification"""
        for value in ({}, {"BOX_ALLOW_UNSIGNED": "0"}):
            with self.subTest(value=value):
                self.run_install(success=False, TEST_BAD_SIGNATURE="1", **value)
                self.untouched()
        result = self.run_install(BOX_ALLOW_UNSIGNED="1", TEST_BAD_SIGNATURE="1", TEST_BAD_GATEKEEPER="1")
        self.assertIn("Apple signature and Gatekeeper checks are skipped", result.stderr)
        self.assertEqual(self.current(), f"0.1.0-{self.target}")

    @category("Verification")
    def test_invalid_github_options_and_release_tags_refuse(self):
        """Invalid repository, unsigned mode, and release tags stop installation"""
        self.script.write_text((ROOT / "install.sh").read_text())
        valid = {"BOX_GITHUB_REPO": "someone/private-box", "BOX_ALLOW_UNSIGNED": "1"}
        changes = [{"BOX_GITHUB_REPO": value} for value in
                   ("", "someone", "someone/box/extra", "https://github.com/someone/box",
                    "--help/box", "someone/..", "some one/box", "someone/box\n", r"someone/box\171")]
        changes += [{"BOX_ALLOW_UNSIGNED": value} for value in ("", "true", "2")]
        changes += [{"TEST_RELEASE_TAG": value} for value in
                    ("0.1.0", "v01.0.0", "v0.1.0-rc.1", "v0.1.0\nother", "v../0.1.0")]
        changes += [{"TEST_GH_FAILURE": "1"}, {"TEST_GH_DOWNLOAD_FAILURE": "1", "BOX_VERSION": "0.1.0"}]
        for changed in changes:
            with self.subTest(changed=changed):
                result = self.run_install(success=False, **(valid | changed))
                if "BOX_GITHUB_REPO" in changed:
                    self.assertIn("BOX_GITHUB_REPO must be owner/repo", result.stderr)
                elif "BOX_ALLOW_UNSIGNED" in changed:
                    self.assertIn("BOX_ALLOW_UNSIGNED must be 0 or 1", result.stderr)
                elif "TEST_RELEASE_TAG" in changed:
                    self.assertIn("expected a ", result.stderr)
                elif "TEST_GH_FAILURE" in changed:
                    self.assertIn("cannot find the latest release", result.stderr)
                else:
                    self.assertIn("cannot download", result.stderr)
                self.untouched()

    @category("Verification")
    def test_unsigned_github_release_still_checks_download(self):
        """Unsigned GitHub downloads keep checksum and archive verification"""
        self.script.write_text((ROOT / "install.sh").read_text())
        self.release("0.1.0", missing=BINARIES[1])
        result = self.run_install(success=False, BOX_GITHUB_REPO="someone/private-box",
                                  BOX_ALLOW_UNSIGNED="1")
        self.assertIn(f"bundle is missing {BINARIES[1]}", result.stderr)
        self.untouched()
        self.release("0.1.0")
        checksums = self.feed / "releases/0.1.0/SHA256SUMS.txt"
        checksums.write_text("0" * 64 + checksums.read_text()[64:])
        result = self.run_install(success=False, BOX_GITHUB_REPO="someone/private-box",
                                  BOX_ALLOW_UNSIGNED="1")
        self.assertIn("checksum mismatch", result.stderr)
        self.untouched()

    def test_install_rerun_upgrade_and_rollback_preserve_user_files(self):
        """Install, rerun, upgrade, and downgrade preserve user data"""
        state = self.home / ".strands/box/profiles/my-agent/profile.toml"
        state.parent.mkdir(parents=True)
        state.write_text("user data")
        first = self.run_install()
        self.assertNotIn("\x1b", first.stderr)
        self.assertIn(
            "box sends usage telemetry to telemetry.strandsagents.com\n"
            "To opt out, run: box telemetry off\n"
            "To learn more: https://github.com/strands-agents/box/blob/main/CLI_TELEMETRY.md\n",
            first.stderr,
        )
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.env["PATH"] = f"{self.home}/.local/bin:{self.env['PATH']}"
        repeated = self.run_install()
        self.assertEqual(repeated.stderr, "box 0.1.0 is already installed.\n")
        self.assertEqual((self.home / ".zshrc").read_text().count("# >>> Box PATH >>>"), 1)
        self.release("0.2.0")
        upgraded = self.run_install()
        self.assertEqual(upgraded.stderr, "Updated box 0.1.0 to 0.2.0.\n")
        self.assertEqual(self.current(), f"0.2.0-{self.target}")
        self.run_install(BOX_VERSION="0.1.0")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.assertEqual(state.read_text(), "user data")
        self.assertTrue((self.home / f".strands/box/packages/0.2.0-{self.target}/box").is_file())
        self.assertEqual([p.name for p in (self.home / ".local/bin").iterdir()], ["box"])

    def test_telemetry_notice_respects_saved_opt_out_on_install_and_reinstall(self):
        """A saved telemetry opt-out suppresses the notice on install and reinstall"""
        installation = self.home / ".strands/box/installation.toml"
        installation.parent.mkdir(parents=True)
        installation.write_text("telemetry = false\n")
        for reinstall in (False, True):
            with self.subTest(reinstall=reinstall):
                if reinstall:
                    shutil.rmtree(self.home / ".strands/box/packages")
                    (self.home / ".local/bin/box").unlink()
                result = self.run_install()
                self.assertIn("Example next steps", result.stderr)
                self.assertNotIn("box sends usage telemetry", result.stderr)
                self.assertNotIn("box telemetry off", result.stderr)
                self.assertNotIn("To learn more:", result.stderr)
                self.assertEqual(self.current(), f"0.1.0-{self.target}")
                self.assertEqual(installation.read_text(), "telemetry = false\n")

    def test_telemetry_notice_respects_environment_opt_out(self):
        """Environment telemetry opt-outs suppress the whole notice"""
        for variable, value in (("BOX_TELEMETRY", "0"), ("DO_NOT_TRACK", "1")):
            with self.subTest(variable=variable):
                try:
                    result = self.run_install(**{variable: value})
                    self.assertIn("Example next steps", result.stderr)
                    self.assertNotIn("box sends usage telemetry", result.stderr)
                    self.assertNotIn("box telemetry off", result.stderr)
                    self.assertNotIn("To learn more:", result.stderr)
                    self.assertEqual(self.current(), f"0.1.0-{self.target}")
                finally:
                    shutil.rmtree(self.home / ".strands/box/packages")
                    (self.home / ".local/bin/box").unlink()

    def test_telemetry_notice_respects_enabled_environment_override(self):
        """The installed binary can enable telemetry over a saved or environment opt-out"""
        installation = self.home / ".strands/box/installation.toml"
        installation.parent.mkdir(parents=True)
        installation.write_text("telemetry = false\n")
        result = self.run_install(BOX_TELEMETRY="1", DO_NOT_TRACK="1")
        self.assertIn(
            "box sends usage telemetry to telemetry.strandsagents.com\n"
            "To opt out, run: box telemetry off\n"
            "To learn more: https://github.com/strands-agents/box/blob/main/CLI_TELEMETRY.md\n",
            result.stderr,
        )
        self.assertEqual(installation.read_text(), "telemetry = false\n")

    def test_telemetry_status_failure_or_unknown_output_keeps_installation(self):
        """An unavailable telemetry status skips the notice and keeps the installation"""
        for status in ("failed", "unknown"):
            with self.subTest(status=status):
                try:
                    result = self.run_install(TEST_TELEMETRY_STATUS=status)
                    self.assertIn("Example next steps", result.stderr)
                    self.assertNotIn("box sends usage telemetry", result.stderr)
                    self.assertNotIn("box telemetry off", result.stderr)
                    self.assertNotIn("To learn more:", result.stderr)
                    self.assertNotIn("telemetry status failed", result.stderr)
                    self.assertEqual(self.current(), f"0.1.0-{self.target}")
                finally:
                    shutil.rmtree(self.home / ".strands/box/packages")
                    (self.home / ".local/bin/box").unlink()

    def test_downloads_and_installed_files_match_the_archive(self):
        """Downloaded files, installed layout, permissions, and links"""
        self.run_install()
        downloads = self.root / "downloads"
        transfers = [json.loads(line) for line in (downloads / "transfers.jsonl").read_text().splitlines()]
        asset = f"box-cli-v0.1.0-{self.target}.tar.gz"
        self.assertEqual([Path(t["url"]).name for t in transfers], ["SHA256SUMS.txt", asset])
        calls = [json.loads(line) for line in (self.root / "gh-calls").read_text().splitlines()]
        self.assertEqual(calls[0], ["release", "view", "--repo", "strands-agents/box",
                                   "--json", "tagName", "--jq", ".tagName"])
        self.assertTrue(all(t["url"].startswith(
            "https://github.com/strands-agents/box/releases/download/v0.1.0/") for t in transfers))
        staging = Path(transfers[0]["destination"]).parent
        self.assertEqual(staging.parent.resolve(), Path("/var/tmp").resolve())
        self.assertTrue(staging.name.startswith("box-download."))
        for transfer in transfers:
            captured = downloads / Path(transfer["url"]).name
            self.assertEqual(Path(transfer["destination"]).parent, staging)
            self.assertEqual(hashlib.sha256(captured.read_bytes()).hexdigest(), transfer["sha256"])
            tag, name = transfer["url"].split("/releases/download/", 1)[1].split("/", 1)
            source = self.feed / "releases" / tag.removeprefix("v") / name
            self.assertEqual(captured.read_bytes(), source.read_bytes())
        self.assertFalse(staging.exists(), "installer must remove download staging")
        archive = downloads / asset
        self.assertEqual((downloads / "SHA256SUMS.txt").read_text(),
                         f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {asset}\n")
        release = self.home / f".strands/box/packages/0.1.0-{self.target}"
        files = {*BINARIES, "release.json", "resources/config.toml", "resources/packs/base/pack.toml",
                 *POLICY_FILES, STARTER_FILE, PLUGIN_FILE, GUIDE_FILE}
        expected = files | {"resources", "resources/packs", "resources/packs/base",
                            "resources/plugins", "resources/plugins/1password",
                            "resources/policies", "resources/policies/open", "resources/policies/scoped",
                            "resources/policies/locked",
                            "resources/starters", "resources/starters/claude"}
        self.assertEqual({p.relative_to(release).as_posix() for p in release.rglob("*")}, expected)
        with tarfile.open(archive) as tar:
            self.assertEqual(set(tar.getnames()), files)
            for name in files:
                installed = release / name
                stream = tar.extractfile(name)
                assert stream is not None
                self.assertEqual(installed.read_bytes(), stream.read(), name)
                self.assertFalse(installed.is_symlink(), name)
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o755 if name in BINARIES else 0o644)
        for directory in (release, *(p for p in release.rglob("*") if p.is_dir())):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        current = self.home / ".strands/box/packages/current"
        launcher = self.home / ".local/bin/box"
        self.assertTrue(current.is_symlink())
        self.assertEqual(current.readlink().as_posix(), release.name)
        self.assertTrue(launcher.is_symlink())
        self.assertEqual(launcher.readlink(), self.home.resolve() / ".strands/box/packages/current/box")
        self.assertEqual(launcher.resolve(), release.resolve() / "box")
        self.assertEqual([p.name for p in launcher.parent.iterdir()], ["box"])
        self.assertEqual(subprocess.check_output([str(launcher), "--version"], env=self.env, text=True),
                         "box 0.1.0\n")
        self.evidence = "\n".join([
            "=" * 90,
            "VERIFIED DOWNLOADS AND INSTALLATION (dummy Box)",
            f"Sample folder kept for inspection: {self.root}",
            "-" * 90,
            "DOWNLOADED FILES: retained copies of the local fixture transfers",
            f"Folder: {downloads}",
            *tree(downloads, "  "),
            f"Original download staging: {staging}",
            "The installer removed that staging folder after verification.",
            "-" * 90,
            "INSTALLED FILES",
            f"Temporary HOME: {self.home}",
            *tree(self.home, "  "),
            "-" * 90,
            "PASS: 2 transfers, SHA-256, every installed file, modes, both links, and dummy --version.",
            "",
            "Global box command would point to:",
            "  ~/.local/bin/box -> ~/.strands/box/packages/current/box",
            "Native binary:",
            f"  {release.resolve() / 'box'}",
            "Your actual global box command was not changed.",
            "",
            f"Remove this fixture when finished: rm -r {self.root}",
            "=" * 90,
        ])
        self.keep = True

    @category("Verification")
    def test_a_release_from_before_the_packs_rename_installs(self):
        """A release laid out like v0.1.11, with packs in resources/shared/, installs"""
        self.release("0.1.0", packs="shared")
        self.run_install()
        release = self.home / f".strands/box/packages/0.1.0-{self.target}"
        self.assertTrue((release / "resources/shared/base/pack.toml").is_file())
        self.assertTrue((release / "resources/policies/project/policy.dw").is_file())
        for absent in ("resources/packs", "resources/plugins", "resources/starters",
                       "resources/policies/scoped"):
            self.assertFalse((release / absent).exists(), absent)

    @category("Verification")
    def test_checksum_and_duplicate_checksum_refuse_before_execution(self):
        """Corrupt or duplicate checksums stop before execution"""
        checksums = self.feed / "releases/0.1.0/SHA256SUMS.txt"
        original = checksums.read_text()
        for value in ("0" * 64 + original[64:], original + original):
            with self.subTest(value=value):
                checksums.write_text(value)
                self.run_install(success=False)
                self.untouched()

    @category("Verification")
    def test_unsafe_archives_refuse_before_execution(self):
        """Unsafe archive paths, links, and permissions are rejected"""
        for name, kind, mode in [
            ("../outside", tarfile.REGTYPE, 0o644),
            ("/outside", tarfile.REGTYPE, 0o644),
            ("resources/packs/link", tarfile.SYMTYPE, 0o777),
            ("resources/packs/hard", tarfile.LNKTYPE, 0o644),
            ("resources/packs/pipe", tarfile.FIFOTYPE, 0o644),
            ("BOX", tarfile.REGTYPE, 0o644),
            ("box", tarfile.REGTYPE, 0o644),
            ("resources/packs/world", tarfile.REGTYPE, 0o666),
        ]:
            with self.subTest(name=name, kind=kind):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode, entry.linkname = kind, mode, "box"
                self.release("0.1.0", extra=(entry, b""))
                self.run_install(success=False)
                self.untouched()

    @category("Verification")
    def test_a_release_without_the_profile_guide_installs(self):
        """A packs release from before the profile guide shipped still installs"""
        self.release("0.1.0", missing=GUIDE_FILE)
        self.run_install()

    @category("Verification")
    def test_missing_files_and_wrong_metadata_refuse_before_execution(self):
        """Missing files and wrong version metadata are rejected"""
        for missing in (*BINARIES, "release.json", "resources/config.toml", "resources/packs/base/pack.toml",
                        *POLICY_FILES, STARTER_FILE):
            with self.subTest(missing=missing):
                self.release("0.1.0", missing=missing)
                self.run_install(success=False)
                self.untouched()
        for metadata in (
            {"box_version": "0.9.0"},
            {"target": "another-platform"},
            {"target": [self.target]},
            {"core_version": 1},
            {"core_version": "not-a-version"},
            {"box_commit": "a" * 39},
            {"box_commit": int("1" * 40)},
            {"core_commit": "g" * 40},
            {"core_commit": None},
        ):
            with self.subTest(metadata=metadata):
                self.release("0.1.0", metadata=metadata)
                self.run_install(success=False)
                self.untouched()
        valid = json.dumps(dict(box_version="0.1.0", target=self.target, core_version="0.1.0",
                                box_commit="a" * 40, core_commit="b" * 40)).encode()
        for data in (b"", b"{", b"[]", b"{}", b"null", valid + b" {}"):
            with self.subTest(release_json=data):
                self.release("0.1.0", release_json=data)
                self.run_install(success=False)
                self.untouched()

    @category("Verification")
    @unittest.skipUnless(platform.system() == "Darwin", "Apple verification")
    def test_wrong_publisher_signature_and_gatekeeper_refuse_before_execution(self):
        """Simulated signing and Gatekeeper failures stop installation"""
        for changes in ({"TEST_TEAM": "OTHER12345"}, {"TEST_BAD_SIGNATURE": "1"},
                        {"TEST_BAD_REQUIREMENT": "1"}, {"TEST_BAD_GATEKEEPER": "1"}):
            with self.subTest(changes=changes):
                result = self.run_install(success=False, **changes)
                self.untouched()
                if "TEST_BAD_REQUIREMENT" in changes:
                    self.assertIn("failed to satisfy specified code requirement", result.stderr)

    def test_version_and_launcher_conflicts_refuse(self):
        """Invalid versions and existing launchers are rejected"""
        for version in ("vv0.1.0", "../0.1.0", "", "0.1.0;exit", "01.0.0",
                        "0.1.1-linux-preview.0", "0.1.1-linux-preview.01", "0.1.1-rc.1",
                        "0.1.1-linux-preview.1+build", "0.1.1-preview.0", "0.1.1-preview.01",
                        "0.1.1-preview", "0.1.1-preview.1-linux", "0.1.1-macos-preview.1"):
            with self.subTest(version=version):
                result = self.run_install(success=False, BOX_VERSION=version)
                self.assertIn("expected a version such as 0.3.0 or 0.3.0-preview.1", result.stderr)
                self.assertFalse((self.root / "gh-calls").exists())
                self.untouched()
        foreign = self.home / ".local/bin/box"
        foreign.parent.mkdir(parents=True)
        foreign.write_text("another installer owns this")
        self.run_install(success=False)
        self.assertEqual(foreign.read_text(), "another installer owns this")
        self.assertFalse(self.log.exists())
        foreign.unlink()
        foreign.symlink_to(self.root / "elsewhere/box")
        result = self.run_install(success=False)
        self.assertIn("another launcher exists", result.stderr)
        self.assertEqual(foreign.readlink(), self.root / "elsewhere/box")

    def test_a_launcher_from_the_earlier_box_folder_moves_to_the_new_one(self):
        """An install in ~/.box/packages, from box 0.2.2 or earlier, upgrades in place"""
        earlier = self.home.resolve() / ".box/packages"
        (earlier / "0.2.2-x").mkdir(parents=True)
        (earlier / "0.2.2-x/box").write_text("earlier box")
        (earlier / "current").symlink_to("0.2.2-x")
        launcher = self.home / ".local/bin/box"
        launcher.parent.mkdir(parents=True)
        launcher.symlink_to(earlier / "current/box")
        result = self.run_install()
        self.assertEqual(launcher.readlink(), self.home.resolve() / ".strands/box/packages/current/box")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.assertIn("Replaced the launcher of an earlier box in ~/.box", result.stderr)
        self.assertEqual((earlier / "0.2.2-x/box").read_text(), "earlier box")
        self.assertEqual(launcher.parent.joinpath("box").resolve(),
                         (self.home / f".strands/box/packages/0.1.0-{self.target}/box").resolve())

    def test_a_failed_install_restores_the_launcher_of_the_earlier_box_folder(self):
        """A failed upgrade from ~/.box/packages leaves the earlier launcher in place"""
        earlier = self.home.resolve() / ".box/packages/current/box"
        launcher = self.home / ".local/bin/box"
        launcher.parent.mkdir(parents=True)
        launcher.symlink_to(earlier)
        self.run_install(success=False, TEST_FAIL_PATH="1")
        self.assertEqual(launcher.readlink(), earlier)
        self.assertFalse((self.home / ".strands/box/packages/current").is_symlink())

    @category("PATH & shells")
    def test_linked_or_unwritable_shell_files_refuse_before_download(self):
        """Linked or unwritable shell files are preserved"""
        target = self.home / "saved"
        target.write_text("leave this alone")
        startup = self.home / ".zshrc"
        startup.symlink_to(target)
        self.run_install(success=False)
        self.assertFalse(self.log.exists())
        self.assertEqual(target.read_text(), "leave this alone")
        startup.unlink()
        startup.write_text("unwritable")
        startup.chmod(0o400)
        self.run_install(success=False)
        self.assertFalse(self.log.exists())

    @category("PATH & shells")
    def test_opt_out_leaves_shell_alone(self):
        """PATH opt-out leaves shell configuration unchanged"""
        result = self.run_install(BOX_NO_MODIFY_PATH="1")
        self.assertFalse((self.home / ".zshrc").exists())
        self.assertIn('export PATH=', result.stderr)

    @category("PATH & shells")
    def test_new_zsh_and_bash_find_box(self):
        """New zsh and bash shells find the installed command"""
        for shell, files in (("/bin/zsh", [".zshrc"]),
                             ("/bin/bash", [".bash_profile", ".bashrc"])):
            with self.subTest(shell=shell):
                if not Path(shell).is_file():
                    self.skipTest(f"{shell} is not installed")
                self.run_install(SHELL=shell)
                for file in files:
                    self.assertIn("# >>> Box PATH >>>", (self.home / file).read_text())
                result = subprocess.run([shell, "-ic", "box --version"], env=self.env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("box 0.1.0", result.stdout)

    @unittest.skipUnless(FISH, "fish is not installed; TEST_FISH_BINARY can select a test copy")
    @category("PATH & shells")
    def test_new_fish_finds_box_without_reading_user_configuration(self):
        """Fish PATH persists without running config during install"""
        assert FISH is not None
        config = self.home / ".config/fish/config.fish"
        config.parent.mkdir(parents=True)
        config.write_text('echo loaded >> "$TEST_CONFIG_LOG"\n')
        self.env["TEST_CONFIG_LOG"] = str(self.root / "config-loaded")
        self.run_install(SHELL=FISH)
        self.run_install(SHELL=FISH)
        self.assertFalse(Path(self.env["TEST_CONFIG_LOG"]).exists())
        result = subprocess.run([FISH, "-ic", "box --version; count $fish_user_paths"], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["box 0.1.0", "1"])
        self.assertTrue(Path(self.env["TEST_CONFIG_LOG"]).exists())

    @category("PATH & shells")
    def test_path_write_failure_does_not_activate_new_release(self):
        """Failed PATH update keeps the previous release active"""
        self.run_install()
        original = (self.home / ".zshrc").read_text()
        (self.home / ".zshrc").unlink()
        self.release("0.2.0")
        self.run_install(success=False, TEST_FAIL_PATH="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.assertFalse((self.home / ".zshrc").exists())
        (self.home / ".zshrc").write_text(original)

    @category("PATH & shells")
    def test_path_already_present_leaves_shell_files_untouched(self):
        """Existing PATH entry leaves shell files unchanged"""
        startup = self.home / ".zshrc"
        startup.write_text("# my settings\n")
        self.run_install(PATH=f"{self.tools}:{self.home}/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(startup.read_text(), "# my settings\n")

    def test_linked_installation_paths_and_changed_path_blocks_refuse(self):
        """Linked install paths and altered PATH blocks are rejected"""
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        for relative in (".strands", ".strands/box"):
            with self.subTest(relative=relative):
                link = self.home / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(elsewhere, target_is_directory=True)
                result = self.run_install(success=False)
                self.assertIn(
                    f"directory is a symbolic link: {self.home.resolve() / relative}",
                    result.stderr,
                )
                self.assertEqual(list(elsewhere.iterdir()), [])
                self.assertFalse(self.log.exists())
                link.unlink()
        startup = self.home / ".zshrc"
        startup.write_text("# >>> Box PATH >>>\n# incomplete\n")
        self.run_install(success=False)
        self.assertFalse(self.log.exists())
        self.assertIn("# incomplete", startup.read_text())

    def test_failed_upgrade_restores_current(self):
        """Failed activation or launch restores the previous release"""
        self.run_install()
        self.release("0.2.0")
        self.run_install(success=False, TEST_FAIL_LAUNCH="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")
        self.run_install(success=False, TEST_FAIL_ACTIVATION="1")
        self.assertEqual(self.current(), f"0.1.0-{self.target}")

    def test_failed_first_install_removes_launcher(self):
        """Failed first install removes its launcher"""
        self.run_install(success=False, TEST_FAIL_LAUNCH="1")
        self.assertFalse((self.home / ".local/bin/box").is_symlink())
        self.assertFalse((self.home / ".strands/box/packages/current").is_symlink())

    def test_modified_release_and_concurrent_installer_refuse(self):
        """Modified releases and competing installers are rejected"""
        self.run_install()
        binary = self.home / f".strands/box/packages/0.1.0-{self.target}/box"
        binary.write_text("modified")
        self.run_install(success=False)
        self.assertEqual(binary.read_text(), "modified")
        lock = self.home / ".strands/box/packages/.install-lock"
        lock.mkdir()
        result = self.run_install(success=False)
        self.assertIn("installation is in progress", result.stderr)
        self.assertTrue(lock.is_dir())

    def test_changed_installed_permissions_refuse(self):
        """Changed installed permissions stop a repeated installation"""
        self.run_install()
        release = self.home / f".strands/box/packages/0.1.0-{self.target}"
        for name, original, changed in (("box", 0o755, 0o644), ("release.json", 0o644, 0o600)):
            with self.subTest(name=name):
                (release / name).chmod(changed)
                result = self.run_install(success=False)
                self.assertIn("installed release permissions differ", result.stderr)
                self.assertEqual((release / name).stat().st_mode & 0o777, changed)
                self.assertEqual(self.current(), release.name)
                (release / name).chmod(original)


@unittest.skipUnless(platform.system() == "Darwin", "macOS distribution scripts")
class Package(unittest.TestCase):
    category_name = "Package"
    skill_source = GUIDE_FILE

    temp: tempfile.TemporaryDirectory[str]
    root: Path
    tools: Path
    script: Path
    output: Path
    env: dict[str, str]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="box-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts/package_macos.sh"
        shutil.copyfile(ROOT / "scripts/package_macos.sh", self.script)
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        (self.root / "Cargo.lock").write_text("version = 4\n")
        packs = self.root / "resources/packs/base"
        packs.mkdir(parents=True)
        (packs / "pack.toml").write_text('[pack]\nname = "@box/base"\n')
        policies = self.root / "resources/policies/open"
        policies.mkdir(parents=True)
        (policies / "policy.toml").write_text('[policy]\nname = "@box/open"\n')
        starters = self.root / "resources/starters/claude"
        starters.mkdir(parents=True)
        (starters / "starter.toml").write_text('[starter]\nname = "@box/claude"\n')
        plugins = self.root / "resources/plugins/1password"
        plugins.mkdir(parents=True)
        (plugins / "plugin.toml").write_text('[plugin]\nname = "@box/1password"\n')
        (self.root / "resources/config.toml").write_text('[starters]\nonly = []\n')
        guide = self.root / self.skill_source
        guide.write_text("# Profile authoring\n")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                        "commit", "-qm", "fixture"], check=True)
        self.output = self.root / "output"
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}",
                        TEST_REPO=str(self.root))
        executable(self.tools / "lipo", "#!/bin/sh\n[ -z \"${TEST_BAD_ARCH-}\" ]\n")
        executable(self.tools / "cargo", f"""#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TEST_REPO"])
remote = "git+https://github.com/strands-agents/box#" + "b" * 40
source = None if os.environ.get("TEST_CORE_SOURCE") == "path" else remote
helper = {{"revision": remote[:-1] + "c", "form": None if source else remote}}.get(
    os.environ.get("TEST_PIN_MISMATCH"), source)
core = pathlib.Path(os.environ.get("TEST_CORE_ROOT") or root / "crates")
if "metadata" in sys.argv:
    print(json.dumps({{"target_directory": str(root / "target"), "packages": [
        {{"name": "strands-box-cli", "version": "0.1.0", "source": None,
          "manifest_path": str(root / "crates/cli/app/Cargo.toml")}},
        {{"name": "strands-box", "version": "0.1.0", "source": source,
          "manifest_path": str(core / "box/Cargo.toml")}},
        {{"name": "strands-box-containment", "version": "0.1.0", "source": helper,
          "manifest_path": str(core / "containment/Cargo.toml")}}
    ]}}))
else:
    (root / "build-started").touch()
    assert "--locked" in sys.argv and "--release" in sys.argv
    assert os.environ["MACOSX_DEPLOYMENT_TARGET"] == "15.0"
    for name in {BINARIES!r}:
        assert name in sys.argv
        path = root / "target/{TARGET}/release" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\\nprintf 'box 0.1.0\\\\n'\\n")
        path.chmod(0o755)
    if changed := os.environ.get("TEST_CHANGED_SKILL_SOURCE"):
        source = root / changed
        source.write_text(source.read_text() + "Changed during the build.\\n")
""")

    def run_package(self, success=True, **changes):
        result = subprocess.run(["/bin/sh", str(self.script), str(self.output)],
                                env=self.env | changes, text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stderr)
        return result

    def test_bundle_contains_locked_helpers_packs_and_metadata(self):
        """Package contains the expected helpers, packs, and metadata"""
        self.run_package()
        archive = self.output / f"box-cli-v0.1.0-{TARGET}.tar.gz"
        with tarfile.open(archive) as tar:
            files = {m.name.removeprefix("./"): m for m in tar if m.isfile()}
            self.assertEqual(set(files),
                             {*BINARIES, "release.json", "resources/config.toml", "resources/packs/base/pack.toml",
                              "resources/policies/open/policy.toml", STARTER_FILE, PLUGIN_FILE, GUIDE_FILE})
            guide = tar.extractfile(files[GUIDE_FILE])
            assert guide is not None
            self.assertEqual(guide.read(), (self.root / GUIDE_FILE).read_bytes())
            self.assertEqual(files[GUIDE_FILE].mode, 0o644)
            settings = tar.extractfile(files["resources/config.toml"])
            assert settings is not None
            self.assertEqual(settings.read(), (self.root / "resources/config.toml").read_bytes())
            self.assertEqual(files["resources/config.toml"].mode, 0o644)
            stream = tar.extractfile(files["release.json"])
            assert stream is not None
            record = json.load(stream)
            self.assertEqual(record["core_commit"], "b" * 40)
            self.assertEqual(record["box_commit"], subprocess.check_output(
                ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip())
            self.assertEqual(record["target"], TARGET)
            for name in BINARIES:
                self.assertEqual(files[name].mode, 0o755)
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual((self.output / "SHA256SUMS.txt").read_text(), f"{expected}  {archive.name}\n")
        self.run_package(success=False)

    def test_missing_or_linked_starter_settings_stop_packaging(self):
        """Missing or linked starter settings stop packaging"""
        settings = self.root / "resources/config.toml"
        settings.unlink()
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    settings.symlink_to("packs/base/pack.toml")
                subprocess.run(["git", "-C", str(self.root), "add", "resources/config.toml"], check=True)
                subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                                "commit", "-qm", "invalid starter settings"], check=True)
                try:
                    self.run_package(success=False)
                    self.assertFalse(self.output.exists())
                finally:
                    if self.output.exists():
                        shutil.rmtree(self.output)

    def test_missing_or_linked_plugins_stop_packaging(self):
        """Missing or linked shipped plugins stop packaging"""
        plugins = self.root / "resources/plugins"
        shutil.rmtree(plugins)
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    plugins.symlink_to("packs")
                subprocess.run(["git", "-C", str(self.root), "add", "-A", "resources"], check=True)
                subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                                "commit", "-qm", "invalid plugins"], check=True)
                result = self.run_package(success=False)
                self.assertIn("shipped plugins are missing or linked", result.stderr)
                self.assertFalse(self.output.exists())

    def test_missing_or_linked_profile_guide_stops_packaging(self):
        """A missing or linked profile guide stops packaging"""
        guide = self.root / GUIDE_FILE
        guide.unlink()
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    guide.symlink_to("packs/base/pack.toml")
                subprocess.run(["git", "-C", str(self.root), "add", GUIDE_FILE], check=True)
                subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                                "commit", "-qm", "invalid profile guide"], check=True)
                try:
                    self.run_package(success=False)
                    self.assertFalse(self.output.exists())
                finally:
                    if self.output.exists():
                        shutil.rmtree(self.output)

    def test_mismatched_pin_and_wrong_architecture_fail(self):
        """Mismatched Core revisions and architecture are rejected"""
        self.run_package(success=False, TEST_PIN_MISMATCH="revision")
        self.assertFalse(self.output.exists())
        self.run_package(success=False, TEST_BAD_ARCH="1")
        self.assertFalse(self.output.exists())

    def test_core_commit_follows_the_core_source(self):
        """A git Core records its pinned commit, and a path Core records the packaged commit"""
        head = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        for form, expected in (("git", "b" * 40), ("path", head)):
            with self.subTest(form=form):
                try:
                    self.run_package(TEST_CORE_SOURCE=form)
                    with tarfile.open(self.output / f"box-cli-v0.1.0-{TARGET}.tar.gz") as tar:
                        stream = tar.extractfile("./release.json")
                        assert stream is not None
                        record = json.load(stream)
                    self.assertEqual(record, dict(box_version="0.1.0", box_commit=head, core_version="0.1.0",
                                                  core_commit=expected, target=TARGET))
                finally:
                    if self.output.exists():
                        shutil.rmtree(self.output)

    def test_core_and_helpers_from_different_sources_fail(self):
        """A path Core packages only when its helpers come from the same place in this repository"""
        build_started = self.root / "build-started"
        self.run_package(TEST_CORE_SOURCE="path")
        shutil.rmtree(self.output)
        build_started.unlink()
        outside = tempfile.TemporaryDirectory(prefix="box-outside-core-")
        self.addCleanup(outside.cleanup)
        for name, changes in (
            ("git Core, path helpers", dict(TEST_CORE_SOURCE="git", TEST_PIN_MISMATCH="form")),
            ("path Core, git helpers", dict(TEST_CORE_SOURCE="path", TEST_PIN_MISMATCH="form")),
            ("path Core outside the repository", dict(TEST_CORE_SOURCE="path", TEST_CORE_ROOT=outside.name)),
            # clean_source checks crates/ only, so a Core elsewhere in the repository could be dirty.
            ("path Core outside crates/", dict(TEST_CORE_SOURCE="path", TEST_CORE_ROOT=str(self.root / "vendor"))),
        ):
            with self.subTest(name):
                result = self.run_package(success=False, **changes)
                self.assertIn("Core and", result.stderr)
                self.assertFalse(build_started.exists())
                self.assertFalse(self.output.exists())

    def test_dirty_sources_and_linked_packs_fail(self):
        """Uncommitted source and linked packs stop packaging"""
        manifest = self.root / "Cargo.toml"
        original = manifest.read_text()
        manifest.write_text(original + "# changed\n")
        self.run_package(success=False)
        self.assertFalse(self.output.exists())
        manifest.write_text(original)
        (self.root / "resources/packs/link").symlink_to(self.root / "resources/packs/base")
        self.run_package(success=False)
        self.assertFalse(self.output.exists())
        (self.root / "resources/packs/link").unlink()
        (self.root / "resources/policies/link").symlink_to(self.root / "resources/policies/open")
        self.run_package(success=False)
        self.assertFalse(self.output.exists())
        (self.root / "resources/policies/link").unlink()
        (self.root / "resources/starters/link").symlink_to(self.root / "resources/starters/claude")
        self.run_package(success=False)
        self.assertFalse(self.output.exists())

    def test_shipped_profile_guide_stays_clean_through_packaging(self):
        """An uncommitted profile guide stops packaging before and after the build"""
        build_started = self.root / "build-started"
        source = self.root / self.skill_source
        original = source.read_text()
        for during_build in (False, True):
            with self.subTest(during_build=during_build):
                try:
                    if not during_build:
                        source.write_text(original + "Uncommitted change.\n")
                    result = self.run_package(
                        success=False,
                        TEST_CHANGED_SKILL_SOURCE=self.skill_source if during_build else "")
                    self.assertIn("commit changes", result.stderr)
                    self.assertEqual(build_started.exists(), during_build)
                    self.assertFalse(self.output.exists())
                finally:
                    source.write_text(original)
                    build_started.unlink(missing_ok=True)
                    if self.output.exists():
                        shutil.rmtree(self.output)

    def test_ignored_pack_files_are_not_published(self):
        """Git-ignored pack files cannot enter the package"""
        (self.root / ".git/info/exclude").write_text("ignored-secret.txt\n")
        (self.root / "resources/packs/base/ignored-secret.txt").write_text("uncommitted bytes")
        self.run_package(success=False)
        self.assertFalse(self.output.exists())


class PackageVerification(unittest.TestCase):
    category_name = "Package"

    def test_package_verifier_copies_existing_installation_or_disables_capture(self):
        """Package verification preserves caller identity before replacing HOME"""
        from unittest.mock import patch
        import test_macos_package as verifier  # pyright: ignore[reportImplicitRelativeImport]

        class Observed(Exception):
            pass

        for contents in ('installation_id = "fixture"\nextra = "preserved"\n', None):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                original = Path(temporary) / ".strands/box/installation.toml"
                if contents is not None:
                    original.parent.mkdir(parents=True)
                    original.write_text(contents)

                def install(archive, root, home, version):
                    release = home / "releases/fixture"
                    release.mkdir(parents=True)
                    (release.parent / "current").symlink_to(release.name)
                    public = home / ".local/bin/box"
                    public.parent.mkdir(parents=True)
                    public.symlink_to(release.parent / "current/box")
                    return release

                def observe(command, workspace, environment):
                    saved = Path(environment["HOME"]) / ".strands/box/installation.toml"
                    self.assertEqual(saved.read_text(), contents or 'installation_id = ""\n')
                    raise Observed

                with patch.object(verifier.Path, "home", return_value=Path(temporary)), \
                     patch.object(verifier.platform, "system", return_value="Darwin"), \
                     patch.object(verifier.platform, "machine", return_value="arm64"), \
                     patch.object(verifier, "unpack"), \
                     patch.object(verifier, "install", side_effect=install), \
                     patch.object(verifier.subprocess, "run"), \
                     patch.object(verifier.subprocess, "check_output", return_value=""), \
                     patch.object(verifier, "run", side_effect=observe), \
                     patch("sys.stdout", new=io.StringIO()):
                    with self.assertRaises(Observed):
                        verifier.verify(Path(temporary) / "archive.tar.gz", "a" * 40)
                self.assertEqual(original.read_text() if original.exists() else None, contents)

    def test_package_verifier_expects_the_core_commit_of_the_core_source(self):
        """Package verification expects the pinned commit for a git Core and Box's commit for a path Core"""
        from unittest.mock import patch
        import test_macos_package as verifier  # pyright: ignore[reportImplicitRelativeImport]

        class Observed(Exception):
            pass

        remote = 'source = "git+https://github.com/strands-agents/box#' + "b" * 40 + '"\n'
        cases = (("git", remote, remote, "b" * 40), ("path", "", "", "a" * 40),
                 ("git Core, path helpers", remote, "", None), ("path Core, git helpers", "", remote, None))
        for name, core, helper, expected in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "crates/cli/app").mkdir(parents=True)
                (root / "crates/cli/app/Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
                (root / "Cargo.lock").write_text(
                    f'[[package]]\nname = "strands-box"\nversion = "0.2.0"\n{core}\n'
                    f'[[package]]\nname = "strands-box-containment"\nversion = "0.2.0"\n{helper}')
                (root / "resources").mkdir()
                (root / "resources/config.toml").write_text('[starters]\nonly = []\n')
                observed = []

                def unpack(archive, destination, record, resources):
                    observed.append(record)
                    raise Observed

                with patch.object(verifier, "ROOT", root), \
                     patch.object(verifier.Path, "home", return_value=root), \
                     patch.object(verifier.platform, "system", return_value="Darwin"), \
                     patch.object(verifier.platform, "machine", return_value="arm64"), \
                     patch.object(verifier, "unpack", side_effect=unpack):
                    with self.assertRaises(Observed if expected else AssertionError):
                        verifier.verify(root / "archive.tar.gz", "a" * 40)
                if expected:
                    self.assertEqual(observed, [dict(box_version="0.1.0", box_commit="a" * 40, core_version="0.2.0",
                                                     core_commit=expected, target=TARGET)])

    def test_workload_checks_pack_metadata_and_policy_outcomes(self):
        """Package tests follow pack metadata and require recorded write decisions"""
        from unittest.mock import patch
        import test_macos_package as verifier  # pyright: ignore[reportImplicitRelativeImport]

        with tempfile.TemporaryDirectory(prefix="box-workload-test-") as temporary:
            root = Path(temporary)
            pack = root / "resources/packs/base/pack.toml"
            pack.parent.mkdir(parents=True)
            pack.write_text('[pack]\nname = "@box/base"\nversion = 7\n')
            for fault in (None, "version", "missing version", "missing pack", "wrong verdict", "wrong path", "missing denial"):
                with self.subTest(fault=fault):
                    home = root / str(fault)
                    workspace = home / "project"
                    workspace.mkdir(parents=True)

                    def run(command, workspace, env):
                        if command[1] == "profile":
                            shown = "@box/base\t70" if fault == "version" else "@box/base\t7"
                            if fault == "missing version":
                                shown = "@box/base"
                            if fault == "missing pack":
                                shown = "another-@box/base\t7"
                            return subprocess.CompletedProcess(command, 0, f"  packs\t{shown}\n", "")
                        (workspace / "direct.txt").write_text("direct\n")
                        (workspace / "broker.txt").write_text("broker\n")
                        records = home / ".strands/box/r/probe/records.jsonl"
                        records.parent.mkdir(parents=True)
                        events = []
                        for name, verdict in (("broker.txt", "permit"), (".box/denied.txt", "deny")):
                            if name.endswith("denied.txt"):
                                if fault == "missing denial":
                                    continue
                                if fault == "wrong verdict":
                                    verdict = "permit"
                                if fault == "wrong path":
                                    name = ".box/another.txt"
                            attributes = dict(path=f"~/project/{name}", verdict=verdict, rule="renamed_rule")
                            events.append(dict(name="policy fs:write", attributes=[
                                dict(key=f"policy.{key}", value=dict(stringValue=value))
                                for key, value in attributes.items()
                            ]))
                        records.write_text(json.dumps({"spans": events}) + "\n")
                        return subprocess.CompletedProcess(command, 0, "package-ok\n", "")

                    with patch.object(verifier, "ROOT", root), patch.object(verifier, "run", run):
                        if fault is None:
                            with patch("sys.stdout", new=io.StringIO()):
                                verifier.workload("box", home, workspace, {})
                        else:
                            with self.assertRaises(AssertionError):
                                verifier.workload("box", home, workspace, {})

    def test_package_timeout_stops_descendants_in_separate_process_groups(self):
        """Package timeout stops the workload before temporary files are removed"""
        from unittest.mock import patch
        import test_macos_package as verifier  # pyright: ignore[reportImplicitRelativeImport]

        with tempfile.TemporaryDirectory(prefix="box-timeout-test-") as temporary:
            root = Path(temporary)
            marker = root / "orphan-write"
            child_pid = root / "child-pid"
            program = """import os, pathlib, sys, time
if os.fork() == 0:
    os.setpgid(0, 0)
    pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
    for descriptor in (0, 1, 2): os.close(descriptor)
    time.sleep(1.5)
    pathlib.Path(sys.argv[1]).write_text("orphan")
    os._exit(0)
time.sleep(10)
"""
            try:
                with patch.object(verifier, "COMMAND_TIMEOUT", 1):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        verifier.run([sys.executable, "-c", program, marker, child_pid], root, os.environ)
                self.assertTrue(child_pid.exists(), "the descendant must start before the timeout")
                time.sleep(1.6)
                self.assertFalse(marker.exists(), "a descendant survived timeout cleanup")
            finally:
                if child_pid.exists():
                    try:
                        os.kill(int(child_pid.read_text()), 9)
                    except ProcessLookupError:
                        pass

    def test_package_verifier_rejects_damaged_or_incomplete_archives(self):
        """Real-package verifier rejects altered bytes, metadata, modes, and links"""
        from test_macos_package import unpack  # pyright: ignore[reportImplicitRelativeImport]

        record = dict(box_version="0.1.0", box_commit="a" * 40,
                      core_version="0.1.0", core_commit="b" * 40, target=TARGET)
        resources = {"resources/packs/base/pack.toml": b'[pack]\nname="@box/base"\n',
                     "resources/config.toml": b'[starters]\nonly=[]\n'}
        files = {name: b"native image" for name in BINARIES}
        files.update(resources, **{"release.json": json.dumps(record).encode()})
        with tempfile.TemporaryDirectory(prefix="box-archive-test-") as temporary:
            root = Path(temporary)
            archive = root / f"box-cli-v0.1.0-{TARGET}.tar.gz"
            for fault in (None, "checksum", "missing", "metadata", "pack", "settings", "missing settings",
                          "mode", "link", "duplicate", "path"):
                with self.subTest(fault=fault):
                    with tarfile.open(archive, "w:gz") as tar:
                        for name, data in files.items():
                            if fault == "missing" and name == BINARIES[1]:
                                continue
                            if fault == "missing settings" and name == "resources/config.toml":
                                continue
                            if fault == "metadata" and name == "release.json":
                                data = json.dumps(record | {"core_commit": "c" * 40}).encode()
                            if fault == "pack" and name.endswith("pack.toml"):
                                data = b"altered pack"
                            if fault == "settings" and name == "resources/config.toml":
                                data = b"altered settings"
                            entry = tarfile.TarInfo(name)
                            entry.size = len(data)
                            entry.mode = 0o755 if name in BINARIES else 0o644
                            if name == "box":
                                if fault == "mode":
                                    entry.mode = 0o644
                                if fault == "link":
                                    entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "/bin/sh", 0
                                if fault == "path":
                                    entry.name = "../escaped"
                            tar.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
                            if fault == "duplicate" and name == "box":
                                tar.addfile(entry, io.BytesIO(data))
                    digest = "0" * 64 if fault == "checksum" else hashlib.sha256(archive.read_bytes()).hexdigest()
                    (root / "SHA256SUMS.txt").write_text(f"{digest}  {archive.name}\n")
                    destination = root / str(fault)
                    if fault is None:
                        unpack(archive, destination, record, resources)
                        self.assertEqual({p.relative_to(destination).as_posix() for p in destination.rglob("*")
                                          if p.is_file()}, set(files))
                    else:
                        with self.assertRaises((AssertionError, ValueError)):
                            unpack(archive, destination, record, resources)
                        self.assertFalse(destination.exists(), "refuse before extraction")
                    self.assertFalse((root / "escaped").exists())


if __name__ == "__main__":
    unittest.main(testRunner=TableRunner)
