"""Unit tests for the features layer of run_corpus.py. They start no box."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import run_corpus as rc

# The per-agent feature checklist: each row is a part of the agent's host setup, and the agents it
# applies to among Claude Code, Codex, and Kiro CLI.
CHECKLIST = {
    "Instructions": ("claude", "codex", "kiro"),
    "Skills": ("claude", "codex", "kiro"),
    "Commands (saved prompts)": ("claude", "codex", "kiro"),
    "Subagents": ("claude", "codex", "kiro"),
    "Output styles": ("claude",),
    "Themes, keybindings": ("claude", "codex", "kiro"),
    "Agent memory": ("claude", "codex", "kiro"),
    "Preferences file": ("claude", "codex", "kiro"),
    "Model choice": ("claude", "codex", "kiro"),
    "Environment variables": ("claude", "codex", "kiro"),
    "Credential helpers, provider keys": ("claude", "codex", "kiro"),
    "Login": ("claude", "codex", "kiro"),
    "Permission rules": ("claude", "codex", "kiro"),
    "Hooks": ("claude", "codex", "kiro"),
    "MCP servers": ("claude", "codex", "kiro"),
    "Plugins, extensions": ("claude", "codex", "kiro"),
    "App state (onboarding, trust)": ("claude", "codex", "kiro"),
    "Sessions and resume": ("claude", "codex", "kiro"),
    "Org-managed settings": ("claude", "codex", "kiro"),
}
MODEL_ROW = "Model call"
HARNESSES = ("claude", "codex", "kiro")
PROGRAMS = {"claude": "claude", "codex": "codex", "kiro": "kiro-cli"}

# A stand-in for `box`. It records each call with the HOME it got, and a run does what the STUB_
# variables say: it fills the profile's storage, prints lines, and answers a line on its stdin.
STUB_BOX = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
home = Path(os.environ["HOME"])
with open(os.environ["STUB_CALLS"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "home": str(home), "cwd": os.getcwd(),
                        "token": os.environ.get("AWS_BEARER_TOKEN_BEDROCK"),
                        "kiro_key": os.environ.get("KIRO_API_KEY"),
                        "kiro_runtime": os.environ.get("KIRO_RUNTIME_DIR"),
                        "leaked": sorted(k for k in ("BOX_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME")
                                         if k in os.environ)}) + "\n")
if sys.argv[1:3] == ["profile", "create"]:
    if os.environ.get("STUB_CREATE_FAILS"):
        print("no pack named no-such-pack")
        sys.exit(1)
    profile = home / ".strands" / "box" / "profiles" / sys.argv[3] / "profile.toml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text("packs = []\n")
    sys.exit(0)
if os.environ.get("STUB_NO_BOX"):
    print("error: the box did not start")
    sys.exit(1)
run = home / ".strands" / "box" / "r" / "b-0000000000000001"
run.mkdir(parents=True, exist_ok=True)
(run / "records.jsonl").write_text("")
print(f"box: running profile {sys.argv[2]} as {run.name} (records: {run / 'records.jsonl'})", flush=True)
storage = home / ".strands" / "box" / "storage" / sys.argv[2] / "default" / "agent"
for path, text in json.loads(os.environ.get("STUB_STORAGE", "{}")).items():
    (storage / path).parent.mkdir(parents=True, exist_ok=True)
    (storage / path).write_text(text)
for source, target in json.loads(os.environ.get("STUB_COPY", "{}")).items():
    (storage / target).parent.mkdir(parents=True, exist_ok=True)
    (storage / target).write_text((home / source).read_text())
if os.environ.get("STUB_SHOW"):  # a system path: print what it holds
    shown = Path(os.environ["STUB_SHOW"])
    print(f"system file: {shown.read_text().strip() if shown.is_file() else 'absent'}", flush=True)
if os.environ.get("STUB_SAY"):
    print(os.environ["STUB_SAY"], flush=True)
for line in sys.stdin:
    print(f"got {line.strip()}", flush=True)
    if os.environ.get("STUB_REPLY_TO") and os.environ["STUB_REPLY_TO"] in line:
        print(os.environ["STUB_REPLY"], flush=True)
print("stdin closed", flush=True)
if os.environ.get("STUB_SAY_LAST"):  # as Claude Code, which reads a piped stdin to its end first
    print(os.environ["STUB_SAY_LAST"], flush=True)
time.sleep(float(os.environ.get("STUB_HANG", "0")))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


def toml_entry(check):
    """One [[feature]] entry. JSON's strings, lists, and booleans are also TOML's."""
    plain = "".join(f"{k} = {json.dumps(v)}\n" for k, v in check.items() if not isinstance(v, dict))
    tables = "".join(f"[feature.{k}]\n" + "".join(f"{json.dumps(a)} = {json.dumps(b)}\n" for a, b in v.items())
                     for k, v in check.items() if isinstance(v, dict))
    return "[[feature]]\n" + plain + tables


class FeatureFailure(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.storage, self.workspace = self.root / "storage", self.root / "ws"
        (self.storage / "config").mkdir(parents=True)
        self.workspace.mkdir()

    def failure(self, check, log=""):
        return rc.feature_failure(check, log, self.storage, self.workspace, self.root / "home")

    def test_the_reason_names_the_first_pattern_that_fails(self):
        log = '{"skills":["probe-skill"],"agents":[]}\n'
        self.assertEqual(self.failure({"holds": ['"skills":[*"probe-skill"']}, log), "")
        self.assertEqual(self.failure({"holds": ['"skills":[*"probe-skill"', '"agents":[*"probe-agent"', "x"]}, log),
                         "the output does not hold '\"agents\":[*\"probe-agent\"'")
        self.assertEqual(self.failure({"holds": ['"skills"'], "lacks": ["probe-skill"]}, log),
                         "the output holds 'probe-skill'")

    def test_an_output_pattern_does_not_match_across_two_lines(self):
        self.assertIn("does not hold", self.failure({"holds": ['"skills":[*"probe-skill"']},
                                                    '{"skills":[]}\n{"other":"probe-skill"}\n'))

    def test_a_storage_file_must_be_there_and_hold_each_pattern(self):
        check = {"storage_holds": {"config/settings.json": ['"theme":*"dark"', '"model"']}}
        self.assertEqual(self.failure(check), "storage has no file config/settings.json")
        (self.storage / "config" / "settings.json").write_text('{\n  "theme": "dark"\n}\n')
        self.assertEqual(self.failure(check), "storage file config/settings.json does not hold '\"model\"'")
        (self.storage / "config" / "settings.json").write_text('{\n  "theme": "dark",\n  "model": "m"\n}\n')
        self.assertEqual(self.failure(check), "")

    def test_a_lacks_pattern_needs_its_file_and_an_empty_pattern_refuses_the_path(self):
        check = {"storage_lacks": {"config/.credentials.json": "", "config/settings.json": "apiKeyHelper"}}
        # A box that copied nothing has no settings.json, and must not pass as "the key stayed out".
        self.assertEqual(self.failure(check), "storage has no file config/settings.json")
        (self.storage / "config" / "settings.json").write_text('{"apiKeyHelper": "x"}')
        self.assertEqual(self.failure(check), "storage file config/settings.json holds 'apiKeyHelper'")
        (self.storage / "config" / "settings.json").write_text("{}")
        (self.storage / "config" / ".credentials.json").write_text("{}")
        self.assertEqual(self.failure(check), "storage has config/.credentials.json")

    def test_a_path_takes_the_workspace_s_dashed_name(self):
        dashed = rc.fill("{workspace.dashed}", self.root, Path("/tmp/a_b/c.d"))
        self.assertEqual(dashed, "-tmp-a-b-c-d")
        memory = self.storage / "config" / "projects" / rc.fill("{workspace.dashed}", self.root, self.workspace)
        memory.mkdir(parents=True)
        (memory / "MEMORY.md").write_text("probe-memory\n")
        check = {"storage_holds": {"config/projects/{workspace.dashed}/MEMORY.md": "probe-memory"}}
        self.assertEqual(self.failure(check), "")

    def test_a_star_in_a_path_names_many_files_and_one_must_hold_the_pattern(self):
        check = {"workspace_holds": {"requests/*/*.json": "<user-rule id=*probe>*probe-one"}}
        self.assertEqual(self.failure(check), "workspace has no file requests/*/*.json")
        (self.workspace / "requests" / "title").mkdir(parents=True)
        (self.workspace / "requests" / "title" / "0.json").write_text('{"content":"a title"}')
        self.assertEqual(self.failure(check),
                         "workspace file requests/*/*.json does not hold '<user-rule id=*probe>*probe-one'")
        (self.workspace / "requests" / "sess_1").mkdir()
        (self.workspace / "requests" / "sess_1" / "0.json").write_text('"<user-rule id=probe>\\n```\\nprobe-one"')
        self.assertEqual(self.failure(check), "")


class FeatureVerdict(unittest.TestCase):
    def test_a_box_that_did_not_run_or_was_stopped_is_an_error_whatever_the_patterns_say(self):
        self.assertEqual(rc.feature_verdict(False, False, ""), ("ERROR", "box-did-not-run"))
        self.assertEqual(rc.feature_verdict(True, True, ""), ("ERROR", "timeout"))
        self.assertEqual(rc.feature_verdict(True, False, "the output does not hold 'x'"),
                         ("RED", "the output does not hold 'x'"))
        self.assertEqual(rc.feature_verdict(True, False, ""), ("GREEN", ""))

    def test_a_result_is_compared_with_its_record(self):
        red = {"expect": {"verdict": "red", "reason": "storage has no file home/prompts/*"}}
        self.assertEqual(rc.feature_mismatch(red, "RED", "", "storage has no file home/prompts/a.md"), "")
        self.assertEqual(rc.feature_mismatch(red, "GREEN", ""), "expected RED, got GREEN")
        # Another failure is RED too, and must not pass as the recorded one.
        self.assertIn("expected the reason", rc.feature_mismatch(red, "RED", "", "the output does not hold 'x'"))
        self.assertIn("expected the reason", rc.feature_mismatch({"expect": {"verdict": "red"}}, "RED", "", "any"))
        self.assertEqual(rc.feature_mismatch({}, "RED", ""), "expected GREEN, got RED")
        self.assertEqual(rc.feature_mismatch({}, "ERROR", ""), "expected GREEN, got ERROR")


class FeatureSkip(unittest.TestCase):
    check = {"id": "x", "harness": "probe", "holds": ["a"], "needs": ["no-such-agent"], "system": True, "model": True}

    def test_every_blocker_is_named(self):
        self.assertEqual(rc.feature_skip(self.check, "/usr/bin:/bin", False, False),
                         "no-program:no-such-agent,needs-system-files,no-credentials")
        self.assertEqual(rc.feature_skip(dict(self.check, needs=["sh"]), "/usr/bin:/bin", True, False),
                         "no-credentials")
        self.assertIsNone(rc.feature_skip(dict(self.check, needs=["sh"]), "/usr/bin:/bin", True, True))

    def test_a_host_with_its_own_managed_settings_does_not_run_that_agent_s_checks(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        managed = folder / "requirements.toml"
        managed.write_text("")
        check = {"id": "x", "harness": "codex", "holds": ["a"]}
        # Each path here is one that the agent's pack lets the agent read.
        self.assertIn("/Library/Managed Preferences/com.anthropic.claudecode.plist", rc.MANAGED_SETTINGS["claude"])
        self.assertIn("/etc/codex/requirements.toml", rc.MANAGED_SETTINGS["codex"])
        with unittest.mock.patch.dict(rc.MANAGED_SETTINGS, {"codex": [str(managed)]}):
            self.assertEqual(rc.feature_skip(check, "/usr/bin:/bin", True, True),
                             f"host-has-managed-settings:{managed}")
            self.assertIsNone(rc.feature_skip(dict(check, harness="probe"), "/usr/bin:/bin", True, True))

    def test_an_entry_with_no_pattern_is_no_check(self):
        self.assertEqual(rc.feature_skip({"id": "x", "note": "why"}, "/usr/bin:/bin", True, True), "no-check")
        self.assertEqual(rc.feature_kind({"id": "x", "note": "why"}), "no-check")


class FeatureRunner(unittest.TestCase):
    """Runs `run_corpus.py --layer features` against a stub box and checks of its own."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.home = self.root / "operator-home"
        self.home.mkdir()
        self.homes = self.root / "h"
        self.homes.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, text in (("box", STUB_BOX), ("agent", "#!/bin/sh\n"),
                           ("sudo", '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        self.out = self.root / "out"
        self.calls_file = self.root / "calls.jsonl"

    def run_features(self, checks, *args, env=None):
        file = self.root / "features.toml"
        file.write_text("".join(toml_entry(c) for c in checks))
        environment = dict(os.environ, HOME=str(self.home), BOX_CORPUS_BIN=str(self.bin),
                           BOX_CODEX_BIN=str(self.root / "no-codex"), BOX_PATH_FALLBACKS="",
                           BOX_FEATURES_FILE=str(file), STUB_CALLS=str(self.calls_file),
                           BOX_FEATURES_HOMES=str(self.homes), BOX_FEATURES_KEEP_HOMES="1",
                           BOX_BEDROCK_KEY_FILE=str(self.root / "no-key"), AWS_BEARER_TOKEN_BEDROCK="",
                           BOX_HOME=str(self.home / ".strands" / "box"), CLAUDE_CONFIG_DIR=str(self.home / ".claude"),
                           CODEX_HOME=str(self.home / ".codex")) | (env or {})
        if "BOX_FEATURES_SYSTEM" not in (env or {}):
            environment.pop("BOX_FEATURES_SYSTEM", None)
        environment["PATH"] = "/usr/bin:/bin"
        result = subprocess.run([sys.executable, str(Path(rc.__file__)), "--layer", "features", *args,
                                 "--out", str(self.out)], capture_output=True, text=True, env=environment)
        results = self.out / "features.json"
        rows = json.loads(results.read_text()) if results.exists() else []
        return result, {r["id"]: r for r in rows}

    def calls(self):
        if not self.calls_file.exists():
            return []
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()]

    def check(self, **fields):
        return {"id": "probe", "row": "Skills", "harness": "codex", "with": "codex,bedrock-mantle",
                "needs": ["agent"], "args": ["app-server"], "holds": ["probe-skill"], **fields}

    def test_stdin_stays_open_until_the_answer_and_the_exit_code_does_not_decide(self):
        check = self.check(stdin=['{"method":"initialize","id":1}', '{"method":"skills/list","id":2}'],
                           until='"id":2', holds=['"name":"probe-skill"'], options=["codex.import-mcp=true"])
        result, rows = self.run_features([check], "--timeout", "20", env={
            "STUB_REPLY_TO": "skills/list", "STUB_REPLY": '{"id":2,"result":{"name":"probe-skill"}}',
            "STUB_EXIT": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((rows["probe"]["verdict"], rows["probe"]["rc"]), ("GREEN", 1))
        log = (self.out / "probe.log").read_text()
        # The stub answers only a line it read, and sees the end of its input only after its answer.
        self.assertLess(log.index('{"id":2,"result"'), log.index("stdin closed"))
        create, run = self.calls()
        self.assertEqual(create["argv"], ["profile", "create", rc.FEATURE_PROFILE, "--with", "codex,bedrock-mantle",
                                          "--policy", "open", "--option", "codex.import-mcp=true",
                                          "--option", "bedrock.sign-in=api-key", "--force"])
        self.assertEqual(run["argv"], ["run", rc.FEATURE_PROFILE, "--", "app-server"])
        self.assertLessEqual({"id", "row", "harness", "verdict", "reason", "expect", "mismatch"}, set(rows["probe"]))

    def test_an_answer_that_never_comes_is_an_error_not_a_red(self):
        check = self.check(stdin=['{"method":"initialize","id":1}'], until='"id":2')
        result, rows = self.run_features([check], "--timeout", "2")
        self.assertEqual((rows["probe"]["verdict"], rows["probe"]["reason"]), ("ERROR", "timeout"))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_an_agent_that_runs_on_after_its_report_is_stopped_and_is_not_a_timeout(self):
        check = self.check(until='"subtype":"init"', holds=['"skills":[*"probe-skill"'])
        result, rows = self.run_features([check], "--timeout", "3", env={
            "STUB_SAY_LAST": '{"type":"system","subtype":"init","skills":["probe-skill"]}', "STUB_HANG": "60"})
        self.assertEqual(rows["probe"]["verdict"], "GREEN", result.stdout)
        self.assertLess(rows["probe"]["seconds"], 30)

    def test_the_box_gets_a_home_of_the_check_s_own_and_never_the_operator_s(self):
        fixture = rc.FEATURE_FIXTURES / "claude"
        check = self.check(host="claude", args=["--version"], holds=[],
                           storage_holds={"config/CLAUDE.md": "probe-instructions"})
        copy = {"STUB_COPY": json.dumps({".claude/CLAUDE.md": "config/CLAUDE.md"})}
        result, rows = self.run_features([check], env=copy)
        self.assertEqual(rows["probe"]["verdict"], "GREEN", result.stdout + result.stderr)
        workspace = self.out / "probe" / "ws"
        calls = self.calls()
        home = Path(calls[0]["home"])
        self.assertEqual(home.parent, self.homes)  # one short folder, not a path under --out
        self.assertEqual([c["argv"][0] for c in calls], ["profile", "run"])
        for call in calls:
            self.assertEqual(call["home"], str(home))
            self.assertEqual(call["leaked"], [])
        self.assertFalse(Path(calls[0]["cwd"]).is_relative_to(rc.REPO), calls[0]["cwd"])
        self.assertEqual(calls[1]["cwd"], str(workspace))
        self.assertFalse((self.home / ".strands" / "box").exists())
        # The fixture's placeholders name this check's workspace.
        self.assertTrue((fixture / ".claude" / "projects" / "{workspace.dashed}").is_dir())
        dashed = rc.fill("{workspace.dashed}", home, workspace)
        self.assertTrue((home / ".claude" / "projects" / dashed / "memory" / "MEMORY.md").is_file())
        self.assertIn(str(workspace), json.loads((home / ".claude.json").read_text())["projects"])

    def test_each_skip_names_its_reason_and_no_skip_fails_only_a_missing_program(self):
        checks = [self.check(id="absent", needs=["no-such-agent"]),
                  self.check(id="system", system=True, system_file={"macos": "/x", "linux": "/x", "content": ""}),
                  self.check(id="model", model=True),
                  {"id": "none", "row": "Sessions and resume", "harness": "codex", "note": "No check."}]
        result, rows = self.run_features(checks, "--no-skip", "--ids", "system", "model", "none")
        self.assertEqual({i: (r["verdict"], r["reason"]) for i, r in rows.items()},
                         {"system": ("SKIP", "needs-system-files"), "model": ("SKIP", "no-credentials"),
                          "none": ("SKIP", "no-check")})
        self.assertEqual(result.returncode, 0, result.stdout)
        result, rows = self.run_features(checks, "--ids", "absent")
        self.assertEqual((rows["absent"]["reason"], result.returncode), ("no-program:no-such-agent", 0))
        result, rows = self.run_features(checks, "--ids", "absent", "--no-skip")
        self.assertIn("could run but is SKIP", rows["absent"]["mismatch"])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(self.calls(), [])

    def test_a_result_that_differs_from_its_record_fails_the_run(self):
        say = {"STUB_SAY": "probe-skill"}
        recorded_red = self.check(holds=["no-such-text"], expect={"verdict": "red", "reason": "no-such-text"})
        result, rows = self.run_features([recorded_red], env=say)
        self.assertEqual((rows["probe"]["verdict"], rows["probe"]["mismatch"], result.returncode), ("RED", "", 0))
        self.assertEqual(rows["probe"]["reason"], "the output does not hold 'no-such-text'")
        result, rows = self.run_features([self.check(expect={"verdict": "red", "reason": "x"})], env=say)
        self.assertEqual((rows["probe"]["mismatch"], result.returncode), ("expected RED, got GREEN", 1))
        result, rows = self.run_features([self.check(holds=["no-such-text"])], env=say)
        self.assertEqual((rows["probe"]["mismatch"], result.returncode), ("expected GREEN, got RED", 1))

    def test_a_box_that_does_not_start_is_an_error(self):
        result, rows = self.run_features([self.check()], env={"STUB_NO_BOX": "1"})
        self.assertEqual(rows["probe"]["verdict"], "ERROR")
        self.assertIn("box-did-not-run", rows["probe"]["reason"])
        result, rows = self.run_features([self.check()], env={"STUB_CREATE_FAILS": "1"})
        self.assertIn("profile-create-failed: no pack named no-such-pack", rows["probe"]["reason"])
        self.assertEqual([c["argv"][0] for c in self.calls()].count("run"), 1)

    def test_a_box_that_fills_storage_and_then_fails_to_start_the_agent_is_an_error(self):
        check = self.check(host="claude", args=["--version"], holds=[],
                           storage_holds={"config/CLAUDE.md": "probe-instructions"})
        env = {"STUB_COPY": json.dumps({".claude/CLAUDE.md": "config/CLAUDE.md"}),
               "STUB_SAY": "strands-box: error: containment setup failed during containment apply"}
        result, rows = self.run_features([check], env=env)
        self.assertEqual(rows["probe"]["verdict"], "ERROR", result.stdout + result.stderr)
        self.assertIn("containment setup failed", rows["probe"]["reason"])

    def test_only_a_model_check_gets_the_key_and_no_log_holds_it(self):
        checks = [self.check(id="plain", holds=["AWS"]), self.check(id="model", model=True, holds=["AWS"])]
        result, rows = self.run_features(checks, env={"AWS_BEARER_TOKEN_BEDROCK": "tok-secret-123",
                                                      "STUB_SAY": "AWS key tok-secret-123"})
        self.assertEqual([rows[i]["verdict"] for i in ("plain", "model")], ["GREEN", "GREEN"], result.stdout)
        tokens = {c["cwd"].split("/")[-2]: c["token"] for c in self.calls() if c["argv"][0] == "run"}
        self.assertEqual(tokens, {"plain": "placeholder-no-model-call", "model": "tok-secret-123"})
        for name in ("plain", "model"):
            self.assertNotIn("tok-secret-123", (self.out / f"{name}.log").read_text())

    def test_only_a_kiro_model_check_gets_the_kiro_key_and_no_log_holds_it(self):
        checks = [self.check(id="plain", harness="kiro", holds=["KIRO"]),
                  self.check(id="model", harness="kiro", model=True, holds=["KIRO"]),
                  self.check(id="codex", model=True, holds=["KIRO"])]
        result, rows = self.run_features(checks, env={"KIRO_API_KEY": "ksk_secret-456",
                                                      "AWS_BEARER_TOKEN_BEDROCK": "tok-secret-123",
                                                      "STUB_SAY": "KIRO key ksk_secret-456"})
        self.assertEqual([rows[i]["verdict"] for i in ("plain", "model", "codex")], ["GREEN"] * 3, result.stdout)
        keys = {c["cwd"].split("/")[-2]: c["kiro_key"] for c in self.calls() if c["argv"][0] == "run"}
        self.assertEqual(keys, {"plain": "ksk_placeholder-no-model-call", "model": "ksk_secret-456",
                                "codex": "ksk_placeholder-no-model-call"})
        for name in ("plain", "model", "codex"):
            self.assertNotIn("ksk_secret-456", (self.out / f"{name}.log").read_text())

    def test_a_kiro_model_check_with_no_kiro_key_is_skip_whatever_the_bedrock_key(self):
        check = self.check(harness="kiro", model=True)
        result, rows = self.run_features([check], env={"AWS_BEARER_TOKEN_BEDROCK": "tok-secret-123",
                                                       "KIRO_API_KEY": "", "BOX_KIRO_KEY_FILE": str(self.root / "no-key")})
        self.assertEqual((rows["probe"]["verdict"], rows["probe"]["reason"]), ("SKIP", "no-credentials"), result.stdout)

    def test_the_kiro_runtime_is_the_operator_s_unless_the_shell_names_one(self):
        self.run_features([self.check(id="default")])
        result, rows = self.run_features([self.check(id="named")], env={"KIRO_RUNTIME_DIR": "/opt/kiro-runtime"})
        runtimes = {c["cwd"].split("/")[-2]: c["kiro_runtime"] for c in self.calls() if c["argv"][0] == "run"}
        self.assertEqual(runtimes, {"default": str(self.home / ".kiro-runtime"), "named": "/opt/kiro-runtime"})

    def test_agent_env_reaches_the_profile_with_the_check_s_workspace(self):
        check = self.check(agent_env={"KIRO_DUMP_REQUESTS": "1", "KIRO_DUMP_REQUESTS_DIR": "{workspace}/requests"})
        result, rows = self.run_features([check], env={"STUB_SAY": "probe-skill"})
        self.assertEqual(rows["probe"]["verdict"], "GREEN", result.stdout + result.stderr)
        home = Path(self.calls()[0]["home"])
        profile = rc.tomllib.loads((home / ".strands" / "box" / "profiles" / rc.FEATURE_PROFILE / "profile.toml").read_text())
        self.assertEqual(profile, {"packs": [], "agent": {"env": {
            "KIRO_DUMP_REQUESTS": "1", "KIRO_DUMP_REQUESTS_DIR": str(self.out / "probe" / "ws" / "requests")}}})

    def test_no_log_holds_the_account_of_a_role_that_a_model_error_names(self):
        said = "403: arn:aws:sts::123456789012:assumed-role/Role/session is not authorized"
        self.run_features([self.check(holds=["403"])], env={"STUB_SAY": said})
        log = (self.out / "probe.log").read_text()
        self.assertIn("arn:aws:sts::***:assumed-role/Role/session", log)
        self.assertNotIn("123456789012", log)

    def test_a_host_edit_runs_the_agent_again_and_the_patterns_test_the_second_run(self):
        check = self.check(host="claude", args=["--version"], holds=[],
                           host_edit={".claude/CLAUDE.md": "probe-two\n"},
                           storage_holds={"config/CLAUDE.md": "probe-two"},
                           storage_lacks={"config/CLAUDE.md": "feature-probe-instructions-one"})
        copy = {"STUB_COPY": json.dumps({".claude/CLAUDE.md": "config/CLAUDE.md"})}
        result, rows = self.run_features([check], env=copy)
        self.assertEqual(rows["probe"]["verdict"], "GREEN", result.stdout)
        self.assertEqual([c["argv"][0] for c in self.calls()], ["profile", "run", "run"])

    def test_a_system_file_is_there_for_the_run_and_gone_after_it(self):
        target = self.root / "etc" / "agent" / "requirements.toml"
        (self.root / "etc").mkdir()
        system_file = {"macos": str(target), "linux": str(target), "content": 'allowed = ["on-request"]\n'}
        check = self.check(system=True, system_file=system_file, holds=['system file: allowed = ["on-request"]'])
        result, rows = self.run_features([check], env={"BOX_FEATURES_SYSTEM": "1", "STUB_SHOW": str(target)})
        self.assertEqual(rows["probe"]["verdict"], "GREEN", result.stdout + result.stderr)
        self.assertEqual(sorted(p.name for p in self.root.joinpath("etc").iterdir()), [])

    def test_a_system_file_that_is_there_is_never_replaced_or_removed(self):
        target = self.root / "etc" / "requirements.toml"
        target.parent.mkdir()
        target.write_text("the operator's own\n")
        system_file = {"macos": str(target), "linux": str(target), "content": "the runner's\n"}
        result, rows = self.run_features([self.check(system=True, system_file=system_file)],
                                         env={"BOX_FEATURES_SYSTEM": "1"})
        self.assertEqual((rows["probe"]["verdict"], rows["probe"]["reason"]),
                         ("ERROR", f"system-file-exists:{target}"))
        self.assertEqual(target.read_text(), "the operator's own\n")
        self.assertEqual(self.calls(), [])


class FeatureChecks(unittest.TestCase):
    checks = rc.feature_checks()

    def test_a_red_record_names_its_reason_and_an_absence_check_shows_that_the_copy_ran(self):
        for check in self.checks:
            with self.subTest(check["id"]):
                if check.get("expect", {}).get("verdict") == "red":
                    self.assertTrue(check["expect"].get("reason"))
                lacks = rc.patterns_of(check.get("storage_lacks"))
                if lacks and not check.get("storage_holds"):
                    self.assertTrue(any(pattern for _path, pattern in lacks),
                                    "only absent paths: an empty storage would pass")

    def test_every_row_of_the_checklist_has_an_entry_for_each_agent_it_applies_to(self):
        have = {(c["row"], c["harness"]) for c in self.checks}
        want = {(row, harness) for row, harnesses in CHECKLIST.items() for harness in harnesses}
        self.assertEqual(sorted(want - have), [])
        self.assertEqual(sorted(have - want), [(MODEL_ROW, h) for h in HARNESSES])
        self.assertEqual([sum(h == harness for _, h in want) for harness in HARNESSES], [19, 18, 18])

    def test_each_agent_has_one_model_call_and_only_kiro_reads_its_report_through_the_model(self):
        model = [(c["row"], c["harness"]) for c in self.checks if c.get("model")]
        self.assertEqual(sorted(r for r in model if r[1] != "kiro"), [(MODEL_ROW, "claude"), (MODEL_ROW, "codex")])
        self.assertEqual([c["id"] for c in self.checks if c["row"] == MODEL_ROW and c["harness"] == "kiro"],
                         ["kiro-hello"])
        # A Kiro check reads storage with no model call, or calls the model to read Kiro CLI's report.
        for check in self.checks:
            if check["harness"] == "kiro" and rc.has_check(check):
                with self.subTest(check["id"]):
                    self.assertEqual(bool(check.get("model")), check["args"] != ["--version"])

    def test_each_entry_is_well_formed(self):
        ids = [c["id"] for c in self.checks]
        self.assertEqual(len(ids), len(set(ids)))
        for check in self.checks:
            with self.subTest(check=check["id"]):
                self.assertTrue(check["id"].startswith(check["harness"] + "-"))
                self.assertIn(check.get("expect", {}).get("verdict", "green"), ("green", "red", "error"))
                if not rc.has_check(check):
                    self.assertTrue(check.get("note"), "an entry with no check says why")
                    continue
                self.assertEqual(check["needs"], [PROGRAMS[check["harness"]]])
                self.assertEqual(check["with"].split(",")[0], check["harness"])
                self.assertTrue(check["args"])
                if "expect" in check:
                    self.assertTrue(check.get("note"), "a record says why")
                if check.get("stdin"):
                    self.assertTrue(check.get("until"), "an agent that reads stdin needs an end")
                    for line in check["stdin"]:
                        json.loads(line)
                if check.get("system"):
                    self.assertEqual(set(check["system_file"]), {"macos", "linux", "content"})
                # The stand-in key cannot reach a model, so only a model check may wait for one.
                if check["harness"] == "claude" and "-p" in check["args"] and not check.get("model"):
                    self.assertEqual(check.get("until"), '"subtype":"init"')

    def test_each_host_fixture_is_there_and_each_fixture_is_used(self):
        used = {c["host"] for c in self.checks if c.get("host")}
        self.assertEqual(used, {p.name for p in rc.FEATURE_FIXTURES.iterdir() if p.is_dir()})


if __name__ == "__main__":
    unittest.main()
