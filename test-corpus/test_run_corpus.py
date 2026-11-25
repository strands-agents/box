"""Unit tests for run_corpus.py. They start no box: python3 -m unittest discover -s test-corpus"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import bench
import run_corpus as rc

with open(rc.GRID, "rb") as f:
    CELLS = tomllib.load(f)["cell"]

# The hosts a committed lockfile may fetch from, so a lockfile made behind a private mirror fails.
PUBLIC_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
                     "conda.anaconda.org", "repo.anaconda.com", "rubygems.org", "repo.packagist.org",
                     "api.github.com", "github.com", "codeload.github.com", "index.crates.io",
                     "static.crates.io"}
LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock",
             "pixi.lock", "Gemfile.lock", "composer.lock", "Cargo.lock"}


def lockfile_hosts(path):
    """Every host a lockfile fetches from. A JSON lockfile is read for its fetch fields, so a
    funding or homepage link does not count. Any other lockfile has every URL in it counted."""
    def host(url):
        return url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0]
    if path.name == "package-lock.json":
        packages = json.loads(path.read_text()).get("packages", {})
        return {host(p["resolved"]) for p in packages.values() if "://" in p.get("resolved", "")}
    if path.name == "composer.lock":
        lock = json.loads(path.read_text())
        return {host(p[key]["url"]) for p in lock.get("packages", []) + lock.get("packages-dev", [])
                for key in ("dist", "source") if "://" in (p.get(key) or {}).get("url", "")}
    text = path.read_text().replace("\\/", "/")
    return {host(url) for url in re.findall(r"[a-z+]+://[^\s\"'<>]+", text)}


class GlobMatch(unittest.TestCase):
    def test_only_the_star_is_special(self):
        self.assertTrue(rc.glob_match("net:connect [::1]:*", "net:connect [::1]:5173"))
        self.assertFalse(rc.glob_match("net:connect [::1]:*", "net:connect 1:5173"))
        self.assertTrue(rc.glob_match("shell:spawn */npx-cli.js", "shell:spawn /a/b/npx-cli.js"))
        self.assertFalse(rc.glob_match("fs:read ~/.npm", "fs:read ~/.npm/x"))


class DenyLines(unittest.TestCase):
    def test_denials_name_no_runner_path(self):
        cell_dir = rc.HOME / "work" / "TS-01"
        decisions = [
            ("deny", "fs:write", "<default-deny>", f"{rc.HOME}/Library/Preferences/.wrangler"),
            ("deny", "fs:read", "<default-deny>", f"{cell_dir}/.env"),
            ("permit", "fs:read", "project_read", f"{cell_dir}/a"),
            ("deny", "fs:read", "<default-deny>", f"{cell_dir}/.env"),
        ]
        self.assertEqual(rc.deny_lines(decisions, cell_dir), [
            "fs:read {workspace}/.env",
            "fs:write ~/Library/Preferences/.wrangler",
        ])


class Mismatch(unittest.TestCase):
    red = {"expect": {"verdict": "red", "denies": ["shell:spawn */npx-cli.js"]}}

    def test_no_expect_means_green(self):
        self.assertEqual(rc.mismatch({}, "GREEN", [], ""), "")
        self.assertEqual(rc.mismatch({}, "RED", ["x y"], ""), "expected GREEN, got RED")

    def test_a_red_record_matches_its_denials_exactly(self):
        npx = "shell:spawn /n/lib/node_modules/npm/bin/npx-cli.js"
        self.assertEqual(rc.mismatch(self.red, "RED", [npx], ""), "")
        self.assertIn("new deny: net:connect a:443", rc.mismatch(self.red, "RED", [npx, "net:connect a:443"], ""))
        self.assertIn("deny stopped: shell:spawn */npx-cli.js", rc.mismatch(self.red, "RED", ["net:connect a:443"], ""))

    def test_a_closed_gap_differs(self):
        self.assertEqual(rc.mismatch(self.red, "GREEN", [], ""), "expected RED, got GREEN")

    def test_an_error_record_needs_its_text_in_the_log(self):
        cell = {"expect": {"verdict": "error", "log": "toolchain is not installed"}}
        self.assertEqual(rc.mismatch(cell, "ERROR", [], "x: toolchain is not installed\n"), "")
        self.assertIn("does not contain", rc.mismatch(cell, "ERROR", [], "other failure"))
        self.assertIn("does not contain", rc.mismatch({"expect": {"verdict": "error"}}, "ERROR", [], "any"))

    def test_a_star_in_an_error_record_matches_within_one_line(self):
        cell = {"expect": {"verdict": "error", "log": "temp file *: Operation not permitted"}}
        self.assertEqual(rc.mismatch(cell, "ERROR", [], "a\nerror: temp file /t/x1: Operation not permitted\n"), "")
        self.assertIn("does not contain", rc.mismatch(cell, "ERROR", [], "temp file /t/x1\n: Operation not permitted\n"))

    def test_a_run_the_runner_stopped_differs_from_its_record(self):
        npx = "shell:spawn /n/lib/node_modules/npm/bin/npx-cli.js"
        error = {"expect": {"verdict": "error", "log": "timeout exceeded"}}
        for cell, verdict, denials, log in ((self.red, "RED", [npx], ""), (error, "ERROR", [], "timeout exceeded\n")):
            with self.subTest(verdict=verdict):
                self.assertEqual(rc.mismatch(cell, verdict, denials, log), "")
                self.assertEqual(rc.mismatch(cell, verdict, denials, log, True),
                                 "the runner stopped the run at --timeout")


class SkipReason(unittest.TestCase):
    tools = set(rc.PROBE_TOOLS)

    def cell(self, **fields):
        return {"id": "X", "machine": "clean", "needs": [], "fixture": "empty", "script": "true", **fields}

    def test_committed_fixtures_and_pinned_clones_run(self):
        self.assertIsNone(rc.skip_reason(self.cell(fixture="cargo-new"), self.tools, False, "scripted"))
        self.assertIsNone(rc.skip_reason(self.cell(fixture=rc.PYTHON_VENV), self.tools, False, "scripted"))
        self.assertIsNone(rc.skip_reason(self.cell(fixture="clone:a/b", fixture_ref="v1"), self.tools, False, "scripted"))
        self.assertEqual(rc.skip_reason(self.cell(fixture="clone:a/b"), self.tools, False, "scripted"),
                         "needs-network-clone:clone:a/b")
        self.assertEqual(rc.skip_reason(self.cell(fixture="no-such-fixture"), self.tools, False, "scripted"),
                         "fixture-not-built:no-such-fixture")

    def test_every_blocker_is_named(self):
        cell = self.cell(machine="lived-in", needs=["git", "no-such-a", "no-such-b"],
                         fixture="no-such-fixture", script="")
        self.assertEqual(rc.skip_reason(cell, self.tools, False, "scripted"),
                         "no-toolchain:no-such-a+no-such-b,needs-lived-in-image,"
                         "fixture-not-built:no-such-fixture,no-scripted-commands")
        self.assertEqual(rc.skip_reason(self.cell(machine="lived-in", script=""), self.tools, False, "scripted"),
                         "needs-lived-in-image,no-scripted-commands")

    def test_an_unset_or_blank_env_var_is_skip(self):
        cell = self.cell(env_vars=["GH_TOKEN", "GIT_GITHUB"])
        self.assertEqual(rc.skip_reason(cell, self.tools, False, "scripted", set()),
                         "no-env:GH_TOKEN+GIT_GITHUB")
        self.assertEqual(rc.skip_reason(cell, self.tools, False, "scripted", {"GH_TOKEN"}),
                         "no-env:GIT_GITHUB")
        self.assertIsNone(rc.skip_reason(cell, self.tools, False, "scripted", {"GH_TOKEN", "GIT_GITHUB"}))
        self.assertEqual(rc.skip_reason(self.cell(env_vars=["GH_TOKEN"], script=""), self.tools, False, "scripted", set()),
                         "no-env:GH_TOKEN,no-scripted-commands")

    def test_a_cell_with_its_own_profile_never_runs_on_the_agent_layer(self):
        cell = self.cell(profile="corpus-github")
        self.assertIsNone(rc.skip_reason(cell, self.tools, True, "scripted"))
        self.assertEqual(rc.skip_reason(cell, self.tools, True, "agent"), "scripted-only-profile")
        self.assertIsNone(rc.skip_reason(self.cell(), self.tools, True, "agent"))

    def test_kiro_runs_a_github_cell_under_kiro_github(self):
        cell = self.cell(profile="corpus-github")
        self.assertIsNone(rc.skip_reason(cell, self.tools, True, "agent", agent="kiro"))
        self.assertEqual(rc.skip_reason(cell, self.tools, True, "agent", agent="claude"),
                         "scripted-only-profile")
        self.assertEqual(rc.agent_cell_profile("kiro", cell), "kiro-github")
        self.assertEqual(rc.agent_cell_profile("kiro", self.cell()), "kiro")
        with open(rc.PROFILES / "kiro-github" / "profile.toml", "rb") as f:
            kiro = tomllib.load(f)
        with open(rc.PROFILES / "corpus-github" / "profile.toml", "rb") as f:
            github = tomllib.load(f)
        self.assertEqual(kiro["egress"], github["egress"])
        self.assertEqual((rc.PROFILES / "kiro-github" / "policy.dw").read_text(),
                         (rc.REPO / "resources/policies/open/policy.dw").read_text())
        options = {f"{a}.{k}": v for a, kv in kiro["options"].items() for k, v in kv.items()}
        self.assertEqual(options, dict(o.split("=") for o in rc.AGENT_PROFILES["kiro"][1]))

    def test_the_mcp_skip_is_for_the_agent_layer(self):
        cell = self.cell(note="MCP servers; not runnable on the agent layer today")
        self.assertIsNone(rc.skip_reason(cell, self.tools, True, "scripted"))
        self.assertEqual(rc.skip_reason(cell, self.tools, True, "agent"), "mcp-not-in-box")


class ShardCells(unittest.TestCase):
    def test_the_shards_split_the_cells_that_run_and_shard_1_lists_the_rest(self):
        cells = [c for c in CELLS if c["section"] == "Python"]
        n = len(bench.plan(cells))
        shards = [rc.shard_cells(cells, k, n) for k in range(1, n + 1)]
        ids = [c["id"] for shard in shards for c in shard]
        self.assertEqual(sorted(ids), sorted(c["id"] for c in cells), "each cell is listed once")
        for cid in ("PY-02", "PY-07", "PY-11"):
            self.assertIn(cid, [c["id"] for c in shards[0]])
        for shard in shards:
            runs = [c for c in shard if c.get("script") and not bench.quarantined(c)]
            self.assertTrue(runs, "every shard the plan makes has a cell to run")


class LinkedWorktree(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_project_is_a_worktree_whose_git_common_dir_lies_outside_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "PY-10"
            cell = {"id": "PY-10", "fixture": rc.LINKED_WORKTREE}
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            self.assertTrue((project / "app.py").is_file())
            common = subprocess.run(["git", "-C", str(project), "rev-parse", "--path-format=absolute",
                                     "--git-common-dir"], capture_output=True, text=True, check=True)
            self.assertEqual(Path(common.stdout.strip()).resolve(),
                             (Path(tmp) / "PY-10.main" / ".git").resolve())
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))


class FixtureRemote(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_a_github_fixture_has_an_https_origin_and_an_uncommitted_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "EV-01"
            cell = {"id": "EV-01", "fixture": "test-github-repo-https"}
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            origin = subprocess.run(["git", "-C", str(project), "remote", "get-url", "origin"],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(origin.stdout.strip(),
                             "https://github.com/strands-agents/box.git")
            status = subprocess.run(["git", "-C", str(project), "status", "--porcelain"],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(status.stdout.strip(), "M README.md")
            count = subprocess.run(["git", "-C", str(project), "rev-list", "--count", "HEAD"],
                                   capture_output=True, text=True, check=True)
            self.assertEqual(count.stdout.strip(), "1")

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_ssh_fixture_is_built_with_an_ssh_origin_and_an_uncommitted_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "EV-02"
            cell = {"id": "EV-02", "fixture": "test-github-repo-ssh"}
            self.assertTrue(rc.fixture_built(cell))
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            git = lambda *a: subprocess.run(["git", "-C", str(project), *a], capture_output=True,
                                            text=True, check=True).stdout.strip()
            self.assertEqual(git("remote", "get-url", "origin"),
                             "git@github.com:strands-agents/box.git")
            self.assertEqual(git("status", "--porcelain"), "M README.md")
            self.assertEqual(git("rev-list", "--count", "HEAD"), "1")


class PythonVenvFixture(unittest.TestCase):
    def test_a_host_without_uv_is_a_fixture_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rc.make_venv(Path(tmp), {"PATH": tmp}),
                             "fixture-build-failed:no uv on PATH")

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_venv_is_made_after_the_commit_and_stays_out_of_it(self):
        made = []

        def make_venv(d, env):
            (d / ".venv" / "bin").mkdir(parents=True)
            made.append(d)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(rc, "make_venv", make_venv):
            project = Path(tmp) / "PY-01C"
            cell = {"id": "PY-01C", "fixture": rc.PYTHON_VENV}
            self.assertTrue(rc.fixture_built(cell))
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            self.assertEqual(made, [project])
            tracked = subprocess.run(["git", "-C", str(project), "ls-files"], capture_output=True,
                                     text=True, check=True).stdout.split()
            self.assertEqual(tracked, ["README.md"])


class GoPrivateModule(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_service_requires_the_private_module_at_its_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "GO-04"
            cell = {"id": "GO-04", "fixture": rc.GO_PRIVATE}
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            self.assertEqual(rc.GO_PRIVATE_MODULE, "github.com/strands-agents/box-corpus-private")
            self.assertTrue((project / "go.mod").read_text().endswith(
                "\nrequire github.com/strands-agents/box-corpus-private v0.1.0\n"))
            self.assertIn(f'greet "{rc.GO_PRIVATE_MODULE}"', (project / "main.go").read_text())

    def test_the_cell_names_the_variable_its_profile_routes(self):
        cell = next(c for c in tomllib.load(open(rc.GRID, "rb"))["cell"] if c["id"] == "GO-04")
        profile = (rc.REPO / "test-corpus" / "profiles" / "corpus-go-private" / "profile.toml").read_text()
        self.assertEqual(cell["env_vars"], ["GIT_CORPUS_PRIVATE"])
        self.assertIn('secret.ref = "env://GIT_CORPUS_PRIVATE"', profile)


class PullRequestBranch(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_project_is_a_feature_branch_whose_origin_does_not_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "EV-03"
            cell = {"id": "EV-03", "fixture": rc.PR_BRANCH}
            self.assertIsNone(rc.make_fixture(cell, project, dict(os.environ)))
            git = lambda *a: subprocess.run(["git", "-C", str(project), *a], capture_output=True,
                                            text=True, check=True).stdout.strip()
            self.assertEqual(git("branch", "--show-current"), "fix-add")
            self.assertEqual(git("remote", "get-url", "origin"), rc.MISSING_REMOTE)
            self.assertEqual(git("status", "--porcelain"), "")
            test = subprocess.run(["bash", "test.sh"], cwd=project, capture_output=True, text=True)
            self.assertNotEqual(test.returncode, 0)


class LaunchChecks(unittest.TestCase):
    def test_each_check_runs_a_profile_the_runner_installs_and_never_an_operators_own(self):
        committed = {p.name for p in rc.PROFILES.iterdir() if p.is_dir()}
        self.assertTrue(committed.isdisjoint({"claude", "codex"}))
        packs = {f"@box/{p.name}" for p in (rc.REPO / "resources" / "packs").iterdir() if p.is_dir()}
        shared = {}
        for check in rc.launch_checks():
            with self.subTest(check=check["id"]):
                if check.get("with"):
                    fields = (check["with"], check.get("options", []), check.get("needs", []))
                    self.assertEqual(shared.setdefault(check["profile"], fields), fields)
                self.assertTrue(check["args"])
                self.assertTrue(check.get("with") or check["profile"] in committed)
                self.assertNotIn(check["profile"], {"claude", "codex"})
                for pack in filter(None, check.get("with", "").split(",")):
                    self.assertIn(f"@box/{pack}", packs)
                if "expect" in check:
                    self.assertIn(check["expect"]["verdict"], {"red", "error"})
                    self.assertTrue(check.get("note"))


class AgentArgs(unittest.TestCase):
    def test_the_codex_model_override_comes_before_exec(self):
        argv = rc.agent_args("codex", "hi")
        self.assertLess(argv.index("model=openai.gpt-5.4"), argv.index("exec"))

    def test_claude_takes_the_prompt_with_p_and_bash_with_c(self):
        self.assertEqual(rc.agent_args("claude", "hi"),
                         ["--dangerously-skip-permissions", "--output-format", "stream-json",
                          "--verbose", "-p", "hi"])
        self.assertEqual(rc.agent_args("probe", "echo hi"), ["-c", "echo hi"])

    def test_kiro_takes_the_prompt_as_a_headless_chat(self):
        self.assertEqual(rc.agent_args("kiro", "hi"), ["--trust-workspace", "--output-format", "stream-json", "hi"])


class SuggestExpect(unittest.TestCase):
    def test_a_printed_record_matches_the_run_it_came_from(self):
        denials = ["shell:spawn /n/lib/node_modules/npm/bin/npx-cli.js"]
        line = rc.suggest_expect({"verdict": "RED", "denials": denials}, "")
        cell = {"expect": tomllib.loads(line)["expect"]}
        self.assertEqual(rc.mismatch(cell, "RED", denials, ""), "")
        log = "starting\nstrands-shell: execution timeout exceeded\n\n"
        line = rc.suggest_expect({"verdict": "ERROR", "denials": []}, log)
        cell = {"expect": tomllib.loads(line)["expect"]}
        self.assertEqual(rc.mismatch(cell, "ERROR", [], log), "")

    def test_an_error_record_names_the_failing_line_and_a_green_run_drops_the_record(self):
        log = "npm error code ENOENT\nnpm error A complete log of this run can be found in: x\nnpm notice done\n"
        line = rc.suggest_expect({"verdict": "ERROR", "denials": []}, log)
        self.assertIn("A complete log", line)
        self.assertNotIn("notice done", line)
        self.assertEqual(rc.suggest_expect({"verdict": "GREEN", "denials": []}, ""), "remove the expect line")


STUB_BOX = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
home = Path(os.environ["HOME"])
with open(home / "calls.jsonl", "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1:3] == ["profile", "create"]:
    if os.environ.get("STUB_CREATE_FAILS"):
        print("no pack named no-such-pack")
        sys.exit(1)
    (home / ".strands/box" / "profiles" / sys.argv[3]).mkdir(parents=True, exist_ok=True)
    sys.exit(0)
run = home / ".strands/box" / "r" / ("b-" + os.urandom(8).hex())
run.mkdir(parents=True, exist_ok=True)
(run / "profile-name").write_text(sys.argv[2] + "\n")
records = []
if os.environ.get("STUB_DENY"):  # "<action> <resource>", journaled as the box journals a denial
    action, resource = os.environ["STUB_DENY"].split(" ", 1)
    attributes = [{"key": f"strands.box.policy.{key}", "value": {"stringValue": value}}
                  for key, value in (("verdict", "deny"), ("action", action), ("rule", "<default-deny>"),
                                     ("resource", resource))]
    records.append({"resourceLogs": [{"scopeLogs": [{"scope": {"name": "strands-box.policy"},
                                                     "logRecords": [{"attributes": attributes}]}]}]})
(run / "records.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
if not os.environ.get("STUB_NO_RECORD_PATH"):
    print(f"box: running profile {sys.argv[2]} as {run.name} (records: {run / 'records.jsonl'})", flush=True)
if os.environ.get("STUB_OTHER_PROFILE"):
    other = run.parent / ("b-" + "f" * 16)
    other.mkdir(exist_ok=True)
    (other / "profile-name").write_text(sys.argv[2] + "-other\n")
    (other / "records.jsonl").write_text("")
    os.utime(other, (time.time() + 10, time.time() + 10))
if os.environ.get("STUB_SAY"):
    print(os.environ["STUB_SAY"], flush=True)
if os.environ.get("STUB_ECHO"):  # the name of a variable whose value the box was given
    print(f"{os.environ['STUB_ECHO']}={os.environ.get(os.environ['STUB_ECHO'], '')}", flush=True)
if os.environ.get("STUB_WRITE"):  # "<file>=<text>": the agent writes a file in its workspace
    name, text = os.environ["STUB_WRITE"].split("=", 1)
    Path(name).write_text(text)
time.sleep(float(os.environ.get("STUB_HANG", "0")))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


class Runner(unittest.TestCase):
    """Runs run_corpus.py against a stub box, so no box starts."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "box").write_text(STUB_BOX)
        (self.bin / "box").chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_corpus(self, *args, path="", env=None):
        environment = dict(os.environ, HOME=str(self.home), BOX_CORPUS_BIN=str(self.bin),
                           BOX_CODEX_BIN=str(self.root / "no-codex"), BOX_PATH_FALLBACKS="",
                           **(env or {}))
        environment["PATH"] = os.pathsep.join(p for p in (path, "/usr/bin:/bin") if p)
        return subprocess.run([sys.executable, str(Path(rc.__file__)), *args, "--out", str(self.root / "out")],
                              capture_output=True, text=True, env=environment)

    def calls(self):
        log = self.home / "calls.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def programs(self, bodies):
        """A folder for PATH of stand-in programs, each a shell script with the body given."""
        folder = self.root / "programs"
        folder.mkdir(exist_ok=True)
        for name, body in bodies.items():
            (folder / name).write_text(f"#!/bin/sh\n{body}\n")
            (folder / name).chmod(0o755)
        return str(folder)

    def test_the_kiro_launch_check_gets_the_stand_in_whatever_key_the_host_holds(self):
        agents = self.root / "agents"
        agents.mkdir()
        (agents / "kiro-cli").write_text("#!/bin/sh\n")
        (agents / "kiro-cli").chmod(0o755)
        self.run_corpus("--layer", "launch", "--ids", "kiro", "--fail-on", "none", path=str(agents),
                        env={"KIRO_API_KEY": "ksk_real-key", "STUB_ECHO": "KIRO_API_KEY"})
        log = (self.root / "out" / "kiro.log").read_text()
        self.assertIn("KIRO_API_KEY=ksk_placeholder-no-model-call", log)

    def test_kiro_with_the_judge_needs_a_bedrock_key_before_any_cell_runs(self):
        result = self.run_corpus("--layer", "agent", "--profile", "kiro", "--judge", "--ids", "EV-07",
                                 env={"KIRO_API_KEY": "ksk_test", "AWS_BEARER_TOKEN_BEDROCK": "",
                                      "BOX_KIRO_KEY_FILE": str(self.root / "no-kiro-key"),
                                      "BOX_BEDROCK_KEY_FILE": str(self.root / "no-bedrock-key")})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--judge calls Bedrock", result.stderr)
        self.assertEqual([call for call in self.calls() if call[0] == "run"], [])

    def test_the_launch_layer_runs_each_check_as_its_profile_with_its_args(self):
        agents = self.root / "agents"
        agents.mkdir()
        for agent in ("codex", "kiro-cli"):
            (agents / agent).write_text("#!/bin/sh\n")
            (agents / agent).chmod(0o755)
        # The stub's runs are all GREEN, so a check whose expect records a refusal differs.
        result = self.run_corpus("--layer", "launch", "--fail-on", "none", path=str(agents))
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual([call[1] for call in runs], [c["profile"] for c in rc.launch_checks()])
        for call, check in zip(runs, rc.launch_checks()):
            self.assertEqual(call[2:], ["--", *check["args"]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_missing_agent_is_skip_and_no_skip_makes_it_fail(self):
        result = self.run_corpus("--layer", "launch", "--ids", "codex")
        self.assertIn("SKIP   no-program:codex", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.run_corpus("--layer", "launch", "--ids", "codex", "--no-skip")
        self.assertIn("could run but is SKIP", result.stdout)
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_install_profiles_copies_the_committed_ones_and_makes_only_the_checks_that_run(self):
        self.run_corpus("--layer", "launch", "--install-profiles", "--fail-on", "none")
        installed = {p.name for p in (self.home / ".strands/box" / "profiles").iterdir()}
        self.assertTrue({p.name for p in rc.PROFILES.iterdir() if p.is_dir()} <= installed)
        creates = [call for call in self.calls() if call[:2] == ["profile", "create"]]
        self.assertEqual(sorted(call[2] for call in creates),
                         sorted({c["profile"] for c in rc.launch_checks() if c.get("with")}))
        options = {c["profile"]: c.get("options", []) for c in rc.launch_checks()}
        for call in creates:
            self.assertIn("--force", call)
            self.assertIn(["--policy", "open"], [call[i:i + 2] for i in range(len(call) - 1)])
            for option in options[call[2]]:
                self.assertIn(["--option", option], [call[i:i + 2] for i in range(len(call) - 1)])
        withs = {c["profile"]: c["with"] for c in rc.launch_checks() if c.get("with")}
        for call in creates:
            # CI's job env holds no AWS keys, so a Bedrock profile signs with the minted key.
            keyed = ["--option", "bedrock.sign-in=api-key"] in [call[i:i + 2] for i in range(len(call) - 1)]
            bedrock = bool({"bedrock", "bedrock-mantle"} & set(withs[call[2]].split(",")))
            self.assertEqual(keyed, bedrock, call)
        for args in (["--layer", "launch", "--ids", "probe"], ["--layer", "scripted", "--ids", "TS-05"]):
            self.home.joinpath("calls.jsonl").unlink()
            self.run_corpus(*args, "--install-profiles", "--fail-on", "none")
            self.assertFalse([call for call in self.calls() if call[:2] == ["profile", "create"]], args)

    def test_a_failed_profile_create_stops_the_run(self):
        result = self.run_corpus("--layer", "launch", "--ids", "claude", "--install-profiles",
                                 env={"STUB_CREATE_FAILS": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("box profile create", result.stderr)
        self.assertFalse([call for call in self.calls() if call[0] == "run"])

    def test_the_scripted_layer_runs_cells_and_no_probe_row(self):
        result = self.run_corpus("--layer", "scripted", "--ids", "EV-07", "--fail-on", "none")
        rows = json.loads((self.root / "out" / "results.json").read_text())
        self.assertEqual([r["id"] for r in rows], ["EV-07"])
        self.assertNotIn("warning", result.stderr)
        result = self.run_corpus("--layer", "scripted", "--ids", "probe", "--fail-on", "none")
        self.assertIn("unknown --ids ignored: probe", result.stderr)

    def test_journal_fallback_finds_the_hex_run_by_its_full_profile_record(self):
        result = self.run_corpus(
            "--layer", "scripted", "--ids", "EV-07", "--fail-on", "none",
            env={"STUB_NO_RECORD_PATH": "1", "STUB_OTHER_PROFILE": "1",
                 "STUB_DENY": "fs:write ~/refused"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads((self.root / "out/results.json").read_text())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "RED")
        self.assertTrue(rows[0]["ran"])
        self.assertEqual(rows[0]["denials"], ["fs:write ~/refused"])

    def judge_server(self, verdict):
        """A local stand-in for Bedrock's Converse API: it records each request and answers with
        the verdict tool's input `verdict`."""
        import http.server
        import threading
        seen = []
        reply = json.dumps({"output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "x", "name": "verdict", "input": verdict}}]}},
            "stopReason": "tool_use", "usage": {"inputTokens": 10, "outputTokens": 5}}).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                seen.append({"path": self.path, "auth": self.headers.get("Authorization"),
                             "body": body.decode()})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *a):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}", seen

    # What a stub agent prints on the agent layer: one Bash call and its output, as stream-json.
    # The output carries the token, which the runner must scrub before anything leaves it.
    AGENT_SAYS = "\n".join(json.dumps(e) for e in [
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                                                       "input": {"command": "sqlite3 app.db '.read top.sql'"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1",
                                                  "content": "globex|900.25\numbrella|700.75\nacme|100.5\n"
                                                             "key tok-secret-123"}]}},
        {"type": "result", "subtype": "success", "result": "The query works."}])

    def test_the_judge_grades_a_cell_with_no_check_from_the_record(self):
        url, seen = self.judge_server({"verdict": "PASS", "reason": "the query printed the top three",
                                       "evidence": "globex|900.25\numbrella|700.75\nacme|100.5"})
        result = self.run_corpus("--layer", "agent", "--ids", "EV-07", "--judge", "--fail-on", "none",
                                 env={"AWS_BEARER_TOKEN_BEDROCK": "tok-secret-123", "BOX_JUDGE_URL": url,
                                      "STUB_SAY": self.AGENT_SAYS, "STUB_WRITE": "top.sql=select 1;"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = json.loads((self.root / "out" / "results.json").read_text())[0]
        self.assertEqual((row["grade"], row["grade_by"], row["judge"]), ("PASS", "judge", "PASS"))
        self.assertIn("judge: the query printed the top three", row["grade_reason"])
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["auth"], "Bearer tok-secret-123")
        self.assertIn(rc.judge.DEFAULT_MODEL, seen[0]["path"])
        sent = json.loads(seen[0]["body"])["messages"][0]["content"][0]["text"]
        self.assertIn("Bash: sqlite3 app.db '.read top.sql'", sent)
        self.assertIn("New files (1): top.sql", sent)  # the agent's file, from the snapshots
        self.assertIn("+select 1;", sent)
        self.assertIn("query output matches the expected top three", sent)  # the cell's pass_check
        self.assertNotIn("tok-secret-123", seen[0]["body"])
        evidence = (self.root / "out" / "EV-07.evidence.txt").read_text()
        self.assertIn("globex|900.25", evidence)
        self.assertNotIn("tok-secret-123", evidence)
        saved = json.loads((self.root / "out" / "EV-07.judge.json").read_text())
        self.assertEqual(saved["model"], rc.judge.DEFAULT_MODEL)
        self.assertIn("judge PASS", result.stdout)

    def test_a_judge_pass_that_quotes_only_the_agent_is_ungraded(self):
        url, _ = self.judge_server({"verdict": "PASS", "reason": "it says so",
                                    "evidence": "The query works."})
        self.run_corpus("--layer", "agent", "--ids", "EV-07", "--judge", "--fail-on", "none",
                        env={"AWS_BEARER_TOKEN_BEDROCK": "tok", "BOX_JUDGE_URL": url,
                             "STUB_SAY": self.AGENT_SAYS})
        row = json.loads((self.root / "out" / "results.json").read_text())[0]
        self.assertEqual((row["grade"], row["judge"]), ("UNGRADED", "UNPROVEN"))
        self.assertIn("only the agent's own words", row["grade_reason"])

    def test_an_agent_that_did_not_finish_is_not_judged(self):
        url, seen = self.judge_server({"verdict": "PASS", "reason": "r", "evidence": "globex|900.25"})
        self.run_corpus("--layer", "agent", "--ids", "EV-07", "--judge", "--fail-on", "none",
                        env={"AWS_BEARER_TOKEN_BEDROCK": "tok", "BOX_JUDGE_URL": url, "STUB_EXIT": "1"})
        row = json.loads((self.root / "out" / "results.json").read_text())[0]
        self.assertEqual((row["grade"], row["judge"]), ("NOT-RUN", ""))
        self.assertEqual(seen, [])

    def test_without_judge_no_model_is_asked_and_a_cell_with_no_check_is_ungraded(self):
        url, seen = self.judge_server({"verdict": "PASS", "reason": "r", "evidence": "globex|900.25"})
        self.run_corpus("--layer", "agent", "--ids", "EV-07", "--fail-on", "none",
                        env={"AWS_BEARER_TOKEN_BEDROCK": "tok", "BOX_JUDGE_URL": url,
                             "STUB_SAY": self.AGENT_SAYS})
        row = json.loads((self.root / "out" / "results.json").read_text())[0]
        self.assertEqual((row["grade"], row["grade_by"], row["judge"]), ("UNGRADED", "", ""))
        self.assertEqual(seen, [])
        self.assertFalse((self.root / "out" / "EV-07.evidence.txt").exists())

    def test_judge_is_refused_on_the_scripted_layer(self):
        result = self.run_corpus("--layer", "scripted", "--ids", "EV-07", "--judge")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--judge grades the agent layer", result.stderr)

    def test_a_sandbox_refusal_line_does_not_move_a_scripted_verdict(self):
        # The scripted layer compares with recorded results, so the box's sandbox lines must not
        # turn a recorded GREEN into RED there. (The agent layer's rule is SandboxRefusals.)
        self.run_corpus("--layer", "scripted", "--ids", "EV-07", "--fail-on", "none",
                        env={"STUB_SAY": "strands-shell: curl: Operation not permitted"})
        row = json.loads((self.root / "out" / "results.json").read_text())[0]
        self.assertEqual(row["verdict"], "GREEN")

    def test_a_run_the_runner_stops_differs_and_is_not_run_again(self):
        programs = self.programs({"node": "", "npm": ""})
        cells = {c["id"]: c for c in CELLS}
        # Both are error records; Mismatch covers a red one.
        gives = {"TS-01": {"STUB_SAY": cells["TS-01"]["expect"]["log"].replace("*", "/n"), "STUB_EXIT": "1"},
                 "TS-14": {"STUB_SAY": cells["TS-14"]["expect"]["log"], "STUB_EXIT": "1"}}
        for cid, env in gives.items():
            for hang, limit in (("0", []), ("30", ["--timeout", "3"])):
                with self.subTest(cell=cid, hang=hang):
                    self.home.joinpath("calls.jsonl").unlink(missing_ok=True)
                    result = self.run_corpus("--layer", "scripted", "--ids", cid, "--no-skip", *limit,
                                             path=programs, env=dict(env, STUB_HANG=hang))
                    self.assertEqual([call[0] for call in self.calls()], ["run"])
                    row = json.loads((self.root / "out" / "results.json").read_text())[0]
                    log = (self.root / "out" / f"{cid}.log").read_text()
                    self.assertEqual(rc.mismatch(cells[cid], row["verdict"], row["denials"], log), "")
                    if hang == "0":
                        self.assertEqual(result.returncode, 0, result.stdout)
                    else:
                        self.assertEqual(result.returncode, 1, result.stdout)
                        self.assertIn("DIFFERS: the runner stopped the run at --timeout", result.stdout)
                        self.assertNotIn("draft record", result.stdout)
        self.home.joinpath("calls.jsonl").unlink()
        result = self.run_corpus("--layer", "scripted", "--ids", "TS-06", "--no-skip", path=programs,
                                 env={"STUB_SAY": "npm error code ENOSPC", "STUB_EXIT": "1"})
        self.assertEqual([call[0] for call in self.calls()], ["run", "run"])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("draft record", result.stdout)

    def test_a_cell_runs_under_its_own_profile_and_its_secrets_never_reach_the_log(self):
        programs = self.programs({"gh": ""})
        secrets = {"GH_TOKEN": "ghs_secret123", "GIT_GITHUB": "x-access-token:ghs_secret123"}
        self.run_corpus("--layer", "scripted", "--ids", "EV-01", "--fail-on", "none", path=programs,
                        env=dict(secrets, STUB_SAY="token ghs_secret123 basic x-access-token:ghs_secret123"))
        [run] = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(run[1], "corpus-github")
        log = (self.root / "out" / "EV-01.log").read_text()
        self.assertIn("token *** basic ***", log)
        self.assertNotIn("ghs_secret123", log)
        self.home.joinpath("calls.jsonl").unlink()
        self.run_corpus("--layer", "scripted", "--ids", "EV-04", "--fail-on", "none")
        [run] = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(run[1], rc.CELL_PROFILE)

    def test_a_cell_whose_env_var_is_unset_is_skip_and_starts_no_box(self):
        programs = self.programs({"gh": ""})
        result = self.run_corpus("--layer", "scripted", "--ids", "EV-01", "--no-skip", path=programs,
                                 env={"GH_TOKEN": "ghs_secret123", "GIT_GITHUB": " "})
        self.assertIn("SKIP   no-env:GIT_GITHUB", result.stdout)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(self.calls())

    def test_a_quarantined_cell_is_skip_and_no_skip_lets_it_through(self):
        # The FastAPI cell has a script, so --no-skip would fail it if its note did not quarantine it.
        cell = {c["id"]: c for c in CELLS}["PY-02"]
        self.assertTrue(cell.get("script"))
        self.assertIn("quarantine", cell["note"].lower())
        result = self.run_corpus("--layer", "scripted", "--ids", "PY-02", "--no-skip",
                                 path=self.programs({"uv": ""}))
        self.assertIn("SKIP   quarantined-by-spec", result.stdout)
        self.assertNotIn("DIFFERS", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.calls())

    def test_a_fixture_that_fails_to_build_is_one_error_row(self):
        result = self.run_corpus("--layer", "scripted", "--ids", "RS-01", "--no-skip",
                                 path=self.programs({"git": "exit 1", "cargo": ""}))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        [row] = json.loads((self.root / "out" / "results.json").read_text())
        self.assertEqual(row["verdict"], "ERROR")
        self.assertIn("fixture-build-failed", row["reason"])
        self.assertFalse(self.calls())


# A line from the Wrangler cell's log on a macOS arm64 run, and the edits that turn its permission
# error into another failure.
PERMISSION_ERRORS = {
    "TS-14": ("\x1b[31m\u2718 \x1b[41;31m[\x1b[41;97mERROR\x1b[41;31m]\x1b[0m \x1b[1mFailed to bind to "
              "127.0.0.1:9229: permission denied.\x1b[0m\n",
              [("permission denied", "address already in use")]),
}


class CorpusPacks(unittest.TestCase):
    """The corpus carries a pack for each toolchain box does not ship. A pack in
    resources/packs/ joins `box profile create`'s `--tools` list and the tools its
    `unknown tool` error names, so a toolchain only the corpus needs belongs in
    test-corpus/packs/ and is installed as the operator's own.

    A cell's `needs` says which toolchains the host must have, not which programs the box
    spawns: the pinned-nightly cell names `rustup` and runs only `cargo`, through its proxy."""

    def corpus_packs(self):
        return {p.name for p in rc.PACKS.iterdir() if p.is_dir()} if rc.PACKS.is_dir() else set()

    def test_each_corpus_pack_declares_its_program_and_its_own_name(self):
        for name in sorted(self.corpus_packs()):
            with self.subTest(pack=name):
                with open(rc.PACKS / name / "pack.toml", "rb") as f:
                    table = tomllib.load(f)
                self.assertEqual(table["run"]["command"], [f"${{{{ inputs.{name}.path }}}}"])
                self.assertEqual(table["inputs"][name]["path"]["program"], name)
                self.assertEqual(table["pack"]["name"], name)

    def test_each_corpus_pack_is_named_by_a_committed_profile(self):
        named = set()
        for folder in rc.PROFILES.iterdir():
            if not folder.is_dir():
                continue
            with open(folder / "profile.toml", "rb") as f:
                named |= set(tomllib.load(f).get("packs", []))
        for name in sorted(self.corpus_packs()):
            with self.subTest(pack=name):
                self.assertIn(name, named)

    def test_install_profiles_copies_each_pack_into_the_operator_s_packs_folder(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        original = rc.HOME
        rc.HOME = root
        try:
            rc.install_profiles([], dict(os.environ))
            # The corpus replaces its own copy even after the pack's text changes.
            for name in sorted(self.corpus_packs()):
                (root / ".strands/box" / "packs" / name / "pack.toml").write_text("stale = true\n")
            rc.install_profiles([], dict(os.environ))
        finally:
            rc.HOME = original
        for name in sorted(self.corpus_packs()):
            with self.subTest(pack=name):
                installed = root / ".strands/box" / "packs" / name / "pack.toml"
                self.assertEqual(installed.read_bytes(), (rc.PACKS / name / "pack.toml").read_bytes())

    def test_install_profiles_keeps_an_operator_s_own_pack_of_the_same_name(self):
        name = next(iter(sorted(self.corpus_packs())), None)
        if name is None:
            self.skipTest("the corpus carries no pack")
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        theirs = root / ".strands/box" / "packs" / name
        theirs.mkdir(parents=True)
        (theirs / "pack.toml").write_text('program = "theirs"\n')
        original = rc.HOME
        rc.HOME = root
        try:
            with self.assertRaises(SystemExit) as refused:
                rc.install_profiles([], dict(os.environ))
        finally:
            rc.HOME = original
        self.assertIn(str(theirs), str(refused.exception))
        self.assertEqual((theirs / "pack.toml").read_text(), 'program = "theirs"\n')

    def operator_profile(self, root, name):
        theirs = root / ".strands/box" / "profiles" / name
        theirs.mkdir(parents=True)
        (theirs / "policy.dw").write_text("// my own rules\n")
        return theirs

    def test_install_profiles_keeps_an_operator_s_own_profile_of_a_committed_name(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        theirs = self.operator_profile(root, rc.CELL_PROFILE)
        original = rc.HOME
        rc.HOME = root
        try:
            with self.assertRaises(SystemExit) as refused:
                rc.install_profiles([], dict(os.environ))
        finally:
            rc.HOME = original
        self.assertIn(str(theirs), str(refused.exception))
        self.assertEqual((theirs / "policy.dw").read_text(), "// my own rules\n")

    def test_install_profiles_replaces_its_own_copy_of_a_committed_profile(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        original = rc.HOME
        rc.HOME = root
        try:
            rc.install_profiles([], dict(os.environ))
            mine = root / ".strands/box" / "profiles" / rc.CELL_PROFILE
            self.assertTrue((mine / ".corpus").is_file())
            (mine / "profile.toml").write_text("stale = true\n")
            rc.install_profiles([], dict(os.environ))
        finally:
            rc.HOME = original
        self.assertEqual((mine / "profile.toml").read_bytes(),
                         (rc.PROFILES / rc.CELL_PROFILE / "profile.toml").read_bytes())

    def test_the_agent_layer_keeps_an_operator_s_own_agent_profile(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        theirs = self.operator_profile(root, "claude")
        original = rc.HOME
        rc.HOME = root
        try:
            with mock.patch.object(rc, "create_profile") as create, \
                    self.assertRaises(SystemExit) as refused:
                rc.install_agent_profile("claude", dict(os.environ))
        finally:
            rc.HOME = original
        create.assert_not_called()
        self.assertIn(str(theirs), str(refused.exception))
        self.assertEqual((theirs / "policy.dw").read_text(), "// my own rules\n")

    def test_the_agent_layer_remakes_the_agent_profile_it_made(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        made = mock.Mock(returncode=0, stdout="", stderr="")
        original = rc.HOME
        rc.HOME = root
        try:
            with mock.patch.object(rc, "create_profile", return_value=made) as create:
                rc.install_agent_profile("claude", dict(os.environ))
                rc.install_agent_profile("claude", dict(os.environ))
        finally:
            rc.HOME = original
        self.assertEqual(create.call_count, 2)
        self.assertTrue((root / ".strands/box" / "profiles" / "claude" / ".corpus").is_file())


class Grid(unittest.TestCase):
    def test_a_check_before_a_script_s_last_line_uses_single_brackets(self):
        """The agent is macOS's /bin/bash 3.2, where a false `[[ ]]` does not stop a script under
        `set -e` unless it is the last command. The Next.js cell's `[[ -f web/package.json ]]`
        passed straight through on CI that way and the cell ran 180 s more."""
        for cell in CELLS:
            lines = [l for l in cell.get("script", "").strip().splitlines() if l.strip()]
            for line in lines[:-1]:
                with self.subTest(cell=cell["id"], line=line):
                    self.assertFalse(line.lstrip().startswith("[["), line)

    def test_each_committed_policy_copy_matches_the_project_starter(self):
        starter = (rc.REPO / "resources/policies/scoped/policy.dw").read_text()
        for name in ("corpus", "corpus-github"):
            with self.subTest(profile=name):
                copy = rc.PROFILES / name / "policy.dw"
                self.assertFalse(copy.is_symlink(), "box refuses a linked policy file")
                self.assertEqual(copy.read_text(), starter)
                with open(rc.PROFILES / name / "profile.toml", "rb") as f:
                    self.assertIn("policy.dw", tomllib.load(f).get("policies", []))

    def test_each_cell_profile_is_committed(self):
        committed = {p.name for p in rc.PROFILES.iterdir() if p.is_dir()}
        for cell in CELLS:
            with self.subTest(cell=cell["id"]):
                self.assertIn(cell.get("profile", rc.CELL_PROFILE), committed)

    def test_every_record_is_well_formed(self):
        for cell in CELLS:
            expect = cell.get("expect")
            if expect is None:
                continue
            with self.subTest(cell=cell["id"]):
                self.assertIn("script", cell)
                self.assertTrue(cell.get("note"))
                self.assertIn(expect.get("verdict"), {"red", "error"})
                if expect["verdict"] == "red":
                    self.assertTrue(expect.get("denies"))
                else:
                    self.assertTrue(expect.get("log"))

    def test_each_permission_record_holds_ci_s_lines_and_rejects_a_full_disk(self):
        cells = {c["id"]: c for c in CELLS}
        for cid, (log, edits) in PERMISSION_ERRORS.items():
            with self.subTest(cell=cid):
                self.assertEqual(rc.mismatch(cells[cid], "ERROR", [], log), "")
                for permission, full_disk in edits:
                    log = log.replace(permission, full_disk)
                self.assertIn("does not contain", rc.mismatch(cells[cid], "ERROR", [], log))

    def test_a_lockfile_behind_a_mirror_names_its_host(self):
        cases = {
            "Gemfile.lock": "GEM\n  remote: https://gems.mirror.example/\n",
            "yarn.lock": '"a@npm:1":\n  resolution: "a@https://npm.mirror.example/a.tgz#abc"\n',
            "uv.lock": 'source = { registry = "https://pypi.mirror.example/simple?token=x" }\n',
            "poetry.lock": '[package.source]\nurl = "https://py.mirror.example/simple"\n',
            "pnpm-lock.yaml": 'lodash@4.17.21:\n  resolved "https://npm1.mirror.example/lodash-4.17.21.tgz#6795"\n',
            "composer.lock": json.dumps({"packages": [{"dist": {"url": "https://php.mirror.example/a.zip"}}]}),
            "pixi.lock": '{"url": "https:\\/\\/conda.mirror.example\\/a.conda"}',
            "Cargo.lock": 'source = "registry+https://crates.mirror.example/index"\n',
        }
        with tempfile.TemporaryDirectory() as d:
            for name, text in cases.items():
                with self.subTest(lock=name):
                    (Path(d) / name).write_text(text)
                    hosts = lockfile_hosts(Path(d) / name)
                    self.assertTrue(any(h.endswith("mirror.example") for h in hosts), hosts)

    def test_each_clone_is_pinned(self):
        for cell in CELLS:
            fixture, ref = str(cell.get("fixture", "")), cell.get("fixture_ref")
            if fixture.startswith("clone:") and ref is not None:
                with self.subTest(cell=cell["id"]):
                    self.assertIsInstance(ref, str)
                    self.assertTrue(re.fullmatch(r"[0-9a-f]{40}|v?\d+(\.\d+)+", ref), ref)

    def test_every_fixture_folder_is_used(self):
        used = {str(c.get("fixture")) for c in CELLS} | {rc.FEATURE_FIXTURES.name}  # the features layer's
        for folder in sorted(p.name for p in rc.FIXTURES.iterdir() if p.is_dir()):
            with self.subTest(fixture=folder):
                self.assertIn(folder, used)

    def test_each_fixture_with_dependencies_commits_a_lockfile_that_matches_it(self):
        for folder in sorted(p for p in rc.FIXTURES.iterdir() if p.is_dir()):
            with self.subTest(fixture=folder.name):
                for lock in sorted(LOCKFILES & {p.name for p in folder.iterdir()}):
                    self.assertLessEqual(lockfile_hosts(folder / lock), PUBLIC_REGISTRIES, lock)
                if (folder / "package.json").exists():
                    self.assertTrue(LOCKFILES & {p.name for p in folder.iterdir()}, "no lockfile")
                if (folder / "package-lock.json").exists():
                    manifest = json.loads((folder / "package.json").read_text())
                    lock = json.loads((folder / "package-lock.json").read_text())
                    for key in ("dependencies", "devDependencies"):
                        self.assertEqual(lock["packages"][""].get(key, {}), manifest.get(key, {}))
                    for name, entry in lock["packages"].items():
                        if name and not entry.get("inBundle"):
                            self.assertTrue(entry.get("resolved", "").startswith("https://registry.npmjs.org/"), name)
                            self.assertTrue(entry.get("integrity"), name)
                if (folder / "pyproject.toml").exists():
                    with open(folder / "pyproject.toml", "rb") as f:
                        dependencies = tomllib.load(f).get("project", {}).get("dependencies", [])
                    if dependencies and not (folder / "pixi.toml").exists():
                        self.assertTrue((folder / "uv.lock").exists())
                        with open(folder / "uv.lock", "rb") as f:
                            locked = {(p["name"], p["version"]) for p in tomllib.load(f)["package"]}
                        for spec in dependencies:
                            name, _, version = spec.partition("==")
                            self.assertTrue(version, spec)
                            self.assertIn((re.sub(r"[-_.]+", "-", name).lower(), version), locked)
                if (folder / "Cargo.toml").exists():
                    with open(folder / "Cargo.toml", "rb") as f:
                        dependencies = tomllib.load(f).get("dependencies", {})
                    if dependencies:
                        self.assertTrue((folder / "Cargo.lock").exists())
                        with open(folder / "Cargo.lock", "rb") as f:
                            locked = {(p["name"], p["version"]) for p in tomllib.load(f)["package"]}
                        for name, spec in dependencies.items():
                            version = spec if isinstance(spec, str) else spec["version"]
                            self.assertTrue(version.startswith("="), name)
                            self.assertIn((name, version[1:]), locked)

    def test_the_csv_to_json_fixture_is_the_program_and_the_pins_its_cell_writes(self):
        script = {c["id"]: c for c in CELLS}["RS-02"]["script"]
        fixture = rc.FIXTURES / "csv-to-json-cli"
        written = script.split("write src/main.rs <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0] + "\n"
        self.assertEqual(written, (fixture / "src" / "main.rs").read_text())
        added = dict(re.findall(r"([\w-]+)@=([\d.]+)", " ".join(l for l in script.splitlines() if "cargo add" in l)))
        with open(fixture / "Cargo.toml", "rb") as f:
            dependencies = tomllib.load(f)["dependencies"]
        pinned = {n: (s if isinstance(s, str) else s["version"]).lstrip("=") for n, s in dependencies.items()}
        self.assertEqual(added, pinned)

    def test_each_install_command_in_a_script_names_an_exact_version(self):
        exact = re.compile(r"^(@[\w.-]+/)?[\w.-]+@=?\d+\.\d+\.\d+$")
        for cell in CELLS:
            for command in re.findall(r"bash -c '([^']*)'", cell.get("script", "")):
                for package in installed_packages(command):
                    with self.subTest(cell=cell["id"], package=package):
                        self.assertRegex(package, exact)


VALUE_FLAGS = {"--features", "-F", "--rename", "--registry", "--path", "--git", "--branch", "--tag",
               "--rev", "--package", "-p"}


def installed_packages(command):
    """The packages each install command in a shell command names, as written."""
    for part in re.split(r"&&|;|\|", command):
        words = part.split()
        if words[:2] in (["npm", "install"], ["npm", "i"], ["cargo", "install"], ["cargo", "add"]):
            args = words[2:]
        elif words[:2] == ["npm", "create"]:
            args = words[2:3]
        elif words[:1] == ["npx"] and len(words) > 1 and words[1].startswith("create-"):
            args = words[1:2]
        else:
            continue
        value = False
        for word in args:
            if value:
                value = False
            elif word in VALUE_FLAGS:
                value = True
            elif not word.startswith("-"):
                yield word


class AvailableTools(unittest.TestCase):
    def test_nvm_and_the_android_sdk_are_folders_not_programs(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "nvm.sh").write_text("")
            none = {"NVM_DIR": f"{d}/none", "HOMEBREW_PREFIX": f"{d}/none"}
            self.assertEqual(rc.available_tools(d, {**none, "NVM_DIR": d, "ANDROID_HOME": d}),
                             {"nvm", "android-sdk"})
            self.assertEqual(rc.available_tools(d, none), set())

    def test_a_homebrew_nvm_counts(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "opt" / "nvm").mkdir(parents=True)
            (Path(d) / "opt" / "nvm" / "nvm.sh").write_text("")
            self.assertEqual(rc.available_tools(d, {"NVM_DIR": f"{d}/none", "HOMEBREW_PREFIX": d}), {"nvm"})

    def test_python_venv_follows_the_probe(self):
        with tempfile.TemporaryDirectory() as d:
            none = {"NVM_DIR": f"{d}/none", "HOMEBREW_PREFIX": f"{d}/none"}
            stub = Path(d) / "python3"
            for code, want in ((0, {"python-venv"}), (1, set())):
                stub.write_text(f"#!/bin/sh\nexit {code}\n")
                stub.chmod(0o755)
                self.assertEqual(rc.available_tools(d, none) - {"python3"}, want)


class Grade(unittest.TestCase):
    def test_an_agent_that_did_not_finish_is_not_graded(self):
        g, why = rc.grade(False, "pnpm test", None)
        self.assertEqual(g, rc.GRADE_NOT_RUN)
        self.assertIn("did not finish", why)

    def test_a_cell_with_no_check_is_ungraded(self):
        g, why = rc.grade(True, "", None)
        self.assertEqual(g, rc.GRADE_UNGRADED)
        self.assertIn("no check", why)

    def test_a_finished_agent_and_a_passing_check_is_a_pass(self):
        g, why = rc.grade(True, "pnpm test", 0)
        self.assertEqual(g, rc.GRADE_PASS)
        self.assertEqual(why, "")

    def test_a_finished_agent_and_a_failing_check_is_a_fail(self):
        g, why = rc.grade(True, "pnpm test", 1)
        self.assertEqual(g, rc.GRADE_FAIL)
        self.assertIn("exited 1", why)

    def test_a_check_timeout_is_a_fail(self):
        g, why = rc.grade(True, "pnpm test", 124)
        self.assertEqual(g, rc.GRADE_FAIL)
        self.assertIn("timed out", why)

    def test_a_grader_box_that_did_not_start_is_ungraded(self):
        g, why = rc.grade(True, "pnpm test", rc.GRADER_DID_NOT_RUN)
        self.assertEqual(g, rc.GRADE_UNGRADED)
        self.assertIn("did not start", why)

    def test_a_check_that_ran_and_exited_nonzero_is_a_fail(self):
        # 125/126 from a check that actually ran (sentinel present) is a task FAIL, not UNGRADED.
        for code in (1, 2, 125, 126):
            g, why = rc.grade(True, "pnpm test", code)
            self.assertEqual(g, rc.GRADE_FAIL, code)
            self.assertIn(f"exited {code}", why)

    def test_an_unfinished_agent_is_not_graded_even_with_a_check(self):
        g, _ = rc.grade(False, "pnpm test", 1)
        self.assertEqual(g, rc.GRADE_NOT_RUN)

    def test_the_check_runs_through_bash_c_after_the_sentinel(self):
        # The box's Shell finds pnpm only as a tool, which a cell's script reaches through
        # `bash -c`, so the grader must too. A bare `pnpm test` was `command not found` (127).
        argv = rc.check_argv("cd packages/app && yarn tsc --noEmit")
        self.assertEqual(argv[0], "-c")
        self.assertEqual(argv[1], f"echo {rc.CHECK_SENTINEL}; bash -c 'cd packages/app && yarn tsc --noEmit'")
        # The quoting holds for a check that has single quotes of its own.
        self.assertEqual(shlex.split(rc.check_argv("echo 'a b'")[1].split("; ", 1)[1]),
                         ["bash", "-c", "echo 'a b'"])


class JudgeGrade(unittest.TestCase):
    def test_pass_and_fail_carry_over(self):
        self.assertEqual(rc.judge_grade("PASS", "tests ran"), (rc.GRADE_PASS, "judge: tests ran"))
        self.assertEqual(rc.judge_grade("FAIL", "it gave up"), (rc.GRADE_FAIL, "judge: it gave up"))

    def test_unproven_and_error_are_ungraded(self):
        g, why = rc.judge_grade("UNPROVEN", "only the agent says so")
        self.assertEqual(g, rc.GRADE_UNGRADED)
        self.assertIn("could not confirm", why)
        g, why = rc.judge_grade("ERROR", "HTTP 403")
        self.assertEqual(g, rc.GRADE_UNGRADED)
        self.assertIn("judge error: HTTP 403", why)

    def test_a_tsv_field_holds_no_tab_or_line_break(self):
        self.assertEqual(rc.tsv_field("a\tb\nc\r\nd"), "a b c d")


class SandboxRefusals(unittest.TestCase):
    def test_a_box_authored_eperm_line_counts(self):
        log = ("strands-box: [agent] HOME=/x PATH=/y\n"
               "strands-shell: curl: Operation not permitted\n")
        self.assertEqual(len(rc.sandbox_refusals(log)), 1)

    def test_a_box_config_refusal_counts(self):
        log = 'strands-box: error: `[tool.uvx]` filesystem entry "x" is refused: ...\n'
        self.assertEqual(len(rc.sandbox_refusals(log)), 1)

    def test_a_coded_config_refusal_counts(self):
        log = 'strands-box: error[B0102]: `[tool.uvx]` filesystem entry "x" is refused: ...\n'
        self.assertEqual(len(rc.sandbox_refusals(log)), 1)

    def test_an_alias_or_trampoline_refusal_counts(self):
        for line in ("strands-box-sock-alias: error[H0302]: curl: Operation not permitted",
                     "strands-box-contain-trampoline: error[H0401]: apply sandbox: Operation not permitted"):
            with self.subTest(line=line):
                self.assertEqual(rc.sandbox_refusals(line + "\n"), [line])

    def test_a_coded_startup_note_does_not_count(self):
        log = ("strands-box: note[B0201]: [agent] runs /bin/bash with no policy decision over these paths:\n"
               "strands-box: warning[B0212]: [tool.x] write grant reaches its program\n")
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_a_coded_or_uncoded_startup_error_stops_the_run(self):
        for line, stopped in (("strands-box: error[B0103]: policy load failed: x", True),
                              ("strands-box: error: internal failure", True),
                              ("box: error: no profile named x", True),
                              ("strands-box: note[B0201]: [agent] runs /bin/bash", False),
                              ("npm error: ENOENT", False)):
            with self.subTest(line=line):
                self.assertEqual(rc.startup_error("ok\n" + line + "\n"), line if stopped else "")

    def test_the_error_reason_names_a_coded_line(self):
        log = "npm notice\nstrands-box: error[B0102]: `[tool.python3]` filesystem entry \"/usr\" is refused\n"
        self.assertEqual(rc.first_error(log), 'strands-box: error[B0102]: `[tool.python3]` filesystem entry "/usr" is refused')
        self.assertEqual(rc.first_error("x\nnpm ERR! error: ENOENT\n"), "npm ERR! error: ENOENT")
        self.assertEqual(rc.first_error("all good\n"), "")

    def test_the_agents_own_prose_does_not_count(self):
        # The agent narrating a refusal is not a box-authored line; the verdict must not read it.
        log = ("The box doesn't allow writes to that folder, so the tool failed with EPERM.\n"
               "create-next-app failed: EPERM: operation not permitted, mkdir '/Users/x/Library'\n")
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_an_indented_quote_of_a_box_line_does_not_count(self):
        # An ordinary EACCES the agent quotes in an indented block, such as a missing chmod +x,
        # must not turn a clean run RED.
        log = "Running the build failed:\n    strands-shell: ./build.sh: Permission denied\n"
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_a_box_shell_refusal_in_a_claude_tool_output_counts(self):
        # Under stream-json the box Shell's refusal of a command Claude ran arrives inside the
        # tool_result event, and it is the box's own line, so it makes the verdict RED.
        log = "\n".join([
            json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t1",
                        "name": "Bash", "input": {"command": "npm install"}}]}}),
            json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1",
                        "is_error": True, "content": "added 3 packages\nstrands-shell: npm: Operation not permitted"}]}}),
        ]) + "\n"
        self.assertEqual(rc.sandbox_refusals(log), ["strands-shell: npm: Operation not permitted"])

    def test_claudes_own_words_and_a_subagent_report_do_not_count(self):
        quote = "```\nstrands-shell: npm: Operation not permitted\n```"
        log = "\n".join([
            json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": quote}]}}),
            json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "a1",
                        "name": "Task", "input": {"prompt": "install and report"}}]}}),
            json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "a1",
                        "content": "strands-shell: npm: Operation not permitted"}]}}),
            json.dumps({"type": "result", "result": quote}),
        ]) + "\n"
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_an_indented_box_line_in_a_tool_output_does_not_count(self):
        log = json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1",
              "content": "notes.md:\n    strands-shell: npm: Operation not permitted"}]}}) + "\n"
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_a_file_mode_eacces_in_a_tool_output_does_not_count(self):
        # Running a script before chmod +x is an ordinary error, not a box refusal; a macOS
        # Seatbelt refusal reads `Operation not permitted`.
        log = json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1",
              "is_error": True, "content": "strands-shell: ./build.sh: Permission denied"}]}}) + "\n"
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_normal_box_startup_lines_do_not_count(self):
        log = ("strands-box: [agent] runs /bin/bash with no policy decision over these paths:\n"
               "strands-box: [tool.uvx] broad exec: may run any reachable binary\n"
               "strands-shell: [[: command not found\n")
        self.assertEqual(rc.sandbox_refusals(log), [])

    def test_a_sandbox_refusal_makes_a_clean_run_red(self):
        v, _ = rc.verdict_for(True, [("permit", "a", "b", "c")], [], 0, False, sandbox_denies=1)
        self.assertEqual(v, "RED")

    def test_no_sandbox_refusal_leaves_a_clean_run_green(self):
        v, _ = rc.verdict_for(True, [("permit", "a", "b", "c")], [], 0, False, sandbox_denies=0)
        self.assertEqual(v, "GREEN")


class AgentFinished(unittest.TestCase):
    def test_a_box_run_that_exited_zero_finished(self):
        self.assertTrue(rc.agent_finished({"ran": True, "timed_out": False, "rc": 0}))

    def test_a_nonzero_exit_did_not_finish(self):
        # An expired key makes claude exit non-zero without touching the workspace; not finished.
        self.assertFalse(rc.agent_finished({"ran": True, "timed_out": False, "rc": 1}))

    def test_a_box_that_never_ran_did_not_finish(self):
        self.assertFalse(rc.agent_finished({"ran": False, "timed_out": False, "rc": None}))

    def test_a_timeout_did_not_finish(self):
        self.assertFalse(rc.agent_finished({"ran": True, "timed_out": True, "rc": 0}))


class AgentProfile(unittest.TestCase):
    def test_the_claude_profile_takes_every_pack_of_the_corpus_profile(self):
        with open(rc.PROFILES / rc.CELL_PROFILE / "profile.toml", "rb") as f:
            corpus = tomllib.load(f)["packs"]
        argv = rc.agent_profile_args("claude")
        self.assertEqual(argv[:4], ["box", "profile", "create", "claude"])
        packs = argv[argv.index("--with") + 1].split(",")
        self.assertEqual(packs[:2], ["claude", "bedrock"])
        self.assertEqual(packs[2:], corpus)
        self.assertEqual(argv[argv.index("--policy") + 1], "open")
        self.assertIn("claude.import-mcp=false", argv)

    def test_each_bedrock_agent_profile_signs_with_the_minted_key(self):
        for profile in ("claude", "codex"):
            argv = rc.agent_profile_args(profile)
            self.assertIn("bedrock.sign-in=api-key", argv, profile)
            self.assertEqual(argv[argv.index("bedrock.sign-in=api-key") - 1], "--option", profile)
        self.assertNotIn("bedrock.sign-in=api-key", rc.agent_profile_args("kiro"))
        self.assertEqual(rc.key_sign_in("claude,@box/bedrock"), ["bedrock.sign-in=api-key"])

    def test_the_agent_profiles_match_their_launch_checks(self):
        # The agent layer makes its profile with the same agent and model packs, and the same
        # options, as the launch check that starts that agent.
        checks = {c["id"]: c for c in rc.launch_checks()}
        for profile, (agent, options) in rc.AGENT_PROFILES.items():
            self.assertEqual(checks[profile]["with"], agent, profile)
            self.assertEqual(checks[profile].get("options", []), options, profile)

    def test_an_unknown_agent_profile_is_refused(self):
        with self.assertRaises(ValueError):
            rc.agent_profile_args("bash")


if __name__ == "__main__":
    unittest.main()
