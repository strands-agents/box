#!/usr/bin/env python3
"""Run golden-corpus cells through a box profile and score each from the box's own journal.

Usage:
  run_corpus.py --layer agent  --profile claude [--ids TS-01 EV-07] [--gate launch] [--out DIR]
  run_corpus.py --layer agent  --profile codex  [--ids ...]
  run_corpus.py --layer agent  --profile kiro   [--ids ...]   # Kiro API key in KIRO_API_KEY or ~/.strands/box/kiro.key
  run_corpus.py --layer scripted                [--ids ...] [--section Python]   # bash runs each cell's script, no model
  run_corpus.py --layer launch                  [--ids claude] # start each agent, no model
  run_corpus.py --layer features                [--ids codex-skills] # one check per agent feature

A cell is GREEN only when the box ran, logged no denial,
and the agent exited 0 within the timeout. It is RED, with the list of denials and their
rule names, when the box logged a denial. It is ERROR when the box did not run, when the
agent layer recorded no policy decision, or when the session ended on a timeout or a
non-zero exit, so a run that did not happen never reads as a pass. The scripted layer is
different: the box grants its workspace statically, so a script that stays inside it
records no decision, and a clean scripted run with none is GREEN. A cell is SKIP when this
host cannot run it (a missing toolchain, the lived-in image, an inherited MCP server, an
unset variable that the cell's `env_vars` names, a network clone, or a fixture the runner does
not build), or, on the scripted layer, when it
has no `script` yet, or, on the agent layer, when it names its own `profile`. On the agent layer a missing model credential fails by default;
--allow-no-credentials turns it into a SKIP instead.

The scripted layer runs each cell's `script` under the `corpus` profile, or the one the cell's
`profile` names: bash is the agent, with the tool packs `box profile create` adds, `@box/npx`, and
the corpus's own in `packs/`. A script sends
each command an agent would run as
`bash -c '<command>'`, which reaches Box's Shell through the box's alias, so policy decides it as
it decides a harness's command.

The launch layer runs the checks in test-corpus/launch.toml. Each starts one profile's agent in a
box with no model call. `box run launch-claude -- --version` shows that Claude Code's program runs
in the box, and `-- mcp list` shows that it also loads the settings the profile gives it.

The features layer runs the checks in test-corpus/features.toml. Each gives one agent a host
setup in a temporary HOME, starts the agent in a box, and reads what the agent reports and what
the profile's storage holds. test-corpus/README.md describes the fields and the verdict.

A scripted cell's or launch check's `expect` records the result CI's runner gives today: a red row
lists its denials, and an error records text that one line of its log holds, where `*` matches
anything. Both layers exit non-zero when a row's result differs from its record (a new denial, a
denial that stopped, another verdict), so a pack change that opens a gap fails CI, and one that
closes a gap updates the record. A run that the runner stops at --timeout always differs, because
a record cannot tell a hang from the result it records. An ERROR that differs is run once more
first, since a registry or clone can fail for a moment, but a run that the runner stopped is not.

On the agent layer the process exits non-zero when any cell lands in a `--fail-on` verdict
(default `red,error`), so a CI step fails on a real finding; with that default, SKIP and GREEN
never fail the run. `--fail-on none` turns failing off on both layers.

The agent layer also gives each cell a task grade: did the agent do the task? A cell with a `check`
command is graded by running it in a box over the workspace the agent left. With --judge, a second
model (judge.py) reads the run's tool calls, their real output and the file changes, and decides
whether the cell's `pass_check` held; it grades every cell with no `check`, and on a cell with one
its verdict is recorded beside the check's so the two can be compared.

Needs Python 3.11 or later (for `tomllib`). macOS ships 3.9 at `/usr/bin/python3`; use a
newer one, for example Homebrew's `python3`.

Reads the grid at test-corpus/corpus.toml. Writes results.tsv + results.json + per-cell
logs under --out (default /tmp/corpus-out/<profile>).
"""
import argparse, json, os, re, shlex, shutil, signal, tempfile, subprocess, sys, threading, time, tomllib
from pathlib import Path

import judge
from bench import quarantined

REPO = Path(__file__).resolve().parent.parent
GRID = REPO / "test-corpus" / "corpus.toml"
LAUNCH = REPO / "test-corpus" / "launch.toml"
FEATURES = Path(os.environ.get("BOX_FEATURES_FILE", REPO / "test-corpus" / "features.toml"))
FIXTURES = REPO / "test-corpus" / "fixtures"
FEATURE_FIXTURES = FIXTURES / "features"
PROFILES = REPO / "test-corpus" / "profiles"
PACKS = REPO / "test-corpus" / "packs"
HOME = Path(os.environ["HOME"])
RUNS = HOME / ".strands/box" / "r"
CELL_PROFILE = "corpus"  # the profile the scripted layer runs each cell under
GRADE_PROFILE = "corpus"  # the agent layer runs each cell's `check` under this, in a box, to grade the task
CHECK_SENTINEL = "__GRADE_CHECK_STARTED__"  # printed before a check runs, so a box that never started is told from a check that failed

# Toolchains this host provides. A cell needing anything outside this set is skipped.
# Checked live at startup, not hard-coded, so the same runner is honest on any host.
PROBE_TOOLS = ["node", "npm", "pnpm", "yarn", "git", "sqlite3", "clang", "swift", "ruby", "rails",
               "java", "cargo", "rustup", "corepack", "xcodebuild", "go", "dotnet",
               "php", "composer", "flutter", "psql", "cmake", "uv", "bun", "jupyter",
               "poetry", "pixi", "brew", "gh", "rbenv", "docker"]

CODEX_VENDOR = os.environ.get("BOX_CODEX_BIN",
                "/opt/homebrew/lib/node_modules/@openai/codex/node_modules/"
                "@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin")

# Directories a login shell has that a process started over SSM or launchd does not. Added
# after the caller's PATH so the box still finds Homebrew and cargo tools on a bare host.
# BOX_PATH_FALLBACKS replaces the list (colon-separated, and empty for none).
PATH_FALLBACKS = (os.environ["BOX_PATH_FALLBACKS"].split(os.pathsep) if "BOX_PATH_FALLBACKS" in os.environ
                  else [str(HOME / ".cargo" / "bin"), "/opt/homebrew/bin", "/usr/local/bin"])

# Fixtures make_fixture builds itself. A folder under test-corpus/fixtures/ is copied, and a
# clone with a `fixture_ref` is cloned at that tag or commit SHA. A cell that names any other fixture is
# SKIP, because an empty repository does not test it.
BUILT_FIXTURES = {"empty", "any-repo", "sqlite-app-db", "test-github-repo-ssh", "python-venv-requests"}
# A fixture whose project holds a .venv with requests installed, made before the box starts. A box
# runs a virtual environment only when no process in it can write the folder, so nothing in the box
# can install into one. The venv's Python is one that uv installs: a macOS framework Python's
# bin/python3.12 starts the interpreter inside Python.app, and that interpreter never sees the
# venv. The pins hold requests and what it imports to what PyPI had on the uv cells' date.
PYTHON_VENV = "python-venv-requests"
PYTHON_VENV_PACKAGES = ["requests==2.32.3", "urllib3==2.4.0", "idna==3.10",
                        "charset-normalizer==3.4.2", "certifi==2025.4.26"]
# uv's own default, which corpus-python-venv's profile grants the agent to run.
UV_PYTHONS = HOME / ".local" / "share" / "uv" / "python"
# A fixture whose project is a linked git worktree: the copied folder becomes the main repository
# beside the project, and the project is a worktree of it, so its git common dir lies outside.
LINKED_WORKTREE = "repo-as-linked-worktree"
# Fixtures whose repository has an `origin` remote and an uncommitted change to README.md. The
# bench's job token can only read the remote, so a cell's push stops at GitHub's 403.
FIXTURE_REMOTES = {
    "test-github-repo-https": "https://github.com/strands-agents/box.git",
    "test-github-repo-ssh": "git@github.com:strands-agents/box.git",
}
# A fixture whose project is a pull request's branch: the copied folder is committed on a feature
# branch with an https origin. The origin repository does not exist, so a push always fails.
PR_BRANCH = "pr-one-failing-check"
MISSING_REMOTE = "https://github.com/strands-agents/box-corpus-fixture-missing.git"
# GO-04's service imports a module from a private repository, so go needs a token to download it.
# The copied go.mod gets a require of the module at a tag of that repository.
GO_PRIVATE = "private-go-module-GOPRIVATE"
GO_PRIVATE_MODULE = "github.com/strands-agents/box-corpus-private"
GO_PRIVATE_VERSION = "v0.1.0"

# Run before every script. The helpers use bash builtins only, because the agent's own
# sandbox may start no program but the box's aliases. `write FILE` stands in for a harness's
# file edit; `serve CMD...` starts CMD in the background until the script ends; and
# `until_ok SECONDS CMD...` retries CMD every two seconds until it succeeds.
PRELUDE = r"""set -euo pipefail
write() { : > "$1"; local line; while IFS= read -r line || [[ -n $line ]]; do printf '%s\n' "$line" >> "$1"; done; }
SERVED=""
set -m  # each served command gets its own process group, so the trap stops its children too
serve() { "$@" >> serve.log 2>&1 & SERVED="$SERVED $!"; }
trap 'for p in $SERVED; do kill -TERM -- "-$p" 2> /dev/null || true; done' EXIT
until_ok() { local limit=$1 start=$SECONDS t; shift; until "$@" > /dev/null 2>&1; do (( SECONDS - start < limit )) || return 1; t=$SECONDS; while (( SECONDS - t < 2 )); do :; done; done; }
"""

def which(tool, path=None):
    return shutil.which(tool, path=path) is not None

def available_tools(path=None, env=None):
    """The `needs` tokens this host satisfies. Most are a program on PATH. nvm is a shell
    function, so it is its nvm.sh in NVM_DIR or Homebrew's nvm folder; python-venv is a python3 that can make a venv; android-sdk is
    the SDK folder that ANDROID_HOME names."""
    env = os.environ if env is None else env
    have = {t for t in PROBE_TOOLS if which(t, path)}
    brew = Path(env.get("HOMEBREW_PREFIX") or "/opt/homebrew")
    if any((folder / "nvm.sh").is_file()
           for folder in (Path(env.get("NVM_DIR") or HOME / ".nvm"), brew / "opt" / "nvm")):
        have.add("nvm")
    sdk = env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT")
    if sdk and Path(sdk).is_dir():
        have.add("android-sdk")
    python = shutil.which("python3", path=path)
    try:
        if python and subprocess.run([python, "-c", "import venv, ensurepip"], capture_output=True,
                                     stdin=subprocess.DEVNULL, env=dict(env), timeout=30).returncode == 0:
            have.add("python-venv")
    except subprocess.TimeoutExpired:
        pass
    return have

def parse_journal(path):
    """Return [(verdict, action, rule, resource)] from an OTLP records.jsonl."""
    out = []
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        for rl in doc.get("resourceLogs", []):
            for sl in rl.get("scopeLogs", []):
                if sl.get("scope", {}).get("name") != "strands-box.policy":
                    continue
                for rec in sl.get("logRecords", []):
                    attrs = {a["key"]: a.get("value", {}).get("stringValue")
                             for a in rec.get("attributes", [])}
                    v = attrs.get("strands.box.policy.verdict")
                    if v:
                        out.append((v,
                                    attrs.get("strands.box.policy.action"),
                                    attrs.get("strands.box.policy.rule"),
                                    attrs.get("strands.box.policy.resource")))
    return out

def agent_args(profile, prompt):
    """What the agent layer passes after `--` to run one headless session of `prompt`."""
    if profile == "claude":
        # The pack keeps Claude Code's permission prompts, which a headless run cannot answer.
        # stream-json writes every tool call and its output to the log, which the judge reads as
        # evidence; -p with stream-json needs --verbose.
        return ["--dangerously-skip-permissions", "--output-format", "stream-json", "--verbose",
                "-p", prompt]
    if profile == "codex":
        # A `-c` after `exec` makes Codex send its requests to api.openai.com, so the
        # model override goes before the subcommand.
        return ["-c", "model=openai.gpt-5.4", "exec", "--skip-git-repo-check", prompt]
    if profile == "kiro":
        # The profile's agent.skip-permissions starts `chat --trust-all-tools`, so these go to chat.
        # stream-json writes every tool call and its output to the log, as Claude's does, and
        # implies --no-interactive.
        return ["--trust-workspace", "--output-format", "stream-json", prompt]
    return ["-c", prompt]  # an agent that is bash runs the prompt as a script

def invoke(profile, argv, cwd, env, timeout):
    """Run `box run <profile> -- <argv>` once and return (exit code, output, timed out).

    stdin is /dev/null so the agent never eats our loop.
    """
    cmd = ["box", "run", profile, "--", *argv]
    with open(os.devnull) as devnull:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=devnull, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = proc.communicate(timeout=timeout)
            return proc.returncode, out, False
        except subprocess.TimeoutExpired:
            return proc.returncode, stop(proc) + "\nTIMEOUT\n", True

def stop(proc):
    """SIGTERM box so it stops the box, then SIGKILL. Return the output so far, never block."""
    for send, wait in ((proc.terminate, 15), (proc.kill, 5)):
        send()
        try:
            more, _ = proc.communicate(timeout=wait)
            return more or ""
        except subprocess.TimeoutExpired as e:
            last = e.output.decode(errors="replace") if isinstance(e.output, bytes) else (e.output or "")
    return last or ""

def journal_path(log):
    """The journal path box prints, or None. Each run prints a line such as
    `box: running profile X with box ID b-5b8e3d70c92f14ab (records: /.../records.jsonl)`."""
    m = re.search(r"\(records: (.+?)\)\s*$", log, re.M)
    return Path(m.group(1)) if m else None

def sandbox_refusals(log):
    """Box-authored refusal lines in a run's output, which the policy journal does not record.

    A tool the box starts runs under the OS sandbox (Seatbelt on macOS, a namespace on Linux), and
    an OS-level refusal is NOT a policy decision, so it never reaches the journal that `denies`
    counts. When the box itself prints such a refusal, it is a real block and should make the box
    verdict RED. Only lines that start with the box's own `strands-shell:`/`strands-box:` prefix, at
    the very start of the line, count. This does not catch a refusal a tool prints to its own output
    and the box does not forward (for example create-next-app's `EPERM` on `~/Library/Preferences`);
    that needs the task grade to show.

    Claude Code and Kiro CLI run with `--output-format stream-json`, so the box Shell's refusal of a command
    Claude ran (`strands-shell: npm: Operation not permitted`) reaches the log inside the JSON event
    that carries that tool's output. Each tool output is scanned line by line, as judge.steps splits
    them out. A tool output also carries ordinary file-mode errors (a script run before `chmod +x`
    reads `Permission denied`, EACCES), so there only the EPERM family counts: a macOS Seatbelt
    refusal reads `Operation not permitted`. The workflow runs on macOS only; a Linux leg would need
    this rule checked against how the box refuses there. Claude's own words and a subagent's report
    are not scanned. Lines outside the
    JSON events (the box's own stderr) are scanned as they are, with the full pattern. An agent that
    prints plain text (Codex, or the bash agent) has no such split, so quoting a box line at the
    start of a line in its prose can trip the scan; an indented quote does not count.
    """
    pattern = re.compile(r"^(strands-shell|strands-box):.*"
                         r"(Operation not permitted|EPERM|EACCES|Permission denied|"
                         r"is refused|denied by policy)")
    tool_pattern = re.compile(r"^(strands-shell|strands-box):.*"
                              r"(Operation not permitted|EPERM|is refused|denied by policy)")
    events, lines = judge.parse_stream(log or "")
    found = [line.strip() for line in lines if pattern.match(line)]
    for step in judge.steps(events):
        if step["kind"] == "output":
            found += [line.strip() for line in step["text"].splitlines() if tool_pattern.match(line)]
    return found


def verdict_for(ran, decisions, denies, rc, timed_out, require_decisions=True, sandbox_denies=0):
    """GREEN when the box ran, blocked nothing, and the agent exited 0 in time.
    A scripted run may journal nothing (its workspace is granted statically), so only the agent layer requires decisions.
    `sandbox_denies` is the count of box-authored OS-sandbox refusals that the journal does not
    record (sandbox_refusals); any makes the verdict RED, like a policy deny."""
    end = "timeout" if timed_out else (f"exit {rc}" if rc else "")
    if not ran:
        return "ERROR", "box-did-not-run"
    if require_decisions and not decisions:
        return "ERROR", "no-policy-decisions"
    if denies or sandbox_denies:
        return "RED", end
    if end:
        return "ERROR", end
    return "GREEN", ""


# The task grade, a second axis over the box verdict. verdict_for says whether the BOX refused
# anything; grade says whether the agent DID the customer workload. They are independent: an agent
# often meets a refusal, works around it, and finishes the task, which reads as RED and PASS.
GRADE_PASS, GRADE_FAIL, GRADE_UNGRADED, GRADE_NOT_RUN = "PASS", "FAIL", "UNGRADED", "NOT-RUN"
GRADER_DID_NOT_RUN = -1  # run_check returns this when the box never started the check (sentinel absent)


def agent_finished(row):
    """Whether the agent completed the workload: the box ran it, it did not time out, and the
    agent exited 0. A non-zero exit (a crash, or a model call that failed, as an expired key gives)
    means the task was not done, so the cell is not graded."""
    return bool(row.get("ran")) and not row.get("timed_out") and row.get("rc") == 0


def check_argv(check):
    """What `box run <grade profile> --` gets to run a cell's check.

    The check runs as `bash -c` inside the box's Shell, the way a cell's script runs a toolchain:
    the box's Shell finds only its own commands, the box's aliases, and the programs a tool table
    runs, so a bare `pnpm test` would be `command not found`. The sentinel is echoed before bash
    starts, so a box that never started the check is told from a check that ran and failed.
    """
    return ["-c", f"echo {CHECK_SENTINEL}; bash -c {shlex.quote(check)}"]


def grade(finished, check, check_rc):
    """Grade whether the agent did the task.

    finished: agent_finished(row) -- the box ran the agent, it did not time out, and it exited 0.
    check: the cell's `check` command, or "" when the cell has none.
    check_rc: that command's exit code; GRADER_DID_NOT_RUN when the box never started the check;
    None when no check ran.

    A cell with no check is UNGRADED, never a silent pass. A check that ran and exited non-zero is
    a task FAIL, whatever the code (125/126 included). Only the box failing to start the check,
    which run_check reports as GRADER_DID_NOT_RUN, is UNGRADED.
    """
    if not finished:
        return GRADE_NOT_RUN, "the agent did not finish (no box run, a timeout, or a non-zero exit)"
    if not check:
        return GRADE_UNGRADED, "the cell has no check command"
    if check_rc == 0:
        return GRADE_PASS, ""
    if check_rc == GRADER_DID_NOT_RUN:
        return GRADE_UNGRADED, "the grader box did not start the check"
    if check_rc == 124:
        return GRADE_FAIL, "the check timed out"
    return GRADE_FAIL, f"the check exited {check_rc}"


def judge_grade(verdict, reason):
    """The task grade from the judge (judge.py), for a cell with no `check`.

    PASS and FAIL carry over. UNPROVEN (nothing in the record proves it either way) and ERROR (the
    judge call failed or gave no verdict) are UNGRADED, so a cell the judge could not settle never
    reads as a pass or a fail."""
    if verdict == judge.PASS:
        return GRADE_PASS, f"judge: {reason}"
    if verdict == judge.FAIL:
        return GRADE_FAIL, f"judge: {reason}"
    if verdict == judge.UNPROVEN:
        return GRADE_UNGRADED, f"judge could not confirm it: {reason}"
    return GRADE_UNGRADED, f"judge error: {reason}"

def tsv_field(text):
    """A value for one TSV column: a tab or line break in it would start a new column or row."""
    return re.sub(r"[\t\r\n]+", " ", str(text or ""))

def glob_match(pattern, text):
    """`*` matches any run of characters, and no other character is special."""
    return re.fullmatch(".*".join(map(re.escape, pattern.split("*"))), text, re.S) is not None

def log_holds(pattern, log):
    """Whether one line of the log holds the pattern, where `*` matches any run of characters."""
    return any(glob_match(f"*{pattern}*", line) for line in log.splitlines())

def deny_lines(decisions, cell_dir):
    """The run's denials as sorted "<action> <resource>" lines. The cell's folder becomes
    {workspace} and the home folder ~, so a record names no runner path."""
    roots = sorted({str(cell_dir), str(cell_dir.resolve())}, key=len, reverse=True)
    lines = set()
    for (verdict, action, _rule, resource) in decisions:
        if verdict != "deny":
            continue
        res = str(resource or "")
        for root in roots:
            res = res.replace(root, "{workspace}")
        lines.add(f"{action} {res.replace(str(HOME), '~')}")
    return sorted(lines)

def mismatch(cell, verdict, denials, log, timed_out=False):
    """How a scripted run differs from the cell's `expect`, or "" when it matches. A run that the
    runner stopped at --timeout always differs, so a hang after the recorded result cannot pass."""
    if timed_out:
        return "the runner stopped the run at --timeout"
    expect = cell.get("expect", {})
    want = expect.get("verdict", "green").upper()
    if verdict != want:
        return f"expected {want}, got {verdict}"
    if want == "RED":
        patterns = expect.get("denies", [])
        new = [d for d in denials if not any(glob_match(p, d) for p in patterns)]
        gone = [p for p in patterns if not any(glob_match(p, d) for d in denials)]
        return "; ".join([f"new deny: {d}" for d in new] + [f"deny stopped: {p}" for p in gone])
    if want == "ERROR" and not (expect.get("log") and log_holds(expect["log"], log)):
        return f"the log does not contain {expect.get('log', '')!r}"
    return ""

def suggest_expect(row, log):
    """A first draft of the `expect` line that records a row's result, for a row whose result
    differs. Replace runner paths with `*` before it goes in the grid."""
    if row["verdict"] == "GREEN":
        return "remove the expect line"
    if row["verdict"] == "RED":
        return f'expect = {{ verdict = "red", denies = {json.dumps(row["denials"])} }}'
    if row["verdict"] == "ERROR":
        lines = [l.strip() for l in log.splitlines() if l.strip()]
        named = [l for l in lines if re.search(r"error|denied|timeout|not permitted", l, re.I)]
        last = (named or lines or [""])[-1]
        return f'expect = {{ verdict = "error", log = {json.dumps(last[:120])} }}'
    return ""

def launch_checks():
    """The launch checks in launch.toml."""
    with open(LAUNCH, "rb") as f:
        return tomllib.load(f)["launch"]

def create_profile(argv, env):
    """Run `box profile create` from an empty folder. A box built from source reads its packs
    from this checkout, and a profile made with the checkout as its workspace cannot copy a
    pack's own file."""
    with tempfile.TemporaryDirectory(prefix="box-create-") as cwd:
        return subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, env=env)

def install_profiles(checks, env):
    """Copy each committed pack into ~/.strands/box/packs/ and each committed profile into
    ~/.strands/box/profiles/, and make each launch check's profile with `box profile create`, as an
    operator would who takes the default policy, `@box/open`. Replaces packs and profiles of the
    same names.

    A pack here is the operator's own, not one box ships, so `box profile create` never adds
    it to a profile of its own accord. A cell that needs one names it in its profile. Each copy
    carries a `.corpus` marker, and a folder without one stops the run rather than being
    replaced, because `~/.strands/box/packs/` is the operator's and `box` itself never writes there."""
    operator = HOME / ".strands/box" / "packs"
    operator.mkdir(parents=True, exist_ok=True)
    for folder in sorted(p for p in PACKS.iterdir() if p.is_dir()) if PACKS.is_dir() else []:
        target = operator / folder.name
        if target.exists() and not (target / ".corpus").is_file():
            sys.exit(f"{target} is not the corpus pack of that name; move it aside to run the "
                     f"corpus, which would otherwise replace it")
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(folder, target)
        (target / ".corpus").write_text("Installed by test-corpus/run_corpus.py.\n")
    target = HOME / ".strands/box" / "profiles"
    target.mkdir(parents=True, exist_ok=True)
    for folder in sorted(p for p in PROFILES.iterdir() if p.is_dir()):
        shutil.rmtree(target / folder.name, ignore_errors=True)
        shutil.copytree(folder, target / folder.name)
    made = set()
    for check in checks:
        if check.get("with") and check["profile"] not in made:
            made.add(check["profile"])
            options = [arg for option in check.get("options", []) + key_sign_in(check["with"])
                       for arg in ("--option", option)]
            r = create_profile(["box", "profile", "create", check["profile"], "--with",
                                check["with"], "--policy", "open", *options, "--force"], env)
            if r.returncode:
                sys.exit(f"box profile create {check['profile']} failed:\n{r.stdout}{r.stderr}")

def key_sign_in(packs):
    """The option that makes a Bedrock profile sign in with the key that CI mints, because the
    job's environment holds no AWS credentials."""
    names = {name.removeprefix("@box/") for name in packs.split(",")}
    return ["bedrock.sign-in=api-key"] if {"bedrock", "bedrock-mantle"} & names else []

# The agent layer's profiles: the agent pack and its model pack, as the launch checks name them in
# test-corpus/launch.toml, plus every pack of the corpus profile. So an agent cell gets the same
# toolchains as the scripted layer, and the two layers differ only in who does the work.
AGENT_PROFILES = {
    "claude": ("claude,bedrock", ["claude.import-mcp=false"]),
    "codex": ("codex,bedrock-mantle", ["codex.import-mcp=false"]),
    "kiro": ("kiro", ["kiro.sign-in=api-key", "agent.skip-permissions=true"]),
}

# Kiro CLI calls Kiro's service, not Bedrock, so its model credential is a Kiro API key.
KIRO_KEY_FILE = Path(os.environ.get("BOX_KIRO_KEY_FILE", HOME / ".strands/box" / "kiro.key"))

def kiro_key():
    """The Kiro API key from KIRO_API_KEY, or from the file in BOX_KIRO_KEY_FILE, or ''."""
    key = os.environ.get("KIRO_API_KEY", "").strip()
    if not key and KIRO_KEY_FILE.exists():
        key = KIRO_KEY_FILE.read_text().strip()
    return key

def agent_profile_args(profile):
    """The `box profile create` argv that makes the agent layer's profile `profile`."""
    if profile not in AGENT_PROFILES:
        raise ValueError(f"no agent profile named {profile!r}; known: {', '.join(sorted(AGENT_PROFILES))}")
    agent, options = AGENT_PROFILES[profile]
    with open(PROFILES / CELL_PROFILE / "profile.toml", "rb") as f:
        packs = tomllib.load(f)["packs"]
    return (["box", "profile", "create", profile, "--with", ",".join([agent, *packs]),
             "--policy", "open"]
            + [arg for option in options + key_sign_in(agent) for arg in ("--option", option)]
            + ["--force"])

def install_agent_profile(profile, env):
    """Make the agent layer's profile. Call it after install_profiles, which puts the corpus's own
    packs in ~/.strands/box/packs/ where `box profile create` finds them."""
    try:
        argv = agent_profile_args(profile)
    except ValueError as e:
        sys.exit(str(e))
    r = create_profile(argv, env)
    if r.returncode:
        sys.exit(f"box profile create {profile} failed:\n{r.stdout}{r.stderr}")

def fixture_built(cell):
    """Whether make_fixture can build the cell's project."""
    fixture = str(cell.get("fixture", ""))
    if fixture.startswith("clone:"):
        return bool(cell.get("fixture_ref"))
    return fixture in BUILT_FIXTURES or (FIXTURES / fixture).is_dir()

def clone(fixture, ref, d, genv):
    """Clone `clone:<owner>/<repo>[#label]` at ref, a tag or a full commit SHA, into d, which must
    not exist. The label names the part of the repository the cell uses, and the clone ignores it."""
    if d.exists():
        return f"fixture-build-failed:{d} is left from an earlier run"
    url = f"https://github.com/{fixture[len('clone:'):].split('#')[0]}.git"
    ref = str(ref)
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        steps = [["git", "init", "-q", str(d)],
                 ["git", "-C", str(d), "remote", "add", "origin", url],
                 ["git", "-C", str(d), "fetch", "-q", "--depth", "1", "origin", ref],
                 ["git", "-C", str(d), "checkout", "-q", "FETCH_HEAD"]]
    else:
        steps = [["git", "clone", "-q", "--depth", "1", "--branch", ref, url, str(d)]]
    quiet = dict(genv, GIT_TERMINAL_PROMPT="0")
    for step in steps:
        try:
            r = subprocess.run(step, capture_output=True, text=True, env=quiet, timeout=600)
        except subprocess.TimeoutExpired:
            return "fixture-build-failed:the clone ran past 600 seconds"
        if r.returncode:
            return f"fixture-build-failed:{r.stderr.strip()[:80]}"
    return None

def make_fixture(cell, d, env):
    """Build the cell's project from scratch. Return None, or a skip/error reason."""
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)  # a re-run must not inherit the last agent's edits
    fixture = str(cell["fixture"])
    # Isolate from the caller's git config so gpgsign or a hook cannot break git.
    genv = dict(env, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
    if fixture.startswith("clone:"):
        return clone(fixture, cell["fixture_ref"], d, genv)
    repo = d.with_name(f"{d.name}.main") if fixture == LINKED_WORKTREE else d
    if repo != d:
        shutil.rmtree(repo, ignore_errors=True)
    if (FIXTURES / fixture).is_dir():
        shutil.copytree(FIXTURES / fixture, repo)
    else:
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "README.md").write_text(f"fixture for {cell['id']}\n")
    if cell["fixture"] == "sqlite-app-db":
        sqlite3 = shutil.which("sqlite3", path=env["PATH"])
        if not sqlite3:
            return "fixture-build-failed:sqlite3 not found"
        r = subprocess.run([sqlite3, str(d / "app.db"),
                            "create table customers(name text, revenue real);"
                            "insert into customers values('acme',100.5),('globex',900.25),"
                            "('initech',50.0),('umbrella',700.75);"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return f"fixture-build-failed:{r.stderr.strip()[:80]}"
    if fixture == GO_PRIVATE:
        with open(d / "go.mod", "a") as gomod:
            gomod.write(f"\nrequire {GO_PRIVATE_MODULE} {GO_PRIVATE_VERSION}\n")
    quiet = dict(check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=genv)
    subprocess.run(["git", "init", "-q", str(repo)], **quiet)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], **quiet)
    subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false",
                    "-c", "user.email=c@example.invalid", "-c", "user.name=Corpus",
                    "commit", "-qm", "fixture"], **quiet)
    if fixture in FIXTURE_REMOTES:
        r = subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", FIXTURE_REMOTES[fixture]],
                           capture_output=True, text=True, env=genv)
        if r.returncode != 0:
            return f"fixture-build-failed:{r.stderr.strip()[:80]}"
        with open(repo / "README.md", "a") as readme:
            readme.write("\nRun `greet` to print a greeting.\n")
    if fixture == PR_BRANCH:
        for step in (["remote", "add", "origin", MISSING_REMOTE], ["checkout", "-q", "-b", "fix-add"]):
            r = subprocess.run(["git", "-C", str(d), *step], capture_output=True, text=True, env=genv)
            if r.returncode != 0:
                return f"fixture-build-failed:{r.stderr.strip()[:80]}"
    if repo != d:
        r = subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", "-b", "work", str(d)],
                           capture_output=True, text=True, env=genv)
        if r.returncode != 0:
            return f"fixture-build-failed:{r.stderr.strip()[:80]}"
    if fixture == PYTHON_VENV:
        # After the commit, so the environment stays out of the fixture's history.
        return make_venv(d, env)
    return None

def make_venv(d, env):
    """Make d/.venv with a Python 3.12 that uv installs in UV_PYTHONS, and install
    PYTHON_VENV_PACKAGES into it. Return None, or a fixture-build-failed reason."""
    uv = shutil.which("uv", path=env["PATH"])
    if not uv:
        return "fixture-build-failed:no uv on PATH"
    venv = d / ".venv"
    env = dict(env, UV_PYTHON_INSTALL_DIR=str(UV_PYTHONS))
    # Copies, not links to uv's cache: a file with a link outside the venv could be changed there.
    steps = [[uv, "venv", "--quiet", "--python", "3.12", "--python-preference", "only-managed",
              str(venv)],
             [uv, "pip", "install", "--quiet", "--python", str(venv / "bin" / "python"),
              "--link-mode", "copy", *PYTHON_VENV_PACKAGES]]
    for step in steps:
        try:
            r = subprocess.run(step, capture_output=True, text=True, env=env,
                               stdin=subprocess.DEVNULL, timeout=600)
        except subprocess.TimeoutExpired:
            return "fixture-build-failed:making the venv ran past 600 seconds"
        if r.returncode:
            return f"fixture-build-failed:{(r.stderr or r.stdout).strip()[-80:]}"
    return None

def scrubber(secrets):
    """A function that replaces each secret, and the password of a `user:password` secret, with
    ***, so no uploaded log holds a token."""
    parts = {p for s in secrets if s for p in (s, s.partition(":")[2]) if p.strip()}
    ordered = sorted(parts, key=len, reverse=True)
    def scrub(text):
        for part in ordered:
            text = text.replace(part, "***")
        return text
    return scrub

# A cell's own profile, as the agent layer's profile for one agent runs it. The cell's routes hold a
# read-only token, so an agent there can read and write nothing (test-corpus/README.md).
AGENT_CELL_PROFILES = {("kiro", "corpus-github"): "kiro-github"}

def agent_cell_profile(agent, cell):
    """The profile the agent layer runs `cell` under for `agent`, or None when it cannot."""
    if not cell.get("profile"):
        return agent
    return AGENT_CELL_PROFILES.get((agent, cell["profile"]))

def skip_reason(cell, tools, have_token, layer, present=frozenset(), agent=None):
    """Every reason this host cannot run the cell, comma-joined, or None. `present` names the
    variables in the cells' `env_vars` that are set, and holds no value."""
    reasons = []
    missing = [t for t in cell["needs"] if t not in tools]
    if missing:
        reasons.append(f"no-toolchain:{'+'.join(missing)}")
    if cell["machine"] == "lived-in":
        reasons.append("needs-lived-in-image")
    note = cell.get("note", "").lower()
    if layer == "agent" and "mcp" in note and "not runnable" in note:
        reasons.append("mcp-not-in-box")
    if quarantined(cell):
        reasons.append("quarantined-by-spec")
    unset = [name for name in cell.get("env_vars", []) if name not in present]
    if unset:
        reasons.append(f"no-env:{'+'.join(unset)}")
    fixture = str(cell.get("fixture", ""))
    if fixture.startswith("clone:") and not cell.get("fixture_ref"):
        reasons.append(f"needs-network-clone:{fixture}")
    elif not fixture_built(cell):
        reasons.append(f"fixture-not-built:{fixture}")
    if layer == "agent" and cell.get("profile") and not agent_cell_profile(agent, cell):
        reasons.append("scripted-only-profile")  # an agent profile could write where the cell's never does
    if layer == "agent" and not have_token:
        reasons.append("no-credentials")  # only reached with --allow-no-credentials
    if layer == "scripted" and not cell.get("script"):
        reasons.append("no-scripted-commands")
    return ",".join(reasons) or None

def shard_cells(cells, k, n):
    """Shard K of N. The shards split the cells that run. Shard 1 also lists the ones that never
    do: a cell with no script, and a quarantined one, which bench.py's plan gives no shard."""
    runnable = [c for c in cells if c.get("script") and not quarantined(c)]
    listed = {c["id"] for c in runnable}
    return runnable[k - 1::n] + ([c for c in cells if c["id"] not in listed] if k == 1 else [])

# The features layer. Each check in features.toml is one row of the feature checklist for one agent.
FEATURE_PROFILE = "f"  # each check has its own HOME, so every check can use one profile name
# Where each check's HOME is made. The box's socket lies under HOME, and a socket path holds about
# 100 bytes, so the folder is short. It is not in /tmp: the box holds a
# credential under HOME, and refuses to start when a grant covers that folder, as a grant of /tmp does.
FEATURE_HOMES = Path(os.environ.get("BOX_FEATURES_HOMES", HOME / ".box-features"))
FEATURE_GRACE = 10  # seconds an agent gets to exit after the runner closes its stdin
SYSTEM_VARIABLE = "BOX_FEATURES_SYSTEM"  # "1" lets the runner write a check's system file with sudo

def feature_checks():
    """The checks in features.toml."""
    with open(FEATURES, "rb") as f:
        return tomllib.load(f)["feature"]

def has_check(check):
    """Whether the entry states something to test."""
    return any(check.get(k) for k in ("holds", "lacks", "storage_holds", "storage_lacks",
                                      "workspace_holds"))

def feature_kind(check):
    """What decides the check: no-check, model, system, agent-report, or storage."""
    if not has_check(check):
        return "no-check"
    if check.get("model"):
        return "model"
    if check.get("system"):
        return "system"
    return "agent-report" if check.get("holds") or check.get("lacks") else "storage"

# An organization's settings for each agent. They are system paths, so the temporary HOME does not
# hide them, and an agent that reads one gives another result.
MANAGED_SETTINGS = {
    "claude": ["/Library/Application Support/ClaudeCode", "/etc/claude-code",
               "/Library/Managed Preferences/com.anthropic.claudecode.plist"],
    "codex": ["/etc/codex/requirements.toml", "/etc/codex/managed_config.toml"],
}

def feature_model_key(check, token, kiro):
    """The model credential of the check's agent: a Kiro API key for Kiro CLI, else the Bedrock key."""
    return kiro if check["harness"] == "kiro" else token

def feature_skip(check, path, system, have_token):
    """Every reason this host cannot run the check, comma-joined, or None."""
    reasons = []
    if not has_check(check):
        reasons.append("no-check")
    else:
        found = [p for p in MANAGED_SETTINGS.get(check["harness"], []) if os.path.lexists(p)]
        if found:
            reasons.append(f"host-has-managed-settings:{found[0]}")
    missing = [t for t in check.get("needs", []) if not which(t, path)]
    if missing:
        reasons.append(f"no-program:{','.join(missing)}")
    if check.get("system") and not system:
        reasons.append("needs-system-files")
    if check.get("model") and not have_token:
        reasons.append("no-credentials")
    return ",".join(reasons) or None

def fill(text, home, workspace):
    """`text` with {home}, {workspace}, and {workspace.dashed} replaced. The dashed form is the
    name Claude Code gives a project's folder: one `-` for each UTF-16 unit that is not an ASCII
    letter or digit."""
    dashed = "".join(c if c.isascii() and c.isalnum() else "-" * (len(c.encode("utf-16-le")) // 2)
                     for c in str(workspace))
    return (text.replace("{workspace.dashed}", dashed).replace("{workspace}", str(workspace))
            .replace("{home}", str(home)))

def copy_host(fixture, home, workspace):
    """Copy the host fixture into `home`. A path and a text file can hold fill's placeholders."""
    for source in sorted(fixture.rglob("*")):
        target = home / fill(str(source.relative_to(fixture)), home, workspace)
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_text(fill(source.read_text(), home, workspace))
        except UnicodeDecodeError:
            shutil.copyfile(source, target)
        shutil.copymode(source, target)

def run_with_stdin(cmd, cwd, env, lines, until, timeout):
    """Run cmd and return (exit code, output, timed out).

    The runner writes `lines` to stdin and keeps it open. It closes stdin when an output line
    holds `until`, or when the agent exits. Then the agent has FEATURE_GRACE seconds to exit
    before the runner stops it, which is not a timeout: an agent that printed its report can
    wait on a model request that never succeeds. With no `until`, stdin closes after the lines.
    With no lines, stdin is /dev/null from the start, because an agent such as Claude Code reads
    a piped stdin to its end before it does anything.
    """
    output, seen = [], threading.Event()
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, text=True,
                            stdin=subprocess.PIPE if lines else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def read():
        for line in proc.stdout:
            output.append(line)
            if until and until in line:
                seen.set()
    reader = threading.Thread(target=read, daemon=True)
    reader.start()

    def close_stdin():
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
    try:
        if lines:
            proc.stdin.write("".join(line + "\n" for line in lines))
            proc.stdin.flush()
    except OSError:
        pass  # the agent exited before it read its input
    deadline = time.time() + timeout
    timed_out = False
    if until:
        while not seen.is_set() and proc.poll() is None and time.time() < deadline:
            seen.wait(0.05)
        timed_out = not seen.is_set() and proc.poll() is None
        close_stdin()
        limit = 0 if timed_out else min(FEATURE_GRACE, max(deadline - time.time(), 0))
    else:
        close_stdin()
        limit = timeout
    try:
        proc.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        timed_out = timed_out or not until
        for send, wait in ((proc.terminate, 15), (proc.kill, 5)):
            send()
            try:
                proc.wait(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                pass
    reader.join(timeout=5)
    return proc.returncode, "".join(output) + ("\nTIMEOUT\n" if timed_out else ""), timed_out

def patterns_of(table):
    """A storage table as (path, pattern) pairs. A value is one pattern or a list of them."""
    return [(path, pattern) for path, value in (table or {}).items()
            for pattern in ([value] if isinstance(value, str) else value)]

def file_text(root, path):
    """The text of the regular file `path` under `root`, or None when there is none."""
    target = root / path
    return target.read_text(errors="replace") if target.is_file() else None

def file_texts(root, path):
    """The texts of the regular files under `root` that `path` names. A `*` in `path` matches
    any run of characters in one part of the path."""
    if "*" not in path:
        text = file_text(root, path)
        return [] if text is None else [text]
    return [p.read_text(errors="replace") for p in sorted(root.glob(path)) if p.is_file()]

def feature_failure(check, log, storage, workspace, home):
    """The first pattern of the check that fails, as the reason for a RED, or "".

    An output pattern is matched against one output line. A file pattern is matched against the
    whole file. An empty pattern in `storage_lacks` means that the path must not exist. Any other
    pattern there needs its file, so a box that copied nothing does not pass. A `*` in a
    `storage_holds` or `workspace_holds` path names many files, and one of them must hold the
    pattern."""
    for pattern in check.get("holds", []):
        if not log_holds(fill(pattern, home, workspace), log):
            return f"the output does not hold {pattern!r}"
    for pattern in check.get("lacks", []):
        if log_holds(fill(pattern, home, workspace), log):
            return f"the output holds {pattern!r}"
    for name, root in (("storage", storage), ("workspace", workspace)):
        for path, pattern in patterns_of(check.get(f"{name}_holds")):
            texts = file_texts(root, fill(path, home, workspace))
            if not texts:
                return f"{name} has no file {path}"
            if not any(glob_match(f"*{fill(pattern, home, workspace)}*", text) for text in texts):
                return f"{name} file {path} does not hold {pattern!r}"
    for path, pattern in patterns_of(check.get("storage_lacks")):
        target = storage / fill(path, home, workspace)
        if not pattern:
            if target.exists() or target.is_symlink():
                return f"storage has {path}"
        else:
            text = file_text(storage, fill(path, home, workspace))
            if text is None:  # a file that was never copied would pass every `lacks`
                return f"storage has no file {path}"
            if glob_match(f"*{fill(pattern, home, workspace)}*", text):
                return f"storage file {path} holds {pattern!r}"
    return ""

def feature_verdict(ran, timed_out, failure):
    """GREEN when the box ran and every pattern held. RED when the box ran and a pattern failed.
    ERROR when the box did not run or the runner stopped it at --timeout. The agent's exit code
    and the box's denials do not decide."""
    if not ran:
        return "ERROR", "box-did-not-run"
    if timed_out:
        return "ERROR", "timeout"
    return ("RED", failure) if failure else ("GREEN", "")

def feature_mismatch(check, verdict, log, reason=""):
    """How a check's result differs from its `expect`, or "" when it matches. A red record names
    the reason, where `*` matches anything, so another failure does not pass as the recorded one."""
    expect = check.get("expect", {})
    want = expect.get("verdict", "green").upper()
    if verdict != want:
        return f"expected {want}, got {verdict}"
    if want == "ERROR" and not (expect.get("log") and log_holds(expect["log"], log)):
        return f"the log does not contain {expect.get('log', '')!r}"
    if want == "RED" and not (expect.get("reason") and glob_match(f"*{expect['reason']}*", reason)):
        return f"expected the reason {expect.get('reason', '')!r}, got {reason!r}"
    return ""

def system_path(check):
    """The path of the check's system file on this OS."""
    return Path(check["system_file"]["macos" if sys.platform == "darwin" else "linux"])

def write_system_file(path, content, env):
    """Write `content` to the system path with sudo. Return (what the runner made, None), or
    (None, the reason it wrote nothing). The runner never replaces a file that is there."""
    if path.exists() or path.is_symlink():
        return None, f"system-file-exists:{path}"
    made = [path]
    folder = path.parent
    while not folder.exists():
        made.append(folder)
        folder = folder.parent
    steps = [(["sudo", "-n", "mkdir", "-p", str(path.parent)], None),
             (["sudo", "-n", "tee", str(path)], content),
             (["sudo", "-n", "chmod", "644", str(path)], None)]
    for step, text in steps:
        r = subprocess.run(step, input=text, stdin=None if text is not None else subprocess.DEVNULL,
                           capture_output=True, text=True, env=env)
        if r.returncode:
            remove_system_file(made, env)
            return None, f"system-file-not-written:{r.stderr.strip()[:80]}"
    return made, None

def remove_system_file(made, env):
    """Remove the file and each folder that write_system_file made, and nothing else. Return the
    paths that are still there."""
    for path in made:
        step = ["rmdir", str(path)] if path.is_dir() and not path.is_symlink() else ["rm", "-f", str(path)]
        subprocess.run(["sudo", "-n", *step], stdin=subprocess.DEVNULL, capture_output=True, env=env)
    return [path for path in made if path.exists() or path.is_symlink()]

def run_feature(check, out, env, token, kiro, timeout, scrub):
    """Run one check in its own HOME and workspace. Return (row fields, log)."""
    base = (out / check["id"]).resolve()
    shutil.rmtree(base, ignore_errors=True)
    workspace = base / "ws"
    workspace.mkdir(parents=True)
    FEATURE_HOMES.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix="bf-", dir=FEATURE_HOMES)).resolve()
    try:
        return feature_run(check, home, workspace, env, token, kiro, timeout, scrub)
    finally:
        if os.environ.get("BOX_FEATURES_KEEP_HOMES") != "1":
            shutil.rmtree(home, ignore_errors=True)
            try:
                FEATURE_HOMES.rmdir()  # only when no other check's HOME is left in it
            except OSError:
                pass

def feature_run(check, home, workspace, env, token, kiro, timeout, scrub):
    """Run one check with `home` as its HOME. Return (row fields, log)."""
    (workspace / "README.md").write_text(f"workspace for {check['id']}\n")
    subprocess.run(["git", "init", "-q", str(workspace)], check=False, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env=dict(env, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1"))
    if check.get("host"):
        copy_host(FEATURE_FIXTURES / check["host"], home, workspace)
    # The Box CLI finds the agent's host setup, and keeps its own files, under HOME. No variable
    # may point it at the operator's own folders.
    box_env = {k: v for k, v in env.items() if k not in ("BOX_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME")}
    box_env["HOME"] = str(home)
    box_env["AWS_BEARER_TOKEN_BEDROCK"] = token if check.get("model") else "placeholder-no-model-call"
    if check.get("model") and check["harness"] == "kiro":
        box_env["KIRO_API_KEY"] = kiro
    # The kiro pack's default runtime folder is under HOME, and this HOME is new. The runtime is
    # the one the operator filled on the host (resources/packs/kiro/README.md).
    box_env.setdefault("KIRO_RUNTIME_DIR", str(HOME / ".kiro-runtime"))
    fields = dict(denials=[], seconds=0, rc=None, timed_out=False)
    made = None
    if check.get("system"):
        # Before the profile is made, so the profile is made on a host that has the file.
        made, problem = write_system_file(system_path(check), check["system_file"]["content"], env)
        if problem:
            return dict(fields, verdict="ERROR", reason=problem), problem + "\n"
    options = [arg for option in check.get("options", []) + key_sign_in(check["with"])
               for arg in ("--option", option)]
    cmd = ["box", "run", FEATURE_PROFILE, "--", *[fill(a, home, workspace) for a in check["args"]]]
    t0 = time.time()
    try:
        r = create_profile(["box", "profile", "create", FEATURE_PROFILE, "--with", check["with"],
                            "--policy", "open", *options, "--force"], box_env)
        if r.returncode:
            log = scrub(r.stdout + r.stderr)
            last = (log.strip().splitlines() or [""])[-1]
            return dict(fields, verdict="ERROR", reason=f"profile-create-failed: {last[:160]}"), log
        if check.get("agent_env"):
            add_agent_env(home / ".strands" / "box" / "profiles" / FEATURE_PROFILE / "profile.toml",
                          {k: fill(v, home, workspace) for k, v in check["agent_env"].items()})
        rc, log, timed_out = run_with_stdin(cmd, workspace, box_env, check.get("stdin", []),
                                            check.get("until"), timeout)
        for path, text in ({} if timed_out else check.get("host_edit", {})).items():
            # The host's file changes, and a second run shows what the box does with the change.
            (home / path).write_text(fill(text, home, workspace))
            rc, more, timed_out = run_with_stdin(cmd, workspace, box_env, check.get("stdin", []),
                                                 check.get("until"), timeout)
            log += more
    finally:
        left = remove_system_file(made, env) if made else []
    if left:
        problem = f"system-file-not-removed:{left[0]}"
        return dict(fields, verdict="ERROR", reason=problem), scrub(log) + problem + "\n"
    log = scrub(log)
    journal = journal_path(log)
    decisions = parse_journal(journal) if journal else []
    # The box copies the host's files and writes its journal before it starts the agent. So a box
    # that then fails to start the agent has a journal and a filled storage, and is not a run.
    stopped = next((l.strip() for l in log.splitlines() if re.match(r"(strands-)?box[\w-]*: error:", l)), "")
    ran = bool(journal) and journal.exists() and not stopped
    storage = home / ".strands" / "box" / "storage" / FEATURE_PROFILE / "default" / "agent"
    failure = feature_failure(check, log, storage, workspace, home) if ran and not timed_out else ""
    verdict, reason = feature_verdict(ran, timed_out, failure)
    if verdict == "ERROR" and not ran:
        first_err = stopped or next((l for l in log.splitlines() if "error:" in l.lower()), "")
        reason = f"{reason}: {first_err.strip()[:160]}" if first_err else reason
    denials = [line.replace(str(home), "~") for line in deny_lines(decisions, workspace)]
    return dict(verdict=verdict, reason=reason, denials=denials, seconds=round(time.time() - t0),
                rc=rc, timed_out=timed_out), log

def add_agent_env(profile, variables):
    """Add `variables` to the profile's `[agent.env]`. `box profile create` writes no `[agent]`."""
    with open(profile, "a") as f:
        f.write("\n[agent.env]\n" + "".join(f"{json.dumps(k)} = {json.dumps(v)}\n" for k, v in variables.items()))

def run_features(args, env, out, token, kiro, fail_set):
    """Run the features layer and write features.json and features.tsv. Return the exit code."""
    checks = feature_checks()
    if args.ids:
        unknown = sorted(set(args.ids) - {c["id"] for c in checks})
        if unknown:
            print(f"warning: unknown --ids ignored: {' '.join(unknown)}", file=sys.stderr)
        checks = [c for c in checks if c["id"] in args.ids]
    system = os.environ.get(SYSTEM_VARIABLE) == "1"
    for number in (signal.SIGTERM, signal.SIGHUP):  # a stopped run still removes its system file
        signal.signal(number, lambda n, _frame: sys.exit(128 + n))
    hide_key = scrubber([token, kiro])
    # A model's refusal names the caller's role, and the log is uploaded. Keep the account out of it.
    scrub = lambda text: re.sub(r"(arn:aws[\w-]*:[\w-]*:[\w-]*:)\d{12}", r"\1***", hide_key(text))
    rows = []
    for check in checks:
        row = dict(id=check["id"], row=check["row"], harness=check["harness"], kind=feature_kind(check),
                   verdict="SKIP", reason="", expect="", mismatch="", denials=[], seconds=0, rc=None,
                   timed_out=False, note=check.get("note", ""))
        reason = feature_skip(check, env["PATH"], system, bool(feature_model_key(check, token, kiro)))
        if reason:
            row["reason"] = reason
            if args.no_skip and "no-program:" in reason:
                row["mismatch"] = f"could run but is SKIP: {reason}"
        else:
            fields, log = run_feature(check, out, env, token, kiro, args.timeout, scrub)
            (out / f"{check['id']}.log").write_text(log)
            row.update(fields)
            row["expect"] = check.get("expect", {}).get("verdict", "green").upper()
            row["mismatch"] = feature_mismatch(check, row["verdict"], log, row["reason"])
        rows.append(row)
        print(f"{row['id']:32} {row['verdict']:6} {row['reason']}"
              + (f"  | denies={len(row['denials'])}" if row["denials"] else "")
              + ("" if row["verdict"] == "SKIP" and not row["mismatch"] else
                 "  | ok" if not row["mismatch"] else f"  | DIFFERS: {row['mismatch']}"))
    columns = ["id", "row", "harness", "kind", "verdict", "reason", "expect", "mismatch", "denials", "seconds"]
    (out / "features.tsv").write_text(
        "\t".join(columns) + "\n" +
        "".join("\t".join(tsv_field("; ".join(r[c]) if c == "denials" else r[c]) for c in columns) + "\n"
                for r in rows))
    (out / "features.json").write_text(json.dumps(rows, indent=2))
    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\n=== features ===")
    print("  ".join(f"{k}:{v}" for k, v in sorted(tally.items())))
    print(f"results: {out}/features.tsv")
    failed = [r["id"] for r in rows if r["mismatch"]] if fail_set else []
    if failed:
        print(f"FAIL: {len(failed)} row(s) differ from their expect: {' '.join(failed)}")
        return 1
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", choices=["agent", "scripted", "launch", "features"], default="agent")
    ap.add_argument("--profile", default="claude")
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--gate")
    ap.add_argument("--section", help="run the cells of one section, such as TypeScript")
    ap.add_argument("--out")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--fail-on", default="red,error",
                    help="comma list of verdicts that exit non-zero "
                         "(red, error, green, skip), or none")
    ap.add_argument("--allow-no-credentials", action="store_true",
                    help="agent layer: SKIP cells when no model credential is set, "
                         "instead of failing")
    ap.add_argument("--shard", help="scripted layer: K/N runs every Nth cell that has a script, "
                                    "starting at the Kth. Shard 1 also lists the cells with none, and the quarantined ones.")
    ap.add_argument("--no-skip", action="store_true",
                    help="scripted, launch, and features layers: a row that is SKIP fails the run when "
                         "it could run (a cell with a script, a launch check, or a feature check whose "
                         "agent's program is absent). A cell its note quarantines stays SKIP")
    ap.add_argument("--install-profiles", action="store_true",
                    help="copy test-corpus/profiles/ into ~/.strands/box/profiles/ and make each launch "
                         "check's profile, replacing profiles of the same names")
    ap.add_argument("--grade", dest="grade", action="store_true", default=True,
                    help="agent layer: when the agent finishes, run the cell's `check` command over "
                         "the workspace to grade whether the task was done (default on)")
    ap.add_argument("--no-grade", dest="grade", action="store_false",
                    help="agent layer: report the box verdict only, do not run the task check")
    ap.add_argument("--judge", action="store_true",
                    help="agent layer: when the agent finishes, a second model (judge.py) reads the "
                         "run's tool calls, their output and the file changes, and decides whether "
                         "the cell's pass_check held. It grades a cell with no `check`; a cell with "
                         "one keeps the check's grade, and the judge's verdict is recorded beside it")
    ap.add_argument("--judge-model", default=os.environ.get("BOX_JUDGE_MODEL", judge.DEFAULT_MODEL),
                    help="the Bedrock model ID the judge calls (default: $BOX_JUDGE_MODEL, or "
                         f"{judge.DEFAULT_MODEL})")
    args = ap.parse_args()

    recorded = args.layer in ("scripted", "launch", "features")  # each compares a row with its expect
    launch = args.layer == "launch"
    if args.judge and args.layer != "agent":
        ap.error("--judge grades the agent layer; the other layers compare with expect")
    out = Path(args.out or f"/tmp/corpus-out/{args.layer if recorded else args.profile}")
    out.mkdir(parents=True, exist_ok=True)
    shard = None
    if args.shard:
        m = re.fullmatch(r"(\d+)/(\d+)", args.shard)
        if not m or not 1 <= int(m.group(1)) <= int(m.group(2)):
            ap.error("--shard: use K/N with 1 <= K <= N, for example 2/3")
        shard = (int(m.group(1)), int(m.group(2)))
    if args.fail_on.strip().lower() == "none":
        fail_set = set()
    else:
        fail_set = {v.strip().upper() for v in args.fail_on.split(",") if v.strip()}
        unknown = fail_set - {"GREEN", "RED", "ERROR", "SKIP"}
        if not fail_set or unknown:
            ap.error(f"--fail-on: {'empty' if not fail_set else 'unknown verdict(s): ' + ','.join(sorted(unknown))}. "
                     f"Use a comma list of GREEN, RED, ERROR, SKIP, or the word none.")

    # Resolve the model credential once. The agent layer needs a real one; the recorded
    # layer calls no model, so a placeholder lets the box start.
    key_file = Path(os.environ.get("BOX_BEDROCK_KEY_FILE", HOME / ".strands/box" / "bedrock.key"))
    token = os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "").strip()
    if not token and key_file.exists():
        token = key_file.read_text().strip()
    kiro = kiro_key()
    kiro_agent = args.layer == "agent" and args.profile == "kiro"
    have_token = bool(kiro if kiro_agent else token)
    # The agent layer calls a model, so a missing credential is an error, not a pass: a
    # nightly with a renamed or misplaced secret must fail, not report 61 green SKIPs.
    # --allow-no-credentials opts into the old SKIP for a caller that wants it.
    if args.layer == "agent" and not have_token and not args.allow_no_credentials:
        if kiro_agent:
            ap.error("no model credential: set KIRO_API_KEY, or put a Kiro API key in "
                     f"{KIRO_KEY_FILE} (BOX_KIRO_KEY_FILE). Pass --allow-no-credentials to "
                     "SKIP the agent cells instead.")
        ap.error("no model credential: set AWS_BEARER_TOKEN_BEDROCK, or put a key in "
                 f"{key_file} (BOX_BEDROCK_KEY_FILE). Pass --allow-no-credentials to "
                 "SKIP the agent cells instead.")
    # The judge calls Bedrock whatever the agent calls, so it needs a Bedrock key of its own.
    if args.layer == "agent" and args.grade and args.judge and not token:
        ap.error("--judge calls Bedrock: set AWS_BEARER_TOKEN_BEDROCK, or put a key in "
                 f"{key_file} (BOX_BEDROCK_KEY_FILE)")

    env = dict(os.environ)
    # Keep the caller's PATH so the box sees the toolchains their shell has, then add the
    # login-shell directories a bare SSM/launchd process would be missing.
    front = [os.environ.get("BOX_CORPUS_BIN", str(REPO / "target" / "debug"))] + \
        ([CODEX_VENDOR] if Path(CODEX_VENDOR).is_dir() else [])
    rest = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    tail = [p for p in PATH_FALLBACKS if p not in rest and p not in front]
    env["PATH"] = os.pathsep.join(front + rest + tail)
    env["AWS_BEARER_TOKEN_BEDROCK"] = token or "placeholder-no-model-call"
    # The kiro profile's route refuses to start the box with no KIRO_API_KEY. Only the Kiro agent
    # layer and the features layer's Kiro model checks call the model: every other run gets the
    # stand-in, so the kiro launch check gives the same result whatever key the host holds.
    env["KIRO_API_KEY"] = kiro if kiro_agent else "ksk_placeholder-no-model-call"
    if args.layer == "features":
        if args.gate or args.section or args.shard:
            ap.error("--gate, --section, and --shard pick corpus cells; the features layer has none. Use --ids.")
        sys.exit(run_features(args, env, out, token, kiro, fail_set))
    cells = launch_checks() if launch else tomllib.load(open(GRID, "rb"))["cell"]
    scrub = scrubber([token, kiro] + [env.get(name, "") for c in cells for name in c.get("env_vars", [])])
    present = {n for c in cells for n in c.get("env_vars", []) if env.get(n, "").strip()}
    if args.ids:
        unknown = sorted(set(args.ids) - {c["id"] for c in cells})
        if unknown:
            print(f"warning: unknown --ids ignored: {' '.join(unknown)}", file=sys.stderr)
        cells = [c for c in cells if c["id"] in args.ids]
    if args.gate and launch:
        ap.error("--gate picks corpus cells; the launch layer has none. Use --ids.")
    if args.gate:
        cells = [c for c in cells if c["gate"] == args.gate]
    if args.section and launch:
        ap.error("--section picks corpus cells; the launch layer has none. Use --ids.")
    if args.section:
        cells = [c for c in cells if c["section"].lower() == args.section.lower()]
    if args.layer == "scripted" and shard:
        cells = shard_cells(cells, *shard)
    if args.install_profiles:
        install_profiles(cells if launch else [], env)
        if args.layer == "agent":
            install_agent_profile(args.profile, env)
    tools = available_tools(env["PATH"], env)
    print(f"toolchains on this host: {' '.join(sorted(tools))}", file=sys.stderr)

    def runs(profile):
        found = set()
        for path in RUNS.glob("*"):
            if not re.fullmatch(r"b-[0-9a-f]{16}", path.name) or path.is_symlink() or not path.is_dir():
                continue
            record = path / "profile-name"
            try:
                if not record.is_symlink() and record.is_file() and record.read_text() == profile + "\n":
                    found.add(path)
            except (OSError, UnicodeError):
                continue
        return found

    # The judge reads what the agent changed, so the workspace is snapshotted before and after the
    # agent runs, and before the check runs (a check may build or write files of its own).
    judging = args.layer == "agent" and args.grade and args.judge
    file_changes = {}
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"

    def run_cell(cell, profile, argv):
        """Build the cell's fixture, run it once, and score it. Return (row, log)."""
        cid = cell["id"]
        d = out / cid
        build = make_fixture(cell, d, env)
        if build:
            return dict(id=cid, verdict="ERROR", reason=build, denies=0, permits=0, seconds=0,
                        rules=[], unexpected_host_denies=[], denials=[], timed_out=False,
                        ran=False, rc=None), build
        before_files = judge.snapshot(d) if judging else None
        before = runs(profile)
        t0 = time.time()
        rc, log, timed_out = invoke(profile, argv, d, env, args.timeout)
        secs = round(time.time() - t0)
        log = scrub(log)
        (out / f"{cid}.log").write_text(log)  # never let the token reach an uploaded log
        if judging:
            file_changes[cid] = scrub(judge.changes(before_files, judge.snapshot(d)))

        journal = journal_path(log)                          # box names it exactly; no race
        if journal is None:                                  # fall back to the new-run diff
            run_dir = max(runs(profile) - before, key=lambda p: p.stat().st_mtime, default=None)
            journal = run_dir / "records.jsonl" if run_dir else None
        decisions = parse_journal(journal) if journal else []
        ran = bool(journal) and journal.exists()  # the box truly wrote a journal, not just named one
        denies = [(r, res) for (v, a, r, res) in decisions if v == "deny"]
        permits = sum(1 for (v, *_) in decisions if v == "permit")
        allowed_hosts = set(cell.get("net", []))
        unexpected = sorted({res for (r, res) in denies
                             if res and ":" in str(res) and str(res).split(":")[0] not in allowed_hosts})
        # Only the agent layer reads the box's sandbox refusal lines. The scripted and launch layers
        # compare with recorded results, which moving them to this rule would change.
        sandbox = [] if recorded else sandbox_refusals(log)
        verdict, why = verdict_for(ran, decisions, denies, rc, timed_out,
                                   require_decisions=not recorded, sandbox_denies=len(sandbox))
        if verdict == "RED" and not denies and sandbox:
            why = (why + "; " if why else "") + f"sandbox refusal: {sandbox[0][:120]}"
        if verdict == "ERROR" and not decisions:
            first_err = next((l for l in log.splitlines() if "error:" in l.lower()), "")
            why = f"{why}: {first_err.strip()[:160]}" if first_err else why
        return dict(id=cid, verdict=verdict, reason=why, denies=len(denies), permits=permits,
                    seconds=secs, rules=sorted({r for (r, _) in denies}),
                    unexpected_host_denies=unexpected, denials=deny_lines(decisions, d),
                    timed_out=timed_out, ran=ran, rc=rc), log

    def run_check(check, cid):
        """Run a cell's success check over the workspace the agent left, and return its exit code.

        The agent just wrote arbitrary files into this workspace, so the check runs INSIDE a box
        (under the corpus bash profile), never on the host: the box contains the filesystem and
        exec, and passes the host's credentials to nothing. The grader is a box run, like the
        scripted layer, not a model call. Its output goes beside the cell's log.

        Limitation: the agent could edit what the check runs (a test, a config) to make it pass.
        A stronger check asserts specific output or file state instead of re-running the agent's
        code; those are authored per cell. See test-corpus/workloads-notes.md.
        """
        grade_env = dict(env)
        grade_env["AWS_BEARER_TOKEN_BEDROCK"] = "placeholder-no-model-call"  # keep the key out of the grader
        # A box that fails to START the check exits non-zero the same as a check that ran and
        # failed, so an exit code alone cannot tell them apart. Print a sentinel first: if it is
        # absent, the box never ran the check (startup, transport, or policy), which grade() reads
        # as a grader error (125), not a task failure.
        rc, output, timed_out = invoke(GRADE_PROFILE, check_argv(check),
                                       out / cid, grade_env, args.timeout)
        (out / f"{cid}.check.log").write_text(scrub(output))
        if timed_out:
            return 124
        return rc if CHECK_SENTINEL in output else GRADER_DID_NOT_RUN

    def run_judge(cell, cid, log, row):
        """Ask the judge whether the agent did the cell's task, from the run's record.

        The judge only reads text, so it runs here on the host: it runs nothing from the workspace,
        and judge.snapshot never follows a link out of it. The record it read and its answer go
        beside the cell's log, with the token scrubbed from both."""
        refusals = [f"policy denied: {line}" for line in row.get("denials", [])] + sandbox_refusals(log)
        record, proof, claims = judge.build_record(
            log, file_changes.get(cid, "No workspace snapshot was taken."), refusals)
        record, proof, claims = scrub(record), scrub(proof), scrub(claims)
        (out / f"{cid}.evidence.txt").write_text(record)
        condition = cell.get("pass_check") or "the task in the prompt is done"
        result = judge.judge(cell["prompt"], condition, record, proof, claims, token,
                             model=args.judge_model, region=region)
        (out / f"{cid}.judge.json").write_text(
            json.dumps(dict(result, model=args.judge_model, pass_check=condition), indent=2))
        return result

    rows = []
    for cell in cells:
        cid = cell["id"]
        if launch:
            missing = [t for t in cell.get("needs", []) if not which(t, env["PATH"])]
            reason = f"no-program:{','.join(missing)}" if missing else None
        else:
            reason = skip_reason(cell, tools, have_token, args.layer, present, args.profile)
        if reason:
            # A quarantine is a skip the corpus chose, so --no-skip, which catches a lost
            # toolchain, lets it through.
            differs = (f"could run but is SKIP: {reason}"
                       if recorded and args.no_skip and (launch or cell.get("script"))
                       and "quarantined-by-spec" not in reason else "")
            rows.append(dict(id=cid, verdict="SKIP", reason=reason, denies=0, permits=0,
                             seconds=0, rules=[], unexpected_host_denies=[], denials=[],
                             timed_out=False, expect="", mismatch=differs))
            print(f"{cid:8} SKIP   {reason}" + (f"  | DIFFERS: {differs}" if differs else ""))
            continue

        if launch:
            profile, argv, cell = cell["profile"], list(cell["args"]), {"fixture": "empty", **cell}
        elif args.layer == "scripted":
            profile, argv = cell.get("profile", CELL_PROFILE), ["-c", PRELUDE + cell["script"]]
        else:
            profile, argv = agent_cell_profile(args.profile, cell), agent_args(args.profile, cell["prompt"])
        row, log = run_cell(cell, profile, argv)
        row["expect"], row["mismatch"] = "", ""
        row["grade"], row["grade_reason"] = "", ""
        if not recorded:
            # The agent layer grades whether the task was done, beside the box verdict. The check
            # runs whenever the agent finished, even after refusals, and only when the cell
            # declares one.
            check = cell.get("check", "") if args.grade else ""
            finished = agent_finished(row)
            check_rc = run_check(check, cid) if (check and finished) else None
            row["grade"], row["grade_reason"] = grade(finished, check, check_rc)
            row["grade_by"] = "check" if (check and finished) else ""
            row["judge"], row["judge_reason"], row["judge_evidence"] = "", "", ""
            if judging and finished:
                # The judge runs on every finished cell. A cell with a check keeps the check's
                # grade, and the judge's verdict beside it shows whether the two agree.
                verdict = run_judge(cell, cid, log, row)
                row["judge"], row["judge_reason"] = verdict["verdict"], verdict["reason"]
                row["judge_evidence"] = verdict["evidence"][:500]
                if not check:
                    row["grade"], row["grade_reason"] = judge_grade(verdict["verdict"], verdict["reason"])
                    row["grade_by"] = "judge"
        if recorded:
            row["expect"] = cell.get("expect", {}).get("verdict", "green").upper()
            row["mismatch"] = mismatch(cell, row["verdict"], row["denials"], log, row["timed_out"])
            # A registry or clone can fail for a moment, but a run that hung would hang again.
            if row["mismatch"] and row["verdict"] == "ERROR" and not row["timed_out"]:
                print(f"{cid:8} retry  {row['mismatch']}")
                row, log = run_cell(cell, profile, argv)
                row["expect"] = cell.get("expect", {}).get("verdict", "green").upper()
                row["mismatch"] = mismatch(cell, row["verdict"], row["denials"], log, row["timed_out"])
            if row["mismatch"] and not row["timed_out"]:  # a record cannot accept a hang
                row["suggest"] = suggest_expect(row, log)
        rows.append(row)
        print(f"{cid:8} {row['verdict']:6} denies={row['denies']:<3} permits={row['permits']:<4} "
              f"{row['seconds']}s  {' '.join(x for x in (row['reason'], ','.join(row['rules'])) if x)}"
              + (("  | ok" if not row["mismatch"] else f"  | DIFFERS: {row['mismatch']}") if recorded else "")
              + (f"  | grade {row['grade']}" + (f": {row['grade_reason']}" if row['grade_reason'] else "")
                 if not recorded and row['grade'] else "")
              + (f"  | judge {row['judge']}" if not recorded and row.get('judge') else ""))
        if row.get("suggest"):
            print(f"{'':8} draft record: {row['suggest']}")

    (out / "results.tsv").write_text(
        "id\tverdict\treason\tdenies\tpermits\tseconds\trules\tunexpected_host_denies\t"
        "expect\tmismatch\tdenials\tgrade\tgrade_reason\tgrade_by\tjudge\tjudge_reason\n" +
        "".join(f"{r['id']}\t{r['verdict']}\t{r.get('reason','')}\t{r['denies']}\t{r['permits']}\t"
                f"{r['seconds']}\t{','.join(r.get('rules',[]))}\t"
                f"{','.join(r.get('unexpected_host_denies',[]))}\t{r.get('expect','')}\t"
                f"{r.get('mismatch','')}\t{'; '.join(r.get('denials',[]))}\t"
                f"{r.get('grade','')}\t{tsv_field(r.get('grade_reason',''))}\t{r.get('grade_by','')}\t"
                f"{r.get('judge','')}\t{tsv_field(r.get('judge_reason',''))}\n" for r in rows))
    (out / "results.json").write_text(json.dumps(rows, indent=2))
    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print(f"\n=== {args.layer if recorded else args.profile} ({args.layer}) ===")
    print("  ".join(f"{k}:{v}" for k, v in sorted(tally.items())))
    if not recorded:
        gt = {}
        for r in rows:
            if r.get("grade"):
                gt[r["grade"]] = gt.get(r["grade"], 0) + 1
        if gt:
            print("grade: " + "  ".join(f"{k}:{v}" for k, v in sorted(gt.items())))
        both = [r for r in rows if r.get("grade_by") == "check" and r.get("judge") in (judge.PASS, judge.FAIL)]
        if both:
            agree = sum(1 for r in both if r["judge"] == r["grade"])
            print(f"judge agrees with the check on {agree} of {len(both)} cells that have both")
    print(f"results: {out}/results.tsv")

    if recorded:  # the scripted and launch layers fail on a result that differs from its record
        failed = [r["id"] for r in rows if r.get("mismatch")] if fail_set else []
        if failed:
            print(f"FAIL: {len(failed)} row(s) differ from their expect: {' '.join(failed)}")
            sys.exit(1)
        return
    failed = [r["id"] for r in rows if r["verdict"] in fail_set]
    if failed:
        print(f"FAIL: {len(failed)} cell(s) in {','.join(sorted(fail_set))}: {' '.join(failed)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
