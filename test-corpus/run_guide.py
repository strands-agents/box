#!/usr/bin/env python3
"""The profile guide's prompt tests: a coding agent on the host follows the guide to do one task.

  run_guide.py [--ids add-tool,add-pack] [--out DIR] [--agent claude] [--timeout 420] [--no-skip]

Each cell of guide/guide.toml gets a home folder of its own, with one profile and two operator
packs. The agent gets one prompt: "Run box help agent and follow it to update profile <profile>."
and the cell's task, or "Run box help agent and follow it to create a profile." for a cell that
starts with no profile. The runner writes no guide: the agent's own run of `box help agent` prints
the path of the guide that ships with box, in the resources folder, and writes nothing. The agent
runs on the host, not in a box, because a boxed agent cannot write a profile. A cell passes when:
  - the agent exits 0;
  - `box profile show --full <profile>` exits 0;
  - that output holds each `shows` text, none of the `absent` texts, and a match for each
    `matches` pattern;
  - every file, folder, link, or mode the agent added or changed in the home folder matches
    `may_change`;
  - no file that ships with box changed: the guide, the packs, the policies, and the starters.
No model grades a cell.

A cell is SKIP when there is no model credential (`no-model-credential`) or no agent program
(`no-agent`), and the run then exits 0, or 1 with --no-skip. The agent gets the box under test first
on its PATH, the model key, and no other variable of the shell except those in PASSED. Any FAIL or ERROR exits 1. results.tsv in --out holds one
row per cell, and each cell's folder holds the agent's log and the `show` output.
"""
import argparse
import fnmatch
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
POLICY = '@id("shell_commands")\npermit (principal, action == Box::Action::"shell:exec", resource);\n'
PACK = """[pack]
name = "{name}"
version = 1
kind = "support"

[inputs.{name}.host]
description = "A host the box reaches."
pattern = "[a-z.]+"
default = "example.com"

[egress.{name}]
destinations = ["${{{{ inputs.{name}.host }}}}"]
"""
# The agent's own state in the home folder, which is not a change to the operator's configuration.
AGENT_STATE = (".claude", ".claude.json", ".claude.json.backup")
# What the agent may use without a prompt. The shell is for `box` alone. Edit and Write are not
# here: `--permission-mode acceptEdits` allows them in the project and in the `--add-dir` folders,
# and nowhere else. Those folders are the cell's `.strands/box`, where the agent edits, and the resources
# folder, where it reads the guide. A change in the resources folder fails the cell.
TOOLS = "Read,Glob,Grep,Bash(box:*)"
# The only variables the agent and `box` get from the shell that runs the cells. The agent's one
# credential is the model key, which the runner adds.
PASSED = ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR", "USER", "AWS_REGION", "ANTHROPIC_MODEL",
          "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
          "ANTHROPIC_DEFAULT_HAIKU_MODEL", "BOX_RESOURCES")
PASS, FAIL, ERROR, SKIP = "PASS", "FAIL", "ERROR", "SKIP"


def load_cells(path=HERE / "guide" / "guide.toml"):
    return tomllib.loads(Path(path).read_text())["cell"]


def snapshot(root, skip=()):
    """Each file, folder, and link below `root`, by its path relative to it, with its mode and,
    for a file, a hash of its content. A link is recorded by its target and is not followed."""
    entries = {}
    for folder, names, leaves in os.walk(root):
        relative = Path(folder).relative_to(root)
        top = relative == Path(".")
        for name in list(names) + leaves:
            if top and name in skip:
                continue
            path = Path(folder) / name
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                entries[str(relative / name)] = f"link:{os.readlink(path)}"
            elif path.is_dir():
                entries[str(relative / name)] = f"dir:{mode:o}"
            else:
                entries[str(relative / name)] = f"{mode:o}:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        names[:] = [n for n in names if not (top and n in skip)]
    return entries


def changed(before, after):
    """The paths added, changed, or removed between two snapshots."""
    return sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))


def outside(paths, patterns):
    """The changed paths that no `may_change` pattern allows."""
    return [p for p in paths if not any(fnmatch.fnmatchcase(p, pattern) for pattern in patterns)]


def prompt_for(cell, home):
    """The one prompt the agent gets: the operator's sentence, then the cell's task."""
    profile = cell.get("profile", "test")
    goal = f"update profile {profile}" if "start" in cell else "create a profile"
    return (f"Run box help agent and follow it to {goal}. "
            + cell["task"].replace("{home}", str(home)))


def prepare(cell, home):
    """Make the cell's home folder, with its profile when the cell starts with one."""
    project = home / "project"
    project.mkdir(parents=True)
    (home / "notes").mkdir()
    (home / "workspace/box-demo/team-handbook").mkdir(parents=True)
    (home / "workspace/box-demo/team-handbook/dependencies.md").write_text(
        "New dependencies need review by the team.\n")
    (home / "settings.json").write_text('{"theme": "dark", "token": "not-for-the-box"}\n')
    for name in ("extra", "other"):
        pack = home / ".strands/box/packs" / name
        pack.mkdir(parents=True)
        (pack / "pack.toml").write_text(PACK.format(name=name))
    if "start" not in cell:
        return
    folder = home / ".strands/box/profiles" / cell.get("profile", "test")
    folder.mkdir(parents=True)
    (folder / "profile.toml").write_text(cell["start"].replace("{home}", str(home)).lstrip())
    (folder / "policy.dw").write_text(POLICY + cell.get("rules", ""))


def agent_argv(agent, prompt, home, resources):
    return [agent, "-p", prompt, "--output-format", "stream-json", "--verbose",
            "--permission-mode", "acceptEdits", "--allowedTools", TOOLS,
            "--add-dir", str(home / ".strands/box"), "--add-dir", str(resources)]


def grade(cell, agent_rc, show, home_changes, shipped_changes):
    """The cell's verdict and the reasons for a FAIL."""
    reasons = []
    if agent_rc != 0:
        reasons.append(f"the agent exited {agent_rc}")
    if show.returncode != 0:
        reasons.append(f"box profile show --full exited {show.returncode}")
    reasons += [f"show does not print {text!r}" for text in cell.get("shows", [])
                if text not in show.stdout]
    reasons += [f"show prints {text!r}" for text in cell.get("absent", []) if text in show.stdout]
    reasons += [f"show has no match for {pattern!r}" for pattern in cell.get("matches", [])
                if not re.search(pattern, show.stdout)]
    reasons += [f"changed outside the profile: {path}"
                for path in outside(home_changes, cell.get("may_change", []))]
    reasons += [f"changed a file that ships with box: {path}" for path in shipped_changes]
    return (FAIL if reasons else PASS), reasons


def shipped_resources(box, env):
    """The resources folder of the box under test: the folder of the guide that `box help agent`
    prints, so the runner and the box agree on it."""
    with tempfile.TemporaryDirectory(prefix="box-guide-", dir="/var/tmp") as scratch:
        scratch_env = {k: v for k, v in env.items() if k in PASSED}
        scratch_env["HOME"] = scratch
        shown = subprocess.run([box, "help", "agent"], env=scratch_env, capture_output=True, text=True)
    if shown.returncode != 0:
        raise ValueError(shown.stderr.strip() or f"exit status {shown.returncode}")
    paths = [line.strip() for line in shown.stdout.splitlines()[1:2]]
    if not paths or not Path(paths[0]).is_file():
        raise ValueError(f"no guide file in its output: {shown.stdout[:200]!r}")
    return Path(paths[0]).resolve().parent


def run_cell(cell, box, agent, resources, env, out, timeout):
    root = Path(tempfile.mkdtemp(prefix="box-guide-", dir="/var/tmp")).resolve()
    home = root / "home"
    cell_env = {k: v for k, v in env.items() if k in PASSED}
    # The agent's shell may run `box` alone, so the box under test goes first on its PATH.
    cell_env.update(HOME=str(home), BOX_TELEMETRY="0", CLAUDE_CODE_USE_BEDROCK="1",
                    AWS_BEARER_TOKEN_BEDROCK=credential(env),
                    PATH=f"{Path(box).parent}{os.pathsep}{env.get('PATH', '')}")
    shipped = None
    try:
        prepare(cell, home)
        prompt = prompt_for(cell, home)
        before, shipped = snapshot(home, AGENT_STATE), snapshot(resources)
        # A copy of the shipped files, put back after the cell when the agent changed them, so the
        # next cell reads the guide that ships.
        backup = root / "resources"
        shutil.copytree(resources, backup, symlinks=True)
        log = out / cell["id"]
        log.mkdir(parents=True, exist_ok=True)
        try:
            with open(log / "agent.log", "w") as output:
                agent_rc = subprocess.run(agent_argv(agent, prompt, home, resources), cwd=home / "project",
                                          env=cell_env, stdout=output, stderr=subprocess.STDOUT,
                                          stdin=subprocess.DEVNULL, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return ERROR, [f"the agent did not finish in {timeout} s"]
        finally:
            # The log is uploaded, so the model key the agent holds must not be in it.
            key = cell_env["AWS_BEARER_TOKEN_BEDROCK"]
            if key and (log / "agent.log").is_file():
                text = (log / "agent.log").read_text(errors="replace")
                (log / "agent.log").write_text(text.replace(key, "***"))
        show = subprocess.run([box, "profile", "show", "--full", cell.get("profile", "test")],
                              cwd=home / "project", env=cell_env, capture_output=True, text=True)
        (log / "show.txt").write_text(show.stdout + show.stderr)
        return grade(cell, agent_rc, show, changed(before, snapshot(home, AGENT_STATE)),
                     changed(shipped, snapshot(resources)))
    finally:
        if shipped is not None and changed(shipped, snapshot(resources)):
            restore(resources, root / "resources")
        shutil.rmtree(root, ignore_errors=True)


def restore(resources, backup):
    """Put the shipped files back as the backup holds them, in place, so the folder stays where
    the box under test reads it."""
    for entry in list(resources.iterdir()):
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    shutil.copytree(backup, resources, symlinks=True, dirs_exist_ok=True)


def credential(env):
    """The model key for the agent, from the workflow's key file or the shell."""
    path = env.get("BOX_BEDROCK_KEY_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text().strip()
    return env.get("AWS_BEARER_TOKEN_BEDROCK", "").strip()


def skip_reason(env, agent):
    reasons = []
    if not credential(env):
        reasons.append("no-model-credential")
    if not shutil.which(agent, path=env.get("PATH")):
        reasons.append("no-agent")
    return ",".join(reasons)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ids", default="", help="cell ids, comma-separated; empty runs every cell")
    ap.add_argument("--out", default="guide-results", help="the folder for results.tsv and logs")
    ap.add_argument("--agent", default="claude", help="the agent program")
    ap.add_argument("--box", default=os.environ.get("BOX_CORPUS_BIN", str(REPO / "target/debug")),
                    help="the folder that holds the box program")
    ap.add_argument("--timeout", type=int, default=420, help="seconds for one agent session")
    ap.add_argument("--no-skip", action="store_true",
                    help="fail when the cells cannot run, where a SKIP would hide a broken setup")
    args = ap.parse_args(argv)
    ids = [i for i in args.ids.replace(",", " ").split() if i]
    cells = [c for c in load_cells() if not ids or c["id"] in ids]
    unknown = set(ids) - {c["id"] for c in cells}
    if unknown or not cells:
        ap.error(f"no cell named {', '.join(sorted(unknown)) or '(none)'}")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    box = str(Path(args.box) / "box")
    skip = skip_reason(env, args.agent)
    if skip and args.no_skip:
        print(f"--no-skip: the cells cannot run: {skip}", file=sys.stderr)
        return 1
    resources = None
    if not skip:
        try:
            resources = shipped_resources(box, env)
        except (OSError, ValueError) as error:
            print(f"box help agent gave no guide path: {error}", file=sys.stderr)
            return 1
    rows = []
    for cell in cells:
        if skip:
            verdict, reasons = SKIP, [skip]
        else:
            try:
                verdict, reasons = run_cell(cell, box, args.agent, resources, env, out, args.timeout)
            except (OSError, subprocess.CalledProcessError) as error:
                verdict, reasons = ERROR, [str(error)]
        rows.append((cell["id"], verdict, "; ".join(reasons)))
        print(f"{verdict:5}  {cell['id']:20}  {'; '.join(reasons)}", flush=True)
        (out / "results.tsv").write_text(
            "id\tverdict\treasons\n" + "".join("\t".join(row) + "\n" for row in rows))
    if skip:
        print(f"every cell is SKIP: {skip}. Set AWS_BEARER_TOKEN_BEDROCK or BOX_BEDROCK_KEY_FILE, "
              f"and put {args.agent} on PATH.")
        return 0
    return 1 if any(row[1] in (FAIL, ERROR) for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
