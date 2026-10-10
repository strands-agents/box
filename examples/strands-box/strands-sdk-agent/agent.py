"""A Strands Agents SDK agent that works on a project from inside a box.

The box starts this file and passes the task on the command line, after `--`. Each tool runs a
command through the box's shell, so the policy decides every file the command touches.
"""

import os
import shlex
import subprocess
import sys

from strands import Agent, tool
from strands.models import BedrockModel

SYSTEM_PROMPT = """You work on the project in the current directory, with the tools you are given.
Keep answers to a few sentences. When a tool reports that the policy denied an operation, quote the
denial, say what it stopped, and end your turn. Do not look for another way to do it."""


def shell(command: str) -> str:
    """Run one command in the box's shell, show it on stderr, and return what it printed."""
    done = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
    print(f"[tool] {command} (exit {done.returncode})", file=sys.stderr)
    if done.stderr:
        print(done.stderr.rstrip(), file=sys.stderr)
    if done.returncode == 0:
        return done.stdout or "(no output)"
    return f"exit {done.returncode}\n{done.stdout}{done.stderr}"


@tool
def list_project() -> str:
    """List the files in the project."""
    return shell("ls -a")


@tool
def read_file(path: str) -> str:
    """Read one file in the project, by its path relative to the project."""
    return shell(f"cat {shlex.quote(path)}")


@tool
def run_command(command: str) -> str:
    """Run a shell command in the project and return its output."""
    return shell(command)


def main() -> int:
    # Keep the model's words in order with the tool lines when the output goes to a file.
    sys.stdout.reconfigure(line_buffering=True)
    task = " ".join(sys.argv[1:])
    if not task:
        print("usage: box run --config box.toml -- <task>", file=sys.stderr)
        return 2
    missing = [name for name in ("MODEL_ID", "AWS_REGION") if name not in os.environ]
    if missing:
        print(f"set {' and '.join(missing)} in [agent] env in box.toml", file=sys.stderr)
        return 2
    agent = Agent(
        model=BedrockModel(model_id=os.environ["MODEL_ID"], region_name=os.environ["AWS_REGION"]),
        system_prompt=SYSTEM_PROMPT,
        tools=[list_project, read_file, run_command],
    )
    agent(task)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
