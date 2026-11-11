#!/usr/bin/env python3
"""Run example tests without cloud deployment or model calls."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
commands = [[sys.executable, "-m", "unittest", "test_fixture", "test_deploy_runtime",
             "test_runtime_strands", "test_runtime_langchain", "test_prepare"],
            [sys.executable, "sdk/test_agent.py"]]
if (ROOT / "langchain-example/vendor").is_dir():
    commands.append([sys.executable, "langchain-example/run-offline-tests.py"])
else:
    print("Skipping LangChain graph tests: prepare the langchain dependencies to run them.", flush=True)
for command in commands:
    subprocess.run(command, cwd=ROOT, check=True)
