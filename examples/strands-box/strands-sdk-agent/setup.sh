#!/bin/sh
# Builds the virtual environment at runtime/.venv, beside this file, and installs requirements.txt
# into it with Homebrew's Python. The box reads the environment and never writes it.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
python=${PYTHON:-/opt/homebrew/bin/python3.14}
[ -x "$python" ] || { echo "no Python at $python: run 'brew install python@3.14', or set PYTHON to another interpreter" >&2; exit 1; }

"$python" -m venv "$here/runtime/.venv"
"$here/runtime/.venv/bin/python3" -m pip install --quiet --upgrade pip
"$here/runtime/.venv/bin/python3" -m pip install --quiet -r "$here/requirements.txt"
mkdir -p "$here/tmp"

echo "installed the Strands Agents SDK into $here/runtime/.venv"
echo "the base interpreter is $("$here/runtime/.venv/bin/python3" -c 'import sys; print(sys.base_prefix)')"
