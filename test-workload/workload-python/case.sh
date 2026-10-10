#!/bin/bash
# workload-python — CPython in its own boundary: a module, a test, an install from
# the package index, and a green pytest run. The interpreter is named absolutely
# because a bare `python3` is Monty (the declared-tool precedence change is
# parked), and the two package-index hosts are the only extra egress.
#
# Reference: artifact section 3. On macOS the table's command is the virtualenv's
# interpreter, so the virtualenv must exist before the box starts: a command that
# names an absent file is refused at load.

wl_manifest() {
  cat <<EOF
tools=python
http=pypi.org files.pythonhosted.org
timeout=900
residuals=monty-bare-python3
residuals_macos=macos-pip-trusted-host
EOF
}

wl_prepare() {
  local proj="$1"
  if [ "$WL_PLATFORM" = macos ]; then
    # The pair names the virtualenv's interpreter when one exists, so build it on
    # the host first and say so loudly if it cannot be built: the generator then
    # names the framework interpreter, and the row carries the reason.
    if [ -x "${WL_PYTHON:-/nonexistent}" ]; then
      "$WL_PYTHON" -m venv "$proj/.venv" || echo "venv creation FAILED under $WL_PYTHON"
      "$proj/.venv/bin/python3" -m ensurepip --upgrade >/dev/null 2>&1 || true
    else
      echo "no framework interpreter resolved on this host: WL_PYTHON=${WL_PYTHON:-unset}"
    fi
  fi
  mkdir -p "$proj/.pylibs" "$proj/.pip-cache"
}

wl_checks() {
  local proj="$1"
  wl_assert_file py-module "$proj/calc.py" "def add"
  wl_assert_file py-test-file "$proj/test_calc.py" "add("
  wl_assert_test_output py-pytest-output "$proj/pytest-out.txt" python
  if [ "$WL_PLATFORM" = macos ]; then
    wl_assert_glob py-pytest-installed "$proj/.venv/lib/*/site-packages/pytest*"
  else
    wl_assert_glob py-pytest-installed "$proj/.pylibs/pytest*"
  fi
  wl_assert_journal py-journal-spawn permit "shell:spawn" python
  wl_note_codex_arg0 "$proj/pytest-out.txt"
}
