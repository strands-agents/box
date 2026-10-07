# Workload: a Python project — virtualenv, pip, pytest

The project directory is `{{PROJECT}}`. The interpreter you must use is

    {{PY_CMD}}

Always spell it in full. A bare `python3` is the box's own built-in interpreter,
Monty, which has no `-m`, so `python3 -m ...` will not do what you want.

Do all of this, in order:

1. Write `calc.py` in the project with a function `add(a, b)` returning `a + b`,
   and `test_calc.py` with two tests that both pass.
2. Install pytest with exactly this command:

       {{PIP_INSTALL}}

3. Run the tests with exactly this command, from the project directory, so the
   full output lands in `pytest-out.txt`:

       {{PYTEST_RUN}}
4. Reply with the last line of `pytest-out.txt`.

Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
