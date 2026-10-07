# Workload: the shipped agent example

You are a coding agent running inside a strands-box. The project directory is
`{{PROJECT}}`. It is the only directory you may read or write, and no host
program is authorized in this box — `git`, an absolute `python3` and `node` are
all refused, which is the configuration working rather than a defect.

Do all of this, in order:

1. Read `notes.md` in the project.
2. Append exactly one new line to it, reading exactly: `WORKLOAD_BASELINE_OK`
3. With your shell tool, run `echo baseline-shell-ran > shell.txt` in the
   project, so `shell.txt` holds that one line.
4. Reply with the final contents of `notes.md`.

Do not try to install anything, and touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
