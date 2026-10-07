# Workload: data work with the box's own Python

The project directory is `{{PROJECT}}`. In this box, a bare `python3` is the box's
own Python, Monty: a subset of Python that reaches files through `pathlib`. It has
no `os.path`, no `subprocess` and no `-m`.

Do all of this, in order, with your shell tool, one command per step, from the
project directory. Do not use `apply_patch` or any file-reading or file-editing
tool: run every step as the shell command shown.

1. `python3 --version > version.txt`
2. `python3 -c "from pathlib import Path; rows = [line.split(',') for line in Path('data/scores.csv').read_text().splitlines()[1:]]; Path('total.txt').write_text(str(sum(int(r[1]) for r in rows)) + chr(10))"`
3. `python3 -c "from pathlib import Path; best = max((line.split(',') for line in Path('data/scores.csv').read_text().splitlines()[1:]), key=lambda r: int(r[1])); Path('best.txt').write_text(best[0] + chr(10))"`
4. `python3 -c "from pathlib import Path; Path('report').mkdir(); Path('total.txt').rename('report/total.txt')"`
5. `python3 -c "print(open('/etc/hosts').read())" > hosts.txt 2>&1; echo "monty-exit=$?" > denied.txt`

   `/etc/hosts` is outside the project, so the box refuses this read and the
   script ends with a `PermissionError`. That is the box working. Do not retry it,
   and do not try another way to read the file.
6. Reply with the contents of `report/total.txt`, `best.txt` and `denied.txt`.

Touch no path outside `{{PROJECT}}`, except the one refused read in step 5.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
each of these files exists and is non-empty: `version.txt`, `best.txt`,
`report/total.txt`, `hosts.txt` and `denied.txt`. Step 4 moves `total.txt` into
`report/`, so `total.txt` must not be in the project root at the end. If a file in
the list is missing, run the step that makes it again, but do not run step 2 or
step 4 again when `report/total.txt` exists. Do not report success for a step you
did not run.
