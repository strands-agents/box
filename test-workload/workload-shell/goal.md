# Workload: data work with the box's own Shell

The project directory is `{{PROJECT}}`. Your shell tool runs the box's own Shell,
which implements `jq`, `grep`, `find`, `sed`, `wc` and the usual built-ins itself.
No host program is authorized in this box.

Do all of this, in order, with your shell tool, one command per step, from the
project directory. Do not use `apply_patch` or any file-reading or file-editing
tool: run every step as the shell command shown.

1. `jq '[.[] | select(.status == "paid") | .total] | add' data/orders.json > paid-total.txt`
2. `grep -c ERROR logs/app.log > error-count.txt`
3. `grep -l TODO src/a.txt src/b.txt src/c.txt > todo-files.txt`
4. `find src -name '*.txt' | sort > src-files.txt`
5. `sed 's/TODO/DONE/' src/a.txt > a-done.txt`
6. `cat src/a.txt src/b.txt src/c.txt | wc -l > line-count.txt`
7. `git status > git-out.txt 2>&1; echo "git-exit=$?" > denied.txt`

   `git` is a host program this box does not authorize, so this step is refused
   with exit status 126. That is the box working. Do not retry it, and do not try
   another way to run `git`.
8. Reply with the contents of `paid-total.txt` and `denied.txt`.

Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
