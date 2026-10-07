# Workload: a git workflow, and the tool-coverage gate

The project directory is `{{PROJECT}}`. `git` is authorized here and runs in its
own boundary; its identity, its author and its editor are already configured, so
a rebase continuation never waits for a terminal. Use plain `git` commands
through your shell tool.

Do all of this, in order:

1. `git init` in the project, then write `story.txt` containing the single line
   `first` and commit it with the message `first commit`.
2. Create a branch `feature`, change `story.txt` to read `feature side` and
   commit it with the message `feature commit`.
3. Return to the default branch, change `story.txt` to read `main side` and
   commit it with the message `main commit`.
4. Rebase `feature` onto the default branch. It will conflict. Resolve the
   conflict so `story.txt` reads exactly `resolved`, then `git add story.txt` and
   `git rebase --continue`. Do not abort the rebase.
5. Write the output of `git log --oneline` to `gitlog.txt` in the project.
6. Then run exactly this command and write whatever it prints, including any
   refusal, to `gate.txt` in the project:

       {{PYTHON}} --version

   That program is deliberately NOT authorized in this box. Do not try to work
   around the refusal, and do not stop the run because of it — recording it is
   the point.
7. Reply with the contents of `gitlog.txt`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
