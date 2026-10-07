# Workload: the agent's own hook, and a delegated subtask

The project directory is `{{PROJECT}}`. A post-write hook is already configured
for you: after you write a file, it writes the line `HOOK_FIRED` to `hook.txt` in
the project. You do not need to install or configure it.

Do all of this, in order:

1. Write a file `feature.txt` in the project containing the single line
   `hook workload`.
2. Read `hook.txt` — the hook writes it — and copy whatever it contains into
   `hook-observed.txt`. If `hook.txt` does not exist, write the single line
   `NO_HOOK_FILE` into `hook-observed.txt` instead. Do not create `hook.txt`
   yourself under any circumstances.
3. Delegate one subtask: ask a subagent to write the exact line
   `SUBAGENT_OK` into `subagent.txt` in the project. If you have no way to
   delegate to a subagent, write `SUBAGENT_UNSUPPORTED` into `subagent.txt`
   yourself and say so in your reply.
4. Reply with the contents of `hook.txt`.

Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
