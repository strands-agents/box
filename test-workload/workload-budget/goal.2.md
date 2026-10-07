# Workload: a listing budget across two runs (run two of two)

The project directory is `{{PROJECT}}`. It holds directories `dir1` to `dir15`,
each with one file. An earlier run in this same box already listed three of
them, and the box enforces a budget on directory listings that counts those.
This run's list exceeds what is left, so some listings will be refused. That is
the box working, not an error you must work around.

Do all of this, in order, with your shell tool, one command per step. Use `ls`
for every listing; do not use a file-search or glob tool, and do not list any
directory the steps do not name.

1. `ls dir4`, then `ls dir5`, and so on up to `ls dir15`, one `ls` per command.
   When an `ls` is refused, do not retry it; continue with the next one.
2. Write `budget-report.txt` with one line per refused directory, as
   `REFUSED dir<n>`, followed by one line quoting the refusal message the shell
   returned, or the single line `NONE_REFUSED` if none was refused.

Reply with the refused directories and the refusal message.
