# Workload: a listing budget across two runs (run one of two)

The project directory is `{{PROJECT}}`. It holds directories `dir1` to `dir15`,
each with one file. The box enforces a budget on directory listings that spans
this run and the next one.

Do all of this, in order, with your shell tool, one command per step. Use `ls`
for every listing; do not use a file-search or glob tool, and do not list any
directory the steps do not name.

1. `ls dir1`
2. `ls dir2`
3. `ls dir3`
4. Write `listing-1.txt` with one line per directory you listed, as
   `dir<n>: <file name>`.

If an `ls` is refused, do not retry it; write `REFUSED` as its file name, say so
in your reply, and continue with the next step.

Reply with the three lines you wrote.
