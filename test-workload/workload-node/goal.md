# Workload: a Node project — npm install and node:test

The project directory is `{{PROJECT}}`. Two spellings are load-bearing in this
box, because a tool table is selected by the program plus its fixed leading
arguments:

    npm  ->  {{NPM_CMD}}
    node ->  {{NODE_CMD}}

Use those exact strings. A bare `npm` or `node` is a different program as far as
this box is concerned and will be refused.

Do all of this, in order:

1. `{{NPM_CMD}} init -y` in the project.
2. `{{NPM_CMD}} install left-pad` — it is a tiny package and the registry is
   permitted.
3. Write `pad.js` exporting a function `pad(s)` that left-pads `s` to width 5
   using `left-pad`, and `pad.test.js` using the built-in `node:test` module with
   one passing test.
4. Run the tests and write their full output to `test-out.txt`, with
   `{{NODE_CMD}} --test > test-out.txt 2>&1`.
5. Reply with the last line of `test-out.txt`.

Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
