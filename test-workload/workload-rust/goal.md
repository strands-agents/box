# Workload: a Rust crate — cargo build, cargo test, commit

The project directory is `{{PROJECT}}`. Two host programs are authorized, and you
must spell both in full:

    cargo -> {{CARGO}}
    git   -> {{GIT}}

Do all of this, in order:

1. `{{CARGO}} init --lib --name boxdemo` in the project.
2. Replace `src/lib.rs` with a public function `pub fn add(a: i32, b: i32) -> i32`
   returning `a + b`, plus a `#[cfg(test)] mod tests` with one test asserting
   `add(2, 2) == 4`.
3. Build it: `{{CARGO}} build > build-out.txt 2>&1`, then reply-worthy proof is in
   that file. The build must succeed.
4. Run `{{CARGO}} test > test-out.txt 2>&1`. On this host the test link step may
   fail; if it does, leave the output in `test-out.txt` and continue. Do not try
   to change the linker or install anything.
5. `{{GIT}} init`, then add everything except the build directories and commit
   with the message `rust workload`. Write `{{GIT}} log --oneline` output to
   `gitlog.txt`.
6. Reply with the last line of `build-out.txt`.

Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
