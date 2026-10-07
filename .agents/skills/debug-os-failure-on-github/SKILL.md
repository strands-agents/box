---
name: debug-os-failure-on-github
description: Debug a CI failure on an OS you are not on (you are on Linux, it fails on macos-latest, or the reverse) without opening a pull request per attempt. Use when a test is green on your machine and red on a GitHub runner, or when you need to run one test or one shell probe on a runner and read the result fast. The core move is a dispatchable, scoped workflow on your own fork: pick one OS, skip lint, filter to one test, and for environment questions run a no-build probe that returns in seconds instead of a ten-minute build. Iterate by pushing to the fork branch and re-dispatching, never by editing a PR.
---

# Debug a CI failure on an OS you are not on

You are on Linux and a test fails only on `macos-latest` (or you are on a Mac and it fails only on
`ubuntu-latest`). The slow way is a pull request per attempt: each push reruns the whole matrix,
builds everything, and takes about fifteen minutes to tell you one thing. Do not do that.

The fast way is a **dispatchable workflow on your own fork**, scoped to the smallest run that
answers your question. You iterate by pushing to a fork branch and re-dispatching. No pull request
is involved until you have the answer.

## The two things that make it fast

1. **Scope the run.** Do not run the matrix, the lint job, and the whole suite to learn one test.
   Run one OS, no lint, and one test. `full-tests.yml` takes three inputs for exactly this:

   ```sh
   gh workflow run full-tests.yml -f ref=<branch|sha> -f os=macos-latest -f lint=false -f filter=<substring>
   ```

   - `os` picks a single runner (`macos-latest`, `ubuntu-latest`, or `both`).
   - `lint=false` skips fmt and clippy.
   - `filter` is a substring of the cargo **test name** (not the test-binary name). It runs only the
     tests whose name matches.
   - Build time does not shrink with `filter` (the build is `--all-targets` for the trampoline). The
     saving is one OS instead of two, no lint, and far fewer tests that execute. To also cut build
     time, scope the build in a throwaway workflow with `--test <binary>` or `-p <crate>`.

2. **For an environment question, build nothing.** Most "green here, red there" failures are the
   environment, not the code: a different active toolchain, a different system path, a pointer file,
   a library location. A workflow that only runs shell commands returns in about fifteen seconds, so
   you can ask five questions in the time one build takes. Print what you suspect differs:

   - macOS: `sw_vers`, `xcode-select -p`, `xcrun --find <tool>`, `which -a <tool>`, `otool -L <bin>`,
     `readlink` of any pointer files, the relevant env vars, and for an interpreter
     `python3 -c 'import sys,os; print(sys.executable, os.path.realpath(sys.executable))'`.
   - Linux: `uname -a`, the distribution release, `which -a <tool>`, `readlink -f <bin>`, `ldd <bin>`,
     and the mount or namespace state that matters.

## Two fork rules, or the dispatch fails

- A pull request from a fork runs the **base** repository's workflow, not your fork's copy. So a
  workflow edit on a fork branch does nothing on a PR. It only takes effect through a manual
  dispatch on the fork (or after it merges to the base).
- `workflow_dispatch` needs the workflow file on the fork's **default** branch to be dispatchable at
  all. Push the workflow to the fork default branch once; after that you can dispatch it against any
  branch or sha with `-f ref=...`.

## The loop

1. Confirm the divergence: check out the exact CI commit, run the test locally, see it pass. Now you
   know the code is fine and the environment differs. Stop reading the diff.
2. Push a no-build probe workflow to your fork default branch. Dispatch it. Read what the runner's
   environment holds that yours does not.
3. Form one hypothesis. Test it with the smallest scoped run: one OS, no lint, one filtered test, or
   the probe with one more command. Change **one** thing per run.
4. Read the result. `gh run watch <id>`, or `gh api repos/<owner>/<fork>/actions/jobs/<jobid>/logs`
   for the raw log. The runner's own log names the cause; do not infer it from a test timeout.
5. When a run confirms the fix, land it and do one final scoped dispatch to prove it green.

## When the failure is containment (deny-default box)

If the failing test starts a contained workload and it dies at startup (a leaf launch, a Seatbelt or
namespace refusal, a startup-marker timeout), the environment difference is usually a path the box's
floor does not grant on the runner. Two extra moves apply, and the full method plus a worked example
(the macOS `/usr/bin/python3` xcode-select leaf) live in
[docs/dev/debug-os-specific-ci-failures.md](../../../docs/dev/debug-os-specific-ci-failures.md):

- Reproduce the box's floor by hand. On macOS write a `sandbox-exec` profile from the `agent` and
  `leaf` cells in `crates/containment/src/containment-data/os-paths.macos.json`; on Linux
  reconstruct the launcher's binds or run the trampoline directly. Validate the reconstruction
  passes locally before you trust its runner failure.
- Read the kernel's own denial, not the test's timeout: on macOS
  `sudo log show --style syslog --last 3m --predicate 'eventMessage CONTAINS "deny"'`; on Linux
  `dmesg`, `journalctl`, or an `strace` of the refused syscall.
