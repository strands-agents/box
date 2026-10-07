# Debug an OS-specific CI failure

A test can pass on your machine and fail on the CI runner for the same commit. The cause is
almost always environment identity, not the code. The runner and your machine differ in some
value the box reads at startup: an active toolchain, a system path, a pointer file, or a library
location. This page gives a general method to find that value, and then a worked example on
macOS.

The method is generic. The containment layer denies by default on both platforms, so the same
class of failure appears on each. macOS uses Seatbelt, and you reproduce it with `sandbox-exec`
and read denials from the unified log. Linux uses the namespace launcher, and you reproduce it
with the trampoline or a minimal namespace and read denials from `dmesg`, `journalctl`, or an
`strace` of the seccomp refusal. Read the platform floor data for either case:
`crates/containment/src/containment-data/os-paths.macos.json` and its Linux sibling.

## Method

### 1. Reproduce locally first, at the exact CI commit

Check out the commit the runner tested. Run the failing test on your machine. You must establish
that the test passes locally and fails on the runner. That divergence is the whole signal. It
tells you the code is correct and the environment differs, so you stop reading the diff and start
reading the environment.

### 2. Build a no-build probe workflow on a fork

Add a small workflow that runs on one OS and builds nothing. It prints the environment identity
of the runner. On macOS the probe prints:

- `sw_vers`
- `xcode-select -p`
- `xcrun --find python3`
- `which -a python3`
- `readlink` of `/var/select/developer_dir` and `/var/db/xcode_select_link`
- `DEVELOPER_DIR`
- `otool -L` of the interpreter
- `python3 -c 'import sys,os; print(sys.executable, os.path.realpath(sys.executable))'`

On Linux the equivalent probe prints `uname -a`, the distribution release, `which -a python3`,
`readlink -f` of the interpreter, `ldd` of it, and the mount and namespace state the launcher
sees.

Two constraints govern the fork:

- A pull request from a fork runs the **base** repository's workflow, not the fork's. An edit to
  the workflow takes effect only after it merges, or through a manual dispatch on the fork.
- `workflow_dispatch` needs the workflow file on the fork's **default** branch to be dispatchable.
  Push the probe to the default branch of your fork first, then dispatch it.

The probe answers one question: what does the runner's environment hold that yours does not?

### 3. Build a faithful sandbox or namespace oracle

The probe shows the difference. Now prove that difference causes the failure. Build the smallest
containment that reconstructs the box's floor by hand.

On macOS, write a `sandbox-exec` profile from the platform floor data: the `agent` and `leaf`
cells in `os-paths.macos.json`, plus the active developer directory that the failing tool's own
`read` list grants. Validate the oracle locally first: it must start the interpreter,
which matches the box's local pass. Then run the same oracle on the runner. It must fail, which
reproduces the box's runner failure. Capture the exact `dyld` or sandbox denial.

On Linux, reconstruct the launcher's namespace and bind set by hand, or run the trampoline
directly, and capture the seccomp or mount denial.

A faithful oracle is the point. If your oracle passes locally and fails on the runner with the
same denial the box gives, you hold the cause. If it passes on both, your reconstruction is not
faithful and you go back to the floor data.

### 4. Read the denials

Read the denial from the platform's own log, not from the test's timeout.

- macOS: `sudo log show --style syslog --last 3m --predicate 'eventMessage CONTAINS "deny"'`.
- Linux: `dmesg`, `journalctl`, or an `strace` of the process that shows the refused syscall.

### 5. Falsify hypotheses one at a time

You now have a denial and an oracle. Change one grant, run the oracle on the runner, and read the
log. Do not change two things at once. For the macOS example the sequence was: is the wrong
directory granted; is a pointer read missing; is a standard-library read missing; does granting
the whole bundle fix it; then, does switching the active developer directory fix it. Each step is
one edit and one run.

### 6. Confirm with a scoped real-box dispatch

When the oracle tells you the fix, confirm it with the real box on CI, scoped to one OS and a
subset of tests. `full-tests.yml` surfaces three inputs for this: `filter` (a substring of the
cargo test name), `os` (a choice that drives the matrix), and `lint` (a toggle). So:

```sh
gh workflow run full-tests.yml -f ref=<sha> -f os=macos-latest -f lint=false -f filter=<substring>
```

Two notes on the scope:

- `filter` matches test **names**, not test-binary names.
- Build time does not shrink with `filter`, because the build is `--all-targets` for the
  trampoline. The saving comes from one OS instead of the matrix, no lint, and far fewer tests
  that execute.

## Worked example: the contained MCP leaf on `macos-latest`

At commit `ffb8197e`, every contained-MCP-leaf test failed on the GitHub `macos-latest` runner
and passed on a local Mac. The test binaries were `runtime_mcp_policy_staging` and
`native_egress_mcp`. Each starts a `#!/usr/bin/python3` tool as a leaf, waits for the tool to
write a `.started` marker, and times out at the eight-second startup deadline
(`native_egress_mcp.rs` `STARTUP`).

**Root cause.** `/usr/bin/python3` on macOS is Apple's `libxcselect` shim, not an interpreter. It
re-execs into the developer directory that `xcode-select` makes active.

- On the local Mac the active directory is the Command Line Tools at
  `/Library/Developer/CommandLineTools`. Its `python3` is a self-contained `Python3.framework/3.9`.
  The tool's own `read` grant on the developer directory covers that framework, so the leaf
  launches, and the `leaf` cell of `os-paths.macos.json` supplies the rest.
- On the `macos-latest` runner the active directory is a full `Xcode.app`, such as
  `/Applications/Xcode_26.6.app/Contents/Developer`. Under a full Xcode the shim delegates to
  `xcodebuild` to resolve the toolchain. That path needs three things a deny-default leaf does not
  give it: the frameworks in `Xcode.app/Contents/SharedFrameworks`, which is a sibling **above** the
  granted `Contents/Developer`; a writable `xcrun_db` cache, which the leaf denies, so the shim
  re-runs `xcodebuild` on every call; and Xcode license acceptance. The leaf provides none of them,
  so the leaf dies before Python runs a line, never writes `.started`, and the harness times out.

The `no_containment_reaches_the_developer_directory` test in `os_paths.rs` pins that neither
runtime set reaches the active developer directory, so a tool grants it in its own table. The
`a_leaf_carries_broad_exec_and_the_main_box_does_not` test in the macOS Seatbelt backend pins the
leaf's exec carve-out. Neither test observes the runner's full-Xcode environment, so the suite is
green locally and the runner is not.

**The fix is CI-environment only.** One line in the macOS test job, before the build, makes
`/usr/bin/python3` take the self-contained Command Line Tools path the box already grants:

```sh
sudo xcode-select -s /Library/Developer/CommandLineTools
```

This was validated end to end through the method above: the hand-built oracle failed on the
runner with the `Xcode.app` active directory and passed once the active directory was the Command
Line Tools, and a scoped `full-tests.yml` dispatch then passed the real leaf tests on
`macos-latest`.

**This is not a product fix, and it does not close the product gap.** A box on a Mac with a full
Xcode active still cannot run a `#!/usr/bin/python3` tool as a leaf. That gap is real and
freeze-gated, and the macOS-containment owner owns it. The CI line only selects an environment the
box already supports so the CI signal measures the code under test rather than the runner's
toolchain layout.
