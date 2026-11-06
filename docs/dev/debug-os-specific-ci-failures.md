# Debug an OS-specific CI failure

A test can pass locally and fail on the continuous integration runner for the same commit.
Investigate differences in startup conditions, such as the active toolchain, system paths, pointer
files, and library locations. This page gives a method to isolate those differences and a macOS
example. A difference between environments can expose a code defect.

Operating system enforcement denies access by default on both platforms, so either can have
this class of failure. macOS uses Seatbelt, and you reproduce it with `sandbox-exec`
and read denials from the unified log. Linux uses the namespace launcher, and you reproduce it
with the trampoline or a minimal namespace and read denials from `dmesg`, `journalctl`, or an
`strace` of the seccomp refusal. Read the platform data for either case:
`crates/containment/src/containment-data/os-paths.macos.json` and its Linux sibling.

## Method

### 1. Reproduce locally first, at the exact CI commit

Check out the commit the runner tested. Run the failing test on your machine. You must establish
that the test passes locally and fails on the runner. The difference shows that the failure depends on conditions that differ between the local system
and the runner. Investigate those conditions before choosing a fix.

### 2. Build a no-build probe workflow on a fork

Add a small workflow that runs on one OS and builds nothing. It prints the runner settings and paths. On macOS the probe prints:

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

Compare the output with the same values from your local system.

<a id="3-build-a-faithful-sandbox-or-namespace-oracle"></a>
### 3. Reproduce the sandbox or namespace restrictions

Use the probe results to identify a candidate cause. Build a minimal sandbox that reproduces
Box's required system access, then test whether the difference causes the failure.

On macOS, write a `sandbox-exec` profile from the platform data: the `agent` and `leaf`
cells in `os-paths.macos.json`, plus the active developer directory that the failing tool's own
`read` list grants. Validate the test sandbox locally first. It must start the interpreter,
which matches the box's local pass. Then run the same test sandbox on the runner. It must fail, which
reproduces the box's runner failure. Capture the exact `dyld` or sandbox denial.

On Linux, reconstruct the launcher's namespace and bind set by hand, or run the trampoline
directly, and capture the seccomp or mount denial.

The test sandbox must reproduce the Box result on both systems. A local pass and the same
runner denial isolate the failure for further tests. If it passes on both, compare its restrictions
with the platform data and correct the reconstruction.

### 4. Read the denials

Read the denial from the platform's own log, not from the test's timeout.

- macOS: `sudo log show --style syslog --last 3m --predicate 'eventMessage CONTAINS "deny"'`.
- Linux: `dmesg`, `journalctl`, or an `strace` of the process that shows the refused syscall.

<a id="5-falsify-hypotheses-one-at-a-time"></a>
### 5. Test one possible cause at a time

Change one grant, run the test sandbox on the runner, and read the denial log. Do not change two things at once. The macOS example checked the granted directory, pointer-file reads, and standard-library reads
in separate runs. Later runs tested access to the whole bundle and a different active developer
directory. Each step changed one condition.

<a id="6-confirm-with-a-scoped-real-box-dispatch"></a>
### 6. Confirm with a limited Box test run

After the test sandbox confirms a candidate fix, test the change with Box on one CI operating
system and a subset of tests. `full-tests.yml` accepts `filter` for a substring of a test name,
`os` for the operating system, and `lint` to enable or disable lint checks:

```sh
gh workflow run full-tests.yml -f ref=<sha> -f os=macos-latest -f lint=false -f filter=<substring>
```

Two notes on the scope:

- `filter` matches test **names**, not test-binary names.
- Build time does not shrink with `filter`, because the build is `--all-targets` for the
  trampoline. The run saves time by selecting one OS, disabling lint checks, and running fewer tests.

<a id="worked-example-the-contained-mcp-leaf-on-macos-latest"></a>
## Worked example: an MCP server on `macos-latest`

At commit `ffb8197e`, every contained-MCP-leaf test failed on the GitHub `macos-latest` runner
and passed on a local Mac. The test binaries were `runtime_mcp_policy_staging` and
`native_egress_mcp`. Each starts a `#!/usr/bin/python3` tool in its own sandbox, waits for the tool to
write a `.started` marker, and reaches the eight-second startup deadline defined by `STARTUP` in `native_egress_mcp.rs`.

`/usr/bin/python3` on macOS is Apple's `libxcselect` shim. It starts the program in the developer
directory that `xcode-select` selects.

- On the local Mac the active directory is the Command Line Tools at
  `/Library/Developer/CommandLineTools`. Its `python3` is a self-contained `Python3.framework/3.9`.
  The tool's own `read` grant on the developer directory covers that framework, so the tool starts, and the `leaf` cell of `os-paths.macos.json` supplies the rest.
- On the `macos-latest` runner the active directory is a full `Xcode.app`, such as
  `/Applications/Xcode_26.6.app/Contents/Developer`. Under a full Xcode the shim delegates to
  `xcodebuild` to resolve the toolchain. That path needs access to `Xcode.app/Contents/SharedFrameworks`, a sibling of the granted
  `Contents/Developer`. It also needs a writable `xcrun_db` cache and Xcode license acceptance.
  The sandbox refuses the cache write, so the shim runs `xcodebuild` on every call. The sandbox
  provides none of these requirements. The process exits before Python starts or writes `.started`,
  and the test harness reaches its deadline.

The `no_containment_reaches_the_developer_directory` test in `os_paths.rs` checks that neither
runtime set reaches the active developer directory, so a tool grants it in its own table. The
`a_leaf_carries_broad_exec_and_the_main_box_does_not` test in the macOS Seatbelt backend checks the broader execution access for a tool's sandbox. Neither test observes the runner's full-Xcode environment, so the suite passes locally and fails on the runner.

The fix changes the CI environment. Before the build, add this line to the macOS test job.
It makes `/usr/bin/python3` use the self-contained Command Line Tools path Box already grants:

```sh
sudo xcode-select -s /Library/Developer/CommandLineTools
```

The test sandbox failed on the runner with the `Xcode.app` active directory. It passed after
selecting the Command Line Tools. A scoped `full-tests.yml` dispatch then passed the Box tests on
`macos-latest`.

A box on a Mac with full Xcode active still cannot run a `#!/usr/bin/python3` tool in its own
sandbox. The macOS containment owner must address this limitation under the interface freeze.
The CI change selects an environment Box already supports, so the tests can evaluate changes
without this toolchain failure.
