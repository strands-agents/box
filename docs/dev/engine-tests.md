# The engine suite

`crates/cli/app/tests/engine.rs` runs `box run` against a real Box Core, so a change that reaches
`box.toml` or `policy.dw` is proven against the engine and not only against the unit tests.

## Run it

```sh
just test-engine
```

`just test-engine` runs `just build-cli` first. `just build-cli` puts `box`, Box Core's
`strands-box`, `strands-box-sock-alias`, and `strands-box-contain-trampoline` in `target/debug`.
Linux also builds `strands-box-storage-compiler` there.
A missing helper fails the suite. `just check` runs the suite too, through `just test`.

The suite runs with `PATH=/usr/bin:/bin`, so on macOS `the_agent_runs_git_through_the_git_pack`
runs `git` through Apple's `/usr/bin/git` stub. The CI `macos` job checks that `xcode-select -p`
names full Xcode before it runs the suite, because the stub fails in a box only with full Xcode.
To test the Command Line Tools case on a Mac that has both, run
`sudo xcode-select -s /Library/Developer/CommandLineTools` first.

## `BOX_ENGINE`

`box_core_accepts_and_starts_each_detected_mcp_server` also runs
`<engine> policy generate-schema --config <run>/box.toml` on the run's config. The engine is
`$BOX_ENGINE` when it is set, else `target/debug/strands-box`. Set `BOX_ENGINE` to check the
config against another Box Core build, such as a release binary:

```sh
BOX_ENGINE=~/box-core/box cargo test -p strands-box-cli --all-features --test engine
```

A `BOX_ENGINE` that names no file fails the test. With no `BOX_ENGINE` and no
`target/debug/strands-box`, the test prints `skipping: ...` after its `box run` half and passes.

## git tests

The `box_git_*` tests run `@box/git` with the first `git` on the test's `PATH` and the test's
`HOMEBREW_PREFIX`, so a missing git fails them. On macOS that must be Homebrew git, under
`HOMEBREW_PREFIX` or `/opt/homebrew`: Apple's `/usr/bin/git` stub cannot start Xcode's
git in a box, so it fails every git test. The GitHub macOS runner has Homebrew git first on
`PATH`.

## Launcher tests

The four `*_downloads_into_profile_storage_and_lists_tools` tests run real `npx`, `uvx`, `bunx`,
and `pnpx` servers. Install Node.js with npm, Python 3, uv, Bun, and pnpm, and put their programs
on `PATH`. Missing launchers fail these tests. CI installs the same prerequisites before the
Linux and macOS engine suites. The Linux job installs pnpm, Bun, and uv in its temporary
launcher directory and exports their executable directories through `GITHUB_PATH`.
The tests download pinned MCP packages from the public npm registry and PyPI, so
registry access is required.

`an_absolute_mcp_command_imports_its_filename_and_starts_the_selected_server` selects an
executable outside `PATH`, through a symlink in a directory with a space. It puts a different
executable with the same name on `PATH`. It imports the filename, checks initialization and a
tool call, and verifies the exact Core command, private environment, canonical policy path, and
unchanged host configuration.

`an_mcp_server_starts_through_a_local_npm_bin_link` uses an offline server behind an npm-style
`node_modules/.bin` link, inside and outside the temporary home. It checks bare and absolute
commands, preserves the invocation path, and reads sibling packages and other files inside the
installation tree. It refuses writes to that tree and reads outside it. This covers the
local-prefix layout without a registry download.

`an_mcp_alias_in_a_system_directory_keeps_the_configuration_valid` puts an executable link
directly in `/tmp` on macOS. It checks that Core loads the configuration and the server keeps
its command, with no additional directory listing that Core refuses.

CI selects Node 22.22.2 and npm 10.9.7 in the `macos` job. It keeps that Node install ahead
of Homebrew on `PATH`, while Python comes from Homebrew. This fixes the npm baseline used by
the tests; it does not establish compatibility with the npm version bundled on the runner.
CI runs the Linux unit tests on the org's four-core runner upstream and on Ubuntu 24.04 in forks.

Bun's npm installer hard-links `bun.exe` and `bunx.exe`, and CI keeps that layout, so the bunx
tests run Box Core's check of a command with several names.

The passing launcher checks include these combinations:

| Launcher | Runtime | Coverage |
| --- | --- | --- |
| npm 10.9.7 | Node 22.22.2 | CI baseline |
| npm 10.9.9 | Node 22.23.4 | Bundled npm on oldest maintained Node LTS line |
| pnpm 10.34.9 | Node 22.22.2 | CI baseline |
| pnpm 10.34.9 | Node 22.23.4 | Oldest supported pnpm major |
| pnpm 12.16.1 | Node 24.22.1 | Native launcher |
| uv 0.13.5 | CI-installed Python | Observed CI run |
| uv 0.13.7 | Python 3.14.3 | Homebrew Python |
| uv 0.13.7 | Python 3.11.18 | Oldest maintained Python line, uv-managed layout |
| Bun 1.4.4 | Node 22.22.2 | CI baseline |
| Bun 1.4.4 | Node 22.23.4 | Oldest maintained Node LTS line |

The lower-runtime checks select a current patch from the oldest maintained
[Node LTS line](https://github.com/nodejs/Release#release-schedule) and
[Python line](https://peps.python.org/pep-0664/): Node 22 and Python 3.11.
[pnpm's support policy](https://github.com/pnpm/pnpm/blob/main/SECURITY.md) includes major 10.
Bun and uv publish no separate LTS track in their
[Bun support](https://github.com/oven-sh/bun/blob/main/SECURITY.md) and
[uv versioning](https://docs.astral.sh/uv/reference/policies/versioning/) policies.
Their rows record exact working versions, not a minimum working patch.

Python 3.11 uses uv's standard `uv/python/<installation>/bin` layout. A custom installation
outside that layout can need explicit runtime read grants; the interpreter's `bin` directory
alone does not contain its standard library.

These measurements cover macOS arm64. The
[initial compatibility scope](../design/cli/decisions.md#launcher-compatibility-claims-name-tested-versions-and-runtimes)
also targets Node 26.13.0 with bundled npm 11.20.0 and with npm 12.2.1; those combinations have
no result yet. These checks establish no coverage for pnpm 11 or other Python versions.

Local checks also pass with uv 0.10.11. Bun 1.3.4 fails while it inspects the current directory
inside the sandbox. Use Bun 1.4.4 for this suite. The uv pack uses an installed Python and
disables Python downloads.

Run a selected version with its launcher directory and runtime directory first on `PATH`:

```sh
cargo test --locked -p strands-box-cli --all-features --test engine \
  uvx_downloads_into_profile_storage_and_lists_tools -- --exact --nocapture
cargo test --locked -p strands-box-cli --all-features --test engine \
  pnpx_downloads_into_profile_storage_and_lists_tools -- --exact --nocapture
```

These are finite version checks. The macOS CI job pins Node, npm, pnpm, and Bun; uv and
Python come from Homebrew without version pins. The Linux job pins pnpm 10.34.9, Bun 1.4.4,
and uv 0.13.7; Node, npm, and Python come from the runner. Passing CI does not establish
compatibility with untested launcher or runtime releases.

The `npx` test fails with npm 11.19.1 on Node 22.22.2 and Node 24.22.1 on macOS. Its lock
refresh calls `utimensat`, which Box Core's write policy refuses. The same policy permits
`utimes`. npm 12.2.1 on Node 24.22.1 also fails with `ECOMPROMISED: Lock compromised`.
npm 11.19.1 on Node 22.16.0 passes. See [`@box/npx` limitations](../../resources/packs/npx/README.md#limitations) for the
working npm and Node pair.

To run only these tests:

```sh
cargo test -p strands-box-cli --all-features --test engine downloads_into_profile_storage -- --nocapture
```

Each test starts with an empty temporary home and cache. It checks initialization, a named tool
in `tools/list`, the cache in profile storage, and the absence of writes to the operator's package
caches. The agent's config has no launcher-cache grant. A run has a 180-second deadline. The
MCP probe stops when its launcher exits and preserves the exit status; a successful exit without
the expected replies also fails. Its offline regression uses a five-second bound. The
launcher settings and script-helper grants must work without a wrapper or a hand-written MCP table.

Each `*_launcher_tool_downloads_and_runs_a_command` test imports an ordinary tool pack.
The JavaScript checks run `semver@7.7.4` through npx, pnpx, and bunx. The uvx check runs the
pinned time server's `--help`. The command goes through the agent's hosted shell. Each tool must populate its
workspace cache without writing to the operator's package caches. The small CLI fixture
needs no large dependency download.
`a_launcher_tool_and_mcp_server_use_separate_caches` runs pnpx in both contexts in one profile.
It checks the direct command, MCP `tools/list`, and both cache locations.
`an_operator_permit_on_the_home_does_not_open_a_launcher_cache` gives a profile with an `npx`
server an operator `fs:write` permit on `~/*`. The Shell's write in the server's launcher cache
must get `box_home_write`, and its write elsewhere in the home must pass. The server starts on
demand, so the test downloads nothing, but it needs `npx` and `node` on `PATH`.

```sh
cargo test -p strands-box-cli --all-features --test engine launcher_tool -- --nocapture
```

The version matrix above records MCP checks. Direct tool checks use npm 10.9.7 on Node 22.22.2,
pnpm 10.34.9 on Node 22.22.2, native pnpm 12.16.1 on Node 24.22.1, Bun 1.4.4 on Node 22.22.2,
and uv 0.13.7 on Python 3.14.3.

The pnpx scratch-directory regression prepares both consumers without running pnpm. It checks
that the direct tool's temporary directory exists before the workspace cache and that the MCP
server uses its separate, prepared cache.

Local npm-prefix checks use pnpm 10.34.9 through `node_modules/.bin` with Node 20.19.0 and
22.22.2. The direct, MCP, and combined cache checks pass with each runtime.

## The pi shell extension

`crates/cli/app/tests/pi_box_shell.rs` runs `resources/packs/pi/box-shell.ts` in a real pi, outside a
box, on any host. A faux model from `@earendil-works/pi-ai` makes pi call its bash tool, and an RPC
`bash` command runs a `!` command. The test checks that both start `BOX_SHELL_PATH`, that a
trusted project's `shellPath` changes neither and its `shellCommandPrefix` still runs, and that
`--no-builtin-tools` and `--tools` turn the tool off. It uses `$PI_BINARY`, else the first `pi` on
`PATH`. With none it skips with a message, unless `BOX_REQUIRE_PI` is set, and then it fails. The
CI `macos` job sets it and installs the pi version that `resources/packs/pi/pack.toml` names. To run it, install pi
with `npm install -g --ignore-scripts @earendil-works/pi-coding-agent@1.5.2`.

## Incoming Linux storage tests

The CLI's `storage_mounts` tests start real profiles before attaching a filesystem through
Filesystem in Userspace (FUSE). Core's `runtime_storage_mounts` tests also cover storage attached
before startup and two roots arriving in either order. Both suites require native Linux user
and mount namespaces, a usable `/dev/fuse`, `mount`, `umount`, `unshare`, and `ip`. Their FUSE
cases are ignored by ordinary test runs. Run them explicitly; a missing fixture fails the test.

Run the following commands from the repository root. Build the trusted passthrough fixture
with a C compiler, `pkg-config`, libfuse 3 development headers, and its library:

```sh
cc -D_FILE_OFFSET_BITS=64 -std=c11 -Wall -Wextra -Werror -O2 \
  $(pkg-config --cflags fuse3) crates/cli/app/tests/support/storage_fixture.c \
  $(pkg-config --libs fuse3) -o /tmp/boxy-storage-fixture
```

Build the CLI, Core, and their helpers from the same source revision. `--all-features` includes
Core's `test-support` feature, which builds the test-only `box-storage-probe`. This command also
builds `strands-box-storage-compiler` beside the CLI and Core binaries. The explicit target
directory keeps the probe path aligned with Cargo output:

```sh
export CARGO_TARGET_DIR="$(pwd)/target"
cargo build --locked -p strands-box -p strands-box-cli -p strands-box-containment \
  --all-features --bins
export BOX_STORAGE_TEST_FUSE=/tmp/boxy-storage-fixture
export BOX_STORAGE_TEST_PROBE="$CARGO_TARGET_DIR/debug/box-storage-probe"
```

Run the Core tests, then the CLI tests. `--include-ignored` runs ten Core FUSE cases,
six CLI FUSE cases, and each suite's ordinary control that distinguishes a reaped child from
a live child. Core also starts pending storage directly as the host user, without the FUSE fixture's
outer user namespace. That test requires a non-root user and reports a skip when run as root.
Run the suites serially:

```sh
cargo test --locked -p strands-box --all-features --test runtime_storage_mounts \
  -- --include-ignored --test-threads=1 --nocapture
cargo test --locked -p strands-box-cli --all-features --test engine storage_mounts:: \
  -- --include-ignored --test-threads=1 --nocapture
```

Each FUSE test creates its own user, mount, process, and network namespaces. The CLI cases
attach storage only after observing the original process's pending marker. The three-role case checks an
agent, a program-resolved tool, and a local Model Context Protocol (MCP) server. The failure case
requires all observed Box-owned processes to exit when a required denial cannot be applied.

Core also tests the first storage read without retries in the agent, three sequential tool launches,
and a local server. One source is mounted before Box starts; a second source stays absent. Another case mounts
storage after the agent starts and before it launches its tools and server.
The three-role test checks that concurrent recipients share one acquisition worker per distinct
source while retaining their separate filesystem permissions.

The file case checks exact-file read and write grants, a hidden subtree, a canonical-directory write
denial, and allowed versus denied execution. A separate test requires Core to reject a mutable
symbolic link used as a write-denial target. Source-side positive controls prove that the
filesystem itself permits the operations Box refuses. The hosted case starts one Shell before
attachment and checks pending paths through both Shell and Monty. After native access succeeds,
that same Shell runs allowed and denied file operations through both interpreters. Each
interpreter also checks metadata and lists a directory containing only two granted files;
the ungranted sibling must remain absent. A separate
file is native-readable and native-writable but has explicit hosted policy denials; each
interpreter must produce the corresponding recorded policy decisions. Ordinary sibling
operations must succeed, and the exact generated rule must deny moving a protected ancestor.
A kernel refusal to move a mount is insufficient evidence for that policy check.

The hosted failure case keeps a Shell program and one Monty evaluation active before
attachment. Both must perform pending read and write checks and acknowledge a challenge.
The incoming source omits a required denial path. The test requires the specific rule
compilation error, shutdown within 15 seconds, no successful read or write markers, and
no remaining observed processes or fixture mounts. A hosted timeout does not satisfy it.

The tests do not cover every storage provider, remount behavior, or macOS. Fixture output is
captured in temporary files so a noisy FUSE request log cannot fill a process pipe.
