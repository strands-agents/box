# Contributing to Strands Box

Thank you for your interest in contributing to the project.

## Setting up

This is a Cargo workspace. Install Rust with [rustup](https://rustup.rs/), then build from
the repository root:

```console
$ cargo build --workspace
```

`rust-toolchain.toml` pins the compiler version, and rustup installs it on the first build.
A default rustup install also gives you the `clippy` and `rustfmt` components the gates need.

To build only Box Core's release binaries:

```console
$ cargo build --release -p strands-box -p strands-box-containment
```

Run the compiled binary as `./target/release/strands-box`. Keep its helper
binaries in the same directory. To build and run `box` itself, see
[Working on the box CLI](#working-on-the-box-cli).

The sections below state what each test suite needs. [AGENTS.md](AGENTS.md) holds the repository
rules.

## Using AI tools

We accept code written by AI. So, we created an AI usage policy that explains how we think about this. 
Please read before contributing: [Strands AI usage policy](https://github.com/strands-agents/harness-sdk/blob/main/team/AI_USAGE_POLICY.md): 

- **You own every line.** Review and understand the whole change before you open the pull
  request, and be ready to explain why it works. The pull request template asks you to
  confirm this.
- **Speak for yourself.** Write the description in your own words. 
- **Start small.** If you are a new contributor, start small. Open an issue that explains
  the problem in your own words, then send one focused pull request. Please don't blast us
  with dozens of PRs at once. 

## Before you open a pull request

Prepare the dependency cache with `cargo fetch --locked` before running tests through
`just` or Cargo. Repeat this step after `Cargo.lock` changes or cached dependencies
are removed. The `shell_dependency_guard` tests inspect dependency sources without
network access. Their metadata query needs archives for all target platforms; a build
for the host platform alone may leave archives missing.

Run the gates with [`just`](https://github.com/casey/just):

```console
$ cargo fetch --locked
$ just check
```

That runs `just fmt-check`, `just clippy`, `just prose`, and `just test`. `just test` runs
`just build-cli` first, because the CLI's tests run the built binaries. Use the recipes rather than
writing the `cargo` calls yourself.
`just --list` shows every recipe. The common ones:

```sh
just build         # strands-box, the alias image, and the containment trampoline
just build-cli     # the box CLI and the Box Core binaries it runs
just test          # build-cli, then the workspace tests
just check         # pre-push gate: fmt-check + clippy + prose + test
just test-all      # workspace tests and box example checks
```

Notes on the test suites:

- **`--all-features` is not optional.** The `box_shell` and `box_credentials` suites sit
  behind the `test-support` feature, so a plain `cargo test` skips them and still reports
  success. `just test` passes the flag.
- **A test that cannot run on your host skips instead of failing.** Watch the output for
  `skipping:`, because a skipped test has proved nothing.
- **Linux continuous integration runs on Ubuntu ARM64 and x86-64 with namespace support.**
  Both architectures run the workspace tests without the former namespace exclusions and reject unexpected
  prerequisite skips. The accepted alias-read limitation and missing credential-daemon
  fixture remain explicit reported gaps.
  Local machines without the required architecture or permissions can still skip tests.
  Workspace and deterministic integration failures on either Linux architecture or macOS fail
  `CI Gate`.
- **Linux CI also checks the three native filesystem forwarding tests in a separate step.** See the
  [Linux native test guide](docs/dev/linux-native-tests.md#forwarding-buffer-tests) for that command
  and the other native test prerequisites.
- **Site manifest changes run a focused test.** In pull-request CI, changes to
  `docs/site-manifest.json`, `docs/site-manifest-retirements.json`, or a publishable page under
  `docs/user/` or `docs/cli/` run the focused site-manifest contract test instead of the full Rust
  test matrix. The test compares the base contract to keep the product ID stable and require an
  append-only retirement before a page or route is removed.

### History persistence

Continuous integration tests both history persistence modes on Linux x86-64, Linux ARM64,
and macOS. Default builds test batched crash recovery and verify that the idle timer saves
history before shutdown. The separate `--no-default-features` build also checks that recovery
retains every returned permit after the process is killed. Both modes refuse new requests
after the kill. These jobs run independently of the all-feature build.

Run the default checks locally with:

```sh
cargo build --locked -p strands-box -p strands-box-containment --bins
cargo test --locked -p strands-box --test box_killed_run -- --show-output
cargo test --locked -p strands-box --lib run::hosted::tests::hosted_idle_timer_flushes_pending_history_without_shutdown -- --exact --show-output
```

Run the per-event crash-recovery check with batching disabled in both commands:

```sh
cargo build --locked -p strands-box -p strands-box-containment --bins --no-default-features
cargo test --locked -p strands-box --no-default-features --test box_killed_run -- --show-output
```

On Linux, follow the namespace and launcher-image setup in the
history persistence steps of the [`unit-test` workflow job](.github/workflows/rust-test-lint.yml) before running the tests.

### Test the release downloader

Run `python3 -m unittest discover -s scripts -p 'test_*.py' -v` to test release packaging and the downloader.
Continuous integration runs the downloader tests on Linux and macOS. These tests use local fixture archives
and simulated HTTP clients; they do not qualify a published binary or its containment behavior.
The [release guide](docs/dev/releases.md#rehearse) describes the architecture, system-library, and packaged-workload checks for Linux ARM64 and x86-64.
Both Linux build jobs must pass the packaged-workload checks before publication.
On Linux, the mount test requires util-linux and permission to create a user and mount namespace.
It creates a `noexec` temporary mount only inside the test process's private namespace.

## Writing code

### Code style

This project follows the standard conventions that
[`rustfmt`](https://github.com/rust-lang/rustfmt) imposes, and it treats clippy warnings as
errors on owned code. Run `just fmt` to format, and `just clippy` to lint.

### Dependencies

Add a dependency to the crate's own `Cargo.toml`. A new dependency needs a call site in the
same change: the box holds secrets in process, so each added crate widens what that process
links.

### `strands-box` is interface-frozen

The `strands-box` verbs and flags, the `box.toml` keys, the broker protocol, and each mechanism
crate's public surface need explicit approval before they change, and a rename or an addition counts.
[AGENTS.md](AGENTS.md) lists every frozen surface and states what to do instead. If your change
needs one of them to move, say so in the pull request and name what breaks.

The box CLI under `crates/cli/` is not frozen.
[crates/cli/AGENTS.md](crates/cli/AGENTS.md#the-cli-is-not-interface-frozen) states what it
must not break.

## Reporting a problem

Open an issue on this repository. For a suspected security problem, read
[SECURITY.md](SECURITY.md) first and report it the way that file states.

## Working on the box CLI

The box CLI lives under `crates/cli/`, with its shipped packs, policies, and starters under
`resources/`. Read [crates/cli/AGENTS.md](crates/cli/AGENTS.md) before you change it. It holds
the rules for that area.

To build `box` from source, you need [Rust](https://rustup.rs/) and
[`just`](https://github.com/casey/just):

```sh
just build-cli    # box and the Box Core helpers, in target/debug
```

Keep the helpers in the same directory as `box`.
[docs/dev/manual-testing.md](docs/dev/manual-testing.md) shows how to run the build with a real
agent and model.

`just test-engine` builds the CLI and runs its suite that drives a real engine. `just prose`
checks the prose of the CLI's docs, and `just check` runs it.

Title the pull request as a conventional commit with a lowercase subject, such as
`fix(cli): refuse a profile with no agent`. The title becomes the commit on `main`.
[crates/cli/AGENTS.md](crates/cli/AGENTS.md#pull-request-title) lists the types and scopes.

A change ships with its docs. [crates/cli/AGENTS.md](crates/cli/AGENTS.md#docs) says which change updates which doc,
and [.agents/references/writing.md](.agents/references/writing.md) says how to write each one: plain
English for a person in `docs/cli/`, and precise engineering prose everywhere else. No em-dashes.

## Developer guides

- The [release guide](docs/dev/releases.md) covers version selection and publication for macOS, Linux ARM64, and Linux x86-64.
- The [macOS release guide](docs/dev/macos-release.md) covers the native-feature build,
  automated signing, notarization, package verification, and release gates.
- The [fuzzing guide](docs/dev/fuzzing.md) covers the long libFuzzer run of the tool grammar shell
  parser.
