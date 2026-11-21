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

[README.md](README.md) states what each test suite needs, and how to install a local `box`
command. [AGENTS.md](AGENTS.md) holds the repository rules.

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
`just --list` shows every recipe.

Three notes on the test suites:

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
