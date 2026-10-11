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

Run the gates with [`just`](https://github.com/casey/just):

```console
$ just check
```

That runs `just fmt-check`, `just clippy`, and `just test`. Use the recipes rather than
writing the `cargo` calls yourself: `just clippy` carries the lint allowances the vendored
`strands-shell` needs, and the bare `cargo clippy ... -D warnings` fails on that crate.
`just --list` shows every recipe.

Three notes on the test suites:

- **`--all-features` is not optional.** The `box_shell` and `box_credentials` suites sit
  behind the `test-support` feature, so a plain `cargo test` skips them and still reports
  success. `just test` passes the flag.
- **A test that cannot run on your host skips instead of failing.** Watch the output for
  `skipping:`, because a skipped test has proved nothing.
- **On Linux, some containment tests need capabilities an ordinary host refuses.**
  Continuous integration skips that set by name, which
  `.github/workflows/rust-test-lint.yml` lists. A failure in one of those on your own
  machine is the host, not your change.

## Writing code

### Code style

This project follows the standard conventions that
[`rustfmt`](https://github.com/rust-lang/rustfmt) imposes, and it treats clippy warnings as
errors on owned code. Run `just fmt` to format, and `just clippy` to lint.

The vendored crate under `crates/shell/` carries upstream clippy warnings that we do not fix
here. `just clippy` allows exactly those lints at the driver level, which is why it is the
command to run.

### Dependencies

Add a dependency to the crate's own `Cargo.toml`. A new dependency needs a call site in the
same change: the box holds secrets in process, so each added crate widens what that process
links.

### `strands-box` is interface-frozen

The CLI verbs and flags, the `box.toml` keys, the broker protocol, and each mechanism crate's
public surface need explicit approval before they change, and a rename or an addition counts.
[AGENTS.md](AGENTS.md) lists every frozen surface and states what to do instead. If your change
needs one of them to move, say so in the pull request and name what breaks.

## Reporting a problem

Open an issue on this repository. For a suspected security problem, read
[SECURITY.md](SECURITY.md) first and report it the way that file states.
