---
reader: Someone who wants to install Box, upgrade it, pick another release, or remove it, usually before or after Get started.
belongs: Installing, upgrading, pinning, and removing box, what the installer puts on the computer, and the installer's variables. Creating a profile and the first run go to getting-started.md, the rest of ~/.strands/box to files.md, the BOX_* variables that box itself reads to cli.md, and how Linux differs from a Mac to limitations.md.
---

# Install Box

Until a release of `box` is published from this repository, build it from source, as
[Install](#install) shows. The rest of this page describes the installer that comes with that
release: it downloads a Box release from GitHub, checks it, and puts `box` on your `PATH`. On
macOS, the checks include Apple's signing and notarization.

## Requirements

An Apple Silicon Mac with macOS 15 or later, and the [GitHub CLI](https://cli.github.com/).
On ARM64 Linux, you need glibc 2.34 or later, `libgcc`, Python 3, the GitHub CLI,
and GNU utilities (`coreutils`, `diffutils`, `findutils`, `tar`, `gzip`, `awk`, `sed`, and `grep`).
See [How Linux differs](limitations.md#how-linux-differs) for what is different from a Mac.
The installer refuses Intel Macs, older macOS versions, and other Linux architectures.

To build from source, you also need [Rust](https://rustup.rs/) and
[`just`](https://github.com/casey/just). You don't need sudo.

Install your agent, such as Claude Code, and set up its credentials first. The installer does
neither.

## Install

Build `box` and the Box Core helpers it runs, and put them on your `PATH`:

```sh
git clone https://github.com/strands-agents/box.git
cd box
just build-cli
export PATH="$PWD/target/debug:$PATH"
```

The build is in `target/debug`, and it uses the packs and starters in the checkout's `resources/`.
The `export` lasts only in this terminal, so add `target/debug` to your `PATH` in your shell's
startup file to keep it. [CONTRIBUTING.md](../../CONTRIBUTING.md) has more on building from source.

Once releases are published here, the installer replaces these steps. Example output on a Mac:

```text
Downloading box-cli-v0.2.0-aarch64-apple-darwin.tar.gz...
Verified checksum, archive, and Apple signature
Installed box 0.2.0.
Added box to $PATH in /Users/you/.zshrc
Open a new terminal, or run: export PATH="$HOME/.local/bin:$PATH"

box run <profile>       # Start an agent in a box, from your project
box profile <command>   # Create, show, and remove profiles

Example next steps (Claude Code with Bedrock):

box profile create claude --with bedrock   # Then set its model and sign in to Bedrock
box run claude                             # Run from your project

box sends usage telemetry to telemetry.strandsagents.com
To opt out, run: box telemetry off
To learn more: https://github.com/strands-agents/box/blob/main/CLI_TELEMETRY.md
```

In a color terminal, a progress bar replaces the `Downloading` and `Installed` lines. On Linux,
the check line is `Verified checksum and archive`, because there are no Apple checks. The
telemetry lines appear only while telemetry is on, so if you've already
[turned it off](cli.md#box-telemetry), a new install keeps that choice and leaves them out.

Open a new terminal as it says, and check that `box` runs:

```console
$ box --version
box 0.2.0
```

The installer checks the download before it changes your installed release. If a check fails,
or the new release doesn't start, you keep the release you had.

Next, [create a Claude Code profile](getting-started.md#2-create-a-claude-code-profile).

## What the installer adds

Each release gets its own folder in `~/.strands/box/packages`, and `current` points to the one you use.
The installer links `~/.local/bin/box` to the `box` in `current`. The rest of `~/.strands/box` is in
[Where Box keeps its files](files.md).

Only `box` goes in `~/.local/bin`, and an agent in a box can't write there. If that folder isn't
on your `PATH`, the installer adds it to your shell's startup files and prints each file it
changes:

| Shell | Files |
| --- | --- |
| zsh | `~/.zshrc`, or `$ZDOTDIR/.zshrc` when `ZDOTDIR` is set |
| bash | `~/.bashrc`, and the first of `~/.bash_profile`, `~/.bash_login`, or `~/.profile` that exists (`~/.bash_profile` if none does) |
| fish | `~/.config/fish/conf.d/box.fish`, under `$XDG_CONFIG_HOME` when that is set |

The installer reads your shell from `SHELL`. If `SHELL` is unset, it uses zsh on macOS and bash
on Linux.

## Upgrade or choose a version

To upgrade, run the install command again. It installs the latest release, switches `current` to
it, and prints `Updated box 0.1.11 to 0.2.0.`, or `box 0.2.0 is already installed.` when there's
nothing new. If you installed with any of the [installer variables](#installer-variables), set
them again, except `BOX_VERSION`.

To install a specific release instead, set `BOX_VERSION` to its number without a leading `v`:

```sh
BOX_VERSION=0.1.11 sh ./install.sh
```

A Linux preview release, such as `0.1.3-linux-preview.1`, is never the latest, so the installer
picks one only when `BOX_VERSION` names it. An older release may have no ARM64 Linux archive, and
then the installer stops on Linux and names the archive it couldn't download.

Old releases stay in `~/.strands/box/packages/`. Installing one you already have switches `current` back
to it without touching its folder. To free the space, delete an old release's folder, but not the
one `current` points to.

## Install from a fork or an unsigned build

To install from another repository, such as your own fork, name it in `BOX_GITHUB_REPO`. On
macOS, a release that isn't signed by the Box publisher, such as a fork's own build, also needs
`BOX_ALLOW_UNSIGNED=1`:

```sh
BOX_GITHUB_REPO=your-account/box \
BOX_ALLOW_UNSIGNED=1 \
sh ./install.sh
```

`BOX_ALLOW_UNSIGNED=1` skips Apple's signature and Gatekeeper checks, and the installer says so
with `Allowing unsigned release; Apple signature and Gatekeeper checks are skipped.` Use it only
for a release you trust. The installer still checks the checksum, archive contents, metadata, and
binary version.

## Manage PATH without the installer

```sh
BOX_NO_MODIFY_PATH=1 sh ./install.sh
```

This leaves your shell's startup files alone, so put `~/.local/bin` on your `PATH` in your own
setup.

## Uninstall

Remove the releases and the link:

```sh
rm -rf ~/.strands/box/packages
rm ~/.local/bin/box
```

That keeps your profiles, packs, storage, and run records in `~/.strands/box`. To remove those too,
delete `~/.strands/box` instead. If the installer edited a zsh or bash startup file, remove the lines
from `# >>> Box PATH >>>` to `# <<< Box PATH <<<`. For fish, delete
`conf.d/box.fish` in your fish config folder, `~/.config/fish` or `$XDG_CONFIG_HOME/fish`.

## Installer variables

`install.sh` reads these from the environment, and refuses arguments on its command line.

| Variable | What it does |
| --- | --- |
| `BOX_VERSION` | The release to install, such as `0.2.0` or `0.1.3-linux-preview.1`, without a leading `v`. Without it, the latest release. |
| `BOX_GITHUB_REPO` | The GitHub repository that supplies releases, as `owner/repo`. Without it, `strands-agents/box`. |
| `BOX_ALLOW_UNSIGNED` | `1` skips Apple's signature and Gatekeeper checks on macOS. It has no effect on Linux. |
| `BOX_NO_MODIFY_PATH` | `1` leaves your shell's startup files alone. |
