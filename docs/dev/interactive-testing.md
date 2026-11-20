# Testing an interactive run

This guide tells you how to test what an operator sees in a terminal: a `box` prompt such as
`[y/N]`, and an agent TUI that runs in a box. The unit tests and `just test-engine` do not cover
these, because they run without a terminal. To try a change by hand in your own terminal, see
[manual-testing.md](manual-testing.md).

## Why a pseudo-terminal

`box` asks a question only when stdin and stderr are terminals. With a pipe, `box` refuses or
skips the question, so a pipe does not test the prompt. An agent TUI also needs a terminal with a
size. A pseudo-terminal (pty) gives the command a real terminal, and a terminal emulator renders
what it draws.

Do not use `script -q /dev/null <command>` with a pipe into it. On macOS, it sends end-of-file
before the piped text, so the command reads an empty answer.

## The driver

`scripts/drive_tui.py` runs a command in a 120 x 40 pty. It follows a list of steps, renders the
screen with `pyte`, and prints the screen as text. `uv` installs `pyte` when the script runs.

```sh
uv run scripts/drive_tui.py '<steps>' -- <command> [args...]
```

The steps are a JSON list:

| Step | What it does |
| --- | --- |
| `["wait", "<text>", <seconds>]` | Reads output until the screen shows `<text>`, then prints the screen. When the time ends first, the driver stops and exits with status 1. |
| `["send", "<keys>"]` | Writes the keys to the terminal. |
| `["sleep", <seconds>]` | Reads output for that time. |
| `["screen"]` | Prints the screen. |

Write keys as escapes: `\\r` is Enter, `\\x1b[B` is Down, `\\x1b[A` is Up, `\\x1b` is Esc, and
`\\x03` is Ctrl-C. When the steps end, the driver stops the command and prints its exit status.

## Before you start

1. Build `box`: `cargo build --workspace`.
2. For an agent run, build the Box Core helpers: `just build`.

   To test the build CI made for a pull request instead, put
   `<repo>/scripts/try-build.sh <pr> --` before the driver, and name `box` without a path:
   `<repo>/scripts/try-build.sh 142 -- uv run <repo>/scripts/drive_tui.py '<steps>' -- box run claude`.
   That build starts with no profiles, so create the profile first with
   `<repo>/scripts/try-build.sh 142 -- box profile create claude`.
   See [manual-testing.md](manual-testing.md#try-a-ci-build-without-building-it).
3. Make an empty workspace for the run: `ws=$(mktemp -d /tmp/box-tui.XXXX)`. Run the driver from
   that directory, because `box run` uses the current directory as the workspace.

## Test a `box` prompt

Use a temporary `HOME`, so the test does not touch the operator's profiles and runs:

```sh
export HOME=$(mktemp -d)
mkdir -p "$HOME/.strands/box/profiles/probe"
echo 'packs = []' > "$HOME/.strands/box/profiles/probe/profile.toml"
uv run scripts/drive_tui.py '[["wait", "[1] Keep", 10], ["send", "2\\r"], ["sleep", 1]]' \
  -- "$PWD/target/debug/box" profile delete probe
```

Test each answer: yes, no, an empty line, and no terminal at all (run the command with
`</dev/null` and no driver).

## Test an agent in a box

An agent run uses the operator's real `HOME`, because `box` finds the agent and the toolchains
there. The run reads the profile from `~/.strands/box/profiles/` and writes a run directory to
`~/.strands/box/r/`.

```sh
cd "$ws"
uv run <repo>/scripts/drive_tui.py \
  '[["sleep", 15], ["screen"]]' -- <repo>/target/debug/box run claude
```

Find what the agent shows first with one long `sleep` and a `screen`. Then add a `wait` and a
`send` for each screen, and run again. Read each screen before you send Enter: the default choice
of a menu can be the choice that exits.

### Credentials

The profile names the model credential. By default a Bedrock profile signs with the host's AWS
identity (`aws://`), so make the test profile with `--option bedrock.sign-in=api-key`. It then names
`env://AWS_BEARER_TOKEN_BEDROCK`, and Box Core stops before the agent starts when that variable is
not set. The shell of a coding agent often does not have it.

- To test the TUI, the keys, and the egress path, set the variable to a dummy value. The agent
  starts, and the first model request gets an error such as `403 Invalid API Key format`. That
  error shows that the request left the box and reached the model host.
- To test a real model answer, the operator sets a real credential in the environment that starts
  the test. Do not look for a credential on the host.

## Clean up

Each agent run leaves a directory in `~/.strands/box/r/`. Remove only the runs that you started. Do not
use `box clean --all` on the operator's `HOME`, because it also removes the operator's runs. A
run's `box.toml` names its workspace, so match your temporary workspace:

```sh
for run in ~/.strands/box/r/*/; do
  grep -q "/tmp/box-tui\." "$run/box.toml" && rm -rf "$run"
done
rm -rf /tmp/box-tui.*
```
