# Testing by hand

This guide tells you how to try a change to `box` in your own terminal, with a real agent and a
real model. To drive the same run from a coding agent, see
[interactive-testing.md](interactive-testing.md).

## Try a CI build without building it

CI uploads a `box` build for each commit on `main` and for each pull request that is not a draft
and not docs-only. To try one on a Mac with Apple silicon, put it first on `PATH` in your current
shell from any checkout:

```sh
eval "$(scripts/try-build.sh 142 --env)"     # zsh or bash: pull request 142
```

```fish
scripts/try-build.sh 142 --env | source      # fish
```

The script picks the syntax from `SHELL` and says which it printed. To choose it yourself, for
example from a bash terminal when your login shell is fish, use `--env sh` or `--env fish`.

Use `main` in place of the number for the tip of `main`. The script downloads the build with `gh`
and prints where it is:

```text
try-build: downloading the build for PR 142 at 93d3646f9b
try-build: box is /var/folders/.../T/box-try/93d3646f9b.../bin/box (PR 142 at 93d3646f9b), with BOX_HOME /var/folders/.../T/box-try/93d3646f9b.../home.
```

Go on from step 3 below, and skip the `alias`. Open a new terminal to go back to your usual `box`.
To run one command instead, put it after `--`:

```sh
scripts/try-build.sh 142 -- box profile show claude
```

Without `--env` or `--`, the script starts your shell with the build first on `PATH`. Your shell's
startup file can put another `box` first again, so `--env` is the reliable form.

- The build starts with no profiles. `BOX_HOME` is a folder for that build alone, so a pull
  request cannot leave profiles that your usual `box` cannot read. Create a profile first:
  `box profile create claude`. A new commit gets a new, empty folder, also when you run `--env`
  again in the same shell.
- To try the build on your own profiles, set `BOX_HOME=~/.strands/box` before you run the script.
- A build that does not read `BOX_HOME` uses its own default data directory, and the script says so.
- The script keeps each build in `$TMPDIR/box-try`, so it downloads a commit once. macOS removes
  old files there by itself. When a file of a build is gone, the script downloads the build
  again. It stops when `TMPDIR` is not set.
  `scripts/try-build.sh --clean` removes every build and its profiles.
- A pull request's build is the pull request merged into `main` as it was when CI ran. The
  script takes the build from the newest CI run for the commit.
- `BOX_TRY` names the build, for example `142@93d3646f9b`.
- To try a build from a fork, set `BOX_TRY_REPO` to the fork, for example
  `BOX_TRY_REPO=you/box scripts/try-build.sh 2 --env`.
- Builds expire 14 days after CI made them. Push a commit or re-run CI to make a new one.
- The script sets `BOX_RESOURCES` to the packs that came with the build.

## 1. Build the checkout

Run these in the checkout that holds the change:

```sh
cargo build --workspace
just build    # once for each checkout: the Box Core helpers go into target/debug
```

### Build the native filesystem policy experiment

Default builds leave the CLI Cargo feature `native-filesystem-policy` off. To compile the
experiment into the CLI, Box Core, and the helper programs, use:

```sh
cargo build --locked -p strands-box-cli -p strands-box -p strands-box-containment \
  --features strands-box-cli/native-filesystem-policy \
  --bin box --bin strands-box --bin strands-box-sock-alias --bin strands-box-contain-trampoline
```

This feature forwards to Box Core's `native-filesystem-policy` Cargo feature. It does not change
the profile default. Select the feature separately in the
[profile's experimental settings](../cli/profiles-reference.md#experimental-native-filesystem-policy).
To activate the experiment, the executable must also satisfy Box Core's
[native policy prerequisites](../user/native-filesystem-policy.md),
including the macOS 27 SDK and signing requirements. Older SDKs can compile a binary that
refuses activation.

Box Core supports experimental activation on Linux ARM64 and x86-64 when the host meets
those prerequisites. A successful build alone does not
qualify a host; run native allow and deny controls on the target system.

## 2. Set up the shell

Point `box` and Box Core at the build. Run this in the checkout, because `git rev-parse` finds the
checkout from the current directory:

```sh
repo="$(git rev-parse --show-toplevel)"
alias box="$repo/target/debug/box"
```

## 3. Get a model credential

By default, the Bedrock providers sign each request with your default AWS credentials (`aws://`),
so set `AWS_PROFILE` to a profile that can call the model and check it with
`aws sts get-caller-identity`. An SSO or `aws login` profile needs
`eval "$(aws configure export-credentials --format env)"` first.

A profile with `bedrock.sign-in = "api-key"` names `env://AWS_BEARER_TOKEN_BEDROCK` instead, so Box Core
reads a Bedrock API key from that variable. Make a short-term key from your AWS credentials:

```sh
export AWS_BEARER_TOKEN_BEDROCK="$(uv run --quiet --no-project --with aws-bedrock-token-generator --with 'botocore[crt]' \
  python -c 'from aws_bedrock_token_generator import provide_token; print(provide_token(region="us-west-2"))')"
```

- The generator signs with your default AWS credentials. Set `AWS_PROFILE` first to use another
  profile.
- Use the region of the profile: `box profile show <profile>` prints `bedrock.region`.
- The key expires (after 12 hours at most). When the model returns 403 after a time, make a new
  key.
- An account that denies `bedrock:CallWithBearerToken` refuses every key. See [@box/bedrock](../../resources/packs/bedrock/README.md#every-model-request-fails-with-403).

## 4. Make a scratch workspace

`box run` uses the current directory as the workspace, and the agent can write in it. Use a
directory that holds nothing you need:

```sh
mkdir -p ~/scratch/box-try && cd ~/scratch/box-try
```

## 5. Start from a clean state (optional)

To test the path that a new operator takes, remove the profiles, their boxes, and their storage
first:

```sh
box profile delete --all   # asks before removal; --no-ask does not ask
```

## 6. Run the agent

Try `box profile create ui-check --with claude`. Check arrow navigation, changing earlier
answers, Review before saving, and cancellation without writing files. Repeat with `NO_COLOR=1`,
`TERM=dumb`, and a narrow terminal. Check `profile list`, `profile show`, and `profile delete`;
Enter at delete keeps the profile.

Create a profile and check the files it writes:

```sh
box profile create claude --with bedrock
sed -n '1,8p' ~/.strands/box/profiles/claude/profile.toml
ls ~/.strands/box/profiles/claude
box help agent
sed -n '1,70p' "$(box help agent | sed -n '2s/^  //p')"
```

Check that the profile comment names `box help agent`, and that the profile folder holds no
`editing-box-profile.md`. Check that `box --help` starts with the line for coding agents. Check
that `box help agent` prints the full path of `editing-box-profile.md` in the `resources` folder of
the `box` under test, the version, the
Box home, the profile names, and the packs folder, and that it prints nothing on standard error.
Check that the file contains the editing steps, rules, and examples, with links inside the file. Tell a host agent
`Run box help agent and follow it to update profile claude.` and name a small profile change.
Check the result from the test project, then start the agent:

```sh
box profile show --full claude
box run claude
```

To check that the command writes nothing, write a file of your own at
`~/.strands/box/editing-box-profile.md` and run `box help agent`. The file stays as it is, and the command
does not print its path. Run the command with `BOX_HOME` set to a folder that does not exist, and
check that the folder still does not exist. Run it with `BOX_RESOURCES=/nonexistent`, and check
that it fails and names that folder. Run `box profile show claude` and `box run claude`, and
check that neither command writes a guide file.

To try Codex, run `box profile create codex --with bedrock-mantle` and then `box run codex`.

Each run has a folder in `$BOX_HOME/r/`, or `~/.strands/box/r/` when `BOX_HOME` is unset.
Its `box.toml` identifies the workspace, and its
`records.jsonl` holds policy decisions.
Give the agent a small task, for example "make a file hello.txt", and check the result in the
workspace.

Check that the startup indicator gives way to the agent and banner when the agent first draws.
Check that the footer shows the profile name (for example, `claude`).
Press **Ctrl+]** to expand the banner. Hover over each file path and check that it brightens like
the buttons, with no underline. Click each path and check that its label shows `Copied path` in blue
for two seconds, then returns to its file label without further input. Paste it into an editor. Check that
the pasted path is complete, including when the banner shortens it. Use a terminal that supports
clipboard writes and permits them. Click the activity heading to change its view, then minimize
the banner again. Type and paste a prompt, and resize the terminal while the agent is active. Check that
the cursor remains in the agent area and that pasted control characters do not toggle the banner.
Press **Ctrl+\\** to turn policy off, then click `Ctrl+\ policy on/off` to restore it without restarting
the agent. Check that `POLICY OFF` stays visible and `POLICY ON` disappears after five seconds.
With policy off, run `bash -c 'echo >> ~/.strands/box/profiles/<profile>/policy.dw'` in the box and
check that it is denied by `box_home_write`. Run again with `--no-banner`, press **Ctrl+\\**, and
check that the agent gets the key and `box runs history` shows no `policy off` row.
In the expanded banner, check that the activity heading and count stay aligned with the table
through both toggles and notice expiry. Repeat the clicks and keyboard checks in both banner sizes
and with `NO_COLOR=1`. The copy notice remains readable without color.
Pasting Ctrl+\\ must not change policy.
Drag across agent text while the agent updates, release, and paste into an editor.
Check that the pasted text matches the selection, including wrapped lines and Unicode.
Scroll to earlier agent output, select text there, and check the pasted text.
Scroll back down, then scroll up and type or paste to return to the prompt.
After exit, check that the shell accepts input and has its default cursor style and mouse behavior.

Repeat with `--no-banner`. Neither display shows startup logs on a successful run. Then put
`[banner]` with `enabled = false` in the profile and check that a run without a flag has no
banner and that `--banner` brings it back.

After the run exits, run the same profile again. Use the same `BOX_HOME` setting for both runs
and these listing commands:

```sh
box runs list
box runs list --format text
box runs list --format json
```

Check that text output has `PROFILE`, `UPDATED (UTC)`, and `BOX ID` columns. Both runs must
appear with their full profile names. The later configuration update must appear first.
`UPDATED (UTC)` must match the modification time of each run's saved `box.toml` file in
Coordinated Universal Time (UTC). This time records a configuration write during preparation;
it does not prove that workload startup succeeded.

Check that unknown timestamps sort last and equal timestamps sort alphabetically by box ID.
The default and `--format text` output must match. JSON must contain the same profiles,
update times, and IDs under the `profile`, `updated`, and `id` keys. Unavailable profile names
or update times must appear as `unknown` in text and `null` in JSON.
Run `box runs list` from another folder and check that its output is unchanged.

Choose a saved run to inspect with the same `BOX_HOME` setting. Replace the example ID with an
ID from the list:

```sh
box runs history b-5b8e3d70c92f14ab
box runs history b-5b8e3d70c92f14ab --deny
```

Check that the output includes recorded time, result, action, resource, rule, and reason. The first
command includes permits, denials, and would-denies when recorded; `--deny` excludes would-denies. Repeated
operations remain separate rows, and recorded values are not shortened. With no matching decisions, check the explicit empty-result message.
Run the commands from another folder and check that the output is unchanged.

Compare the default output with `--format text`, then inspect the JSON output:

```sh
box runs history b-5b8e3d70c92f14ab --format text
box runs history b-5b8e3d70c92f14ab --format json
box runs history b-5b8e3d70c92f14ab --format json --tail 0
```

Check that `--format text` matches the output with no format option. JSON contains the same
decisions as seven-key objects, and `--tail 0` prints `[]`. The `enforced` key preserves recorded
Booleans and uses `null` when the flag is absent or invalid. Parse the JSON with your usual JSON tool
to check its syntax.

For a saved-log fixture with denials marked as not enforced, compare the two selectors:

```sh
box runs history b-5b8e3d70c92f14ab --deny
box runs history b-5b8e3d70c92f14ab --would-deny
box runs history b-5b8e3d70c92f14ab --would-deny --format json
box runs history b-5b8e3d70c92f14ab --deny --would-deny
```

A denial with the Boolean record attribute `strands.box.policy.enforced` set to `false` appears as
`would deny` in text. JSON keeps `result` as `deny` and sets `enforced` to `false`. Only
`--would-deny` includes these decisions; `--deny` retains denials with a true or absent flag.
The last command must reject the conflicting flags with exit status `2`, before reading history.
Check an empty would-deny selection for the text message and JSON `[]`. Keep constructed fixtures
in a separate `BOX_HOME`; they test inspection and do not prove runtime log-only behavior.

For a run with denied decisions, choose a denied row and replace the example action, resource
substring, and timestamp below with values from that row:

```sh
box runs history b-5b8e3d70c92f14ab --deny --action fs:read --resource /private \
  --since 2026-11-11T12:26:41.123456789Z --tail 2
```

Check that every returned row matches all the filters. Repeat without `--tail` and compare its
last two rows with the `--tail 2` output. Repeat the filtered command with `--format json` and
check that it returns the same decisions.
See [`box runs history`](../cli/cli.md#box-runs-history) for the field meanings,
filter rules, and incomplete-log errors.

Check custom `BOX_HOME` selection with a run that has decisions under the default `~/.strands/box/r`.
Replace the example ID below with that run's ID. Create an empty log in a separate directory:

```sh
box_history_check="$(mktemp -d /var/tmp/box-history.XXXXXX)"
mkdir -p "$box_history_check/r/b-5b8e3d70c92f14ab"
: > "$box_history_check/r/b-5b8e3d70c92f14ab/records.jsonl"
```

Record the file contents, modification times, and permissions in both directories. Then run:

```sh
BOX_HOME="$box_history_check" box runs history b-5b8e3d70c92f14ab --format json
BOX_HOME="$box_history_check/missing" box runs history b-5b8e3d70c92f14ab --format json
```

The first history command must succeed with `[]`. The second must exit with status `1`, without
showing decisions from the default directory. File contents, modification times, and permissions
must stay unchanged in both directories, and `missing` must remain absent.
Neither command may create `~/.strands/box/installation.toml`.

Using the same directories and recorded file state, check saved-run discovery:

```sh
BOX_HOME="$box_history_check" box runs list --format json
BOX_HOME="$box_history_check/missing" box runs list --format json
```

The first listing must contain only the example ID, with `null` for `profile` and `updated`.
The second must succeed with `[]`, even though the default directory contains saved runs.
File contents, modification times, and permissions must stay unchanged in both directories.
The `missing` directory must remain absent, and neither command may create `~/.strands/box/installation.toml`.

## Check telemetry delivery

Use [`scripts/capture_telemetry.py`](../../scripts/capture_telemetry.py) when inspecting or changing
CLI telemetry. It saves HTTP payloads while you build and run Box separately. It uses only the
Python standard library.

Use the Box build you want to inspect and keep its matching sandbox helpers beside it.
The [endpoint override](../cli/cli.md#environment-variables) works in ordinary builds.

In one terminal, start the receiver from your source checkout. Choose an output directory that
does not exist:

```sh
python3 scripts/capture_telemetry.py --output /tmp/box-telemetry-capture --port 8765
```

```text
http://127.0.0.1:8765/box/ping
```

The URL appears when the receiver is ready. Omit `--port` to choose an available port and use
the printed URL.

In another terminal, use the shell, profile, and credentials from the steps above. Point
`box_telemetry_binary` at the build you want to inspect, then run from the scratch workspace:

```sh
box_telemetry_binary="$repo/target/debug/box"
cd ~/scratch/box-try
BOX_RESOURCES="$repo/resources" BOX_TELEMETRY=1 \
  BOX_TEST_TELEMETRY_ENDPOINT=http://127.0.0.1:8765/box/ping \
  "$box_telemetry_binary" run claude --no-banner
```

CLI telemetry goes to the local receiver, which does not forward it. Agent and Box Core telemetry
targets remain as configured.

Each `request-0001.json`, `request-0002.json`, and subsequent file holds one pretty-printed HTTP
payload, which can be an event or an array of events. The matching `.body` file holds the original
request bytes. The helper captures the payloads without checking their telemetry schema or meaning.

Expect `run/1` when launch is observed. Keep the agent running for more than
60 seconds to see a `polling/1` interval. Exit normally to see the final partial interval and
`shutdown/1`. Incomplete journal intervals are omitted. Events from one invocation share
`installation_id`, `run_id`, and `context`. A preparation failure gives `run/1` and `shutdown/1`
without polling. If Ctrl+C ends the agent, check for the same completion event. After the run,
stop the receiver with Ctrl+C or SIGTERM; it finishes accepted requests before exiting.

After Box exits, optionally copy its [`records.jsonl`](../cli/files.md#profile-storage-and-runs)
into the capture directory. For the terminal run above, find it beside the `box.log` file named in
the exit summary. This lets you compare Core's `workload_started` record with the outgoing `run/1`
payload. A reused box's journal also contains earlier invocations.

Run the CLI telemetry end-to-end tests from the checkout. They launch Box with temporary profiles,
a local receiver, and no model credential:

```sh
cd "$repo"
cargo test -p strands-box-cli --all-features --test telemetry -- --nocapture
```

The CLI dev dependency enables the test transport for Cargo tests, including tests without
`--all-features`.

## When the run fails

| What you see | What to do |
| --- | --- |
| `AWS default credential chain resolved no credentials` | Set `AWS_PROFILE`, or export an SSO profile's keys, in this shell (step 3). |
| `credential variable AWS_BEARER_TOKEN_BEDROCK is not set` | Export the key in this shell (step 3). |
| `403` from the model | Sign in again or make a new key, and check the region (step 3). |
| Claude Code waits and prints nothing | The account cannot call the model: Claude Code's default, or the one the host settings name. Set `ANTHROPIC_MODEL` in `[agent.env]` of the profile. See [@box/claude](../../resources/packs/claude/README.md#claude-code-starts-then-sits-there). |
| A policy denial | Run `box runs history <box-id> --deny` with the saved run ID. Read the resource, rule, and reason. |

## Check MCP configuration import

Turn on import first: set `claude.import-mcp = true` or `codex.import-mcp = true` under the
profile's `[options]` table, or answer `true` when `box profile create` asks. Run
`box profile show claude` or `box profile show codex` in the scratch project. Note the
storage folder, the declared MCP servers, and any omitted automatic declarations. Start the agent once, then inspect
`agent/config/.claude.json` for Claude Code or `agent/home/config.toml` for Codex below that storage
folder.
The MCP section contains the selected host entries, including servers with no generated policy.
For Claude Code, the file also holds the
onboarding flags, the trust answer for the project, and the interface toggles that the pack's
`fill` row adds, and no other host setting. Declared local
entries use the program alias and resolved arguments, without environment fields. Remote
entries retain their credential variable references. Other entries use the bare filename and
omit environment fields only when a final stdio declaration matches their command's filename and
arguments, including a command with a full path. Otherwise, they keep their original settings,
including environment fields, and a profile table with `type` that replaces one says so in its
skip line. Check a host entry whose command is `node`, `uv`, or
`python3`: its settings must be present, although `box profile show --full` has no generated
MCP table or rules for it.

Run again with matching settings. No MCP import notice appears. Change formatting and an
unrelated saved setting, then run again; the import remains quiet.
With no host MCP entries, the import leaves saved settings alone and prints no notice.

Edit a server and add a setting in the stored file. Change one server in the host configuration
and run again. A difference notice names affected servers without printing their settings.
The stored file retains both edits. Set `claude.import-mcp = false` or
`codex.import-mcp = false` under the profile's `[options]` table and run again. The stored file
still retains both edits, and no import notice appears. With import off, the box generates no
declarations or permissions from those host entries, so preserving a stored entry does not
guarantee that it can run.

Stop other runs of this profile in the scratch project and back up its stored file. Remove only
`mcpServers` for Claude Code or `mcp_servers` for Codex. With import disabled, run and exit the
agent. Enable import and run again: the missing section receives current host entries and
other settings remain. Replace the section with an empty object or table and run again:
it stays empty. The MCP import writes only its section; pack settings copies can add other keys.

The engine test `generated_mcp_config_selects_shared_program_servers_with_private_environment`
uses a fake agent to call two servers through one executable with distinct imported arguments.
It checks that each server receives its private environment. It requires no model credential.

## Package launchers

Run the real launcher checks in [the engine suite](engine-tests.md#launcher-tests). They use an
empty temporary home and a probe agent, so they need no model credential and do not change the
operator's profiles. Each launcher must initialize its MCP server and return the expected tools.


To check the launchers as agent tools, use the same launcher versions and run:

```sh
cargo test -p strands-box-cli --all-features --test engine launcher_tool -- --nocapture
```

This uses temporary profiles with the ordinary tool packs. It checks package execution through
the agent's shell and separate caches when pnpx also starts an MCP server.

## Installation support

Use an installed npm MCP server with Node from nvm, then with Homebrew Node. Use a Python MCP
server installed through uv or pipx. Configure each server in the agent's host configuration and
run `box profile show --full <profile>` from a separate project. The server needs no Node or
Python tool pack in the profile.

Inspect the `# installation` comments and each server's filesystem grants. An nvm runtime has no
Homebrew grants. A Homebrew runtime reads its own keg, the dependency kegs named by its receipts,
and specific configuration directories. It does not read the entire `Cellar`, `opt`, or `etc`.
On macOS, a Homebrew program can list `bin` and `opt` without reading unrelated programs or
packages.

Start each server through the box, list its tools, and complete a local tool call. For a Python
server, verify that the grants include its own environment and the actual base interpreter's
libraries. Repeat with a second environment and confirm that neither server gets the other's
files. Record child-execution behavior separately; a read denial is not an execution denial.
