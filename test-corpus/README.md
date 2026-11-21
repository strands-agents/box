# The golden corpus

The golden corpus is the set of sessions a developer runs in their first days with
`box`. The committed grid is `corpus.toml`. The runner is `run_corpus.py`. One command runs
the grid, and each cell reports pass or the list of denials with their rule names.

`corpus.toml` is the source of the cells: each cell is one task, its prompt, and its checks. The
runner reads that file, so the grid has no other copy.

## The grid

`corpus.toml` holds one `[[cell]]` per test. Each cell carries:

- `id`, `section`, `gate`, `machine`: the cell's identity and when it runs. Sections 1 to
  3 (36 cells) gate launch. Nine cells need the lived-in machine image.
- `prompt`: the agent-layer prompt, as a developer would type it.
- `script`: the bash the scripted layer runs as the agent (see [Write a script](#write-a-script)).
  A cell with no script is SKIP `no-scripted-commands` on that layer. A SKIP row names every
  reason the cell cannot run, comma-joined, such as `needs-lived-in-image,no-scripted-commands`.
- `expect`: what the script gives on the bench's runner today (see [Record what a cell gives](#record-what-a-cell-gives)).
- `fixture`: what the project directory starts as. A folder under `fixtures/` is copied, and
  `clone:<owner>/<repo>` is cloned at the tag or full commit SHA in `fixture_ref`. A `#label` after
  the repository names the part of it the cell uses, such as `#gradle`, and the clone ignores it.
- `needs`: the toolchains the cell uses. The runner marks a cell SKIP when a tool here is
  absent, so a missing tool is never a false FAIL.
- `net`: the hosts the cell legitimately reaches. A deny of a host outside this list is a
  real finding. A deny of a host in it is a pack gap.
- `pass_check`: the cell's task-outcome check.
- `note`: known denials, caveats, and the disposition of any quarantined cell.
- `profile`: the committed profile the scripted layer runs the cell under. It defaults to
  `corpus`. The GitHub cells name `corpus-github` (see [The GitHub cells](#the-github-cells)). A
  cell that names one is SKIP `scripted-only-profile` on the agent layer, because the agent's own
  profile could hold a credential that writes.
- `env_vars`: the variables the cell's profile routes as credentials, such as `GH_TOKEN`. When one
  is unset or blank, the cell is SKIP `no-env:<NAME>`, because the box refuses to start without
  it. The runner replaces each one's value in the cell's log with `***`.

Add a cell by adding a `[[cell]]`. Nothing else changes.

## The two layers

The corpus runs in two layers.

- The scripted layer runs the cell's expected commands (its `script`) in the box with no
  model, under the `corpus` profile: the tool packs that `box profile create` adds, `@box/npx`, `@box/uv`, `@box/uvx`, the
  corpus's own packs in `packs/` for toolchains box does not ship, and bash as the agent. It
  runs on the corpus bench, on its schedule and on dispatch, and catches policy gaps in those packs, with two exceptions: the
  profile moves npx's HOME into the project, and it gives npm a project `XDG_CONFIG_HOME` and
  `WRANGLER_SEND_METRICS=false`. Each hides the walls its comment names.
  The profile's `policy.dw` is a copy of the `@box/scoped` policy starter, which lets the box's
  shell run. Its other policy file, `downloads.dw`, also lets the box reach the Playwright and Prisma
  download sites, and the profile turns off Prisma's report to checkpoint.prisma.io.
- The agent layer runs the real harness (Claude Code, Codex) against the prompt in its
  headless mode. It is meant to run nightly on the Mac pool, where it catches the paths a model
  takes. Nothing runs it on a schedule yet.

Launch checks, in `launch.toml`, sit beside the two layers. Each starts one profile's agent in a
box with no model call. For Claude Code and Codex, `--version` shows that the agent's program runs
in the box, and `mcp list` shows that it also reads the settings its profile gives it: settings it
cannot read or parse fail the check. Neither shows that an MCP server works or that the agent can
reach its model. They run with the scripted layer.

Feature checks, in `features.toml`, test that an agent in a box gets the setup you made on the
host. [The feature checks](#the-feature-checks) describes them.

## How to run it

### One time: build the box

The runner needs Python 3.11 or later (`tomllib`); macOS ships 3.9 at `/usr/bin/python3`,
so use Homebrew's `python3`. It calls the `box` you build, so build it and its two helpers:

```sh
cargo build --locked -p strands-box-cli -p strands-box -p strands-box-containment \
  --bin box --bin strands-box-sock-alias --bin strands-box-contain-trampoline
```

The runner puts `target/debug` in front of your `PATH`, and the Codex native-binary
folder when it exists. The rest of the path is your own, so the box sees the toolchains
your shell has. `BOX_CORPUS_BIN` names another folder to use in place of `target/debug`. The
runner also adds `~/.cargo/bin`, `/opt/homebrew/bin`, and `/usr/local/bin` after your path, for a
host started over SSM. `BOX_PATH_FALLBACKS` replaces that list, and an empty value adds none.
The runner's unit tests use both variables to run a stub `box`.

### One time: create the profiles

The agent layer runs a profile you already have, and a cell whose profile is missing reports
ERROR. Create the two agent profiles once:

```sh
target/debug/box profile create claude --with bedrock --option bedrock.sign-in=api-key
target/debug/box profile create codex --with bedrock-mantle --option bedrock.sign-in=api-key
```

The scripted layer and the launch checks run profiles the runner installs. `--install-profiles`
copies each pack in `packs/` into `~/.strands/box/packs/` and each committed profile in
[`profiles/`](profiles/) into `~/.strands/box/profiles/`. On the launch layer it
also makes each check's profile, such as `launch-claude`, with `box profile create --policy open`.
It replaces
packs and profiles of those names, and never touches `claude` or `codex`. A pack of your own under
one of those names stops the run instead of being replaced. This copies the profiles and runs
the probe check alone:

```sh
python3 test-corpus/run_corpus.py --layer launch --ids probe --install-profiles
```

The engine suite in `crates/cli/app/tests/engine.rs` loads the same `probe` file as its `PROBE`
profile. In CI, on every pull request that is not a draft and not docs-only, and every push to `main`, the `macos`
job of `cli-test.yml` runs the `probe` check and every launch check. The cells run in the corpus bench, below. None
needs a model key.

### Run the cells on the bench

The corpus bench, `.github/workflows/corpus.yml`, runs the scripted layer on GitHub's runners: one
job per section, split into shards of at most six cells with a script. It runs on a schedule and when
you dispatch it, never on a pull request, and `CI Gate` does not need it. A job is red when one of
its cells differs from its `expect`, and the other jobs run on. The Linux jobs run on an ARM64
runner and are advisory: a red one does not fail the run.

The schedule, in UTC: 14:47, 18:47, and 22:47 on weekdays (09:47, 13:47, and 17:47 ET in standard
time), 02:47 Tuesday to Saturday (18:47 PT the day before), and 06:47 and 10:47 every day. In
daylight saving time each local time is an hour later. A scheduled run uses at most three macOS
runners at once, so it leaves room for CI's macOS job.

Dispatch it on a branch, with any of the inputs:

```sh
gh workflow run corpus.yml --ref <branch> -f ids=TS-01,RS-04
gh workflow run corpus.yml --ref <branch> -f section=Python -f platform=both
```

`platform` is `macos` (the default), `linux`, or `both`, and `no_skip=true` fails a cell that has a
script but is SKIP. The scheduled run sets both: it runs both platforms and fails such a cell. Then wait for the run and fetch its results:

```sh
# A new run takes a few seconds to appear. Check that this is yours by its start time.
run=$(gh run list --workflow corpus.yml --branch <branch> --event workflow_dispatch --limit 1 \
  --json databaseId -q '.[0].databaseId')
gh run watch "$run" --exit-status
gh run download "$run" --name corpus-results          # summary.md and every row in results.json
gh run download "$run" --pattern 'cells-macos-*'      # each job's results.tsv and per-cell logs
```

Each job installs the toolchains its section's cells name in `needs`: setup actions for Node, Go,
uv, and PHP with Composer, and `test-corpus/bench-toolchains.sh` for the rest. Each tool with a
release is pinned to it. rbenv and psql come from Homebrew or apt at their current version, and
nvm is the runner image's own when it has one. An install that fails warns, and its cells are SKIP
`no-toolchain`. The runner images already have Java, .NET, CMake, Swift, Ruby, git, gh, and
sqlite3. macOS also has Xcode, Homebrew, and the Android SDK, and Linux has Docker. So Docker cells
are SKIP on macOS, Xcode, Homebrew, and Android cells are SKIP on Linux, and Flutter cells are SKIP
on both, because the bench does not install it yet. A lived-in cell is SKIP everywhere.

Each job gives the GitHub cells its own read-only token (see [The GitHub cells](#the-github-cells)).

The run's page shows the same verdict table as `summary.md`. It ends with the cells that have no
script and their count, because the scripted layer never runs them. `test-corpus/bench.py` plans the jobs
and writes the table, and `test-corpus/bench-cells.sh` runs one job's cells.

### Run a few cells

```sh
# one cell, by id
python3 test-corpus/run_corpus.py --layer agent --profile claude --ids EV-07

# a whole gate (the 36 launch cells)
python3 test-corpus/run_corpus.py --layer agent --profile claude --gate launch

# the whole grid
python3 test-corpus/run_corpus.py --layer agent --profile claude
python3 test-corpus/run_corpus.py --layer agent --profile codex
```

Each cell prints one line, for example `EV-07 RED denies=3 permits=154 33s
<default-deny>`. The runner writes `results.tsv`, `results.json`, and a per-cell log under
`/tmp/corpus-out/<profile>/`.

### The GitHub cells

EV-01, EV-02, and EV-03 run under the `corpus-github` profile: `@box/git`, `@box/gh`, and bash as
the agent. Its two routes put a GitHub token on the box's requests, and the agent sees only a
stand-in:

- `GH_TOKEN` goes to `api.github.com` as `Authorization: token <value>`, for gh.
- `GIT_GITHUB` goes to `github.com` as Basic auth on every request, for git. It holds
  `x-access-token:<token>`.

The bench sets both from the job's own token, which can read the repository and its pull requests
and can write nothing. So each cell reads the repository, and its dry-run push stops at GitHub's
403. EV-02's origin is an SSH remote, which `@box/git` sends over HTTPS, so the same token reaches it. Nothing is written, and a GREEN means the box blocked nothing, not that a PR opened.

To run it on your machine, use a token that can only read `strands-agents/box`, such as
a fine-grained token with read access to contents and pull requests. A token that can write lets
the dry-run push through, and the cell fails:

```sh
export GH_TOKEN=<read-only token>
export GIT_GITHUB="x-access-token:$GH_TOKEN"
python3 test-corpus/run_corpus.py --layer scripted --ids EV-01 EV-02 --install-profiles
```

Without the two variables, each cell is SKIP `no-env:GH_TOKEN+GIT_GITHUB`.

EV-03 takes the same two variables, because the profile routes both. It reads the newest failed
run's logs and writes nothing, so it has no fix or push step:

```sh
export GH_TOKEN=<read-only token>
export GIT_GITHUB="x-access-token:$GH_TOKEN"
python3 test-corpus/run_corpus.py --layer scripted --ids EV-03 --install-profiles
```

### The private Go module cell

GO-04 runs under the `corpus-go-private` profile: `@box/go` with `GOPRIVATE` set, and bash as the
agent. Its service imports `github.com/strands-agents/box-corpus-private`, a module in a private
repository. So go downloads it with git, and the profile's route puts the token from
`GIT_CORPUS_PRIVATE` on git's requests to github.com. The runner pins the module at its `v0.1.0`
tag. A token that can read that repository is enough, such as a fine-grained token with read
access to its contents:

```sh
export GIT_CORPUS_PRIVATE="x-access-token:<read-only token>"
python3 test-corpus/run_corpus.py --layer scripted --ids GO-04 --install-profiles
```

Without the variable, the cell is SKIP `no-env:GIT_GITHUB`.

### The agent layer needs a model key

The agent layer runs the real harness against a live model, so it needs a Bedrock API key
in `AWS_BEARER_TOKEN_BEDROCK`. The runner reads one for you from the file in
`BOX_BEDROCK_KEY_FILE` (default `~/.strands/box/bedrock.key`), or you set the variable directly:

```sh
export AWS_BEARER_TOKEN_BEDROCK="$(... your Bedrock key ...)"
python3 test-corpus/run_corpus.py --layer agent --profile claude --ids EV-07
```

With no key, the agent layer stops before it runs anything and names the variable and the
key path it checked. A nightly whose secret is missing or renamed then fails rather than
reporting 67 green skips. Pass `--allow-no-credentials` to SKIP the agent cells instead.
The scripted layer needs no model and runs with a placeholder credential.

### Codex needs its native binary

Codex ships as an npm launcher the box cannot start. Its native binary is vendored inside
the npm package, and the runner puts that directory on the path. If your Codex lives
elsewhere, point the runner at the directory holding the native `codex`:

```sh
export BOX_CODEX_BIN=/path/to/codex-native/bin
python3 test-corpus/run_corpus.py --layer agent --profile codex --ids EV-07
```

Codex also needs a served model, because its default is not on the mantle endpoint. The
runner pins one with `-c model=...` before `exec`. A `-c` after `exec` sends Codex's
requests to api.openai.com instead, which the box denies.

### Kiro CLI needs a Kiro API key and its runtime folder

Kiro CLI calls Kiro's service, not Bedrock, so `--profile kiro` reads a Kiro API key from
`KIRO_API_KEY`, or from the file in `BOX_KIRO_KEY_FILE` (default `~/.strands/box/kiro.key`). The runner
makes the `kiro` profile with `kiro.sign-in=api-key` and `agent.skip-permissions=true`, so each cell
runs `chat --trust-all-tools --output-format stream-json`, so the judge reads each tool call and
its output, as it does for Claude Code. Fill Kiro's runtime folder first, as
[Set up the runtime folder first](../resources/packs/kiro/README.md#set-up-the-runtime-folder-first)
says:

```sh
KIRO_RUNTIME_DIR="$HOME/.kiro-runtime" kiro-cli --v3 chat --list-sessions
python3 test-corpus/run_corpus.py --layer agent --profile kiro --ids TS-01 --install-profiles
```

On the Mac pool, the 10:11 UTC nightly of `workloads.yml` runs Kiro CLI on every cell, and a dispatch
with `-f agent=kiro` runs it on demand. Both read the `KIRO_API_KEY` secret of the `workloads`
environment. Without it every Kiro cell is SKIP with that reason, and the run fails. The judge calls Bedrock whatever the agent is, so `--judge` also
needs the Bedrock key, and the runner stops before any cell without one.

The GitHub cells run under the `kiro-github` profile: `@box/kiro`, `@box/git`, `@box/gh`, the
routes of `corpus-github`, and the `@box/open` policy that the agent layer's other profiles take, so Kiro CLI holds only a stand-in for the read-only token. Claude Code and
Codex have no such profile, so their GitHub cells are SKIP `scripted-only-profile`.

### Filters

`--ids A B C` runs named cells, or named launch checks with `--layer launch`. `--gate
launch|first-update|follows` runs a gate, and `--section Python` runs one section. With neither, the runner runs all 67. A cell
whose toolchain is absent, or that needs the lived-in image, an unpinned clone, or a fixture
the runner does not build yet, is SKIP with the reason, so a bare laptop reports a small set
of real results and skips the rest rather than failing them. On the scripted layer, a cell
with no `script` is SKIP too. `--shard K/N` runs every Nth cell that has a script, starting at
the Kth, so CI can split the cells across runners.

On the agent layer, the run exits non-zero when any cell lands in a `--fail-on` verdict
(default `red,error`), so a CI step fails on a real finding. With that default, SKIP and GREEN
never fail the run. The scripted layer and the launch checks exit non-zero when a row's result
differs from its `expect`. `--no-skip` also fails them when a cell with a script, or a launch
check, is SKIP, so a runner that lost a toolchain or an agent cannot pass by skipping. Pass
`--fail-on none` to always exit 0.

## The profile guide's prompt tests

`run_guide.py` tests the guide that ships with `box`, whose path `box help agent` prints. Each cell of `guide/guide.toml` is
one profile task, such as adding a tool or a policy rule. The runner makes a home folder for the
cell, with one profile and two operator packs, and gives a coding agent one prompt:
"Run box help agent and follow it to update profile `<profile>`." and the task. The cell that
starts with no profile gets "Run box help agent and follow it to create a profile." The runner
writes no guide. The agent runs `box help agent`, which prints the path of
`editing-box-profile.md` in the resources folder and writes nothing. The runner passes that
folder and the cell's `.strands/box` to Claude Code with `--add-dir`, so the agent reads the guide in the
first and edits in the second. The agent runs on the host, not in a box, because a boxed agent
cannot write a profile. Its shell may run `box` and nothing else, and the runner puts the `box`
under test first on the agent's `PATH`. The agent gets the model key and no other
credential of your shell.

A cell passes when all of these hold, and no model grades it:

- the agent exits 0;
- `box profile show --full <profile>` exits 0;
- that output holds each `shows` text of the cell, none of its `absent` texts, and a match for
  each of its `matches` patterns;
- every file, folder, link, or mode the agent added or changed in the home folder matches the
  cell's `may_change`;
- no file in `resources/`, which holds the guide and the packs that ship with `box`, changed.

```sh
python3 test-corpus/run_guide.py                       # every cell
python3 test-corpus/run_guide.py --ids add-tool,add-pack
```

It needs `claude` on your `PATH` and a Bedrock key in `AWS_BEARER_TOKEN_BEDROCK`. Without either,
every cell is SKIP with `no-model-credential` or `no-agent`, and the run exits 0. The `guide` job
of `workloads.yml` runs the cells nightly, and on a dispatch with `-f guide=true`, and never on a
pull request. `--no-skip` fails a run that cannot start, which the job uses when it has a key. Results
vary between runs, so run a guide change three times before you trust a PASS.
`test_run_guide.py` tests the runner with a stub `box` and a stub agent.

## The feature checks

`features.toml` holds one `[[feature]]` for each row of the per-agent feature checklist (`CHECKLIST`
in `test_features.py`) and each agent the row applies to, for Claude Code, Codex, and Kiro CLI. A check shows that the agent
in a box gets one part of the setup you made on the host: your instructions, your skills, your
model, your organization's policy. The file's header describes each field.

```sh
python3 test-corpus/run_corpus.py --layer features
python3 test-corpus/run_corpus.py --layer features --ids codex-skills claude-hooks
KIRO_API_KEY=ksk_... python3 test-corpus/run_corpus.py --layer features --ids kiro-instructions
```

Each check runs in a temporary HOME of its own, a new folder in `~/.box-features` that the runner
removes after the check, with its workspace under `--out` at `<id>/ws`. The HOME is short because the
box's socket lies under it, and a socket path holds about 100 bytes. It is not in `/tmp`, because the
box refuses to start when a grant covers the folder that holds its credential. `BOX_FEATURES_HOMES` names another folder
for these, and `BOX_FEATURES_KEEP_HOMES=1` keeps them. The runner copies the check's `host` folder from `fixtures/features/` into that HOME,
makes the check's profile there with `box profile create --policy open`, and runs it. So a check
reads the host setup in its fixture, and never your own `~/.claude`, `~/.codex`, `~/.kiro`, or
`~/.strands/box`. The agent's program must be on your `PATH`. A Kiro CLI check reads Kiro's runtime from
`KIRO_RUNTIME_DIR`, or `~/.kiro-runtime` when it is not set, so fill that folder first, as
`resources/packs/kiro/README.md` says.

A check tests what the agent reports, what the profile's storage holds, or both:

- Codex `app-server` answers JSON-RPC requests on its standard input. The check sends the lines in
  `stdin`, and `thread/start` and `skills/list` report the instructions, the model, the approval
  policy, and the skills of a session.
- Claude Code `-p x --output-format stream-json --verbose` prints an `init` event that lists its
  skills, commands, subagents, output style, permission mode, MCP servers, and plugins. The model
  request after it fails, because the key is a stand-in.
- Kiro CLI `chat --output-format stream-json` prints the session's commands (skills and saved
  prompts), its model, and the steering files it reads. Kiro CLI reports none of it before it
  signs in, so each of these checks calls the model once. A check's `agent_env` can set
  `KIRO_DUMP_REQUESTS`, so Kiro CLI writes each model request in the workspace, and the check
  reads the steering text that reached the model.
- `--version` starts the agent after the box fills the profile's storage. The check then reads the
  box's copy, such as `config/settings.json` for Claude Code, and also names what the copy must
  not hold, such as a credential file.

The runner closes the agent's standard input when an output line holds the check's `until` text.
It stops an agent that is still running ten seconds later, and that is not a timeout. A check with
no `stdin` gets an empty standard input from the start.

A check is GREEN when the box ran, each `holds` pattern matched, and no `lacks` pattern matched.
It is RED when the box ran and a pattern failed, and the reason names the first one. It is ERROR
when the box did not start, or when the runner stopped it at `--timeout`. The agent's exit code
does not decide, and neither do the box's denials, which the row lists. A check is SKIP when:

- `no-program`: the agent's program is not on `PATH`.
- `needs-system-files`: the check needs a file in a system folder, such as
  `/etc/codex/requirements.toml`, and `BOX_FEATURES_SYSTEM` is not `1`. With `BOX_FEATURES_SYSTEM=1`
  the runner writes the file with `sudo -n`, and removes the file and each folder it made after the
  check. It never replaces a file that is there: that check is ERROR `system-file-exists`.
- `host-has-managed-settings`: this machine has an organization's settings for the agent, in a
  system folder that the check's own home does not hide, so the agent would give another result.
- `no-credentials`: the check calls the model, and its agent's key is not set: a Kiro API key in
  `KIRO_API_KEY` or `~/.strands/box/kiro.key` for Kiro CLI, and a Bedrock API key for the others. Each
  check that calls the model uses a prompt that asks for one word. For Claude Code and Codex one
  check calls it, and for Kiro CLI each check that reads Kiro CLI's report does.
- `no-check`: the entry has no pattern. It records a row that has no test, and its `note` says why.

A check's `expect` records its verdict on the bench, as a launch check's does. A row that is not
done records `expect = { verdict = "red", reason = "..." }`, with the reason the row gives, where `*`
matches anything. Another failure then differs from the record, and the work that makes the row GREEN removes the
record in the same pull request. The run exits non-zero when a result differs from its record. `--no-skip`
also fails a check whose agent's program is absent.

The runner writes `features.json`, `features.tsv`, and a log for each check under `--out` (default
`/tmp/corpus-out/features`). Each row holds the check's `id`, `row`, `harness`, `verdict`,
`reason`, `expect`, and `mismatch`. The `features` job of `.github/workflows/workloads.yml` runs
the checks on dispatch and each night on a macOS runner, with `BOX_FEATURES_SYSTEM=1`, and uploads
the results with the run's other artifacts. It reads the Kiro API key from the `KIRO_API_KEY`
secret of the `workloads` environment.

## Add a test

Each test is an entry in a file. CI runs each launch check on the next push, and the bench runs
each cell on its schedule or when you dispatch it.

- **A script for a corpus cell.** Add `script` to the cell in `corpus.toml`, as
  [Write a script](#write-a-script) describes. For a project to start from, add a folder under
  `fixtures/` and name it in `fixture`, or give a `clone:` fixture a `fixture_ref`: a tag, or a full commit SHA
  when the repository has no tag.
- **A launch check.** Add a `[[launch]]` entry to `launch.toml`, with the packs in `with`, so the
  check runs the profile `box profile create` makes. Set an input in `options` when the profile
  would otherwise read your own setup, as the Claude Code and Codex checks do for your MCP servers.
  Then install the agent's native program in the `macos` job in `cli-test.yml`, pinned by version and
  SHA-256, beside Claude Code and Codex.
- **A tool the cells need.** A cell whose tool has no pack stays SKIP, because the box starts no
  program a pack does not name. Write the pack in `packs/<tool>/pack.toml`, name it in `packs` in
  `profiles/corpus/profile.toml`, install the tool in `bench-toolchains.sh` if the runner lacks it, and
  give the cell a script. The `pixi` pack is an example: it keeps pixi's package cache in the project. Keep the pack here rather than in `resources/packs/` when only the corpus
  needs the tool: a pack there joins `box profile create`'s `--tools` list and the tools its
  `unknown tool` error names, so it is part of what box offers every operator.

Dispatch the bench on your branch, and read the job's output. A row whose result differs from its record prints a draft of the
line that records it, unless the runner stopped the run at `--timeout`:

```text
codex    ERROR  denies=0   permits=0    1s  exit 1: ...  | DIFFERS: expected GREEN, got ERROR
         draft record: expect = { verdict = "error", log = "..." }
```

Paste the line into the entry. The draft is the last line of the log that names an error, so
check that it names this failure. A line that other failures print too, such as npm's
`A complete log of this run ...`, lets them pass. Trim `log` to the part that stays the same from
run to run, and put `*` in place of a runner path or a random name in `denies` and `log`. Then add
a one-line `note` that says why.
[Record what a cell gives](#record-what-a-cell-gives) has the format.

## Write a script

A script is bash, and it runs as the agent, the way a harness runs. Send each command an agent
would type to Box's Shell with `bash -c`. The box puts its alias first on the agent's `PATH`
under the name `bash`, so policy decides that command as it decides a harness's command. A
program the script starts without `bash -c` is not checked the same way. Each `bash -c` starts
in the project folder, so begin it with `cd` when it runs in a subfolder:

```sh
bash -c 'npm create vite@6.5.0 web -- --template react-ts'
bash -c 'cd web && npm install'
```

The agent's own sandbox starts no program but the alias, so the rest of the script uses bash
builtins. The runner puts three helpers before every script, and `set -euo pipefail`:

- `write FILE <<'EOF'` writes a file, as a harness's file edit does.
- `serve CMD...` starts a dev server in the background until the script ends.
- `until_ok SECONDS CMD...` retries CMD every two seconds, for example
  `until_ok 120 bash -c 'curl -sf http://localhost:3000'`.

Pin every version a command installs, so a new release cannot change a cell's result. A fixture
with dependencies commits its lockfile (`package-lock.json` or `Cargo.lock`), so `npm install` and
cargo pick the same versions every run.

Do not read a file into a command with `<`. The bytes reach the program empty and nothing says so,
so a cell that compares the output fails on the comparison with no sign of the cause
(strands-agents/box#319). Use the program's own file facility instead, as the sqlite3 cell uses
`sqlite3 app.db ".read top.sql"`. Writing with `>` is unaffected.

The agent is macOS's `/bin/bash`, which is bash 3.2. There a false `[[ ... ]]` does not stop the
script under `set -e` unless it is the last line, so a check in the middle of a script uses
`[ ... ]`, as the Next.js cell does with `[ -f web/package.json ]`. A `[[ ]]` on the last line
still decides the result.

## Record what a cell gives

A cell's `expect` records what its script gives on the bench's macOS runner today. A cell with no `expect`
must be GREEN. A red cell lists its denials as `<action> <resource>`, where the cell's folder
is `{workspace}`, the home folder is `~`, and `*` matches anything:

```toml
expect = { verdict = "red", denies = ["shell:spawn */npm/bin/npx-cli.js"] }
```

An error records text that one line of its log holds, and `*` matches anything in that line:

```toml
expect = { verdict = "error", log = "could not create temp file */.rustup/tmp/*: Operation not permitted (os error 1)" }
```

The bench fails a job when a result differs: a new denial, a recorded denial that stopped, or another
verdict, including a red cell that turned GREEN. A pack change that opens a gap fails the bench, and
one that closes a gap updates `expect` in the same pull request. A run that the runner stops at
`--timeout` always differs, because a record cannot tell a hang from the result it records. A
run that differs and is ERROR is run once more first, since a registry or a clone can fail for a
moment. A run that the runner stopped is not run again. The `denials` column of `results.tsv`
holds each row's denials in this form, ready to copy, and the runner prints a draft `expect` line
for a row that differs, unless the runner stopped it. A launch check's `expect` takes the same
form.

## The verdict

A cell is GREEN only when the box ran, logged no denial, and the agent exited 0 before
the timeout. It is RED when the box logged a denial, and the line lists the rule names. It
is ERROR when the box did not run, when the agent layer recorded no policy decision, or
when the session ended on a timeout or a non-zero exit, so a run that did not happen never
reads as a pass. The scripted layer is different: the box grants its workspace statically,
so a script that stays inside it records no decision, and a clean scripted run with none is
GREEN. It is SKIP
when the cell cannot run here (a missing toolchain, the lived-in image, an inherited MCP
server on the agent layer, a cell's own `profile` on the agent layer, an unset variable in the
cell's `env_vars`, an unpinned clone, or a fixture the runner does not build yet),
or when a scripted cell has no `script`.

The runner leads with the journal because zero asks and zero blocks is the one bar every
cell in the corpus shares. The task-outcome checks in `pass_check` are not executable yet,
so a GREEN today means the box blocked nothing, not that the task was done.

## Known limitation

No agent cell reaches zero blocks today, because the shipped packs deny a host each harness
reaches at startup. That is a pack decision for strands-agents/box#563, not a runner change. The runner reports
the denials so the decision has data.
