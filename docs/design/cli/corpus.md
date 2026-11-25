# The golden corpus runner

The golden corpus is the set of sessions a developer runs in their first days with `box`.
This page explains how `box` runs that corpus, and the gaps that remain. The
cells are in [`test-corpus/corpus.toml`](../../../test-corpus/corpus.toml). The user-facing how-to is [`test-corpus/README.md`](../../../test-corpus/README.md).

## What the runner must do

One command runs the corpus. Each cell reports pass, or the list of denials with their
rule names. Results should carry the `box` and Box Core versions, so a regression is attributable (see the gaps below).
Making a red cell green is strands-agents/box#563, not the runner's job.

## Two layers

The corpus has two layers, and they run in two places.

| Layer | What runs | When | Catches |
| --- | --- | --- | --- |
| Scripted | The cell's expected commands, in the box, no model | On a schedule and on dispatch, on the corpus bench | Policy gaps, deterministically |
| Agent | The real harness (Claude, Codex) given the prompt, headless | Nightly and on dispatch, on the GitHub macOS pool (`workloads.yml`) | Whether the agent does the workload, and the paths a model takes |

The scripted layer is the deterministic half: it needs no model and no cloud, so it runs
on GitHub-hosted runners, on the corpus bench (`corpus.yml`). The agent layer runs the real coding
agent against a live model on the GitHub macOS pool (`workloads.yml`), nightly and on dispatch,
with a short-term Bedrock key each job mints through GitHub OIDC. Each agent cell carries two results: the box verdict (did
the box refuse anything) and, when the cell declares a `check` command, a task grade (PASS/FAIL)
from re-running that check over the workspace the agent left, whenever the agent finished. The
grader is not a model call.

## The grid

`test-corpus/corpus.toml` holds the cells as data, one `[[cell]]` per test. Each cell
carries its id, section, gate, and machine state, the prompt a developer would type, the
fixture the project starts as, the toolchains the cell needs, the hosts it legitimately
reaches, and the pass check. The grid is data, which is what lets a runner read the corpus
rather than a person.

Adding a cell is adding a `[[cell]]`. The `needs` and `net` fields are what make a run
honest: a cell whose toolchain is absent is skipped with that reason, and a deny of a host
outside `net` is a real finding while a deny of a host inside it is a pack gap.

## The runner

`test-corpus/run_corpus.py` reads the grid, runs each selected cell through a profile, and
scores it from the box journal at `~/.strands/box/r/<run>/records.jsonl`. It has no third-party
dependency and parses the journal itself.

The verdict leads with the journal, not the task outcome. A cell is GREEN only when the
box ran, logged no denial, and the agent exited 0 before the timeout. It is RED when the
box logged a denial. It is ERROR when the box did not run, when the agent layer recorded no
policy decision, or when the session ended on a timeout or a non-zero exit, so a run that
did not happen never reads as a pass. The scripted layer is different: the box grants its
workspace statically ("runs /bin/bash with no policy decision over these paths"), so a
script that stays inside it records no decision, and a clean scripted run with none is
GREEN. It is SKIP when the host cannot run it. The journal
verdict (zero asks, zero blocks) is the one bar every cell in the corpus shares, and the
denial list with rule names is what each cell reports. The per-cell
task-outcome checks (each cell's `pass_check`) are specific to each cell; encoding them as
executable checks is listed under gaps.

A cell is skipped, not failed, when its toolchain is absent, when it needs the lived-in
image, when the agent layer needs an inherited MCP server the box does not carry, when its
fixture is a clone with no pinned tag or is not built yet, or when its `note` quarantines it,
and on the scripted layer when it has no `script`. A skip carries its reason, so a missing
tool on one host never reads as a containment regression. This matches how the Box Core
`test-integ` suite treats a platform skip or a quarantine. `--no-skip` fails a cell that has a
script and is SKIP, so the nightly shows a lost toolchain. A quarantined cell stays SKIP under
it, because the corpus chose that skip. To work on a quarantined cell, take the word out of its
`note` and run it.

The runner keeps the caller's `PATH` and puts only `target/debug`, and the Codex
native-binary directory when it exists, in front of it, then re-adds the login-shell
directories a bare SSM or launchd process would be missing. A tool pack finds its program
on `PATH`, so the box gets the toolchains the developer's shell has, not a fixed list.

The agent layer needs a Bedrock credential, read from `AWS_BEARER_TOKEN_BEDROCK` or the
file in `BOX_BEDROCK_KEY_FILE` (default `~/.strands/box/bedrock.key`, not a world-writable temp
path). Without one, the agent layer stops before any cell runs and names the variable and the
resolved key path, so a nightly with a missing or renamed secret fails rather than
reporting green skips forever; `--allow-no-credentials` opts into a SKIP instead. The
scripted layer calls no model and runs with a placeholder credential. On the agent layer the
run exits non-zero when any cell lands in a `--fail-on` verdict (default `red,error`, validated
against the four verdicts); with that default, SKIP and GREEN never fail it. The scripted layer
exits non-zero when a cell's result differs from its `expect`, and a cell that the runner stops
at `--timeout` always differs. The runner reads the journal path box prints for
each run, so a second run of the same profile on the host cannot be scored by mistake.

## Where each layer runs

The scripted layer runs on the corpus bench, `corpus.yml`, on GitHub-hosted macOS runners, with
advisory ARM64 Linux runners beside them, on a schedule and on dispatch. It never runs on a pull
request, and `CI Gate` does not need it. The `macos` job of `cli-test.yml` runs the `probe` launch check
and starts Claude Code, Codex, and Kiro CLI under the profiles their starters make (`launch.toml`). The bench
runs the cells that have a script. Each cell runs under the profile its `profile` field names,
by default the `corpus` profile: the tool packs `box profile create` adds, `@box/npx`, and the corpus's own, with bash
as the agent, and
sends each command to Box's Shell with `bash -c`, so policy decides it as it decides a
harness's. The job fails when a cell's result differs from the `expect` its grid entry
records, so a pack change that opens a gap fails the next bench run. Dispatch the bench on the
branch before the pull request merges, and record a closed gap in the same pull request.

The agent layer runs on GitHub-hosted macOS runners (`workloads.yml`), nightly and on dispatch.
It is a separate rig from Box Core's `test-workload` suite (`workload-suite.yml`), which allocates
its own EC2 hosts.

## Two machine states

Nine cells are marked lived-in and need a second Mac image: nvm, uv, rustup, rbenv,
existing caches, a git credential helper, `gh` logged in, and a private npm registry. The
other cells run on a clean image. Each cell's `machine` field sets the split: the lived-in cells test reading
existing developer config and credentials, which a clean image cannot exercise. Two images
are two artifacts to build and keep current. Until strands-agents/box#564 decides the lived-in image, EV-03 is
marked clean so the bench runs it. It stays RED until `@box/gh` can reach GitHub's log storage
(strands-agents/box#569), and its `expect` keeps GREEN so the bench reports that gap on each run.

## Harness coverage

Claude Code and Codex both run today. Codex ships as an npm launcher the box cannot start;
its native binary is vendored inside the npm package, and the runner puts that directory on
the path. When the model override comes after `exec`, Codex sends its requests to
`api.openai.com`, not to the Bedrock endpoint that the pack's `-c` flags configure. With
every override before `exec`, it reaches the Bedrock endpoint, so the runner puts its
override there. Kiro CLI, the third launch harness, runs as `--profile kiro`. It takes a Kiro API key, not a Bedrock key, and Kiro CLI's runtime folder must be
filled on the runner before the run ([Set up the runtime folder first](../../../resources/packs/kiro/README.md#set-up-the-runtime-folder-first)).
The Kiro column runs on macOS.

## Current gaps

The runner and the grid work. The path to a useful nightly runs through these gaps.

Pack gaps, found by running 18 cells on Claude (all red) and by running Codex. Most of
those runs used an empty repository, from before the runner skipped unbuilt fixtures, so
the denials are real but the cells were not tested. They are the input to strands-agents/box#563, and they
are a small set, not one per cell.

- The `@box/bedrock` pack allows `bedrock-runtime` but not the `bedrock` control plane that
  Claude Code probes at startup, so every Claude cell logs one deny. Codex denies
  `chatgpt.com`, `ab.chatgpt.com`, and `api.github.com` at startup the same way. Until the packs allow the harness's own
  startup traffic, or the scorer records it as an accepted exception, no agent cell reaches
  zero blocks.
- The default profile adds the git, cargo, node, and npm tool packs, but there is no pack
  for the Ruby, Homebrew, and other toolchains the remaining cells need. A tool is a
  pack, so declaring a corpus toolchain means adding one. A pack in
  `resources/packs/` joins `box profile create`'s `--tools` list and the tools its
  `unknown tool` error names, so a toolchain only the corpus needs goes in
  `test-corpus/packs/` instead and the runner installs it as the operator's own.
  `sqlite3`, `python3`, `poetry`, and `pixi` are those
  ([decision](decisions.md#the-scripted-layer-gates-pack-coverage)). go and gh have shipped
  packs, `@box/go` and `@box/gh`, which no default profile adds. The corpus profile loads `@box/go`. Only the
  `corpus-github` profile loads `@box/gh`, so the other cells cannot reach its hosts. The GitHub cells run
  under that profile, with the bench's read-only job token, which
  can read and never write, so a cell proves reach and never opens a real PR. Its `github` route puts
  `GH_TOKEN` on gh's calls to `api.github.com`, as `@box/gh`'s README shows. git gets no stand-in
  it would send, so the `github_git` route sets `secret.inject = "always"` and
  `secret.placement = "basic_auth"`, and the box adds `GIT_GITHUB` (`x-access-token:<token>`) to
  every request to `github.com`. A clone or fetch then reads the repository, and a push stops at
  GitHub's own 403. A cell that names a variable in `env_vars` is SKIP when it is unset, because the
  box refuses a route whose variable is unset, and the runner hides each value in the cell's log.

Three Box Core gaps stop or mislead several scripted cells. Each cell's `expect` records its
result, and its `note` names the gap it hits.

- A command that does not end, such as a dev server, runs until the agent's own tool timeout, and the
  Shell has no way to run it in the background. Box Core stops any one command after 30 seconds by
  default, with `strands-shell: execution timeout exceeded`. The Box CLI's default is in the
  [profile reference](../../cli/profiles-reference.md#limits). The corpus profile sets
  `shell.timeout = 600`, because a scripted cell has no agent tool to stop a hung command.
- A file redirected into a command, as in `sqlite3 app.db < top.sql`, reaches the program empty,
  and nothing says so: no denial, no message, exit 0. A cell that compares the output then fails on
  the comparison alone. The sqlite3 cell hit this and now reads its query through sqlite3's own
  `.read`. Prefer a program's own file facility to a `<` redirect until this is fixed, and expect
  the same from `psql < schema.sql` or `python t.py < in.txt`. Tracked at
  strands-agents/box#319.
- A program in a box can't listen on a TCP port, even on loopback, so a server it starts gets no
  callers. The TypeScript dev-server cells still run, because the steps before each bind (the
  scaffold, the install, and the tests) pass, and each one's `expect` records where it stops. The
  three Python cells that run a server or a notebook (FastAPI, the pandas notebook, and the
  geopandas notebook through pixi) are quarantined instead, with their fixtures kept. Their
  `expect` holds on macOS only: there, uvicorn's bind fails and a Jupyter kernel can't open its
  local ports. On Linux, the box refuses bash's `setpgid` and the FastAPI server never answers,
  and a Jupyter kernel aborts in libzmq before it opens a port, for a reason not yet traced.
  Tracked at strands-agents/box#285.

On GitHub's macOS runners, the `cargo` on `PATH` is Homebrew rustup's bash script, which
`@box/cargo` skips. The bench installs rustup's own proxies into `~/.cargo/bin`, as
rustup's installer sets up a developer's Mac.

Runner and corpus gaps, this task's own follow-ups.

- The bench report lists the cells that have no script, with their count. Those cells need a
  pack for their tool first (java, dotnet, cmake, swift, ruby, php, bun, corepack),
  the lived-in image, a harness MCP table (TS-13), or docker (EV-08), which GitHub's macOS
  runners do not have. A new pack adds its cells' scripts, and `bench-toolchains.sh` installs its
  tool when the runner lacks it.
- Most task-outcome checks are prose, and only a few cells add an executable `check`, so GREEN
  means "zero blocks", not yet "task done and zero blocks". A script that ends with its outcome check, as RS-02 and TS-07
  do, closes that gap for its cell.
- Most fixtures are not built. The runner builds `empty`, `any-repo`, and EV-07's
  `sqlite-app-db`, commits EV-03's `pr-one-failing-check` on a feature branch whose origin does
  not exist, copies the folders under `test-corpus/fixtures/` (`cargo-new`,
  `csv-to-json-cli`, `repo-rust-toolchain-nightly`, `repo-eslint-prettier`, `nextjs-login-page`,
  `nextjs-tailwind-app`, and `create-cloudflare-worker`), and clones RS-01's ripgrep at a tag. It gives EV-01's `test-github-repo-https` an uncommitted change and
  an https `origin`, `strands-agents/box`, which the bench's token can read and cannot
  write. It builds EV-02's `test-github-repo-ssh` the same way, with the SSH form of that
  `origin`. It copies GO-04's `private-go-module-GOPRIVATE` and adds a require of a module from a
  private repository at a tag, which the cell downloads with a token that can read only that
  repository.
  It
  reports every other cell SKIP `fixture-not-built:<name>`. Each missing fixture serves one
  cell:
  - The output of another cell: `cs-01-output` (CS-02), `go-01-output` (GO-02),
    `php-01-output` (PHP-02), `sw-01-output` (SW-02).
  - Made by a scaffold command or template: `dotnet-new-webapi` (CS-01),
    `swift-package-init-executable` (SW-01), `rails-new` (RB-01),
    `django-startproject-sqlite` (PY-09), `composer-create-laravel` (PHP-01),
    `create-turbo-pnpm` (TS-10), `xcode-swiftui-template` (SW-03).
  - A small project built by hand: `pnpm-workspace-one-failing-vitest` (TS-04),
    `express-app-nvm-node24` (TS-08), `repo-nvmrc-20` (TS-09), `yarn4-workspace-react18`
    (TS-11), `repo-ts-script` (TS-15), `small-package-pyproject` (PY-04),
    `library-with-tests` (PY-05), `poetry-project` (PY-06), `data-dir-csv` (PY-07),
    `labeled-csv` (PY-08), `repo-as-linked-worktree` (PY-10), `pixi-project` (PY-11),
    `script-in-package` (PY-13), `node-repo` (EV-05), `small-cmake-project` (CC-01),
    `repo-ruby-version-3.4` (RB-02).
  - An external service or account:
    `npmrc-private-registry-token` (TS-12), `homebrew-postgres-5432` (EV-06),
    `m2-settings-mirror-creds` (JV-04).
  - Harness MCP configuration: `harness-mcp-memory-filesystem` (TS-13),
    `harness-mcp-uvx-fetch` (PY-12).
- The Codex column on the laptop-runnable cells is not yet measured. A first run passed the
  model override after `exec`, so Codex sent every request to `api.openai.com`, the box
  denied each one, and every cell ran to its timeout. The runner now passes the override
  before `exec`; the column needs a run on a host where the box can start.
- The agent layer runs on the GitHub macOS pool (`workloads.yml`). Each job assumes
  the workloads role through GitHub OIDC from the `workloads` environment and mints a
  short-term Bedrock key from it (`test-corpus/workloads-notes.md`). The `lived-in` machine image
  is not built, so cells that need it still SKIP. Most cells have a prose `pass_check` but no
  executable `check` yet, so they report UNGRADED until a check is authored and confirmed by a run.
- Results do not record the commit they ran on yet. `box` and Box Core build from the same
  checkout, so that commit names both versions.
- EV-08 has no committed disposition: it is the one-ask exception until the socket proxy
  ships. It is marked in the grid and skipped.
- EV-04 waits on the worktree-location decision, but it runs. Its script puts the worktree
  inside the project, so the scripted layer tests the git work and not that decision. On the
  agent layer the agent picks the location, so that run does test the decision.
