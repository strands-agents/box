# test-workload/ — the agent-driven workload suite

This suite asks one question: **when a real coding agent does real work inside a box, does the box
let the work through, and does it hold the boundary?**

`test-integ/` asks the opposite question. It puts a hostile program in a box and counts the
refusals. It needs no credentials and no network, so it runs on every pull request. This suite
starts an agent, gives it a goal, and lets it call a model. It therefore needs cloud resources, so
its cloud run is dispatched by hand and gated on a maintainer's approval, while its verdict layer
runs free on any pull request that touches it. Read "How this suite reaches CI, and why it is
gated" below.

## What a cell is

A **cell** is one dimension and one agent. The suite holds fourteen dimensions and runs three agents.
Nine dimensions run for every agent and five are two-run dimensions, of which four name one agent,
so one platform gives 34 cells, and Linux and macOS together give 68.

| Agent | What runs in the box |
|---|---|
| `claude` | Claude Code, from its standalone install. |
| `codex` | Codex CLI, through its Node shim. |
| `strands` | An agent built on the Strands Agents SDK, `common/workload-strands-agent.py`. |

| Dimension | What the agent must do |
|---|---|
| `workload-baseline` | Write and read a file in the project. |
| `workload-git` | Make a commit with the contained `git`. |
| `workload-python` | Run a Python program. |
| `workload-node` | Run a Node program. |
| `workload-rust` | Compile and run a Rust program. |
| `workload-agent-hook` | Let its own hook configuration fire. |
| `workload-mcp-stdio` | Reach a local MCP server over stdio. |
| `workload-shell` | Do data work with the box's own Shell (`jq`, `grep`, `find`, `sed`, a pipeline), and report the refusal of a host binary. |
| `workload-monty` | Do data work with the box's own Python, Monty, through `python3 -c`, and report the refusal of a read outside the project. |
| `workload-budget` | Two runs. List directories under a listing budget that spans both runs, meet the refusal in run two, and report it. |
| `workload-resume-claude` | Two runs. Claude Code only. Resume the conversation with `--resume <session-id>` in the same box and recall a token from run one. |
| `workload-resume-codex` | Two runs. Codex only. Resume the thread with `exec … resume <thread-id>` in the same box and recall a token from run one. |
| `workload-kill-claude` | `workload-resume-claude`, with run one ended by SIGKILL. |
| `workload-kill-codex` | `workload-resume-codex`, with run one ended by SIGKILL. |

Each dimension directory holds five files, and a two-run dimension a sixth, `goal.2.md`:

| File | Purpose |
|---|---|
| `goal.md` | The prompt the agent receives. |
| `case.sh` | The dimension's grants, its project skeleton, and its checks. |
| `agent-a.sh` | Generates the box and runs the agent in it. |
| `agent-b.sh` | Composes the verdict from the files on disk. |
| `oracle.sh` | Records the host state before and after the run. |

`common/` holds the shared parts:

| File | Purpose |
|---|---|
| `workload-bootstrap.sh` | The on-instance entry. It builds the box, installs the agents and toolchains, and runs every cell. |
| `workload-lib.sh` | Host path resolution and the per-agent adapter. |
| `boxgen.py` | Writes the `box.toml` and `policy.dw` pair for one cell. |
| `workload-agent-a.sh`, `workload-agent-b.sh` | The two drivers every dimension's wrappers call. |
| `workload-oracle-lib.sh`, `journal_find.py` | The verdict library and the decision-journal reader. |
| `workload-run-validity.sh` | The gate that decides whether an agent made a tool call at all. |
| `workload-strands-agent.py` | The Strands agent. |
| `workload-run-validity-test.sh`, `workload-strands-agent-test.py`, `workload-two-run-test.sh` | Tests that run on your own host. See "Checks you can run here". |

**Agent B is not a model call.** It reads the artefacts and applies the dimension's rules. A model
must not grade its own run.

`network-egress/` is an older dimension of a different kind: an adversarial probe with four files
and no `case.sh`. It runs through `common/bootstrap.sh` with `common/oracle-lib.sh`,
`common/agent-a-runner.sh`, `common/agent-b-runner.sh`, and `common/box-config.toml`, not through
`workload-bootstrap.sh`. `common/lib.sh` serves only the `manual/` drivers.

## How one cell runs

`workload-bootstrap.sh` keeps this order for every cell, and the order is a contract:

```text
oracle.sh start  ->  agent-a.sh $RUN_DIR  ->  oracle.sh stop  ->  agent-b.sh $RUN_DIR
```

The oracle empties `checks.jsonl` when it starts. A check that must reach the verdict therefore
belongs in the oracle-time list, not only in the agent-time list.

## Verdicts

A cell writes `verdict.json`. The verdict is `PASS`, `FAIL`, or `ERROR`. A residual name tells you
why: `run-invalid` (the agent made no tool call), `case-timeout`, `suite-deadline`, `agent-absent`,
`missing-case-dir`, `no-verdict`, or `BOXGEN_FAILED`.

Two exit codes have fixed meanings, and you must not confuse them:

- **125** — the boundary or the transport failed.
- **126** — the policy refused the action. This is the box working.

The suite runs `set -uo pipefail` and never `set -e`, because a failing cell must still leave a
verdict behind.

## Running it

The suite runs on one EC2 instance per platform. `workload-bootstrap.sh` is the entry point, and it
does every step itself: it builds the box from a source tarball in S3, installs the three agents and
the four toolchains, writes instance-role credentials, runs every cell, and uploads the artefacts.

```sh
LEDGER_BUCKET=<your-bucket> BOX_COMMIT=<sha> RUN_ID=<id> \
  bash test-workload/common/workload-bootstrap.sh
```

Linux must be **arm64**, because the scripts install the arm64 builds of the agents and the Rust
toolchain. Linux containment itself also runs on x86_64.

### Inputs

No file in this directory names an account, a bucket, an image, or a credential. Every such value
is an environment variable, and a script that needs one refuses to run without it.

Inputs for `workload-bootstrap.sh`:

| Variable | Required | Meaning |
|---|---|---|
| `LEDGER_BUCKET` | yes | The S3 bucket that holds `box-src/<sha>.tar.gz` and receives `reports/`. |
| `BOX_COMMIT` | yes | The box commit to build. `box-src/latest.tar.gz` is the fallback. |
| `RUN_ID` | yes | A name for this run, used in the report key. |
| `STAGE_PREFIX` | no | A key prefix in the bucket, before `box-src/`. |
| `PLATFORM` | no | `linux` or `macos`. Default: from `uname`. |
| `AWS_REGION` | no | Default `us-west-2`. The Bedrock host and the model geography follow it. |
| `CASES` | no | Space-separated dimensions. Default: all fourteen, the five two-run dimensions last. |
| `AGENTS` | no | Space-separated agents. Default: `claude codex strands`. |
| `WL_DEADLINE_S` | no | Suite deadline in seconds. Default `5400`. |
| `WL_STRANDS_MODEL` | no | The Bedrock model id for the Strands agent. Default: derived from the region. |
| `WL_CODEX_MODEL` | no | The model id for Codex. Default `openai.gpt-5.6-terra`. |
| `WL_STRANDS_SDK_VERSION` | no | The Strands Agents SDK version to install. Default `1.57.1`. |
| `WL_CLAUDE_VERSION` | no | One released Claude Code version. Unset installs the latest. |
| `WL_CODEX_VERSION` | no | One released Codex CLI version. Unset installs the latest. |
| `WL_HOME_DIR` | no | The suite's own home. Default `/var/tmp/wl-home`. |

Claude Code and the Codex CLI install at their latest release by default, and the Strands SDK at a
fixed version. The difference is deliberate: this suite exists to find the case where a new agent
release stops working inside the box, and a standing pin hides that. The SDK is pinned because the
entry script in `common/workload-strands-agent.py` is written against one SDK API.
`common/workload-bootstrap.sh` logs a `builds:` line naming the three versions it installed, so a red
cell stays attributable, and `WL_CLAUDE_VERSION` and `WL_CODEX_VERSION` reproduce that run.

Inputs for the `manual/` drivers, read by `common/lib.sh`:

| Variable | Required by | Meaning |
|---|---|---|
| `KEY_PAIR` | `provision.sh` | The EC2 key pair name. |
| `VPC_ID` | `provision.sh` | The VPC that holds the default subnets to launch in. |
| `SECURITY_GROUP` | `provision.sh` | The security group id for the instances. |
| `INSTANCE_PROFILE` | `provision.sh` | The instance profile name. Its role signs the model calls and writes the bucket. |
| `LINUX_AMI` | `linux/provision.sh` | An AL2023 arm64 image id in `AWS_REGION`. |
| `MACOS_AMI` | `macos/provision.sh` | A macOS arm64 image id in `AWS_REGION`. |
| `ARTIFACTS_BUCKET` | `run-harness.sh`, `upload_to_s3` | The bucket for the probe harness reports. |
| `AWS_ACCOUNT` | no | Shown by `setup.sh`. The AWS CLI default credential chain selects the account. |
| `AWS_CREDENTIAL_REFRESH` | no | A shell command that refreshes your credentials. Unset means the default chain. |
| `AWS_REGION` | no | Default `us-west-2`. |
| `LINUX_INSTANCE_TYPE`, `MACOS_INSTANCE_TYPE` | no | Default `t4g.large` and `mac-m4.metal`. An M4 host needs a macOS 15 or newer `MACOS_AMI`. |
| `PROJECT_TAG` | no | The `Project` tag on every resource. Default `strands-box-containment-tests`. |
| `SOURCE_TARBALL` | no | The box source tarball to upload. Default `/tmp/strands-box-src.tar.gz`. |
| `WL_CLAUDE_VERSION` | no | Read by `install.sh` too. One released Claude Code version. Unset installs the latest. |

### The `manual/` drivers

These run from your own machine and reach an instance over SSH tunnelled through an SSM session,
so the instances need no inbound rule and are never addressed by a public IP. The SSH key itself is
ephemeral and pushed through EC2 Instance Connect, which is an API call rather than a network path.
Running them needs the AWS CLI's `session-manager-plugin` installed locally.
`setup.sh` chains them.

No driver calls a verb the box does not have. `install.sh` writes the `box.toml` and `policy.dw`
pair itself, through `render_box_pair` in `common/lib.sh`, from the same two sources
`common/bootstrap.sh` uses on an instance: `common/box-config.toml` and `test-integ/src/fixture.dw`.
A caller supplies `box_dir`, and the box has no verb that creates one, so the driver creates the
workspace and the box directory on the instance before it uploads the pair.

| Script | What it does |
|---|---|
| `manual/setup.sh` | Provision, install, and optionally run, for one platform or both. |
| `manual/<platform>/provision.sh` | Launch an instance. The macOS one allocates a Dedicated Host first. |
| `manual/<platform>/install.sh` | Upload the source tarball, build the box, install the agent. |
| `manual/macos/run-harness.sh` | Ship this directory to the instance and run `common/bootstrap.sh` there. |
| `manual/<platform>/run-jailbreak.sh` | Run the probe prompt against a built box. |
| `manual/teardown.sh` | Stop the instances, or terminate them and release the host. |

## Checks you can run here

Three tests need no instance, no box, and no model:

```sh
bash test-workload/common/workload-run-validity-test.sh
python3 test-workload/common/workload-strands-agent-test.py
bash test-workload/common/workload-two-run-test.sh
```

The second one skips its MCP checks unless `STRANDS_LIB_DIR` names a `pip install --target`
directory that holds the SDK. The third pins the two-run path: the session id each agent names,
where a second run's arguments go, the journal counts the budget assertions read, the box identity
snapshot, the disclosure comparison, the dimension-to-agent filter, and the policy a budget
dimension appends to its pair.

## Adding a dimension

A new dimension is one more `test-workload/workload-<name>/` directory with the five files. Copy
`agent-a.sh`, `agent-b.sh`, and `oracle.sh` from any dimension: each is a thin wrapper that calls
the driver in `common/`. Write `goal.md`, and write `case.sh` with the three functions
`workload-lib.sh` calls:

| Function | What it declares |
|---|---|
| `wl_manifest` | The tool tables the pair needs, the policy additions, the timeout, and the expected residuals. |
| `wl_prepare <project>` | The project skeleton and any fixture the pair names. |
| `wl_checks <project>` | The on-disk assertions the oracle scores. |

`workload-bootstrap.sh` runs every directory that `CASES` names. Nothing else registers a dimension.

A dimension that applies to one agent sets `wl_agents` at the top of its `case.sh`, as
`wl_agents="claude"`. The bootstrap writes no row for the other agents: the dimension has no cell
for them, and a cell that does not exist is not a cell that could not run. A name outside the
agent vocabulary records one `ERROR` row for the dimension, `dimension-agents-unknown`, so a typo
cannot make a dimension vanish.

### Two-run dimensions

A dimension that must start the same box twice says so in its manifest:

| Key | Meaning |
|---|---|
| `runs=2` | Keep the project and `box_dir` and start the box twice. Absent, or `1`, is one run. |
| `run1_stop=exit` or `kill` | How run one ends. `kill` sends SIGKILL to the box and every process beneath it. |
| `run1_stop_when=<path>` | With `kill`: the box dies as soon as this path exists. `{{PROJECT}}` expands. |
| `policy_file=<path>` | A file `boxgen.py` appends to `policy.dw` as written, with `{{TILDE_PROJECT}}` spelled the way the box reports the project. A budget rule lives here, because the generator has no key for a `forbid`. |

`boxgen.py` ignores the first three keys, so the generated pair is the same with or without them.

The driver reads `goal.md` for run one and `goal.2.md` for run two, and calls these functions when
`case.sh` defines them:

| Function | When | What it does |
|---|---|---|
| `wl_goal <run>` | Before each run | Prints the goal file for that run, instead of the two names above. The `workload-kill-*` dimensions use it to read their sibling's goals. |
| `wl_goal_vars <run>` | Before each run | Prints `KEY=value` lines the prompt may use as `{{KEY}}`. The resume dimensions pass the token this way, so it reaches the agent only through run one's prompt. |
| `wl_run_args <run> <previous-turns> <previous-stderr>` | Before run two | Prints run two's arguments, one per line, read from run one's stream. A function that cannot name them returns 1, and the cell fails with that cause rather than start a fresh run. |
| `wl_between_runs <run> <project>` | After run one | Records anything the checks must compare against run two, such as a session file's modification time. |
| `wl_prestate` | At `oracle.sh start` | Records host state the checks compare at stop, such as a listing of `$HOME/.claude`. |

The run arguments take the position each agent reads them in: before the fixed flags for Codex and
the Strands entry (`resume <id> --json …`), after them for Claude Code (`… --resume <id>`).
`common/workload-lib.sh` holds `wl_session_id`, which reads the id from the `system` `init` event
for Claude Code and the `thread.started` event for Codex, and `wl_write_budget`, which writes a
`forbid` that fires once N responses of one filesystem operation lie within the last hour.

A two-run cell leaves one file per run beside the usual ones: `turns.<n>.jsonl`, `stderr.<n>.log`,
`decisions.<n>.jsonl` (the journal as it stood when run n ended), `box-state.<n>.json` (the box id,
the record's inode, the commit file's digest, the history database's inode), `run-args.<n>`, and
`goal-vars.<n>`. `turns.jsonl` and `agent-a.log` hold both runs, and `agent-a.json` carries a `runs`
list with each run's status, exit code, and how it stopped. The oracle library adds the assertions
that read them: `wl_assert_same_box`, `wl_assert_no_line`, `wl_assert_disclosure_stable`,
`wl_assert_tree_unchanged`, `wl_assert_budget_carried`, and `wl_assert_runs_valid`.

The two budgets count `mkdir` (`create_dir`) and `ls` (`enumerate`), not content writes and reads.
Claude Code's Bash tool writes a working-directory file and sources a snapshot on every call, so a
`write_content` or `read_content` count would carry one event per call that no goal can hold still.
`wl_assert_budget_carried` reads the spend from counts: no refusal in run one, at least one in run
two, and run two permitted exactly the budget minus run one's attempts. A history that reset at run
two permits the whole budget again and fails the third check. The counts come from the
`shell:exec` records for the one command the goal names, so a spelling the goal forbids (`mkdir d4
d5`, a glob) is a cell that fails, not one that passes by another route.

## How this suite reaches CI, and why it is gated

`.github/workflows/ci.yml` runs the deterministic suite on the plain `pull_request` trigger. That is
safe only because the deterministic suite needs no secret and no cloud credential. A pull request
from a fork gets a read-only token, so no approval gate is necessary.

This suite needs all four of the things that design removed:

1. Two EC2 instances, one of them a dedicated Mac host.
2. Credentials for the test account.
3. An S3 bucket for the source tarball and the verdict ledger.
4. A live model, called once per cell.

It therefore runs behind `.github/workflows/workload-suite.yml`, which has **no automatic trigger**:
a maintainer dispatches it (`workflow_dispatch`) against a named ref — a branch, tag, SHA, or
`refs/pull/<N>/head` for a pull request. The approval is the security boundary, not a formality:
dispatch permission is repo `write`, and the `manual-approval` environment (whose
`required_reviewers` rule names the `strands-box-maintainers` team) narrows execution to
maintainers — a contributor can request a run, only a maintainer can let it spend. The job then
builds and executes the named ref's own code on real compute with real credentials.

The workflow is **non-blocking by construction**, for three independent reasons: it has no pull
request trigger, so it reports no check on a pull request at all; `ci.yml` does not call it and
`ci-gate` does not list it; and no ruleset on this repository requires any status check. A failed or
unapproved run cannot stop a merge.

**It is a scaffold, and it cannot pass yet.** Every account value is a required input with no
default, and `require_inputs` refuses a driver that lacks one, so an approved run fails in seconds
until a maintainer populates nine repository secrets and stands up the OIDC role, VPC, security
group, instance profile, AMIs, and bucket. That failure is honest and non-blocking; it is not a
containment result. The secret names are listed in the workflow's own header. Until then the only
path that can actually run the suite is a local one — `manual/setup.sh` against an operator's own
account — or an out-of-band pipeline.

The suite's **verdict layer** does run in CI, free and on no approval:
`.github/workflows/verdict-hermetic.yml` tests `test-workload/verdict/` and `test-common/`, which
are pure functions over synthetic fixtures and need none of the four things above. `ci.yml`
path-filters it, so it runs on a pull request that touches those directories and is reported as
skipped on one that does not. That leg is blocking when it runs, because a false PASS in a verdict
rule reports containment that was never measured.

## Two things not to "fix"

1. **`workload-bootstrap.sh` uploads the aggregate verdict twice.** The second key holds the
   segment `indeterministic/`. That key is a wire contract with an out-of-band collect step, and it
   is not a path in this repository. Do not rename it. The same segment appears in the probe
   harness keys and in its `mode` field, for the same reason.
2. **Most scripts in `common/` are mode 644, and the suite depends on no mode bit there.** Each one
   is `source`d, or it is started as `bash <path>` or `python3 <path>`. The exceptions are the probe
   harness scripts (`bootstrap.sh`, `lib.sh`, `oracle-lib.sh`, the two runners),
   `workload-run-validity.sh`, `workload-run-validity-test.sh`, `workload-two-run-test.sh`, and
   `workload-strands-agent.py`, which are 755. In a dimension directory, only `agent-a.sh`,
   `agent-b.sh`, and `oracle.sh` are mode 755. `case.sh` is 644, because a dimension script
   `source`s it. The `manual/` drivers are 755, because an operator starts them by name.

## Host resolution, and why a grant names a real file

`workload-lib.sh` resolves every host path the grants name. The box refuses a filesystem grant that
names a **symbolic link**, so the suite always resolves to the canonical file:

- Claude Code installs a launcher symlink under `~/.local/bin`, so the grant names the version
  directory instead.
- `/usr/bin/node` and `/bin/sh` are links on AL2023, so the grants name the real programs.
- `/usr/bin/cc` and `/usr/bin/ld` are links, so the exec list names the programs that `gcc` starts.
- On macOS the `Versions/Current` Python spelling matches nothing, so the grant names the keg path.
- The Strands agent runs with the host's canonical `python3` and a `pip install --target`
  directory, because a virtual environment's `bin/python3` is a link.

The suite also gives itself a home at `/var/tmp/wl-home` rather than borrow the instance user's
home. The instance home is mode 0700, and the namespace backend cannot traverse it when it builds
the mount view. The home is not under `/tmp`, because `/tmp` is `/private/tmp` on macOS, and the
box refuses a floor grant that encloses the operator home.
