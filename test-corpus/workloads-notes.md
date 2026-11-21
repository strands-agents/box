# Workloads workflow: notes and decisions

`.github/workflows/workloads.yml` runs the corpus **agent layer** on the GitHub macOS pool: it
gives Claude Code each cell's customer prompt inside a box, and reports two results per cell. This
records the decisions and the one open dependency.

## What a run reports
Each cell gets two words. The first is about the box; the second is about the agent.


- **Box verdict** (GREEN / RED / ERROR): did the box refuse anything on the way? This is the
  corpus's existing `verdict_for`.
- **Task grade** (PASS / FAIL / UNGRADED / NOT-RUN): did the agent actually do the workload? The
  grade comes from `run_corpus.py grade()`, which runs the cell's `check` command over the
  workspace the agent left, whenever the agent finished: the box ran it, it did not time out, and it exited 0, whatever the
  box refused on the way. An agent often meets a refusal, works around it, and finishes, which
  reads as RED and PASS. A non-zero exit (a crash, or a model call that failed, as an expired key
  gives) is NOT-RUN, so a run never passes with no model. A cell with a `check` is graded by
  running it; the check runs behind a printed sentinel, so a grader box that fails to start (whose
  exit code alone would look like a failed check) is read as UNGRADED, not a task FAIL. Every other
  cell is graded by the judge (decision 11).
- **Graded by** (check / judge): who gave the task grade. On a cell with a check the judge runs
  too, and the report says whether it agrees with the check.

## Decisions

1. **Reuse the corpus prompts, don't author a new set.** Every cell in `corpus.toml` already has a
   `prompt` that is a customer workload ("CI is red on the formatPrice test. Fix it."). The agent
   layer in `run_corpus.py` already runs Claude Code on it. The workflow wires that, rather than
   adding a second list of the same tasks.
2. **Grading is a second axis, not a change to the box verdict.** `verdict_for` still measures the
   box. `grade()` is new and measures the task. The existing scripted and launch layers are
   untouched, and their unit tests are unchanged.
3. **The check runs inside a box, not on the host.** The agent just wrote arbitrary files into
   the workspace, so re-running its code on the host would be a containment escape (it would run
   with the job's credentials). The check runs under the corpus bash profile in a box, like the
   scripted layer: the box contains the filesystem and exec and passes the host's credentials to
   nothing. Residual limitation: the agent could edit what the check runs (a test, a config) to
   make it pass. A stronger check asserts specific output or file state rather than re-running the
   agent's code; those are per-cell follow-ups.
4. **Start with two graded cells.** TS-04 (`pnpm test`) and TS-11 (`cd packages/app && yarn tsc
   --noEmit`) are the cells whose `pass_check` maps to a clean, re-runnable command with no running
   server. Every other cell runs and reports its box verdict, and its grade is UNGRADED until a
   `check` is authored for it. The two starter checks are written to match each cell's `pass_check`
   but have not been confirmed by a real run yet (see the open dependency), so the first keyed run
   is where they get tuned.
5. **Non-blocking, dispatch and nightly only.** No `pull_request` trigger. The nightly runs every
   cell, once for Claude Code (09:41 UTC) and once for Kiro CLI (10:11 UTC), because the launch
   tracker needs an agent-layer result for each cell and harness. The cost is accepted for now, and
   the set can be narrowed later. A dispatch runs the default set (`DEFAULT_IDS`), or names `ids`, a
   `gate`, or ticks `all` for every cell. A plan job (`bench.py plan --agent`) splits the cells into groups of 4, each
   group is its own macOS job that installs only the toolchains its cells need (the same steps as
   `corpus.yml`), and a report job (`bench.py workloads-report`) puts every cell in one table. One
   job for all 63 would take hours and pass the job's time limit. A cell this runner cannot run is
   SKIP with its reason, so `all` still lists every cell.
6. **The agent profile has the corpus profile's packs.** `run_corpus.py --install-profiles` makes
   the `claude` profile with `claude,bedrock` plus every pack in
   `test-corpus/profiles/corpus/profile.toml`, so an agent cell gets the same toolchains as the
   scripted layer, and the two layers differ in who does the work. The first run used only Box's
   default tools (cargo, git, node, npm, pnpm, yarn), so the Flask cell had no Python and the
   Next.js cell had no `npx`. The profile takes the packs only. The corpus profile's policy file
   (`downloads.dw`) and its `[tool.*]` settings that work around known refusals are not copied.
7. **The grade runs after refusals, but requires the agent to have exited 0.** The first run
   graded only after a GREEN box verdict, and every cell came back RED (Claude met some refusal and
   worked around it), so no check ran even where Claude did the task. The grade now runs whenever
   the agent finished, where finished means the box ran it, it did not time out, and it exited 0.
   The exit-0 part matters: an expired key makes `claude` exit non-zero without touching the
   workspace, and that must not be graded against an untouched fixture.
8. **The key check makes a real Bedrock call.** The workflow's "Check the Bedrock key" step does a
   one-token Converse, so an expired or wrong key fails the run at that step instead of letting
   every cell report ERROR under a green job. It is the job's first step after the checkout, so a
   bad key fails in about a minute, before the Rust build and the toolchain installs.
9. **A check must fail on no work.** TS-04's `pnpm test` fails on the untouched fixture (its test is
   red), so it is a valid check. TS-11's `yarn tsc --noEmit` passes on the untouched React 18
   fixture, so the check first requires react 19 in the app's package.json, which proves the
   upgrade happened. The Next.js cell gets a check too: its success is a live dev server, which
   cannot be checked after the run (the server is gone, and the box cannot listen on a port,
   strands-agents/box#285), so the check verifies the step below, that the app was scaffolded and
   builds. The prompt names no folder, so the check finds the package.json that lists next, at the
   top or one folder down. `next build` downloads the template's Google font and fails without it,
   so `profiles/corpus/downloads.dw` permits fonts.googleapis.com and fonts.gstatic.com.
10. **Box-authored sandbox refusals count toward the box verdict.** A tool the box starts runs
   under the OS sandbox, and an OS-level refusal is not a policy decision, so it never reaches the
   journal that `denies` counts. `sandbox_refusals` scans the run's output for the box's OWN
   refusal lines (the `strands-shell:`/`strands-box:` prefixes, at the very start of a line) and
   makes the verdict RED. Under Claude Code's `--output-format stream-json`, the box Shell's refusal
   of a command Claude ran arrives inside the event that carries that tool's output, so each tool
   output is scanned line by line too, for the EPERM family only (`Operation not permitted`, a
   macOS Seatbelt refusal), since a tool output also holds ordinary `Permission denied` errors such
   as a script run before `chmod +x`. Claude's own words and a subagent's report are not. An agent
   that prints plain text (Codex, or the bash agent) has no such split, so quoting a box line at the
   start of a line in its prose can trip the scan; an indented quote does not count. Limit: a
   refusal a tool prints to its own output and the box does not forward (create-next-app's EPERM on
   `~/Library/Preferences`) is not caught on the box axis; the task grade shows it instead. This
   applies to the agent layer only: the scripted and launch layers compare with recorded results,
   and moving them to this rule is a separate change made with a fresh bench run.
11. **A judge grades the cells that have no check.** Only 3 of the 63 cells have a `check`, and
   about half the rest cannot have one on a hosted runner (a live dev server, a private registry).
   Every cell has a `pass_check` sentence, so `--judge` hands it to a second model
   (`test-corpus/judge.py`, `BOX_JUDGE_MODEL`, Sonnet 5.5 on the US route) with the record of the
   run, and the model answers PASS, FAIL or UNPROVEN. Box Core's workload grader is deliberately
   not a model call; this judge differs from the case that rule guards against in three ways:
   - **It reads evidence, not the agent's say-so.** Claude Code runs with
     `--output-format stream-json`, so the log holds every tool call and its real output. The
     runner also snapshots the workspace before and after the agent (and before the check runs),
     so the record shows the files the agent changed. The agent's own words are in the record
     too, marked as claims.
   - **A PASS must quote its proof, and the runner checks the quote.** Each line of the quote has
     to be a whole line, whitespace aside, of a tool's output, the file changes, or the box's
     refusals. The command the agent typed is not proof, and neither is a fragment such as
     `3 passed` lifted from `1 failed, 3 passed`. A PASS that quotes anything else becomes
     UNPROVEN, which the table shows as UNGRADED. A PASS also needs every part of the condition
     shown: a part the record cannot show, such as "nothing new in ~/.cargo/bin", makes the answer
     UNPROVEN. Asked about the failing-vitest cell's old log, which held only Claude's final
     message, the judge answered UNPROVEN; given the same run's `pnpm test` output it answered PASS
     and quoted the passing test line.
   - **It is a different model from the agent, and its answer is checked against the scripts.** On
     a cell with a check the check's grade stands and the judge's verdict is recorded beside it, so
     each run says how often the two agree.
   The judge only reads text, so it runs on the host. It runs nothing from the workspace, and the
   snapshot never follows a link or reads a file with a second hard link, so a link the agent made
   cannot pull a host file into the record. The record and the answer are uploaded as
   `<id>.evidence.txt` and `<id>.judge.json`, with the token scrubbed. Sonnet 5.5 refuses a
   temperature and a forced tool choice, so a verdict can vary between runs of the same record;
   the quote check and the agreement count are what keep that visible. Each judged cell is one
   Converse call of a few thousand input tokens, small next to the Opus session it grades.

## The Bedrock credential

The in-box agent and the judge call Bedrock with a **short-term Bedrock API key**, a bearer token
Bedrock checks against the AWS session that made it. Each macOS job makes its own:

1. The job runs in the `workloads` environment with `id-token: write`, and assumes the role named in
   the repository secret `WORKLOADS_ROLE_ARN` through GitHub OIDC, for 2 hours. It is a secret, not a
   variable, because the ARN names the AWS account.
2. `test-corpus/bedrock_key.py` mints the key from that session into a file outside the cells'
   folder, and `run_corpus.py` reads it through `BOX_BEDROCK_KEY_FILE`. The role's own credentials
   reach only this step: `configure-aws-credentials` runs with `output-env-credentials: false`.
3. "Check the Bedrock key" makes a one-token call with the key alone to each model the run uses.

What the role allows, and why:

- **Trust:** only this repository's `workloads` environment.
  The environment has no branch rule, so a dispatch from any branch gets a key. That lets a branch
  that changes the agent layer test itself. It exposes no more than the repo secret it replaces,
  which every branch's workflow could read: anyone who can push a branch could get a key either way.
  The difference is that each key now reaches only three models and stops working within 2 hours.
  IAM can't cap what those calls cost. GitHub creates the environment on the first run that names it.
- **Models:** `bedrock:InvokeModel` and `InvokeModelWithResponseStream` on the US inference profiles
  of Claude Opus 5.5, Sonnet 5.5 and Haiku 5.5, and on those models in us-east-1, us-east-2 and
  us-west-2, where the profiles route. The workflow pins Claude Code's side models to these three,
  because a call to any other model is refused.
- **`bedrock:CallWithBearerToken`**, which a call made with the key needs.

`bedrock_key.py` uses only the standard library, so it runs on the runner's own Python before any
setup step. It produces the same key as `aws-bedrock-token-generator` 1.1.0 byte for byte
(`test_bedrock_key.py` pins two of that library's keys), and a key it minted from a real session
called Opus 5.5, Sonnet 5.5 and Haiku 5.5 with no other credential.

The workflow reads no long-lived Bedrock secret: each run mints its own key, and the key stops
working when the role session ends.

## What is verified

The agent layer, the checks and the plan/report jobs have run on CI.
The judge is pinned by `test_judge.py` and by runner tests that drive it against a stub box and a
local stand-in for Bedrock (`BOX_JUDGE_URL`). Its first CI run agreed with the check
on all three cells that have one (the failing-vitest and React 19 cells PASS, the Next.js cell
FAIL) and graded the Flask tests cell FAIL, quoting pytest's `1 failed, 489 passed` line.
