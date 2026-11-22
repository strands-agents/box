# feature-critic: CLI area

Paths: `crates/cli/`, `resources/`, `test-corpus/`, `docs/cli/`, `docs/design/cli/`, and the CLI's
scripts and their tests in `scripts/`: `scripts/try-build.sh`, each `scripts/*-cli.py`,
`scripts/test_try_build.py`, and `scripts/test_ci_workflow.py`. The
[Core area](review-core.md) covers the rest of `crates/`.

Read [`feature-critic.md`](../../agents/feature-critic.md) first. This file adds the checks for `box`.

## What this area names

- **Contract:** the plan, when the caller gives a path in `.agents/plans/`. The plan is the
  contract, and the diff is the claim.
- **Approvals:** an entry in `docs/design/cli/decisions.md`, or a human's approval that you can link:
  their comment or review on the pull request, or their approval of the plan. An agent's own plan
  or pull request body is not an approval.
- **Anchors for a design finding:** an entry in `docs/design/cli/decisions.md`, a comment in the
  pack's `pack.toml`, a rule in `crates/cli/AGENTS.md`, or the nearest existing code that does the same job.
- **Decision log:** `docs/design/cli/decisions.md`. **Decision skill:** `decision`.
  **Trigger table:** [What a change updates](../../../crates/cli/AGENTS.md#what-a-change-updates).
- **Place of a finding:** the symbol.
- **Untrusted input:** operator input and host state.
- **Also report:** what fails `crates/cli/app/tests/engine.rs`, and what widens what a box grants.

## Rules

- Review only what `box` owns: its code, its packs, its tests, and its docs. Do not read Box
  Core's source.

## Checks

0. **Requirements need tests.** Each requirement in the plan has a test. With no plan, each claim
   that the diff makes has a test that you can name.
1. **Tests.** Each refusal and failure path has a test that fails when the code is wrong. Flag a
   test that asserts nothing.
2. **The engine suite.** `crates/cli/app/tests/engine.rs` runs `box run` against Box Core in
   `crates/box/`. It is `box`'s own proof that what `compile` writes is accepted. When the
   diff changes what `compile` writes, a test in `engine.rs` covers the new output, or the diff says
   why not. `engine.rs` runs no tool, so for a tool or a tool host rule, a unit test of the rule and
   the `check_policy()` pass below are the proof. `box run` and `box profile show` also call
   `strands_box::check_policy()` (the `check` module), so a generated rule that Box Core refuses
   fails there before a box starts.
3. **What a box grants.** `box` writes the `box.toml` and `policy.dw` for each run, so a `box`
   diff can widen what the agent reaches. Compare what a run gets before and after for each change
   that can alter what `compile` writes: `compile`, `render`, `lang`, `reference`, `tool`, `mcp`,
   `starter`, `program` (it picks and refuses the program behind `[agent] command`, and behind
   each tool), `host` (`find_on` takes the first program in an absolute `PATH` folder, and
   `box_homes` names the places that `program` passes over), `install_layout` (the files that a
   configured program needs become grants), `create`, or a pack under `resources/packs/`. A change
   in one of these modules that cannot reach the output (a deleted report line, for example) needs
   no comparison; say why.
   - Build `box` at the fork point in a scratch worktree, and on the diff. Give each build its own
     `CARGO_TARGET_DIR`, apart from the gate target, because `--all-features` builds test code.
   - Use one `HOME` path and one project path for both builds, under
     `${HOME}/.cache/feature-critic/`. Delete and make them again between the two runs. Two paths
     give two storage keys (`<project>-<hex>`), and every storage path and rule then differs.
   - The new `HOME` hides an agent installed under the real home. Find its native program: it is
     the program that the agent pack's `search` picks, which `box profile show <profile>` prints as
     `<agent>.path` with the real `HOME`. Or use `which -a <agent>` and take the file that is not a
     script. Put a link to it in a directory at the front of `PATH`. A node script there is passed
     over, but a wrapper there is run, because the search never runs a candidate.
   - A diff to the program search, or to the `search` of an agent pack, does not show in a `HOME`
     with no installed agent. For it, make each folder that `search` lists under `${{ home }}` in
     the new `HOME`, with a link to the real program in each.
   - Compare the profiles that the diff touches. When the diff touches agent selection, a starter,
     or a shared pack, compare `claude --with bedrock`, `claude --with anthropic`, and
     `codex --with bedrock-mantle`.
   - Run `box profile create <name> --with <packs> --policy open </dev/null` and then
     `box profile show --full <name>` from the project directory, and `diff` the `box.toml` and
     `policy.dw` that each build prints. At a terminal, `create` asks the starter's questions and
     the policy question, so give it no terminal, or answer each question with `--option` and
     `--policy`. Do not run `box run <name>` first: for a starter name, it creates the missing
     profile.

   Report each of these unless a decision entry or the plan names it:
   - A new or wider entry in `[agent.filesystem]` or `[tool.<name>.filesystem]`, a new `exec`
     entry, or a new `[tool.<name>]` or `[mcp.<name>]` table.
   - A new `[[mcp-servers]]` row, or a row that reads a new host file.
   - A new `permit` in `policy.dw`, or a wider one: a rule in a policy starter's `policy.dw`
     (`resources/policies/<name>/`), a `spawn_*`, `package_hosts_connect`, or
     `package_hosts_request` rule that `render::tool_rules` writes for a tool, an `mcp_<name>_*`
     rule for an MCP server, or a `route_*`, `storage_*`, or `workspace_*` rule
     ([`policy-holds-no-placeholder`](../../../docs/design/cli/decisions.md#policy-holds-no-placeholder)).
   - A guard that `box` writes or a policy starter holds, and the diff removes or narrows: the
     `open_loopback` forbid in `@box/open`, the `box_home_*` forbids, the `project_configuration_*`
     forbids, or the `<workspace>/.box` entry that `compile` adds to the `deny` list of each
     process and each stdio `[mcp.<name>]` server. Each of these is a BLOCKER.
   - A new `[egress.<name>]` route, or a route with more `destinations`.
   - An input in a `command` element or in `destinations` with no `pattern` and no `values`
     ([`an-input-in-a-command-or-route-is-bounded`](../../../docs/design/cli/decisions.md#an-input-in-a-command-or-route-is-bounded)).
   - A new input with `from = "env:<NAME>"`, because it copies a host value into the box (the
     `base` pack copies only `TERM` and `COLORTERM`). An input of this kind that can read a variable
     an `env://` credential reference names is a BLOCKER
     ([`an-env-reference-cannot-read-a-credential`](../../../docs/design/cli/decisions.md#an-env-reference-cannot-read-a-credential)),
     or a credential value (not its `env://` reference) in `box.toml`, `policy.dw`, the report
     that `box profile show` or `box profile create` prints, or an error.
4. **What a later run trusts.** A later run trusts `~/.strands/box`, the directory that holds `box`, the
   resources directory that holds the shipped packs (the set `run::protected` returns), and
   `<workspace>/.box`
   ([`a-run-cannot-write-what-a-later-run-trusts`](../../../docs/design/cli/decisions.md#a-run-cannot-write-what-a-later-run-trusts)).
   Check that the diff keeps each refusal that guards them, and that a new path goes through the
   same refusal:
   - `refuse_reach` in `compile`: no write grant reaches a protected directory
     (`WriteOverProtected`), and no program, `exec` entry, or `PATH` directory of a process lies
     under a write grant (`ProgramUnderWrite`). A new kind of grant or a new process is in this
     check, or the diff says why not.
   - `compile` refuses a workspace that holds the operator home or the run's own directories
     (`ProjectHoldsHome`, `ProjectHoldsBox`), and `run` refuses a `<workspace>/.box` that is a
     link or a file.
   - Each directory `box` creates goes through `files::create_real_directory`, so no write
     follows a link.
   - Each `[[storage.files]]` copy goes through `storage_files::Refusals::check` for its source and
     for each link it follows, copies once, builds in a staging directory, and refuses a file that
     changed since the plan
     ([`the-packs-decide-what-is-copied`](../../../docs/design/cli/decisions.md#the-packs-decide-what-is-copied),
     [`a-copy-belongs-to-the-box`](../../../docs/design/cli/decisions.md#a-copy-belongs-to-the-box)).
   - Each authored policy file in a profile's `policies` goes through `profile::policy_path`, which
     keeps it, and its link target, inside the profile folder, and the load refuses a file with more
     than one hard link. `box` refuses `policies` in a pack.
   - A path check reads the real path (`resolve`), then acts on that path. A check on one spelling
     followed by an open of another is a BLOCKER.
5. **Host programs.** `box` runs host programs outside any box through `Host::command`, such as
   `/usr/bin/xcode-select -p`. It has a timeout and no standard input. A new probe goes through
   it. A `search` never runs a candidate (`search_never_runs_a_candidate`). A tool's `program`
   (`tool`) and an input's `search` (`lang`) never pick a program in the workspace. `program::check` refuses a program whose path or real file lies where a box writes on
   every run (the workspace, the run's storage, and the box homes), a link to nothing, and a file
   that is not executable, and returns the real file behind a link. A write grant of the run is
   checked elsewhere: `refuse_under_grants` (`lang`), `refuse_under_writes` (`tool`), and
   `refuse_reach` (`compile`). A search passes over a candidate that `program::check` refuses, but
   the run is refused, or the tool is skipped, for a program under a write grant
   (`a_program_link_under_a_write_grant_is_refused_from_an_option_or_the_search`). The
   search in `lang` (`candidate`) also passes over a node script (`program::runs_node`) and gives the real file,
   never the link (`search_follows_a_link_to_the_real_program`), and
   `program::candidates` lists where to look. A candidate source that the diff adds or removes in
   `program` or `tool` changes which program a host with several installs gets:
   confirm that this is the intent, and that the chosen program is still outside the workspace
   and every write grant.
6. **Decision entries in this area.**
   - An entry's answer is its title claim and its `Rejected.` lines. A rewrite that changes either
     needs the approval that the shared Decision entries check asks for. An edit that keeps an entry
     true without a change to its answer needs no approval: the Docs check below checks it.
   - Each new or rewritten entry passes the test in the `decision` skill's "What earns an entry".
     For one that fails, propose a sentence in the pull request instead. Do not judge the reasoning
     in an entry: the caller runs the `decision-critic` agent on it.
7. **Smallest layer.** The change uses the smallest layer that holds it: a pack or a starter (an
   input, a `when` gate, a starter `ask` or question), then the profile language (a new key), then
   the CLI. An operator's choice is a pack input that a starter asks for, stored in `[options]`,
   because `box run` asks nothing once a profile exists
   ([`box-run-takes-no-option-values`](../../../docs/design/cli/decisions.md#box-run-takes-no-option-values)).
   These are examples of signs of a larger layer: a new or changed command, flag, run-time prompt,
   or `BOX_*` variable that `box` reads; a new parameter that `Profile::resolve`,
   `reference::resolve`, and `run::compile_run` all pass on; a change to the order of the run steps;
   and a rewrite that changes a `decisions.md` entry's answer (its title claim or `Rejected.`). The
   list is not complete: any other change at the CLI layer that adds or changes a choice the
   operator makes needs a Layer reason. A fix or a refactor that adds no operator choice needs none.
   For each sign, and each other CLI change that adds or changes an operator choice, in the diff,
   unless it is a fix or a refactor that adds no operator choice:
   - Read the plan's Layer reason, and check it against the code. Find out if a smaller layer does
     the same job. For example, a `bool` pack input that defaults to false and a starter `ask`
     entry replace a run-time prompt and a flag.
   - A missing reason, or a reason that the code disproves, is a BLOCKER. Name the smaller layer
     that does the job.
   - A reason that the code confirms is a `DESIGN` note, not a blocker.
8. **Docs in this area.** The pre-1.0 rule is in [`crates/cli/AGENTS.md`](../../../crates/cli/AGENTS.md#docs).
   - Each command, flag, prompt, error, path, and variable that the diff adds or changes, and that
     is meant to ship, is in `docs/cli/`, or in the pack's `README.md` when only one shipped pack
     has it ([Pack READMEs](../../../crates/cli/AGENTS.md#pack-readmes)). Each one it removes is gone from
     there.
   - A `docs/cli/` change that names one pack's own behavior, limit, or fix, or adds a link to
     one pack outside the pack list in `docs/cli/README.md`, is a `DOCS` finding. The exception
     is a Claude Code fact that `getting-started.md` needs to finish the walkthrough.
   - Do not report a behavior change as a regression when the change is the intent of the diff or
     the behavior is in flux. Report it only when it fails `engine.rs` or breaks a safety rule.
   - A section that a diff adds to a `docs/cli/` page with an entry in
     [`user-page-tests.md`](../user-page-tests.md), and that fails the page's `belongs` test, is a
     `DOCS` finding. Name the page that the test sends it to.
   - A `docs/cli/` page may link a page in `docs/design/cli/` for background. It still states
     each fact the operator needs to act.
   - A `docs/cli/` or pack `README.md` change that adds implementation detail, an edge case the
     reader can't act on, or a glossary, or that breaks the page's type shape
     ([Page types](../writing.md#page-types)) with no reason in the pull request, is a `DOCS`
     finding. Check the page's sections and tables, not only its sentences.
   - A doc that the diff makes restate a fact its owner holds
     ([Where each fact lives](../../../crates/cli/AGENTS.md#where-each-fact-lives)) is a `DOCS` finding: a
     second copy of a list of keys, tables, flags, packs, or starters, a default, accepted values,
     or a precedence order. The fix is to delete the copy and link the owner. When the diff
     updates a copy that existed before, say so and ask for the deletion instead.
   - Each decision entry the diff touches has no date, status, test name, or `file.rs:LINE`.
   - No committed file links a plan, a draft, or a research note.
9. **Readable user docs.** Read each changed `docs/cli/` page or pack `README.md` about a surface
   that ships as an operator who has never used `box`. Report each sentence a person would need to
   read twice, each step with no expected output, each internal name (a module, a type) that leaks
   in, and each run of uniform, choppy sentences. Use `.agents/references/writing.md`.
10. **The Box Core boundary.** The CLI is a client of Box Core
    ([When the CLI needs something Box Core lacks](../../../crates/cli/AGENTS.md#when-the-cli-needs-something-box-core-lacks)).
    - A diff that changes a CLI path and also changes Box Core's contract (a `box.toml` key, a
      `strands-box` verb or flag, or the library's public API in `crates/box/src/lib.rs`) is a
      BLOCKER. Name the Core change, which goes in its own pull request first.
    - A profile or pack key whose only stated reason is to match a `box.toml` name or shape is a
      `DESIGN` note. Name the spelling a `box` user would expect.
11. **Standards.** A comment names what an item is, in one line. A type is named after what it is
    in the product. In a shipped `pack.toml`, a line that the diff adds or changes for a reason only
    that pack has carries the reason in a comment beside it, and a comment that the diff makes false
    is a docs finding ([Pack comments](../../../crates/cli/AGENTS.md#pack-comments)).

## Gates

Run this once:

```sh
just check
```

`just check` runs each recipe that `check` lists in `justfile`, including the engine suite in
`crates/cli/app/tests/engine.rs`, which starts real boxes. If `just` is not installed, run each recipe
that `check` lists, and each recipe it depends on first (such as `build-cli` before `test`), in
that order, and paste each tail.

If a test passes and the feature looks absent, find out why.

### Claims that only a real run proves

A claim that no test can check, such as "the agent starts in a box", needs a real run. Run it once
by hand, with a dummy credential, and report the command and the result under `BY HAND`. The
agent reaching its provider and getting an authentication error counts as a start, and so does
the agent's own screen in the box, under the `box` banner. Run it in the background and stop it
after that. For a pull request, `scripts/try-build.sh <pr>` runs the build that CI made. If you
cannot run it, report the claim as unverified.

### Platforms

CI builds and tests on Linux and macOS, and runs the engine suite on macOS only. The command for
the other platform is `cargo check --workspace --target <the other triple> --all-features`.

## Output blocks

After `BLOCKERS`:

```
GRANTS   (always present when the diff touches a module or pack that the What a box grants check names)
- before -> after: <each grant that moved> | none
- approved by: <decisions.md anchor | link to a human's approval | UNVERIFIED: the plan names it, no linked approval | UNAPPROVED>
```

The `DESIGN` line:

```
- layer: <each sign of a larger layer> : <the plan's reason> -> justified | BLOCKER, use <smaller layer> | none
```

After `DOCS`:

```
BY HAND  (always present when a claim needs a real run)
- <claim> : <command run> -> <result> | UNVERIFIED: <why not run>
```

`GATES` holds `just check`, or each command it runs.

## Verdict

A grant that moved and that neither a decision entry nor the plan names (`UNAPPROVED`) forces
`rework`. An `UNVERIFIED` grant does not change the verdict: the caller confirms the approval.
