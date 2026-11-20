# AGENTS.md

Guidance for coding agents. `CLAUDE.md` symlinks to this file. Edit `AGENTS.md`.

## What this folder is

`box`, the Strands Box product CLI. It turns host state into one complete Box Core
configuration and runs a workload in a box. Box Core is the zero-trust runtime. Its own binary is
also named `box`, but this CLI links Box Core as a library and never installs that binary. Box
Core is everything under `crates/` outside `crates/cli/`, with its test suites and its rules in the
root [`AGENTS.md`](../../AGENTS.md).

The CLI owns the operator experience: discover harness state, choose defaults, validate operator
input, write `box.toml` and `policy.dw`, and invoke Box Core. Box Core owns everything a box enforces. The two
meet at one contract, `strands_box::run()`. Box Core's
[`docs/user/config.md`](../../docs/user/config.md) states the configuration contract.

## The CLI is not interface-frozen

Box Core is interface-frozen; the CLI is not. It is greenfield. The freeze that governs Box Core does
not govern the CLI. `box` is in development, so a change to the profile format, to `~/.strands/box`, or
to a command needs no migration. What the CLI must not do is **break the Box Core contract**: it writes configuration
Box Core accepts, and it calls Box Core's public library API. Treat Box Core's config schema and library surface
as an external dependency, even though Box Core is in the same workspace.

## How the CLI depends on Box Core

Box Core has a library target, so the CLI links the `strands-box` crate (`crates/box`) by path.

- Box Core publishes per-platform tarballs (`box-<tag>-<triple>.tar.gz`) holding `box`,
  `strands-box-sock-alias`, and `strands-box-contain-trampoline`, plus `SHA256SUMS.txt`.
- Box Core also ships a public `download.sh` for operators, which unpacks into `./box-core`.

`just build-cli` builds `box`, `strands-box`, `strands-box-sock-alias`, and
`strands-box-contain-trampoline` in `target/debug`. Keep both helper programs in the same
directory as `box`.

`box` does not download Box Core.

`box` asks Box Core instead of copying its lists ([decisions.md](../../docs/design/cli/decisions.md#box-runs-a-pinned-box-core-release)).

Box Core's configuration requires both **`name` and `box_dir`**
(`name` labels the box, `box_dir` selects it and is absolute). `box` writes `command`,
`workspace`, `env`, `filesystem`, `file-watching`, and `ingress` in `[agent]`, which refuses `dependency`.
Box's own docs name "Box CLI" as the writer of `box.toml`, so finding the agent's native binary and
supplying `TERM`/`COLORTERM` for the selected display are this CLI's job.

## Module layout

One module owns one step. Two crates hold the modules ([decisions.md](../../docs/design/cli/decisions.md#packs-and-profiles-are-their-own-crate)).
A row names the module's job, not the keys, tables, or flags it reads, so a new key does not change it.

`crates/cli/profile` (`strands-box-cli-profile`) owns packs and profiles from the file to the box: it
parses a profile and its packs, resolves them against a host, and compiles `box.toml` and
`policy.dw`. It names no module of the CLI.

| Module | Step |
| --- | --- |
| `host` | What the host holds: programs on `PATH`, paths, and command output. |
| `program` | A program on the host for a tool, an agent, or an MCP server: the checks that refuse one a box could have planted, and its `#!` interpreter. |
| `tool` | Each `[tool.<name>]` that names a `program`: the program, its `#!` interpreter, its helpers, and what it inherits. |
| `install_layout` | The installation layouts, and the files that a configured program needs. |
| `profile` | The profile folder, its schema, and profile names. |
| `lang` | The profile language: placeholders, packs and their headers, inputs, the program search, and the merge. It reads each pack through `strands-box-cli-telemetry`, which records where the pack came from. |
| `plugin` | The plugins that a profile lists: where each one is, the check of its file, and the rules on who declares a secret source and who names a reference that one reads. |
| `reference` | The `Sources` a run resolves against, and the hand-off from `tool` to `lang`. |
| `mcp` | The MCP servers that the packs' `[[mcp-servers]]` rows name in host files: the reader, the `[mcp.<name>]` tables, and each skip with its reason. |
| `mcp_config` | The host MCP entries written into the agent's configuration in storage, independently of generated policy. |
| `compile` | A resolved profile, a workspace, and an instance become one `box.toml` and `policy.dw`. |
| `render`, `error` | Policy text, and the errors. |
| `files` | File writes that never follow a link. |
| `locate` | The line of a key in a TOML file, and the known name a misspelled one is close to. |
| `storage_files` | The host files that `[[storage.files]]` copies into storage: the source checks, the links, the copy, the host tree a `sync` row reads on every run, and the rewrite of each `set` value and each `fill` row on every run. |
| `storage_sync` | The record of what `box` last copied for each `sync = true` row, the lock, the update that brings a copy up to date with the host, and the copies a run makes. |
| `storage_edit` | The parts of a JSON or TOML file that a copy keeps, the values that its `set` rows write, and the kept values that a `fill` row adds. |

`crates/cli/app` (`strands-box-cli`) owns the operator: the commands, `box run` and its terminal,
starters, `create`, `detect`, Box Core's policy check, and the call into Box Core. Its `lib.rs`
imports each profile module that it names at its old path, so `crate::lang` still names it.

| Module | Step |
| --- | --- |
| `resources` | Where the packs and plugins that `box` ships are. |
| `create` | The packs that `--with` names become a profile, and the host `Sources` that references resolve against. |
| `detect` | The `[[source]]` places a starter reads once at create: the parser, the refusals, and the reader. |
| `starter` | Reading `~/.strands/box/config.toml`, the starters menu, a starter's `starter.toml`, and the questions it asks. |
| `policy_starter` | The policy starters that `box` ships and the operator's own, the `[policy-starters]` menu, and the policy question. |
| `check` | Box Core's check of a compiled policy, and each error placed by Box Core's location. |
| `run` | `box run`: mint an instance or find the one `--box-id` names, resolve, compile, and call Box Core. It owns the optional banner terminal. |
| `run_list` | `box runs list`: read saved profiles, configuration update times, and run IDs without changing runs. |
| `records` | `box runs history`: read saved policy decisions for a run, filter their recorded fields, and print text or JSON. |
| `output` | `OutputFormat`: the text or JSON selection shared by `box runs list`, `box runs history`, and `box profile show`; `json_line` writes one JSON document on a line. |
| `telemetry` | The adapter that passes loaded profile bytes, packs, and resolved MCP targets to `strands-box-cli-telemetry`. |
| `storage_hooks` | The hooks that a `[[storage.hooks]]` row imports from a host file: the walk that its `key` states, the script checks, and the rewrite of the copy on each run. |
| `credential` | The credential reference. |
| `report` | The operator report. |

`compile` owns the config contract, so its output matches Box Core's schema.
`crates/cli/telemetry` owns telemetry consent, collection, payload construction, delivery, and schema checks. It collects
system metadata, persists installation identity, hashes loaded sources, verifies pack origins,
and reads saved MCP sections.
It depends on no CLI or Box Core types.
`crates/cli/pack-tests` (`strands-box-cli-pack-tests`) holds the tests of the packs that `box`
ships. Each pack with tests has one module, named after the pack (`src/<pack>.rs`). It runs `box`
through the CLI's `test-support` API (`FakeHost`, `Trial`, `Launcher`, and the helpers in
`test_support`). A test that checks what one shipped pack does goes in the module of that pack.
A test of the profile language, or of `box` with a pack as its example, stays beside the code it
tests. Some pack tests use CLI internals that `test-support` does not expose, so they stay in
`strands-box-cli`: the yarn, node, and bunx tests that use the `Scene` of `profile_tests.rs`, the
kiro starter test in `starter_tests.rs`, and the codex starter test in `tests.rs`.
`docs/design/cli/decisions.md` states why the profile model is what it is,
`docs/design/cli/profile-language.md` states the language, and `docs/design/cli/profiles.md` shows a run
end to end. `box` has no direct dependency on a policy crate: `box run` and `box profile show`
call `strands_box::check_policy()`, so Box Core validates the policy before a box starts.

## Building and testing

```sh
just build-cli
cargo test  --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`just --list` holds the workspace tasks. `just check` is the pre-push gate. Root `AGENTS.md` holds
Box Core's own gates.
`cargo test -p strands-box-cli-profile` tests the profile crate on its own, without the CLI.
`cargo test -p strands-box-cli-pack-tests` tests the shipped packs, and
`cargo test -p strands-box-cli-pack-tests codex::` tests one of them. For a pack with tests that
stay in `strands-box-cli` (yarn, node, bunx, pi, kiro, and codex), also run
`cargo test -p strands-box-cli --lib <pack>`.

`crates/cli/app/tests/engine.rs` runs `box run` against a real Box Core. `just test-engine`
builds `box`, Box Core's `strands-box`, and both helpers before it runs the suite. Missing helpers
fail the tests. The MCP test runs `strands-box policy generate-schema` on a compiled `box.toml`,
and `BOX_ENGINE` names another Box Core binary for it ([`docs/dev/engine-tests.md`](../../docs/dev/engine-tests.md)). The CI
`macos` job (in `cli-test.yml`, which `ci.yml` calls) builds the same programs and runs the suite on each push, each pull request that is
not a draft, and each night. A pull request merges only when the `CI Gate` job passes. It needs
every other CI job, and it fails on a draft. On a pull request, the `detect-changes` job's path
filters skip the jobs that its files cannot affect: a docs-only pull request runs only Prose,
Packaging tests, and the gate, a CLI-only pull request skips Box Core's unit tests and containment
suite, and a Box Core change also runs the CLI's engine suite. When a CLI check starts to read a
new file, add the file to the `cli` filter. A path that no filter and no entry in the `other` skip
list matches runs every check.

To test what an operator sees in a terminal (a `box` prompt, or an agent TUI in a box), drive the
command in a pseudo-terminal with `scripts/drive_tui.py`. Follow
[`docs/dev/interactive-testing.md`](../../docs/dev/interactive-testing.md) before you claim that an
interactive change works. When the operator asks how to try a change by hand, point them to
[`docs/dev/manual-testing.md`](../../docs/dev/manual-testing.md), and keep that guide current when a step
changes. `scripts/try-build.sh <pr|main>` runs the build that CI made for a pull request or for
`main`, so a reviewer can try a change without building it.

`scripts/macos-release-cli.py` signs and notarizes the macOS build of `box`. No workflow calls it
yet. Its `NATIVE_LAUNCHER` is the launcher that a test in `resources.rs` installs.

## Working principles

- **Docs ship with the code.** A change is not done until its docs match it, in the same commit.
  See [Docs](#docs).
- **Adversarial review before commit.** Review code once, immediately before commit, as a gate
  beside build, clippy, fmt, and test. The `feature-critic` and `test-critic` agents do the review.
- **Write few comments, or none.** A comment names what an item is. Rationale belongs in
  `docs/design/cli/decisions.md`. One line, and stop. A shipped `pack.toml` or `plugin.toml` is the
  exception: see [Pack comments](#pack-comments).
- **Name a type after what it is in the product**, not the mechanism.

## Docs

Docs change in the same commit as the code they describe. A checkout of any commit then shows the
user guide and the design as they were at that commit, and `git log -p` on a doc shows how it got
there. So no doc carries a date, a status, or a changelog.

The CLI is pre-1.0 and in flux. Document the user-facing surfaces that ship, not each
intermediate change on the way to them. A behavior that changes while a feature is in flux is not a
regression, and an in-flux flag, message, or error with no `docs/cli/` entry is not doc debt.

Six places hold repository documentation. Each has one reader and one test for what belongs there.

| Place | Reader | Answers | Belongs here when |
| --- | --- | --- | --- |
| `docs/cli/` | An operator who runs `box` | How do I use it? | An operator needs it to use `box` without the source or the designs, and it holds for more than one pack. |
| `resources/packs/<pack>/README.md`, `resources/plugins/<plugin>/README.md` | An operator who uses that pack or plugin | How do I use this pack or plugin? | It holds only for that pack or plugin: its sign-in, its options, its setup steps, its errors, and what it does not support. |
| `docs/design/cli/decisions.md` | A contributor or a reviewer | Why is it like this? | The user decided a choice that passes the `decision` skill's test: it refuses or redirects a later change to a different part of `box`. |
| Comments in `resources/packs/<pack>/pack.toml`, `resources/plugins/<plugin>/plugin.toml` | A pack or plugin author, or a reviewer | Why does this pack or plugin hold this line? | The reason applies to that file's line, and to no other pack or plugin. |
| `docs/design/cli/<topic>.md` | A contributor | How does it work? | A new contributor would lose an hour to rediscover it. |
| `docs/dev/` | A contributor | How do I work on this repository? | A build, test, or manual-test step is not obvious. |

`resources/editing-box-profile.md` is a shipped asset for a coding agent without the
source checkout, so it is the one doc allowed to repeat the profile reference. A change to a key or
a rule that it repeats updates it in the same change. The repository
authoring skill keeps its source-checkout context.

### Where each fact lives

A fact about the present surface has one owning page. Every other page that needs it shows the
command or the minimal TOML for its own task and links to the owner. It does not copy a list, a
default, an accepted-value set, or a precedence order.

| Fact | Owner |
| --- | --- |
| Profile and pack keys and tables: name, type, default, accepted values, which file may hold them | `docs/cli/profiles-reference.md` for a key that a profile writes and the rules that profiles and packs share, and `docs/cli/packs-reference.md` for a key that only a pack writes. A profile task goes in `docs/cli/profiles.md`, which shows the keys the task uses and links the reference. |
| Commands and flags, the `BOX_*` variables that `box` reads, exit status | `docs/cli/cli.md` |
| Installing, upgrading, and removing `box`, and the installer's variables | `docs/cli/install.md` |
| Files under `~/.strands/box` | `docs/cli/files.md` |
| The tables and keys of `~/.strands/box/config.toml` (`[starters]`, `[policy-starters]`, `[banner]`), and which banner setting wins: `--banner`, a profile's `[banner]`, or `config.toml` | `docs/cli/config.md` |
| What a starter or a policy starter is, how to write one, the policy menu, and creating a profile from one: the questions, detected answers, the policy choice and the link to the shipped policies in `resources/policies/` on GitHub | `docs/cli/starters.md` |
| What Box is, and how its parts fit together | `docs/cli/how-box-works.md`, a short section for each part |
| What a profile is and decides, where it lives, and how to change one | `docs/cli/profiles.md`, with an example for each change. `docs/cli/profiles-reference.md` is the key reference. |
| What a pack is, its kinds, and how to write one | `docs/cli/packs.md`. `docs/cli/packs-reference.md` is the key reference. |
| What a plugin is, how to use one, and how to write one | `docs/cli/plugins.md`. `docs/cli/plugins-reference.md` is the reference for the `plugin.toml` keys and the plugin rules. |
| The `starter.toml` keys and the policy starter keys (`policy.toml`) | `docs/cli/starters-reference.md` |
| What a policy checks, where a run's rules come from (rule files, generated rules, Box Core's checks), and how to write a rule | `docs/cli/policies.md`. Box Core's policy guide owns the rule syntax. |
| How `box` joins a run's policy, and the `@id` of each generated rule | `docs/cli/policies-reference.md` |
| The shipped packs and plugins | `docs/cli/README.md` (see [Pack READMEs](#pack-readmes)) |
| What an error means and how to fix it, when the message does not say | `docs/cli/troubleshooting.md`, or the pack's README |
| What a box leaves to the operator, for every pack | `docs/cli/limitations.md`, or the pack's README for a limit of one pack |
| How a part works: steps, merge semantics, what reaches Box Core | The design page for the area. It names the keys it explains and links to the user page for the rest. A user page that would explain the mechanism links here for background instead. |
| Why a choice holds | `decisions.md`. An entry names what it decides, not the current list of keys, flags, or defaults. |

A complete list of keys, tables, flags, packs, or starters exists once. When a change adds to such
a list in a second place, delete the copy and link to the owner instead of updating it.

### What a change updates

Each fact the change adds or changes goes to its owner in the table above. The rows below say which
other kinds of doc a change also needs. They do not add a second home for the same fact.

| When a change ... | Update |
| --- | --- |
| Adds, changes, or removes a command, flag, prompt, error message, path, or `BOX_*` variable | Its owner, or the pack's `README.md` when only one shipped pack has it. A how-to page that the change makes wrong. |
| Settles a choice that passes the `decision` skill's test, after the user decides it | One entry in `decisions.md`, with the `decision` skill. Every other choice is a sentence in the pull request. |
| Adds or changes a line in a shipped pack or plugin for a reason that only it has | A comment beside the line, in that `pack.toml` or `plugin.toml`. |
| Adds or changes an option, a setup step, an error, or a limit that only one shipped pack or plugin has | Its `README.md`. See [Pack READMEs](#pack-readmes). |
| Goes against or reverses an entry | Fit the code to the entry, or rewrite that entry in place with a human's approval, and keep its anchor. |
| Changes how a part works: the steps of a run, the files it writes, what reaches Box Core | The design page for that area. |
| Changes the profile language or editing workflow | `docs/cli/profiles-reference.md`, `docs/cli/packs-reference.md`, or `docs/cli/plugins-reference.md`, and the part of `resources/editing-box-profile.md` that repeats it. |
| Changes a build, test, or manual-test step | The guide in `docs/dev/`. |

### Rules

- **One fact has one home in repository documentation** ([Where each fact lives](#where-each-fact-lives)).
  A user page may link a design page for background, and still states each fact the operator needs
  to act. A design page links to the user page for a command or a key, and to `decisions.md` for a
  reason. A restated fact is fixed by deleting the copy.
- **Examples share their sample values.** A sample box ID is `b-5b8e3d70c92f14ab`, so a
  format change is one search and replace.
- **Decision entries.** Record an entry only when the choice passes the test in the `decision`
  skill, and only after the user decides it. A choice that an operator would notice goes to the
  user before code. Every other choice is a sentence in the pull request. An agent never records
  its own choice for review. A missing entry is never a review finding. The log can lag the code,
  and the code owns current behavior. A change that goes against an entry either fits the code to
  the entry or rewrites the entry, and a human approves the rewrite. A pull request that changes
  what an entry says fixes that entry.
- **Plans, drafts, and research stay local.** They go in `.agents/plans/`, `.agents/drafts/`, and
  `.agents/explorations/`, which are git-ignored. Never commit them and never link them. When the
  work is done, what a reader needs moves into the places above.
- **Docs state the present.** Git holds the history.
- **Never cite `file.rs:LINE`.** Name the symbol or the type.
- **Add no doc a reader did not ask for.** A longer doc is not a better doc.

### Pack comments

A shipped pack keeps its own reasons. A comment beside a variable, a grant, a helper, or a starter
row states why the pack holds it: what the tool does without it, or why a grant stops where it
stops. A pack's tested versions go in a comment at the top of the file. The comment changes in the
same diff as its line, and it ships with the pack, so an operator who copies the pack gets it too.
A shipped plugin keeps the reasons for its lines in its `plugin.toml` in the same way.

- A reason that holds for more than one pack, or for `box` itself, is an entry in `decisions.md`.
  The pack comment links to it by path and anchor (`docs/design/cli/decisions.md#<anchor>`).
- A design page describes what packs have in common, and does not repeat a pack's comments.

### Pack READMEs

A shipped pack keeps its own operator docs in `README.md` beside its `pack.toml`. An operator reads
it in the repository, as they read `docs/cli/`. A copy also ships beside the installed pack, but
`docs/cli/` does not ship, so a relative link from that copy to a user page resolves only in the
repository. A comment in `pack.toml` states why a line is there, for a pack author. The
README states how to use the pack, for an operator. The two do not repeat each other. A shipped
plugin keeps its `README.md` beside its `plugin.toml`, and each rule below holds for it too.

- **Pack-only facts go in the README.** Examples: how an agent signs in, a pack's options such as
  `kiro.sign-in` or `claude.import-skills`, a setup step that only one agent needs, how one agent
  asks before it acts, what one agent brings into the box, an error that only one agent prints,
  and what a pack does not support.
- **`docs/cli/` names no pack's own behavior.** It describes `box` and what every pack uses:
  profiles, packs, plugins, policies, starters, imports, credentials, and the checks a run makes. It does not
  list each pack's limits, fixes, or settings, and it does not add a link per pack at each place.
  This scales to any number of packs, including packs that `box` does not ship.
- **One generic pointer per page.** `limitations.md` and `troubleshooting.md` each say once that a
  pack's own limits and fixes are in the **Limitations** and **Troubleshooting** sections of its
  README, and link to the pack list.
- **One pack list.** `docs/cli/README.md` lists each shipped pack that has a README, under the
  heading for its kind of pack, such as **Agents**, and each shipped plugin under **Plugins**.
  This is the only place in `docs/cli/` that names each pack and each plugin.
- **Fixed headings.** A README opens with what the pack does, then holds the how-to sections the
  pack needs. Limits go under `## Limitations` and errors under `## Troubleshooting`, with those
  exact headings, so the generic pointer stays correct for every pack.
- **One example agent.** `docs/cli/` uses Claude Code (`@box/claude`) as its example. An example
  shows a shared mechanism. A fact that holds only for Claude Code goes in `@box/claude`'s README.
  `docs/cli/` uses `@box/1password` as its example plugin, under the same rule.
- **The tutorial is the exception.** `getting-started.md` is a Claude Code walkthrough. It keeps
  each Claude Code fact that an operator needs to finish it, such as the model choice and the
  first-run prompts, and it may link to `@box/claude`'s README for the rest.
- **Pack-only text in `docs/cli/` is a docs finding**, except in the tutorial. Move it to the
  pack's README.
- Links: a README links to a user page as `../../../docs/cli/<page>.md`, and
  `docs/cli/README.md` links to a README as `../../resources/packs/<pack>/README.md` or
  `../../resources/plugins/<plugin>/README.md`.

### Voice

[`.agents/references/writing.md`](../../.agents/references/writing.md) holds the rules.

- **`docs/cli/` and pack READMEs are for a person.** Plain English that a person can read aloud: lead with the
  goal, show the command and its output, use the operator's words, and leave out internals.
- **Design pages in `docs/design/cli/` are plain English too**, written as an explanation for a
  contributor or a reviewer ([Design pages](../../.agents/references/writing.md#design-pages)). An
  existing page moves to this voice when a change rewrites it.
- **Everything else is for an engineer.** Decision entries, dev guides, agent guidance,
  commit messages, review text, and comments use plain English: short declarative sentences,
  present tense, positive statements. They are exact about mechanism.
- **No em-dashes or en-dashes in `docs/cli/`, `docs/design/`, pack, plugin, and policy READMEs,
  or decision entries.** Use a period, comma, parentheses, colon, or "and"/"but"/"so". `just prose` checks
  those files.
- **"Surrounding OS" and "operator".** User and design prose follows the
  [terms](../../.agents/references/writing.md#terms-in-user-and-design-prose) in `writing.md`.

### Skills

`.agents/` holds the skills and agents, and `.claude/skills` and `.claude/agents` link to it.

| Skill or agent | Use it to |
| --- | --- |
| `feature` | Build a change end to end, with its docs in the same change. |
| `decision` | Record, re-answer, or weigh one entry in `decisions.md`. |
| `user-docs` | Write or rewrite a page in `docs/cli/`, or a pack's or plugin's `README.md`. |
| `docs-sync` | Find each doc that a change, or the code as it is, makes wrong. |
| `feature-critic` (agent) | Review a change in a fresh context before commit, docs included. |
| `test-critic` (agent) | Prove that each new test fails without its change, beside `feature-critic`. |
| `decision-critic` (agent) | Review the reasoning in a decision draft or entry before the user decides it. |

A pull request body follows [the template](../../.github/pull_request_template.md): Description, Related
Issues, Type of Change, Testing, and Checklist. Write it as plain prose a teammate would write. Lead with the
problem and why the change is right, then say how it works in a few sentences. Do not use stacked
bold labels or a file list. Name each decision entry the change adds or rewrites by anchor. A
choice that is not a decision, as the `decision` skill defines it, is one to three sentences in the
body.

After you open a pull request, do not amend, rebase, or force-push. To catch up with `main` or fix
a conflict, merge `origin/main` into the branch and push. The squash merge drops those merge
commits.

Every `Cargo.lock` change needs a maintainer's approval before it merges. The pull request says
which versions moved and why.

## Pull request title

The merge squashes a pull request, so its title becomes the commit subject on `main`. Write the
title as a conventional commit, `type(scope): subject`, with a lowercase subject in the imperative
mood: `feat(cli): let operators write their own policy starters`.

- **Type**: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, or `revert`.
- **Scope**: optional. Name the area: `cli`, `profile`, `telemetry`, `packs` (or one pack, such as
  `codex`), `corpus`, `release`, or `workloads`. A `docs` title can name the guide: `user` for
  `docs/cli/`, `design` for `docs/design/cli/`, or `dev` for `docs/dev/`.

`.github/workflows/pr-title.yml` checks the title on each pull request to `main`. It is the same
check that Box Core uses. It is not a required check.
