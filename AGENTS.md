# AGENTS.md

Guidance for coding agents. `CLAUDE.md` symlinks to this file, here and in `box`, `containment`,
`credentials`, and `policy`. Edit the `AGENTS.md`.

**To run Box, not to change it**, follow [`docs/user/getting-started.md`](docs/user/getting-started.md),
or use the `setting-up-a-box` skill.

## Commit and pull request flow

Open the pull request against `main`, and paste its URL in the chat response. The merge squashes
the branch, and the pull request title becomes the subject of the commit on `main`. Do not
squash the branch yourself.

**Add a commit for each change, and do not rewrite history that a reviewer saw.** Do not amend,
squash, or force-push after you open the pull request, because a rewritten branch removes the
reviewer's view of what changed since their last review. Rebase onto `main` only to resolve a
conflict.

**The first commit message has three sections, in this order, and no fourth.** The subject line
comes first, then:

1. **Problem.** What is wrong today, and what it costs. State it before any solution. A commit that
   cannot name a problem is a commit nobody asked for.
2. **Solution.** What the change does about it, and every interface that moved. Name a rejected
   alternative only when a reader would otherwise ask why.
3. **Tests.** What was run and what it proved. Name the test that pins each claim. State what you
   did **not** run, and what is still broken, in this section rather than nowhere.

Write each section under its own `## ` heading. Keep the whole message in Simplified Technical
English. **A claim about behaviour needs a test named beside it, or it is not a claim.** A later
commit needs only a subject line that names the feedback or the defect it addresses.

**A pull request description follows `.github/PULL_REQUEST_TEMPLATE.md`.** Lead with the problem and
the reasoning a reviewer cannot read off the diff. State each load-bearing decision, anything verified
in a way continuous integration cannot catch, and each follow-up you deferred and why. Do not restate
the file list.

Write all pull-request prose in ASD-STE100 Simplified Technical English.

## STOP — `strands-box` is interface-frozen

Two classes of change need the user's explicit approval **before** you write code, and an agent
may not grant it to itself:

1. **An interface change** — anything an external party observes or depends on.
2. **A foundational-premise change** — anything that alters *why* the box is safe.

The freeze is a scrutiny gate, not a prohibition. What is forbidden is making one
**incidentally**: during a refactor, during a cleanup, or to make a test easier to write. A
rename counts, and so does an addition. The test is not "is this source-compatible" but **"can
an external party observe this."** `feature-critic` treats both classes as BLOCKER-tier.

**Frozen surfaces**, each stated in full in `box/AGENTS.md`: the CLI verbs and their flags
(`run` and `policy generate-schema` — `stop`, `ls`, `rm`, and `reset` are deleted with the
`~/.strands-box/b/` namespace they enumerated, because a caller supplies `box_dir` and Box cannot
locate a box it was not handed);
the nine `box.toml` top-level keys (`name`, `box_dir`, `policy`, `agent`, `tool`,
`egress`, `mcp`, `telemetry`, `experimental-features`), of which `name` and `box_dir` are required; the five fields that `[agent]` and each `[tool.<name>]` hold
(`command`, `workspace`, `env`, `filesystem`, `native-filesystem-policy`); the filesystem lists — `[agent.filesystem]`
holds eight, and a `[tool.<name>.filesystem]` holds six, because `metadata` and `exec` are refused on a tool
(a leaf discovers metadata across the operator home, and runs its toolchain through broad exec on
macOS); the four box inputs (policy,
credentials, name, workload); `Record`, `LiveRecord`, and their versions; the broker protocol at `PROTOCOL_VERSION`; the alias names and
the rule deriving a socket from an alias's own path; the policy action vocabulary and what
`when temporal` observes; each mechanism crate's `pub use` set; and
`reserved_workload_environment`.

**Premises.** Each has a test pinning it. Do not weaken one to land a change, and do not delete
or `#[ignore]` its test to green a suite.

- The authored policy is the only authorizer, and absent policy is default-deny.
- Deny-only floors stay *beneath* policy, never beside it.
- The workload is untrusted, and it writes only where a list grants a write.
- Validate once, then act on the identity you approved.
- The environment is composed, never inherited.
- A credential binding is not an authorization.
- A box's trusted process is hardened and holds only its own box's plaintext secrets.
- `HOME` is the operator's own home, unless `[agent] env.HOME` names another directory. There is no
  private box home, and no verb copies configuration into one. The box directory holds `bin`,
  `run`, `trust`, and `private`, and none of them is a home.
  `box_filesystem.rs::home_is_the_operators_unless_the_agent_declares_one` pins the default.
  **A home grants no reach.** The workload reaches a path under the home only when a list in
  `[agent.filesystem]` names it, which
  `reach_under_the_operator_home_is_only_what_is_listed` and
  `a_harness_configuration_directory_reads_when_listed_and_not_otherwise` pin. The lists
  (`read`, `write`, `read_file`, `write_file`, `list`, `metadata`, `exec`, `deny`) are where an
  operator states direct reach for the workload's own syscalls, and `write` does not imply `read`.
  `[agent.filesystem]` holds all eight; a `[tool.<name>.filesystem]` holds six, because a tool
  discovers existence and metadata across the operator home and runs its toolchain
  through broad exec on macOS, and so states no
  `metadata` and no `exec` list — the leaf renders the inverse of the agent box's existence-denied home
  and runs its toolchain via `process-exec*`, on macOS, keeping content gated and the credential floor
  and box state refused; the agent box keeps enumerated exec and full W^X and is byte-identical.
  Linux is the residual: a writable bind reads there, and the startup disclosure says so on that
  entry's line.
  Each grant is disclosed on stderr at startup, because no `fs:*` decision covers one. An absent
  section grants none of it. `workspace` names the initial working directory and grants nothing: the
  box enters it, and the workload cannot read it until a list names it, which
  `the_workspace_is_enterable_and_unreadable_until_listed` pins.
  **`[agent.filesystem]` and `[agent] workspace` govern the agent's box alone.** A tool gets its
  reach from its own `[tool.<name>]` table, through the same translation. No box's own
  `.strands-box` is reachable from either, which
  `the_boxs_own_private_tree_is_unreachable_from_inside` and
  `run_config.rs::a_tool_grant_cannot_expose_the_box_directory` pin.
- The trusted half is the `run` process
  ([decisions](docs/design/decisions.md#one-trusted-process-per-box)), and one `run` owns a box
  ([decisions](docs/design/decisions.md#one-run-owns-one-box-directory)).
  `serve/` is gone: the broker moved to `run/broker/`, `serve/daemon/` and the `daemon` verb are
  deleted, and box has no library target. Do not reintroduce a daemon.
- Every declared stdio MCP server runs in its own contained leaf box, and `shell:spawn` decides
  whether it starts. `mcp.rs::a_grantless_stdio_entry_is_still_contained` and
  `runtime_mcp_start.rs::absent_start_permit_refuses_the_server_and_it_never_runs` pin the two
  halves. A leaf that sets `contain_egress = false` bypasses the gateway, and that downgrade is
  residual risk.

**Instead of changing an interface:** fix the defect behind it, because most findings are a
missing refusal. If one must change, ask first and name what breaks. Bump `RECORD_VERSION`,
`LIVE_VERSION`, or `PROTOCOL_VERSION` when its shape changes. **An approved interface change
carries the page that states that interface, in the same commit**, because a frozen surface is one
an external party reads about before they depend on it. [What a change
updates](#what-a-change-updates) names the page for each surface.

## Agent process boundary — DO NOT BROADEN

Every interpreter stays outside the Agent's Seatbelt domain. Preserve this shape:

```text
strands-box run  (the box's TCB)       trusted, outside Agent SBPL
|-- Policy  (ONE per box)              the only authority; one temporal history
|-- egress gateway  ------------------> that Policy
|-- Strands Shell   (one per REQUEST) -> that Policy
|-- Monty / Python  (one per REQUEST) -> that Policy
`-- strands-box-contain-trampoline -> contained Agent
                      `-- private zsh / bash / sh / python3 / python aliases -> box.sock
```

All five aliases reach one `run/box.sock`, and `argv[0]` selects the interpreter before the
client connects.

- **One `Policy` per box**
  ([decisions](docs/design/decisions.md#one-policy-engine-per-box)), in the box's own process. Two instances mean two temporal
  histories, so a rule spanning `fs:*` and `net:*` enforces nothing.
- **One Shell and one Monty VM per request**
  ([decisions](docs/design/decisions.md#no-state-crosses-a-call-boundary)).
- **The interpreters run outside the cage**, reached only over a pathname socket.

The macOS minimum for an agent invoking Shell as a child:

```scheme
(allow process-exec (literal "<agent>"))
(allow file-read-metadata (literal "<agent>"))
(allow process-exec (literal "<shell alias>"))
(allow file-read-metadata (literal "<shell alias>"))
(allow process-fork)
```

- The paired `file-read-metadata` is required, because a `PATH` search stats each candidate
  before it execs. Grant metadata only, never `file-read*`.
- `posix_spawn` and `fork` need the unscoped `process-fork`. SBPL has no path, argv, or
  child-count filter for it, so a generic filter compiles and authorizes nothing.
- Never use `process-exec*`, a host shell, or an inherited `PATH` tree **in the agent box**. The
  agent has no broad-exec carve-out: it gets one `process-exec` rule for its own command, and one
  more for each `exec` entry — a literal for a file, and a subpath for a directory — each paired with
  a metadata read and never with `file-read*`. The operator-authorized **leaf** is the one carve-out
  ([decisions](docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds),
  macOS-only): it renders `process-exec*` so a tool runs its whole toolchain
  after `shell:spawn` admits the top-level program, and one `(allow file-map-executable …)` over its
  writable grants so a build loads what it compiles, while the agent keeps full W^X.
  `seatbelt.rs::the_agent_profile_never_carries_broad_exec` pins the agent's count and the absence of
  the broad form, and `a_leaf_carries_broad_exec_and_the_main_box_does_not` pins the leaf exception.
- `process-fork` leaves fork-bomb risk as stated residual risk.
- **Never execute a workload-named program from the box's trusted process.** That process is
  outside the cage, so `Command::new(name)` there is arbitrary code execution, and a `permit`
  covers *whether* a program runs and never *where*. A real binary belongs inside the cage,
  exec'd by the shim, one `process-exec` literal plus its paired metadata read per allowlisted
  binary, on a read-only bind. Then `fs:*` stops firing, and one decision covers a process tree.

## Current state

`crates/box` is the box, and its mechanism crates sit beside it — `credentials`, `containment`,
`egress-gateway`, `policy`, `telemetry`. `box` is `[[bin]]`-only. Vendored: `shell`, with an `UPSTREAM.md`. `.agents/pocs/` is outside the workspace. Read `members` in `Cargo.toml`.

**Read `telemetry`'s own `AGENTS.md` before you build on it.** Its receiver is reachable by the
workload, and it carries an open defect that hangs a box on exit.

`egress-gateway` is the outbound boundary and holds no allow/deny authority. Two things there
are deliberately not authorization: the SSRF floor, which is deny-only, and `CapabilityOutcome`,
which has no `Allow` variant. `policy` exposes one facade: `PolicyEngine::open`, `decide`, `record`,
`effective`.

`policy` embeds the durable Dogwood engine through the published `dogwood-language` and
`dogwood-local-engine` crates. Its commit, recovery, policy-change, and time contract is owned by
the policy crate's tests, and
[history is durable per box](docs/design/decisions.md#history-is-durable-per-box-and-has-no-rewind)
records why.

## Vendored upstreams

The vendored crate is pinned but **not** frozen. Ask: *would upstream call this a bug?*
Yes means fix it there and say in the diff why it is upstream's — a wrong result, a lost error, a
hang, an unsound check, or a suspension its API cannot report. No means orchestrate it in `box/`,
which owns composition.

1. **Assert the requirement; do not merely satisfy it.** Prefer impossible by construction, and
   settle for refuses at startup.
2. **A vendored fix keeps its suite green and adds no lints.** These crates carry upstream lint
   failures, so the check is *unchanged warning count*. Record divergence in `UPSTREAM.md`.
3. **Prove the guard fires.** Introduce the defect, watch the refusal, restore.

A change that makes a local build work, relaxes a version, or routes around something the box
should configure is divergence.

## Building and testing

`rust-toolchain.toml` pins the compiler, and rustup installs it on the first build. Never edit
`Cargo.lock` and never relax a version requirement:

```sh
cargo build   -p <package> --all-features
cargo test    -p <package> --all-features
cargo clippy  -p <package> --all-targets --all-features
cargo fmt     -p <package> --check
```

- **`--all-features` is not optional.** `box_shell` and `box_credentials` sit behind
  `test-support`, so a plain `cargo test` skips them and reports success.
- **Interpreter-dependent tests skip rather than fail.** Watch for `skipping: ...`.
- **Owned clippy warnings are not expected; vendored ones are.** Check your crate:
  `cargo clippy ... 2>&1 | grep -c -- '--> crates/<your-crate>'` must print `0`.

`just --list` holds the workspace-wide equivalents, and [README.md](README.md) what they need.

## Working principles

- **Docs ship with the code.** A change is not done until its docs match it, in the same commit.
  [Docs](#docs) names each place that holds prose, and
  [What a change updates](#what-a-change-updates) maps each observable surface to its page.
- **Understand the problem before you reach for a solution.** Nothing is decided yet, so never
  present a candidate as chosen.
- **Workflow: research, key decisions, align, spec and build.** Research goes to
  `.agents/explorations/` as `{topic}.exp.md`, prototypes to `.agents/pocs/`, and each
  architecture choice to a local `/kd` draft before a spec. A decided choice becomes one entry in
  `docs/design/decisions.md`. A spec is a local `/spec` draft and is never committed. Code lands in
  `crates/`.
- **House style is [docs/conventions.md](docs/conventions.md)**, a checklist to run before you
  commit a new crate or new public surface.
- **Write few comments, or none.** A comment names what an item is. It never argues for a change.
  The rationale belongs in the commit message.

  **One line, and stop.** A `///` gets one sentence. A `//!` gets one sentence, plus a table when
  the module has parts worth listing. Delete the `///` when the name already says it. Nothing in a
  doc comment may state a measurement, a defect it once had, a rejected alternative, or a reason.
  Those go in the crate's `AGENTS.md`. A second copy inline is how the two came to disagree.

  **Do not restate a decision beside the code that implements it.** Cite its
  `docs/design/decisions.md` anchor instead, because a reader who needs the signature must not
  scroll past the argument.

  **Assume a reader who knows the language.** Never explain what a `Vec`, a `match`, or an `Option`
  does.
- **`containment` is the reference public surface — copy it.** Private modules so the `pub use`
  facade bounds the API, `#![warn(missing_docs, unreachable_pub)]`, one root noun reached by one
  verb taking one config value, a fluent consuming builder with no `XBuilder` and no `.build()`,
  `pub(crate)` provider traits, and a sealed named-profile constructor.
- **Name a type after what it is in this product**, not the mechanism and not an abstract shape.
  **`session` is banned in new public names**; say `workload`. Avoid abbreviations. A name that
  needs a gloss at a call site is wrong.
- **Adversarial review is mandatory for code, once, immediately before commit** — a gate beside
  build, clippy, fmt, and test. Never run one mid-task on work still being shaped.
  `feature-critic` reviews code, runs the gates, and checks the prose that the diff falsifies.
  `decision-critic` reviews a decision or a spec and is not a gate. **No review asks for a doc that
  the change did not make wrong, and no review asks a code change to add a decision entry.** Triage
  every finding: fix it, or say why you left it.

### Docs

**Docs ship with the code.** A change is not done until its docs match it, in the same commit. A
checkout of any commit then shows the user guide and the design guide as they were at that commit,
and `git log -p` on a page shows how it got there. So no page carries a date, a status, or a
changelog.

This repository is pre-1.0 and in flux. Document the surfaces that ship, not each step on the way to
one. A behaviour that changes while a feature is in flux is not a regression, and an in-flux flag,
message, or error with no `docs/user/` entry is not doc debt. Two things narrow this valve. A surface
that the freeze above names is not in flux, so a change to one is never exempt from the table below.
And the valve covers prose alone: a committed artifact that must still work, such as a policy under
`examples/`, is not prose and no change may leave it broken.

**Seven places hold committed prose that a code change can make wrong, and there is no eighth.**
Each has one reader and one test for what belongs there. The `docs-writer`, `docs-reviewer`,
`docs-audit`, and `docs-planner` skills apply
[`.agents/references/voice-guide.md`](.agents/references/voice-guide.md) to the two guides, and
`docs-sync` finds which of the seven a change makes wrong.

| Place | Reader | Answers | Belongs here when |
|---|---|---|---|
| `docs/user/` | An operator who runs a box | How do I use it? | An operator needs it to run Box, without the source and without the design guide. |
| `docs/design/<topic>.md` | A security evaluator or a contributor | How does it work, and why trust it? | A reader must trust the mechanism, or a new contributor loses an hour to rediscover it. |
| `docs/design/decisions.md` | A contributor or a reviewer | Why is it like this? | The user decides a choice through `/kd`. The page is a dated record and it ages, so a code change adds no entry here. |
| `docs/dev/` | A contributor | How do I work on this repository? | A build, test, or debug step needs more than the command. |
| `docs/conventions.md` | A contributor who adds a crate or public surface | What does house style require? | The rule is mechanical, so a reviewer or a gate can check it. |
| `README.md`, here and in each crate | Someone who builds Box, and a consumer of that crate | What is this, and what is its surface? | The purpose, the `pub use` facade, or a gate changes. `crates/box/README.md` also holds the CLI verbs, the four box inputs, and the config keys, and two tests pin it. |
| `AGENTS.md`, here and in each crate | A coding agent | What must I not break here? | A frozen surface, a premise, or a gate moves. |

`.agents/explorations/`, `.agents/drafts/`, and `.agents/pocs/` hold local working material and are
never committed. Add no doc a reader did not ask for.

#### What a change updates

The left column is the observable surface the diff touches. Each row that matches names the page to
update in the same commit. A surface with no row and no page is in flux, and the valve above covers
it.

| When a change ... | Update |
|---|---|
| Adds, removes, or renames a CLI verb or a flag | `crates/box/README.md`, which `documented_commands.rs` pins, and each `docs/user/` page that spells that verb. |
| Adds, removes, renames, or retypes a `box.toml` key, or a field in `[agent]` or `[tool.<name>]` | `docs/user/config.md`, and `crates/box/README.md`, which `documented_inputs.rs` pins. Also the key's own page when it has one: `egress.md`, `mcp.md`, `telemetry.md`, or `native-filesystem-policy.md`. |
| Changes what a filesystem list grants, or adds or removes a list | `docs/user/config.md`, in the `[agent.filesystem]` section and in what is refused, and `docs/design/containment.md`. |
| Adds, renames, or removes a policy action, an attribute a rule reads, or what `when temporal` observes | `docs/user/policy/actions.md`. Also `docs/user/policy.md` when the count of actions or a common rule moves, and `docs/design/policy.md` when a history rule sees something else. |
| Changes a refusal, a denial, or a warning that an operator reads | The errors or exit-status section of the page for that surface, each under `docs/user/`: `config.md` for the loader, `policy.md` for a policy that fails to load and for how a denial reads, and `shell.md`, `monty.md`, `egress.md`, `mcp.md`, or `telemetry.md` for the rest. A refusal the load emits also reaches `docs/design/policy.md`, which lists the classes of rule the load refuses. |
| Changes the startup disclosure on stderr | `docs/user/config.md`, which holds the example line, and `docs/design/architecture.md`. |
| Changes the box directory, a file it holds, or an alias name | `docs/user/config.md` for what an operator supplies or reads, and `docs/design/binaries.md` for the alias and the socket. |
| Changes the shape of a telemetry record | `docs/user/telemetry.md`, in what a record carries. |
| Bumps `RECORD_VERSION` | `docs/user/native-filesystem-policy.md`, which names each record version by number. |
| Bumps `LIVE_VERSION` or `PROTOCOL_VERSION`, and nothing else | No page. Neither version reaches a reference page, and `docs/user/config.md` states the mismatch refusal without a number. |
| Adds or removes an environment name that the box reserves or composes | `docs/user/config.md` for the refusal the operator meets, and `docs/design/egress.md` for a proxy or a certificate name. |
| Changes how a part works: the order a run comes up, which process decides, what a sandbox grants, what reaches the gateway | The `docs/design/` page for that part. `docs/design/README.md` maps each page to the question it answers. |
| Changes a step in getting started, or a command a tutorial runs | `docs/user/getting-started.md`, and each page under `docs/user/tutorials/` that runs that step. |
| Changes a build, test, or debug command, or a gate | `README.md`, the Building and testing section above, and `docs/dev/` when the step needs a guide. |
| Adds a crate, or changes a crate's `pub use` facade | That crate's `README.md`, and `docs/conventions.md` when the change sets a new house rule. Recount the names from `src/lib.rs` and correct every count in the `README.md` and in the crate's `AGENTS.md`, because each states one. |
| Changes the policy load, the policy grammar, or what a rule may spell | Each committed policy under `examples/` must still load, and each one a page shows must still match that page. |
| Settles a choice that a reader could question or undo | No page in this commit. Offer `/kd` to the user, because an entry enters `docs/design/decisions.md` only after the user decides it. |

#### Rules

1. **A decision enters `docs/design/decisions.md` through `/kd`, and only once the user decides
   it.** The analysis stays in the local draft. An entry states the answer, the alternative that
   lost, and the cost, in the shape its neighbours use. It carries no status line and no date. Each
   entry sits under a stable anchor, and code cites that anchor by relative link.
2. **A decision that moves rewrites the entry it moves.** Rewrite its title, its answer, and every
   cost the change makes false, and keep its `<a id>` anchor, because code cites it. Never leave a
   stale entry beside a second entry that corrects it.
   **No committed doc links a local draft or an exploration note**, because `.gitignore` holds
   `/.agents/drafts/` and `/.agents/explorations/`, so the link is dead in every clone.
3. **One fact has one owner.** The code and its tests own behaviour, and a decision owns why.
   Never cite a `file.rs:LINE`: name the symbol or the test. Never cite a spec, a requirement
   number, or a draft's `KD-N` from code, because none of them is committed.
4. **Mermaid: quote every edge label** as `A -.->|"source kind"| B`, and compile each block with
   `mmdc`. A grep check misses these lexer errors.
5. **Use one word for one thing.** [docs/design/terminology.md](docs/design/terminology.md) gives
   the term to use and the words not to use. It is a rule, not a suggestion. Do not introduce a
   synonym because it reads better in one sentence.
6. **Write every prose artifact in ASD-STE100 Simplified Technical English**, including code
   comments, commit messages, and code-review text. The rules are in the
   [ASD-STE100 specification](https://www.asd-ste100.org/). The style controls the sentences and this
   repository controls the structure. Identifiers are not prose. **The pages in `docs/user/` and
   `docs/design/` are the exception:** they use the plain-English voice in
   `.agents/references/voice-guide.md`, because a reader of a guide must be able to read it aloud.

## AGENTS.md maintenance

Do NOT update this file unless explicitly asked.
