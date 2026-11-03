# Documentation updates

Read this reference before writing or reviewing docs, or committing a code change.
Paths in backticks are relative to the repository root.

**Docs ship with the code.** A change is not done until its docs match it, in the same commit. A
checkout of any commit then shows the user guide and the design guide as they were at that commit,
and `git log -p` on a page shows how it got there. So no page carries a date, a status, or a
changelog.

This repository is pre-1.0 and in flux. Document the surfaces that ship, not each step on the way to
one. A behaviour that changes while a feature is in flux is not a regression, and an in-flux flag,
message, or error with no `docs/user/` entry is not doc debt. Two things narrow this valve. A surface
that the [interface freeze](../../AGENTS.md#strands-box-is-interface-frozen) names is not in flux,
so a change to one is never exempt from the table below.
And the valve covers prose alone: a committed artifact that must still work, such as a policy under
`examples/`, is not prose and no change may leave it broken.

**Seven places hold committed prose that a code change can make wrong, and there is no eighth.**
Each has one reader and one test for what belongs there. The `docs-writer`, `docs-reviewer`,
`docs-audit`, and `docs-planner` skills apply
[the voice guide](voice-guide.md) to the two guides, and
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

`team/designs/` holds the design documents that a human writes before a feature is built. A
design document is a snapshot that is not kept in step with the code, so it is not one of the seven.
An agent does not write, audit, or update one.

## What a change updates

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
| Changes a build, test, or debug command, or a gate | `README.md`, the [verification rules](../../AGENTS.md#verify-before-commit), and `docs/dev/` when the step needs a guide. |
| Adds a crate, or changes a crate's `pub use` facade | That crate's `README.md`, and `docs/conventions.md` when the change sets a new house rule. Recount the names from `src/lib.rs` and correct every count in the `README.md` and in the crate's `AGENTS.md`, because each states one. |
| Changes the policy load, the policy grammar, or what a rule may spell | Each committed policy under `examples/` must still load, and each one a page shows must still match that page. |
| Settles a choice that a reader could question or undo | No page in this commit. Offer `/kd` to the user, because an entry enters `docs/design/decisions.md` only after the user decides it. |
