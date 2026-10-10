Follow [repository guidance](../../AGENTS.md).

## ⛔ This crate is interface-frozen

Read the **"`strands-box` is interface-frozen"** section of the
[repository guidance](../../AGENTS.md) before changing anything here. A change to an
observable surface — the CLI verbs and flags, `box.toml`'s keys, the four box inputs, the
on-disk records (`Record` at `RECORD_VERSION`, `BoxLive` at
`LIVE_VERSION`), the broker wire protocol, the alias names and their socket derivation, the
policy action vocabulary, the composed workload environment — or to a foundational premise,
needs the user's explicit approval **before** the code is written. Fixing a defect behind the
current interface needs no approval and is almost always the right move. Even a *narrowing*
is gated, and no security test named here may be deleted or `#[ignore]`d to green a suite.

## Module map — one decision per module

**This layout is deliberate. Do not collapse, merge, or re-split these modules as part of
unrelated work.** `dispatch` in `command/mod.rs` is the sequence of decisions; each module owns
one and none implements another's. When something needs a home, the question is *which decision
is this*, not *which file is smallest*.

Three groups, split by **lifetime**: `record/` is what a box *is* before anything runs, `run/` is one
box's trusted half alive for one run, and `command/` is the argv parser plus one module per verb.
`error.rs`, `main.rs`, and `test_support.rs` sit at the crate root, and
`bin/strands-box-sock-alias.rs` is the one image every alias execs.

`command/{policy,run}` is **two modules for two verbs**. `command/cli.rs` holds the clap derive tree
and nothing else, and `run/configure` owns **no verb at all**: it is the creation mechanism `run`
calls, and it is not operator-facing. `list`, `stop`, and `remove` are deleted with the verbs they
implemented — see "The lifecycle verbs are gone" below before adding one back.

The three `record/` modules each answer one question. `config` is `box.toml` — the two wire records,
plus one module per vocabulary: `process`, `filesystem`, `egress`, `env`, `mcp`, and `telemetry`.
`process` holds `ProcessSpec`, the one shape `[agent]` and each `[tool.<name>]` take, and the
`Filesystem` that spec carries. `filesystem` translates the eight lists into containment cells.
`layout` sites the filesystem. `config/mcp` is `box.toml`'s MCP
declarations — identity, never authority. `workspace` finds a workspace's `.strands-box/`, which is
where the operator's authored `box.toml` and `policy.dw` live; only `policy generate-schema` reads it
now, because `run` takes one `--config` path and searches nowhere. **That directory is not
`box_dir`** — one word names two things, and the box creates neither.

- **Four phases, in order.** `record::config` decides the four inputs — `Cli`, the `box.toml`
  wire record, and every refusal. `record::layout` sites the filesystem: one root, `BoxRoot`, with
  every other path computed from it. `run::contain::boundary` translates one `ProcessSpec` into a
  boundary: the one exec literal, the eight lists as cells, the runtime minimum, the mediation
  plumbing, and the composed environment.
  `run::contain::supervise` runs the child: process group, wait, exit code.
  *Why separate:* the types enforce a strict dependency order — a `BoxRoot` cannot exist
  before a validated `BoxName`, and a `Boundary` cannot exist before a `BoxRoot`. Merging any
  two would let a later phase's value be built before its input was validated.
- **Four more modules complete `run/contain/`.** `executable` resolves the one exec literal the
  profile permits. `runtime_minimum` states the cells
  Core adds beneath every spec, one list per operating system. `trampoline` owns
  `strands-box-contain-trampoline` integrity, identity-bound exec, and the setup-status pipe.
  `terminal` hands the controlling terminal to the child and hands it back.
  *Why separate:* `executable` and `trampoline` answer unrelated questions — *what may run* versus
  *how the helper is launched safely* — and apart, each is independently testable, which is how the
  trampoline's invariants got tested at all. `runtime_minimum` is a table rather than a decision, so
  it sits apart from the translator that reads it. `terminal` shares nothing with `supervise` but a pid:
  it is `tcsetpgrp` and the `SIGTTOU` dance around it, and it was the least-tested code in that
  file. It takes the leader pid rather than a `ProcessGroup`, which is what keeps the two modules
  from depending on each other.
- **`broker/` is one boundary with two interpreters** —
  `run/broker/{aliases,host,program,protocol,shell,python,reach,mcp}`. `aliases` is box-lifetime
  (exec literals and `PATH` entries, placed when a box is configured), `host` owns the one socket
  and the per-connection reader, `program` is the per-Program state a Call mutates, `shell` and
  `python` are the two interpreters, `reach` states the one reachable path set both share,
  `mcp` owns the two decisions an MCP server meets — `shell:spawn` for whether it starts and
  `mcp:call` for each tool call — and `protocol` is the contract between the two ends.
  *Why one boundary:* `argv[0]` chooses the interpreter before an alias derives a path, so a
  second socket would re-state a decision the client already made. Adding an interpreter costs
  an `Interpreter` variant and a constructor.
  *What is NOT collapsed:* the **five alias files** stay five, because each is a distinct exec
  literal. And the *lifetime* split inside `broker/` is load-bearing — merging `aliases` into
  `host` would put a per-run image copy on the startup path.
  *One narrowed property:* one listener is one failure domain, so a bind failure refuses the
  whole box rather than leaving one interpreter serving. A box where Python silently does not
  work is worse than one that refuses to load.
- **Two names are stale by scope, deferred deliberately.** `ShellError` is the *broker*
  listener's error type (`Bind`, `Serve`) and also covers `aliases.rs`'s image materialization
  for the **Python** alias. And `host.rs` still threads `Arc<ShellSpec>` through four
  signatures, so it is **not** interpreter-agnostic; its module doc says so rather than
  claiming otherwise. Both are known debt, not oversights.
- **`error` holds the typed taxonomy**, one variant group per owner above. Every module needs
  it, so it must not live inside one of them.
- **The composition stays thin.** `main.rs` declares the four modules and calls
  `command::cli_main()`; `cli_main` parses argv, applies the hardening for `run`, builds a runtime,
  and hands off to `dispatch`, which takes one verb per arm. A fifth step, or an inline
  `insert`/`join`/`if let`, belongs in a phase. If either file grows, the phase boundary is
  wrong.
- **No stringly-typed catch-all error.** A new failure gets a variant on the owning phase's
  enum, never a `format!` into a general one.

### Refactors that would undo this, and what they cost

Each looks like a simplification and is not. If one is genuinely wanted, record why here first.

- **Re-merging `executable` into `trampoline`** (or either into `boundary`). Costs the
  independent testability the trampoline's security invariants depend on.
- **Giving `BoxRoot` back its cached path fields** so accessors return `&Path`. That made it a
  bag of six derived values behind eight single-caller accessors. **`BoxRoot` stores `root` and
  `home` precisely because both are canonicalized once** — see the canonicalization rule below,
  which a rewrite here has broken before.
- **Collapsing `boundary` into `command::run`** as "just wiring". It owns the mechanism assembly
  order and holds the proxy alive for the child's lifetime. Inlining puts that ownership in a
  stack frame where nothing names it.
- **Flattening `error` into one `BoxError`** with `String` variants. That is the catch-all,
  re-created.
- **Giving the crate a library target back.** **There is no `lib.rs` and no `[lib]` target**, so
  nothing links the box and every caller reaches it as a process. `tests/library_surface.rs` went
  with the façade. Every module is `pub(crate)`, and what the façade held is now a property of that
  structure. Keep every part:
  - Nothing outside the crate can name `run`, `contain`, or `record`, so `Boundary`, `Trampoline`, and
    `Attachment` are unreachable. That matters most for `run`, because `flock` is per file
    descriptor, so two in-process calls both succeed, and that breaks
    [one policy engine per box](../../docs/design/decisions.md#one-policy-engine-per-box).
  - `Boundary::assemble` and `Trampoline::command` stay `pub(crate)`. A caller that can assemble a
    boundary can assemble a weaker one.
  - `BoxError` is an **opaque struct** over a `pub(crate)` enum. Exposing the enum leaks nine
    mechanism types.
  - **No signature names or returns a `PolicyEngine`**, a host path, a working directory, an
    environment overlay, or a proxy port. So nothing outside the box holds an authority object.

  **Nothing outside the box depends on a box crate, and that absence is the enforcement.** A
  caller starts `strands-box run` as a child process and reaches it only through that process's
  stdio. So it **cannot** open a `PolicyEngine`, build a `ContainmentConfig`, hold a proxy handle, or resolve a
  secret, because no such type is in scope: one `Policy` per box holds by construction
  rather than by discipline, and no CA private key and no resolved secret can exist in that address
  space. A path dependency would buy nothing either way, because cargo ignores one on a
  `[[bin]]`-only crate and only warns.

  The limit: any crate depending on `strands-box-policy` can call `Policy::open`, whatever this
  crate exposes. The dependency graph and the manifest guard hold the one-instance rule.
  [Box is a process](../../docs/design/decisions.md#box-is-a-process-and-reads-one-complete-configuration)
  states why.

## The box contract

- **The box takes four inputs and no others: policy, credentials, name, workload.** Two are
  authority (policy, credentials), one is identity (name), one is selection (workload). Do not
  add a fifth. In particular do not add an argument, config key, or builder granting
  **authority** the four do not: a working directory, an environment overlay, a proxy port, or a
  mechanism value (`ContainmentConfig`, a proxy handle, a `Vault`, a policy adapter, a
  `containment_bin`). `--work-dir`, `--bind`, `--read-path`, and `--home` must keep reaching the
  workload as its own argv.

  The test is **authority**, not spelling. A key may name a host path and still not be an input.
  A key that decides *which requests are governed*, or grants a reach policy does not judge, is
  a fifth input whatever it is called.

  Two more are ambient
  dependencies the process makes visible — `$HOME` (which must stay ambient, or it becomes the
  caller-chosen home this rule forbids) and `$PATH` (that is the *operator's* environment, so a
  caller wanting determinism passes an absolute program path).

  **`tests/four_inputs.rs` is the guard.** It asserts both halves: no withheld flag is a box
  argument, and `ConfigFile` carries exactly **eight** keys — `agent`, `box_dir`, `egress`, `mcp`,
  `name`, `policy`, `telemetry`, and `tool`. That is the `box.toml` key set, and it is
  **not** the stored `Record`'s key set: `Record` adds `version` and `box_id`, which no operator
  authors. Read
  which one a passage means before you change a count. The withheld-flag guard is split in two —
  `the_withheld_flags_are_not_box_arguments` reads the argv parser for a declared flag and the
  record field lists for a key, while `configuration_keys_are_not_command_line_flags` reads the
  argv parser alone, because a whole-file sweep cannot tell a record's key from a flag. Delete
  either and the other passes while the rule is gone. **A line sweep over the whole config source
  is what both avoid**: it reported `--home` because a private function takes a parameter spelled
  `home`.

  **`env` is a key on every `ProcessSpec`, not a fifth input.** It states the literal environment
  the box hands that process, and the box inherits nothing from the host. It grants no reach and
  cannot claim a name the box owns: `ProcessSpec` refuses every name in
  `reserved_workload_environment`, so proxy routing, CA trust, `PWD`, `USER`, and every loader hook
  are out of its reach, and `compose` applies the table *before* every box-owned name as a second
  line. `HOME` and `PATH` are not reserved, because a process must state where it lives and where it
  looks for a bare name. `HOME` and `TMPDIR` must each be absolute.
  `box_filesystem.rs::no_host_variable_is_inherited` pins the composition.

  **There is no declared bind, and the vocabulary is deleted.** `Reach`'s `Bind` and `Mount`
  types, the `binds` parameter, the `mounts` field, and `to_host`'s renaming branch are gone. Do
  not reintroduce the vocabulary to hold a shape nothing populates. A `~`-relative rule carries
  the portability a bind used to: every path under the operator home is reported relative to it
  before the decision, so an authored policy holds in every clone. Both shipped examples ship
  their policy **verbatim** and assert the old `PROJECT_PATH` token is absent. The remaining
  limit: a project **outside** the operator home has no `~`-relative spelling.

  **`workspace` is a key on every `ProcessSpec`, and it grants nothing.** It names the initial
  working directory. The box canonicalizes it, refuses it unless it is an absolute directory, and
  refuses the operator's home through `record::workspace::refuse_operator_home`. An absent key means
  the agent's own workspace. For a tool it means the caller's working directory, but only when that
  directory resolves inside the agent's workspace or inside a tree the tool's own `read`, `write`,
  `list`, or `metadata` list names; for any other caller directory the tool starts in the agent's
  workspace. What the key changes is which absolute path a *relative* name means. Without it the
  agent started where the policy named nothing, so `cat src/main.rs` resolved outside every rule and
  was default-denied — which reads as a policy bug and broke the shipped codex example's own
  permitted-read check.

  **The workspace is enterable and unreadable until a list names it.** The box grants `Metadata` at
  `Dir` scope, so `chdir` and `getcwd` work. The directory is neither readable nor enumerable. A `read` or `write` entry
  in the same spec's `filesystem` makes the contents reachable by the process's own syscalls, with
  no `fs:*` decision in the path. That is exactly what a project entry buys and what the startup
  disclosure names. `box_filesystem.rs::the_workspace_is_enterable_and_unreadable_until_listed`
  pins the default, and
  `record::config::filesystem::a_project_entry_subtracts_every_boxs_own_authority` pins that such an
  entry still holds no box's `.strands-box`.

  **A tool's workspace and reach come from its own `[tool.<name>]` table.** One translator reads
  both specs, so a tool holds what it declares and nothing the agent declared.
  `run::contain::boundary::one_spec_translates_the_same_as_agent_and_as_tool` pins that the two
  translate alike, and
  `box_shell.rs::the_shells_home_matches_the_workloads_and_its_cwd_is_the_project` pins that the
  hosted Shell stands where the workload stands.

  **MCP servers are `box.toml` tables, not a second file.** Each server is one `[mcp.<name>]`
  table whose `type` selects the transport — `type = "stdio"` (a local server with a `command`) or
  `type = "http"` (a remote server with `destinations`), so nothing restates the name. The reason is what once made a
  separate `mcp.toml` a defended file: the file names a program the box starts outside
  containment, and it sat inside the project where the starter policy permits `fs:write` — so a
  workload wrote an entry, the next `run` materialized an alias, and `shell:spawn` decided a
  program the *workload* picked. `box.toml` was already defended.
  `policy::SELF_DEFENDED_FILES` is two entries for the same reason.
- **`ConfigureRequest` is the interface; `ConfigFile` is the wire record.** `ConfigureRequest` is the
  validated four-input request that composition consumes, and `Record` is what `configure` stores.
  `ConfigFile`/`EgressEntry` are the private `Deserialize` shapes and hold strings. Keep the serde
  types private and keep `deny_unknown_fields` on both: a typo is a load error, never a silently
  dropped field.

  **`name` and `[agent]` are keys in the file, and the file is the only source of truth.** There is
  no `--name` flag: `box_dir` selects the box and the file names it, so a second selector could
  disagree with the first. `run_config.rs::run_selects_a_box_by_its_configuration_alone` pins that
  `--name` is refused. A bare `run` executes the stored `[agent] command`, and a trailing argv
  **appends** to it, so the key states the invocation prefix and the line the operator typed states
  the rest. `run_config.rs::a_trailing_argv_appends_to_the_stored_command` is the pin. **The key is
  spelled `command` on `[agent]`, on each `[tool.<name>]`, and on each `[mcp.<name>]`**, because one
  word names one thing: the executable and its fixed leading arguments. `configure::apply` writes the
  settled name into the `Record`, and `run` reads the record, so the file is never consulted twice
  about one box. **Do not reintroduce `--name`**; reconciling a flag against the file is the shape in
  which the file's key became silently dead once already.

  **`box.toml` carries eight top-level keys — `name`, `box_dir`, `policy`, `[agent]`,
  `[tool.<label>]`, `[egress.<name>]`, `[mcp.<name>]`, and `[telemetry.<kind>]`.** A ninth is a
  fifth input until argued otherwise, the way `env` is argued above. `[agent]` and each
  `[tool.<label>]` hold one `ProcessSpec`, which is four fields — `command`, `workspace`, `env`,
  and `filesystem` — and `filesystem` holds the path lists: eight for `[agent]`, six
  for a `[tool.<label>]`, which has no `metadata` or `exec` list: a leaf discovers metadata across the
  operator home ([a leaf discovers metadata](../../docs/design/decisions.md#a-leaf-discovers-existence-and-metadata-content-stays-gated))
  and runs its toolchain through broad exec on macOS
  ([a leaf runs its whole toolchain](../../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds)).
  **`name` and `box_dir` are required, and every other key is optional.** `version` and `box_id`
  are **not** among them: they belong to `Record`.

  **The box is the credential boundary. No process table selects what it reaches.** The agent gets
  every declared `[tool.<label>]`, every `[mcp.<name>]` alias, and every egress route. Each tool and
  each MCP leaf gets every egress route, and no alias and no broker socket, so it starts no tool.
  [The box is the credential boundary](../../docs/design/decisions.md#the-box-is-the-credential-boundary)
  owns why. **Do not add a per-process selection**: the gateway and the broker cannot tell
  which process in a box calls, so a selection would bound nothing. A process that must not get a
  credential goes in another box.

  **A key that moved is refused by name.** `refuse_removed_keys` runs before the real parse, so a
  file carrying the old `[filesystem]`, `workspace`, `[env]`, `[agent] packs`, `[agent] code`,
  `[agent] default_command`, `[agent] read`, `[agent] write`, `[tool.<name>] exec`,
  `[tool.<name>] read`, `[tool.<name>] write`, `[tool.<name>.filesystem] metadata`, or
  `[tool.<name>.filesystem] exec` gets a refusal
  naming where that key went, rather than an unknown-field error.
  `run_config.rs::name_is_required_and_every_removed_key_is_refused_by_name` pins each one. Read the
  `record::config` modules for the current set rather than this list, and keep the key names exact —
  the freeze table sends a reader here to learn what is frozen.
- **Validation happens once, when `ConfigureRequest` is built.** After that, composition is assembly.
  Do not re-derive meaning from a string downstream: no `strip_prefix("env://")`, no host
  re-parsing, no second reserved-name check at projection time. `EgressRoute` carries
  `provisioned_name` so the scheme is interpreted in one place.
- **A credential binding is not an authorization
  ([a binding is configuration](../../docs/design/decisions.md#a-credential-binding-is-configuration-not-a-policy-action)).**
  It says only what is attached to a request policy already permitted. Keep every refusal holding
  that line: one exact host, no wildcard, no path, locator required, one credential authority per
  destination, and `aws://` taking no header or prefix. A key that narrows or widens *which
  requests* are governed makes this file a second authority — that is the defect, not the syntax.
- **This crate holds no list of credential paths, and must not grow one back.** `~/.aws`, `~/.ssh`,
  a keychain, a browser profile — every one lives in `containment`'s `FORBIDDEN_PATHS`, judged
  beneath every grant the translator renders, through `containment::validate_grant`. Two lists in
  two crates was the defect: the box once screened only its own built-in paths, so a record's
  `[agent]` entries reached the translator with no credential check at all. The one punch-through is
  a store the operator names exactly, which `validate_grant` reports and
  `record::config::filesystem::a_credential_store_is_granted_only_when_named_exactly` pins. A prefix
  of a store, or a parent of one, stays refused.
- **The authored policy is the only authorizer, at all three enforcement points.** Box builds
  three adapters over the one `Arc<PolicyEngine>`: `EgressPolicyInterceptor` for the proxy (`net:*`),
  `ShellPolicyInterceptor` for the hosted Shell (`shell:exec`, `shell:spawn`, `fs:*`), and
  `ScriptPolicyInterceptor` for Python (`fs:*`). A command line is judged once, on the resolved
  command: `shell:exec` when the Shell implements the program, `shell:spawn` when a host binary
  runs instead. Three views of one authority, never three
  authorities — `box`'s `Cargo.toml` enables all three policy features for that reason. The
  proxy's `CapabilitySet` carries credential injection only. **Never add a destination allowlist
  beside the policy, and never expose an upstream-CA knob.** A metadata address is refused by a
  policy `forbid` on `context.input.ip`, not by the proxy.

  **The Shell's binds are writable, and its mount set is not a floor.** Read-only
  protected nothing and cost parity: under one identical `permit fs:write`, Monty wrote to the box
  home and succeeded while the Shell was refused with `read-only bind mount` — one rule, two
  meanings. What carries the boundary instead is the pair of floors below. Do not describe the
  mount set as a floor, and do not widen a mount to make something work. `verify_direct_binds`
  refuses startup unless every bind is exactly the declared one **and** `direct`, because `Copy`
  is the vendored crate's default and the wrong spelling fails invisibly — reads keep working and
  are only stale. It compares entry by entry rather than counting, because a count passed while a
  bind named the wrong directory.
- **`HOME` is the operator's home, unless `[agent] env.HOME` names another directory.** There is no
  private box home, and no verb copies configuration into one.
  `box_filesystem.rs::home_is_the_operators_unless_the_agent_declares_one` pins the default. Two
  floors carry the boundary:
  - **A home is never a grant, and the agent's own syscalls reach almost nothing.** The profile
    grants its program, `bin/`, `run/box.sock`, `trust/`, the workspace at `Dir` scope, the cells
    `run/contain/runtime_minimum.rs` states, and what the eight lists in `[agent.filesystem]` name.
    Everything else is an interpreter request policy decides, and
    `box_filesystem.rs::reach_under_the_operator_home_is_only_what_is_listed` pins that naming the
    home as `HOME` reaches nothing under it.
    A list entry under the operator's home is the one relaxation of this floor, and
    [the runtime minimum](../../docs/design/decisions.md#the-runtime-minimum-is-two-sets-and-the-agent-takes-the-smaller-one)
    states its cost. `box_filesystem.rs::a_harness_configuration_directory_reads_when_listed_and_not_otherwise`
    pins both halves, planting a decoy in each of `.claude`, `.codex`, `.kiro`, and `.agents` so a
    refusal cannot be an absent file. An operator who lists one must accept both costs: those
    directories hold live OAuth tokens the agent then reads with no decision in the path, and — the
    sharper half — a `write` entry on `~/.claude/settings.json` hooks or `~/.codex/config.toml`
    executes attacker-chosen commands the next time the operator runs that harness **outside any
    box**. Read-only does not fix the first cost, because the tokens are the file. Prefer a copy
    inside the project, which the shipped examples do.
  - **`Reach`'s deny floor refuses every path resolving into `~/.strands-box`, the machine state, or
    THIS box's own directory**, whatever a `permit` says. It is checked on the canonical identity,
    because a spelling check is laundered by a symlink the workload can plant. **There is no
    exception, and a home does not earn one.** `layout::refuse_home_in_box_state` refuses a declared
    `env.HOME` that resolves into a reserved host root, into the box directory, or through a
    `.strands-box` component — **and one that ENCLOSES the box directory**, because a declared home
    is one of `Reach`'s roots while only this box's own directory is forbidden, so an enclosing home
    would put box state inside the reachable set. Both directions hold for `[agent]` and for each
    `[tool.<name>]`, so the floor never meets a home it would have to carve out for. The carve-out it
    replaces was the home's own subtree plus its ancestor chain for traversal; with `env.HOME` naming
    the product directory, "below the owned root" covered every sibling box, so one `permit fs:read`
    read another box's `policy.dw`. `refuse_home_in_box_state` is called at config time in
    `RunContract::read` and again in `boundary::translate`, the two places `refuse_operator_home` is
    called; `reach.rs`'s `a_home_inside_trusted_box_state_reaches_nothing_there` pins the floor half,
    and `layout.rs`'s `a_declared_home_enclosing_the_box_directory_is_refused` pins the enclosing one.

    **A SIBLING box's state is no longer covered, and that is an accepted residual** — see "A sibling
    box's stored state is reachable" under Open findings. Do not read this bullet as covering it.

  `run/broker/reach.rs` is the single place the set is stated, so the Shell's mount table and
  `ReachFloor` cannot disagree.

  **A local MCP server receives the OPERATOR's home**, because it runs as the operator, inside its
  own leaf box, and looks for their session there. `host.rs::start_mcp_server` reads
  `Reach::reported_home` for that reason; a private box home left a node MCP server and
  `uvx mcp-proxy-for-aws` started and unable to authenticate. `HOME` for the workload and `HOME`
  for an MCP server stay two questions, and one answer no longer breaks the other.
- **A rule reads `~/<relative>`, not a host path.** Two things about it are load-bearing.
  **`ApprovedPath::as_path` stays what every EFFECT acts on** and only the decision reads
  `reported()`; this crate has had two escapes from "validate one spelling, act on another". And
  **both interpreters must report the same way** — one build had the Shell adapter report `~`
  while the script adapter reported the host path, which is fail-closed for a `permit` and
  **fail-open for a `forbid`**: `forbid fs:read when path like "~/.ssh/*"` matched through
  `bin/zsh` and matched nothing through `bin/python3`. The request event and the resolution event
  must also agree, because the engine holds them in separate bags and a mismatch is a silently
  unmatched temporal clause — an exfiltration guard stopped firing and egress stayed open after
  the secret was read.
- **Policy crosses as `AuthoredSource` (origin + text), not a path and not a compiled `Policy`.**
  `Policy::open` strict-validates the text and opens no file. `origin` is a diagnostic and audit label —
  it feeds `EffectivePolicy::policy_id` and is not opened. Absent policy is default-deny, not
  unconstrained.
- **`box_dir` is authority, and the name no longer is.** `box_dir` is required and absolute, and it
  is what selects a box: one directory is one box. The name became a path component under the old
  `$HOME/.strands-box/b/<name>` default, and that default is gone — **Box owns no namespace and
  creates no directory above the one `box_dir` names.** `create_box_directory_if_absent` refuses a
  path whose parent is absent rather than making one.

  `BoxName::parse` still accepts one component of letters, digits, `.`, `_`, or `-` and nothing else.
  Keep it: the name labels the box in its record and its telemetry, and relaxing it is its own gated
  change. What moved is *why* — the byte budget it used to spend is now measured on the real path, by
  the 103-byte broker-socket check in `open_directory_inner_with`. Do not reintroduce a caller-chosen
  home directory under any spelling: blanket read-write on a caller-named directory would let a
  caller name `$HOME` or `/`. A record at `version = 1` describes a root under the earlier `boxes/`
  namespace, which is why `RECORD_VERSION` refuses it.

  **A declared `box_dir` keeps its authored spelling, and is not canonicalized.**
  `run_config.rs::an_ancestor_symlink_spelling_starts_the_box_and_stays_visible` pins that the stored
  record carries the path the operator wrote. So a caller that wants the canonical spelling
  canonicalizes before it writes the key; the shipped fixtures do.
- **There is one root and it is a box's own**
  ([one trusted process per box](../../docs/design/decisions.md#one-trusted-process-per-box)).
  It is not a temporary directory. **The box root** — whatever `box_dir` names — persists from
  creation until the caller removes it, and holds four children: `bin`, `run`, `trust`, and
  `private`. None of them is a home. A machine-level second root sited a daemon serving N boxes;
  with the `run` process owning its box, every path a box needs is under that box's root, and the
  lock proving who owns it is one of them — `private/.lock`, beside the live record at
  `private/live.json`. `$XDG_STATE_HOME/strands-box`, or `$HOME/.local/state/strands-box`, survives
  only as a reserved host root `reserved_host_roots` names, so the deny floor still refuses a path
  resolving there.

  **Ownership is a lock rather than a stored process id.** The kernel releases an `flock` however the
  holder dies, so a `kill -9`ed owner leaves no box a later `run` cannot take. A pid probe cannot
  carry this, because the operating system reuses a pid: it answers "is something alive" and never
  "is *that* owner alive". `ls` tried the lock and `stop` read `BoxLive` after it; both verbs are
  gone, so `run` is the only reader and `BoxLive` is now written for diagnostics rather than read by
  a verb.

  **Creation is not check-then-act.** `apply` takes the box's operation lock across its check and
  its write and re-checks the record under it, so whichever caller takes the lock second reads the
  winner's record. The tree is created *before* the lock, because the lock file lives inside the
  root's private tree. `concurrent_runs_of_one_project_produce_exactly_one_box` spawns eight
  contenders and asserts the stored record parses and names the contended box — it asserted `ls`
  printed one row until that verb was deleted; it asserts `succeeded >= 1` deliberately, because
  `run` is create-or-*reuse* and a loser that finds the winner's record succeeds too.

  Per-run artifacts are *named* rather than sited in a `mkdtemp` scaffold: a containment config is
  `private/containment/<digest>.json`, a verified trampoline image is
  `private/trampoline/<digest>.bin`. **Do not reintroduce a per-run scaffold** — content addressing
  is what lets two concurrent runs of one box share a directory without racing. Create each
  directory individually so its mode is explicit and an existing symlink is refused rather than
  followed.
- **The stored root is the spelling the caller wrote, and the CALLER canonicalizes it.** Box used to
  canonicalize, because it sited the root itself; `box_dir` is now authored, and
  `run_config.rs::an_ancestor_symlink_spelling_starts_the_box_and_stays_visible` pins that the stored
  record carries the authored path. So the rule moved rather than went away: **a caller that does not
  canonicalize gets the defect below, and the box will not catch it.**

  On macOS both `/var` and `$TMPDIR` are reached through symlinks into `/private`. A path's canonical
  spelling is used several ways at once — a declared `HOME`, a workspace, the profile's grants — so
  all of them must agree with what the kernel checks. Containment canonicalizes the grant itself, so
  it will *not* catch an uncanonical spelling on the box's behalf: the profile ends up correct while
  the environment the box hands the workload points somewhere never granted. **This has already
  regressed once**, and every write inside the declared home returned `EPERM`. If
  `tests/box_filesystem.rs` starts failing with "Operation not permitted" on a path that looks
  correct, compare the granted spelling against the one in the workload's environment before looking
  anywhere else. Every fixture and shipped script canonicalizes its own `box_dir` for this reason —
  `fixture.rs`'s `short_operator_home` and `boxes_parent` both do.

  `the_root_is_canonical_when_the_operator_home_is_a_symlink` covered the box-canonicalizes-it half
  and is deleted with it.
- **The workload's environment is composed, never inherited, and box-owned values go last.** So a
  phantom cannot displace proxy routing, CA trust, or the fixed identity.
  `reserved_workload_environment` is what a credential may not claim; when the box starts setting
  a new variable, add it there in the same change. **Never forward the operator's `PATH`.**
- **One exec rule for the command, and one more for each `exec` entry.** The profile permits
  `process-exec` on exactly the resolved command, so a wrapper script resolved from a bare name needs
  an `exec` grant on the interpreter it runs. The spec's own `PATH`, or `/usr/bin:/bin` when it
  declares none, is a resolution input and not a grant. Refuse anything that is not an executable regular file. An operator who wants a toolchain
  names its directories in that spec's `exec` list, and each entry renders one rule — a literal for
  a file, and a subpath for a directory. The **agent box has no broad-exec carve-out** and gets one
  rule per grant; a **leaf** renders `process-exec*` (macOS-only,
  [a leaf runs its whole toolchain](../../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds))
  so it runs its whole toolchain, which `containment`'s `the_agent_profile_never_carries_broad_exec`
  and `a_leaf_carries_broad_exec_and_the_main_box_does_not` pin.

  **This is a macOS property, and Linux does not enforce it.** Seatbelt renders one `process-exec`
  literal per grant, so the exec set *is* the grant count. The namespace launcher renders no exec
  rule at all — its exec set is whatever the mount view leaves runnable, which is every `+x` file
  on a read-only bind. Measured with one `bash` workload and four aliases: **14 execve-able paths
  against 5 grants**, the extras being the ELF loader, seven mode-`0755` libraries, and the
  workload bound under both spellings (measured before the view reproduced link spellings as links;
  a link spelling is no longer a second bind, so that extra remains only for a spelling reached
  through a linked ancestor). None can run workload-authored bytes, because W^X's
  `noexec` refuses the mapping, so it is a premise gap rather than a hole.
  `containment`'s `view.rs::the_view_leaves_exactly_the_intended_paths_executable` bounds it, and
  narrowing it is deferred. Do not restate this bullet as a cross-platform guarantee.

  **A relative path with a separator is refused, because no directory is its root.** An absolute
  path is used as authored, and a bare name is searched on the spec's `PATH`.
  `a_relative_path_with_a_separator_is_refused` and
  `a_bare_name_resolves_on_the_declared_search_path` are the pins. A search entry that is not
  absolute is skipped rather than rebased, because one entry the box cannot honour is no reason to
  reject a `PATH` that also names usable directories.

  **The grant is prepared from the route, so the spelling the profile renders and the spelling the
  box execs are one string**. The route keeps a canonical directory and its own
  final component. A symlinked program therefore starts through the link and is authorized on its
  target, which `the_route_carries_a_canonical_directory` and
  `a_linked_program_is_started_through_the_link_and_granted_on_its_target` pin. Do not canonicalize
  the final component, and do not render a second spelling.

  **A script launches an interpreter, so the whole chain is granted.** `shebang_interpreter_chain`
  reads each `#!` line, resolves a `#!/usr/bin/env <name>` line to the real interpreter on the search
  path, and bounds the chain so a cycle cannot loop. Without those grants a script refuses at exec
  and no `fs:*` decision explains it. `a_direct_path_shebang_chain_names_its_interpreter` and
  `env_shebang_resolves_the_real_interpreter_on_the_search_path` are the pins.

  **The resolver reads no file to pick a different program.** An absolute path is used as authored and
  a bare name is searched on the declared `PATH`, and nothing else can replace the candidate.
  Launcher resolution was deleted from here on 2026-09-21. `[agent] command` names the agent's
  own executable.

  **A command inside a directory the same spec makes writable is a startup warning, not a refusal.**
  A process that can write the command's directory can choose the program it runs, so the overlap is
  a real exposure. The operator authored both lists, so the box states the overlap on stderr and
  proceeds rather than dropping either. `boundary.rs::a_writable_command_is_disclosed_as_a_warning`
  and `containment`'s `an_exec_grant_inside_a_write_root_warns_and_applies_beneath_every_backend`
  pin the two levels.
- **`strands-box-contain-trampoline` is located beside the box executable and nowhere else.** It is
  opened with no final-symlink following, checked for native executable format and the embedded
  identity marker, and executed from that opened identity — Linux through `/proc/self/fd/<fd>`,
  macOS through a private mode-`0700` copy at `private/trampoline/<digest>.bin`, written to a
  pid-named staging file and renamed into place. **Never validate one pathname and reopen it for
  exec.** The marker is an artifact-kind check, not authentication.
- **A containment setup failure is not a workload exit.** The single-byte setup-status pipe
  distinguishes them by stage (config read, config validation, apply, target environment, target
  exec). Keep the byte values in step with the trampoline's, and keep reporting the stage rather
  than collapsing it into a generic launch error.
- **The child owns its process group and the terminal, and cleanup is unconditional.** Terminate
  the group and restore the terminal on every path, including the error paths before the child is
  waited on. `ProcessGroup` and `ForegroundTerminal` clean up on drop; do not remove those impls in
  favour of explicit calls alone.
- **The box's trusted process hosts the Shell, and every interpreter route the workload has meets
  the box's one Policy.** The workload reaches Monty two ways — the `python3` alias directly, and a
  `python`/`python3` command inside the Shell
  ([Monty two ways](../../docs/design/decisions.md#python-in-the-shell-is-monty)), and the box
  judges both on the same `Arc<PolicyEngine>`. There is **one `Policy` per box** ([one policy
  engine](../../docs/design/decisions.md#one-policy-engine-per-box)): `broker/host` owns the one
  socket and its listener, and `broker/shell` builds the Shell on the same `Arc<PolicyEngine>` the
  egress gateway holds. The Shell is built **per connection** ([no state crosses a
  call](../../docs/design/decisions.md#no-state-crosses-a-call-boundary)), with no queue and no
  shared worker. `broker/aliases` keeps only alias materialization, which is box-lifetime.
  `strands-box-sock-alias` — the installed image, named for what it does rather than for an
  interpreter — is **alias-only**: it opens no `Policy`, links neither `policy` nor
  `strands-shell`, and has no serving role. Three rules carry the boundary:
  - **There is no serving role in the image, and its own name is refused.** The workload can exec
    the alias, so a `--serve` flag would let it start its own Shell with no policy. The role is
    gone rather than guarded; the name check is defence in depth.
  - **The alias derives its socket from its own path** — `<box root>/bin/<name>` →
    `<box root>/run/box.sock`, one socket for all five aliases. `BROKER_SOCKET_RELATIVE` is
    `["run", "box.sock"]` joined to the alias's grandparent, and **no path the box computes carries
    a `public/` component**. Accepting a socket as an argument would let the workload aim its
    requests at a socket it controls.
  - **The hosted Shell has no network of its own — it can reach only the gateway
    ([Shell network](../../docs/design/decisions.md#shell-network-goes-through-the-egress-gateway)).**
    The Shell itself never dials an origin: its one outbound path routes through the box's egress
    gateway, and the gateway makes the network call under the same `net:connect`/`http:request`
    policy as workload traffic. So a Shell request is governed, not a route around the box's only
    governed one. With no gateway the network stays off (fail-closed). Never add a second network
    client that reaches an origin directly, around the gateway.
  - **The hosted Monty (Python) reaches the network the same way, and only that way
    ([one `fetch` function](../../docs/design/decisions.md#a-monty-script-reaches-the-network-through-one-fetch-function)).**
    A script's one curated `fetch` routes through the box's egress gateway, which makes the
    `net:connect`/`http:request` decision under the same policy as workload traffic; Monty itself
    builds no client and dials no origin. With no `EgressRouting` the network stays off, so Monty's
    network moved from *off by absence* to *off unless egress is present*. The only HTTP client in
    the Monty host path is the one `fetch` handler, built from `EgressRouting`, pinned by a CI guard.
    Never add a second network client that reaches an origin directly.

  The alias is a hard link to the installed image where possible and a length-verified copy
  otherwise, and **neither outcome may be assumed** — `EXDEV` selects the copy path. A hard link
  shares one inode with the installed image, which is why tightening the alias's mode tightens the
  *install*. The copy path reads from the *opened* identity and verifies the byte count, so
  replacing the installed file mid-copy cannot change what lands.
- **One Shell per *request*, built in `handle_connection`
  ([no state crosses a call](../../docs/design/decisions.md#no-state-crosses-a-call-boundary)).** `serve` hands each
  connection to `run_connection_on_own_thread` and each builds its own `Shell`. **Do not
  reintroduce a request queue feeding a shared worker**: that existed only because one long-lived
  `Shell` held cwd/env/functions and had to be serialized, and keeping it after the state was gone
  left the cost without the cause — a trivial command queued ~4.4s behind a sibling's `sleep 6`,
  against 376 ms once the queue was removed. Before the change, an `export` or `cd` in one
  `strands-box run` was visible to a *different* run. Two runs share *authority* by design — one
  policy, one proxy, one history — never a mutable session.
- **Shell failure is per request, structurally.** A disconnect, an expired deadline, or a failed
  build costs *that request* and nothing else, because each connection owns its Shell. The
  one-packet kill switch a security review once found here — returning an error unbound the socket
  and left every later command unable to connect — is unrepresentable, not guarded. Only a
  **listener** failure stays fatal, and it is fatal to that box alone. `BrokerHost::start` still
  builds one Shell before binding, so a spec that cannot build refuses to publish a socket at all.
  **Never re-read the policy file when building**; that would discard temporal history, making a
  disconnect a history-clearing primitive the workload holds.
- **The Shell concurrency limit is closed, and `Shell: Send` was not what closed it
  ([no state crosses a call](../../docs/design/decisions.md#no-state-crosses-a-call-boundary)).**
  Every `Shell` is `!Send` — one `Rc` field in the vendored crate. What closed the limit is that
  **`ShellSpec` is `Send`**: `serve` moves the spec to `run_connection_on_own_thread`, which gives
  each connection its own thread and its own current-thread runtime, and the `Shell` is built on
  arrival. A non-yielding command — the embedded Lua interpreter — therefore pins its own thread
  and nobody else's (27.73s → 328ms). **Do not put the connections back on one shared `LocalSet`.**
  What remains is a bound rather than a limit: `SERVE_CONNECTION_CAPACITY` is 64, and the accept
  loop reaps one connection before it admits the sixty-fifth.
- **Why the Shell gets its own thread, measured.** A Lua busy loop starved the control socket: with
  `lua -e "while true do end"` running through the alias, an unrelated `strands-box run` took
  **27.73s** and `stop` took 10.09s then escalated to `SIGKILL`. With a *yielding* `sleep`, the same
  probe took **0.33s**. `Shell::run` being `async` with 156 `.await` points is true of the shell
  grammar and **false of the embedded Lua interpreter**, whose `mlua` interrupt hook returns
  `VmState::Continue` synchronously and never awaits. **Do not move the Shell back onto a runtime
  shared with the control socket.**
- **A `Shell` is cheap, which is what makes per-request affordable.** ~110-350 microseconds to
  build: 632 bytes over an `Arc<Mutex<Vfs>>`, holding no interpreter (`setup_lua_vm` constructs its
  `Lua` per `lua` invocation). Reusing one across requests trades a three-hundred-microsecond
  saving for the shared-session bugs that per-request Shells removed.
- **The box writes no diagnostic log file, and must not grow one.** Startup and failure reach the
  operator's stderr, where a `run` already is: the trusted half is the `run` process
  ([one trusted process per box](../../docs/design/decisions.md#one-trusted-process-per-box)), so
  a spawned server whose output a verb had to read back no longer exists. **Never open a log file
  per request or per command** — it would be unbounded and untruncated, so a per-command line is a
  disk the workload fills by doing its job, and a second informal stream beside the telemetry a box
  writes at `private/telemetry/records.jsonl` invites the two to disagree. Anything derived from a
  connection also describes the *workload's* process topology, which no diagnostic stream has a
  reason to carry. A failure printed to stderr stays — a rejected client, a failed accept, an
  unrecorded outcome — because those are bounded by something going wrong rather than by throughput.
- **Five residuals of hosting the Shell in the trusted process. None may be quietly dropped.**
  - **That process is not OS-contained**, and runs the Shell beside the in-memory CA key and the
    resolved secrets. What holds is *mediation*, not a process boundary: the Shell's synthesized
    environment and its VFS are why the secrets stay unreachable.
    `tests/box_credentials.rs::the_shell_cannot_read_the_daemons_resolved_secrets` is that proof
    and must not be deleted.
  - **The vendored Shell embeds a Lua 5.4 C interpreter**, non-optionally (`mlua` with
    `lua54, async, vendored`), reachable as a `lua` builtin. Never describe the Shell as a small
    `unsafe`-free parser: `grep unsafe shell/src/` returns zero and is misleading, because the
    interpreter is in the dependency graph.
  - **A `forbid` on command text is not a containment boundary.** Admission judges the **resolved**
    command in `run_pipeline`, after parsing, expansion, and resolution of the first word. So
    `command` is the line rebuilt from expanded words, and the attempt also carries `program`, the
    identity the first word resolved to. One effect has many spellings, so a `command like` pattern
    is a weak match. **Write a rule on `program` rather than on `command`**: `alias safe=rm` makes
    the spelling `safe`, and the `alias` builtin raises no decision of its own. The load-bearing
    controls are the path-scoped `fs:*` rules, which is why `fs:*` admission carries a **resolved
    path**. `a_denied_command_substitution_does_not_run` is the pin. **Re-measuring this class needs
    a no-substitution control first** — an earlier investigation reported a pre-expansion leak as
    a command-substitution bypass because every probe wrapped its payload in `$(…)`.
  - **Command substitution raises its own event, and the count is parity rather than an absolute.**
    Substituted text is parsed and run like any other, so each command inside it reaches
    `run_pipeline` and raises its own resolved `shell:exec`. All three routes — substitution,
    `eval`, and `xargs` or `source` — report ten for ten iterations, and no decision is taken over a
    submission itself. Three guards in `shell/tests/kernel_effect_interception.rs` hold this:
    `command_substitution_is_admitted_as_its_own_event` (an **exact-entry** match, because a
    `contains` match passes on the outer command's entry and proves nothing),
    `a_denied_command_substitution_does_not_run`, and
    `substitution_fan_out_is_counted_like_every_other_route`, which asserts parity rather than the
    absolute count.
  - **The Lua surface is mediated, and `lua_popen_is_judged_by_policy` must not be deleted.**
    `io.popen` and `os.execute` once called `exec::execute_capture` directly, so a policy permitting
    any `lua -e …` let two lines of Lua run arbitrary shell text unjudged. Admission is now on the
    resolved command in `run_pipeline`, which `execute_capture` reaches, so each command Lua runs
    gets its own `shell:exec`. The rest of the surface is clean: `io.open`, `os.remove`,
    `os.rename`, `dofile`, `loadfile`, `require`, and `io.lines` all raise a mediated `fs:*` attempt
    and all fail closed when denied; `debug`, `package.loadlib`, `os.setlocale`, `io.input`, and
    `io.output` are `nil`, because the VM is built with only
    `STRING|TABLE|MATH|UTF8|COROUTINE`. The MCP server's four tools reach the same `Mediated` handle
    and enforce identically; its **client** (`mcp_client.rs`) is outside the mediation graph and
    unreachable in the shipped box, which never writes the config file it needs.
- **The alias accepts `-c` and `-l` as separate arguments.** Claude Code invokes a shell as
  `execFile(shell, ["-c", "-l", command])`, hardcoded with no environment override, and a real
  shell accepts the flags split. What keeps this from becoming a third argument slot: the
  3-argument form is accepted **only** when both leading arguments are recognized flags (`-c`/`-l`)
  *and* one of them is `-c`. So `-c CMD /tmp/attacker.sock` is refused, and so is `-l -l CMD`.
  `the_alias_accepts_no_socket_argument` and
  `a_three_argument_form_that_is_not_two_flags_is_refused` pin the pair; deleting either leaves the
  other passing while the guard is gone. Every accepted spelling derives its socket through one
  `shell_mode`, because a second copy of that derivation is where an argument-supplied socket path
  would get in.

  **It is an enumerated set, not a general parser, and that is a known cost.** `-cl CMD`,
  `-lic CMD`, and `-c -i CMD` all run in `/bin/zsh` and are all refused here, so a harness that
  clusters or adds flags hits `exit code 125`. Two properties any generalization must keep: no
  argument may name a socket path, and exactly one command string may be submitted. A parser that
  skips unrecognized flags would be a widening, not a cleanup.

  **One prompt is three submissions** — a ~4 KB shell-snapshot script, `env`, then the command
  wrapped in `setopt … && eval '<command>' … && pwd -P >| …` — which is why a policy authored
  against the bare command denies every run.
- **`[agent] read` and `[agent] write` are lists, and each directory entry is a recursive
  grant.** A list because one path was not enough for a caller whose runner and whose handler
  live apart: the interpreter refused the runner with `Operation not permitted` while the
  handler's own tree was granted. The floor names neither tree, because an operator makes a
  virtualenv or a `node_modules` wherever they like. An entry on a path that does not exist is
  refused, never skipped, and `record/config/filesystem.rs` states every other refusal class.
- **The alias must send `StdinEof`.** `forward` sends `Open`, `Call`, **`StdinEof`**, and the third
  frame is not optional. A harness invoking `zsh -c` supplies nothing on stdin, so without the EOF
  the Program's stdin channel stays open and any command that pre-reads stdin blocks to its
  deadline — the `lua` builtin does exactly that, so **every** `lua` call took 34–36s and came back
  as `the call exceeded its deadline`. Two things worth not repeating:
  - **`close_stdin` must drop the sender, not send an empty frame.** The vendored `ChannelReader`
    reaches end-of-stream only on `Poll::Ready(None)` — every sender gone. A zero-length recv is a
    successful 0-byte read, so `read_to_string_limited` loops on it forever. `ProgramControl` holds
    `Arc<Mutex<Option<Sender>>>` so one `StdinEof` closes the channel for every clone.
  - **When a bisect says "not mine", check which variable actually moved.** The control that called
    this pre-existing varied the *vendored crate* while holding the box constant.
- **A Call's output streams.** `Program::adopt` installs a `ChannelWriter` on `STDOUT` and
  `STDERR`, and `run_call` drains them *inside* its `select!` loop so a chunk leaves while the Call
  is still running. Four things worth not rediscovering:
  - **The cause was in the vendored crate**, not a missing setter: `set_channel_writer` is public
    and `out_msg` checks it first, but the vendored single-builtin fork installed its own pipes over
    both descriptors and discarded the caller's. Fixed in `shell/` — see its `UPSTREAM.md` — with
    `shell/tests/channel_writer_inheritance.rs` as the proof, plus
    `capture_is_unchanged_when_no_writer_is_installed`, which passed before and after and is what
    makes the change additive.
  - **Draining after the Call returns is the defect, not a simplification.** A program that never
    exits would have its first byte delivered never. The post-loop drain exists only for what was
    written between the last poll and the Call ending, and it runs on the interrupted and expired
    paths too.
  - **`ProgramOutput` is a separate type for two independent reasons.** A running Call holds
    `&mut Program` for its whole duration, so the receiving ends cannot live there. And `emitted`
    must survive across Calls — streaming removed the single-frame ceiling, so without a running
    total a Program emits without limit by printing in a loop across many Calls.
  - **`next_chunk` awaits and `drain_ready` does not, and using the wrong one hangs the process.**
    The senders live on the Shell, which outlives every Call, so the output channels *never* reach
    end-of-stream for a live Program; awaiting one after a Call has finished waits forever.
    `next_chunk` belongs only inside the `select!` that races it against the Call.
- **The reader never blocks on a Call.** `serve_transport` reads and dispatches; each `Call` moves
  its `ProgramSlot` into a task and hands it back through a completion channel. Five things hold
  this shape:
  - **`Input` and `StdinEof` were blocked as well as `Signal`**, so a request/reply session
    *deadlocked*: the `Input` carrying request 2 was not read until the Call ended, and the Call
    would not end until it saw request 2. `a_program_serves_a_request_reply_session` is the test.
  - **A running Program stays reachable through `running`, keyed by id.** `Input`, `StdinEof`, and
    `Signal` find it there while its slot is inside a task, which is why `control_for` consults both
    maps. Dropping that lookup reinstates the deadlock for `Input` only — the hardest version to
    notice, since `Signal` would still work.
  - **One writer task owns the socket's write half.** Two owners of one half is not expressible, and
    a shared `Mutex` would serialize exactly the streaming this exists for.
  - **One Call per Program, refused rather than queued.** A second `Call` for a busy Program gets
    `Denied`. A queue the client cannot see turns a fast command into an unexplained wait.
  - **A completion is matched to a Call, never to a Program.** `Close` removes the id from `running`
    and leaves that Call's completion in flight, so after `Close 1; Open 1; Call 1` the abandoned
    Call's completion arrives while a *different* Call holds id 1. Matching on `ProgramId` alone
    ended the live Call with the dead one's status and put the **closed** Shell's slot back
    underneath it. `RunningCall::sequence` closes it. **Do not "simplify" the completion arm back to
    `running.remove(&done.id).is_some()`.** It reproduced only on **aarch64**, with the right text
    and the wrong status, so a status-only or output-only assertion misses half of it, and
    `a_reused_program_id_never_reports_a_closed_calls_status` runs twelve cycles because a single
    cycle passes on most runs.
- **What `hardening` buys, and the gaps that are easy to misread.** The trusted process holds the CA
  private key, every resolved plaintext secret, and the box's one `Policy` with its temporal
  history. `hardening` makes that memory unreadable with two syscalls per platform. **Every
  mechanism applies unconditionally, and no environment variable declines one.**
  `no_environment_variable_declines_the_hardening` is the guard and must not be deleted; it reads
  the module's own source rather than probing behaviour, because the defect it closed was a
  *branch* and a behavioural test proves only that this build ignores this spelling. A debugger now
  needs a source change and a rebuild.
  - **`PR_SET_DUMPABLE=0`** (Linux) is the strong one by itself: `PTRACE_ATTACH`, `PTRACE_SEIZE`,
    and `process_vm_readv` return `EPERM`, and `mem`, `maps`, `smaps`, `environ`, `auxv`, `pagemap`,
    `fd/`, and the `root`/`cwd`/`exe` links return `EACCES`. **Yama is not what refuses these** —
    the dumpability check in `__ptrace_may_access` runs first, which is why this holds at
    `ptrace_scope=0`.
  - **`RLIMIT_CORE=0`** (both platforms) stops a core dump and only that. Kept for two properties
    dumpable lacks: it **survives `execve`**, and zeroing `rlim_max` makes it irreversible.
  - **`PT_DENY_ATTACH`** (macOS) refuses a debugger. Weakest of the three, and its cost is a
    `SIGKILL`, so it is applied last.
  - **`mlockall` is deliberately absent.** Under a finite `RLIMIT_MEMLOCK` it either fails with
    `ENOMEM` and locks nothing, or succeeds and starves the heap — a 300 MiB limit produced an
    allocation failure at 146 MiB of growth. Swap is an open residual. **Do not "fix" this by
    adding `mlockall`.**
  - **`PR_SET_DUMPABLE` does not survive `execve`.** It is inherited across `fork`, but every child
    the box creates is `fork`+`exec`, so it protects this image and confers nothing on the
    trampoline or the workload.
  - **Root bypasses dumpable entirely.** This defends against same-uid peers, never root.
  - **`cmdline`, `stat`, `status`, `mountinfo`, `net/*`, and `task/*/{stat,status,cmdline}` stay
    readable.** Only the address space is protected, never the process topology.
  - **It stops the *read*, not the *copy*.** Un-wiped plaintext copies on the request path are
    fixed in `credentials` and `egress-gateway`.
  - **Applied only for the spelling that holds a secret.** The other verbs are CLI clients, and
    dumpable=0 refuses **even the process's own parent**, so applying it everywhere would make the
    lost ability to debug unconditional.
- **Why the Linux egress transport is a descriptor, not a port (`netns_relay`).** Under the
  namespace launcher a workload with gateway-routed egress (the default) runs in a fresh network
  namespace with no routes, so *nothing* is reachable — including the proxy port on host loopback.
  (A leaf with `contain_egress = false` instead **joins the host network namespace** and needs no
  relay at all. See
  [native egress is a leaf escape](../../docs/design/decisions.md#native-egress-is-an-operator-declared-leaf-escape).)
  The trampoline creates the listening socket
  **inside** that namespace and passes the descriptor out over `SCM_RIGHTS`; the box accepts on it
  from the host namespace and splices each connection to the gateway. **A socket's network namespace
  is fixed when the socket is created, and that is the whole trick** — the listener stays bound in
  the workload's namespace forever, so the workload's `connect` reaches it with no route at all, and
  the box keeps accepting after the creating process has been replaced by `exec`. Do not replace
  this with a port, an address, or a re-bind on the host side; none survive the missing route. The
  relay carries bytes and decides nothing: reachability is *which descriptor was passed in*, and
  every request is still judged by the gateway's policy interceptor. **Adding a destination check
  here would be a second authority beside the policy.** On macOS none of this runs, because
  Seatbelt's `network-outbound` rule pins the workload to the proxy port directly.
- **`run/broker/python/effects.rs` is the script's filesystem boundary, and its path-approval
  primitive is `Reach::approve` in `run/broker/reach.rs`. Treat any change to either as a change to
  the security boundary** — together they are the only thing between attacker-supplied Python and the
  operator's filesystem. Two escapes were found in its first version, both pinned by a test that
  must not be deleted:
  - a **dangling symlink written through** (`a_dangling_symlink_cannot_be_written_through`). "It
    cannot be a symlink because it does not exist" is false: `canonicalize` fails with `ENOENT` on a
    dangling link, so the path took the create branch, got its name re-attached, passed
    `starts_with`, and `fs::write` followed it out of the box with the trusted process's authority.
    Hence `symlink_metadata` on the re-attached leaf.
  - an **intra-home link laundering a path-scoped rule**
    (`an_intra_home_symlink_cannot_launder_a_scoped_read`). `ScriptPolicyInterceptor` resolves
    lexically, so `home/public/alias -> home/private/secret` was judged as `/public/alias` and read
    from `/private/secret`. Both are inside the home, so no mount floor catches it; refusing a
    non-canonical spelling is what closes it.

  Planting either link needs no privilege, because the workload's profile grants blanket
  `file-write*` over its home. **`Reach::approve` must keep returning the canonical `PathBuf` it
  approved rather than a boolean**: both defects were the shape of checking one spelling and acting
  on another. `python/effects.rs` keeps that value and acts on it; the Shell side still throws it
  away — the first open finding below.
- **The script interpreter is a *weaker* memory-safety case than the Shell.** Monty carries **46
  `unsafe` blocks including a hand-rolled raw-pointer heap**, against the vendored Shell's zero, and
  it runs beside the in-memory CA key and the resolved secrets. So the argument for hosting it there
  is not memory safety: it is the floors above, plus that Monty performs no I/O of its own — every
  effect, filesystem **and** network, arrives as a suspension the host answers. Egress
  widened *what the host performs* from filesystem to filesystem+network; it did not give the
  interpreter I/O of its own. If a compromise ever has to be treated as arbitrary code in this
  process, the answer is to move the interpreter out and let it ask for each decision over a
  channel, which
  [the interpreters run in the trusted process](../../docs/design/decisions.md#the-interpreters-run-in-the-trusted-process)
  names.
- **A rate or budget cap must be a `forbid`, never a second `permit`.** Permits combine by
  permit-overrides, so a `permit … when temporal { count < N }` scoped to a whole action grants
  everything the narrow rules excluded — a cap that *widens* the policy. The codex example shipped
  that bug and its own denial check caught it; `tests/box_shell.rs` pins the behaviour.
- **`box-egress-probe` is a declared test-only binary under `tests/support/`, gated by the
  non-default `test-support` feature**, along with the credential end-to-end suite that spawns it.
  Keep the name, path, and gate explicit so a normal build cannot mistake it for a product binary.
  The probe speaks the proxy protocol itself because macOS `curl` reads a config path the box denies
  — that denial is the box working, not something to route around.
- **The end-to-end suites assert kernel and wire behaviour, not rendered text.** Profile-text
  assertions belong to `containment`'s conformance suite. A failure in `tests/box_filesystem.rs`,
  `tests/box_credentials.rs`, or `tests/box_shell.rs` means the boundary moved. `box_shell.rs` uses
  `/bin/bash` as its workload deliberately — it resolves `zsh` off `PATH` exactly as an agent
  harness does — which is also why that suite does not assert `/bin/bash` is denied: it holds the
  *workload's* own exec grant.

## The lifecycle verbs are gone, and must not come back by halves

`ls`, `stop`, `rm`, and `reset` are deleted, with the `$HOME/.strands-box/b/` namespace they read.
Every one of them found a box by enumerating that namespace or by resolving a name into it, so with
`box_dir` required there is nothing for them to enumerate: **Box cannot locate a box it was not
handed.** The caller that created the directory holds the path and owns the lifecycle — end the `run`
process to stop a box, remove the directory to delete one.

What went with them: `command/{list,stop,remove}.rs`, `layout::{every_box_name, boxes_namespace,
box_root_path, default_box_directory}`, `BoxRoot::{sited, open}`, `config::selected_box_or_project`,
`lock::{is_running, running_port, stop}`, `LayoutError::NotConfigured`, and
`DaemonError::LoadedBoxes`.

**A verb that takes a `box_dir` argument is a new interface, not a restoration.** If one is wanted,
argue it as an addition and note what `ls` cannot mean any more: there is no set of boxes to list, so
the verb would report on one directory the caller already named.

## Open findings — divergences no decision covers

Do not treat any of these as settled by the code existing.

- **A sibling box's stored state is reachable, and this is the sharpest one.** `Reach`'s `forbidden`
  set is `reserved_host_roots()` — `~/.strands-box` and the machine state directory — plus **this**
  box's own root, and nothing else (`run/broker/reach.rs`). With the `~/.strands-box/b/<name>` default
  withdrawn, **no box the product creates lands under a reserved root**, so a `permit fs:read` in box
  A's policy reaches box B's `private/policy.dw` and `private/box.toml` whenever both sit under a
  parent the reachable set covers — which the operator home always does. Measured during review:
  `approve()` returned `Ok` for `<home>/boxes/b/private/policy.dw` with box A at `<home>/boxes/a`.

  Under the old default the namespace was itself a reserved root, so one row covered every sibling.
  That is the property that went, and `reach.rs`'s own pin still passes only because its fixture
  hardcodes a `.strands-box/b/<name>` path.

  **The shipped layouts realize it**: the containment harness's `det-harness` + `det-harness-py`
  each put two or more boxes under one parent.

  **Accepted as a residual by the maintainers**, with the `box_dir` change. Box cannot close it
  by knowing where other boxes are — a caller supplies the path — so the candidates are: refuse a
  grant or a home enclosing `box_dir`'s **parent** (over-refuses for a caller who deliberately groups
  boxes), detect sibling box state on disk at config time (racy, and a box may not exist yet), or a
  new box-set input the caller declares. **The adjacent half IS closed**: a declared `env.HOME` that
  encloses `box_dir` is refused, which was the same defect reached through a home rather than a grant.

  What still holds, and what a reader must not over-read from it: a box cannot reach its **own**
  private tree, `~/.strands-box`, or the machine state; and both `SELF_DEFENDED_FILES` stay protected
  by identity rather than by path, so the *authored* config and policy of a running box are refused
  even when the file is reachable.
- **The telemetry destination guard narrowed with it.** `record/config/telemetry.rs` refuses a
  destination inside **this** `box_dir` outside `private/`; it used to refuse one inside any box's
  non-private tree, by stripping the namespace prefix. Same root cause as above, and the fail-closed
  branch for an unresolvable home went with it — there is no namespace left to be unable to resolve.
- **A stdio MCP server runs in a leaf box, and a leaf is wider than the agent's box.**
  `start_mcp_server` starts every declared stdio server as a contained leaf through the trampoline,
  after `shell:spawn` permits it. The uncontained start below it runs only when the box declares no
  stdio server, so no declared server reaches it, or on a non-unix build. The residuals: the leaf
  reaches its own `filesystem` lists with no `fs:*` decision; on macOS it runs its whole toolchain
  through broad exec, discovers metadata across the operator home, and loses W^X over its own
  writable grants, because one `file-map-executable` allow renders after the write deny so a build
  loads what it compiles; on Linux a writable bind also reads; an
  `[mcp.<name>.network] contain_egress = false` leaf bypasses the gateway, so its traffic has no
  network decision, and no credential injection, which the box records as an
  `egress:native` decision; and `mcp:call` bounds what the agent may ask for, not what the server
  does inside its leaf. The network half **is** pinned end to end, by
  `native_egress_mcp.rs::a_gateway_mcp_server_cannot_reach_an_unproxied_host_endpoint` and its
  native-egress control. What no end-to-end test covers is a **filesystem** refusal from inside a
  stdio server's leaf: `a_grantless_stdio_entry_is_still_contained` pins that translation, not the
  kernel.
- **The Shell floor discards the path it approved. This is the sharpest one.**
  `ReachFloor::approve_one` ends `.map(|_approved| ())`, so the canonical identity `Reach::approve`
  resolved is thrown away and the vendored `VfsKernel::resolve_host` re-resolves the caller's
  **string** and acts on that — the exact shape this file forbids twice. The race is winnable, not
  theoretical: the workload holds blanket `file-write*` over its home, can run concurrently with a
  broker call, and can retry, so swapping a directory for a symlink between approval and the effect
  makes a process that is **not** OS-contained write outside the box. Fix by threading the approved
  identity to the effect, or better by opening once under the root (`openat2` with
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and acting on the descriptor. **Do not** "simplify"
  `approve_one` into a bare `approve` call: `PathRefusal::Unreachable` and the outside-the-set case
  share one message, so a path whose spelling is inside a root but whose identity is not would
  silently become a pass.
- **The alias image is readable by the workload on Linux, and execute-only breaks the launcher.**
  `read -r leaked < "$ALIAS"` returns `\x7fELF`. On macOS the profile carries the property by itself
  (`process-exec` plus `file-read-metadata`, never `file-read*`); on Linux a bind mount cannot
  subtract read. Writes are still refused, so the workload reads bytes of a binary it may already
  execute — low severity, but a parity gap against a stated premise.

  **Why the obvious fix does not work.** Mode `0o500` → `0o100` plus an unconditional copy was tried
  and reverted: the namespace backend's `elf_dependencies` reads every exec grant as the same uid to
  find its interpreter and libraries, so nothing launches. A hard link shares one inode, so
  tightening the alias tightens the *installed* image.

  **Why it cannot be fixed inside containment.** `Operation::Exec` at `File` scope is the grant
  shape for the five aliases *and* for the workload's own program, which is frequently a system
  binary — so a backend tightening every execute-only grant would `chmod 0o100 /bin/bash`. Containment cannot tell
  "a file the box owns" from "the operator's binary" without a new field on the grant, which is
  `containment`'s frozen public surface. Closing it needs the user's approval for one of: an
  execute-only grant carrying **where to read its dependencies from**; an execute-only grant the box
  marks as **its own to tighten**; or the planner staging its own copy inside the view — which is
  ruled out, because the planner cannot tell an alias from the workload's program and copying every
  exec grant would copy `codex`, at 297 MB. Breaking the hard link costs a **20.5 MB per-box copy**.

  **The test is gated with the maintainers' approval, and gating is not inverting.**
  `the_alias_image_is_execute_only` asserts the read property where the platform can express it and
  asserts *nothing about reads* where it cannot; the write assertions run everywhere, and the skip
  prints `skipping: this platform cannot express execute-without-read`. The gate names the selected
  **backend**, not the kernel: an earlier gate returned `abi > 0`, the opposite of the condition
  that runs a box, so the assertion never executed on Linux at any ABI. It returns `true`
  unconditionally off Linux, so **macOS always runs it**. What is **not** allowed: gating the
  assertion and then asserting the leak is *present*, which pins the gap as desired behaviour.
- **Two negative assertions pin the reach of a project path.** Both behaviours are covered: the
  **workload's own** syscall on a project path is denied by containment until a list names it
  (`box_filesystem.rs::the_workspace_is_enterable_and_unreadable_until_listed`), and an `fs:*`
  permit on a path outside the reachable set is refused **regardless of the rule**
  (`reach.rs::Reach::approve`, pinned by
  `a_path_outside_the_reachable_set_is_refused_in_the_callers_spelling`). What is still wanted is an
  **end-to-end** test, a permitting rule refused through the whole box, which is blocked by the
  `operator_home` box-e2e drift — a containment-config schema mismatch that fails box creation for
  the whole `box_filesystem`/`box_shell` suite. The mechanism is already unit-covered, so this is
  completeness, not a hole.

**One narrow residual on Linux.** The mount view mounts a fresh writable tmpfs at `/tmp`, so an
operator whose `$HOME` is under `/tmp` gets `bin/`, `run/`, and `trust/` writable for that box. The
workload still cannot overwrite any file the box placed — each is its own read-only bind — and
cannot execute what it adds, because the shadowing tmpfs is `noexec`. So the cost is a file
appearing beside an alias. The fixture home is `/var/tmp/sb<pid>-<n>` for this reason, and
`fixture.rs`'s `FIXTURE_HOME_PARENT_TEXT` carries the constraint: anything chosen there must stay
off the fresh-mount list.

**`kernel_refusals` counts two spellings of a refusal, deliberately.** Seatbelt says `Operation not
permitted`; the namespace launcher does not put the path in the view at all, so the shell says
`No such file or directory` — a **stronger** refusal that an `EPERM`-only tally reads as a pass. It
does not count `Read-only file system` or `Text file busy`, which come from a bind mount and an
in-use image rather than from a decision.

Two testing traps: **`rg` times out on this tree** (`target/`), so use
`find … -print0 | xargs -0 grep`. And **do not assert a reset by the absence of `/tmp`** — assert
the home by name.

## Inline docs are short; the rationale lives here

**A doc comment says what the item is. It does not argue.**

| Where | What belongs there |
|---|---|
| `///` on an item | one paragraph: what it is, and any refusal a caller must expect |
| `//!` at a module head | one sentence, plus a table when the module has parts worth listing |
| **this file** | why a boundary exists, what breaking it cost, what was measured |
| `docs/design/decisions.md` | why a decision was made, under a stable anchor |

- **Do not re-grow the essays.** A new measured finding, a new footgun, a new "this already
  regressed once" goes in this file — not into a `///` block a reader must scroll past to reach the
  signature. A second copy inline is how the two came to disagree.
- **A one-line `//` beside the line it explains is still fine.** What was removed is the *block* of
  prose. If the note needs a second paragraph, it belongs in this file.

Skip the `///` entirely when the name already says it — a `version: u32` documented as "the format's
version" is noise, though "so a stale file from another build is a refusal" earns its line because
it states the *behaviour*.

## Cite a decision by anchor, not by number

The code and its tests own behaviour. `docs/design/decisions.md` owns why, and each entry has a
stable `<a id>` anchor. Cite an entry by that anchor: a **relative link** from Markdown, and
`docs/design/decisions.md#<anchor>` in a code comment. Do not cite a decision by a number, because
a number can land on the wrong target rather than on none, and a link fails visibly. A decision
that reaches shipped code gets its entry in the same change.
