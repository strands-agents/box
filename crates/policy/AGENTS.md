# Policy Agent Guidance

For `crates/policy/**`. Follow the repository-root `AGENTS.md` first.

- This crate is interface-frozen: the `pub use` façade, and the authored vocabulary of action
  names, readable attributes, and what `when temporal { … }` observes. An operator's policy file is
  their source code.
- Fix the Box integration, the schema, and the event mapping behind the façade without approval.
- `dogwood-language` and `dogwood-local-engine` are published crates, pinned at `=1.0.0`.
- Close a gap listed here; never widen one. Never delete or `#[ignore]` a test that pins one.

## Read This First: Durable Dogwood History

- The engine is Dogwood: the published `dogwood-language` and `dogwood-local-engine` crates.
  Cedar's authorizer is deleted. Issue #59 lists what 1.0.0 lacks and where the box covers it.
- The code and its tests own the commit, recovery, policy-change, and time contract.
  [History is durable per box](../../docs/design/decisions.md#history-is-durable-per-box-and-has-no-rewind)
  records why. Do not restate that contract here.

## Sources Of Truth

- Behaviour and the durability contract: `src/**` and `tests/**`.
- Decisions: [`docs/design/decisions.md`](../../docs/design/decisions.md). Its entries on
  [the engine](../../docs/design/decisions.md#the-engine-is-dogwood),
  [durable state](../../docs/design/decisions.md#history-is-durable-per-box-and-has-no-rewind),
  [temporal enforcement](../../docs/design/decisions.md#temporal-rules-are-enforced-against-recorded-history), and
  [the public surface](../../docs/design/decisions.md#the-policy-crate-exposes-one-facade) record why.
- Rewrite a decision entry when its answer changes, as the root guidance requires.

## Public Contract Discipline

- The lifecycle is `PolicyEngine::open` → `decide` → `record` → `effective`.
  `PolicyEngine::validate` sits off it and returns no authority.
- The root `pub use` set in `src/lib.rs` is the whole API: 49 names with
  `--all-features` and 42 by default. Recompute it when you touch the façade.
- `KernelPolicyAdapter` is available only with `kernel-adapter`. Its consumer is the Box
  crate's `HostedBox`, enabled through `kernel-policy-integration`.
- Keep modules private. Keep every `dogwood_language` and `cedar_policy` type out of the façade.
- Keep `cedar-policy = "=4.11.0"` exact: the schema and the request gate are Cedar types, and
  Dogwood's own constraint is a caret range.
- `decide` and `record` take the `GovernedBox` as integration metadata. Assign that name from the
  endpoint you own; never read it from a request.
- `decide` is not a pure query: it observes the request into history first, so a denied request
  can advance history. The code and its tests own the exact verdict contract.
- One resource entity, `Box::Resource`, always uses the id `"unused"`. It carries no policy
  information, so a rule discriminates on the action and `context.input`.
- One principal, `Box::Agent`, always uses the id `"self"`. `Principal::with_id` retains integration
  metadata and does not change the policy identity.
- One `PolicyEngine` per run and one history file per box provide structural box isolation.
  Authored policy cannot discriminate on a box name.
- `PathResolver` is the only public minter of an `ApprovedPath`.
- `validate`'s caller is `read_authored_policy`, through `ConfigureRequest::load`, for `run` and
  `init`. Unvalidated, a bad policy exits 0 and fails at the next `run`. Keep
  `box/tests/box_lifecycle.rs::create_refuses_a_policy_the_engine_cannot_load` and
  `validation_accepts_and_refuses_exactly_what_open_does`.
- Do not reintroduce `PolicyConfig`, `ContainmentScope`, `containment_config`, `PolicyMode`, or
  `Remediation` without an entry in [`decisions.md`](../../docs/design/decisions.md). Add a public
  extension point only after
  [an external consumer is named](../../docs/design/decisions.md#the-policy-crate-exposes-one-facade).

## Internal Ownership

- `policy.rs` the lifecycle. `dogwood.rs` the private engine, event mapping, scope lock, and clock.
  `schema.rs` the `.cedarschema`, the name constants, and the request gate. `request.rs`,
  `outcome.rs`, `decision.rs`, `error.rs` their public types. `path.rs` the path types.
  `adapters/` one module per enforcement point, each behind its own feature.
- Put a new boundary in `adapters/`, not in a new root file. Keep a method with its type.

## Fail-Closed Invariants

- `open` returns an authority only after the engine's `Validator` strict-validates; `lower()` alone
  accepts a typo'd action. An unrecognized action is `PolicyError::UnknownAction`.
- Abort loading when `uses_providers()` is true.
- Keep the schema request gate in `decide`, although no caller reaches it today.
- Keep production timestamps on the durable engine's trusted system wall clock.
  `FixedClock` and `open_with_test_clock` are test-only.
- Keep `decide` infallible, and preserve its verdict contract.
- Preserve the startup refusal: `open` never returns an authority on empty or partial history.
- Deny a poisoned scope lock as `DenyReason::InternalFault`. Never call `into_inner()`.
- Grant only on `Decision::Allow`, and only with empty `diagnostics().errors()`.
- Never discard a `record` error.
- Treat `EffectivePolicy::policy_id` as diagnostic, not as an attested digest.
- An adapter may narrow a verdict and must never manufacture `Allow`.
- Absent policy is deny-by-default.
- Leave containment, credentials, and network enforcement to their owners.

## Known Limits — State These, Do Not Silently Work Around Them

- Declare context under `input`. A flat `context` makes `context has path` statically false, so a
  rule loads and never fires.
- The request gate has no externally-constructible non-conformance case; see
  `tests/readme_examples.rs::a_conforming_request_reaches_a_catch_all_permit`.
- A temporal predicate cannot name an action group, and offers no `or` and no wildcard, so write
  one clause per granular action. The spellings are `shell:exec`, `http:request`, and `mcp:call`.
  Do not reintroduce a group action.
- Key a precondition on `::response`, because a `::request` predicate matches a denied attempt.
  Pinned by `tests/temporal_shell_e2e.rs::a_denied_attempt_satisfies_a_request_keyed_precondition`.
- History is pruned to the deepest window, and the workload fills that window. State an
  availability bound.
- Pin a destination on `host` and `port`, and refuse an address with a `forbid` on the string `ip`.
- `context.input.path` also carries a URL path, so guard a filesystem rule with
  `context.input has operation`.
- `body_bytes` is the offer on a `::request` and the delivery on a `::response`.
- Sum an outbound budget over `http:request::response`, as `tests/policies/egress_byte_budget.dw`
  does. One exchange records one such event, at reply time, with the delivered request bytes and
  the reply's `output.status`. Pinned by
  `tests/temporal_egress_budget.rs::a_reply_adds_nothing_to_an_outbound_budget`.
- An outcome-only fact reaches history through the event kind (`response` vs `error`); every filesystem response also carries `output.result`.
- Do not extend a durability, audit, atomicity, or performance claim past what the tests
  pin.

## Documentation Boundaries

- `README.md` serves a Rust consumer. Extend `tests/readme_examples.rs` with each example, and
  apply the `docs-writer` skill there. Keep workflow, structure, and review rules here.

## Change Checklist

1. Read the relevant entries in
   [`decisions.md`](../../docs/design/decisions.md).
2. Reconcile the public names across the code, the tests, and `README.md`.
3. Run `build`, `test`, `clippy --all-targets`, and `fmt --check` for `-p strands-box-policy`, each
   with and without `--all-features`, plus `RUSTDOCFLAGS="-D warnings" cargo doc`. Vendored
   clippy warnings from `strands-shell` are expected; policy-owned warnings must be zero.
4. Give a temporal change a long-run test, because a short one passes on a sawtooth.
5. Run `feature-critic` before you commit. Keep `Cargo.lock`, `egress-gateway`, and `credentials`
   unchanged.

## Measured fail-opens and footguns

- LIVE GAP: the Script boundary resolves lexically, so a read through a symlink and a rename onto
  an aliased destination each evade a rule. Containment is the only control. Pinned by
  `tests/policy_script_fs_e2e.rs::script_symlink_aliasing_is_not_defended`. To close it, resolve a
  rename's source and its destination's final component no-follow and the destination's parents follow, and resolve through Monty's mount table,
  never with `std::fs::canonicalize`.
- LIVE GAP: `approve_host`'s refusal variant shows whether a host path exists: a path through a
  live symlink at any component is `NotCanonical` and one through a dangling symlink `Unresolvable`,
  and a plain path outside every root is `Unresolvable` when its parent is missing and `Unreachable`
  when it is not. This is the existence-oracle class on host binds. Give one reason for every
  refusal of a path the caller may not reach.
- LIVE GAP: on a direct host bind the Shell reports a read through a host symlink by the alias
  spelling, so a link to a directory carries a subtree read `forbid` away. A scoped `fs:write`
  admits the link since a relative target is judged on the path it resolves to; a scoped `fs:move`
  already did. Pinned by
  `tests/symlink_target_scope_e2e.rs::a_directory_symlink_on_a_direct_bind_is_not_defended_by_a_subtree_read_forbid`.
  To close it, judge the `Filesystem` arm on the in-bind canonical identity the kernel resolves.
- LIVE GAP: `like` is case-sensitive and macOS is not, so `policy.DW` stays exposed. Do not widen
  the pattern to `*.dw`, which over-denies an ordinary `.dw` file.
- `SELF_DEFENDED_FILES` is `["box.toml", "policy.dw"]`, and it is public so tests and
  `box/src/define/layout.rs` derive from it. Add no `*.cedar` rule and no speculative entry. A
  defended filename costs an escalation chain, as `mcp.toml` did.
- Raise three legs for a `FilesystemPair`: the source as the pair operation, the source as
  `fs:read_content`, and the destination. Do not reduce it to two. A rename whose destination
  exists raises a fourth, `fs:delete` on the destination, because the rename removes what it held.
- Shell outbound HTTP raises no attempt, so policy does not cover it and only the deny-only
  `network_enabled` switch and SSRF floor do. Do not decide egress in the Shell adapter. The MCP
  `shell` tool reaches `run_pipeline`, so it does raise `shell:exec`.
- Record an outcome this vocabulary cannot name as `Indeterminate`; never drop it.
- Refuse `os.getenv` and `os.environ` while the schema cannot name them, because the box projects
  credential phantoms into the environment. Pinned by
  `an_environment_read_is_refused_while_the_schema_cannot_name_it`.
- Refuse `Mkdir` with `parents == true`, because `ScriptPermit` cannot bound the ancestors.
- Keep `classify` exhaustive. If upstream marks `OsFunctionCall` `non_exhaustive`, add `_ => None`,
  denied.
- Keep `Admitted::Clock` bounded to `date.today()` and `datetime.now()`, decided by nobody and
  recorded nowhere.
- Map `Stat`, `Exists`, `IsFile`, `IsDir`, and `IsSymlink` to `fs:read_metadata`. The
  vocabulary does not separate follow from no-follow.
- Do not align the Script adapter with upstream `monty-dogwood`, which leaves an unmapped call
  ungated and authorizes the caller's spelling. Deny an unmapped call, and normalize before you
  decide.
- Write every field a temporal predicate reads to both bags: `.field()` and `.request_context()`.
- Keep both saturations deny-ward: `Clock::now()` to 0, and `clamp(bytes)` to `i64::MAX`.
- A dropped `ScriptPermit` submits `FsResult::Indeterminate` from `Drop`. Keep `#[must_use]`, claim
  `reported` before you submit, and discard a `Drop` recording failure. `EffectPermit` and
  `KernelPermit` mirror it.
- The engine differential is deleted with Cedar (528 verdicts, 0 divergences). It caught the
  missing request gate (32 verdicts), so the gate lives in `decide`.
- Parse the schema at `open`, never lazily: a lazy parse costs the first call ~1.5 ms and turns a
  load error into a first-request deny. `cached_uid` saves ~7 µs per verdict and still yields
  `PolicyError::Schema`.
