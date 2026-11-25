# Policy guidance

The root freeze covers the facade, policy vocabulary, and temporal observations. An operator's
policy is source code. Keep Dogwood and Cedar types behind the facade. Dependency pins live in
`Cargo.toml`; preserve the exact Cedar requirement even when Dogwood accepts a wider range.
Read [durable history](../../docs/design/decisions.md#history-is-durable-per-box-and-has-no-rewind)
before changing persistence; code and tests own its current commit and recovery behavior.

## Authorization traps

- `decide` records a request before deciding, including denied requests. Keep its returned
  `RequestId` for the outcome, and refuse an ordinary effect with no allow token.
- Strict validation is required: lowering alone accepts misspelled actions. Keep the request
  schema gate and parity between `check`, `validate`, and opening the engine, including staged MCP.
- Assign `GovernedBox` from the endpoint you own, never the request. Box/principal names used for
  integration metadata are not authored-policy identities.
- Log-only mode flips only recorded `Forbidden` or `NoMatch` denials with an installed policy.
  Missing policy, pending schemas, evaluator faults, and degraded tools still deny. Keep the flip
  inside the authority; adapters must not manufacture allows. Test both admission and outcomes.
- A poisoned lock denies; recovering its contents is not recovery of valid authority. Never discard
  an explicit outcome-recording error. Dropped permits still submit an indeterminate outcome.
- Keep filesystem pairs' source mutation, source content-read, and destination checks. A rename
  over an existing destination also needs destination deletion. A permit on one path covers no other.
- Populate both request context and logged input for fields read by both policy types. Reserved
  history fields use `logged_field` only. Preserve deny-ward clock and byte-count saturation.

## Known limits

- A precondition on `::request` can be satisfied by a denial; key successful work on `::response`.
  MCP responses also include cancellation and unread replies, so require `output.reply: "result"`.
  Structured-output history is safe for positive prerequisites, not an unavoidable exfiltration
  trigger: a workload can make a reply unreadable or too large to record.
- Rate and budget caps need `forbid`, not a second `permit`: permits combine and can widen a narrow
  grant. Outbound HTTP budgets count delivered request bytes on `http:request::response`;
  WebSocket traffic is a separate action and contributes no bytes to that budget.
- Context fields live under `input`. Filesystem and HTTP both have `path`; preserve the checks
  refusing mixed input families and mixed action namespaces rather than silently parking bad rules.
- Per-tool history survives restart only for rules whose heads name per-tool actions alone.
  A Box-headed rule reading tool history starts fresh. A server never discovered in this run can
  leave a pending rule unenforced. See `tests/runtime_mcp_policy_staging.rs`.
- Clear degraded-tool holds only after a complete bundle commits. A rejected late schema must not
  let a tool fall back to the coarse `mcp:call` grant. Two missing schemas cannot recover through
  separate rejected relists.
- The Script adapter resolves paths lexically in the interpreter's namespace; host `canonicalize`
  is the wrong fix. Symlink reads and aliased rename destinations need the host's separate checks
  (`script_symlink_aliasing_is_not_defended`). The Shell adapter trusts upstream resolution too;
  neither adapter alone supplies Box's `Reach` floor.
- Host path refusals can reveal existence. Case-sensitive self-defense filename rules do not cover
  every spelling on a case-insensitive filesystem. Do not describe these as closed by the adapter.
- Deny unmapped Monty calls, environment reads, and recursive mkdir until the vocabulary can bound
  them. The admitted clock calls remain unrecorded. Do not copy upstream `monty-dogwood`'s ungated
  fallback for an unmapped call.
- Shell HTTP is governed through Box's gateway, not this crate's Shell adapter. Adding egress
  decisions to that adapter would duplicate the network authority.
- One common schema type per grammar action caused quadratic load time in measured Dogwood builds.
  Keep grammar inputs inline (`a_grammar_with_many_actions_declares_no_type_per_action_and_loads`).
  MCP schemas still declare per-tool types; large catalogs need measurement before performance claims.
- A tool whose MCP schema does not generate stays in the catalog with no per-tool action, so only
  `mcp:call` rules decide it. Never give it an action with untyped arguments: a guarded `forbid` on
  an argument would load and never fire. With no action, a rule that names it cannot load and the
  tool degrades (`a_rule_on_a_left_out_tool_degrades_it_and_the_rest_of_the_server_works`). Its
  arguments are not checked against its schema, which a typed tool's are. The per-tool retry
  composes with a `Box::Agent` and `Box::Resource` stub and skips a list with no `$ref`, because a
  full composition per tool timed out `catalog_page_limit_accepts_256_pages_and_refuses_a_257th`.

## Verification beyond the root gates

Run the root build, test, and clippy gates with both default features and `--all-features`, and
run rustdoc with warnings denied. Temporal changes need long-run tests: a short run can miss
periodic history failures. README examples belong in
`tests/readme_examples.rs`. Do not infer durability, audit completeness, or performance from
an unexercised branch.
