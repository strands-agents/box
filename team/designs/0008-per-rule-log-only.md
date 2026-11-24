# 0008: Strands Box per-rule log-only mode

## Problem
Today a new rule in `policy.dw` enforces from its first call, so a mistake in it blocks real work. [Box-wide log-only mode (0005)](0005-log-only-mode.md) trials a whole policy by turning enforcement off for the box. It doesn't fit adding one rule to a policy that's already enforcing, because every other rule stops enforcing too.

## Goal
Let a builder mark individual rules in `policy.dw` as log-only. The other rules keep enforcing. Box evaluates each log-only rule on every action and records which ones would have changed the outcome. A rule can then be promoted to enforce without losing its history.

This is the per-rule control that [0005](0005-log-only-mode.md) leaves out of v1. It needs a change in Dogwood's local engine, which isn't released yet. It doesn't depend on 0005 being built, so the two can ship in either order.

## Success criteria
- A log-only rule never changes what happens to an action.
- For every action, the record names each log-only rule that would have changed its outcome on its own.
- Flips are recorded in both directions: a log-only forbid that would deny, and a log-only permit that would allow.
- A log-only rule's history advances on every event, like an enforced rule's.
- Adding a log-only rule resets no other rule's history.
- Promoting a rule to enforce keeps its history and resets nothing else.
- After a restart, Box knows which rules are log-only before its first decision.
- A policy without log-only rules behaves as today.

## Proposed behavior
- A rule is log-only when it carries `@enforcement("log_only")` and an `@id`.
- Box installs every rule, so the engine keeps history for all of them.
- Box enforces the rules without the marker (the active rules).
- For each log-only rule, Box also works out what it would do to the action if it were active. If the outcome would change, that rule would flip the action.
- To promote a rule, remove the marker. To demote it, add the marker back.

## Key decisions

### KD 1: Mark rules in `policy.dw`
Decision: The marker is a Dogwood annotation, `@enforcement("log_only")`, on the rule. Any other value is refused, and so is a log-only rule without an `@id`.

Rationale: Policy-generation tools write `policy.dw`, not `box.toml`, so the marker has to live in the policy. Dogwood already parses any `@name("value")` annotation, so the language doesn't change. Records name log-only rules, and a rule without an `@id` is named by its position ("the forbid rule with no @id"), which moves when the file changes.

### KD 2: The marker isn't part of a rule's identity
Decision: Box removes the `@enforcement` annotation from a rule's text before it installs the rule and compares it with what's installed. Two rules that differ only by the marker are refused.

Rationale: Box recognizes an installed rule by its exact text. A rule whose text changes is deleted and added again, and a new rule starts with empty history (`policy_set_change_parts` in `crates/policy/src/dogwood.rs`). Without this, promoting a rule would reset it.

What happens to history:
- Adding a log-only rule: it starts with empty history. Nothing else resets.
- Promoting or demoting: same rule, history kept.
- Editing anything other than the marker: a new rule with new history, as today.
- Removing a rule: its history is gone. Adding it back starts fresh.

### KD 3: One engine, and Box passes the log-only list
Decision: Box keeps one Dogwood engine with every rule installed. On each decision, it passes the list of log-only rules. The engine returns the answer over the active rules and, for each listed rule, the answer over the active rules plus that rule, all from the same event and history.

Rationale:
- Two engines (one with the active rules, one with all of them) would stamp events at different times, so a rule like "within 1h" could disagree near the window edge. Promoting a rule into the active engine would also start it with empty history.
- Box can't work this out from one decision over all rules. When that decision is a deny from a log-only forbid, Cedar doesn't say whether an active permit also matched, and a log-only permit can be hidden behind a log-only forbid on the same call.
- The engine keeps no new state, so recovery doesn't change.

Cost: with n log-only rules, each decision checks about n + 2 rule sets. There's no limit on n.

This needs a Dogwood local engine release with the new call, and Box moves its Dogwood pins to it.

### KD 4: Box rebuilds the list on every start
Decision: Box builds the log-only list from the markers each time it installs the policy, including on startup, and refuses to decide until the list exists.

Rationale: After a crash, the engine recovers every rule and doesn't know which are log-only. A missing list would make log-only rules enforce, and a log-only permit would let actions through.

### KD 5: Records keep the enforced verdict
Decision: Unlike [0005 KD 3](0005-log-only-mode.md#kd-3-records-keep-the-policys-verdict), `verdict`, `cause` and `determining.ids` describe the decision Box applied, because Box does apply the active rules. Under box-wide log-only they follow 0005 instead (KD 7). Each action with log-only rules adds:
- `strands.box.policy.log_only.would_flip`: the log-only rules that would change the action's outcome (KD 9).
- `strands.box.policy.log_only.unevaluated`: the log-only rules Box couldn't judge for this action, because their answer came back with an error or they are pending or degraded (KD 8). These never count as flips, for the reason in [0005 KD 5](0005-log-only-mode.md#kd-5-only-policy-denials-flip).

An error makes Box deny as `InternalFault`, so a rule in `unevaluated` because of an error would fault if promoted. When the active rules' own answer has an error, Box denies as `InternalFault` and records no log-only results for that decision.

The `policy_installed` record lists the log-only rules.

Rationale: Tools that read `verdict` keep seeing what really happened, so a log-only forbid doesn't show up as a denial. Naming each rule is the promotion signal: "this rule would have blocked N actions this week".

### KD 6: Judged against the history that happened
Decision: [0005 KD 4](0005-log-only-mode.md#kd-4-history-records-what-really-happened) applies. A log-only rule is judged against the history that really happened, not one where it had been enforcing.

Trade-off: Log-only rules can affect each other's results. Suppose rule A requires `verify_identity` before a password reset, and rule B allows at most two resets a day. Two unverified resets go through, and A would flip both. A later verified reset then gets a B flip, because B counts the first two. If A had been enforcing, those resets wouldn't exist. When rules build on each other, promote the first one before trialling the next.

### KD 7: Works under box-wide log-only, as in AgentCore
Decision: Both can be on, and [box-wide log-only](0005-log-only-mode.md) takes precedence, so nothing is enforced. The active rules still make the decision, and Box records it as [0005 KD 3](0005-log-only-mode.md#kd-3-records-keep-the-policys-verdict) describes. Log-only rules are compared with the active rules' outcome (KD 9), not with what Box applied, and recorded in `log_only.*` as usual.

Rationale: Under engine-level LOG_ONLY, AgentCore "still computes the decision and you still receive `LOG_ONLY` telemetry" ([Test a policy in LOG_ONLY mode](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-test-a-policy.html)), so a generated policy behaves the same in both modes. Comparing with the active outcome keeps flips meaningful when nothing is enforced.

### KD 8: Log-only rules don't hold MCP tools
Decision: Log-only rules are left out of the pending and degraded tool sets, so whether a tool is held depends only on the active rules. While a log-only rule is pending or degraded, it isn't installed, so Box lists it in `unevaluated` on every decision, not only on calls to its tool, and marks it as pending in the `policy_installed` list.

Rationale: A pending rule can decide actions other than its tool's calls, such as a rule that counts a tool's past calls to limit `http:request`. Listing it everywhere keeps its trial from looking like "never fires". Box holds a tool while a rule for it waits on its schema, so a call can't ride the coarse `mcp:call` permit with that rule's constraint unenforced (`refine_tool_call` in `crates/policy/src/policy/authority.rs`). A log-only rule's constraint isn't enforced anyway, so holding the tool would only block real work and break the first success criterion.

### KD 9: A flip is judged on the action's outcome
Decision: A log-only rule flips an action when the outcome Box would apply, with that rule active, differs from the outcome under the active rules alone. Box applies the same steps it applies to the active answer: a per-tool `NoMatch` rides the coarse `mcp:call` allow, and the first deny among an action's gates and legs decides it. `would_flip` is merged across all of the action's gates and legs. When a log-only permit would pass a gate or leg that isn't the last, the later ones don't run, so that flip is an upper bound: the action could still be denied later.

Rationale: The engine's answer isn't always what Box applies. For a tool with no active per-tool rule, the engine answers `NoMatch`, and Box allows the call on the coarse permit. A log-only per-tool forbid then turns an allowed call into a denied one, even though both engine answers are deny. A log-only per-tool permit changes the engine answer but not the outcome. An action checked in several legs, such as a Strands Shell rename, can be flipped by one leg that isn't the last.

## Interface additions
Merging this design approves these additions to frozen surfaces:
- The `@enforcement("log_only")` annotation, and refusing a log-only rule without an `@id`.
- `strands.box.policy.log_only.would_flip` and `strands.box.policy.log_only.unevaluated` on decision records.
- The list of log-only rules on the `policy_installed` record.

## Implementation sketch
- `crates/policy/src/dogwood.rs`: read and strip the marker during validation and expansion, refuse duplicates that differ only by the marker and log-only rules without an `@id`, build the log-only list from the installed rules, and call the new engine API on each decision instead of `submit`. Return the per-rule answers with the active answer.
- Enforce the active answer. Errors on it keep today's handling (deny as `InternalFault`).
- `crates/policy/src/policy/authority.rs`: leave log-only rules out of `pending_typed_tools` and the degraded set, and apply `refine_tool_call`'s mapping to each per-rule answer.
- `crates/policy/src/policy.rs`: compute `would_flip` and `unevaluated` where an action's gates and legs are combined, and merge them across its observations.
- `crates/telemetry/src/record.rs` adds the two attributes and the log-only list on `policy_installed`.
- Bump the Dogwood pins, and test history across an upgrade and a rollback to the previous binary, including that the older binary enforces a marked rule.

## Limitations and not in this design
- A Box released before this design ignores the marker and enforces marked rules, and so does any Box when the annotation name is misspelled, because Box ignores annotations it doesn't know. For a log-only permit, that grants access. Refusing unknown annotation names is a separate change.
- Log-only rules affect each other's results when they count the same actions (KD 6).
- Rules that matched without changing the outcome aren't recorded.
- Each decision's cost grows with the number of log-only rules (KD 3).
- A permit flip on a gate or leg that isn't the last is an upper bound (KD 9), so "this rule would have allowed N actions" can be too high.
- It depends on a Dogwood local engine release.
