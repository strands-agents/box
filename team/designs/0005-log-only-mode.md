# 0005: Strands Box log-only mode

## Problem
Policy-generation tools can produce Dogwood policies for AgentCore and for Strands Box. On AgentCore, a builder can deploy a new policy in LOG_ONLY mode, watch what it would block on real traffic, and promote it to enforcement when it's safe. Box has no equivalent.

## Goal
Add a box-wide log-only mode to Box that matches AgentCore's LOG_ONLY: the policy is evaluated on every action as if enforced, but its denials don't block. Box records what would have happened, so a builder can safely trial a generated policy and then switch to enforcement.

## Success criteria
- For the same workload and policy, the actions marked would-deny in log-only mode match the actions denied in enforce mode, up to each run's first flip.
- In log-only mode, would-deny actions complete and the workload's exit code and outputs match a permit-all run.
- The OS sandbox, deny-only floors, credential isolation and private-state protection behave the same in both modes.
- Without the setting, Box enforces and existing configs behave exactly as today.
- Box discloses log-only mode on stderr at startup and marks every not-enforced decision in telemetry.
- Every run's `policy_installed` record states its mode, so a log-only run with no would-denies is still identifiable.
- A generated policy runs in Box log-only mode, and a tool or script reports the would-deny actions.

## Proposed behavior
- One setting in `box.toml` turns log-only mode on for the whole box. It's off by default, so existing boxes behave exactly as today. This mirrors AgentCore's engine-level LOG_ONLY.
- An action the policy would deny proceeds. Its decision record keeps the policy's verdict and rule ids, and is marked as not enforced.
- Log-only mode relaxes only Dogwood verdicts. The OS sandbox, deny-only floors, credential isolation and Box's private state stay exactly as today.
- Box states log-only mode on stderr at startup, next to its filesystem-grant disclosures.
- Results go to the existing decision telemetry (`records.jsonl`), so a policy tool, a script, or `jq` can count would-be denials.
- The `policy_installed` record carries the run's mode (`enforce` or `log_only`).

## Key decisions

### KD 1: Box-wide, not per rule
Decision: One switch for the whole box.

Rationale: It covers the trial-then-promote flow and keeps the change small. Per-rule log-only (AgentCore's policy-level mode) needs enforced rules and shadow rules evaluated side by side. That's v2, if users need it. A Dogwood annotation such as `@enforcement("log_only")` would be a natural fit then, since it keeps the setting inside the policy.

### KD 2: The setting lives on the `policy` key in `box.toml`
Decision: The `policy` key accepts today's string, or a table that also says how the policy is applied.

```toml
# today, unchanged
policy = "policy.dw"

# log-only mode
[policy]
source = "policy.dw"
enforcement = "log_only"      # "enforce" (default) or "log_only"
```

Both forms are accepted:
- The string `policy = "policy.dw"` means "this file, enforced", so every existing config keeps working unchanged.
- The `[policy]` table takes `source` (required) and `enforcement` (optional, default `enforce`), and only builders who want log-only mode need it.
- A config uses one form or the other. In the table, a missing `source`, an unknown `enforcement` value, or an unknown field is refused with a clear error, like every other key today.

Rationale:
- Log-only mode changes how the policy input is applied, not what Box runs, so it isn't a new input. Keeping it next to the policy file makes that obvious to anyone reading the config, and `box.toml` keeps its nine keys.
- Policy tools and launchers are often separate. A setting in the config can be written by whatever prepares the box, while a CLI flag only reaches whoever runs it.
- The `box` binary is being replaced by a new Box CLI. A config setting works the same under any CLI, with no new argument and no box contract amendment.
- A config value lands in the box's stored record, so a run can always show afterwards that it wasn't enforcing.
- A CLI flag is more visible at launch. To cover that, Box states log-only mode on stderr at the start of every run and records it on `policy_installed`, so a box can't quietly stay in log-only mode after a trial.
- `[experimental-features]` doesn't fit, because AgentCore ships LOG_ONLY as a normal feature and builders need to rely on it to promote policies.
- `enforce` and `log_only` map to AgentCore's `ENFORCE` and `LOG_ONLY`, so tools that target both map them one to one.

This changes the shape of the `policy` key and the stored record (`RECORD_VERSION` bump). It also bends the premise that the authored policy is the only decision authority. Merging this doc is the approval for both.

### KD 3: Records keep the policy's verdict
Decision: `verdict` keeps the policy's answer. A decision Box didn't apply gets a new optional attribute, `strands.box.policy.enforced = false`. Nothing else is added: the record already carries `cause`, `reason` and `determining.ids`.

In log-only mode, a would-deny action runs, so its record says `verdict = deny` and `enforced = false`. That pair is a decision flip: the action would flip from allowed to blocked once enforcement is turned on. Zero flips over a long trial means the policy is safe to enforce. Permits, and denials that still block in log-only mode (the floors and KD 5), carry no `enforced` field.

Example: the agent writes `README.md`, and the policy doesn't allow it.

| Field | Enforce | Log-only mode |
|---|---|---|
| `verdict` | `deny` | `deny` |
| `enforced` | none | `false` |
| `cause`, `determining.ids` | the policy's | the policy's |

The mode is also recorded once per run, on the `policy_installed` control-plane record (`enforce` or `log_only`). With `enforced` only on would-denies, a clean log-only run would otherwise look like an enforcing one, and that's the run that matters most, because zero flips is the signal that a policy is safe to enforce.

Rationale: The point of log-only mode is to see what the policy would deny, so `verdict == "deny"` should find every would-deny directly. Adding `enforced` per decision, rather than per box, keeps real blocks (KD 5) distinguishable from would-denies. The telemetry docs describe records as the effective decision, so that wording changes: a record with `enforced = false` describes a decision that wasn't applied. Tools that alarm on every `deny` should filter on `enforced`.

### KD 4: History records what really happened
Decision: An action allowed only because of log-only mode records `::request` and `::response` with its real output, like any permitted action. Not `::error`.

Box keeps a history so rules can depend on the past, for example "allow `git push` only if `npm test` passed earlier". Each action leaves `::request` (asked), then `::response` (it happened) or `::error` (it didn't). In log-only mode a would-be-denied action really runs, so the history says it happened.

Example: the policy forbids `rm`. In enforce mode, `rm notes.txt` is blocked and the agent tries something else. In log-only mode, `rm` runs (first flip), the file is gone, and the agent carries on down a different path. Everything up to and including the first flip previews enforce mode exactly. After that it's an approximation.

Rationale: `::error` means the operation did not happen. Later temporal rules need to see real history. AgentCore evaluates against real traffic the same way.

Trade-off: After the first flip, the run drifts from what enforce mode would have done, because the agent never hit the denial. Box marks the first flip of each run (`strands.box.policy.first_flip = true`, on the first `enforced = false` decision) so tools can tell exact results from approximate ones.

### KD 5: Only policy denials flip
Decision: Log-only mode flips `Forbidden` and `NoMatch` only. `PolicyPending` (the policy bundle isn't installed yet) and `InternalFault` (evaluation failed) still deny.

Rationale: Those two aren't policy decisions. Letting them through would mean a missing or broken policy fails open. Log-only mode should test a policy, not switch off safety when evaluation breaks.

### KD 6: Reload keeps the mode
Decision: The mode comes from `box.toml` and stays fixed for the run. `reload()` swaps policy text only.

## Implementation sketch

```text
 agent action
     │
     ▼
 enforcement point  (Strands Shell · Monty · egress gateway · MCP broker)
     │
     ▼
 PolicyEngine::decide_request          crates/policy/src/policy.rs
     │  authority.decide(...)  ──►  real Dogwood decision
     │  conclude(...)          ──►  DecisionObserver ──► records.jsonl
     │                                (policy's verdict + enforced = false when not applied)
     │
     │  log-only mode and deny is Forbidden / NoMatch?
     │     yes ─► return Allow to the caller
     │     no  ─► return the real decision
     ▼
 deny-only floors   (reachable paths, credential stores)  ── still refuse
     │
     ▼
 operation runs ──► ::response recorded in temporal history
```

- Every request already goes through `PolicyEngine::decide_request`, which calls the authority and then `conclude`, the point that reports to the `DecisionObserver`. The change goes there, and Shell, Monty, egress, MCP admission and grammar actions all pick it up without per-point changes.
- Deny-only floors run after the engine, so they keep refusing in log-only mode.
- In `crates/box/src/record/config/mod.rs`, `ConfigFile.policy` accepts a string or a `{ source, enforcement }` table, `enforcement` is stored in the `Record` (bump `RECORD_VERSION`), and it's passed into the `PolicyEngine` when the box builds it, as a builder option like `.observed_by(...)`.
- The `enforced` and `first_flip` attributes are added where decision attributes are built, in `crates/telemetry/src/record.rs`, and the mode is added to the `policy_installed` control-plane record.
- One stderr line is printed at startup.

## Limitations and not in v1
- Per-rule log-only alongside enforced rules should be v2, if users need it.
- Generating policies is out of scope, since policy-generation tools already do this.
- Decisions after the first flip are approximate (KD 4).
- In log-only mode, the policy doesn't protect you during the trial, so any action the policy would refuse can happen. Only containment still applies.