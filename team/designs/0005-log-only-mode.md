# 0005: Strands Box LOG_ONLY mode

## Problem
Policy-generation tools can produce Dogwood policies for AgentCore and for Strands Box. On AgentCore, a builder can deploy a new policy in LOG_ONLY mode, watch what it would block on real traffic, and promote it to enforcement when it's safe. Box has no equivalent.

## Goal
Add a box-wide LOG_ONLY mode to Box that matches AgentCore's meaning: the policy is evaluated on every action as if enforced, but its denials don't block. Box records what would have happened, so a builder can safely trial a generated policy and then switch to enforcement.

## Success criteria
- For the same workload and policy, the actions marked would-deny in LOG_ONLY match the actions denied in enforce mode, up to each run's first flip.
- In LOG_ONLY, would-deny actions complete and the workload's exit code and outputs match a permit-all run.
- The OS sandbox, deny-only floors, credential isolation and private-state protection behave the same in both modes.
- With no setting, Box enforces and existing configs behave exactly as today.
- Box discloses LOG_ONLY on stderr at startup and marks every not-enforced decision in telemetry.
- A generated policy runs in Box LOG_ONLY, and a tool or script reports the would-deny actions.

## Proposed behavior
- One setting turns LOG_ONLY on for the whole box. It's off by default, so existing boxes behave exactly as today. This mirrors AgentCore's engine-level LOG_ONLY.
- An action the policy would deny proceeds. Its decision record carries the policy's verdict, the rule ids, and a marker that it was not enforced.
- LOG_ONLY relaxes only Dogwood verdicts. The OS sandbox, deny-only floors, credential isolation and Box's private state stay exactly as today.
- Box states LOG_ONLY on stderr at startup, next to its filesystem-grant disclosures.
- Results go to the existing decision telemetry (`records.jsonl`), so a policy tool, a script, or `jq` can count would-be denials.

## Key decisions

### KD 1: Box-wide, not per rule
Decision: One switch for the whole box.

Rationale: It covers the trial-then-promote flow and keeps the change small. Per-rule LOG_ONLY (AgentCore's policy-level mode) needs enforced rules and shadow rules evaluated side by side. That's v2, if users need it. A Dogwood annotation such as `@enforcement("log_only")` would be a natural fit then, since it keeps the setting inside the policy.

### KD 2: The setting lives on the `policy` key
Decision: The `policy` key accepts today's string, or a table that also says how the policy is applied.

```toml
# today, unchanged
policy = "policy.dw"

# LOG_ONLY
[policy]
source = "policy.dw"
enforcement = "log_only"      # "enforce" (default) or "log_only"
```

Both forms are accepted:
- The string `policy = "policy.dw"` means "this file, enforced", so every existing config keeps working unchanged.
- The `[policy]` table takes `source` (required) and `enforcement` (optional, default `enforce`), and only builders who want LOG_ONLY need it.
- A config uses one form or the other. In the table, a missing `source`, an unknown `enforcement` value, or an unknown field is refused with a clear error, like every other key today.

Rationale:
- LOG_ONLY changes how the policy input is applied, not what Box runs, so it isn't a new input. Keeping it next to the policy file makes that obvious to anyone reading the config.
- A CLI flag doesn't work, because the box contract forbids authority-changing flags and a flag wouldn't land in the box's stored record. A config value does, so a run can always show it wasn't enforcing.
- `[experimental-features]` doesn't fit, because AgentCore ships LOG_ONLY as a normal feature and builders need to rely on it to promote policies.
- `enforce` and `log_only` map to AgentCore's `ENFORCE` and `LOG_ONLY`, so tools that target both map them one to one.

This changes the shape of the `policy` key and the stored record (`RECORD_VERSION` bump). It also bends the premise that the authored policy is the only decision authority. Merging this doc is the approval for both.

### KD 3: Records keep the effective verdict
Decision: A policy denial in LOG_ONLY is recorded as `verdict = permit`, because the action ran, with new attributes:
- `strands.box.policy.enforcement = "log_only"` on every decision in a LOG_ONLY box
- `strands.box.policy.log_only.verdict = "deny"`
- `strands.box.policy.log_only.cause`, `.reason`, `.determining.ids` for what the policy said and which rules decided it

In LOG_ONLY, one action has two answers: what the policy said (deny) and what actually happened (it ran). `verdict` keeps what happened, and the new fields keep what the policy said. When the two disagree, that's a decision flip: the action would flip from allowed to blocked once enforcement is turned on. Zero flips over a long trial means the policy is safe to enforce.

Example: the agent writes `README.md`, and the policy doesn't allow it.

| Field | Enforce | LOG_ONLY |
|---|---|---|
| `verdict` | `deny` | `permit` |
| `enforcement` | none | `log_only` |
| `log_only.verdict` | none | `deny` |

Rationale: The telemetry docs define verdict as the effective decision. A new verdict value would silently break consumers that filter on `deny` and `permit`. A record with `verdict = permit` and `log_only.verdict = deny` is what AgentCore calls a decision flip, and counting flips is its promotion signal. Anything that still blocks in LOG_ONLY (the floors and KD 5) stays `verdict = deny` with no `log_only` fields.

### KD 4: History records what really happened
Decision: An action allowed only because of LOG_ONLY records `::request` and `::response` with its real output, like any permitted action. Not `::error`.

Box keeps a history so rules can depend on the past, for example "allow `git push` only if `npm test` passed earlier". Each action leaves `::request` (asked), then `::response` (it happened) or `::error` (it didn't). In LOG_ONLY a would-be-denied action really runs, so the history says it happened.

Example: the policy forbids `rm`. In enforce mode, `rm notes.txt` is blocked and the agent tries something else. In LOG_ONLY, `rm` runs (first flip), the file is gone, and the agent carries on down a different path. Everything up to and including the first flip previews enforce mode exactly. After that it's an approximation.

Rationale: `::error` means the operation did not happen. Later temporal rules need to see real history. AgentCore evaluates against real traffic the same way.

Trade-off: After the first flip, the run drifts from what enforce mode would have done, because the agent never hit the denial. Box marks the first flip of each run (`strands.box.policy.log_only.first_flip = true`) so tools can tell exact results from approximate ones.

### KD 5: Only policy denials flip
Decision: LOG_ONLY flips `Forbidden` and `NoMatch` only. `PolicyPending` (the policy bundle isn't installed yet) and `InternalFault` (evaluation failed) still deny.

Rationale: Those two aren't policy decisions. Letting them through would mean a missing or broken policy fails open. LOG_ONLY should test a policy, not switch off safety when evaluation breaks.

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
     │                                (real verdict + log_only fields)
     │
     │  LOG_ONLY and deny is Forbidden / NoMatch?
     │     yes ─► return Allow to the caller
     │     no  ─► return the real decision
     ▼
 deny-only floors   (reachable paths, credential stores)  ── still refuse
     │
     ▼
 operation runs ──► ::response recorded in temporal history
```

- Every request already goes through `PolicyEngine::decide_request`, which calls the authority and then `conclude`, the point that reports to the `DecisionObserver`. The change goes there, and Shell, Monty, egress, MCP admission and grammar actions all pick it up without per-point changes.
- Deny-only floors run after the engine, so they keep refusing in LOG_ONLY.
- In `crates/box/src/record/config/mod.rs`, `ConfigFile.policy` accepts a string or a `{ source, enforcement }` table, `enforcement` is stored in the `Record` (bump `RECORD_VERSION`), and it's passed into the `PolicyEngine` when the box builds it, as a builder option like `.observed_by(...)`.
- The KD 3 attributes are added where decision attributes are built, in `crates/telemetry/src/record.rs`.
- One stderr line is printed at startup.

## Limitations and not in v1
- Per-rule LOG_ONLY alongside enforced rules should be v2, if users need it.
- Generating policies is out of scope, since policy-generation tools already do this.
- Decisions after the first flip are approximate (KD 4).
- In LOG_ONLY, the policy doesn't protect you during the trial, so any action the policy would refuse can happen. Only containment still applies.