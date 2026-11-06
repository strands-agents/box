# 0005: Strands Box log-only mode

## Problem
Policy-generation tools can produce Dogwood policies for AgentCore and for Strands Box. On AgentCore, a builder can deploy a new policy in LOG_ONLY mode, watch what it would block on real traffic, and promote it to enforcement when it's safe. Box has no equivalent.

## Goal
Add a box-wide log-only mode to Box that matches AgentCore's engine-level LOG_ONLY: the policy is evaluated on every action as if enforced, but its denials don't block. Box records what would have happened, so a builder can safely trial a generated policy and then switch to enforcement.

AgentCore has two LOG_ONLY controls:
- Per-policy `enforcementMode = LOG_ONLY`: one policy (one rule) is evaluated and logged while the rest keep enforcing. This is the main way AgentCore users trial a new rule, and what policy-generation tools use.
- Engine-level `mode = LOG_ONLY`: nothing in the engine is enforced.

This doc is v1 and matches only the engine-level control: box-wide log-only. The per-policy control, per-rule log-only in Box, is a planned v2 with its own design, because it needs a change in Dogwood's local engine. v1 alone doesn't give per-rule trials.

## Success criteria
- For the same workload and policy, the actions marked would-deny in log-only mode match the actions denied in enforce mode, up to each run's first flip.
- In log-only mode, would-deny actions complete and the workload's exit code and outputs match a permit-all run.
- The OS sandbox, the reachable-paths floor, credential isolation (the agent never holds a secret) and private-state protection behave the same in both modes.
- Without the setting, Box enforces and existing configs behave exactly as today.
- Box discloses log-only mode on stderr at startup, including what it exposes, and marks every not-enforced decision in telemetry.
- Every run's `policy_installed` record states its mode, so a log-only run with no would-denies is still identifiable.
- A generated policy runs in Box log-only mode, and a tool or script reports the would-deny actions.

## Proposed behavior
- One setting in `box.toml` turns log-only mode on for the whole box. It's off by default, so existing boxes behave exactly as today. This mirrors AgentCore's engine-level LOG_ONLY.
- An action the policy would deny proceeds. Its decision record keeps the policy's verdict and rule ids, and is marked as not enforced.
- Log-only mode relaxes only Dogwood verdicts, matching AgentCore's engine-level LOG_ONLY. The OS sandbox, the reachable-paths floor, credential isolation and Box's private state stay exactly as today.
- On the Strands Shell and Monty path, the policy is the only protection for the operator's home directory, credential files and cloud metadata. In log-only mode those reads and requests can happen.
- The egress gateway attaches a bound credential to every permitted request to its destination (a credential binding is configuration, not a policy action). In log-only mode, a request the policy would deny, such as a `DELETE` to a bound API, is sent with that credential.
- Box states log-only mode on stderr at startup, next to its filesystem-grant disclosures, and says that policy forbids (including on credentials, cloud metadata and credential-bound destinations) are not enforced.
- Results go to the existing decision telemetry (`records.jsonl`), so a policy tool, a script, or `jq` can count would-be denials.
- The `policy_installed` record carries the run's mode (`enforce` or `log_only`).

## Parity with AgentCore

| AgentCore LOG_ONLY | Box log-only mode (v1) |
|---|---|
| Engine-level `mode = LOG_ONLY`: policies are evaluated, nothing is enforced | `[policy] enforcement = "log_only"`: Dogwood verdicts are evaluated, none is enforced |
| Explicit forbids and default-deny both stop blocking | `Forbidden` and `NoMatch` both flip (KD 5) |
| Decision flips report what would have changed | `verdict = deny` with `enforced = false` (KD 3) |
| Results go to traces and CloudWatch metrics (`LogOnlyMatches`, `LogOnlyDecisionFlips`) | Results go to the decision records; consumers count flips |
| Per-policy `enforcementMode = LOG_ONLY` (one rule logged, the rest enforce) | Not in v1. Per-rule log-only, planned v2 |

Deliberate differences:
- Evaluation faults (`PolicyPending`, `InternalFault`) still deny (KD 5), so a missing or broken policy doesn't fail open.
- Box's built-in floors and the OS sandbox still apply, because they aren't policy.
- Box is local, so there are no metrics; records carry the same signal.

## Key decisions

### KD 1: Box-wide, not per rule
Decision: One switch for the whole box.

Rationale: It matches AgentCore's engine-level LOG_ONLY and keeps the change small. Per-rule log-only (AgentCore's policy-level mode) needs enforced rules and shadow rules evaluated side by side. That's a planned v2 with its own design, because it needs a change in Dogwood's local engine. A Dogwood annotation such as `@enforcement("log_only")` would be a natural fit then, since it keeps the setting inside the policy.

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
- The `box` binary is being replaced by a new Box CLI. A config setting works the same under any CLI, with no new argument and no fifth input.
- A config value lands in the box's stored record, so a run can always show afterwards that it wasn't enforcing.
- A CLI flag is more visible at launch. To cover that, Box states log-only mode on stderr at the start of every run and records it on `policy_installed`, so a box can't quietly stay in log-only mode after a trial.
- `[experimental-features]` doesn't fit, because AgentCore ships LOG_ONLY as a normal feature and builders need to rely on it to promote policies.
- `enforce` and `log_only` map to AgentCore's `ENFORCE` and `LOG_ONLY`, so tools that target both map them one to one.

This changes the shape of the `policy` key and the stored record (`RECORD_VERSION` bump), and it adds a public builder method to the frozen `PolicyEngine` façade. It also goes against four written rules, which this doc approves changing for log-only mode:
- The authored policy is the only decision authority (`docs/design/decisions.md`).
- "An adapter may narrow a verdict and must never manufacture `Allow`", and "Grant only on `Decision::Allow`" (`crates/policy/AGENTS.md`).
- No `PolicyMode` without an entry in `decisions.md` (`crates/policy/AGENTS.md`).
- "There is no approval verdict… never turn a deny into an allow" (`docs/design/decisions.md`).

The implementation adds the matching `decisions.md` entry. Merging this doc is the approval for all of the above.

### KD 3: Records keep the policy's verdict
Decision: `verdict` keeps the policy's answer. A decision Box didn't apply gets a new optional attribute, `strands.box.policy.enforced = false`. The policy's answer needs nothing else, since the record already carries `cause`, `reason` and `determining.ids`. KD 4 adds `first_flip`, and `policy_installed` carries the run's mode.

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
Decision: Log-only mode flips `Forbidden` and `NoMatch` only, so explicit forbids and default-deny both become would-denies, as in AgentCore's LOG_ONLY. `PolicyPending` (the policy bundle isn't installed yet) and `InternalFault` (evaluation failed) still deny. A denial Box can't pair with a request id (a degraded MCP tool) isn't flipped either, because Box can't record a `::response` for it. A per-tool MCP decision pairs with the request id from the `mcp:call` admission it follows.

Rationale: `PolicyPending` and `InternalFault` aren't policy decisions. Letting them through would mean a missing or broken policy fails open. Log-only mode should test a policy, not switch off safety when evaluation breaks.

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
 PolicyEngine::decide_request / refine_tool_call      crates/policy/src/policy.rs
     │  authority.decide(...)  ──►  real Dogwood decision
     │  conclude(...)          ──►  DecisionObserver (observes the real decision)
     │
     │  log-only mode, deny is Forbidden / NoMatch, and it pairs with a request id?
     │     yes ─► return Allow to the caller, marked not enforced
     │     no  ─► return the real decision
     ▼
 reachable-paths floor   (box dir, box.toml, loaded policy)  ── still refuses
     │
     ▼
 enforcement point builds the record (EffectiveDecision) ──► records.jsonl
     │   (policy's verdict + cause + rule ids, enforced = false when not applied)
     ▼
 operation runs ──► ::response recorded in temporal history
```

- Requests reach the engine through `PolicyEngine::decide` (and `decide_grammar_action`), which share `decide_request`, and, for MCP per-tool calls, `PolicyEngine::refine_tool_call`. Both call the authority and then `conclude`. The flip goes after `conclude`, so both paths get it.
- The reachable-paths floor runs after the engine, so it keeps refusing in log-only mode. There's no credential floor under Strands Shell and Monty (`decisions.md`, "No credential floor sits beneath the interpreters"), so the policy is the only protection there.
- In `crates/box/src/record/config/mod.rs`, `ConfigFile.policy` accepts a string or a `{ source, enforcement }` table, `enforcement` is stored in the `Record` (bump `RECORD_VERSION`), and it's passed into the `PolicyEngine` when the box builds it, as a builder option like `.observed_by(...)`.
- Records are built at each enforcement point, not by the observer. `EffectiveDecision` (`crates/box/src/run/telemetry.rs`) gets a "not enforced" state, set in `gate_permit` / `from_policy` when the observed decision is a flippable deny, so the record keeps the policy's verdict, cause and rule ids. Each enforcement point under `crates/box/src/run/` uses it, with a test that checks the whole record (`verdict`, `cause`, `determining.ids`, `enforced`) for a would-deny. `crates/telemetry/src/record.rs` adds the `enforced` and `first_flip` attributes, and the mode on the `policy_installed` record.
- One stderr line is printed at startup, naming the exposure.

## Limitations and not in v1
- Per-rule log-only alongside enforced rules is a planned v2 with its own design (it needs a Dogwood change and release).
- Generating policies is out of scope, since policy-generation tools already do this.
- Decisions after the first flip are approximate (KD 4).
- In log-only mode, the policy doesn't protect you during the trial, so any action the policy would refuse can happen. That includes reading credential files in the operator's home, reaching cloud metadata, sending data out through Strands Shell or Monty, and sending requests the policy would deny to credential-bound destinations with their credentials attached, because the policy is the only protection on those paths. Run trials only where that's acceptable, such as a disposable VM or a host with no credentials you care about.