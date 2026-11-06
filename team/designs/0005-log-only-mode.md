# 0005: Strands Box log-only mode

## Problem
Policy-generation tools can write Dogwood policies for AgentCore and for Strands Box. On AgentCore, a builder can deploy a new policy in LOG_ONLY mode, see what it would block on real traffic, and switch it to enforce when it's ready. Box can't do this.

## Goal
Add a box-wide log-only mode that matches AgentCore's engine-level LOG_ONLY. Box evaluates the policy on every action as if it were enforced, but denials don't block. Box records what would have been denied, so a builder can trial a generated policy before enforcing it.

AgentCore has two LOG_ONLY controls:
- Per-policy `enforcementMode = LOG_ONLY` logs one policy while the rest enforce. Most AgentCore users trial a new rule this way, and policy-generation tools use it.
- Engine-level `mode = LOG_ONLY` enforces nothing.

This doc (v1) covers only the engine-level control. Per-rule log-only is a planned v2 with its own design, because it needs a change in Dogwood's local engine.

## Success criteria
- For the same workload and policy, the actions marked would-deny in log-only mode match the actions denied in enforce mode, up to the run's first flip.
- In log-only mode, would-deny actions complete, and the exit code and outputs match a permit-all run.
- The OS sandbox, the reachable-paths floor, credential isolation and private-state protection behave the same in both modes.
- Without the setting, Box enforces and existing configs behave as today.
- Box states log-only mode and what it exposes on stderr at startup.
- Every not-enforced decision is marked in telemetry.
- Every run's `policy_installed` record states its mode.
- A tool or script can list the would-deny actions from a log-only run of a generated policy.

## Proposed behavior
- A setting in `box.toml` turns log-only mode on for the whole box. It's off by default.
- An action the policy would deny goes ahead. Its record keeps the policy's verdict and rule ids and is marked not enforced.
- Only Dogwood verdicts are relaxed. The OS sandbox, the reachable-paths floor, credential isolation (the agent never holds a secret) and Box's private state don't change.
- Results go to the existing decision records (`records.jsonl`), and the `policy_installed` record carries the mode (`enforce` or `log_only`).

### What log-only mode exposes
- On the Strands Shell and Monty path, the policy is the only protection for the operator's home directory, credential files and cloud metadata. There's no credential floor under the interpreters (`decisions.md`). In log-only mode, those reads and requests can happen, and data can be sent out.
- The egress gateway attaches a bound credential to every permitted request to its destination, because a credential binding is configuration, not a policy action. In log-only mode, a request the policy would deny, such as a `DELETE` to a bound API, goes out with that credential.
- Box prints this on stderr at startup, next to its filesystem-grant disclosures.
- Run trials only where that's acceptable, such as a disposable VM or a host with no credentials you care about.

## Parity with AgentCore

| AgentCore LOG_ONLY | Box log-only mode (v1) |
|---|---|
| Engine-level `mode = LOG_ONLY`: policies are evaluated, nothing is enforced | `[policy] enforcement = "log_only"`: Dogwood verdicts are evaluated, none is enforced |
| Explicit forbids and default-deny both stop blocking | `Forbidden` and `NoMatch` both flip (KD 5) |
| Decision flips report what would have changed | `verdict = deny` with `enforced = false` (KD 3) |
| Results go to traces and CloudWatch metrics (`LogOnlyMatches`, `LogOnlyDecisionFlips`) | Results go to the decision records, and consumers count flips |
| Per-policy `enforcementMode = LOG_ONLY` (one rule logged, the rest enforce) | Not in v1. Per-rule log-only is planned for v2 |

Deliberate differences:
- Evaluation faults (`PolicyPending`, `InternalFault`) and degraded MCP tools still deny (KD 5), so a missing or broken policy doesn't fail open.
- Box's built-in floors and the OS sandbox still apply, because they aren't policy.
- Box is local, so there are no metrics. The records carry the same signal.

## Key decisions

### KD 1: Box-wide, not per rule
Decision: One switch for the whole box.

Rationale: It matches AgentCore's engine-level LOG_ONLY and keeps the change small. Per-rule log-only needs enforced and shadow rules evaluated side by side, which needs a Dogwood change (v2). A Dogwood annotation such as `@enforcement("log_only")` could carry the setting then.

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

Both forms work:
- `policy = "policy.dw"` means this file, enforced, so existing configs don't change.
- The `[policy]` table takes `source` (required) and `enforcement` (optional, default `enforce`).
- A config uses one form. A missing `source`, an unknown `enforcement` value or an unknown field is refused, like any other bad key.

Rationale:
- Log-only mode changes how the policy is applied, so it belongs next to the policy file, and `box.toml` keeps its nine keys.
- Whatever prepares the box can write the config. A CLI flag only reaches whoever runs the box.
- The `box` binary is being replaced by a new Box CLI, and a config setting works the same under any CLI.
- The value is saved in the box's stored record, so a run can show later that it wasn't enforcing.
- A flag is more visible at launch. The stderr line and the `policy_installed` mode cover that.
- `[experimental-features]` doesn't fit, because AgentCore ships LOG_ONLY as a normal feature.
- `enforce` and `log_only` map one to one to AgentCore's `ENFORCE` and `LOG_ONLY`.

This changes the `policy` key and the stored record (bump `RECORD_VERSION`), and adds a public builder method to the frozen `PolicyEngine` façade. It also changes four written rules for log-only mode:
- The authored policy is the only decision authority (`docs/design/decisions.md`).
- "An adapter may narrow a verdict and must never manufacture `Allow`", and "Grant only on `Decision::Allow`" (`crates/policy/AGENTS.md`).
- No `PolicyMode` without an entry in `decisions.md` (`crates/policy/AGENTS.md`).
- "There is no approval verdict… never turn a deny into an allow" (`docs/design/decisions.md`).

The implementation adds the `decisions.md` entry. Merging this doc approves these changes.

### KD 3: Records keep the policy's verdict
Decision: `verdict` keeps the policy's answer. A decision Box didn't apply gets `strands.box.policy.enforced = false`. The record already has `cause`, `reason` and `determining.ids`, so nothing else is needed.

A would-deny in log-only mode records `verdict = deny` and `enforced = false`. That pair is a flip: an action that will be blocked once enforcement is on. Permits, and denials that still block (the floors and KD 5), have no `enforced` field.

Example: the agent writes `README.md`, and the policy doesn't allow it.

| Field | Enforce | Log-only mode |
|---|---|---|
| `verdict` | `deny` | `deny` |
| `enforced` | none | `false` |
| `cause`, `determining.ids` | the policy's | the policy's |

The `policy_installed` record states the run's mode once. Without it, a clean log-only run would look like an enforcing one, and a clean run is the signal that a policy is safe to enforce.

Rationale: `verdict == "deny"` should find every would-deny. Putting `enforced` on each decision keeps real blocks apart from would-denies. The telemetry docs say records are the effective decision, so that wording changes. Tools that alarm on every `deny` should filter on `enforced`.

### KD 4: History records what really happened
Decision: An action allowed only because of log-only mode records `::request` and `::response` with its real output, not `::error`.

Box keeps a history so rules can depend on the past, like "allow `git push` only if `npm test` passed". `::error` means the action didn't happen, but in log-only mode it did.

Example: the policy forbids `rm`. In enforce mode, `rm notes.txt` is blocked and the agent tries something else. In log-only mode, `rm` runs (the first flip), the file is gone, and the agent takes a different path. Everything up to and including the first flip matches enforce mode. After that it's an approximation.

Rationale: Later temporal rules need real history. AgentCore evaluates real traffic the same way.

Trade-off: After the first flip, the run drifts from enforce mode. Box marks that decision with `strands.box.policy.first_flip = true`, so tools can tell exact results from approximate ones.

### KD 5: Only policy denials flip
Decision: Only `Forbidden` and `NoMatch` flip, so explicit forbids and default-deny both become would-denies, as in AgentCore. These still deny:
- `PolicyPending` (the policy isn't installed yet) and `InternalFault` (evaluation failed).
- A denial with no request id, because Box can't record a `::response` for it. A per-tool MCP decision uses the request id of the `mcp:call` admission before it.
- A degraded MCP tool (its argument schema will never stage). Box reports it as `NoMatch`, and it has a request id on the per-tool path, so the flip checks for it by name.

Rationale: None of these is a policy decision. Flipping them would make a missing or broken policy fail open.

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
     │  log-only mode, deny is Forbidden / NoMatch, not a degraded tool,
     │  and it pairs with a request id?
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

- Requests reach the engine through `PolicyEngine::decide` and `decide_grammar_action`, which share `decide_request`, and through `PolicyEngine::refine_tool_call` for MCP per-tool calls. Both paths call the authority and then `conclude`, and the flip goes after `conclude`.
- The reachable-paths floor runs after the engine, so it still refuses.
- In `crates/box/src/record/config/mod.rs`, `ConfigFile.policy` accepts a string or a `{ source, enforcement }` table. `enforcement` is stored in the `Record` (bump `RECORD_VERSION`) and passed to the `PolicyEngine` builder, like `.observed_by(...)`.
- Each enforcement point under `crates/box/src/run/` builds its own record. `EffectiveDecision` (`crates/box/src/run/telemetry.rs`) gets a not-enforced state, set in `gate_permit` / `from_policy` when the observed decision is a flippable deny. Each enforcement point gets a test that checks the whole record (`verdict`, `cause`, `determining.ids`, `enforced`) for a would-deny.
- Some actions are checked in several legs: a Strands Shell symlink or rename (`FilesystemPair` in `crates/policy/src/adapters/shell.rs`: source `fs:write` and `fs:read`, then destination `fs:delete` and `fs:write`), a Monty rename (`perform_rename` in `python/effects.rs`), and a rename onto a bound destination. Today the first denial stops the attempt, so the record comes from the last observation (`ObservationCapture::last()`). In log-only mode a flipped leg doesn't stop the rest, so the record comes from the first flippable deny among the attempt's observations. Test: a symlink to a read-forbidden path records the read leg's rule ids with `verdict = deny`, `enforced = false` and `first_flip = true`.
- An MCP `tools/call` passes the coarse `mcp:call` gate and then the per-tool gate (`refine_tool_call`). The remote path checks `http:request` first (`mcp_gates` in `crates/policy/src/adapters/egress.rs`). Today the stdio path (`crates/box/src/run/broker/mcp/admission.rs`) and the remote path (`remote_mcp_decision` in `telemetry.rs`) record one gate, because the first deny stops the call. In log-only mode a flipped gate lets the next one run, and the record would show the later permit. The same first-flippable-deny rule applies. Tests: a coarse `forbid` with a per-tool `permit` records the coarse rule with `verdict = deny`, `enforced = false` and `first_flip = true` on both paths, and a degraded tool still refuses.
- `crates/telemetry/src/record.rs` adds `enforced`, `first_flip` and the `policy_installed` mode.
- Box prints one stderr line at startup naming the exposure.

## Limitations and not in v1
- Per-rule log-only is a planned v2 (it needs a Dogwood change and release).
- Generating policies is out of scope, since policy-generation tools already do it.
- Decisions after the first flip are approximate (KD 4).
- The policy doesn't protect the host during a trial (see "What log-only mode exposes").