# Example policies

Copy-from `policy.dw` fragments, one recurring shape each. Each is grounded in the
in-repo sources: `crates/policy/README.md` and the policy tests. Combine the fragments into one `policy.dw` for a real box; the box is
deny-by-default, so a policy only ever adds reachability.

| File | Shape |
|---|---|
| `agent-anthropic.dw` | An agent reaching the Anthropic API, with read and write on the project directory. |
| `agent-openai.dw` | An agent reaching the OpenAI API, with read and write on the project directory. |
| `agent-bedrock.dw` | An agent reaching Amazon Bedrock, with read and write on the project directory. |
| `forbid-delete.dw` | Refuse every delete, whatever a permit says. |
| `temporal-write-budget.dw` | A `forbid` with a `when temporal { … }` count keyed on `::response`, which caps writes beside any permit. |
| `shell-guard.dw` | Permit commands, then `forbid` one dangerous line with a `has`-guarded argument read. |

The three agent examples share a shape: two egress legs to the API host, a `shell:exec`
permit, and two-clause read and write on the project directory. They differ only in the
API host. Replace `~/project` with the box's project path, and pair them with
`forbid-delete.dw`, `shell-guard.dw`, or `temporal-write-budget.dw` to harden them.

Validate by loading. There is no standalone validator: the box validates the policy at
load, fail-closed, so `strands-box run` re-reads `policy.dw` every time. Edit a rule and
run again.
