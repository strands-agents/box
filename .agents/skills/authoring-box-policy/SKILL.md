---
name: authoring-box-policy
description: Author or edit a Strands Box policy (`policy.dw`) — turn an operator's natural-language allow/deny intent into a validated Dogwood policy over the box's fixed action vocabulary, including `when temporal { … }` history rules. Use when writing, editing, reviewing, or converting an intent into a box policy. This skill CREATES or EDITS a policy against the box's built-in schema — you never author a Dogwood schema, because the box ships a fixed one.
---

# Authoring a Strands Box policy (Dogwood)

Your job: turn a natural-language authorization intent into a **Dogwood `policy.dw`** for a Strands
Box that loads clean and means what the operator actually intended. This is a *formalization* task
— the hard part is not the syntax (that is documented; see [Ground truth](#the-ground-truth-read-before-authoring))
but **pinning down ambiguous intent** and mapping it onto the right construct over the box's fixed
vocabulary.

**This is an interactive session, not a one-shot generator.** You work with the operator: draw out
the intent, ask a sharp question rather than guess when a requirement is underspecified, propose
rules, and confirm what stays refused. Do **not** return a policy you have not loaded.

**You author rules, not a schema.** A generic Dogwood deployment makes the operator author an action
schema and a service schema. Strands Box does not — the box ships a fixed, built-in schema, so the
vocabulary of actions, the one principal, and the context shape are already set. You write the
`permit` and `forbid` rules against that schema — [the fixed vocabulary](#the-fixed-vocabulary) is
below.

Follow the loop in order:

1. **Disambiguate** the intent (resolve every gap that changes the output).
2. **Formalize** it into `policy.dw`.
3. **Validate** by loading it into the box — fail-closed, mandatory (see
   [Step 3](#step-3--validate-by-loading-mandatory--never-skip)). An unloaded policy is not a
   finished answer.
4. **Round-trip** the intent and present the result.

## The ground truth (read before authoring)

Treat these as authoritative; do not invent syntax, an action, or a field from memory. If a
construct is not in these sources, it does not exist.

**Box-specific — the vocabulary and the floors:**

- **[The fixed vocabulary](#the-fixed-vocabulary)** below — the one principal, the fixed resource,
  every action and its context, and the temporal event shape. The source of truth for the box.
- **The built-in schema** you author against, read but never edit. Generate it in the workspace
  with `box policy generate-schema`, which writes `.strands-box/actions.cedarschema` (actions and
  their context) and `.strands-box/events.dwschema` (what a `when temporal { … }` rule observes).
  The generated files also carry each declared MCP server's per-tool actions, which a static copy
  cannot.
- **The bundled `examples/`** — whole agent policies and single-shape refinements to copy from. See
  `examples/README.md`.
- **The decisions** behind the vocabulary, in [`docs/design/decisions.md`](../../../docs/design/decisions.md): the
  [closed action vocabulary](../../../docs/design/decisions.md#the-action-vocabulary-is-closed-and-strict-validated-at-load),
  the [filesystem actions](../../../docs/design/decisions.md#filesystem-authorization-uses-four-verbs-and-a-catch-all),
  [temporal rules](../../../docs/design/decisions.md#temporal-rules-are-enforced-against-recorded-history), and
  [a credential binding is not an authorization](../../../docs/design/decisions.md#a-credential-binding-is-configuration-not-a-policy-action).

**Language grammar — bundled in this skill's `references/`:**

- **`references/dogwood-policy-language.md`** — core policy syntax: `permit`/`forbid`, the
  `(principal, action, resource)` scope, `when`/`unless`, and the full Cedar expression language
  (operators, literals, methods, `has`/`like`/`is`, sets/records). See its "Condition expression
  language" and "What parses but is rejected" sections.
- **`references/dogwood-temporal-expressions.md`** — the `temporal { … }` sublanguage:
  `formerly`/`previous`/`since`, windows, `exists`/`tp`, `count`/`sum`, and the **acceptance rules**.
  Read "Writing temporal expressions that are accepted" in full before writing any history rule.

## The fixed vocabulary

Every request is `(principal, action, resource, context)`. The principal is always
`Box::Agent::"self"` (leave it a bare `principal`) and the resource is always
`Box::Resource::"unused"`, so **the action scopes a rule** and every readable field rides
`context.input`. There is no `context.system`, no `context.principal`, and no `now`; the only field
outside `input` is `output`, on a `::response`, read only by a temporal rule: `output.result` on a
filesystem response, `output.status` on an `http:request` response, and the exit `output.status` on a
`shell:exec` or `shell:spawn` response.

The actions are a closed set. A policy names one; it cannot add one. The last column is the exact
`context.input` fields you scope on.

| Action | `context.input` fields |
|---|---|
| `fs:read` / `fs:write` / `fs:delete` / `fs:move` / `fs:other` | `path: String`, `operation: Fs<Kind>Operation` |
| `net:connect` | `host: String`, `ip?: ipaddr`, `port: Long` |
| `http:request` | `host`, `port`, `method`, `path` (a **URL** path), `body_bytes: Long`, `intercepted: Bool`; the reply's `status: Long` is on `output`, matched as `::response{ output.status: 500 }` in a temporal predicate |
| `shell:exec` | `command`, `program`, `arg1?`, `arg2?`, `arg_count: Long`, `cwd`; the exit `status: Long` is on `output`, matched as `::response{ output.status: 0 }` in a temporal predicate (a signal reports 128 plus its number, a permitted binary that cannot start reports 126, a command with no reported status reports -1, and a background `&` command records its status when it ends) |
| `shell:spawn` | the `shell:exec` fields plus `program_path: String`, and the same `output.status`. The workload can set a `shell:exec` status (a shell function of the same name does it), so a precondition on a host binary's success reads `shell:spawn` and pins `program_path` |
| `mcp:call` | `server`, `method`, `tool?`, `prompt?`, `uri?` |
| `<server>::Action::"<tool>"` | per-tool, emitted by `box policy generate-schema` |

**Filesystem `operation` enums** (narrow within an `fs:` action):
`FsReadOperation` = `read_content`, `read_metadata`, `enumerate`, `read_link`, `change_dir`, `exec`;
`FsWriteOperation` = `write_content`, `create_dir`, `set_permissions`, `symlink`;
`FsDeleteOperation` = `remove_file`, `remove_dir`; `FsMoveOperation` = `rename`;
`FsOtherOperation` = `other`.

**Rules that bite:**

- No action groups — `fs:read` does not cover `fs:write`; cover a family one clause per action.
- One outbound host is two decisions — `net:connect` (port, before TLS) **and** `http:request`
  (host, after TLS).
- Guard an optional field with `has` (`arg1`, `arg2`, `tool`, `prompt`, `uri`, `ip`); an unguarded
  read is a load error.
- `path` is a filesystem path on `fs:*` and a URL path on `http:request`; only `fs:*` carries
  `operation`, so guard a filesystem rule with `context.input has operation`.
- Write a shell rule on `program` (what the first word resolved to), not `command`. Do not read `ip`
  in a temporal predicate — it faults.
- `tool:invoke`, `model:invoke`, `agent:invoke`, and `cred:inject` are removed — naming one is an
  `UnknownAction` load error.

**Temporal event shape.** For action `A`: a `A::request` (its `input` fields), a `A::response` (its
`input` **and** `output` fields, only for an effect that happened), and a `A::error`. Key a
precondition on `::response`; a window is mandatory and capped at 24h; there is no `||`.

For the rationale behind the vocabulary, read the `## Policy` section of
[`docs/design/decisions.md`](../../../docs/design/decisions.md).

## The floors you cannot change

A policy only ever **adds** reachability. Some things hold whatever a rule says:

- **Deny-by-default, deny-overrides.** No permit means deny, and a `forbid` always beats a `permit`.
  An exception to a broad allow is a `forbid` that carves a hole, never a narrower permit.
- **The reach floor** refuses every path inside a `.strands-box` directory and every write to the
  `box.toml` and policy this run loaded, beneath policy, in every box. No rule widens it.
- **The SSRF / cloud-metadata floor** sits below the engine. A rule can deny more, never re-open it.
- **A credential binding is not an authorization**
  ([decisions](../../../docs/design/decisions.md#a-credential-binding-is-configuration-not-a-policy-action)). An `[egress.*]` entry in `box.toml` says
  only what is *attached* to a request the policy already permitted. It never makes a destination
  reachable — reachability is this policy's decision alone. The two must name the same host.
- **Information providers are not available.** A `Provider::Name(args)` call or a `guardrails { … }`
  clause aborts box startup. Do not reach for a computed fact — there is no provider path in the box.

## Step 1 — Disambiguate intent (do this first)

A prose intent almost always leaves gaps that change the formal policy. Resolve every gap that
affects the output. If you can infer the answer from an obvious convention, state your assumption and
proceed; otherwise ask. Prefer a few sharp, batched questions over silently guessing.

**Every policy needs egress to an LLM provider.** The agent cannot run without reaching a model, so
a policy that grants no provider access does not work — confirm which one (Amazon Bedrock, OpenAI, or
Anthropic) and write its two egress legs (`net:connect` **and** `http:request`) before anything else.
Match the provider to the box's configured endpoint. See the three agent examples in `examples/`.

1. **Effect and default.** Granting (`permit`) or restricting (`forbid`)? The box is default-deny
   with deny-overrides. "The agent may X" → a `permit`. "Never X" / "block X when Y" → a `forbid`
   that carves a hole out of the permits.
2. **Which action(s)?** The principal and resource are fixed, so **the action is what scopes a
   rule.** Map the operator's nouns to concrete actions from the table above. Remember: no groups
   (one clause per `fs:` verb), and two legs for one outbound host (`net:connect` **and**
   `http:request`).
3. **Where does each fact live?** Every fact rides `context.input.<field>` — confirm the field name
   and type against the table. There is no principal/resource attribute to read (both are fixed), no
   `context.system`, and no provider for a computed fact. A fact about the **past** goes to the
   temporal sublanguage (Step 2b).
4. **Path and host scope.** For a filesystem rule, get the exact path and whether it is one file or a
   subtree — a subtree needs two clauses (the directory and its contents; see Common shapes). Prefer
   `~`-relative paths so the file is portable. For a host, get the exact hostname and port.
5. **Temporal specifics** (if history is involved) — the highest-value disambiguations:
   - **"happened at least once recently"** → `formerly within W`.
   - **"the immediately preceding event"** → `previous within W`.
   - **"has held continuously since an anchor"** → `left since within W right`;
     **"has NOT happened since"** → a negated `since` left (there is no dedicated operator).
   - **The window `W` is mandatory** (`s`/`m`/`h`/`d`; no week/month/year) and **capped at 24h** in
     the box. If the operator says "recently" without a number, ask — there is no default, and you
     cannot raise the cap (the event schema is fixed).
   - **"the same X"** → pin the past predicate's field to the current request:
     `input.path: context.input.path`. With one principal, principal-correlation is automatic;
     correlate anything else (same path, same host) explicitly, or "the same X" silently becomes
     "any X".
   - **Counting/summing** → `count`/`sum` (no `min`/`max`/`avg`). Confirm the threshold and operator.
   - **Key on `::response`, never `::request`.** A `::request` event exists even for a denied
     attempt, so a step-up keyed on `::request` is defeated by asking and being refused. A
     `::response` exists only for an effect that happened.
6. **Edge cases the prose glosses over.** An absent optional field (`has` guard)? Inclusive boundary
   (windows are closed)? Surface these and pick a defensible default, stating it.

Tie each question to how it changes the policy — *"'recent' — within what window (e.g. `1h`)? And
the same host the agent reached, or any host?"* — not a vague "can you clarify?".

## Step 2 — Formalize

### 2a. Core (single-request) rules

Map the disambiguated intent onto the rule shape (doc comment, `@id`, `@description` on a `forbid`,
effect, scope, `when`/`unless`, `;`). Lead each rule with a `//` comment in the operator's words and
an `@id("…")`. Keep the scope as the coarse filter (the action) and put fine logic in `when`/`unless`.

**Give every `forbid` a `@description("…")` that the agent can act on.** The box prints every
`@description` on a determining `forbid` into the denial message that the agent sees, so the string
is how the policy *talks to the agent* about why a request was refused. Say what is refused and what
the agent should do instead — a sentence the agent can read and take a different action from, not an
internal note. A `@description` on a `permit` is ignored, so put the author's reason there in a
leading `//` comment instead.

```text
// Refuse setting permissions anywhere, whatever a write permit allows.
@id("no_chmod")
@description("This workload cannot change file permissions. Make the file writable before the box starts, or ask the operator to add a chmod rule.")
forbid ( principal, action == Box::Action::"fs:write", resource )
when { context.input.operation == Box::FsWriteOperation::"set_permissions" };
```

Use the operator/method vocabulary from `references/dogwood-policy-language.md`. Watch the type rules
it calls out: decimals are equality-only, `/` and `%` are unsupported, and there is no `let … in`.

### 2b. History-dependent rules (`temporal { … }`)

Attach `when temporal { … }` (or `unless temporal { … }` for absence) and build the body from
predicates and the `formerly`/`previous`/`since` operators. Every field a predicate reads is derived
from the action's `input` record.

```text
// Refuse a write once six writes have completed in the last 60 seconds.
@id("write_budget")
forbid ( principal, action == Box::Action::"fs:write", resource )
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
            )
        )) == total
        && total >= 6
    )
};
```

**A cap is a `forbid`.** A permit only adds permission, so a permit cannot narrow another permit:
`permit … when temporal { total < 6 }` beside a broader `fs:write` permit caps nothing, and the box
refuses that shape at load. Write the budget as a `forbid` that fires at or above the cap. The permit
shape is correct only when it is the sole permit for that action; then write that reason in a
comment above the rule.

The sublanguage has strict acceptance rules — closedness, range restriction, conjunct order,
aggregates as operands, tp-dependence — and a plausible-looking rule is routinely *rejected*. **Read
"Writing temporal expressions that are accepted" in `references/dogwood-temporal-expressions.md`
before you write one**, and copy the budget shape above from `examples/temporal-write-budget.dw`.
There is **no `||`** — "A or B" is two rules.

### 2c. Computed facts

Not available. The box aborts startup on an information provider or a `guardrails` clause. If the
intent needs a computed fact (a regex denylist, a risk score), it cannot be expressed as box policy —
say so rather than reach for a provider.

## Step 3 — Validate by loading (MANDATORY — never skip)

**Every policy MUST load into the box before you present it.** There is **no standalone validator, no
`dogwood` CLI in this repository, and no `validate` verb** on the box. The box validates the policy
**at load, fail-closed**: an unknown action or a mistyped attribute aborts startup with a load error,
so an unloaded policy is a guess.

`strands-box run` re-reads `box.toml` and `policy.dw` every time, so the whole loop is: edit a rule,
run again, read the result.

- A load error names the parse, schema, or unknown-action fault. Fix it and re-run.
- A denied action at runtime returns a refusal that names the component, the reason, and the rule
  that decided ([decisions](../../../docs/design/decisions.md#a-denial-names-the-rule-that-refused-it)).

**How to test the policy you just wrote.** Use the existing
[Strands getting-started guide](../../../docs/user/getting-started.md) for a complete configuration.
From a project with `.strands-box/box.toml` and `.strands-box/policy.dw`, run its configured agent:

```sh
strands-box run --config .strands-box/box.toml
```

Ask the agent to perform one permitted action and one forbidden action. Inspect the decision log
for the expected rules. Edit the policy and run the same configuration again.

A load proves the policy is *legal*, not that a temporal rule *means what you intended* — the box has
no replay or trace tool. For a history rule, reason carefully against the acceptance rules and, where
you can, exercise the box to see the effect deny as expected.

**A runtime denial is often a `box.toml` problem, not a policy bug — read `box.toml` before you
touch the policy.** The policy decides only *reachability*; `box.toml` decides which endpoint the
agent calls, what environment it runs in, and which credential is attached. When a run is refused,
check `box.toml` for these before editing a rule:

- **The agent is pointed at the wrong host.** A denial for a host your policy never granted usually
  means the harness is calling a different endpoint. Check the agent's model configuration and
  `AWS_REGION` against the destination in `box.toml` and the host in the policy.
- **The environment is composed, never inherited.** A variable exported in your shell does not reach
  the workload. Set `AWS_REGION` and other workload variables in `box.toml`'s `[agent.env]` table.
  Box reserves its proxy routing, certificate, and identity variables.
- **The credential is not attached.** A permitted host still needs a credential wired through an
  `[egress.<name>]` entry naming a reference (`env://VAR`, `aws://<profile>`), never a literal. A
  binding is not an authorization — it and the policy must name the same host.

So a 403 or a refused host is frequently the policy working correctly over a `box.toml` that points
the agent, its environment, or its credential somewhere the policy does not grant.

## Step 4 — Intent round-trip and output

Only after the policy loads, do a final intent check and present the result. Re-read the policy back
into English and confirm the effect (permit vs forbid), the correlation pins ("same" vs "any"), the
window, and inclusive boundaries.

Return, in this order:

1. A one-line restatement of the intent as you understood it.
2. The assumptions you made (paths, windows, correlations, defaults), called out explicitly.
3. **Load status** — state plainly that the box loaded the policy, or the load error and your fix.
4. The `policy.dw` rules, each with a `//` comment, an `@id`, and (on every `forbid`) a
   `@description` the agent can act on.
5. A short plain-English gloss of each rule, and **what stays refused**.

Keep the policy minimal and idiomatic — match the bundled `examples/`. Do not add rules the operator
did not ask for.

## Common shapes

Point the operator at the bundled `examples/`; these are the patterns that recur.

- **Reach exactly one host.** Two rules — the L4 connect scoped to the port, the L7 request scoped to
  the host. See `examples/agent-anthropic.dw`.
- **Read or write a project subtree.** Two clauses per verb, because a prefix is not a directory:
  `context.input.path == "~/project"` **or** `context.input.path like "~/project/*"`. A bare prefix
  also matches a sibling whose name merely starts the same way.
- **Refuse an action a broad permit would allow.** A `forbid` on the exact action. See
  `examples/forbid-delete.dw`.
- **Guard a shell command.** A `forbid` on `shell:exec` with a `has`-guarded argument read. See
  `examples/shell-guard.dw`.
- **Bound a rate or a budget.** A `forbid` with a `when temporal { … }` count over one action, keyed
  on `::response`, that fires at or above the cap. A permit cannot narrow another permit, so a cap is
  a `forbid`. See `examples/temporal-write-budget.dw`.

## Do not

- Do not author a schema, an event schema, or an information provider. The box ships the schema and
  forbids providers.
- Do not invent an action, an operator, or a context field. Use only what the fixed vocabulary, the
  bundled reference, and the examples show.
- Do not rely on an `[egress.*]` binding to make a host reachable — write the `net:connect` and
  `http:request` rules.
- Do not try to re-open a floor, or expect a permit to beat a `forbid`.
- Do not key a temporal step-up on `::request`, and do not read `ip` in a temporal predicate.
- Do not write a budget as a `permit` beside another permit for the same action; the box refuses it
  at load, because the permit cannot narrow the other one.
- Do not present a policy you have not loaded into the box.
- Do not ship a `forbid` without a `@description`. The agent reads that string on a denial, so an
  absent one leaves it to retry the same request.
