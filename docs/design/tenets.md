# Tenets (unless you know better ones)

*In priority order: when tenets conflict, higher wins.*

1. **Assume the agent is compromised.** Enforcement fails closed and sits beyond the agent's reach; controls inside the boundary are floors, not walls. Defense in depth: no single mechanism is assumed foolproof, and every prior-art system we studied broke by failing open or by trusting its own glue.

2. **The agent never holds the secret.** Credentials are injected at the boundary and scoped to the destination; requests are authorized by who is asking, not just where they're going. An allowlisted endpoint is still an exfiltration channel if anything in the sandbox can use it.

3. **Secure by default, workable by default.** A developer brings the framework of their choice and gets an agent that is contained out of the box and still does its job; major frameworks work without adaptation. We never buy convenience with fail-open defaults.

4. **Log the decision, not just the event.** Every allow and deny is reconstructable: what was asked, by whom, and why it was decided that way. We are honest about limits: traffic we don't terminate is logged at connection level, and telemetry never becomes a credential hole inside the boundary.

5. **Portable in definition, honest in guarantees.** The same agent definition runs on a laptop, in a container, and inside a MicroVM, over open standards and multiple protocols. Each platform gets its highest security posture, never the lowest common denominator; we surface the per-platform differences and refuse to run silently degraded.

6. **Extensible at the edges, fixed at the core.** Backends are pluggable behind honest capability reporting; the policy engine is part of the trusted core and is never swappable.

7. **Performance is a constraint, not an afterthought.** Security is additive, never the reason an agent fails to do its job. Enforcement stays local, minimizing latency and external dependencies.

---

## Non-goals

- **Cross-tenant isolation.** The box secures a single operator's agent workload; isolating tenants from each other is the hosting platform's job (Nitro/KVM). Multi-agent controls within one workload, such as sub-agent delegation and attenuation, are in scope.
- **Enterprise zero-trust network products.** We are not building a network mesh. Per-request provenance binding at the box boundary (tenet 2) is in scope.
- **Kernel-exploit resistance.** A kernel escape defeats operating system enforcement; that residual risk is accepted and mitigated by the platform's isolation tier, not the box.

---

## Performance constraints (targets to measure against)

| Dimension | Target |
|-----------|--------|
| Policy enforcement | < 1 ms per decision (local, no network hop); asserted, not yet benchmarked |
| Sandbox startup | < 50 ms cold start on macOS/Linux process-sandbox tier; the MicroVM tier is ~125 ms (accepted: a full-VM boundary trades startup for stronger isolation) |
| Memory overhead | < 20 MB resident for the box's trusted process |

