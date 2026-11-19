<a id="tenets-unless-you-know-better-ones"></a>
# Tenets

These tenets state how Box should protect an agent workload. They are open to revision when a
better principle is proposed. When tenets conflict, the one listed first takes priority.

1. **Assume the agent is compromised.** Enforcement fails closed and runs beyond the agent's reach.
   Controls inside the boundary provide additional restrictions but cannot establish the boundary
   themselves. No single mechanism is foolproof. Every prior system we studied failed open or trusted
   the code that connected its parts.

2. **The agent never holds the secret.** Box adds credentials at the boundary and scopes them to the
   destination. Authorization checks who sends the request as well as where it goes. An allowed
   endpoint can still receive private data if anything in the sandbox can use it.

3. **Secure by default, workable by default.** A developer can use their chosen framework with an
   agent that is contained from startup and can still do its job. Major frameworks work without
   adaptation. Convenience never justifies a default that fails open.

4. **Record each decision and its reason.** Every allow and deny must be reconstructable, including
   the request, its caller, and the reason. State the limits of the records. Traffic that Box does not
   terminate has connection-level records. Telemetry must not expose credentials inside the boundary.

5. **Keep definitions portable and state platform guarantees.** The same agent definition runs on a
   laptop, in a container, and inside a MicroVM, using open standards and multiple protocols. Use each
   platform's strongest available protection. Disclose platform differences and refuse to run with
   silently reduced protection.

6. **Support replaceable backends and a fixed policy engine.** Backends report their capabilities
   accurately. The policy engine is part of the trusted code and cannot be replaced.

7. **Treat performance as a constraint.** Security adds protection without preventing the agent from
   doing its job. Enforcement stays local to limit latency and external dependencies.

---

## Non-goals

- **Cross-tenant isolation.** The box protects one operator's agent workload. The hosting platform,
  such as Nitro/KVM, isolates tenants. Multi-agent controls within one workload, such as sub-agent
  delegation and attenuation, are in scope.
- **Enterprise zero-trust network products.** Box is not a network mesh. Binding each request to its
  source at the box boundary, as required by tenet 2, is in scope.
- **Kernel-exploit resistance.** A kernel escape defeats operating system enforcement. The platform's
  isolation provides mitigation for this accepted risk. Box does not.

---

<a id="performance-constraints-targets-to-measure-against"></a>
## Performance constraints

These are targets for measurement.

| Dimension | Target |
|-----------|--------|
| Policy enforcement | < 1 ms per decision, locally with no network hop. This target is asserted but not yet benchmarked. |
| Sandbox startup | < 50 ms cold start for macOS/Linux process sandboxes. The MicroVM tier is ~125 ms. We accept the longer startup for stronger isolation from a full virtual machine. |
| Memory overhead | < 20 MB resident for the box's trusted process |
