# Terminology

Use the terms in the first column. Do not use the alternatives in the second. Before adding a term,
check whether an existing definition describes what you mean.

## Terms

| Term | Do not use | Definition |
| --- | --- | --- |
| **box** | cage, container, jail, untrusted compute box, containment boundary | The complete boundary Box builds for a workload, and the isolated set of resources inside it. A box is its sandboxes and the box's trusted process: the agent's sandbox, the sandbox for each tool or local MCP server, and the box's trusted process, which runs outside every sandbox. **Use "box" for the complete boundary. Use "workload" for the processes running inside it.** |
| **sandbox** | None | The operating system boundary that restricts a process's access to resources. **Use "sandbox" for this mechanism, not as a synonym for Box's complete protection.** |
| **separate sandbox** | leaf box, child box, sub-box, nested box, sidecar | The sandbox Box starts for one operator-declared program, either a host binary admitted by a `shell:spawn` permit or a `stdio` MCP server. It is contained, and it is wider than the agent's sandbox. **Name the owner as "a tool's sandbox", "a local MCP server's sandbox", or "its own sandbox". Use "separate sandbox" only when comparing it with the agent's sandbox.** |
| **workload** | None | The processes a box runs. One box runs one workload. **Say "workload" when you mean the processes, even when that workload is an agent.** |
| **agent** | None | A workload that runs model output. **An agent is a kind of workload, not a synonym for one.** Say "agent" only when running model output is the point. |
| **harness** | None | The product that supplies and drives an agent, such as the Strands CLI. **Keep the harness distinct from the agent and the workload.** |
| **the box's trusted process** | Box process, trusted Box process, trusted host, TCB, trusted computing base, trusted side, trusted half | Our code that runs outside every sandbox on the same machine. It holds the policy, it answers the box's requests, and it is the box's only route to the network. **A box has three parts: the agent's sandbox, the box's trusted process, and the sandbox for each tool or local MCP server. Fit the words to the sentence: "the trusted process", "its trusted process", and "the box's own trusted process" are all fine. Use "TCB" only when you quote a requirement that already does.** |
| **supervisor** | orchestrator | The role that starts the box's process, owns its terminal and its exit code, and reaps it. **Keep this role distinct from the box's trusted process.** One process currently performs both roles, but the requirements distinguish them. |
| **surrounding OS** | the host, the machine, the developer's machine | The operating system the box runs under. **Use this rather than "the host"**, which is ambiguous between this machine and a remote one. "Host OS" is fine in "host binary", "the host OS's shell", and "the host OS's Python", where it marks the operator's own program as opposed to the box's. |
| **the host OS's shell** | the shell alone for this program | The operator's own shell, which runs `box run`. Box looks up a host binary on its `PATH`. **Say "the host OS's shell" whenever a sentence could also mean Strands Shell, the box's shell, so "the shell" never names two things.** |
| **the host OS's Python** | real Python, real CPython, the Python alone for this program | The operator's own Python, such as CPython in a virtual environment. A tool, or an agent that is itself a Python program, runs it. **Say it whenever a sentence could also mean Monty, the box's Python.** |
| **operator** | user, customer | The person who configures a box and runs it on their own machine. |
| **tenant** | customer | One organization's environment on shared hardware, which the hosting platform keeps apart from every other tenant. **Keep the tenant distinct from the operator.** |
| **sandbox grants** | containment configuration, operating system restrictions, profile, except for the macOS rendering, sandbox config | Everything one sandbox allows, fixed before its process starts. This includes its filesystem grants and, for a tool or local MCP server, its network settings. The operating system enforces them. **Say "sandbox grants" for everything a sandbox allows, and "filesystem grants" when the sentence is only about paths. Use "profile" only for the macOS rendering.** |
| **filesystem grants** | path grants | The paths one sandbox can reach and their access modes, from the `filesystem` lists in `box.toml`. They are part of the sandbox grants. |
| **grant** | permission, allow, rule | One authorized path and its access mode in a sandbox's filesystem grants. **A grant is one entry, not another word for the filesystem grants.** |
| **operator-defined-reads** | operator-selected reads, read grants | The filesystem grants that expose surrounding-OS files or directories directly to the workload for read access. An exact path selects one file, `directory/` selects one directory, and `directory/*` selects its subtree. |
| **operator-defined-writes** | operator-selected writes, write grants | The filesystem grants that expose surrounding-OS files or directories directly to the workload for write access. An exact path selects one file, `directory/` selects one directory, and `directory/*` selects its subtree. |
| **policy** | policy definition, authored policy, rules | What the operator authors. It decides each operation while the box runs. **Policy and the sandbox grants are two tiers, not two words for one thing.** Keep this distinction when describing enforcement. |
| **operating system enforcement** | containment, kernel enforcement | The operating system's restrictions on a sandboxed process's own system calls, such as opening a file. Box sets the limits before the process starts, and the process can't change them. **It pairs with policy.** |
| **reachable paths check** | reach floor, sandbox OS boundary | The deny-only check Box applies after policy permits a file operation through Strands Shell or Monty. It refuses a path outside the operator's home, the agent's `HOME`, and the workspace, a path inside Box's own state, and the `box.toml` and policy that this run loaded. Box sets it, the operator can't turn it off, and the operating system doesn't enforce it. |
| **policy decision** | None | One permit or deny for one request, such as one command or one file operation. |
| **tool grammar** | tool pack | The TOML that describes a tool's actions, effects, and rules for reading a command line as one of those actions. Box decides a command that a grammar reads as a `Tool::<name>` action. **Say "tool grammar" in Box Core. A tool pack is a concept of the Box CLI, a separate product built on Box Core. It configures a tool for a profile and can ship a grammar.** |
| **alias** | command channel, shim, shell socket, IPC channel | The program inside the agent's sandbox that the agent runs to reach the broker over `run/box.sock`. For "command channel", name the part you mean: the alias, the broker, or `run/box.sock`. Box places `strands-box-sock-alias` in the box directory's `bin/` as `zsh`, `bash`, `sh`, `python3`, `python`, and each MCP program name. **The alias is untrusted.** It provides compatibility and enforces no restrictions. |
| **broker** | server, listener | The part of the box's trusted process that accepts the alias's connections on `run/box.sock`. |
| **interpreter** | None | Strands Shell or Monty, acting on the box's behalf. **Name the one you mean.** The requirements call the pair "the interpreters". |
| **egress gateway** | egress proxy, the proxy | The outbound boundary. It decides and forwards each request. |
| **relay** | None | The part that carries bytes across the box's network boundary. **It decides nothing.** Calling it a gateway implies authority it must never hold. |
| **box directory** | box home, home, private home | The private per-box directory. It holds `bin`, `run`, `trust`, and `private`. The workload cannot reach it, and no child of it is a home. |
| **runtime minimum** | pack, bundle, base grants | The paths an interpreter must have to start. Core adds them to each process, and `run` discloses them at startup. The operator authors none of them. |
| **process specification** | session config, agent config, tool config | The `command`, `workspace`, `env`, and `filesystem` fields in `[agent]` and each `[tool.<name>]`, plus the optional experimental `native-filesystem-policy` selection. |
| **absent** | denied, blocked, refused | A path the box can name and cannot reach. The call fails as "no such file". **Absent and refused are different outcomes**, and only Linux makes an ungranted path absent. |

## Three terms that look like synonyms and are not

**workload, agent, harness.** These name three different things. Use the definitions above to
distinguish them.

**policy, sandbox grants.** These are two enforcement tiers. The operator authors policy, which
decides each operation. Strands Box builds sandbox grants before the box starts.

**egress gateway, relay.** The egress gateway decides requests. The relay carries bytes.
