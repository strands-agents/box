# Locked (`@box/locked`)

In a profile it creates, the agent can read your project but not change it. The box's shell runs none of its own commands,
and the agent reaches only the hosts your packs and profile allow: the model, the package
registries of the tools `box` found, your MCP servers, and any route you add.

`box profile create --policy locked` copies [`policy.dw`](policy.dw) into the profile folder, and
writes `[project] access = "read"` into `profile.toml`. Both are yours: change them, and the next
run uses them. `access = "write"` lets the agent change your project again.

## What it holds

- `dev_null`: programs can read and write `/dev/null`. Every other permit in the run comes from what
  your packs and profile declare.
- The shell's own commands, such as `cd`, `cat`, and `echo`, are refused. A tool that a pack
  declares, such as `git`, still starts, because `box` writes its permit.
- The agent's own file tools still work. Your profile's filesystem lists decide what they reach.
- To let the shell run some commands, add the `shell_commands` rule that the comment in
  `policy.dw` shows, with a condition that names them. Agents run `uname` at startup, so the
  example names it first.

## Limitations

- A toolchain that writes into your project fails, such as `cargo build` writing `target` or
  `npm install` writing `node_modules`.
- An agent whose shell tool runs setup commands of its own before each command can't run any
  shell command, a declared tool included. Its pack's README says so under **Limitations**.
- Nothing blocks a cloud metadata service. A route or a rule you add that matches its host or
  address lets the agent reach the machine's credentials. On a cloud machine, add a `forbid` for its
  metadata hosts and addresses, as Box Core's
  [policy guide](https://github.com/strands-agents/box/blob/main/docs/user/policy.md) shows for
  `metadata_addresses`.
