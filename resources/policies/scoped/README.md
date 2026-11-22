# Scoped (`@box/scoped`)

The box's shell can run any command, and the agent reaches only the hosts your packs and profile allow: the model, the package registries of
the tools `box` found (such as `registry.npmjs.org` for npm), your MCP servers, and any route you
add. Every other host is refused.

`box profile create --policy scoped` copies [`policy.dw`](policy.dw) into the profile folder, and
writes `[project] access = "write"` into `profile.toml`, so the agent can read and change your
project. Both are yours: change them, and the next run uses them.

## What it holds

- `shell_commands`: the box's shell can run any command. Each file a command touches is still
  checked. To allow only some commands, add a condition to this rule, as its comment shows. Without
  it, the shell runs nothing.
- `dev_null`: programs can read and write `/dev/null`.
- No network rule. To let the agent reach one more host, add a route to `profile.toml`, as the
  comment at the end of `policy.dw` shows.

## Limitations

- Nothing blocks a cloud metadata service. A route or a rule you add that matches its host or
  address lets the agent reach the machine's credentials. On a cloud machine, add a `forbid` for its
  metadata hosts and addresses, as Box Core's
  [policy guide](https://github.com/strands-agents/box/blob/main/docs/user/policy.md) shows for
  `metadata_addresses`.
