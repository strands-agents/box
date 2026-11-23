# Open (`@box/open`)

The box's shell can run any command, and the agent can reach any host on the internet, so it can search the web, read docs, and fetch
packages. It can't reach a service on this machine, such as a local database.

`box profile create --policy open` copies [`policy.dw`](policy.dw) into the profile folder, and
writes `[project] access = "write"` into `profile.toml`, so the agent can read and change your
project. Both are yours: change them, and the next run uses them.

## What it holds

- `shell_commands`: the box's shell can run any command. Each file a command touches is still
  checked. To allow only some commands, add a condition to this rule, as its comment shows. Without
  it, the shell runs nothing.
- `dev_null`: programs can read and write `/dev/null`.
- `open_connect` and `open_request`: the agent can connect and send HTTP requests to any host.
- `open_websocket`: the agent can open a WebSocket to any host. After the WebSocket opens, policy
  decides nothing more, and Box doesn't redact a credential in its messages.
- `open_loopback`: except to a loopback address, such as `127.0.0.1`.
- `open_link_local`: or to a link-local address (`169.254.0.0/16`, `fe80::/10`). Most clouds serve
  the machine's credentials from `169.254.169.254`, so this blocks that metadata service.

## Limitations

- Hosts on your local network are reachable.
- A few metadata endpoints sit outside link-local and stay reachable: AWS's IPv6 `fd00:ec2::254`,
  Azure's WireServer `168.63.129.16`, and Alibaba Cloud's `100.100.100.200`. On those clouds, add a
  `forbid` for them to your copy, as Box Core's
  [policy guide](https://github.com/strands-agents/box/blob/main/docs/user/policy.md) shows for
  `metadata_addresses`.
