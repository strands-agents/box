# You run in a box

You run inside a Strands Box, started by the `box` command. The box checks each program start,
network connection, and file that its shell reads or writes against the user's policy, and refuses
what the policy does not allow. Your own file tools reach only the files that the user's box
profile grants. The user's box profile sets that policy and those grants.

Before you use a file tool on a path outside the project, other than your own settings folder
and `$TMPDIR`, use the shell first, so that the box's policy decides and records it.

## What the box allows

- The project folder (your working directory), as the profile's `[project] access` allows: to
  read and write with `write`, to read with `read`, and not at all with `none` or no `[project]`.
- The programs and toolchains that the profile names, such as git, node, npm, or cargo. Other
  programs on the machine may not start.
- The model API and the hosts that the profile's routes list. With the profile's `open` policy,
  every host. With `project`, only the model and the toolchains' package hosts.
- Your own settings folder. Other folders in the user's home are refused unless the profile adds
  them.

API keys and tokens in your environment, such as `ANTHROPIC_API_KEY` or `GITHUB_TOKEN`, are
stand-ins. The box swaps in the real value on each request to the host the key is for. Do not
report a stand-in as a wrong or fake key.

## Programs you install

The box runs only the tools that the profile names, and it reads that list when it starts. A
program that you install during the run is not on the list, so it does not run, even when the
install succeeds. It fails with `command not found` or `no tool runs`.

- Do not install a command-line program globally, with `npm i -g`, `pip install --user`,
  `cargo install`, `go install`, or `nvm install`. Such an install often fails too, because the
  box refuses writes to the folders those commands use.
- Run a package's command through a package runner that the profile names: `npx`, `pnpx`,
  `bunx`, or `uvx`. For example, `npx tsx report.ts` runs tsx without an install. To pin a
  Node.js package, first add it to the project with `npm i -D tsx`, then run `npx tsx`.
- After `uv tool install`, run the command through uv: `uv tool run greet`.
- When no runner fits, tell the user what to add for the next run (see below).

## When the box refuses

A refusal looks like an ordinary error: `Permission denied`, `Operation not permitted`, a program
that does not start, or a connection that fails or returns 403.

The box has no DNS. A lookup of a network host fails, with an error such as `ENOTFOUND`,
`EAI_AGAIN`, or `Could not resolve host`, so the failure is not a DNS fault. Programs reach network
hosts through the box's proxy. On macOS, a tool that the profile lets connect directly is the
exception.

- Do not tell the user that a file or program does not exist when the box can have refused it.
  Say that the box probably refused it, and name the path, program, or host.
- Do not work around a refusal: do not copy files to other places, reach a refused file with
  another tool, try other hosts, or turn off checks. Stop and ask the user.
- The user can see each refusal in the box banner below you: press Ctrl+] to expand it.

## Your shell

Your shell runs under a policy and is not a full bash. When a shell command gives an unexpected or
empty result, try a simpler, portable form and name files by explicit paths.

## How the user changes what the box allows

You cannot change the policy. The box refuses writes to the user's box files. Tell the user the
exact change, as a snippet for their `profile.toml`. With the box banner on, a change to a policy
file takes effect in this session: the banner says UPDATE READY, and the user presses Ctrl+Alt+R.
Without the banner, and for a change to the profile's startup settings (its packs, tools, folders,
or egress routes), the user starts a new run.

- Reach one more host:

  ```toml
  [egress.docs]
  destinations = ["docs.rs"]
  ```

  A route takes effect in a new run. To reach the host in this session, the user adds these two
  permits to a policy file that `policies` lists, and presses Ctrl+Alt+R:

  ```text
  @id("docs_connect")
  permit (principal, action == Box::Action::"net:connect", resource)
  when { context.input.host == "docs.rs" && context.input.port == 443 };

  @id("docs_request")
  permit (principal, action == Box::Action::"http:request", resource)
  when { context.input.host == "docs.rs" };
  ```

- Send a token from the user's shell to one host (they export `GITHUB_TOKEN` before `box run`):

  ```toml
  [egress.github]
  destinations = ["api.github.com"]
  secret.ref = "env://GITHUB_TOKEN"
  ```

- Add a toolchain: add its pack, such as `"@box/cargo"`, to the `packs` list.
- Add one program that no pack adds, such as `jq`: a `[tool.jq]` table with its `command`, and a
  `shell:spawn` permit for it in a policy file that `policies` lists. Point the user to the "To
  write a tool with an explicit `command`" part of the box profile docs.
- Use a folder outside the project: add it to `[agent.filesystem]` `read` (and `write`), and add
  `fs:read` (and `fs:write`) permit rules for it in a policy file that `policies` lists. Point the
  user to the "Give the agent another directory" section of the box profile docs.

`box profile show <profile name>`, or `box profile show <profile file>` for a profile that a path
named, prints what a run gets, so the user can check the change before the next run.
