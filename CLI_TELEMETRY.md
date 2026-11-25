# Usage telemetry

`box run` sends usage events so the Strands Agents team can see how `box` is used and where it
fails. Telemetry is on by default; run `box telemetry off` to save an opt-out for future runs.
See [`box telemetry`](docs/cli/cli.md#box-telemetry) to check the setting
or turn it off through environment variables.

## How it works

- Only `box run` sends events.
- By default, each run sends three kinds of event to `https://telemetry.strandsagents.com/box/ping`:
  a start event, a count of policy decisions about once a minute, and an end event.
  A [developer endpoint override](docs/cli/cli.md#environment-variables) sends them to a local receiver instead.
- `box` sends them from your machine, outside the box, so your profile's network policy does not
  apply to them.
- If sending fails, your command continues without a telemetry error. At the end of a run,
  `box` waits at most two seconds for the last events, including after Ctrl+C or a failed start.
  A crash or forced stop can lose events.

## What we collect when telemetry is on

| What | Detail |
| --- | --- |
| Installation ID | A random ID saved in `~/.strands/box/installation.toml`, the same for every run on this machine. |
| Run ID | A new random ID for each run, even when you reuse a box. |
| Build | The `box` version and the operating system and processor type it was built for. |
| Operating system | The version of your operating system, such as `14.5` on macOS or your Linux distribution's release, such as `24.04`. It is left out if your system doesn't report one. |
| [Profile](docs/cli/profiles.md) | A hash (a fingerprint) of `profile.toml`, the names of packs included with `box` that it uses, and whether it names policy files, uses custom packs, or has MCP servers set up. |
| Start | Whether the box launched, the kind of error if it didn't, and how long startup took. |
| Activity | How many times the box permitted or denied each kind of action, such as `fs:write` or `shell:exec`. |
| End | How long the run took, whether the command succeeded, and whether the box finished or reported an error. |

Counts can be incomplete and don't replace your
[local records](docs/cli/cli.md#box-runs-history).

## What we do not collect

Events do not contain prompts, agent output, file contents or paths, credentials, command text or
arguments, or profile and policy text. Custom pack names, MCP server settings, and MCP tool names,
arguments, and results are also excluded.

## How long we keep the data

We retain usage telemetry for 13 months and cannot delete it on request. Turning telemetry off
stops future events; it does not delete data already sent.
