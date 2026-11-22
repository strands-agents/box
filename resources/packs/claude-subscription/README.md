# A Claude subscription as the model provider (`@box/claude-subscription`)

The `@box/claude-subscription` pack lets Claude Code (`@box/claude`) reach its model with your
claude.ai Pro or Max plan instead of an Anthropic API key. The box adds a token from
`claude setup-token` to Claude Code's requests, and the agent only sees a stand-in.

## Make a profile

1. On your machine, run `claude setup-token` and sign in in the browser it opens. It prints a
   token that starts with `sk-ant-oat01-`.
2. Put the token in `CLAUDE_CODE_OAUTH_TOKEN` in the terminal you run `box` from:

   ```sh
   export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
   ```

3. Make the profile. `box profile create claude` asks which model provider Claude Code uses: pick
   **A Claude subscription**. Or name the pack yourself:

   ```sh
   box profile create claude --with claude,claude-subscription
   ```

The profile lists `@box/claude-subscription` and sets `claude.host = "anthropic"`. Keep that
value: with `bedrock`, Claude Code talks to Bedrock and never uses the token.

Use this pack instead of `@box/anthropic`, not beside it. `@box/anthropic` sends your API key to
all of `api.anthropic.com`, and this pack sends the token to only part of that host, so
`box run` and `box profile show` refuse a profile that lists both. Without `@box/anthropic`, your `ANTHROPIC_API_KEY` doesn't reach the box, so
Claude Code uses the token.

## The paths that get the token

The box adds the token only to Claude Code's model, settings, and sign-in paths on
`api.anthropic.com`, which the `[egress.anthropic-subscription]` route in [`pack.toml`](pack.toml)
lists. The rest of the host stays reachable without the token, which is what WebFetch's safety
check and Claude Code's telemetry need.

When a Claude Code feature fails with a 401 from another path on `api.anthropic.com`, add the path
to the route in your `profile.toml`. Write the pack's list and your path, because your list
replaces the pack's:

```toml
[egress.anthropic-subscription]
destinations = [
    "api.anthropic.com/v1/",
    "api.anthropic.com/api/claude_cli/",
    "api.anthropic.com/api/claude_code/",
    "api.anthropic.com/api/oauth/",
    "api.anthropic.com/api/claude_code_grove",
]
```

[Destinations](../../../docs/user/egress.md#destinations) says how a path matches.

## Limitations

- The pack works only with Claude Code. Other agents don't read `CLAUDE_CODE_OAUTH_TOKEN`.
- Some Claude Code features call paths that the route leaves out, such as
  `/api/claude_code_grove`, and get a 401 until you add the path as shown above.

## Troubleshooting

### The run stops because two routes overlap

```text
box: error: Box Core cannot check the policy: invalid credential entry for host "api.anthropic.com/v1/": `anthropic-subscription` overlaps `anthropic` at "api.anthropic.com"; one destination is one authority, and a request matching both has no unambiguous secret or backend
```

The profile lists both `@box/anthropic` and `@box/claude-subscription`. Delete `"@box/anthropic"`
from `packs` in `profile.toml` to use your subscription, or `"@box/claude-subscription"` to use
your API key.
