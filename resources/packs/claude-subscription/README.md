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

Use this pack instead of `@box/anthropic`, not beside it. Both packs send a credential to
`api.anthropic.com`, so `box run` and `box profile show` refuse a profile that lists both.
Without `@box/anthropic`, your `ANTHROPIC_API_KEY` doesn't reach the box, so Claude Code uses the
token.

## The token goes on every request to Anthropic

Claude Code makes some requests to `api.anthropic.com` without its token, such as WebFetch's
check that a site is safe to fetch. So the box adds your token to every request the agent sends to
`api.anthropic.com`, whether or not the request carries the stand-in. That keeps every Claude Code
feature working, whatever paths a new release calls.

The cost: for this one host, the box can't tell whether a request came from Claude Code or from
another program in the box. Any program in the box can call `api.anthropic.com` with your
subscription. The token still goes nowhere else. Each time the box adds the token to a request
that carried no stand-in, it writes a warning to the run's `box.log`, not to your screen. When
the run ends, `box` prints where that log is.

## Limitations

- The pack works only with Claude Code. Other agents don't read `CLAUDE_CODE_OAUTH_TOKEN`.

## Troubleshooting

### The run stops because two routes overlap

```text
box: error: Box Core cannot check the policy: invalid credential entry for host "api.anthropic.com": `anthropic-subscription` overlaps `anthropic` at "api.anthropic.com"; one destination is one authority, and a request matching both has no unambiguous secret or backend
```

The profile lists both `@box/anthropic` and `@box/claude-subscription`. Delete `"@box/anthropic"`
from `packs` in `profile.toml` to use your subscription, or `"@box/claude-subscription"` to use
your API key.
