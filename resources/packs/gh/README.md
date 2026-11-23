# gh in a box (`@box/gh`)

The `@box/gh` pack lets the agent run the GitHub CLI, `gh`, that your `PATH` finds. Add it with
`box profile create <name> --tools git,gh`, or add `@box/gh` to `packs` in your profile.

## Signing in

gh in the box never reads your own gh login. To give it a token, add this route to your profile:

```toml
[egress.github-api]
destinations = ["api.github.com"]
secret.ref = "env://GH_TOKEN"
secret.prefix = "token "
```

Then export `GH_TOKEN` before `box run`. gh holds a placeholder key, and the box puts the real token on
each request to `api.github.com`. Use a token that can do only what you want the agent to do,
such as a fine-grained token with read access to one repository. This is the same route that
[Give the agent a token for another service](../../../docs/cli/profiles.md#give-the-agent-a-token-for-another-service)
shows.

## What gh can reach

`github.com`, `api.github.com`, and the hosts that GitHub sends gh on to:

| Host | Commands |
| --- | --- |
| `results-receiver.actions.githubusercontent.com` | `gh run view --log` and `--log-failed` |
| `codeload.github.com` | `gh release download --archive` |
| `release-assets.githubusercontent.com` | `gh release download`, `gh extension install` |

Every program in the box can reach these hosts, not only gh.

## Limitations

- The route above covers only gh's API calls. git over HTTPS, the git that gh starts included,
  gets no credential from it. For git, add the `github.com` route in
  [Push to GitHub with git](../../../docs/cli/profiles.md#push-to-github-with-git).
- These stop at a deny: `gh run download`, a single job's log (`gh api .../actions/jobs/<id>/logs`,
  and the per-job fallback of `gh run view --log`), `gh release upload`, the `gh gist` commands,
  `gh attestation verify`, and `gh codespace`.
- On macOS, gh must be 2.101.0 or later.
