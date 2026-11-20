# git in a box (`@box/git`)

The `@box/git` pack lets the agent run the `git` that your `PATH` finds.

## GitHub SSH remotes go over HTTPS

The box has no `ssh` and can't read `~/.ssh`. So `@box/git` sends a GitHub SSH remote over HTTPS
instead. A remote such as `git@github.com:owner/repo.git` or
`ssh://git@github.com/owner/repo.git` works as `https://github.com/owner/repo.git`. Your
project's `.git/config` doesn't change.

## Homebrew

On a Mac, `@box/git` reads Homebrew's `Cellar` and `opt` folders, where git finds its own commands
and curl. It uses `HOMEBREW_PREFIX`, which `brew shellenv` sets, or `/opt/homebrew` when the
variable is absent. If Homebrew is somewhere else and your shell does not set `HOMEBREW_PREFIX`,
add its location to your profile:

```toml
[options]
homebrew.prefix = "/usr/local"
```

## Apple's git

Apple's `/usr/bin/git` cannot find the developer folder from inside a box when full Xcode is
selected. So when your `PATH` finds `/usr/bin/git`, `@box/git` runs the `git` in the developer folder
that `xcode-select -p` reports, such as `/Applications/Xcode.app/Contents/Developer/usr/bin/git`.
The agent still types `git`.

- If `xcode-select -p` fails, the `git` tool is skipped.
- If that folder has no `usr/bin/git`, or its `git` lies where a box can write, the `git` tool is
  skipped with the reason.

## Limitations

- An SSH remote on another host than GitHub stops with `cannot run ssh`. Give the project an
  HTTPS remote for that host.
- `[tool.git.network] contain_egress = false` in your profile does not make SSH work. `@box/git`
  still sends GitHub SSH remotes over HTTPS, and the box still has no `ssh`. The setting only makes
  git's HTTPS connections skip the box's gateway, so your policy no longer decides them and the
  agent can point `git` at any host.
- On a Mac, `@box/git` is tested with Homebrew's git and with Apple's git from full Xcode. Apple's
  git from the Command Line Tools alone is not tested yet.

## Troubleshooting

### `git` is skipped because the developer folder holds no `usr/bin/git`

The folder that `xcode-select -p` reports has no `git`. Select a developer folder that has one,
such as with `sudo xcode-select -s /Applications/Xcode.app`, or install Homebrew's git with
`brew install git` so that your `PATH` finds it first.

### `git` stops with `cannot run` or `unable to find remote helper`

If `git worktree add -b` or `git push` over HTTPS stops in the box this way:

- If your git is neither Homebrew's nor Apple's `/usr/bin/git`, install Homebrew's with
  `brew install git`, so that your `PATH` finds it first.
- If it is Homebrew's, check that `HOMEBREW_PREFIX` is set, or set `homebrew.prefix`, as in
  [Homebrew](#homebrew).
