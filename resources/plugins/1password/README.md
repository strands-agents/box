# 1Password (@box/1password)

The `@box/1password` plugin lets the box read a secret, such as an API token, from your 1Password
vault when it starts. The box runs the 1Password command-line program, `op`, on your machine, outside
the box, with your own sign-in. The agent only ever sees a stand-in, and the box puts the real
secret on each request that your policy allows.

## Read a token from 1Password

List the plugin in your profile, and name the item on the route that the token goes to:

```toml
plugins = ["@box/1password"]

[egress.github]
destinations = ["api.github.com"]
secret.ref = "op://Private/GitHub/token"
secret.env = "GH_TOKEN"
```

`secret.ref` is the item's secret reference, the same text that `op read` takes: the vault, the
item, and the field. In the 1Password app, **Copy Secret Reference** on a field gives you one.
`secret.env` names the variable that holds the stand-in in the box. You don't set `GH_TOKEN`
yourself.

`box` finds `op` on your `PATH`. To use another copy, set its full path in your profile:

```toml
[options]
onepassword.path = "/usr/local/bin/op"
```

A profile file that you run by its path can't set it, as the [plugin reference](../../../docs/cli/plugins-reference.md#a-profile-file-that-runs-by-its-path) says.

`box profile show` prints the copy that the box runs:

```text
  plugins   @box/1password 1
  source    op:// runs /usr/local/bin/op (@box/1password)
```

## Sign in

The box runs `op read` once for each secret when it starts, so `op` has to be able to sign in at
that moment. On your own Mac, use the 1Password app: turn on **Integrate with 1Password CLI** in
its **Developer** settings. When the box starts, approve the request in the app if it asks. On a
machine without the app, export a service account's token in `OP_SERVICE_ACCOUNT_TOKEN` before
`box run`, or the address and token of a 1Password Connect server in `OP_CONNECT_HOST` and
`OP_CONNECT_TOKEN`. The plugin doesn't pass a session from `eval "$(op signin)"`
([Limitations](#limitations)).

If you have more than one 1Password account, set `OP_ACCOUNT` to the one to use.

## What op gets from your shell

`op` runs with your home folder, a `PATH` of `/usr/bin:/bin`, and only these variables, when your
shell sets them:

| Variable | What it is for |
| --- | --- |
| `OP_ACCOUNT` | The account `op` uses. |
| `OP_CONNECT_HOST` | The address of a 1Password Connect server. |
| `TMPDIR` | Your temporary folder. `op` keeps the session file of a manual `op signin` under it. |
| `OP_SERVICE_ACCOUNT_TOKEN` | The token of a service account. |
| `OP_CONNECT_TOKEN` | The token of a Connect server. |

The last two are credentials. The plugin also lists `op`'s settings folders, `~/.config/op` and
`~/.op`, and the 1Password app's folder, `~/Library/Group Containers/2BUA8C4S2C.com.1password`.
The box keeps these credentials and folders from the agent, as
the [plugin reference](../../../docs/cli/plugins-reference.md#protect) describes, except in the cases that
[MCP servers in the box](../../../docs/cli/limitations.md#mcp-servers-in-the-box) names.

## Your own copy

To change what this plugin does, copy its folder to `~/.strands/box/plugins/<name>/`, such as
`~/.strands/box/plugins/my-1password/`. In the copy's `plugin.toml`, set `name` to the folder name, and
make your change. Then list `my-1password` in `plugins` in place of `@box/1password`. The
[plugin reference](../../../docs/cli/plugins-reference.md) lists each key.

## Limitations

- The plugin doesn't pass `XDG_CONFIG_HOME` or `OP_CONFIG_DIR` to `op`, because the box protects
  only the folders that the plugin lists. If you keep `op`'s settings in another folder, make your
  own copy of this plugin ([Your own copy](#your-own-copy)), with that folder after `--config` and
  in `[protect] paths`:

  ```toml
  [run]
  command = ["${{ inputs.onepassword.path }}", "--config", "/Users/you/op-settings", "read", "op://{ref}"]

  [protect]
  env   = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"]
  paths = ["/Users/you/op-settings",
           "${{ home }}/Library/Group Containers/2BUA8C4S2C.com.1password"]
  ```
- The plugin doesn't pass a manual sign-in, the session that `eval "$(op signin)"` makes. `op`
  names that variable after your account, `OP_SESSION_<account>`, and a plugin names each variable
  in full. The 1Password app, a service account token, and a 1Password Connect server all work.
  So with this plugin, the box doesn't keep an `OP_SESSION_<account>` variable of your shell from
  the agent either: an MCP server of your agent that reads it comes in. Each of the two ways below
  keeps it back.

  To keep a manual sign-in, make your own copy of this plugin ([Your own copy](#your-own-copy)),
  and name your session variable in it. This prints the name, and not the token:

  ```sh
  env | grep -o '^OP_SESSION_[^=]*'
  ```

  In the copy, add the variable to `[env]`, and add its name to the `env` list of `[protect]`.
  Keep `paths` as it is. Here for `OP_SESSION_my`:

  ```toml
  [env]
  OP_SESSION_my = { from = "env:OP_SESSION_my" }

  [protect]
  env = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_SESSION_my"]
  ```

  `op` keeps the file of that session in the folder `com.agilebits.op.<your user ID>` of your temporary folder: `$TMPDIR`, or `/tmp` when your shell sets no `TMPDIR`. The plugin can't list that folder, because its path
  differs for each user and a path of a plugin takes no variable. No pack or policy that `box`
  ships lets the agent, a tool, or the box's shell read your temporary folder. But a profile
  grant, a project folder that holds it, or a policy rule for the box's shell can give it to one
  of them, and that program can then read the session file. `op` 2.42.0 doesn't take that file
  without your `OP_SESSION_<account>` variable (`op whoami` says `could not find session token`).
  To close the folder, add its full path to `[protect] paths` in your copy. This prints it:

  ```sh
  tmp="${TMPDIR:-/tmp}"; echo "${tmp%/}/com.agilebits.op.$(id -u)"
  ```

  The box then stops a profile whose grant reaches that folder, and a tool with a grant beside it
  can't see it. The box's shell can still read or change it if a policy rule allows that, so don't
  write one.

  If you sign in to more than one account, a profile in `~/.strands/box/profiles/<name>/` can
  declare the source itself in place of the plugin, with Box's keys. There an entry that ends
  with `*` covers each variable with that prefix. Take `@box/1password` out of `plugins`, because
  one scheme has one source, and write the full path that `command -v op` prints as the program:

  ```toml
  [secret-source.op]
  protocol        = "box.secret-source.v1"
  command         = ["/usr/local/bin/op", "read", "op://{ref}"]
  pass-env        = ["OP_ACCOUNT", "TMPDIR"]
  pass-secret-env = ["OP_SESSION_*"]
  deny            = ["~/.config/op", "~/.op",
                     "~/Library/Group Containers/2BUA8C4S2C.com.1password"]
  ```

  Add the session folder's full path to `deny` there too. A profile file that you run by its path
  can't hold this table. The
  [profile reference](../../../docs/cli/profiles-reference.md#what-a-profile-holds) says what
  the table can hold.
- With the plugin in your profile, no grant can reach the 1Password app's folder, `~/Library/Group Containers/2BUA8C4S2C.com.1password`. The 1Password SSH agent keeps its socket there, at `t/agent.sock`. So a profile that gives that socket to a tool, such as `git`, stops when the box starts. Use another SSH agent for that tool.
- A field whose value is a JSON object needs `#` and a key at the end of the reference, such as
  `op://Private/Service/config#token`. Without it, the box stops, so one host never gets every key
  in it.
- The box reads each secret once, when it starts. If you change the item, start a new run.
- On Linux, the box closes a folder that the plugin lists only if it exists when the box starts. For each one that doesn't, the box prints a line such as this one:

  ```text
  strands-box: [secret-source.op]: `deny` entry "~/.op" names /home/you/.op, which does not exist when the box starts, so no sandbox denies it in this run
  ```

  The box doesn't close that folder in that run, unless `op` makes it while the box reads your secrets. Expect the line for `~/.op`, which only an older install of `op` makes, and for `~/Library/Group Containers/2BUA8C4S2C.com.1password`, which is the folder of the Mac app. Expect it for `~/.config/op` too, until `op` has made that folder. The plugin lists no folder of the 1Password app for Linux, so a grant on one doesn't stop the run. See the [plugin reference](../../../docs/cli/plugins-reference.md#protect).

## Troubleshooting

### The box stops when it starts, with an error from op

The box couldn't read one of your items, so it stopped before the agent started. Run the same
read in your shell, with the reference from your profile:

```sh
op read "op://Private/GitHub/token"
```

If that fails too, `op` tells you why: most often it isn't signed in, or the vault, item, or field
name is wrong. If it works in your shell but not in the box, `op` may need a variable that isn't
in the table above, because `op` gets no others. To pass one more, make your own copy of this
plugin ([Your own copy](#your-own-copy)) with the variable in `[env]`, as
[the plugin reference](../../../docs/cli/plugins-reference.md#env) shows. If you signed in with
`eval "$(op signin)"`, that variable is your session, which is a credential: follow the steps for
a manual sign-in under [Limitations](#limitations), so that it also goes in `[protect] env`.
