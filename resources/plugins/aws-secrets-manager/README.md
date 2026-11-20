# AWS Secrets Manager (@box/aws-secrets-manager)

The `@box/aws-secrets-manager` plugin lets the box read a secret, such as an API key, from AWS
Secrets Manager when it starts. The box runs the AWS command-line program, `aws`, on your machine,
outside the box, with your own AWS identity. The agent only ever sees a stand-in, and the box puts
the real secret on each request that your policy allows.

## Read a secret

List the plugin in your profile, and name the secret on the route that it goes to:

```toml
plugins = ["@box/aws-secrets-manager"]

[egress.github]
destinations = ["api.github.com"]
secret.ref = "aws-secretsmanager://team/github-token"
secret.env = "GH_TOKEN"
```

The part after `aws-secretsmanager://` is the secret's name or ARN, as
`aws secretsmanager get-secret-value --secret-id` takes it. `secret.env` names the variable that
holds the stand-in in the box. You don't set `GH_TOKEN` yourself.

`box` finds `aws` on your `PATH`. To use another copy, set `aws-secrets-manager.path` to its full
path under `[options]` in your profile. A profile file that you run by its path can't set it ([plugin reference](../../../docs/cli/plugins-reference.md#a-profile-file-that-runs-by-its-path)). `box profile show` prints the copy that the box runs.

### Read one key of a JSON secret

A secret often holds a JSON object with several keys. Add `#` and the key to read just that one.
This sends one key of a shared secret to a telemetry service:

```toml
plugins = ["@box/aws-secrets-manager"]

[telemetry.langsmith]
kind = "otlp"
destination = "https://api.smith.langchain.com/otel"
secret.ref = "aws-secretsmanager://team/telemetry#LANGSMITH_API_KEY"
secret.header = "x-api-key"
```

Without a key, the box stops on a secret that holds a JSON object, so one host never gets every key
in it. Two references to the same secret with different keys read it only once.

## Sign in

`aws` finds your identity the way it does in your shell, from the variables below and the files in
`~/.aws`. On your own machine, set `AWS_PROFILE` to a profile in `~/.aws/config` before `box run`,
or run the box under a tool that exports keys, such as `aws-vault exec work -- box run claude`.

## What aws gets from your shell

`aws` runs with your home folder, a `PATH` of `/usr/bin:/bin`, and only these variables, when your
shell sets them.

Settings:

- `AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`
- `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`
- `AWS_CONTAINER_CREDENTIALS_FULL_URI`, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`,
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`
- `AWS_EC2_METADATA_DISABLED`, so `aws` uses an EC2 instance's identity only when your shell
  allows it

Credentials:

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- `AWS_CONTAINER_AUTHORIZATION_TOKEN`

The plugin also lists `~/.aws` and the token folders of EKS identities,
`/var/run/secrets/eks.amazonaws.com` and `/var/run/secrets/pods.eks.amazonaws.com`. The box keeps
these credentials and folders from the agent, as
the [plugin reference](../../../docs/cli/plugins-reference.md#protect) describes, except in the cases that
[MCP servers in the box](../../../docs/cli/limitations.md#mcp-servers-in-the-box) names.

## Your own copy

To change what this plugin does, copy its folder to `~/.strands/box/plugins/<name>/`, such as
`~/.strands/box/plugins/my-secrets-manager/`. In the copy's `plugin.toml`, set `name` to the folder name,
and make your change. Then list `my-secrets-manager` in `plugins` in place of
`@box/aws-secrets-manager`. The [plugin reference](../../../docs/cli/plugins-reference.md) lists
each key.

## Limitations

- The secret must be in the region that `aws` uses: set `AWS_REGION`, or `region` in your AWS
  profile. `aws` doesn't take the region from an ARN.
- Keep the AWS profile that the plugin uses in `~/.aws/config` or `~/.aws/credentials`. The plugin
  doesn't pass `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE`, because the box protects only
  the folders that the plugin lists. So `aws` doesn't see a file that one of them points to.
- The box keeps the token file of `AWS_WEB_IDENTITY_TOKEN_FILE` or
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` from the agent only in the two EKS folders above. The
  plugin can't list another place, because a path of a plugin takes no variable. If your token file is in
  another folder, the box doesn't protect it. A profile grant, a project folder that holds it, or a
  policy rule for the box's shell can give it to the agent, a tool, or the box's shell. That
  program can then read the token file.

  To close that folder, make your own copy of this plugin ([Your own copy](#your-own-copy)), and
  add the token file's folder to `[protect] paths`. The box then
  stops a profile whose grant reaches that folder. The box's shell can still read or change it if a
  policy rule allows that, so don't write one.
- A binary secret doesn't work. `aws` prints `null` for it, and the box stops.
- A secret that holds a JSON object needs `#` and a key at the end of the reference, as
  [Read one key of a JSON secret](#read-one-key-of-a-json-secret) shows. Without it, the box
  stops.
- Don't use an AWS profile that sets `credential_process`. The box doesn't stop you. But a bare
  program name there fails on the `PATH` above, and a full path runs that program outside the box,
  where the box protects nothing for it.
- The box doesn't check that this identity is the one that an `aws://` route signs with.
- An MCP server of your agent that sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or
  `AWS_SESSION_TOKEN` in its `env` is left out while you list this plugin, even with keys of its
  own.
- The box reads each secret once, when it starts. If you change the secret, start a new run.
- On Linux, the box closes a folder that the plugin lists only if it exists when the box starts. For each one that doesn't, the box prints a line such as this one:

  ```text
  strands-box: [secret-source.aws-secretsmanager]: `deny` entry "/var/run/secrets/eks.amazonaws.com" names /run/secrets/eks.amazonaws.com, which does not exist when the box starts, so no sandbox denies it in this run
  ```

  The box doesn't close that folder in that run, unless `aws` makes it while the box reads your secrets. Expect the line for the two EKS token folders, which exist only in an EKS pod, and for `~/.aws` when you have none. See the [plugin reference](../../../docs/cli/plugins-reference.md#protect).

## Troubleshooting

### The box stops when it starts, with an error from aws

The box couldn't read one of your secrets, so it stopped before the agent started. Run the same
read in your shell, with the name from your profile:

```sh
aws secretsmanager get-secret-value --secret-id team/github-token --query SecretString
```

If that fails too, `aws` tells you why: most often the identity has expired, the region is wrong,
or the identity isn't allowed to read the secret. If it works in your shell but not in the box,
`aws` may need a variable that isn't in the lists above, such as `HTTPS_PROXY` or `AWS_CA_BUNDLE`,
because `aws` gets no others. To pass one more, make your own copy of this plugin
([Your own copy](#your-own-copy)) with the variable in `[env]`, as
[the plugin reference](../../../docs/cli/plugins-reference.md#env) shows.
