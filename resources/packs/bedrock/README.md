# Amazon Bedrock as the model provider (`@box/bedrock`)

The `@box/bedrock` pack lets the agent reach its model on Amazon Bedrock, in the region that
`bedrock.region` names (`us-west-2` unless you set it). `@box/bedrock-mantle`, Bedrock's
OpenAI-compatible endpoint for Codex, works the same way and takes the same options.

## Sign in

`bedrock.sign-in` sets how the box signs in to Bedrock. `box profile create` asks for it, shows
what `aws` lets the box do, and saves your answer in the profile, even when it's the default.

| Value | What the box does |
| --- | --- |
| `aws` (the default) | Signs each request with your default AWS identity, outside the box ([which credentials](../../../docs/cli/profiles-reference.md#aws-credentials)). Box Core prints one warning when the run starts. The route is `[egress.bedrock]`. |
| `api-key` | Adds the Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK` to each request. The agent only sees a stand-in. The route is `[egress.bedrock-api-key]`, so a profile that changes the route's keys, such as `destinations` or `secret.ref`, writes them under that name. Keys under `[egress.bedrock]` don't apply with `api-key`. |

The agent never sees your AWS credentials or your key.
[Connect to Bedrock](../../../docs/cli/getting-started.md#3-connect-to-bedrock) shows how to set
up `aws`, including an SSO or `aws login` profile, which the box can't read directly.
[Sign in with a Bedrock API key](#sign-in-with-a-bedrock-api-key) shows `api-key`.

To sign with one named AWS profile, whatever `AWS_PROFILE` says, keep `aws` and add this to
`profile.toml`, with your AWS profile's name:

```toml
[egress.bedrock.secret]
ref = "aws://your-profile"
```

### Sign in with a Bedrock API key

Pick `api-key` when `box profile create` asks how the box signs in, or set it in the `[options]`
table of the profile's `profile.toml`:

```toml
[options]
bedrock.sign-in = "api-key"
```

A key needs the account to allow Bedrock API keys (the IAM action `bedrock:CallWithBearerToken`),
and [`uv`](https://docs.astral.sh/uv/) to run the tool that makes it. This command makes a key for
`us-west-2` with your current AWS identity, and puts it in `AWS_BEARER_TOKEN_BEDROCK`, the variable
the box reads it from. Put the profile's `bedrock.region` in place of `us-west-2`, because a key only
works in the region it was made for:

```sh
export AWS_BEARER_TOKEN_BEDROCK="$(uv run --quiet --no-project --with aws-bedrock-token-generator --with 'botocore[crt]' python -c 'import sys; from aws_bedrock_token_generator import provide_token; print(provide_token(region=sys.argv[1]))' us-west-2)"
```

To check the key, run `echo "${#AWS_BEARER_TOKEN_BEDROCK}"`. You want a number in the hundreds or
more. A `0` means the command failed: read the error it printed and check your AWS profile. The key
lasts up to 12 hours, and once it runs out, the model answers with `403` until you run the same
`export` again. Run `box run` in the terminal where you exported it.

## Troubleshooting

### Every model request fails with 403

Work through these in order.

1. **AWS refused the request, and the box didn't.** Run `box runs history <box-id> --deny` with
   the box ID that `box run` printed. If it shows nothing for the Bedrock host, and
   `box runs history <box-id> --resource bedrock` shows the request as `permit`, the 403 came from
   AWS. A message such as `is not available for this account` or `INVALID_PAYMENT_INSTRUMENT`
   points to the next cause. To check outside the box, send one small request from the terminal
   where you run `box run`, with the profile's region and the model ID that
   [Get started](../../../docs/cli/getting-started.md#choose-the-model) set:

   ```sh
   aws bedrock-runtime converse --region <region> \
     --model-id <model-id> \
     --messages '[{"role":"user","content":[{"text":"hi"}]}]'
   ```

   If this fails with the same message, the fix is in your AWS account, not in the box.
2. **The account can't use the model.** An Anthropic model can need an AWS Marketplace
   subscription, which Bedrock starts on the account's first call. That needs a valid payment
   method on the account and the IAM actions `aws-marketplace:ViewSubscriptions` and
   `aws-marketplace:Subscribe` on the identity that makes the call. Someone with those permissions
   can make the first call, and after that other identities in the account can call the model
   without them. An Anthropic model earlier than Claude Opus 4.7 also needs the account's use case
   form, which you submit once from the model catalog in the Bedrock console. The subscription can
   take a few minutes to finish
   ([Request access to models](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)).
   Otherwise the model has to be one that Bedrock serves in the profile's region. With Claude Code,
   see [Claude Code starts, then sits there](../claude/README.md#claude-code-starts-then-sits-there).
3. **The credentials expired.** A message such as `The security token included in the request is
   expired` means the AWS session ended. Sign in again, or export the keys again, as in
   [Connect to Bedrock](../../../docs/cli/getting-started.md#3-connect-to-bedrock), and start a new
   run. A Bedrock API key lasts up to 12 hours, or until the AWS session that made it ends, so make
   a new one the same way.
4. **The key is for another region.** With `api-key`, a key works only in the region it was made
   for. `box profile show <name>` prints the profile's `bedrock.region`, so make the key for that
   region.
5. **Your account doesn't allow Bedrock API keys.** If your AWS role denies
   `bedrock:CallWithBearerToken`, every key gets a 403. Use a role that allows it, or set
   `bedrock.sign-in = "aws"`, which signs with your AWS credentials.
6. **The agent uses another provider.** See
   [The agent can't reach its model](../../../docs/cli/troubleshooting.md#the-agent-cant-reach-its-model).
