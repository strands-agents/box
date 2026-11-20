# Amazon Bedrock as the model provider (`@box/bedrock`)

The `@box/bedrock` pack lets the agent reach its model on Amazon Bedrock, in the region that
`bedrock.region` names (`us-west-2` unless you set it). `@box/bedrock-mantle`, Bedrock's
OpenAI-compatible endpoint for Codex, works the same way and takes the same options.

## Sign in

`bedrock.sign-in` sets how the box signs in to Bedrock. `box profile create` asks for it, shows
what `aws` lets the box do, and saves your answer in the profile, even when it's the default.

| Value | What the box does |
| --- | --- |
| `aws` (the default) | Signs each request with your default AWS identity, outside the box ([which credentials](../../../docs/cli/profiles-reference.md#aws-credentials)). Box Core prints a warning for each request it signs this way. The route is `[egress.bedrock]`. |
| `api-key` | Adds the Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK` to each request. The agent only sees a stand-in. The route is `[egress.bedrock-api-key]`, so a profile that changes the route's keys, such as `destinations` or `secret.ref`, writes them under that name. Keys under `[egress.bedrock]` don't apply with `api-key`. |

The agent never sees your AWS credentials or your key.
[Sign in to Bedrock](../../../docs/cli/getting-started.md#4-sign-in-to-bedrock) shows how to set
up each one, and how to use an SSO or `aws login` profile, which the box can't read directly.

To sign with one named AWS profile, whatever `AWS_PROFILE` says, keep `aws` and add this to
`profile.toml`, with your AWS profile's name:

```toml
[egress.bedrock.secret]
ref = "aws://your-profile"
```

## Troubleshooting

### Every model request fails with 403

Work through these in order.

1. **AWS refused the request, and the box didn't.** Run `box runs history <box-id> --deny` with
   the box ID that `box run` printed. If it shows nothing for the Bedrock host, and
   `box runs history <box-id> --resource bedrock` shows the request as `permit`, the 403 came from
   AWS. A message such as `is not available for this account` or `INVALID_PAYMENT_INSTRUMENT`
   points to the next cause. To check outside the box, send one small request with the same AWS
   profile, region, and model ID that [Get started](../../../docs/cli/getting-started.md#3-choose-the-model) set:

   ```sh
   aws bedrock-runtime converse --region "$REGION" --profile "$AWS_PROFILE_NAME" \
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
   [Sign in to Bedrock](../../../docs/cli/getting-started.md#4-sign-in-to-bedrock), and start a new
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
