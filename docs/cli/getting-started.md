---
reader: Someone new to Box who wants Claude Code running in a box in one of their own projects, and who follows the steps in order.
belongs: Only the steps of that first run, Claude Code on Amazon Bedrock, and each Claude Code fact needed to finish it. Install options go to install.md, files under ~/.strands/box to files.md, other agents and providers to profiles.md, the other policies to starters.md, Claude Code's other behavior to resources/packs/claude/README.md, and fixes after the first run to troubleshooting.md.
---

# Get started with Box

On this page, you install Box and run Claude Code in a box in one of your own projects. The agent
can change files in your project, talk to its model, and look things up on the internet, but the
rest of your machine is out of its reach: your other files, your keys, and the services that
listen only on localhost.

## Requirements

- An Apple Silicon Mac with macOS 15 or later, or Linux on ARM64 or x86_64.
  [Install Box](install.md#requirements) lists what Linux needs.
- The [GitHub CLI](https://cli.github.com/) (`gh`), signed in with `gh auth login`. The installer
  downloads Box with it.
- The [AWS CLI](https://aws.amazon.com/cli/), to look up a model ID and check your sign-in.
- Claude Code from its native installer. The box starts the native executable, and the `npm`
  package is a Node script, so if you installed Claude Code with `npm`, reinstall it:

  ```sh
  curl -fsSL https://claude.ai/install.sh | bash
  ```

- An AWS account that can call Claude models on Amazon Bedrock, and an AWS profile for it on this
  machine. For an Anthropic model, the first call in an account can need an AWS Marketplace
  subscription, so the account needs a valid payment method, and the identity that makes the first
  call needs the IAM actions `aws-marketplace:ViewSubscriptions` and `aws-marketplace:Subscribe`.
  An Anthropic model earlier than Claude Opus 4.7 also needs the account's first-time use case form.
  If you're not sure, carry on: step 5 shows what a refusal looks like, and [Every model request fails with 403](../../resources/packs/bedrock/README.md#every-model-request-fails-with-403)
  tells an AWS refusal from a box denial.

## 1. Install Box

Download the installer and run it:

```sh
gh api 'repos/strands-agents/box/contents/install.sh?ref=main' \
  -H 'Accept: application/vnd.github.raw' > install.sh &&
BOX_VERSION=0.3.0-preview.1 sh ./install.sh
```

It installs the `0.3.0-preview.1` release, puts `box` on your `PATH`, and ends with example next
steps. Usage telemetry is on by default, and the installer says how to turn it off
([Usage telemetry](../../CLI_TELEMETRY.md)).

Open a new terminal, and do every step from here on in it, because later steps use variables that
earlier ones set. Check that `box` runs:

```console
$ box --version
box 0.3.0-preview.1
```

If the installer stops instead, it says why. [Install Box](install.md) covers what it adds,
upgrading, and uninstalling.

## 2. Create a Claude Code profile

A [profile](profiles.md) tells `box` how to run one agent: which program to start, which tools to
give it, and which model service it may reach. Make one for Claude Code on Amazon Bedrock:

```sh
box profile create claude --with bedrock
```

`box` asks for the region, how the box signs in to Bedrock, whether to bring in your MCP servers
and hooks, and the policy. Press Enter to accept each default: `us-west-2`, your AWS credentials
(`aws`), no MCP servers or hooks, and the Open policy, which lets the agent search the web and read
docs. If your Claude Code settings or your shell
(`AWS_REGION` or `AWS_DEFAULT_REGION`) already name a region, `box` doesn't ask, and the Review
tab lists it under **DETECTED OPTIONS**. To pick another policy later, see
[Pick the agent's policy](starters.md#pick-the-agents-policy).

On Review, choose **Save profile**. `box` then shows what it saved and what to do before the
first run:

```text
  BEFORE RUNNING

  • Skipped tools: pnpm (@box/pnpm), yarn (@box/yarn).
  • The bedrock route signs with your default AWS identity. Box Core warns on each request.
```

Your list may differ. A skipped tool is one that `box` didn't find on your machine. Install it
whenever you like, and the next run picks it up. The second line says how the box signs in to
Bedrock (step 4). Choose **Exit**, not **Run**, because Claude Code still needs a model.

The profile is in `~/.strands/box/profiles/claude/profile.toml`, and its first lines look like this:

```toml
# Written by `box profile create`. Your values go here, and the packs hold the rest.
# `box profile show claude` prints what a run gets.
# For help from a coding agent, tell it: Run box help agent and follow it.
packs = ["@box/claude", "@box/bedrock", "@box/cargo", "@box/git", "@box/node", "@box/npm", "@box/pnpm", "@box/yarn"]
policies = ["policy.dw"]
```

The `@box/` names are packs that come with Box. They hold the details of running Claude Code,
reaching Amazon Bedrock, and using each tool, so your own file stays short. `policy.dw`, beside
it, is your copy of the policy you picked. [Profiles](profiles.md) shows how to change either
file.

## 3. Choose the model

Steps 3 and 4 call AWS from this terminal. Set `REGION` to the profile's region (`us-west-2`
unless you picked another), set `AWS_PROFILE_NAME` to your AWS profile, and sign in if that
profile uses SSO or `aws login`:

```sh
REGION=us-west-2
AWS_PROFILE_NAME=your-profile
aws sso login --profile "$AWS_PROFILE_NAME"   # only if it uses SSO (for `aws login`, run `aws login --profile "$AWS_PROFILE_NAME"`)
```

If Claude Code on your machine already uses a Bedrock model ID that your account can call in this
region (`model` or `ANTHROPIC_MODEL` in `~/.claude/settings.json`, or `ANTHROPIC_MODEL` in your
shell), the box uses it, so skip to step 4. Otherwise Claude Code uses its default model, and if
your account can't call that one, Claude Code keeps retrying and the run looks stuck.

List the Claude models on Bedrock in your region:

```sh
aws bedrock list-inference-profiles --region "$REGION" --profile "$AWS_PROFILE_NAME" \
  --query "inferenceProfileSummaries[?contains(inferenceProfileId, 'anthropic')].inferenceProfileId" \
  --output text
```

Pick one your account is allowed to call (if you don't know, ask whoever runs the account) and copy
its full ID as the command prints it, such as `global.anthropic.claude-opus-5-5`. A short name such
as `opus` won't work. Then
add it to the end of `~/.strands/box/profiles/claude/profile.toml`:

```toml
[agent.env]
ANTHROPIC_MODEL = "global.anthropic.claude-opus-5-5"
```

## 4. Sign in to Bedrock

The box signs each request to Bedrock with your AWS credentials, outside the box, so the agent
never sees them. It uses the AWS identity that the AWS CLI uses in the terminal where you run
`box run`. Point it at your AWS profile and check it:

```sh
export AWS_PROFILE="$AWS_PROFILE_NAME"
aws sts get-caller-identity
```

Two different things are called a profile here. `claude` is the Box profile you made in step 2.
`AWS_PROFILE_NAME` is a profile in `~/.aws/config` or `~/.aws/credentials`.

If that AWS profile signs in with AWS IAM Identity Center (SSO) or `aws login`, the box can't read
it yet, so export its temporary keys in this terminal instead:

```sh
eval "$(aws configure export-credentials --profile "$AWS_PROFILE_NAME" --format env)"
```

The exported keys end with the sign-in session, so run this again in each new terminal and after
you sign in again. [Which AWS profiles work](profiles-reference.md#aws-credentials) is listed in the
reference.

### Use a Bedrock API key instead

To sign in with a Bedrock API key, pick `api-key` when `box profile create` asks how the box signs
in, or set it in the `[options]` table of `~/.strands/box/profiles/claude/profile.toml`:

```toml
[options]
bedrock.sign-in = "api-key"
```

A key needs the account to allow Bedrock API keys (the IAM action `bedrock:CallWithBearerToken`),
and [`uv`](https://docs.astral.sh/uv/) to run the tool that makes it. This command makes a key and
puts it in `AWS_BEARER_TOKEN_BEDROCK`, the variable the box reads it from:

```sh
export AWS_BEARER_TOKEN_BEDROCK="$(AWS_PROFILE="$AWS_PROFILE_NAME" uv run --quiet --no-project --with aws-bedrock-token-generator --with 'botocore[crt]' python -c 'import sys; from aws_bedrock_token_generator import provide_token; print(provide_token(region=sys.argv[1]))' "$REGION")"
```

A key only works in the region it was made for, so `REGION` has to match the profile's. To check
the key, run `echo "${#AWS_BEARER_TOKEN_BEDROCK}"`. You want a number in the hundreds or more. A
`0` means the command failed: read the error it printed and check the AWS profile name. The key
lasts up to 12 hours, and once it runs out, the model answers with `403` until you run the same
`export` again.

A run that has already started keeps its old sign-in, so start a new run after you change it.

## 5. Run Claude Code in a project

The agent can read and change the files in the directory where you start it, and nothing outside
it unless the profile adds it. Start it in the project you want it to work on, not in a folder that
holds keys or credentials:

```sh
cd ~/src/my-app
box run claude
```

`box` shows a loading display until Claude Code is ready, and then Claude Code starts with an
[activity banner](cli.md#the-activity-banner) below it. Press **Ctrl+]** to expand the banner.

If you already use Claude Code in this project, it goes straight to the prompt, because `box`
brings in your finished onboarding and your answer to the folder trust question. Otherwise Claude
Code asks its first-time questions: a color theme, some security notes, and whether you trust the
folder. That last one defaults to **No, exit**, so press the down arrow to pick
**Yes, I trust this folder** before you press Enter. It won't ask you to log in, since the profile
points it at Bedrock.

Claude Code starts with the permission settings from your machine, so it may ask before it edits a
file or runs a command, and the box checks each action either way.
[How Claude Code asks before it acts](../../resources/packs/claude/README.md#how-claude-code-asks-before-it-acts)
shows how to change that.

Now watch the box work. Ask Claude Code to create `hello.txt` with the word hi in it, and say yes
if it asks. The file shows up in `~/src/my-app`. Then ask Claude Code to run
`echo hi > ~/outside.txt` in its shell, and say yes if it asks. The box stops that command, and
Claude Code tells you it couldn't write the file. Press **Ctrl+]** to see the denial in the
banner. If Claude Code uses its own Write tool instead, the box stops that too, but the banner
doesn't show it ([The box](how-box-works.md#the-box) says why).

Quit Claude Code with `/exit` to end the run. `box` then shows any messages saved during the run,
and [`box runs history`](cli.md#box-runs-history) lists every decision the box made. To pick up
where you left off next time, pass Claude Code's own flag after `--`:

```sh
box run claude -- --continue
```

### If the run doesn't start

| What you see | What to do |
| --- | --- |
| `AWS default credential chain resolved no credentials` | Set `AWS_PROFILE`, or export the SSO keys, in this terminal (step 4). |
| `credential variable AWS_BEARER_TOKEN_BEDROCK is not set` | The profile signs in with a key. Make the key in this terminal ([Use a Bedrock API key instead](#use-a-bedrock-api-key-instead)). |
| Claude Code starts, but after you give it a task it says `API error` and keeps retrying | Check the model ID from step 3. |
| A `403` error from the model | Check the sign-in from step 4. With a key, make a new one, with `REGION` set to the profile's region. If that doesn't help, work through [Every model request fails with 403](../../resources/packs/bedrock/README.md#every-model-request-fails-with-403). |

## What's set up

You have a `claude` profile, and `box run claude` uses it in any project. Every new terminal finds
`box`. `AWS_PROFILE`, exported keys, and a Bedrock API key last only in the terminal that set them,
so run step 4 again in each new one.
To get a newer release, see [Upgrade or choose a version](install.md#upgrade-or-choose-a-version).

`box` keeps the profile, Claude Code's settings and history, and a record of each run in `~/.strands/box`.
[Where Box keeps its files](files.md) says what each folder holds, and which files the tools write
into your project.

## Clean up

Each run leaves a folder in `~/.strands/box/r`, and they pile up. To remove them:

```sh
box clean --all
```

```text
box: Remove 4 boxes and their records? A box that is still running is kept.

> [1] Keep (default)
    Cancel without changes.

  [2] Remove
    Delete the items listed above.
```

Choose **Remove**. The profile, and Claude Code's settings and history, stay. To start over, run
`box profile delete --all`: it asks first, then deletes every profile with its boxes and storage,
and you'll need to redo steps 2 and 3.

## Where to go next

- [How Box works](how-box-works.md): what the box, profiles, packs, and policies are, and how they
  fit together.
- [Profiles](profiles.md): give the agent another host, folder, or tool, change its
  region, or set up another agent.
- [Starters](starters.md): switch the policy, or answer the questions from
  a script.
- [Limitations](limitations.md): what a box doesn't protect you from. Read it before you trust a
  run with work that matters.
