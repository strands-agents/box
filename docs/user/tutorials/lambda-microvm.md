# Run Box on Lambda MicroVM

This tutorial packages Box in a Lambda MicroVM image and runs a repair workload under a Box policy.
An optional Claude Code exercise sends the same repair and refusal instructions to a real agent.
Use the [runnable example](../../../examples/lambda-microvm/) from a complete repository checkout.

The example uses Amazon Linux 2023 on ARM64, operator user ID (UID) 0, and the `ALL` capability setting.
It grants explicit access to system libraries.
These are the tested settings, not a minimum-permission configuration.

## Before you start

Use an AWS account with access to the Lambda MicroVM APIs in `us-east-1`.
This example uses those APIs directly, not a Lambda function.
For managed code or container deployment on AgentCore Runtime, use the [Runtime tutorial](agentcore-runtime.md).

Install Python 3.11 or later and `uv`.
Configure an AWS profile for your development account.
The deployment needs permission to create CloudFormation stacks, IAM roles, S3 storage, logs, and Lambda MicroVM images and instances.
The caller must also pass the generated build and execution roles.
For Claude, enable access to the `us.anthropic.claude-sonnet-4-6` inference profile in `us-west-2`.

Obtain a Linux ARM64 Box package and its build receipt.
The receipt must supply the archive's SHA-256 digest and full source revision.
The archive must contain an executable `box` at its root, with its packaged helpers.
The preparation step refuses a wrong digest, wrong architecture, archive links, or paths outside the extraction directory.

The example downloads Claude Code 2.1.305 from its pinned package URL and verifies its SHA-512 digest.
You can supply that same archive with `--claude-package`.
The image builder uses the Dockerfile in the example, so this path does not require local Docker.

## Deploy and run

Run this command from the repository root.
Replace the account, profile, package path, digest, and source revision with your values.

```sh
uv run --with boto3==1.42.61 python examples/lambda-microvm/demo.py \
  --account 123456789012 \
  --profile dev \
  --name box-lambda-example \
  --box-package /absolute/path/box-linux-arm64.tar.gz \
  --box-sha256 YOUR_VERIFIED_ARCHIVE_SHA256 \
  --box-revision YOUR_FULL_SOURCE_REVISION \
  --exercise
```

The command checks the selected account before it changes AWS resources.
CloudFormation creates retained artifact storage, a log group, a build role, and an execution role.
Stack termination protection stays enabled.
The build role reads the source archive.
The execution role permits the selected Bedrock model and bearer authentication.

The runner uploads a checksum-addressed source archive and builds an image from Amazon Linux base image version 2.
It starts a 4096 MiB ARM64 instance from the exact resulting image version.
It verifies the source fingerprint, Box package, Box executable digest, architecture, and operator UID before it starts the workload.

Example output:

```text
Evidence: .../examples/lambda-microvm/results/<run>
Fixed workload: 11 checks passed.
Claude exercise: 10 checks passed.
Cloud resources remain retained. Instances have an eight-hour service lifetime.
This profile uses operator UID 0, ALL capabilities, and explicit library grants.
```

Omit `--exercise` to run only the fixed workload.
Each deployment creates a new image version and instance.
Use `--target` for another workload on an existing instance.

## What the workload verifies

The fixed workload reads coding instructions and repairs `add(a, b)` through Strands Shell, the shell implementation that applies Box policy.
Independent arithmetic checks verify the repaired function.
The workload also attempts direct access to a private file and a write to a read-only file.
Box must refuse both operations.

Separate shell calls attempt a private-file read, a protected-file deletion, and a request to `example.com`.
The verifier requires matching refusal records and unchanged protected files.
An operator control first confirms that the surrounding operating system can access those files.
This distinguishes Box refusals from ordinary file permissions.

With `--exercise`, the runner supplies startup instructions to Claude Code.
Claude must repair the function through Bash and attempt each of the three policy refusals.
The verifier checks the repaired source, model request, file effects, exit status, and policy records.
The command collects all terminal output pages before it accepts completion.

This Claude exercise uses Bash.
It does not cover the native file tools or Model Context Protocol (MCP) exercise in the Runtime example.
The command runs Claude in batch mode.
It does not open a local interactive terminal.

## Inspect the configuration and evidence

Each run writes a separate directory under `examples/lambda-microvm/results/`.
The directory contains the exact target, image request, build result, and application identity.
The `fixed/` directory contains the generated `box.toml`, policy, operation output, checks, and protected-file digests in `result.json`.
The `claude/` directory contains the workload identifier, terminal output, final checks, and policy audit records.

The application composes the agent's environment.
Claude receives no copied local authentication files.
The trusted process obtains a short-lived Bedrock token from its execution role and supplies it to Box's egress configuration.
The client keeps Lambda authentication headers in memory.
It does not save those headers with the evidence.

The fixed workload grants direct reads of system libraries and the reference file.
It grants no direct project writes.
Claude can read its project and write its own state and temporary directory.
Its Bash repair uses policy-mediated writes.
See [filesystem grants](../config.md) and [egress configuration](../egress.md) for these two controls.

## Reuse an instance

Use the exact `target.json` from the first run.
The runner refuses a different account, region, image version, package, or source fingerprint.

```sh
uv run --with boto3==1.42.61 python examples/lambda-microvm/demo.py \
  --account 123456789012 \
  --profile dev \
  --target examples/lambda-microvm/results/RUN_DIRECTORY/target.json \
  --exercise
```

The runner resumes a suspended instance before it checks the application.
Each invocation creates fresh workload directories and a new Claude workload identifier.
It does not resume a previous Claude conversation.
An expired instance requires another deployment.

## Retention and limits

The runner does not delete cloud resources.
The stack retains storage, roles, and logs even if you later remove the stack.
Images and source archives also remain.
Log events expire after 30 days.
Instances have an eight-hour maximum lifetime and can suspend after 15 idle minutes.
Retained resources can incur charges.

Use a new `--name` for an independent deployment.
The runner refuses a changed infrastructure template or an image owned by different build infrastructure.
It does not replace those resources automatically.

The tested Box baseline leaves descendants running after forced termination of its trusted process.
The workload checks do not establish cancellation, timeout cleanup, or combined Linux release qualification.
Reusing an instance does not prove that an active agent survives suspension.
