# Use experimental storage mounts on AgentCore Runtime

Box can start a workload before Amazon Bedrock AgentCore Runtime attaches storage, then expose the mounted files with the workload's filesystem restrictions. The `linux-storage-mounts` setting enables this experimental Linux feature. The [storage example](../../examples/cloud-deployments/agentcore-runtime/storage/) runs a small file-operation workload so you can check the setup without model access.

The example starts Box before opening the Runtime HTTP listener. Runtime can snapshot that running process and attach storage when it restores a session. The existing sandbox receives the protected storage view; the HTTP wrapper does not postpone Box startup until invocation.

## Before you start

Use a Linux ARM64 build machine with Docker, a C compiler, Python 3.10 or later, and the repository's Rust toolchain and native build dependencies. Use a source checkout that contains `linux-storage-mounts` and this example. Keep every Box helper from that same build together. A released package that lacks the setting cannot run the example.

Use an AWS account with AgentCore Runtime platform V2 and managed session storage in your chosen Region. The deployment commands need AWS CLI credentials that can push an image to Amazon Elastic Container Registry (ECR), create the example's AWS Identity and Access Management (IAM) role through CloudFormation, pass that role to Runtime, and create, inspect, invoke, stop, and delete the test runtime. Use an existing ECR repository in the same account and Region. This example uses container user ID zero; it does not establish support for a non-root Runtime image.

Deployment incurs AWS charges. Use a dedicated runtime, CloudFormation stack, and image tag, then follow [Remove the example](#remove-the-example). The optional S3 bucket procedure also requires a dedicated, empty object prefix.

## Configure an existing agent

In the Box CLI's `profile.toml`, add the feature flag and the storage paths to the processes that need them. This fragment extends an already configured agent:

```toml
[experimental-features]
linux-storage-mounts = true

[agent.filesystem]
mounts = ["/mnt/storage"]
read = ["/mnt/storage"]
```

For Box Core, use the same tables in `box.toml`. The example generates a complete Core configuration with a configured workload and its startup dependencies. The CLI composes Core configuration from a profile; these are different files, not two required copies of the setting.

`mounts` selects incoming storage and grants no access by itself. Add `write`, `read_file`, `write_file`, `exec`, `deny`, or `deny_write` only as your workload needs them. Keep any stronger source filesystem or IAM restrictions. Box cannot make a read-only source writable. A directory write grant on Linux requires a covering read grant. An `exec` grant concerns direct program execution; it does not stop an allowed interpreter from reading a script.

For several Runtime mounts, list each exact attachment path in `mounts`. Add separate lists under `[tool.<name>.filesystem]` and `[mcp.<name>.filesystem]` for configured tools and local Model Context Protocol (MCP) servers. They do not inherit the agent's lists. Hosted Strands Shell and Python (Monty) use the agent's protected storage view and also require the corresponding `fs:*` policy permission.

The CLI's `[storage] directories` creates persistent directories that the CLI owns. It does not configure Runtime storage. Use `filesystem.mounts` for externally mounted paths. Packs can contribute mount paths, but only the profile can enable the experimental flag. See the [profile reference](profiles-reference.md#incoming-linux-storage) and [Core configuration reference](../user/config.md#filesystemmounts) for merge rules and refusals.

Create each declared attachment directory in the image before Box starts. Keep the executable, its interpreter, and its initial working directory outside storage that has not arrived. An already running application must retry unavailable file operations while Box prepares the protected view. This feature adds no Runtime readiness handshake. Required permission paths must exist when Box admits the source; an unenforceable required rule stops that Box instance. Mount replacement, removal, and additional mounts beneath an admitted root are outside this experiment's guarantees.

## Build the example image

Run these commands from the repository root on Linux ARM64. The explicit binary list includes the storage compiler used to prepare restricted views:

```sh
cargo build --locked --all-features \
  -p strands-box -p strands-box-containment \
  --bin strands-box --bin strands-box-sock-alias \
  --bin strands-box-contain-trampoline --bin strands-box-storage-compiler
python3 examples/cloud-deployments/agentcore-runtime/storage/prepare.py \
  --bin-dir "$(pwd)/target/debug" --source-revision "$(git rev-parse HEAD)"
docker build --platform linux/arm64 -t box-runtime-storage:example \
  examples/cloud-deployments/agentcore-runtime/storage
```

The preparation step copies matching binaries, records the source revision you supply, and builds the example workload. That revision field is a build record; binary hashes alone do not prove which source produced them. The image runs as user ID zero. It starts a single Box before listening on port 8080 and uses `/mnt/storage` as the incoming storage path. It does not run a Filesystem in Userspace (FUSE) service or require `/dev/fuse` inside the workload; Runtime supplies the filesystem.

You can first check the delayed-mount sequence in a disposable local container:

```sh
python3 examples/cloud-deployments/agentcore-runtime/storage/verify-local.py \
  --image box-runtime-storage:example --output /tmp/box-storage-local-evidence
```

This local check uses a privileged container to create its test mount. That privilege belongs to the local mounting fixture; it is not a Runtime deployment parameter.

## Publish the image and create its execution role

Set these values for your account. `REPOSITORY` is an existing repository name, not a full URI. Use a new `RUN` value for each deployment:

```sh
export AWS_REGION=us-west-2
export REPOSITORY=YOUR_EXISTING_ECR_REPOSITORY
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export RUN_SUFFIX=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
export RUN=box_storage_${RUN_SUFFIX}
export STACK_NAME=box-storage-${RUN_SUFFIX}
export IMAGE_TAG=${RUN}
export IMAGE_URI=${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPOSITORY}:${IMAGE_TAG}
export EXAMPLE=examples/cloud-deployments/agentcore-runtime/storage
export RECEIPTS=/tmp/${RUN}
mkdir -p "${RECEIPTS}"
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin \
  "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
docker tag box-runtime-storage:example "${IMAGE_URI}"
docker push "${IMAGE_URI}"
aws cloudformation deploy --region "${AWS_REGION}" \
  --template-file "${EXAMPLE}/role.yaml" --stack-name "${STACK_NAME}" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
  RepositoryArn=arn:aws:ecr:${AWS_REGION}:${ACCOUNT_ID}:repository/${REPOSITORY}
export ROLE_ARN=$(aws cloudformation describe-stacks --region "${AWS_REGION}" \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue | [0]' --output text)
```

The role trusts the AgentCore service for runtimes in your account and Region. It permits image downloads from the named repository and writes to Runtime log groups. Managed session storage needs no customer bucket permission in this template. The commands use standard AWS Region endpoints; adapt the partition and registry address before using another AWS partition.

## Create a managed-storage runtime

Install the deployment dependency in a virtual environment:

```sh
python3 -m venv "${RECEIPTS}/venv"
"${RECEIPTS}/venv/bin/pip" install boto3==1.42.72
```

Generate the create request from your values:

```sh
python3 - <<'PYTHON'
import json, os, pathlib, uuid
request = {
    "agentRuntimeName": os.environ["RUN"],
    "agentRuntimeArtifact": {"containerConfiguration": {
        "containerUri": os.environ["IMAGE_URI"]}},
    "roleArn": os.environ["ROLE_ARN"],
    "networkConfiguration": {"networkMode": "PUBLIC"},
    "protocolConfiguration": {"serverProtocol": "HTTP"},
    "platformVersion": "V2",
    "filesystemConfigurations": [{"sessionStorage": {"mountPath": "/mnt/storage"}}],
    "environmentVariables": {"STORAGE_PATH": "/mnt/storage"},
    "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 300, "maxLifetime": 1800},
    "clientToken": str(uuid.uuid4()),
    "description": "Experimental Box storage example"
}
pathlib.Path(os.environ["RECEIPTS"], "create.json").write_text(json.dumps(request, indent=2))
PYTHON
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" create \
  --request "${RECEIPTS}/create.json" --receipt "${RECEIPTS}/runtime.json"
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" status \
  --receipt "${RECEIPTS}/runtime.json"
```

Repeat `status` until Runtime reports `READY`. If it reports `CREATE_FAILED`, inspect `failureReason` before invoking. Confirm that the response retains `platformVersion: V2` and the `/mnt/storage` filesystem configuration. The image is ARM64; the request does not rely on an undocumented `architecture` field.

The helper signs the control API request directly because some SDK models omit `platformVersion` or `filesystemConfigurations`. It still uses your normal credential provider and the service's validation. It does not bypass account permissions or make an unavailable storage type available. See the [Runtime filesystem configuration guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html) for current service availability and the [create API](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html) for request fields.

## Invoke and inspect the result

Use a new session ID for the first invocation:

```sh
export SESSION_ID=${RUN}-$(python3 -c 'import uuid; print(uuid.uuid4())')
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" invoke \
  --receipt "${RECEIPTS}/runtime.json" --session-id "${SESSION_ID}" \
  > "${RECEIPTS}/invocation.json"
cat "${RECEIPTS}/invocation.json"
```

A successful response contains `"status": "PASS"`. Read its individual checks as well. The example requires evidence that the workload started before the provider mount, that the same workload later reads the mounted marker, and that a source-writable location remains unwritable through the workload's read-only view. Outside mounted storage, it also checks an ordinary allowed path and an explicitly denied child path. If the deployment started with storage already present, it must not count that as delayed-mount coverage.

The trusted HTTP wrapper creates the marker on mounted storage. The sandboxed workload performs the reported file operations. Its process identity must remain the same across arrival; restarting Box after invocation would test a different order.

The example is a setup check. It does not cover every filesystem list, hosted tools, configured tools, or local MCP servers. Use the project's broader storage tests when changing those contracts. Do not treat an operation that the source filesystem already refuses as proof of Box enforcement.

## Try the tested S3 bucket mount

The earlier Runtime campaign also exercised a FUSE filesystem whose source was `mountpoint-s3`, using `s3BucketMount`. This is different from the `s3FilesAccessPoint` interface in the public filesystem guide. Use this procedure only if the Runtime team confirms that `s3BucketMount` is available to your account and Region. A rejection is an availability limit, not a reason to substitute S3 Files and claim the same test.

Use a dedicated empty prefix ending in `/`, and a bucket in the same Region. This example's optional role grants do not include access to a customer-managed encryption key. Keep a separate S3 runtime, role stack, and receipt:

```sh
export S3_BUCKET=YOUR_BUCKET
export S3_PREFIX=box-storage-example/${RUN}/
export S3_STACK_NAME=${STACK_NAME}-s3
aws cloudformation deploy --region "${AWS_REGION}" \
  --template-file "${EXAMPLE}/role.yaml" --stack-name "${S3_STACK_NAME}" \
  --capabilities CAPABILITY_IAM --parameter-overrides \
  RepositoryArn=arn:aws:ecr:${AWS_REGION}:${ACCOUNT_ID}:repository/${REPOSITORY} \
  BucketName=${S3_BUCKET} BucketPrefix=${S3_PREFIX}
export S3_ROLE_ARN=$(aws cloudformation describe-stacks --region "${AWS_REGION}" \
  --stack-name "${S3_STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue | [0]' --output text)
python3 - <<'PYTHON'
import json, os, pathlib, uuid
root = pathlib.Path(os.environ["RECEIPTS"])
request = json.loads((root / "create.json").read_text())
request.update(agentRuntimeName=os.environ["RUN"] + "_s3",
               roleArn=os.environ["S3_ROLE_ARN"], clientToken=str(uuid.uuid4()))
request["filesystemConfigurations"] = [{"s3BucketMount": {
    "bucket": os.environ["S3_BUCKET"], "prefix": os.environ["S3_PREFIX"],
    "mountPath": "/mnt/storage", "s3BucketRegion": os.environ["AWS_REGION"]}}]
(root / "s3-create.json").write_text(json.dumps(request, indent=2))
PYTHON
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" create \
  --request "${RECEIPTS}/s3-create.json" --receipt "${RECEIPTS}/s3-runtime.json"
```

Repeat the status and invocation commands with `s3-runtime.json` and a fresh session ID saved as `S3_SESSION_ID`. Confirm the observed provider in the invocation result. Keep the managed-storage receipt separate. A fixed S3 prefix is shared by sessions that select it; it does not have managed session storage's per-session isolation.

The earlier S3 run could not qualify two execution-denial checks or two append checks because matching unboxed source operations also failed. Those results do not prove Box denied the operations. Creating a file and overwriting it are separate operations from appending. This reduced read-only example makes no execution or append claim.

## Troubleshoot

| Observation | Check |
| --- | --- |
| Creation fails and the receipt says `PENDING`. | Keep the receipt and inspect the recorded runtime name and request token before retrying. Creation might have succeeded even if the response was lost; do not create another runtime blindly. |
| Box rejects `linux-storage-mounts` or a helper is missing. | Build all listed binaries from the same source checkout and copy them together. |
| Runtime creates the container but never becomes healthy. | Inspect its logs for Box startup failure. Keep the configured program and working directory outside pending storage. |
| Invocation cannot read the marker. | Check the provider mount, declared path, matching read grant, and the workload's continued process identity. Retrying is appropriate while protection is being prepared; a terminated Box needs its reported error fixed. |
| A required path prevents admission. | Ensure required permission and denial paths exist in the incoming filesystem. Avoid wildcard expansion or optional entries that disappear before arrival. |
| A denied operation also fails outside Box. | Treat it as an unqualified control and choose an operation that the source permits. |
| Box shutdown exceeds three seconds. | Keep the exit code and process observations. Recorded successful Runtime shutdowns sometimes took about ten seconds; a three-second harness deadline is not a product limit. |

## Remove the example

Stop the session, delete the dedicated runtime, and wait until `status` reports that the runtime no longer exists:

```sh
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" stop \
  --receipt "${RECEIPTS}/runtime.json" --session-id "${SESSION_ID}"
"${RECEIPTS}/venv/bin/python" "${EXAMPLE}/deploy.py" --region "${AWS_REGION}" delete \
  --receipt "${RECEIPTS}/runtime.json"
```

If you also created the optional S3 runtime, stop it with `--receipt "${RECEIPTS}/s3-runtime.json" --session-id "${S3_SESSION_ID}"`, delete it with that receipt, and wait for deletion. Delete its role stack named by `S3_STACK_NAME` after the runtime is gone. Use `aws s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}" --recursive` to inspect its dedicated prefix, then remove only that prefix's example objects. Do not delete a caller-owned bucket.

Then delete the managed example's role stack and the image tag after both runtimes are gone:

```sh
aws cloudformation delete-stack --region "${AWS_REGION}" --stack-name "${STACK_NAME}"
aws cloudformation wait stack-delete-complete --region "${AWS_REGION}" --stack-name "${STACK_NAME}"
aws ecr batch-delete-image --region "${AWS_REGION}" --repository-name "${REPOSITORY}" \
  --image-ids imageTag="${IMAGE_TAG}"
docker image rm "${IMAGE_URI}" box-runtime-storage:example
```

Keep the receipts you need before removing local build outputs. The commands retain the caller-owned ECR repository and S3 bucket. For the optional S3 test, remove only the marker objects in its dedicated prefix. Inspect the runtime's log group separately and delete it if you do not need the logs.
