# Use storage that arrives after Box starts

This example starts a native workload through Box Core before Amazon Bedrock AgentCore Runtime takes its initial snapshot. When Runtime later mounts storage for an invocation, the same workload reads and writes that storage through its existing sandbox.

The HTTP application compares each sandbox operation with an operation outside the sandbox, inside the Runtime container. It uses fixed file operations and needs no model access. It does not exercise the Box CLI, hosted Shell or Monty, configured tools, or local Model Context Protocol (MCP) servers.

## Prepare the image

Use Linux ARM64, Python 3.10 or later, a C compiler, Docker, and Box's [native build dependencies](../../../../README.md#build-from-source). Install `boto3` for deployment and offline request tests. The container runs as user and group `1000:1000`; configure an EFS or S3 Files access point with matching identity and write access.

Use a clean, committed checkout of the Box revision you want to test. Build all three helpers from that checkout, then run these commands from its root:

```sh
cargo build --locked -p strands-box -p strands-box-containment --all-features
python3 examples/cloud-deployments/agentcore-runtime/storage/prepare.py \
  --bin-dir target/debug --source-root . --source-revision "$(git rev-parse HEAD)" \
  --strip-debug
python3 examples/cloud-deployments/agentcore-runtime/storage/test_example.py -v
```

Preparation checks the whole tracked source tree and refuses uncommitted or untracked changes. It copies the helpers, compiles the native workload, and records the commit, tree, and file hashes in `binary-manifest.json`. `--strip-debug` removes debug information from the copies and records both binary hashes; the original build outputs remain intact. Retain the build log alongside the manifest: binary hashes alone do not prove build provenance.

Build and push the image to an existing Amazon Elastic Container Registry (ECR) repository. Set `IMAGE_URI` to a new tag in that repository. Authenticate Docker to ECR before pushing.

```sh
docker build --platform linux/arm64 -t "$IMAGE_URI" \
  examples/cloud-deployments/agentcore-runtime/storage
docker push "$IMAGE_URI"
```

## Configure one storage provider

Create a Runtime execution role that can pull from the image repository and write Runtime logs. The optional [`role.yaml`](role.yaml) CloudFormation template adds storage permissions for one provider. It references existing resources; it does not create a repository, filesystem, access point, bucket, or network.

Save this request as `runtime-request.json`, replacing the image URI, role ARN, and Runtime name. Use a new name for each deployment.

```json
{
  "agentRuntimeName": "box_storage_example",
  "agentRuntimeArtifact": {
    "containerConfiguration": {"containerUri": "123456789012.dkr.ecr.us-west-2.amazonaws.com/example:storage-example"}
  },
  "roleArn": "arn:aws:iam::123456789012:role/RuntimeStorageExample",
  "platformVersion": "V2",
  "architecture": "ARM64",
  "networkConfiguration": {"networkMode": "PUBLIC"},
  "protocolConfiguration": {"serverProtocol": "HTTP"},
  "filesystemConfigurations": [{"sessionStorage": {"mountPath": "/mnt/storage"}}]
}
```

This request uses managed session storage, which is in Preview. For another provider, replace its `filesystemConfigurations` entry:

| Provider | Entry | Additional setup |
| --- | --- | --- |
| Amazon EFS | `{"efsAccessPoint":{"accessPointArn":"EFS_ACCESS_POINT_ARN","mountPath":"/mnt/storage"}}` | Use VPC networking, an accessible mount target, matching user/group identity, and execution-role permissions to mount and write. |
| Amazon S3 Files | `{"s3FilesAccessPoint":{"accessPointArn":"S3_FILES_ACCESS_POINT_ARN","mountPath":"/mnt/storage"}}` | Use VPC networking, an accessible mount target, matching user/group identity, and S3 Files execution-role permissions. This provider uses Network File System (NFS). |
| Amazon S3 bucket | `{"s3BucketMount":{"bucket":"amzn-s3-demo-bucket","prefix":"box-example/{runtimeSessionId}/","mountPath":"/mnt/storage"}}` | Grant list, read, and write access to the prefix. This provider uses Mountpoint for Amazon S3 and supports public networking. |

For EFS and S3 Files, replace `networkConfiguration` with:

```json
{
  "networkMode": "VPC",
  "networkModeConfig": {
    "subnets": ["subnet-REPLACE"],
    "securityGroups": ["sg-REPLACE"]
  }
}
```

Follow the [Runtime filesystem guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html) for access-point permissions, mount-target availability, and TCP port 2049 rules. With `role.yaml`, select `StorageType=EFS` or `S3Files` and supply the filesystem and access-point ARNs. For a bucket, select `StorageType=Bucket`, set `BucketName`, and set `BucketPrefix=box-example/`. That role allows the whole example prefix; it does not enforce a separate IAM boundary for each Runtime session. The AWS guide shows session-scoped IAM policies.

## Create and invoke the Runtime

Run these commands from this example directory. Set `REGION` and keep every receipt. Add the script's global `--profile` argument if needed.

```sh
mkdir -p receipts
python3 deploy.py --region "$REGION" create \
  --request runtime-request.json --receipt receipts/runtime.json
python3 deploy.py --region "$REGION" status --receipt receipts/runtime.json
```

Wait for the reported Runtime status to become `READY` before invoking. Re-run `status` to observe progress. A failure during initialization includes Box's startup error in the Runtime logs.

The application records the initial mount layout and starts Box before opening its HTTP listener. Startup refuses an ordinary directory, a disconnected mountpoint, or a provider that is already mounted. The example does not create a substitute mount or wait until invocation to start Box. A successful `/ping` therefore requires the sandbox workload to have started first.

```sh
SESSION_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
python3 deploy.py --region "$REGION" invoke --receipt receipts/runtime.json \
  --session-id "$SESSION_ID" --output receipts/first.json
```

A successful result has `result.status` equal to `PASS`. Read its five cases:

- A Runtime-created marker becomes readable inside the existing sandbox.
- A sandbox-created file becomes readable outside it.
- An executable memory mapping has the same result inside and outside. The example does not execute the mapped bytes.
- An ordinary read grant still permits its file.
- An unrelated denied directory remains inaccessible inside the sandbox while the Runtime control can read it.

Each response includes the original workload identity, the initial and current mount records, operation results, and binary manifest. `UNQUALIFIED` means the required provider arrival or writable fixture was absent. It is not a passing restriction test. The script returns a nonzero exit code for an unsuccessful run and preserves its receipt.

To check persistence, stop the Runtime session and invoke the same session ID again:

```sh
python3 deploy.py --region "$REGION" stop --receipt receipts/runtime.json --session-id "$SESSION_ID"
python3 deploy.py --region "$REGION" invoke --receipt receipts/runtime.json \
  --session-id "$SESSION_ID" --operation read --previous receipts/first.json \
  --output receipts/resumed.json
```

The resumed invocation reads the earlier generated file. Its workload identity proves continuity within that restored instance, not that the compute instance survived the stop. Snapshot-created identities can repeat across restored instances.

## Understand the storage grant

The generated Core configuration selects `/mnt/storage` in `[agent.filesystem].receive_mounts` and grants the whole directory read, write, and execution access. The selection itself grants no access. Box requires compatible grants and connects incoming mounts without a background watcher.

Future mounts retain the provider's options. Box does not add read-only or no-execution restrictions to future mounts, or mask selected subdirectories. This example compares executable mapping outcomes but requires writable storage to create its fixtures. It does not qualify a read-only provider.

S3 bucket operations here use new files and sequential writes, with no appends, in-place updates, or renames. Managed session storage records permission metadata but does not enforce those permission bits; this example makes no `chmod` enforcement claim.

The offline tests check configuration, startup ordering, request receipts, native file operations, and SDK request construction. They intercept HTTP sends and make no AWS calls. Older SDK models omit some documented Runtime fields, so `deploy.py` inserts only its validated V2, ARM64, and filesystem fields before the SDK signs one create request. AWS still validates the request. A successful offline run does not qualify Runtime, Box's mount behavior, other architectures, or macOS.

## Clean up

Stop each Runtime session you created, then delete only the Runtime identified by its creation receipt:

```sh
python3 deploy.py --region "$REGION" stop --receipt receipts/runtime.json --session-id "$SESSION_ID"
python3 deploy.py --region "$REGION" delete --receipt receipts/runtime.json
```

The helper preserves the borrowed image repository, execution role, VPC, access points, filesystems, and bucket. Remove an image or CloudFormation role stack separately only if you created it for this run. The storage tests leave a unique `box-example-<id>` directory for the persistence check. Its path appears in the result; remove only that run's generated files when you no longer need them. Do not recursively remove the selected storage root.

If creation fails before confirmation, retain the pending receipt and check its Runtime name and client token before retrying. The helper refuses resource actions from an unconfirmed receipt to avoid losing track of a possibly created Runtime.
