# Run Box on Amazon EKS

Amazon Elastic Kubernetes Service (EKS) runs these Box workloads as Kubernetes Jobs.
Start with the fixed script to check project changes and protected-file refusals.
Then run Claude Code against a mock deployment service to see Box block retries after repeated failures.

## Before you start

Use an EKS cluster with Linux ARM64 workers and pod user namespaces.
ARM64 is the 64-bit Arm processor architecture.
The worker and admission settings must permit `hostUsers: false`, `procMount: Unmasked`, and `seccompProfile: Unconfined`.
These settings relax the outer container's restrictions so Box can create its own sandboxes.
The workload runs as user 991, drops capabilities, and disables privilege escalation.

Install Docker with an ARM64 builder, Python 3, and `kubectl`.
Authenticate to a container registry that you can push to and your workers can pull from.
Configure `kubectl` for your cluster. The [EKS connection guide](https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html) explains that step.
Cluster and registry usage can incur charges.

The [sample README](../../../examples/cloud-deployments/eks/README.md#tested-configuration) lists the Box revision, platform versions, and results for each example.
The coding and deployment examples passed on EKS, including checks through the full ten-minute cooldown.
Test the deployment example on your cluster. The recorded versions are tested configurations, not minimum requirements.

## Cluster baseline

Use the recorded configuration as a starting point: Kubernetes 1.35, Amazon Linux 2023 ARM64 workers,
Linux kernel 6.12.111, and containerd 2.3.5. These versions describe the tested combination, not the
minimum supported versions. Check the control plane and workers separately; upgrading the control
plane does not establish that the workers can run this example.

```sh
kubectl version -o yaml
kubectl get nodes -o custom-columns='NAME:.metadata.name,KUBELET:.status.nodeInfo.kubeletVersion,KERNEL:.status.nodeInfo.kernelVersion,RUNTIME:.status.nodeInfo.containerRuntimeVersion,ARCH:.status.nodeInfo.architecture'
```

The cluster must preserve and implement these settings:

| Setting | Requirement |
| --- | --- |
| Pod `hostUsers: false` | Pod user namespaces isolate the container's user IDs from the node's IDs. The API server, kubelet, container runtime, and worker filesystems must support them. |
| Container `procMount: Unmasked` | The outer container must leave `/proc` unmasked so Box can mount the process-information filesystem in its own sandbox. |
| Container `seccompProfile.type: Unconfined` | The outer container must permit the Linux system calls Box uses to create its sandbox. |
| Admission rules | The namespace's Pod Security settings and any custom admission rules must permit these settings. Permission to create a Job alone does not establish this. |

Kubernetes 1.31 has separate feature gates, `UserNamespacesSupport` and `ProcMountType`, for the first
two settings. A feature gate is a switch that enables a Kubernetes feature. When these API-server
gates are disabled, Kubernetes can remove `hostUsers` or replace `procMount` with `Default` instead
of rejecting the request. Both features became enabled by default in upstream Kubernetes 1.33.
That default alone does not verify an EKS cluster's worker or admission configuration.

For an older cluster, use a compatible cluster and worker configuration before running this example.
Changing only `spec.kubelet.config.featureGates.UserNamespacesSupport` in an AL2023 node launch
template does not enable an API-server feature or `ProcMountType`. This guide does not provide a
validated older-cluster opt-in procedure. Do not treat a nonzero
`/proc/sys/user/max_user_namespaces` as proof of pod user namespace support: the runtime and mounted
filesystems also need support. See the [Kubernetes user namespace requirements](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
and [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

Before creating a Job, `run.py` sends a server-side dry run and checks the returned settings.
A dry run uses the API server's validation and admission path without saving the Job.
The operator therefore needs permission to create Jobs even for this check.
If Kubernetes removes a required setting, the script exits with a configuration error and creates no Job:

```text
The cluster did not preserve required Box settings in the server dry-run Job; no Job was created:
  hostUsers: expected false; received null
  procMount: expected Unmasked; received "Default"
```

The script prints warnings returned by the dry run. It also checks the created Job and its Pods,
because Pod admission can differ from Job admission. Before it first observes a Pod, it reads that Job's
`FailedCreate` events and reports the controller's message, including admission rejections.
The operator needs permission to list namespace events for this diagnostic. If the event query
fails, the script prints a warning, saves the error, and continues its bounded wait.
Pod-creation events are warnings: quota exhaustion, webhook outages, and admission rules can change
while the controller retries. The script keeps waiting and accepts a later valid Pod. If the Job fails
before creating a Pod or the wait expires, the failed receipt includes the last creation error.
A configuration mismatch also produces a failed receipt and a recovery command.
It leaves the Job available for inspection and cleanup. A Pod might already have started before
this later check; this diagnostic is not a security boundary. A successful check confirms only
that the settings were preserved. The workload must still start and pass its checks.

## Build the image

Clone the repository and enter the sample directory:

```sh
git clone https://github.com/strands-agents/box.git
cd box/examples/cloud-deployments/eks
export IMAGE='YOUR_REGISTRY/box-example:scripted'
export NAMESPACE='box-example'
export KUBE_CONTEXT='YOUR_KUBERNETES_CONTEXT'
docker build --platform linux/arm64 --target scripted -t "$IMAGE" .
docker push "$IMAGE"
```

The Dockerfile fetches and builds the pinned Box source.
Build dependencies remain in the build stage. The runtime image contains Box, Python, Bash, and the exercise.
Record the pushed image digest. For repeated runs, set `IMAGE` to that immutable digest.

## Submit the Job

Inspect the generated Job before submitting it:

```sh
python3 run.py --image "$IMAGE" --namespace "$NAMESPACE" --render
```

The output is a Job document with one workload container and an ARM64 node selector.
The fixed script requires no model access or workload role.

```sh
kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" --dry-run=client -o yaml | \
  kubectl --context "$KUBE_CONTEXT" apply -f -
python3 run.py --image "$IMAGE" --namespace "$NAMESPACE" --context "$KUBE_CONTEXT"
```

The runner checks the server dry run, creates a Job, verifies its Pod settings, and waits for completion.
It saves logs and a receipt under `evidence/JOB_NAME/`.
`pod-configuration.json` preserves the last Pod configuration checked during polling.
A successful receipt contains `passed: true` and 11 successful checks.
A failed workload or missing result returns a nonzero exit code.
If polling fails after submission, the runner saves an incomplete receipt and prints the command to inspect the existing Job.
The Job can continue running. Use its recorded name for inspection and cleanup.

## Read the result

The workload corrects `add(a, b)` through Box's shell.
An independent check verifies three arithmetic cases and the exact resulting source.
The remaining checks compare policy decisions, native access results, and protected-file hashes.

| Operation | Expected result |
| --- | --- |
| Read and change project files through Box's shell | Permitted. |
| Read the private fixture directly or through the shell | Refused. |
| Change the read-only reference file | Refused. |
| Delete the protected project file | Refused by policy. |
| Request `https://example.com/` | Refused by policy. |

Use `receipt.json` for the outcome and `stdout.json` for individual checks.
Use `pods.json` and `stderr.txt` to diagnose startup or admission failures.
A client error alone does not establish a policy refusal. The verifier also checks the decision records.

<a id="run-claude-code"></a>
## Run Claude Code

Claude Code uses an Amazon Bedrock model. Its tools send requests to a mock deployment service for a checkout application.
The service simulates deployment failures. It does not deploy application code.
After three failed responses within five minutes, Box blocks deployment retries for ten minutes. This pause is the cooldown.
The agent can still check deployment status.

The agent uses Model Context Protocol (MCP) to call `deploy_checkout` and `deployment_status`.
Box checks their HTTP requests before forwarding permitted requests to the mock service.
Use `us-west-2` and access to the selected `us.anthropic.claude-sonnet-4-6` inference profile.
The dedicated workload role grants invocation access to the selected model and the account's default Bedrock project.
It also grants `bedrock:CallWithBearerToken` for the temporary token.

Use EKS Pod Identity to connect the role to a separate Kubernetes service account.
The trusted controller obtains credentials outside the agent's sandbox and generates a short-lived Bedrock token.
Box inserts the token into permitted model requests. The agent receives a substitute value.
Direct credential retrieval from inside the agent's sandbox requires separate validation.

```sh
export AWS_REGION='us-west-2'
export CLUSTER_NAME='YOUR_CLUSTER'
export SERVICE_ACCOUNT='box-example'
export IDENTITY_STACK='BoxExamplePodIdentity'
export CLAUDE_IMAGE='YOUR_REGISTRY/box-example:claude'
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" create serviceaccount "$SERVICE_ACCOUNT"
aws cloudformation deploy --region "$AWS_REGION" --stack-name "$IDENTITY_STACK" \
  --template-file pod-identity.json --capabilities CAPABILITY_IAM \
  --parameter-overrides ClusterName="$CLUSTER_NAME" Namespace="$NAMESPACE" \
    ServiceAccount="$SERVICE_ACCOUNT" InstallAgent=false
docker build --platform linux/arm64 --target claude -t "$CLAUDE_IMAGE" .
docker push "$CLAUDE_IMAGE"
python3 run.py --mode claude --exercise deployment-cooldown \
  --image "$CLAUDE_IMAGE" --namespace "$NAMESPACE" --context "$KUBE_CONTEXT" \
  --service-account "$SERVICE_ACCOUNT" --region "$AWS_REGION" \
  --model us.anthropic.claude-sonnet-4-6
```

`InstallAgent=false` uses an existing Pod Identity Agent addon.
If your cluster lacks that addon, use `InstallAgent=true` and a compatible `AgentVersion` parameter.
Follow the [Pod Identity setup requirements](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html), including the worker's permission to assume pod identities.
The trusted controller needs network access to the AWS endpoints used for credentials and model calls.

The runner selects `deployment-cooldown` by default for Claude and records the selected example in `receipt.json`.
A successful result contains `passed: true`.
The test checks for three failed deployments, at least two blocked retries, and a successful status check after the failures.
The mock service returns HTTP 503 (service unavailable) for its first three deployment requests and HTTP 201 (created) afterward.
Box enforces the cooldown.

The agent finishes after those checks. It does not wait for the cooldown to end.
Run the [test without a model](../../../examples/cloud-deployments/eks/claude/README.md#check-cooldown-expiry-without-a-model) to check that deployment becomes available again.
That test waits through the full ten-minute cooldown and checks that Box permits the next deployment request.
The supplied client makes sequential calls within one box. Requests already in flight and activity in other boxes remain outside this limit.
Model responses can vary. Check `receipt.json` for the test result, even if the agent reports success.

To run the coding and file-permission example, select `boundaries`:

```sh
python3 run.py --mode claude --exercise boundaries \
  --image "$CLAUDE_IMAGE" --namespace "$NAMESPACE" --context "$KUBE_CONTEXT" \
  --service-account "$SERVICE_ACCOUNT" --region "$AWS_REGION" \
  --model us.anthropic.claude-sonnet-4-6
```

Its expected result is `passed: true` with 23 successful checks.

## Clean up

Use the Job name printed by the runner:

```sh
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" delete job JOB_NAME_FROM_RECEIPT
```

Repeat for each example Job you created.
If you created the optional identity stack, delete it after its Jobs finish:

```sh
aws cloudformation delete-stack --region "$AWS_REGION" --stack-name "$IDENTITY_STACK"
aws cloudformation wait stack-delete-complete --region "$AWS_REGION" --stack-name "$IDENTITY_STACK"
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" delete serviceaccount "$SERVICE_ACCOUNT"
```

Delete the example images through your registry's image-management tools when you finish.
Retain shared cluster resources and any existing Pod Identity addon.
