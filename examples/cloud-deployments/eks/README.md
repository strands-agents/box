# Run a workload on EKS

This example runs a workload in an Amazon Elastic Kubernetes Service (EKS) Job with Box inside its container.
The fixed script changes project files while Box protects selected files.
The Claude Code example sends deployment requests to a mock service.
Box blocks retries after repeated failures while status checks remain available.

Follow the [full build guide](../../../docs/user/tutorials/eks.md) for prerequisites, image creation, deployment, result checks, and cleanup.

## Source

- `Dockerfile` builds the pinned Box source and offers `scripted` and `claude` image targets.
- `run.py` renders a Job or submits it through your selected Kubernetes context.
- `app/practice.py` performs the fixed coding exercise and checks protected files and policy decisions.
- `claude/` contains the deployment and coding examples, plus their checks.
- `pod-identity.json` creates a workload identity for the optional model calls.

Preview the Job without contacting a cluster:

```sh
python3 run.py --image YOUR_REGISTRY/box-example:scripted --render
```

The output is a Kubernetes Job document. The script performs no cloud operation with `--render`.
For Claude, `--exercise deployment-cooldown` selects the default deployment task.
Use `--exercise boundaries` for the coding and file-permission task.
The [Claude README](claude/README.md) explains both examples and how to test them without a model.

## Cluster requirements

Use the [cluster baseline](../../../docs/user/tutorials/eks.md#cluster-baseline) before building or deploying.
It lists the tested worker configuration, required settings, admission requirements, and older-cluster limits.
`run.py` stops before Job creation if Kubernetes removes required settings during a server dry run.
It also checks the created Job and Pods.
A preserved setting does not prove that the worker runtime can implement it.

## Tested configuration

The Box source pin is `f0dc6f49ea8bb8608502afffa50c8748f6c24ca2`.
Recorded EKS checks used Kubernetes 1.35, Amazon Linux 2023 ARM64, kernel 6.12.111, and containerd 2.3.5.
The fixed coding example passed 11 checks. The Claude Code 2.1.305 coding and file-permission example passed 23 checks.

The Claude Code 2.1.305 deployment example passed seven checks on EKS, with kernel `6.12.111-136.204.amzn2023.aarch64`.
The separate ten-minute cooldown test passed 14 checks, including refusal near expiry and a permitted request after expiry.
The shortened repeated-failure test passed 17 checks.
Both Claude examples used a trusted controller with EKS Pod Identity to obtain model access.

The Job requires pod user namespaces, `procMount: Unmasked`, and an outer `seccompProfile: Unconfined`.
These are tested settings, not proven minimum privileges or production approval.
Direct Pod Identity retrieval inside the agent's sandbox remains unvalidated.
Base-image packages resolve during image creation. Record the resulting image digest and repeat the checks after changes.
