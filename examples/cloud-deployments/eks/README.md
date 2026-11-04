# Run a coding workload on EKS

A coding workload needs to change project files while protected files remain outside its access.
This example runs that workload in a Kubernetes Job with Box inside its container.
A fixed script checks the deployment. An optional Claude Code agent chooses tools against the same kinds of restrictions.

Follow the [full build guide](../../../docs/user/tutorials/eks.md) for prerequisites, image creation, deployment, result checks, and cleanup.

## Source

- `Dockerfile` builds the pinned Box source and offers `scripted` and `claude` image targets.
- `run.py` renders a Job or submits it through your selected Kubernetes context.
- `app/practice.py` performs the fixed coding exercise and checks protected files and policy decisions.
- `claude/` contains the agent controller, fixed task, synthetic tool service, and dependency pins.
- `pod-identity.json` creates a workload identity for the optional model calls.

Preview the Job without contacting a cluster:

```sh
python3 run.py --image YOUR_REGISTRY/box-example:scripted --render
```

The output is a Kubernetes Job document. The script performs no cloud operation with `--render`.

## Tested configuration

The Box source pin is `f0dc6f49ea8bb8608502afffa50c8748f6c24ca2`.
Recorded EKS checks used Kubernetes 1.35, Amazon Linux 2023 ARM64, kernel 6.12.111, and containerd 2.3.5.
The fixed exercise passed 11 checks. The Claude Code 2.1.305 variant passed 23 checks.
The model variant used a trusted controller with EKS Pod Identity to obtain model access.

The Job requires pod user namespaces, `procMount: Unmasked`, and an outer `seccompProfile: Unconfined`.
These are tested settings, not proven minimum privileges or production approval.
Direct Pod Identity retrieval inside the agent's sandbox remains unvalidated.
Base-image packages resolve during image creation. Record the resulting image digest and repeat the checks after changes.
