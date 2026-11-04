# Run Box in a Linux cloud environment

Use these examples to run Box around a workload on Amazon Elastic Kubernetes Service (EKS) or Amazon Bedrock AgentCore Runtime.
Each example includes source, setup commands, policy checks, and cleanup instructions.

| Example | What you run | What Box demonstrates |
| --- | --- | --- |
| [EKS](eks/) | A fixed coding exercise, with an optional Claude Code agent. | Permitted project changes, protected files, and refused deletion and network requests. |
| [AgentCore Runtime](agentcore-runtime/) | A shipment agent using Strands or LangChain, with scripted controls. | A dispatch depends on an earlier eligibility response. A completed shipment or refund closes competing requests for five minutes. |

Start with the [EKS build guide](../../docs/user/tutorials/eks.md) or the [Runtime build guide](../../docs/user/tutorials/agentcore-runtime.md).
The source examples pin the Box revisions used for their recorded cloud checks.
Keep their Linux ARM64 and service configuration limits when adapting them.

For Linux environment requirements and service configuration, read the [cloud deployment guide](../../docs/user/cloud-deployments.md).
The guide also covers Lambda MicroVM.
