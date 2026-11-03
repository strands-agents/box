# Resolve a shipment on AgentCore Runtime

A support agent must replace a delayed shipment without sending two replacements or also issuing a refund.
This example runs a Strands or LangChain agent inside Box and deploys it to Amazon Bedrock AgentCore Runtime.
The model chooses tools. Box checks each service request against recent response history.

Follow the [full build guide](../../../docs/user/tutorials/agentcore-runtime.md) to prepare dependencies, deploy, invoke, inspect the result, and clean up.

## Choose a workload

| Workload | Source | Behavior |
| --- | --- | --- |
| Strands | [`sdk/`](sdk/) | One Strands agent uses four Python tools and sequential execution. |
| LangChain | [`langchain-example/`](langchain-example/) | `langchain.agents.create_agent` uses `ChatBedrockConverse`. LangGraph runs the agent loop underneath. |
| Scripted shipment | `run-demo.py` | Fixed requests test successful, failed, and unrelated eligibility responses without a model. |
| Research control | [`research/`](research/) | Fixed requests compare a request budget with a static policy. |

The service and customer are synthetic. The model calls in the two agent variants are live.
Five fixed prompts exercise premature dispatch, eligible dispatch, duplicate dispatch, a refund, and a final response.
The independent verifier compares tool calls, Box decisions, and service effects.

## Prepare and test

Use Linux ARM64 and Python 3.12, with Git, Rust, and the native build dependencies from the build guide.
From this directory:

```sh
python3.12 prepare.py --framework strands
python3.12 -m pip install -r requirements-deploy.txt
python3.12 run-tests.py
```

Preparation builds the pinned Box source and installs locked Python dependencies.
It records local binary and dependency hashes. Build outputs and invocation receipts stay outside Git.
Use a fresh checkout and `--framework langchain` for the LangChain variant.
The offline tests make no model calls. The LangChain graph tests also block socket connections.

## Tested scope

The Box source pin is `e4ca8b80359b2213d684de31cd6ef32e0d61478a`.
Recorded cloud checks used managed Runtime V2, Python 3.12, Linux ARM64, and a non-root operator.
Strands 1.63.0 passed 24 assertions. LangChain 1.4.8 with LangChain AWS 1.9.1 passed 36 assertions.
Both used `us.anthropic.claude-sonnet-4-6` through `us-west-2`.
The lock files record the remaining dependency versions.

The policy uses five minutes of history, one synthetic order, and sequential requests.
It does not prove permanent exclusivity, concurrent correctness, or recovery after a lost response or restart.
The backend must enforce those properties in a production application.
The Strands response checks cover selected confirmed fields. Intermediate model prose remains ungraded.
The LangChain verifier checks structured facts before a trusted template renders the final response.
Rebuilt packages require fresh run results. Existing cloud results do not qualify other platforms or configurations.
