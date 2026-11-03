# LangChain shipment agent

`agent.py` constructs `langchain.agents.create_agent` with `ChatBedrockConverse` and four Python tools.
LangGraph supplies the execution loop beneath LangChain.
`run-demo.py` verifies the service requests, Box decisions, and committed effects.
The final response uses a trusted template after verification of the extracted shipment facts.

Prepare the `langchain` variant from the [parent example](../README.md).
Run from the `agentcore-runtime/` directory with an authenticated development profile:

```sh
AWS_PROFILE=YOUR_PROFILE python3.12 langchain-example/run-demo.py \
  --output-dir ./output-langchain --box-binary ./box-core/box \
  --region us-west-2 --model us.anthropic.claude-sonnet-4-6
```

Use a new output directory for each run.
A successful run writes `result.json` with `status: PASS` and 36 successful assertions.
Five fixed prompts exercise policy refusals and successful resolution. Intermediate model prose remains ungraded.
The model can vary its tool choices and fail verification.

Follow the [Runtime build guide](../../../../docs/user/tutorials/agentcore-runtime.md#use-langchain) for deployment and cleanup.
The [parent README](../README.md#tested-scope) states platform and policy limits.
