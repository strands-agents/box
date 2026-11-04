# Strands shipment agent

`agent.py` builds a Strands `Agent` with `BedrockModel` and four Python tools.
`run-demo.py` starts the synthetic service and Box, then checks the agent against service effects and policy decisions.
`SequentialToolExecutor` runs one tool at a time.

Prepare the `strands` variant from the [parent example](../README.md).
Run from the `agentcore-runtime/` directory with an authenticated development profile:

```sh
AWS_PROFILE=YOUR_PROFILE python3.12 sdk/run-demo.py \
  --output-dir ./output-strands --box-binary ./box-core/box \
  --region us-west-2 --model us.anthropic.claude-sonnet-4-6
```

Use a new output directory for each run.
A successful run writes `result.json` with `status: PASS` and 24 successful assertions.
The model can vary its tool choices and fail verification.
The verifier checks selected final response fields. It does not grade every sentence.

Follow the [Runtime build guide](../../../../docs/user/tutorials/agentcore-runtime.md) for deployment and cleanup.
The [parent README](../README.md#tested-scope) states platform and policy limits.
