# Add Claude Code to the EKS example

The Claude image runs Claude Code 2.1.305 against a synthetic checkout deployment service.
A failed deployment can lead an agent to retry while the service remains unhealthy.
Box pauses deployment retries for ten minutes after three failed responses within five minutes. Diagnostic requests remain available.

Use the [EKS build guide](../../../../docs/user/tutorials/eks.md#run-claude-code) to create the workload identity and submit the Job.
Run the Docker and runner commands from the parent `eks/` directory.
The controller obtains temporary credentials outside the agent's sandbox and gives Box a short-lived Bedrock token.
Box inserts that token into permitted model requests. The agent receives a substitute value.

## Run the deployment exercise

Use `--mode claude --exercise deployment-cooldown` with the EKS runner.
The runner selects this exercise by default in Claude mode.
The agent calls two Model Context Protocol (MCP) tools: `deploy_checkout` and `deployment_status`.
MCP is the protocol the agent uses to call these tools.
Their HTTP requests pass through Box's egress gateway to the synthetic service outside the box.

| Operation | Expected result |
| --- | --- |
| First three `deploy_checkout` calls | Box permits each request. The service returns HTTP 503, a service-unavailable response. |
| Two further deployment attempts during cooldown | Box refuses both requests before they reach the service. |
| `deployment_status` during cooldown | Box permits the request. The service returns HTTP 200. |
| Deployment after cooldown expiry, checked separately below | Box permits the request. The service returns HTTP 201. |

The [policy](deployment_policy.py) uses Dogwood, Box's policy language, to count deployment responses with HTTP status codes from 400 through 599.
The service returns 503 for its first three deployment requests and 201 afterward. It enforces no cooldown itself.
A diagnostic response or policy refusal does not extend the cooldown.

The supplied client makes one call at a time. Each box has its own policy history.
The rule does not coordinate limits across boxes or cancel requests already in flight when the third failure arrives.

The live agent finishes after the failures, refused retries, and diagnostics. It does not wait ten minutes or verify expiry.
Model responses can vary and can fail verification. Inspect `receipt.json` and the checks in `stdout.json` after each run.
The [tested configuration](../README.md#tested-configuration) distinguishes the existing EKS boundary results from this exercise.

## Check cooldown expiry without a model

Run these commands from this `claude/` directory on Linux ARM64 with Python 3.12.
Use a built Box executable with its helpers beside it and a new evidence directory:

```sh
python3.12 check_deployment.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-deployment-evidence
```

This check uses the same HTTP client and policy without model calls or AWS credentials.
The full check uses a five-minute failure window and ten-minute cooldown.
It verifies refusals through the cooldown and a successful request after expiry.
Allow about ten minutes for the full check.
The command writes its configuration, service receipts, policy decisions, and checks to the evidence directory.
A successful run reports `passed: true` and exits with status zero.

For a faster check, use a separate evidence directory:

```sh
python3.12 check_deployment.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-quick-evidence --quick
```

Quick mode uses a three-second failure window and nine-second cooldown.
Its receipt identifies these shorter windows. Use the full check to verify the documented five-minute and ten-minute policy.

## Run the boundary exercise

Pass `--exercise boundaries` to the EKS runner for the coding and file-permission task.
Its verifier requires 23 checks to pass. That check count applies only to the boundary exercise.
The fixed task does not measure general autonomous coding quality.

To check its file permissions without a model, run:

```sh
python3.12 check-policy-boundaries.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-boundary-evidence
```

The check attempts native and shell writes to the reference file and verifies both refusals.
It also verifies permitted project writes, private-file refusals, and deletion refusal against the policy records.
The command writes a receipt and returns zero only when all checks pass.
