# Add Claude Code to the EKS example

Run Claude Code against a mock deployment service to see Box stop repeated retries.
The service simulates failed deployments of a checkout application. It does not deploy application code.

After three failed responses within five minutes, Box blocks further deployment requests for ten minutes.
This pause is the cooldown. The agent can still check deployment status.

We tested this deployment example in a Linux container on 64-bit Arm (ARM64).
It still needs testing on Amazon Elastic Kubernetes Service (EKS).
The [tested configuration](../README.md#tested-configuration) lists the versions and results for each example.

Use the [EKS build guide](../../../../docs/user/tutorials/eks.md#run-claude-code) to create the workload identity and submit the Job.
Run the Docker and runner commands from the parent `eks/` directory.
The controller obtains temporary credentials outside the agent's sandbox and gives Box a short-lived Bedrock token.
Box inserts that token into permitted model requests. The agent receives a substitute value.

<a id="run-the-deployment-exercise"></a>
## Run the deployment example

Use `--mode claude --exercise deployment-cooldown` with the EKS runner.
The runner selects this example by default in Claude mode. The image pins Claude Code 2.1.305.
The agent uses Model Context Protocol (MCP) to call two tools:
`deploy_checkout` requests a deployment, and `deployment_status` checks its status.
Box checks their HTTP requests before forwarding permitted requests to the mock service outside the box.

| Operation | Expected result |
| --- | --- |
| First three `deploy_checkout` calls | Box permits each request. The service returns HTTP 503, a service-unavailable response. |
| Two more deployment attempts during the cooldown | Box blocks both requests before they reach the service. |
| `deployment_status` during the cooldown | Box permits the status check. The service returns HTTP 200 (success). |
| Deployment after the cooldown, tested separately below | Box permits the request. The service returns HTTP 201 (created). |

The [policy](deployment_policy.py) uses Dogwood, Box's policy language, to count failed deployment responses (HTTP status codes 400 through 599).
The mock service returns 503 for its first three deployment requests and 201 afterward. Box enforces the cooldown.
Status checks and blocked retries do not extend the cooldown. Later failures can start another cooldown.

The supplied client makes one call at a time. Each box has its own policy history.
The rule does not coordinate limits across boxes or cancel requests already in flight when the third failure arrives.

The agent finishes after Box blocks its retries and permits a status check.
It does not wait ten minutes or test whether deployment becomes available again.
Model responses can vary. Read `receipt.json` for the result and `stdout.json` for the individual checks.

## Check cooldown expiry without a model

Run these commands from this `claude/` directory on Linux ARM64 with Python 3.12.
Use a built Box executable with its helpers beside it and a new evidence directory:

```sh
python3.12 check_deployment.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-deployment-evidence
```

This check uses the same HTTP client and policy without model calls or AWS credentials.
The full check uses a five-minute failure window and a ten-minute cooldown.
It checks that Box blocks retries during the cooldown and permits a deployment request after the cooldown ends.
Allow about ten minutes for the full check.
The command saves its configuration, service request log, Box policy decisions, and test results in the evidence directory.
A successful run reports `passed: true` and exits with status zero.

For a faster check, use a separate evidence directory:

```sh
python3.12 check_deployment.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-quick-evidence --quick
```

Quick mode uses a three-second failure window and nine-second cooldown.
The test report records these shorter durations. Use the full check to test the five-minute and ten-minute policy.

To test whether later failures start another cooldown, run the command below.
It uses a mock service that always returns deployment failures, a thirty-second failure window, and a three-second cooldown.
It checks that the fourth and fifth failures each start another cooldown while status checks remain available.

```sh
python3.12 test_deployment_policy.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-policy-regression-evidence
```

Continuous integration runs this test against a Box build from the pull request.

<a id="run-the-boundary-exercise"></a>
## Run the coding and file-permission example

Pass `--exercise boundaries` to the EKS runner for the coding and file-permission task.
Its verifier requires 23 checks to pass. That count applies only to this coding example.
The fixed task does not measure general autonomous coding quality.

To check its file permissions without a model, run:

```sh
python3.12 check-policy-boundaries.py --box-binary /absolute/path/to/box \
  --evidence-dir /absolute/path/to/new-boundary-evidence
```

The check attempts native and shell writes to the reference file and verifies both refusals.
It also verifies permitted project writes, private-file refusals, and deletion refusal against the policy records.
The command writes a receipt and returns zero only when all checks pass.
