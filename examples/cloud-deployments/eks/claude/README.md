# Add Claude Code to the EKS example

The Claude image runs Claude Code 2.1.305 against a fixed task and synthetic files.
Box permits project work and the selected model route, while the task also requests operations that policy refuses.

Use the [EKS build guide](../../../../docs/user/tutorials/eks.md#run-claude-code) to create the workload identity and submit the Job.
Run the Docker and runner commands from the parent `eks/` directory.
The controller obtains temporary credentials outside the agent's sandbox and gives Box a short-lived Bedrock token.
Box inserts that token into permitted model requests. The agent receives a substitute value.

The verifier requires 23 checks to pass. Model responses can vary and can fail verification.
The fixed exercise does not measure general autonomous coding quality.
The tested platform and outer-container settings appear in the [example README](../README.md#tested-configuration).

## Check file permissions without a model

On Linux ARM64, use the built Box executable with its helpers beside it:

```sh
python3 check-policy-boundaries.py --box-binary /absolute/path/to/box --evidence-dir /absolute/path/to/new-evidence
```

The check attempts native and shell writes to the reference file and verifies both refusals.
It also verifies permitted project writes, private-file refusals, and deletion refusal against the policy records.
The command writes a receipt and returns zero only when all checks pass.
