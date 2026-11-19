# Compare a research budget with a static policy

A fixed research workload reads synthetic records and sends a brief to a local receiver.
Box permits the budgeted requests, then refuses requests beyond the policy's allowance.
The static-policy control uses the same workload without the temporal budget.

Prepare the parent example with `--framework scripted`.
Run from the `agentcore-runtime/` directory:

```sh
python3.12 research/run-demo.py --output-dir ./output-research --box-binary ./box-core/box
```

The runner writes `result.json` and exits nonzero if verification fails.
This control makes fixed requests and uses no language model.
Read the `checks` field and the receiver's recorded effects together.
The [Runtime build guide](../../../../docs/user/tutorials/agentcore-runtime.md#run-the-scripted-controls) also runs this control in a deployment.
