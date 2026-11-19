# Run Strands Box on Google Cloud

Run a Strands agent with Gemini on a Google Compute Engine Linux virtual machine (VM).
Box blocks deployment retries for ten minutes after three failures, while status checks remain available.
The deployment service is a local mock. The agent makes real Gemini requests through the Vertex AI API.

Follow the [tutorial](../../../docs/user/tutorials/google-cloud.md) to deploy the VM, inspect the results, and remove its resources.

## Source files

| File | Purpose |
| --- | --- |
| [`deploy.py`](deploy.py) | Creates the VM, reads results, and removes owned resources. |
| [`setup-vm.sh`](setup-vm.sh) | Builds Box, installs dependencies, and runs the checks. |
| [`agent.py`](agent.py), [`run-demo.py`](run-demo.py) | Strands agent and its verification controller. |
| [`requirements.txt`](requirements.txt), [`dependency-lock.txt`](dependency-lock.txt) | Python dependencies and pinned versions. |
| [`../eks/claude/`](../eks/claude/) | Shared mock service, tools, cooldown policy, and policy checker. |
| `test_*.py` | Offline tests for deployment, cleanup, model transport, and result handling. |

## Tested configuration

The full cooldown check and eight live Gemini turns passed on this configuration:

| Component | Tested value |
| --- | --- |
| Compute Engine | `t2a-standard-4`, `us-central1-a` |
| Operating system | Debian 12, image `debian-12-bookworm-arm64-v20261102` |
| Runtime | ARM64, kernel `6.1.0-54-cloud-arm64`, Python `3.11.2`, ordinary user |
| Box source | `da4993143596d390e4e7525bc90339d10db23212` |
| Agent and model | Strands `1.63.0`, Google Gen AI `2.34.0`, `gemini-3.8-flash` in `global` |

This example does not establish support for Google Kubernetes Engine, Cloud Run, x86-64 Linux, or other VM images.

## Local checks

Run the unit tests from this directory after installing the locked dependencies in a Python environment:

```sh
python3 -m unittest discover -p 'test_*.py' -v
```

The transport tests use recorded-format model responses. They do not replace the live VM checks.
