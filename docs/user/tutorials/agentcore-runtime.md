# Run a Box shipment agent on AgentCore Runtime

Amazon Bedrock AgentCore Runtime runs this shipment agent with Box around its process.
The agent reads a synthetic order, checks eligibility, and requests one replacement.
Box refuses premature dispatch, duplicate dispatch, and a competing refund.
Use Strands for the first run. The same sample also includes a LangChain variant.

## Before you start

Prepare the package on Linux ARM64 with Python 3.12, pip, Git, and Rust through rustup.
ARM64 is the 64-bit Arm processor architecture.
The Box checkout selects its Rust toolchain. Install its [native build dependencies](../../../README.md#build-from-source).
On Amazon Linux 2023, the build requires GCC, G++, Make, CMake, OpenSSL development files, pkg-config, and Perl.
Python 3.12 also needs the pip and virtual-environment packages.

Use a development AWS account and an existing Amazon S3 bucket in `us-west-2` owned by that account.
Authenticate a profile with permissions to deploy CloudFormation, create the execution role, upload the package, and invoke Runtime.
The execution role receives model permissions from the generated template.
Model and cloud-resource usage can incur charges.

The [sample README](../../../examples/cloud-deployments/agentcore-runtime/README.md#tested-scope) records the tested source revision, framework versions, and platform limits.
The deployment uses managed Runtime V2 with Python 3.12 and a non-root operator.
The model profile and endpoint are fixed to the tested commercial AWS configuration.

## Prepare the package

Clone the repository and enter the sample directory:

```sh
git clone https://github.com/strands-agents/box.git
cd box/examples/cloud-deployments/agentcore-runtime
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-deploy.txt
python prepare.py --framework strands
python deploy-runtime.py package --with-strands --output-dir ./deployment-strands
```

Preparation builds the pinned Box source and installs locked dependencies for Linux ARM64 and Python 3.12.
It writes local manifests with file hashes. Packaging checks those hashes before producing `runtime.zip`.
The output directory also contains `runtime.cloudformation.json` and `package-receipt.json`.

Inspect the generated template before deployment.
It creates one Runtime and an execution role with package-read, logging, and selected model permissions.
The role includes `bedrock:CallWithBearerToken`, which requires a wildcard resource.

## Deploy and invoke

Set the account, profile, bucket, and a new stack name:

```sh
export ACCOUNT_ID='YOUR_12_DIGIT_ACCOUNT'
export AWS_PROFILE='YOUR_DEVELOPMENT_PROFILE'
export PACKAGE_BUCKET='YOUR_EXISTING_BUCKET'
export STACK_NAME='BoxShipmentDemoStrandsExample'
python deploy-runtime.py deploy --with-strands \
  --account "$ACCOUNT_ID" --profile "$AWS_PROFILE" --region us-west-2 \
  --bucket "$PACKAGE_BUCKET" --stack-name "$STACK_NAME" \
  --output-dir ./deployment-strands
python deploy-runtime.py invoke --example shipment-strands \
  --account "$ACCOUNT_ID" --profile "$AWS_PROFILE" --region us-west-2 \
  --stack-name "$STACK_NAME" --output-dir ./deployment-strands
```

The helper checks the account and bucket Region, uploads the package, and creates or updates the example's stack.
It refuses to update a stack without its example ownership tag.
Each invocation writes a unique receipt before it sends the request.
The wrapper starts fresh Box state and a synthetic service for that invocation.
The checked-in policies use port 0. Each runner binds that field to its synthetic service's allocated port.

## Read the result

The five fixed prompts exercise the following sequence:

| Request | Expected result |
| --- | --- |
| Read the order, then dispatch before eligibility | The read succeeds. Box refuses dispatch. |
| Check eligibility, then dispatch | The service confirms one replacement. |
| Dispatch again | Box refuses the duplicate. |
| Request a refund | Box refuses the competing resolution. |
| Produce the customer response | The verifier checks confirmed shipment fields. |

Check the receipt:

```sh
python - <<'PYTHON'
import json
from pathlib import Path
receipt = json.loads(Path("deployment-strands/invocation-shipment-strands-receipt.json").read_text())
result = receipt["result"]["result"]
assert receipt["result"]["status"] == result["status"] == "PASS"
assert result["checks"] and all(value is True for value in result["checks"].values())
print("Shipment PASS", len(result["checks"]), "checks")
PYTHON
```

The Strands result contains 24 assertions about this fixed conversation.
Read the agent's report with the service effects and Box decisions. Intermediate model prose remains ungraded.
Model responses can vary and can fail verification.

The policy uses five minutes of recent response history for one order and sequential requests.
It does not establish permanent exclusivity, concurrent correctness, or recovery after a lost response or process restart.
A production service must enforce those properties when it commits a shipment or refund.

<a id="use-langchain"></a>
## Use LangChain

Use a fresh example checkout and prepare it with `python prepare.py --framework langchain`.
Install `requirements-deploy.txt` in its virtual environment as above.
The variant uses `langchain.agents.create_agent` and `ChatBedrockConverse`, with LangGraph underneath.

Follow the same package, deploy, and invoke steps with these substitutions:

| Strands setting | LangChain setting |
| --- | --- |
| `--with-strands` | `--with-langchain` |
| `--example shipment-strands` | `--example shipment-langchain` |
| `./deployment-strands` | `./deployment-langchain` |
| `BoxShipmentDemoStrandsExample` | `BoxShipmentDemoLangchainExample` |

The expected result contains 36 successful assertions.
The verifier checks structured shipment facts before a trusted template creates the final customer response.
Use `deployment-langchain/invocation-shipment-langchain-receipt.json` for its result.

<a id="run-the-scripted-controls"></a>
## Run the scripted controls

Both framework packages include fixed shipment and research controls.
Invoke them with `--example shipment` or `--example research` using the same deployment arguments.
These controls make no model calls.
The research control compares a request budget with a static policy against a synthetic local receiver.

## Stop and remove the deployment

Stop each invocation with the exact unique receipt path printed by the helper.
Use the corresponding output directory and stack for the variant you deployed.

```sh
python deploy-runtime.py stop --receipt ./deployment-strands/invocations/SESSION_UUID.json \
  --account "$ACCOUNT_ID" --profile "$AWS_PROFILE" --region us-west-2 \
  --stack-name "$STACK_NAME" --output-dir ./deployment-strands
```

The stop request retains the Runtime, stack, and package.
To remove the example stack, disable its termination protection and delete it:

```sh
aws cloudformation update-termination-protection --no-enable-termination-protection \
  --stack-name "$STACK_NAME" --region us-west-2 --profile "$AWS_PROFILE"
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region us-west-2 --profile "$AWS_PROFILE"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region us-west-2 --profile "$AWS_PROFILE"
```

Delete only this example's package object from S3 after the stack deletion completes.
Its key is `box-shipment-example/PACKAGE_SHA256/runtime.zip`, using the hash in `package-receipt.json`.
Retain the shared bucket. CloudWatch log groups can remain after stack deletion. Apply your account's log-retention policy.
