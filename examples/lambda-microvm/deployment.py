"""Build a retained Lambda image and record its exact identity."""
import hashlib
import json
from pathlib import Path
import time

from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent


def save(path, value):
    path.write_text(json.dumps(value, indent=2, default=str) + "\n")


def infrastructure(session, args):
    client = session.client("cloudformation")
    name = "box-lambda-" + args.name
    template = json.loads((ROOT / "infrastructure.json").read_text())
    try:
        stack = client.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as error:
        if error.response["Error"]["Code"] != "ValidationError" or "does not exist" not in str(error):
            raise
        print("Create retained artifact storage and roles: " + name, flush=True)
        client.create_stack(
            StackName=name, TemplateBody=json.dumps(template),
            Parameters=[{"ParameterKey": "ImageName", "ParameterValue": args.name}],
            Capabilities=["CAPABILITY_IAM"], EnableTerminationProtection=True,
            Tags=[{"Key": "purpose", "Value": "box-lambda-example"}],
        )
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            stack = client.describe_stacks(StackName=name)["Stacks"][0]
            if stack["StackStatus"] == "CREATE_COMPLETE":
                break
            if stack["StackStatus"] != "CREATE_IN_PROGRESS":
                raise RuntimeError("Infrastructure failed: " + stack["StackStatus"])
            time.sleep(5)
        else:
            raise TimeoutError("Infrastructure exceeded ten minutes")
    if stack["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE") or not stack.get("EnableTerminationProtection"):
        raise RuntimeError("The example stack must be ready with termination protection enabled")
    actual = client.get_template(StackName=name)["TemplateBody"]
    if isinstance(actual, str):
        actual = json.loads(actual)
    parameters = {p["ParameterKey"]: p["ParameterValue"] for p in stack["Parameters"]}
    if actual != template or parameters.get("ImageName") != args.name:
        raise RuntimeError("The retained stack differs from this example. Use a new --name.")
    return {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}


def deploy(session, args, archive, fingerprint, identity, evidence):
    outputs = infrastructure(session, args)
    client = session.client("lambda-microvms")
    image = f"arn:aws:lambda:{args.region}:{args.account}:microvm-image:{args.name}"
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    key = f"{args.name}/{checksum}/demo.zip"
    session.client("s3").upload_file(str(archive), outputs["Bucket"], key)
    config = {
        "name": args.name,
        "description": "Retained Box Lambda MicroVM example",
        "baseImageArn": f"arn:aws:lambda:{args.region}:aws:microvm-image:al2023-1",
        "baseImageVersion": "2",
        "buildRoleArn": outputs["BuildRole"],
        "codeArtifact": {"uri": f"s3://{outputs['Bucket']}/{key}"},
        "egressNetworkConnectors": [
            f"arn:aws:lambda:{args.region}:aws:network-connector:aws-network-connector:INTERNET_EGRESS",
        ],
        "resources": [{"minimumMemoryInMiB": 4096}],
        "cpuConfigurations": [{"architecture": "ARM_64"}],
        "additionalOsCapabilities": ["ALL"],
        "hooks": {
            "port": 9000,
            "microvmImageHooks": {
                "ready": "ENABLED", "readyTimeoutInSeconds": 120,
                "validate": "ENABLED", "validateTimeoutInSeconds": 120,
            },
            "microvmHooks": {
                hook + suffix: value for hook in ("run", "resume", "suspend", "terminate")
                for suffix, value in (("", "ENABLED"), ("TimeoutInSeconds", 10))
            },
        },
        "logging": {"cloudWatch": {"logGroup": outputs["LogGroup"]}},
        "tags": {"purpose": "box-lambda-example"},
    }
    save(evidence / "image-request.json", config)
    try:
        prior = client.get_microvm_image(imageIdentifier=image)
    except client.exceptions.ResourceNotFoundException:
        created = client.create_microvm_image(**config)
    else:
        previous_version = prior.get("latestActiveImageVersion") or prior.get("latestFailedImageVersion")
        if not previous_version:
            raise RuntimeError("An image build already uses this name. Wait for it to finish.")
        previous = client.get_microvm_image_version(imageIdentifier=image, imageVersion=previous_version)
        if previous["buildRoleArn"] != outputs["BuildRole"]:
            raise RuntimeError("This image belongs to different infrastructure. Use a new --name.")
        fields = client.meta.service_model.operation_model("UpdateMicrovmImage").input_shape.members
        created = client.update_microvm_image(
            imageIdentifier=image, **{k: v for k, v in config.items() if k in fields},
        )
    version = created["imageVersion"]
    print(f"Build {args.name} version {version}. Cloud resources remain retained.", flush=True)
    deadline, report = time.monotonic() + 1200, 0
    while time.monotonic() < deadline:
        built = client.get_microvm_image_version(imageIdentifier=image, imageVersion=version)
        save(evidence / "image-build.json", built)
        if built["state"] == "SUCCESSFUL":
            break
        if built["state"] == "FAILED":
            raise RuntimeError("Image build failed: " + str(built.get("stateReason")))
        if time.monotonic() - report > 30:
            print("Image state: " + built["state"], flush=True)
            report = time.monotonic()
        time.sleep(5)
    else:
        raise TimeoutError("Image build exceeded twenty minutes")
    if built["imageVersion"] != version or built["codeArtifact"] != config["codeArtifact"]:
        raise RuntimeError("Built image does not match the requested source")
    instance = client.run_microvm(
        imageIdentifier=image, imageVersion=version, executionRoleArn=outputs["ExecutionRole"],
        maximumDurationInSeconds=28800,
        idlePolicy={"maxIdleDurationSeconds": 900, "suspendedDurationSeconds": 28800,
                    "autoResumeEnabled": True},
    )
    record = {
        "account": args.account, "region": args.region, "name": args.name,
        "image": image, "version": version, "microvm_id": instance["microvmId"],
        "fingerprint": fingerprint, "package": identity, "archive_sha256": checksum,
        "infrastructure": outputs,
    }
    save(evidence / "target.json", record)
    return record
