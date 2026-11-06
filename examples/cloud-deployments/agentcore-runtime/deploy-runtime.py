#!/usr/bin/env python3
"""Package, deploy, invoke, or stop one recorded demonstration session."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent
OWNER = "box-shipment-example"
SOURCES = ("runtime_app.py", "run-demo.py", "fixture.py", "shipment-client.py", "policy.dw", "binary-manifest.json")


def save(path, value):
    path.write_text(json.dumps(value, indent=2, default=str) + "\n")


def context(why, *requirements):
    return {"com.aws.cloudformation.Context": {"why": why, "must": list(requirements)}}


def template(with_strands=False, with_langchain=False):
    if with_strands and with_langchain:
        raise ValueError("Choose only one live framework variant")
    framework = "LangChain" if with_langchain else "Strands SDK"
    sub = lambda value: {"Fn::Sub": value}
    definition = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Run the synthetic shipment policy demonstration in one isolated managed-code Runtime.",
                "Parameters": {
            "RuntimeName": {"Type": "String", "AllowedPattern": "BoxShipmentDemo[A-Za-z0-9_]*", "MaxLength": 48},
            "PackageBucket": {"Type": "String", "AllowedPattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"},
            "PackageKey": {"Type": "String", "AllowedPattern": "box-shipment-example/[a-f0-9]{64}/runtime.zip"},
        },
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Metadata": context("Read the fixed code package and write Runtime logs.",
                                    "No model or production service access is required."),
                "Properties": {
                    "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                        "Action": "sts:AssumeRole", "Condition": {
                            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                            "ArnLike": {"aws:SourceArn": sub("arn:${AWS::Partition}:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:runtime/${RuntimeName}-*")},
                        },
                    }]},
                    "Policies": [{"PolicyName": "ShipmentPackageAndLogs", "PolicyDocument": {
                        "Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                             "Resource": sub("arn:${AWS::Partition}:s3:::${PackageBucket}/${PackageKey}")},
                            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents"],
                             "Resource": sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/bedrock-agentcore/runtimes/${RuntimeName}-*")},
                            {"Effect": "Allow", "Action": "logs:DescribeLogGroups",
                             "Resource": sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:*")},
                        ],
                    }}],
                },
            },
            "ShipmentRuntime": {
                "Type": "AWS::BedrockAgentCore::Runtime",
                "Metadata": context("Exercise real Box decisions against a synthetic local shipment service.",
                                    "Use only the packaged fixed workload."),
                "Properties": {
                    "AgentRuntimeName": {"Ref": "RuntimeName"},
                    "Description": "Deterministic shipment policy demonstration with synthetic data; no language model.",
                    "RoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "PlatformVersion": "V2", "ProtocolConfiguration": "HTTP",
                    "NetworkConfiguration": {"NetworkMode": "PUBLIC"},
                    "LifecycleConfiguration": {"IdleRuntimeSessionTimeout": 600, "MaxLifetime": 3600},
                    "AgentRuntimeArtifact": {"CodeConfiguration": {
                        "Code": {"S3": {"Bucket": {"Ref": "PackageBucket"}, "Prefix": {"Ref": "PackageKey"}}},
                        "Runtime": "PYTHON_3_12", "EntryPoint": ["runtime_app.py"],
                    }},
                    "Tags": {"DemoOwner": OWNER, "Purpose": "SyntheticShipmentPolicyDemo"},
                },
            },
        },
        "Outputs": {
            "RuntimeArn": {"Description": "The isolated shipment demonstration Runtime.", "Value": {"Fn::GetAtt": ["ShipmentRuntime", "AgentRuntimeArn"]}},
            "RuntimeId": {"Description": "Runtime identifier for readback.", "Value": {"Fn::GetAtt": ["ShipmentRuntime", "AgentRuntimeId"]}},
        },
    }


    if with_strands or with_langchain:
        resources = definition["Resources"]
        role = resources["ExecutionRole"]
        role["Metadata"] = context("Read the package, write logs, and invoke the selected Bedrock model.",
                                   "Credentials remain with the trusted controller and Box proxy.")
        role["Properties"]["Policies"].append({"PolicyName": "ShipmentLangChainModel" if with_langchain else "ShipmentStrandsModel", "PolicyDocument": {
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                 "Resource": [sub("arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:inference-profile/us.anthropic.claude-sonnet-4-6")]
                    + [sub("arn:${AWS::Partition}:bedrock:" + region + "::foundation-model/anthropic.claude-sonnet-4-6")
                       for region in ("us-east-1", "us-east-2", "us-west-2")]},
                {"Effect": "Allow", "Action": "bedrock:CallWithBearerToken", "Resource": "*"},
            ]}})
        runtime = resources["ShipmentRuntime"]
        runtime["Metadata"] = context("Run a " + framework + " shipment agent and fixed policy controls.",
                                       "Use only synthetic shipment data and the selected model.")
        runtime["Properties"]["Description"] = framework + " shipment agent with real Bedrock responses and synthetic services; includes scripted controls."
        runtime["Properties"]["EnvironmentVariables"] = {
            "BOX_DEMO_MODEL_ID": "us.anthropic.claude-sonnet-4-6",
            "BOX_DEMO_REGION": {"Ref": "AWS::Region"},
        }
        definition["Description"] = "Run the " + framework + " shipment example and scripted controls in one managed-code Runtime."
    return definition


def package(output, with_strands=False, with_langchain=False):
    if with_strands and with_langchain:
        raise ValueError("Choose only one live framework variant")
    output.mkdir(parents=True, exist_ok=True)
    binary_manifest = json.loads((ROOT / "binary-manifest.json").read_text())
    research = ["research/" + name for name in (
        "run-demo.py", "client.py", "fixture.py", "policy.dw", "policy-static.dw",
        "assignment.json", "tested-build.json",
    )]
    files = list(SOURCES) + research + sorted(binary_manifest["files"])
    if with_strands or with_langchain:
        directory = "langchain-example" if with_langchain else "sdk"
        label = "LangChain" if with_langchain else "Strands"
        framework_files = [directory + "/" + name for name in (
            "agent.py", "run-demo.py", "requirements.txt", "dependency-lock.txt", "dependency-manifest.json",
        )]
        dependency_manifest = json.loads((ROOT / directory / "dependency-manifest.json").read_text())
        if (dependency_manifest.get("python_minor") != "3.12"
                or dependency_manifest.get("architecture") != "aarch64"
                or (with_langchain and dependency_manifest.get("platform") != "Linux")):
            raise ValueError(label + " dependencies must target Python 3.12 on Linux ARM64")
        for name, expected in dependency_manifest["files"].items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != (directory, "vendor"):
                raise ValueError("Invalid " + label + " dependency path")
            dependency = ROOT / relative
            if with_langchain and any((ROOT / Path(*relative.parts[:i])).is_symlink()
                                      for i in range(1, len(relative.parts) + 1)):
                raise ValueError("Invalid LangChain dependency path: symbolic link")
            if dependency.is_symlink() or hashlib.sha256(dependency.read_bytes()).hexdigest() != expected:
                raise ValueError(label + " dependency checksum mismatch: " + name)
            framework_files.append(name)
        files += framework_files
    contents = {}
    for name in files:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid package path")
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing regular package file: " + name)
        data = path.read_bytes()
        expected = binary_manifest["files"].get(name)
        if expected and hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Box binary checksum mismatch: " + name)
        if name == "box-core/box" and (data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00"):
            raise ValueError("The Box executable must be Linux ARM64")
        contents[name] = data
    manifest = {"mode": ("LangChain with live Bedrock responses and scripted controls" if with_langchain else
                         "Strands SDK with live Bedrock responses and scripted controls" if with_strands else
                         "deterministic scripted workload; no language model"),
                "with_strands": with_strands,
                "box_revision": binary_manifest["box_revision"],
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}}
    if with_langchain:
        manifest.update(with_langchain=True, example="shipment-langchain")
    contents["deployment-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    archive = output / "runtime.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for name, data in sorted(contents.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            native_dependency = (with_langchain and Path(name).parts[:2] == ("langchain-example", "vendor")
                                 and (Path(name).suffix == ".so" or ".so." in Path(name).name))
            entry.external_attr = (stat.S_IFREG | (0o755 if name.startswith("box-core/") or native_dependency else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, data)
    definition = template(with_strands=with_strands, with_langchain=with_langchain)
    body = json.dumps(definition, indent=2) + "\n"
    if len(body.encode()) > 51200:
        raise ValueError("CloudFormation template exceeds the inline size limit")
    (output / "runtime.cloudformation.json").write_text(body)
    save(output / "deployment-manifest.json", manifest)
    receipt = {"archive": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
               "bytes": archive.stat().st_size, "template_bytes": len(body.encode()), "manifest": manifest}
    save(output / "package-receipt.json", receipt)
    return receipt


def session_for(args):
    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != args.account:
        raise ValueError("The selected profile does not match the explicit account")
    return session


def validate_runtime_arn(value, account, region, runtime_name):
    pattern = (r"arn:aws:bedrock-agentcore:([a-z0-9-]+):([0-9]{12}):runtime/("
               + re.escape(runtime_name) + r"-[A-Za-z0-9]+)")
    matched = re.fullmatch(pattern, value) if isinstance(value, str) else None
    if not matched or matched.group(1) != region or matched.group(2) != account:
        raise ValueError("Expected the full ARN of this isolated Runtime in the selected account and region")
    return value


def deploy(args, receipt):
    from botocore.exceptions import ClientError
    session = session_for(args)
    cfn = session.client("cloudformation")
    try:
        existing = cfn.describe_stacks(StackName=args.stack_name)["Stacks"][0]
    except ClientError as error:
        detail = error.response.get("Error", {})
        if detail.get("Code") != "ValidationError" or "does not exist" not in detail.get("Message", ""):
            raise
        existing = None
    if existing and {x["Key"]: x["Value"] for x in existing.get("Tags", [])}.get("DemoOwner") != OWNER:
        raise ValueError("Refusing to change a stack without this demonstration's ownership tag")
    s3 = session.client("s3")
    location = s3.get_bucket_location(Bucket=args.bucket, ExpectedBucketOwner=args.account)["LocationConstraint"] or "us-east-1"
    if location != args.region:
        raise ValueError("The package bucket must be in the Runtime region")
    body = (args.output_dir / "runtime.cloudformation.json").read_text()
    cfn.validate_template(TemplateBody=body)
    key = OWNER + "/" + receipt["sha256"] + "/runtime.zip"
    s3.put_object(Bucket=args.bucket, Key=key, Body=(args.output_dir / "runtime.zip").read_bytes(),
                  ContentType="application/zip", ServerSideEncryption="AES256",
                  Metadata={"sha256": receipt["sha256"]}, ExpectedBucketOwner=args.account)
    common = {"StackName": args.stack_name, "TemplateBody": body, "Capabilities": ["CAPABILITY_IAM"],
              "Parameters": [{"ParameterKey": "RuntimeName", "ParameterValue": args.stack_name.replace("-", "_")},
                             {"ParameterKey": "PackageBucket", "ParameterValue": args.bucket},
                             {"ParameterKey": "PackageKey", "ParameterValue": key}],
              "Tags": [{"Key": "DemoOwner", "Value": OWNER}],
              "ClientRequestToken": str(uuid.uuid4())}
    if existing:
        try:
            cfn.update_stack(**common)
            waiter = "stack_update_complete"
        except ClientError as error:
            if "No updates are to be performed" not in str(error):
                raise
            waiter = None
    else:
        cfn.create_stack(**common, EnableTerminationProtection=True)
        waiter = "stack_create_complete"
    if waiter:
        cfn.get_waiter(waiter).wait(StackName=args.stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 120})
    stack = cfn.describe_stacks(StackName=args.stack_name)["Stacks"][0]
    outputs = {row["OutputKey"]: row["OutputValue"] for row in stack["Outputs"]}
    control = session.client("bedrock-agentcore-control")
    wire = {}
    control.meta.events.register("after-call.bedrock-agentcore-control.GetAgentRuntime",
                                 lambda http_response, **kwargs: wire.update(json.loads(http_response.content)))
    control.get_agent_runtime(agentRuntimeId=outputs["RuntimeId"])
    if wire.get("platformVersion") != "V2" and wire.get("managedComputeConfiguration", {}).get("version") != "V2":
        raise ValueError("The deployed Runtime did not report V2")
    code = wire.get("agentRuntimeArtifact", {}).get("codeConfiguration", {}).get("code", {}).get("s3", {})
    if code.get("bucket") != args.bucket or code.get("prefix") != key:
        raise ValueError("The deployed Runtime does not reference the prepared package")
    arn = validate_runtime_arn(wire.get("agentRuntimeArn"), args.account, args.region,
                               args.stack_name.replace("-", "_"))
    result = {"stack": args.stack_name, "region": args.region, "runtime_arn": arn,
              "runtime_arn_source": "GetAgentRuntime.agentRuntimeArn",
              "package_sha256": receipt["sha256"], "runtime": wire,
              "mode": receipt["manifest"]["mode"]}
    save(args.output_dir / "deployment-receipt.json", result)
    return result


def receipt_time():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save_invocation_receipt(path, receipt, exclusive=False):
    data = json.dumps(receipt, indent=2, default=str) + "\n"
    if exclusive:
        with path.open("x") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def invoke(args):
    from botocore.config import Config
    from botocore.exceptions import ClientError
    session = session_for(args)
    record = json.loads((args.output_dir / "deployment-receipt.json").read_text())
    arn = validate_runtime_arn(record.get("runtime_arn"), args.account, args.region,
                               args.stack_name.replace("-", "_"))
    client = session.client("bedrock-agentcore", config=Config(read_timeout=300 if args.example in ("shipment-strands", "shipment-langchain") else 180, retries={"max_attempts": 0}))
    identity = str(uuid.uuid4())
    directory = args.output_dir / "invocations"
    directory.mkdir(parents=True, exist_ok=True)
    canonical = directory / (identity + ".json")
    latest = args.output_dir / ("invocation-" + args.example + "-receipt.json")
    receipt = {"created_utc": receipt_time(), "runtime_session_id": identity, "runtime_arn": arn,
               "account": args.account, "region": args.region, "stack": args.stack_name,
               "example": args.example, "qualifier": "DEFAULT", "invocation_status": "pending",
               "receipt_path": str(canonical.resolve())}
    save_invocation_receipt(canonical, receipt, exclusive=True)
    save_invocation_receipt(latest, receipt)
    print("Canonical invocation receipt: " + str(canonical), file=sys.stderr, flush=True)
    try:
        deadline = time.monotonic() + 120
        while True:
            try:
                response = client.invoke_agent_runtime(agentRuntimeArn=arn, qualifier="DEFAULT", runtimeSessionId=identity,
                                                       contentType="application/json", payload=json.dumps({"operation": "run", "example": args.example}).encode())
                break
            except ClientError as error:
                if error.response["Error"]["Code"] != "RetryableConflictException" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        try:
            result = json.loads(response["response"].read())
        finally:
            response["response"].close()
        if not isinstance(result, dict):
            raise ValueError("The Runtime response must contain a JSON object")
        receipt["result"] = result
        receipt["invocation_status"] = "passed" if result.get("status") == "PASS" else "failed"
        if receipt["invocation_status"] == "failed":
            raise RuntimeError("The deployed demonstration failed; inspect the canonical invocation receipt")
    except (Exception, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        if receipt["invocation_status"] != "failed":
            receipt["invocation_status"] = "interrupted" if interrupted else "error"
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
        outcome = "interrupted" if interrupted else "failed"
        print("Runtime invocation " + outcome + "; receipt: " + str(canonical), file=sys.stderr, flush=True)
        raise
    finally:
        receipt["observed_utc"] = receipt_time()
        save_invocation_receipt(canonical, receipt)
        save_invocation_receipt(latest, receipt)
    return receipt


def stop(args):
    from botocore.config import Config
    path = args.receipt.resolve()
    receipt = json.loads(path.read_text())
    arn = validate_runtime_arn(receipt.get("runtime_arn"), args.account, args.region,
                               args.stack_name.replace("-", "_"))
    identity = receipt.get("runtime_session_id")
    try:
        valid_identity = isinstance(identity, str) and str(uuid.UUID(identity)) == identity
    except ValueError:
        valid_identity = False
    if not valid_identity:
        raise ValueError("The receipt must contain the exact UUID session identifier created by this helper")
    canonical = (args.output_dir / "invocations" / (identity + ".json")).resolve()
    if path != canonical:
        raise ValueError("Use the exact invocations/SESSION_UUID.json receipt, not the latest example receipt")
    if any(receipt.get(key) != expected for key, expected in (
        ("account", args.account), ("region", args.region), ("stack", args.stack_name), ("qualifier", "DEFAULT"),
    )):
        raise ValueError("The receipt must match the selected account, region, stack, and DEFAULT qualifier")
    deployment = json.loads((args.output_dir / "deployment-receipt.json").read_text())
    if deployment.get("runtime_arn") != arn:
        raise ValueError("The receipt does not identify the Runtime in this deployment directory")
    session = session_for(args)
    client = session.client("bedrock-agentcore", config=Config(read_timeout=60, retries={"max_attempts": 0}))
    token = str(uuid.uuid4())
    directory = args.output_dir / "stops" / identity
    directory.mkdir(parents=True, exist_ok=True)
    stop_path = directory / (token + ".json")
    attempt = {"requested_utc": receipt_time(), "status": "pending", "client_token": token,
               "runtime_arn": arn, "runtime_session_id": identity, "qualifier": "DEFAULT",
               "account": args.account, "region": args.region, "stack": args.stack_name,
               "invocation_receipt_path": str(path), "receipt_path": str(stop_path.resolve())}
    save_invocation_receipt(stop_path, attempt, exclusive=True)
    print("Session stop receipt: " + str(stop_path), file=sys.stderr, flush=True)
    try:
        response = client.stop_runtime_session(agentRuntimeArn=arn, runtimeSessionId=identity,
                                              qualifier="DEFAULT", clientToken=attempt["client_token"])
        attempt["response"] = response
        status = response.get("statusCode", response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
        if status != 200 or response.get("runtimeSessionId", identity) != identity:
            raise ValueError("StopRuntimeSession did not confirm this request with HTTP 200")
        attempt["status"] = "request_accepted"
    except (Exception, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        attempt["status"] = "interrupted" if interrupted else "error"
        attempt["error"] = {"type": type(error).__name__, "message": str(error)}
        outcome = "interrupted" if interrupted else "failed"
        print("Session stop " + outcome + "; receipt: " + str(stop_path), file=sys.stderr, flush=True)
        raise
    finally:
        attempt["observed_utc"] = receipt_time()
        save_invocation_receipt(stop_path, attempt)
    return attempt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("package", "deploy", "invoke", "stop"))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "deployment")
    parser.add_argument("--account")
    parser.add_argument("--example", choices=("shipment", "research", "shipment-strands", "shipment-langchain"), default="shipment")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--bucket")
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--with-strands", action="store_true", help="Package the pinned Strands SDK and grant the selected model route.")
    variants.add_argument("--with-langchain", action="store_true", help="Package the pinned LangChain example and grant the selected model route.")
    parser.add_argument("--receipt", type=Path, help="Exact OUTPUT/invocations/SESSION_UUID.json for the stop command.")
    parser.add_argument("--stack-name", default="BoxShipmentDemoExample")
    args = parser.parse_args()
    if not re.fullmatch(r"BoxShipmentDemo[A-Za-z0-9-]{0,33}", args.stack_name) or len(args.stack_name) > 48:
        parser.error("Use an isolated stack name beginning with BoxShipmentDemo, at most 48 characters")
    if args.action != "package" and (not args.account or not re.fullmatch(r"[0-9]{12}", args.account)):
        parser.error("Cloud operations require an explicit 12-digit --account")
    if args.action == "deploy" and not args.bucket:
        parser.error("Deployment requires an existing same-account --bucket in the selected region")
    if args.action == "stop" and args.receipt is None:
        parser.error("Session stop requires one exact --receipt path")
    if args.action != "stop" and args.receipt is not None:
        parser.error("Use --receipt only with the stop command")
    args.output_dir = args.output_dir.resolve()
    if args.action == "invoke":
        receipt = invoke(args)
        print("Runtime demonstration passed; receipt: " + receipt["receipt_path"])
        return
    if args.action == "stop":
        receipt = stop(args)
        print("Session stop request accepted; receipt: " + receipt["receipt_path"])
        return
    receipt = package(args.output_dir, with_strands=args.with_strands, with_langchain=args.with_langchain)
    print("Package SHA-256: " + receipt["sha256"])
    print("Package and CloudFormation template: " + str(args.output_dir))
    if args.action == "deploy":
        deploy(args, receipt)
        print("Isolated Runtime deployed; receipt: " + str(args.output_dir / "deployment-receipt.json"))


if __name__ == "__main__":
    main()
