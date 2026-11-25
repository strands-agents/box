#!/usr/bin/env python3
"""Create and exercise one Runtime while preserving borrowed images, roles, and storage."""
import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid


def write_json(path, value, replace=False):
    if not replace:
        with path.open("x") as stream:
            json.dump(value, stream, indent=2, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    else:
        with tempfile.TemporaryDirectory(prefix=".runtime-receipt-", dir=path.parent) as directory:
            temporary = Path(directory) / "receipt.json"
            write_json(temporary, value)
            os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_request(payload):
    if payload.get("platformVersion") != "V2":
        raise ValueError("Use platformVersion V2 so Box starts in the initial snapshot")
    if payload.get("architecture", "ARM64") != "ARM64":
        raise ValueError("This image requires architecture ARM64")
    payload["architecture"] = "ARM64"
    if "capacityProviderConfiguration" in payload:
        raise ValueError("This example requires managed Runtime V2 without a capacity provider")
    mounts = payload.get("filesystemConfigurations", [])
    if len(mounts) != 1 or len(mounts[0]) != 1:
        raise ValueError("Configure exactly one storage provider")
    provider, config = next(iter(mounts[0].items()))
    if provider not in {"sessionStorage", "efsAccessPoint", "s3FilesAccessPoint", "s3BucketMount"}:
        raise ValueError("Use sessionStorage, efsAccessPoint, s3FilesAccessPoint, or s3BucketMount")
    allowed = {"sessionStorage": {"mountPath"},
               "efsAccessPoint": {"mountPath", "accessPointArn"},
               "s3FilesAccessPoint": {"mountPath", "accessPointArn"},
               "s3BucketMount": {"mountPath", "bucket", "prefix", "s3BucketRegion", "s3BucketOwner"}}
    if not isinstance(config, dict) or set(config) - allowed[provider]:
        raise ValueError("Unexpected fields in the storage provider configuration")
    required = {"sessionStorage": {"mountPath"}, "efsAccessPoint": {"mountPath", "accessPointArn"},
                "s3FilesAccessPoint": {"mountPath", "accessPointArn"},
                "s3BucketMount": {"mountPath", "bucket", "prefix"}}[provider]
    if required - set(config) or any(not isinstance(value, str) or not value for value in config.values()):
        raise ValueError("Storage provider fields must be nonempty strings")
    mount_path = config.get("mountPath", "")
    if not mount_path.startswith("/") or mount_path == "/":
        raise ValueError("The provider mountPath must be an absolute directory below /")
    environment = payload.setdefault("environmentVariables", {})
    if environment.get("STORAGE_PATH", mount_path) != mount_path:
        raise ValueError("STORAGE_PATH must equal the provider mountPath")
    environment["STORAGE_PATH"] = mount_path
    if provider in {"efsAccessPoint", "s3FilesAccessPoint"} and payload.get("networkConfiguration", {}).get("networkMode") != "VPC":
        raise ValueError("EFS and S3 Files require VPC network mode")
    return payload


def send_create(client, request):
    """Add three documented fields after older SDK models serialize the request.

    Botocore still selects the endpoint, signs the final body, sends the request,
    and parses service errors. The handler applies to this one create call only.
    """
    extensions = {key: request[key] for key in ["platformVersion", "architecture", "filesystemConfigurations"]}
    parameters = {key: value for key, value in request.items() if key not in extensions}
    event = "before-call." + client.meta.service_model.service_id.hyphenize() + ".CreateAgentRuntime"
    identifier = "runtime-storage-example-" + uuid.uuid4().hex

    def inject(params, **_):
        body = json.loads(params["body"])
        if set(body) & set(extensions):
            raise ValueError("The SDK unexpectedly serialized an extension field")
        body.update(extensions)
        params["body"] = json.dumps(body).encode()
        for key in list(params["headers"]):
            if key.lower() == "content-length":
                params["headers"][key] = str(len(params["body"]))

    client.meta.events.register(event, inject, unique_id=identifier)
    try:
        return client.create_agent_runtime(**parameters)
    finally:
        client.meta.events.unregister(event, unique_id=identifier)


def create_runtime(client, payload, receipt, region):
    request = validate_request(copy.deepcopy(payload))
    request.setdefault("clientToken", str(uuid.uuid4()))
    saved = {"schema": 1, "creation_status": "PENDING", "region": region, "owns_runtime": True,
             "request": request, "borrowed_resources": {
                 key: request.get(key) for key in ["roleArn", "agentRuntimeArtifact", "networkConfiguration", "filesystemConfigurations"]}}
    write_json(receipt, saved)
    try:
        saved["response"] = send_create(client, request)
        saved["creation_status"] = "CONFIRMED"
        write_json(receipt, saved, replace=True)
    except Exception as exc:
        saved["creation_error"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(receipt, saved, replace=True)
        raise RuntimeError("Creation outcome may be unknown. Keep the receipt and inspect its runtime name, clientToken, and creation_error before retrying: " + str(receipt)) from exc
    return saved


def load_owned(receipt, region):
    saved = json.loads(receipt.read_text())
    if saved.get("schema") != 1 or saved.get("region") != region or saved.get("owns_runtime") is not True:
        raise ValueError("Use the creation receipt for this example and Region")
    if saved.get("creation_status") != "CONFIRMED":
        raise ValueError("Creation is unconfirmed; inspect the pending request before another create or delete")
    return saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("create")
    create.add_argument("--request", type=Path, required=True)
    create.add_argument("--receipt", type=Path, required=True)
    for name in ["status", "invoke", "stop", "delete"]:
        sub = commands.add_parser(name)
        sub.add_argument("--receipt", type=Path, required=True)
        if name in {"invoke", "stop"}:
            sub.add_argument("--session-id", required=True)
        if name == "invoke":
            sub.add_argument("--operation", choices=["inspect", "run", "read", "finish"], default="run")
            sub.add_argument("--previous", type=Path, help="Earlier invocation JSON containing persistent_file; required for read")
            sub.add_argument("--output", type=Path, required=True, help="New file for this invocation's evidence")
    args = parser.parse_args()
    # Load the SDK only for explicit deployment actions; offline tests do not need AWS access.
    import boto3
    from botocore.config import Config
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    control = session.client("bedrock-agentcore-control", config=Config(retries={"total_max_attempts": 1}))
    if args.action == "create":
        result = create_runtime(control, json.loads(args.request.read_text()), args.receipt, args.region)
    else:
        saved = load_owned(args.receipt, args.region)
        runtime = saved["response"]
        if args.action == "status":
            result = control.get_agent_runtime(agentRuntimeId=runtime["agentRuntimeId"])
        elif args.action == "delete":
            result = control.delete_agent_runtime(agentRuntimeId=runtime["agentRuntimeId"])
        else:
            if len(args.session_id) < 33:
                parser.error("Use a Runtime session ID of at least 33 characters")
            client = session.client("bedrock-agentcore", config=Config(read_timeout=180, connect_timeout=20,
                                      retries={"total_max_attempts": 1}))
            arguments = {"agentRuntimeArn": runtime["agentRuntimeArn"], "runtimeSessionId": args.session_id, "qualifier": "DEFAULT"}
            if args.action == "stop":
                result = client.stop_runtime_session(**arguments, clientToken=str(uuid.uuid4()))
            else:
                payload = {"action": args.operation, "request_id": uuid.uuid4().hex}
                if args.operation == "read":
                    if not args.previous:
                        parser.error("read requires --previous with an earlier invocation receipt")
                    payload.update(json.loads(args.previous.read_text())["result"]["persistent_file"])
                evidence = {"region": args.region, "runtime_arn": runtime["agentRuntimeArn"],
                            "session_id": args.session_id, "request": payload, "status": "PENDING"}
                write_json(args.output, evidence)
                response = client.invoke_agent_runtime(**arguments, contentType="application/json", accept="application/json",
                                                       payload=json.dumps(payload).encode())
                stream = response["response"]
                try:
                    result = json.loads(stream.read())
                finally:
                    stream.close()
                evidence.update(status="COMPLETE", http_status=response.get("statusCode"), result=result)
                write_json(args.output, evidence, replace=True)
                print(json.dumps(evidence, indent=2, default=str))
                if response.get("statusCode") != 200 or (args.operation != "inspect" and result.get("status") != "PASS"):
                    raise SystemExit(1)
                return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
