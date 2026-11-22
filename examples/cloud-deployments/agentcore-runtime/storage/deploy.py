"""Deploy and exercise the experimental Runtime storage example."""

import argparse
import json
import os
import pathlib
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config


def control(session, method, path, payload=None):
    # Sign the HTTP request because older SDK models omit filesystemConfigurations
    # or platformVersion. Service validation still applies to every field.
    client = session.client("bedrock-agentcore-control")
    url = client.meta.endpoint_url.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    request = AWSRequest(method=method, url=url, data=data,
                         headers={"Content-Type": "application/json"})
    credentials = session.get_credentials().get_frozen_credentials()
    SigV4Auth(credentials, "bedrock-agentcore", session.region_name).add_auth(request)
    wire = urllib.request.Request(url, data=data, method=method,
                                  headers=dict(request.headers))
    try:
        with urllib.request.urlopen(wire, timeout=120) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"Runtime returned HTTP {error.code}: {detail}") from error


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_runtime(session, payload, receipt, region):
    payload = dict(payload)
    payload.setdefault("clientToken", str(uuid.uuid4()))
    pending = {"creationStatus": "PENDING", "region": region, "request": payload}
    try:
        with receipt.open("x") as stream:
            json.dump(pending, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise RuntimeError("Receipt already exists; inspect it before creating another runtime: " + str(receipt)) from error
    sync_directory(receipt.parent)
    try:
        result = control(session, "PUT", "/runtimes/", payload)
    except Exception as error:
        raise RuntimeError("Create outcome is unconfirmed; keep the pending receipt at " + str(receipt)
                           + " and inspect its runtime name and clientToken before retrying: " + str(error)) from error
    try:
        with tempfile.TemporaryDirectory(prefix=".runtime-result-", dir=receipt.parent) as directory:
            completed = pathlib.Path(directory) / "result.json"
            with completed.open("x") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(completed, receipt)
            sync_directory(receipt.parent)
    except Exception as error:
        print(json.dumps(result, indent=2, default=str), flush=True)
        raise RuntimeError("Runtime creation returned a result, but saving the receipt failed. "
                           "Preserve the result printed above and inspect " + str(receipt) + ": " + str(error)) from error
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", help="Optional AWS credentials profile")
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("create")
    create.add_argument("--request", required=True, type=pathlib.Path)
    create.add_argument("--receipt", required=True, type=pathlib.Path)
    for name in ("status", "invoke", "stop", "delete"):
        sub = commands.add_parser(name)
        sub.add_argument("--receipt", required=True, type=pathlib.Path)
        if name in ("invoke", "stop"):
            sub.add_argument("--session-id", required=True)
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.action == "create":
        payload = json.loads(args.request.read_text())
        if payload.get("platformVersion") != "V2":
            parser.error("The example requires platformVersion V2")
        result = create_runtime(session, payload, args.receipt, args.region)
    else:
        saved = json.loads(args.receipt.read_text())
        if saved.get("creationStatus") == "PENDING":
            parser.error("Creation is unconfirmed; inspect the receipt's runtime name and clientToken before creating again")
        runtime_id = urllib.parse.quote(saved["agentRuntimeId"], safe="")
        if args.action in ("status", "delete"):
            result = control(session, "GET" if args.action == "status" else "DELETE",
                             f"/runtimes/{runtime_id}/")
        else:
            client = session.client("bedrock-agentcore", config=Config(
                read_timeout=180, connect_timeout=20,
                retries={"total_max_attempts": 1}))
            arguments = dict(agentRuntimeArn=saved["agentRuntimeArn"],
                             runtimeSessionId=args.session_id, qualifier="DEFAULT")
            if args.action == "stop":
                result = client.stop_runtime_session(**arguments, clientToken=str(uuid.uuid4()))
            else:
                response = client.invoke_agent_runtime(**arguments,
                    contentType="application/json", accept="application/json",
                    payload=json.dumps({"action": "run", "request_id": uuid.uuid4().hex}).encode())
                stream = response["response"]
                try:
                    result = json.loads(stream.read())
                finally:
                    stream.close()
                print(json.dumps(result, indent=2, default=str))
                if response.get("statusCode") != 200 or result.get("status") != "PASS":
                    raise SystemExit(1)
                return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
