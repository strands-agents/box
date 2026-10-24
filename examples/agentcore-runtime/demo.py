#!/usr/bin/env python3
"""Prepare, deploy, and verify both Runtime examples in your AWS account."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

import boto3

ROOT = Path(__file__).resolve().parent
BASELINE_SHA256 = "89e8547d009731cd3f4a671e15b0f3485a254cc0085e201484bd25e1b3047271"
BASELINE_REVISION = "913f5367f57424b3bda65dc4a05278a5664f635d"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--box-package", type=Path)
    parser.add_argument("--box-sha256", default=BASELINE_SHA256)
    parser.add_argument("--box-revision", default=BASELINE_REVISION)
    parser.add_argument("--claude-package", type=Path)
    parser.add_argument("--exercise", action="store_true",
                        help="Also run the Claude functionality exercise on both runtimes")
    parser.add_argument("--skip-deploy", action="store_true",
                        help="Verify the existing example stack without packaging or deployment")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{12}", args.account):
        parser.error("--account must contain 12 digits")
    if not args.skip_deploy and args.box_package is None:
        parser.error("--box-package is required for deployment")
    session = boto3.Session(profile_name=args.profile, region_name="us-west-2")
    if session.client("sts").get_caller_identity()["Account"] != args.account:
        raise RuntimeError("The AWS profile does not select --account")
    env = dict(os.environ, AWS_REGION="us-west-2", AWS_DEFAULT_REGION="us-west-2")
    if args.profile:
        env["AWS_PROFILE"] = args.profile
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                    "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"):
            env.pop(key, None)

    def run(command, cwd=ROOT):
        print("\n$ " + shlex.join(list(map(str, command))), flush=True)
        subprocess.run(command, cwd=cwd, env=env, check=True)

    if not args.skip_deploy:
        from prepare import prepare
        if not shutil.which("agentcore") or not shutil.which("docker"):
            raise RuntimeError("Install the AgentCore CLI and Docker first")
        args.box_package = args.box_package.expanduser().resolve()
        if args.claude_package:
            args.claude_package = args.claude_package.expanduser().resolve()
        prepare(args)
        run(["agentcore", "validate"])
        cdk = ROOT / "agentcore/cdk"
        if not (cdk / "node_modules").exists():
            run(["npm", "ci", "--no-audit", "--no-fund"], cwd=cdk)
        for mode in ("managed", "container"):
            run(["agentcore", "package", "--runtime", "boxdemo_" + mode])
        run(["agentcore", "deploy", "--dry-run", "--target", "default", "--json"])
        run(["agentcore", "deploy", "--target", "default", "--yes", "--json"])

    spec = json.loads((ROOT / "agentcore/agentcore.json").read_text())
    stack_name = "AgentCore-" + spec["name"] + "-default"
    cfn = session.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if not stack.get("EnableTerminationProtection"):
        raise RuntimeError("The example stack must retain termination protection")
    if stack["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise RuntimeError("The example stack is not ready")
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    control = session.client("bedrock-agentcore-control")
    targets = {}
    for row in resources:
        if row["ResourceType"] == "AWS::BedrockAgentCore::Runtime":
            target = control.get_agent_runtime(agentRuntimeId=row["PhysicalResourceId"].rsplit("/", 1)[-1])
            mode = target["environmentVariables"]["DEMO_MODE"]
            if mode in targets:
                raise RuntimeError("Duplicate deployment mode")
            targets[mode] = target["agentRuntimeArn"]
    if set(targets) != {"managed", "container"}:
        raise RuntimeError("Expected one managed and one container runtime")
    for mode in ("managed", "container"):
        command = [sys.executable, str(ROOT / "invoke.py"), "--arn", targets[mode]]
        if args.profile:
            command += ["--profile", args.profile]
        run(command)
        if args.exercise:
            run(command + ["--agent", "claude", "--exercise"])
    print("\nBoth deployment types passed. Evidence is in " + str(ROOT / "results"))
    print("Cloud resources remain deployed. New Runtime sessions include /var/tmp/box-manual/box.toml.")


if __name__ == "__main__":
    main()
