#!/usr/bin/env python3
"""Run the throwaway AWS credential prototype against STS GetCallerIdentity."""

import argparse
import configparser
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HOST = "sts.us-east-1.amazonaws.com"
URL = f"https://{HOST}/?Action=GetCallerIdentity&Version=2011-06-15"


def seed_environment(environment, profile):
    config = configparser.RawConfigParser()
    config.read(
        environment.get("AWS_CONFIG_FILE", str(Path.home() / ".aws" / "config"))
    )
    section = "default" if profile == "default" else f"profile {profile}"
    command = shlex.split(config.get(section, "credential_process"))
    reply = subprocess.run(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=35,
        check=False,
    )
    if reply.returncode:
        raise SystemExit("The seed credential_process failed; its output was withheld.")
    credentials = json.loads(reply.stdout)
    for variable, field in (
        ("AWS_ACCESS_KEY_ID", "AccessKeyId"),
        ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
        ("AWS_SESSION_TOKEN", "SessionToken"),
    ):
        if credentials.get(field):
            environment[variable] = credentials[field]
        else:
            environment.pop(variable, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=("chain", "profile"))
    parser.add_argument("--profile", help="AWS_PROFILE for the chain, or the explicit profile name.")
    parser.add_argument(
        "--seed-profile",
        help="For the chain demo, fetch a profile's credentials into the parent environment.",
    )
    parser.add_argument("--calls", type=int, default=1)
    args = parser.parse_args()
    environment = dict(os.environ)
    if args.source == "chain":
        if args.seed_profile:
            seed_environment(environment, args.seed_profile)
        if args.profile:
            environment["AWS_PROFILE"] = args.profile
        reference = "aws-chain://"
    else:
        reference = f"aws://{args.profile or 'bedrock'}"
    binary = ROOT / "target/debug/strands-box"
    probe = ROOT / "target/debug/box-egress-probe"
    if not binary.is_file() or not probe.is_file():
        raise SystemExit("Build first: cargo build -p strands-box --all-features --bins")
    results = []
    with tempfile.TemporaryDirectory(prefix="box-aws-", dir="/var/tmp") as directory:
        scratch = Path(directory)
        workspace = scratch / "work"
        workspace.mkdir()
        policy = scratch / "policy.dw"
        policy.write_text(
            f'permit(principal, action == Box::Action::"net:connect", resource)\n'
            f'when {{ context.input.host == "{HOST}" && context.input.port == 443 }};\n'
            f'permit(principal, action == Box::Action::"http:request", resource)\n'
            f'when {{ context.input.host == "{HOST}" && context.input.method == "GET" }};\n'
        )
        config = scratch / "box.toml"
        workload = [
            str(probe), URL, "AWS_ACCESS_KEY_ID", "--", "/usr/bin/true"
        ]
        config.write_text(
            'name = "aws-prototype"\n'
            f"box_dir = {json.dumps(str(scratch / 'state'))}\n"
            f"policy = {json.dumps(str(policy))}\n"
            "[agent]\n"
            f"command = {json.dumps(workload)}\n"
            f"workspace = {json.dumps(str(workspace))}\n"
            "[agent.filesystem]\n"
            'exec = ["/usr/bin/true"]\n'
            "[egress.aws]\n"
            f"destinations = [{json.dumps(HOST)}]\n"
            f"secret.ref = {json.dumps(reference)}\n"
        )
        for _ in range(args.calls):
            result = subprocess.run(
                [str(binary), "run", "--config", str(config)],
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            passed = (
                result.returncode == 0
                and "status=200" in result.stdout
                and "status_after=200" in result.stdout
            )
            results.append({
                "source": args.source,
                "exit": result.returncode,
                "both_sts_requests_200": passed,
            })
            if not passed:
                print(result.stdout)
                print(result.stderr)
                raise SystemExit(1)
    print(json.dumps({"runs": results}, indent=2))


if __name__ == "__main__":
    main()
