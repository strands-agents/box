"""Mint a short-term Bedrock API key from AWS credentials with aws-bedrock-token-generator.

The Workloads workflow (.github/workflows/workloads.yml) assumes the workloads role through GitHub
OIDC, then runs this to turn that session into the bearer key the box and the judge use. Bedrock
honours the key until its expiry runs out or the session that signed it ends, whichever is first.
The workflow installs the package from bedrock-key-requirements.txt, with each hash checked.

Usage (credentials from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN):
  bedrock_key.py --region us-west-2 --expires 7200 --out KEYFILE

The key goes to KEYFILE, created with mode 0600. Standard output gets only a GitHub `::add-mask::` line,
so the key never shows in a job log.
"""
import argparse
import datetime
import os
import sys

MAX_EXPIRES = 43200  # 12 hours, the longest a short-term key lasts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", ""))
    ap.add_argument("--expires", type=int, default=MAX_EXPIRES)
    ap.add_argument("--out", required=True, help="the file to write the key to (mode 0600)")
    args = ap.parse_args(argv)
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        sys.exit("bedrock_key.py: AWS credentials are missing")
    if not args.region:
        sys.exit("bedrock_key.py: a Region is required")
    if not 1 <= args.expires <= MAX_EXPIRES:
        sys.exit(f"bedrock_key.py: expires must be between 1 and {MAX_EXPIRES} seconds")
    from aws_bedrock_token_generator import provide_token
    key = provide_token(region=args.region, expiry=datetime.timedelta(seconds=args.expires))
    print(f"::add-mask::{key}", flush=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")


if __name__ == "__main__":
    main()
