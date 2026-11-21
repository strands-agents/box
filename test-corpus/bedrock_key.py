"""Mint a short-term Bedrock API key from AWS credentials, with the standard library only.

The Workloads workflow (.github/workflows/workloads.yml) assumes the workloads role through GitHub
OIDC, then runs this to turn that session into the bearer key the box and the judge use. It does what
aws-bedrock-token-generator 1.1.0 does: it presigns a `CallWithBearerToken` request to
bedrock.amazonaws.com with SigV4, and the key is `bedrock-api-key-` plus that URL in base64. Bedrock
honours the key until X-Amz-Expires runs out or the session that signed it ends, whichever is first.

Usage (credentials from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN):
  bedrock_key.py --region us-west-2 --expires 7200 --out KEYFILE

The key goes to KEYFILE, created with mode 0600. Standard output gets only a GitHub `::add-mask::` line,
so the key never shows in a job log.

Runs on the Python a macOS runner ships before setup-python (3.9), so it uses no newer syntax.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import os
import sys
import urllib.parse

HOST = "bedrock.amazonaws.com"
SERVICE = "bedrock"
PREFIX = "bedrock-api-key-"
MAX_EXPIRES = 43200  # 12 hours, the longest a short-term key lasts
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _quote(text):
    return urllib.parse.quote(text, safe="-_.~")


def _hmac(key, text):
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def mint(access_key, secret_key, session_token, region, expires, now):
    """The key for these credentials, valid `expires` seconds from `now` (a UTC datetime)."""
    if not access_key or not secret_key:
        raise ValueError("AWS credentials are missing")
    if not region:
        raise ValueError("a Region is required")
    if not 1 <= expires <= MAX_EXPIRES:
        raise ValueError("expires must be between 1 and %d seconds" % MAX_EXPIRES)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    scope = "%s/%s/%s/aws4_request" % (amz_date[:8], region, SERVICE)
    params = [
        ("Action", "CallWithBearerToken"),
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", "%s/%s" % (access_key, scope)),
        ("X-Amz-Date", amz_date),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    if session_token:
        params.append(("X-Amz-Security-Token", session_token))
    encoded = [(_quote(k), _quote(v)) for k, v in params]
    query = "&".join("%s=%s" % kv for kv in encoded)
    canonical_request = "\n".join([
        "POST", "/", "&".join("%s=%s" % kv for kv in sorted(encoded)),
        "host:%s\n" % HOST, "host", EMPTY_SHA256,
    ])
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), amz_date[:8])
    for part in (region, SERVICE, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    url = "%s/?%s&X-Amz-Signature=%s&Version=1" % (HOST, query, signature)
    return PREFIX + base64.b64encode(url.encode("utf-8")).decode("ascii")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", ""))
    ap.add_argument("--expires", type=int, default=MAX_EXPIRES)
    ap.add_argument("--out", required=True, help="the file to write the key to (mode 0600)")
    args = ap.parse_args(argv)
    try:
        key = mint(os.environ.get("AWS_ACCESS_KEY_ID", ""), os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
                   os.environ.get("AWS_SESSION_TOKEN", ""), args.region, args.expires,
                   datetime.datetime.now(datetime.timezone.utc))
    except ValueError as e:
        sys.exit("bedrock_key.py: %s" % e)
    print("::add-mask::%s" % key, flush=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")


if __name__ == "__main__":
    main()
