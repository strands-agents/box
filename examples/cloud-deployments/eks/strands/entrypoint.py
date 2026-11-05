"""Run the parent and child agents with credentials held outside their Boxes."""
import argparse
import contextlib
import datetime
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parent
EVIDENCE = Path("/evidence")
ROLE_PATTERN = r"arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]+)"
class ConfigurationError(ValueError):
    pass


CREDENTIAL_OVERRIDES = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
)


def pod_token(region, expected_role):
    """Bind a short-lived token to the configured Pod Identity role."""
    import boto3
    from botocore.config import Config
    from aws_bedrock_token_generator import provide_token

    match = re.fullmatch(ROLE_PATTERN, expected_role or "")
    if not match:
        raise ConfigurationError("EXPECTED_ROLE_ARN must identify the example's Pod Identity role")
    if any(os.environ.get(name) for name in CREDENTIAL_OVERRIDES):
        raise ConfigurationError("Pod Identity mode refuses inherited credential overrides")
    token_file = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
    if not os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or not token_file or not Path(token_file).is_file():
        raise ConfigurationError("EKS Pod Identity injection is missing")
    session = boto3.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None or credentials.method != "container-role":
        raise ConfigurationError("Expected the Pod Identity container credential provider")
    identity = session.client("sts", config=Config(connect_timeout=5, read_timeout=10,
                              retries={"total_max_attempts": 2})).get_caller_identity()
    partition, account, role = match.groups()
    prefix = "arn:" + partition + ":sts::" + account + ":assumed-role/" + role.rsplit("/", 1)[-1] + "/"
    if identity.get("Account") != account or not identity.get("Arn", "").startswith(prefix):
        raise ConfigurationError("The pod identity differs from the configured role")

    class BoundProvider:
        def load(self):
            return credentials

    token = provide_token(region=region, aws_credentials_provider=BoundProvider(),
                          expiry=datetime.timedelta(minutes=15))
    return token, {"credential_provider": credentials.method,
                   "aws_identity": {key: identity[key] for key in ("Account", "Arn")},
                   "token_expiry_minutes": 15}


def build_facts():
    """Verify the packaged Box binaries before starting the agents."""
    build = json.loads((ROOT / "box-build.json").read_text())
    expected = {"strands-box", "strands-box-sock-alias", "strands-box-contain-trampoline"}
    if set(build["binaries"]) != expected:
        raise ValueError("The image has an incomplete Box binary manifest")
    for name, digest in build["binaries"].items():
        if hashlib.sha256((Path("/usr/local/bin") / name).read_bytes()).hexdigest() != digest:
            raise ValueError("A packaged Box binary differs from its build manifest")
    return {"box": build, "kernel": platform.release(), "architecture": platform.machine(),
            "python": platform.python_version(), "uid": os.getuid(), "gid": os.getgid(),
            "packages": {name: importlib.metadata.version(name) for name in
                         ("strands-agents", "boto3", "botocore", "pydantic", "aws-bedrock-token-generator")},
            "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in sorted(ROOT.glob("*.py"))}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["baseline", "alternate"], default="baseline")
    parser.add_argument("--auth", choices=["pod-identity", "bearer-token"], default="pod-identity")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--model", default=os.environ.get("BEDROCK_MODEL_ID"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"))
    args = parser.parse_args(argv)
    output = (args.output or EVIDENCE / (args.mode + "-" + uuid.uuid4().hex)).resolve()
    result = {"passed": False, "checks": {}, "receipt": None, "platform": {}, "error": None}
    diagnostics = io.StringIO()
    token = ""
    try:
        if not args.model or not args.region:
            raise ConfigurationError("Set BEDROCK_MODEL_ID and AWS_REGION, or supply --model and --region")
        if output.parent != EVIDENCE.resolve() or output.exists():
            raise ConfigurationError("Output must be a new direct child of /evidence")
        facts = build_facts()
        if args.auth == "pod-identity":
            token, identity = pod_token(args.region, os.environ.get("EXPECTED_ROLE_ARN"))
        else:
            token = os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "")
            if not token:
                raise ConfigurationError("Bearer-token mode needs AWS_BEARER_TOKEN_BEDROCK")
            identity = {"credential_provider": "caller-bearer-token", "aws_identity": None,
                        "token_expiry_minutes": None}
        facts.update(identity, mode=args.mode, model_id=args.model, region=args.region)
        result["platform"] = facts
        os.environ["AWS_BEARER_TOKEN_BEDROCK"] = token
        import controller
        from verify import validate
        with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
            code = controller.main(["--output", str(output), "--model", args.model,
                                    "--region", args.region, "--mode", args.mode, "--timeout", "300"])
        receipt = json.loads((output / "receipt.json").read_text())
        result["receipt"] = receipt
        if code != 0 or receipt.get("passed") is not True:
            raise ValueError("The agent workflow did not complete successfully")
        validation = validate(receipt, expected_program=ROOT / "agent_program.py")
        checks = validation.get("checks")
        if validation.get("verified") is not True or not isinstance(checks, dict) or not checks or any(
                value is not True for value in checks.values()):
            raise ValueError("The receipt verifier did not confirm every check")
        result.update(passed=True, checks=checks)
    except Exception as error:
        result["error"] = (str(error) if isinstance(error, ConfigurationError) else
                           type(error).__name__ + ": the example failed; inspect its receipt and pod diagnostics")
    finally:
        os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
        text = diagnostics.getvalue()
        if text:
            sys.stderr.write(text.replace(token, "[REDACTED]") if token else text)
        try:
            text = json.dumps(result, allow_nan=False)
        except (ValueError, TypeError):
            result.update(passed=False, checks={}, receipt=None, error="The result is not valid JSON")
            text = json.dumps(result, allow_nan=False)
        print(text.replace(token, "[REDACTED]") if token else text, flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
