#!/usr/bin/env python3
"""Sign, notarize, and verify the macOS release through the configured services."""

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import typing
from urllib.parse import urlsplit
import uuid
import zipfile

IDENTIFIER = "com.amazon.strands.box"
ENTITLEMENT = "com.apple.developer.endpoint-security.client"
BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
LAUNCHER = '''#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$root/Box.app/Contents/MacOS/box" "$@"
'''
NOTARY_TIMEOUT = "30m"
SUBMISSION_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
SECRET_ARN = r"arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+"
APPLE_ID = r"[A-Za-z0-9][^@\s]*@[^@\s]+\.[^@\s]+"
APP_SPECIFIC_PASSWORD = r"[a-z0-9]{4}(?:-[a-z0-9]{4}){3}"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack_build(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as source:
        members = {}
        for member in source.getmembers():
            name = member.name.removeprefix("./")
            if member.isdir() and name in ("", "."):
                continue
            require(name in BINARIES and member.isfile(), "Unexpected build archive entry")
            require(name not in members, "Duplicate build archive entry")
            members[name] = member
        require(set(members) == set(BINARIES), "Incomplete build archive")
        for name, member in members.items():
            with source.extractfile(member) as stream, (destination / name).open("xb") as output:
                shutil.copyfileobj(stream, output)
            (destination / name).chmod(0o755)


def unpack_signed(archive, destination, root):
    destination.mkdir()
    with zipfile.ZipFile(archive) as source:
        seen = set()
        total = 0
        for member in source.infolist():
            path = PurePosixPath(member.filename)
            require(not path.is_absolute() and ".." not in path.parts, "Unsafe signed archive path")
            require(path.parts and path.parts[0] == root, "Unexpected signed archive root")
            require(str(path) not in seen, "Duplicate signed archive path")
            seen.add(str(path))
            mode = member.external_attr >> 16
            require(member.is_dir() or stat.S_ISREG(mode), "Unexpected signed archive file type")
            require(not stat.S_ISLNK(mode), "Signed archive contains a symlink")
            total += member.file_size
            require(total <= 1024 * 1024 * 1024, "Signed archive exceeds 1 GiB")
        for member in source.infolist():
            target = destination / member.filename
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod((member.external_attr >> 16) & 0o777)


def prepare_bundle(binaries, destination, version):
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-linux-preview\.[1-9]\d*)?", version),
            "Invalid release version")
    app = destination / "Box.app"
    executables = app / "Contents/MacOS"
    executables.mkdir(parents=True)
    for name in BINARIES:
        shutil.copy2(binaries / name, executables / name)
    with (app / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({
            "CFBundleIdentifier": IDENTIFIER,
            "CFBundleExecutable": "box",
            "CFBundleName": "Box",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": version.split("-")[0],
            "CFBundleShortVersionString": version.split("-")[0],
        }, stream)
    metadata = destination / "SIGNING_METADATA"
    metadata.mkdir()
    with (metadata / "Box.entitlements").open("wb") as stream:
        plistlib.dump({ENTITLEMENT: True}, stream)
    return app


def stage_package(app, stage):
    stage.mkdir()
    shutil.copytree(app, stage / "Box.app")
    (stage / "box").write_text(LAUNCHER)
    (stage / "box").chmod(0o755)
    for name in BINARIES[1:]:
        (stage / name).symlink_to(f"Box.app/Contents/MacOS/{name}")


def manifest(team, profile=None):
    requirements = {"team_id": team}
    if profile:
        requirements.update({
            "profile_name": profile,
            "profile_type": "distribution",
            "signing_args": {"entitlements_path": "SIGNING_METADATA/Box.entitlements"},
        })
    else:
        requirements["certificate_type"] = "developerIDAppDistribution"
    return {
        "type": "app", "os": "osx", "name": "Box",
        "outputs": [{"label": "macos", "path": "Box.app" if profile else "EXECUTABLES_TO_SIGN"}],
        "app": {"identifier": IDENTIFIER, "signing_requirements": requirements},
    }


def verify(app, team, profile_name, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    require(re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid Apple team ID")
    executable = app / "Contents/MacOS/box"
    requirement = (
        f'anchor apple generic and identifier "{IDENTIFIER}" '
        'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
        f'and certificate leaf[subject.OU] = "{team}"'
    )
    for path in (app, *(app / "Contents/MacOS" / name for name in BINARIES)):
        subprocess.run(["codesign", "--verify", "--strict", "-R", "=" + requirement, str(path)], check=True)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(info["CFBundleIdentifier"] == IDENTIFIER and info["CFBundleExecutable"] == "box",
            "Unexpected bundle identity or entry point")
    entitlements = plistlib.loads(subprocess.check_output(
        ["codesign", "-d", "--entitlements", ":-", str(executable)],
        stderr=subprocess.DEVNULL,
    ))
    profile = plistlib.loads(subprocess.check_output(
        ["security", "cms", "-D", "-i", str(app / "Contents/embedded.provisionprofile")],
    ))
    for values in (entitlements, profile["Entitlements"]):
        require(values.get(ENTITLEMENT) is True, "Missing Endpoint Security authorization")
        require(values.get("com.apple.application-identifier") == f"{team}.{IDENTIFIER}",
                "Application identifier mismatch")
        require(values.get("com.apple.developer.team-identifier") == team, "Team mismatch")
    require(profile["Name"] == profile_name and profile["TeamIdentifier"] == [team],
            "Unexpected provisioning profile")
    require(profile["ExpirationDate"] > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
            "Expired provisioning profile")
    prefix = str(evidence / "certificate-")
    subprocess.run(["codesign", "-d", "--extract-certificates=" + prefix, str(executable)],
                   check=True, capture_output=True)
    require(Path(prefix + "0").read_bytes() in profile["DeveloperCertificates"],
            "Signing certificate is not authorized by the profile")
    details = subprocess.run(["codesign", "-dvvv", str(executable)], check=True,
                             capture_output=True, text=True).stderr
    require(f"Identifier={IDENTIFIER}\n" in details and f"TeamIdentifier={team}\n" in details,
            "Unexpected signature identity")
    require("Authority=Developer ID Application:" in details, "Not a Developer ID signature")
    require("runtime" in details and "Timestamp=" in details, "Missing runtime hardening or timestamp")
    save(evidence / "verification.json", {
        "identifier": IDENTIFIER, "team": team, "profile": profile_name,
        "profile_uuid": profile["UUID"], "entitlements": entitlements,
        "binaries": {name: digest(app / "Contents/MacOS" / name) for name in BINARIES},
    })


class NotaryAuth(typing.NamedTuple):
    options: list
    password: typing.Optional[str] = None
    apple_id: typing.Optional[str] = None


def notary_credential(secret):
    try:
        value = json.loads(secret)
    except ValueError:
        value = None
    require(isinstance(value, dict), "Notarization secret is not a JSON object")
    apple = {"apple_id", "app_specific_password"} & value.keys()
    require(not (apple and {"key_id", "private_key"} & value.keys()),
            "Notarization secret holds both an API key and an Apple ID")
    if apple:
        apple_id, password = value.get("apple_id"), value.get("app_specific_password")
        require(isinstance(apple_id, str) and re.fullmatch(APPLE_ID, apple_id),
                "Invalid notarization Apple ID")
        require(isinstance(password, str) and re.fullmatch(APP_SPECIFIC_PASSWORD, password),
                "Invalid app-specific password")
        return "apple-id", apple_id, password
    key_id, key = value.get("key_id"), value.get("private_key")
    require(isinstance(key_id, str) and re.fullmatch(r"[A-Z0-9]{10,}", key_id),
            "Invalid notarization key ID")
    require(isinstance(key, str) and key.strip().startswith("-----BEGIN PRIVATE KEY-----")
            and key.strip().endswith("-----END PRIVATE KEY-----"),
            "Invalid notarization private key")
    return "api-key", key_id, key


@contextlib.contextmanager
def notary_auth(profile=None, credential=None, team=None):
    if profile:
        yield NotaryAuth(["--keychain-profile", profile])
        return
    kind, identity, secret = credential
    if kind == "apple-id":
        yield NotaryAuth(["--apple-id", identity, "--team-id", team], secret, identity)
        return
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "notary.p8"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write(secret)
        yield NotaryAuth(["--key", str(path), "--key-id", identity])


def notarytool(auth, *arguments):
    # The password goes on standard input, never in an argument list. A new session has no
    # terminal, so notarytool reads standard input instead of prompting on a terminal.
    options = {"input": auth.password + "\n", "start_new_session": True} if auth.password else {}
    result = subprocess.run(["xcrun", "notarytool", *arguments, *auth.options],
                            capture_output=True, text=True, **options)
    if auth.apple_id:
        # Keep the prompt, the password, and the Apple ID out of logs and saved evidence.
        result.stdout, result.stderr = (
            text.replace(f"Password for {auth.apple_id}: ", "").replace(auth.password, "<password>")
            .replace(auth.apple_id, "<apple-id>")
            for text in (result.stdout, result.stderr))
    return result


def notarize(app, auth, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    archive = evidence / "Box.zip"
    subprocess.run(["ditto", "-c", "-k", "--keepParent", str(app), str(archive)], check=True)
    submitted = notarytool(auth, "submit", str(archive), "--wait",
                           "--timeout", NOTARY_TIMEOUT, "--output-format", "json")
    try:
        submission = json.loads(submitted.stdout)
    except ValueError:
        submission = None
    if not isinstance(submission, dict):
        submission = {"output": (submitted.stdout + submitted.stderr)[-2000:]}
    save(evidence / "submission.json", submission)
    identifier = str(submission.get("id", ""))
    require(re.fullmatch(SUBMISSION_ID, identifier), "Notarization submission failed: "
            + str(submission.get("message") or submitted.stderr or submitted.stdout)[-500:])
    log = evidence / "log.json"
    if notarytool(auth, "log", identifier, str(log)).returncode:
        print(f"Could not download the notarization log for {identifier}", flush=True)
    status = submission.get("status")
    if status != "Accepted" and log.exists():
        print(log.read_text(), flush=True)
    require(status == "Accepted", f"Notarization {identifier} ended with status {status}")
    for attempt in range(1, 6):
        stapled = subprocess.run(["xcrun", "stapler", "staple", str(app)],
                                 capture_output=True, text=True)
        if stapled.returncode == 0:
            break
        require(attempt < 5, f"Stapling failed: {(stapled.stdout + stapled.stderr)[-500:]}")
        time.sleep(30)
    return identifier


def verify_notarization(app, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    stapled = subprocess.run(["xcrun", "stapler", "validate", str(app)],
                             capture_output=True, text=True)
    require(stapled.returncode == 0, "Missing or invalid stapled notarization ticket")
    paths = (app, *(app / "Contents/MacOS" / name for name in BINARIES))
    for path in paths:
        subprocess.run(["codesign", "--verify", "--strict", "--check-notarization",
                        "-R", "=notarized", str(path)], check=True)
    save(evidence / "notarization.json", {
        "stapled": True, "notarized": [str(path.relative_to(app.parent)) for path in paths],
    })


class Signer:
    def __init__(self):
        import boto3
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        import requests

        self.session = boto3.Session()
        self.s3 = self.session.client("s3")
        self.region = os.environ["AWS_REGION"]
        self.endpoint = os.environ["CD_SIGNER_ENDPOINT"].rstrip("/")
        endpoint = urlsplit(self.endpoint)
        require(endpoint.scheme == "https" and endpoint.hostname and not endpoint.username
                and not endpoint.password and not endpoint.query and not endpoint.fragment
                and endpoint.path in ("", "/"), "Invalid signing endpoint")
        self.bucket = os.environ["CD_SIGNER_BUCKET"]
        self.access_role = os.environ["CD_SIGNER_BUCKET_ACCESS_ROLE"]
        self.team = os.environ["CD_SIGNER_TEAM_ID"]
        self.profile = os.environ["CD_SIGNER_PROFILE_NAME"]
        require(re.fullmatch(r"[A-Z0-9]{10}", self.team), "Invalid Apple team ID")
        require(bool(self.profile.strip()), "Missing Apple profile name")
        self.SigV4Auth, self.AWSRequest, self.requests = SigV4Auth, AWSRequest, requests

    def request(self, method, path, body=None):
        data = json.dumps(body) if body is not None else ""
        request = self.AWSRequest(method=method, url=self.endpoint + path, data=data,
                                  headers={"Content-Type": "application/json"})
        self.SigV4Auth(self.session.get_credentials().get_frozen_credentials(),
                      "signer-builder-tools", self.region).add_auth(request)
        response = self.requests.request(method, request.url, data=data,
                                         headers=dict(request.headers), timeout=90,
                                         allow_redirects=False)
        require(200 <= response.status_code < 300,
                f"Signing API returned HTTP {response.status_code}: {response.text[:1000]}")
        return response.json()

    def sign(self, artifact, configuration, work, phase):
        directory = work / phase
        directory.mkdir()
        subprocess.run(["gtar", "-czf", str(directory / "artifact.gz"),
                        "-C", str(artifact), "."], check=True)
        package = directory / "package.tar.gz"
        subprocess.run(["gtar", "-czf", str(package), "-C", str(directory), "artifact.gz"], check=True)
        key = f"box-release/{uuid.uuid4().hex}/{phase}"
        locations = {
            "bucket": self.bucket, "bucketAccessRole": self.access_role,
            "inputKey": f"pre-signed/{key}/package.tar.gz",
            "outputKey": f"signed/{key}/package.tar.gz",
        }
        with package.open("rb") as stream:
            self.s3.put_object(Bucket=self.bucket, Key=locations["inputKey"],
                               Body=stream, IfNoneMatch="*")
        body = {"manifest": configuration, "s3ArtifactLocations": locations}
        save(directory / "request.json", body)
        response = self.request("POST", "/v2/sign-tasks", body)
        save(directory / "submit.json", response)
        task = response["signTaskId"]
        require(re.fullmatch(r"[0-9a-fA-F-]{36}", task), "Invalid signing task ID")
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            response = self.request("GET", "/v2/sign-tasks/" + task)
            save(directory / "status.json", response)
            status = response["status"]
            print(f"{phase}: {task}: {status}", flush=True)
            if status == "success":
                require(response["manifest"] == configuration, "Returned manifest mismatch")
                require(response["s3ArtifactLocations"] == locations, "Returned object location mismatch")
                output = directory / "signed.zip"
                self.s3.download_file(self.bucket, locations["outputKey"], str(output))
                destination = directory / "output"
                unpack_signed(output, destination, configuration["outputs"][0]["path"])
                return destination
            require(status in ("created", "processing", "inProgress"),
                    f"Signing failed: {response.get('errorMessage', status)}")
            time.sleep(10)
        raise TimeoutError(f"Signing task {task} exceeded 15 minutes")


def release(args):
    work = args.work.resolve()
    work.mkdir()
    signer = Signer()
    credential = None
    if args.notary_secret:
        region = args.notary_secret.split(":")[3]
        secret = signer.session.client("secretsmanager", region_name=region).get_secret_value(
            SecretId=args.notary_secret)
        credential = notary_credential(secret.get("SecretString", ""))
        print("Notarization credential: " + ("an Apple ID with an app-specific password"
              if credential[0] == "apple-id" else "an App Store Connect API key"), flush=True)
    with notary_auth(args.notary_keychain_profile, credential, signer.team) as auth:
        checked = notarytool(auth, "history", "--output-format", "json")
    require(checked.returncode == 0,
            f"Notarization credentials were refused: {(checked.stderr or checked.stdout)[-500:]}")
    binaries = work / "binaries"
    unpack_build(args.input, binaries)
    helper_input = work / "helper-input"
    helpers = helper_input / "EXECUTABLES_TO_SIGN"
    helpers.mkdir(parents=True)
    for name in BINARIES[1:]:
        shutil.copy2(binaries / name, helpers / name)
    signed_helpers = signer.sign(helper_input, manifest(signer.team), work, "helpers")
    for name in BINARIES[1:]:
        signed = signed_helpers / "EXECUTABLES_TO_SIGN" / name
        subprocess.run(["codesign", "--verify", "--strict", str(signed)], check=True)
        shutil.copy2(signed, binaries / name)
    app_input = work / "app-input"
    prepare_bundle(binaries, app_input, args.version)
    signed = signer.sign(app_input, manifest(signer.team, signer.profile), work, "application")
    app = signed / "Box.app"
    verify(app, signer.team, signer.profile, work / "verification")
    for name in BINARIES[1:]:
        require(digest(binaries / name) == digest(app / "Contents/MacOS" / name),
                "Application signing changed a helper")
    with notary_auth(args.notary_keychain_profile, credential, signer.team) as auth:
        submission = notarize(app, auth, work / "notarization")
    verify_notarization(app, work / "verification")
    stage = work / "package"
    stage_package(app, stage)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["gtar", "-czf", str(args.output.resolve()), "-C", str(stage), "."], check=True)
    save(work / "receipt.json", {
        "source_sha": args.source_sha, "version": args.version,
        "features": ["native-filesystem-policy"],
        "input_sha256": digest(args.input), "output_sha256": digest(args.output),
        "notarized": True, "notarization_id": submission,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sign = sub.add_parser("sign")
    for name in ("input", "output", "work"):
        sign.add_argument("--" + name, required=True, type=Path)
    sign.add_argument("--version", required=True)
    sign.add_argument("--source-sha", required=True)
    notary = sign.add_mutually_exclusive_group(required=True)
    notary.add_argument("--notary-secret",
                        help="ARN of a Secrets Manager secret that holds an App Store Connect API key, "
                             "or an Apple ID and an app-specific password")
    notary.add_argument("--notary-keychain-profile",
                        help="notarytool keychain profile for a local run")
    check = sub.add_parser("verify")
    check.add_argument("--app", required=True, type=Path)
    check.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "sign":
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha), "Expected a full source SHA")
        require(bool(args.notary_keychain_profile)
                or re.fullmatch(SECRET_ARN, args.notary_secret or ""),
                "Expected a notarization secret ARN or keychain profile")
        release(args)
    else:
        verify(args.app, os.environ["CD_SIGNER_TEAM_ID"],
               os.environ["CD_SIGNER_PROFILE_NAME"], args.evidence)
        verify_notarization(args.app, args.evidence)
