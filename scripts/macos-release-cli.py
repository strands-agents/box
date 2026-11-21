#!/usr/bin/env python3
"""Sign, notarize, and verify the macOS box package through the configured services."""

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

# The CLI and its helpers use Box Core's application identity.
APPLICATION = "com.amazon.strands.box"
IDENTIFIERS = {
    "box": APPLICATION,
    "strands-box-sock-alias": APPLICATION,
    "strands-box-contain-trampoline": APPLICATION,
}
BINARIES = tuple(IDENTIFIERS)
SIGNED = "EXECUTABLES_TO_SIGN"
OBJECT_PREFIX = "box-release/boxy"
HARDENED_RUNTIME = 0x10000
SIGNED_LIMIT = 1024 * 1024 * 1024
VERSION = r"\d+\.\d+\.\d+(?:-(?:linux-)?preview\.[1-9]\d*)?"
NATIVE_FEATURE = "strands-box-cli/native-filesystem-policy"
ENTITLEMENT = "com.apple.developer.endpoint-security.client"
NATIVE_LINKS = {
    **{name: f"Box.app/Contents/MacOS/{name}" for name in BINARIES[1:]},
    "resources": "Box.app/Contents/Resources/resources",
    "release.json": "Box.app/Contents/Resources/release.json",
}
NATIVE_LAUNCHER = '''#!/bin/sh
set -eu
path=$0
count=0
while [ -L "$path" ]; do
    count=$((count + 1))
    [ "$count" -le 40 ] || { echo "box: installation link loop" >&2; exit 1; }
    directory=$(CDPATH= cd -P -- "$(/usr/bin/dirname -- "$path")" && pwd)
    target=$(/usr/bin/readlink "$path")
    case "$target" in
        /*) path=$target ;;
        *) path=$directory/$target ;;
    esac
done
root=$(CDPATH= cd -P -- "$(/usr/bin/dirname -- "$path")" && pwd)
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


def unpack_build(archive, programs, kept):
    """Put the build's programs in one folder, and its release.json and resources/ in another."""
    programs.mkdir()
    kept.mkdir()
    with tarfile.open(archive) as source:
        members = {}
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if member.isdir() and str(path) == ".":
                continue
            require(not path.is_absolute() and ".." not in path.parts, "Unsafe build archive path")
            require(not any(part.startswith("._") for part in path.parts),
                    "Unexpected macOS metadata file in build archive")
            name = str(path)
            if name in BINARIES or name == "release.json":
                require(member.isfile(), "Unexpected build archive entry")
            else:
                require(path.parts[:1] == ("resources",) and (member.isfile() or member.isdir()),
                        "Unexpected build archive entry")
            require(name not in members, "Duplicate build archive entry")
            members[name] = member
        require(set(BINARIES) | {"release.json"} <= set(members), "Incomplete build archive")
        for name, member in members.items():
            target = (programs if name in BINARIES else kept) / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            target.chmod(0o755 if name in BINARIES else member.mode & 0o777)
    require((kept / "resources" / "packs").is_dir(), "Missing pack resources")


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
            require(not stat.S_ISLNK(mode), "Signed archive contains a symlink")
            require(member.is_dir() or stat.S_ISREG(mode), "Unexpected signed archive file type")
            total += member.file_size
            require(total <= SIGNED_LIMIT, "Signed archive exceeds 1 GiB")
        for member in source.infolist():
            target = destination / member.filename
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod((member.external_attr >> 16) & 0o777)


def manifest(team, profile=None):
    if profile:
        return {
            "type": "app", "os": "osx", "name": "Box",
            "outputs": [{"label": "macos", "path": "Box.app"}],
            "app": {"identifier": IDENTIFIERS["box"], "signing_requirements": {
                "team_id": team, "profile_name": profile, "profile_type": "distribution",
                "signing_args": {"entitlements_path": "SIGNING_METADATA/Box.entitlements"},
            }},
        }
    return {
        "type": "app", "os": "osx", "name": "Box",
        "outputs": [{"label": "macos", "path": SIGNED}],
        "app": {"identifier": APPLICATION, "signing_requirements": {
            "team_id": team, "certificate_type": "developerIDAppDistribution",
        }},
    }


def verify(directory, team, evidence, identifiers=None):
    evidence.mkdir(parents=True, exist_ok=True)
    require(re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid Apple team ID")
    identifiers = IDENTIFIERS if identifiers is None else identifiers
    for name, identifier in identifiers.items():
        requirement = (
            f'anchor apple generic and identifier "{identifier}" '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            f'and certificate leaf[subject.OU] = "{team}"'
        )
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f"{name} is not a regular file")
        subprocess.run(["codesign", "--verify", "--strict", "-R", "=" + requirement, str(path)],
                       check=True)
        details = subprocess.run(["codesign", "-dvvv", str(path)], check=True,
                                 capture_output=True, text=True).stderr
        require(f"Identifier={identifier}\n" in details and f"TeamIdentifier={team}\n" in details,
                f"Unexpected signature identity: {name}")
        require("Authority=Developer ID Application:" in details,
                f"Not a Developer ID signature: {name}")
        flags = re.search(r"\bflags=0x([0-9a-f]+)", details)
        require(flags and int(flags.group(1), 16) & HARDENED_RUNTIME,
                f"Missing hardened runtime: {name}")
        require(re.search(r"^Timestamp=", details, re.MULTILINE), f"Missing secure timestamp: {name}")
    save(evidence / "verification.json", {
        "identifiers": identifiers, "team": team,
        "binaries": {name: digest(directory / name) for name in identifiers},
    })



def native_profile():
    profile = os.environ.get("CD_SIGNER_PROFILE_NAME", "")
    require(bool(profile.strip()) and profile == profile.strip(),
            "Native signing and verification require CD_SIGNER_PROFILE_NAME for the shared Box application")
    require(re.fullmatch(r"[A-Z0-9]{10}", os.environ.get("CD_SIGNER_TEAM_ID", "")),
            "Invalid Apple team ID")
    return profile


def native_build_metadata(args):
    require(args.build_metadata is not None, "Native signing requires build metadata")
    record = json.loads(args.build_metadata.read_text())
    require(isinstance(record, dict), "Invalid build metadata")
    require(record.get("box_commit") == args.source_sha, "Build metadata source mismatch")
    require(record.get("box_version") == args.version, "Build metadata version mismatch")
    require(record.get("target") == "aarch64-apple-darwin", "Build metadata target mismatch")
    require(record.get("archive_stage") == "unsigned_build", "Expected unsigned_build metadata")
    require(record.get("runtime_qualified") is False, "Unexpected build qualification claim")
    features = record.get("cargo_features")
    require(isinstance(features, list) and all(isinstance(value, str) for value in features)
            and len(features) == len(set(features)) and NATIVE_FEATURE in features,
            "Build metadata missing native-filesystem-policy")
    require(record.get("archive") == args.input.name, "Build metadata archive name mismatch")
    require(record.get("archive_sha256") == digest(args.input), "Build metadata SHA-256 mismatch")
    return record


def prepare_native_bundle(programs, kept, destination, version):
    app = destination / "Box.app"
    executables = app / "Contents/MacOS"
    executables.mkdir(parents=True)
    for name in BINARIES:
        shutil.copy2(programs / name, executables / name)
    shutil.copytree(kept, app / "Contents/Resources")
    with (app / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleIdentifier": IDENTIFIERS["box"], "CFBundleExecutable": "box",
                      "CFBundleName": "Box", "CFBundlePackageType": "APPL",
                      "LSMinimumSystemVersion": "27.0",
                      "CFBundleVersion": version.split("-")[0],
                      "CFBundleShortVersionString": version.split("-")[0]}, stream)
    metadata = destination / "SIGNING_METADATA"
    metadata.mkdir()
    with (metadata / "Box.entitlements").open("wb") as stream:
        plistlib.dump({ENTITLEMENT: True}, stream)
    return app


def verify_native(app, team, profile_name, evidence):
    executables = app / "Contents/MacOS"
    require({path.name for path in executables.iterdir()} == set(BINARIES),
            "Unexpected native application programs")
    verify(executables, team, evidence)
    identifier = IDENTIFIERS["box"]
    requirement = (f'anchor apple generic and identifier "{identifier}" '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   f'and certificate leaf[subject.OU] = "{team}"')
    subprocess.run(["codesign", "--verify", "--strict", "-R", "=" + requirement, str(app)], check=True)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(info.get("CFBundleIdentifier") == identifier and info.get("CFBundleExecutable") == "box",
            "Unexpected bundle identity or entry point")
    executable = executables / "box"
    entitlements = plistlib.loads(subprocess.check_output(
        ["codesign", "-d", "--entitlements", ":-", str(executable)], stderr=subprocess.DEVNULL))
    profile = plistlib.loads(subprocess.check_output(
        ["security", "cms", "-D", "-i", str(app / "Contents/embedded.provisionprofile")]))
    for values in (entitlements, profile.get("Entitlements", {})):
        require(values.get(ENTITLEMENT) is True, "Missing Endpoint Security authorization")
        require(values.get("com.apple.application-identifier") == f"{team}.{identifier}",
                "Application identifier mismatch")
        require(values.get("com.apple.developer.team-identifier") == team, "Team mismatch")
    require(profile.get("Name") == profile_name and profile.get("TeamIdentifier") == [team],
            "Unexpected provisioning profile")
    expiration = profile.get("ExpirationDate")
    require(isinstance(expiration, datetime.datetime)
            and expiration > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
            "Expired provisioning profile")
    require(profile.get("ProvisionsAllDevices") is True and not profile.get("ProvisionedDevices"),
            "Profile does not authorize Developer ID distribution")
    prefix = str(evidence / "certificate-")
    subprocess.run(["codesign", "-d", "--extract-certificates=" + prefix, str(executable)],
                   check=True, capture_output=True)
    require(Path(prefix + "0").read_bytes() in profile.get("DeveloperCertificates", []),
            "Signing certificate is not authorized by the profile")
    save(evidence / "native-authorization.json", {
        "identifier": identifier, "team": team, "profile": profile_name,
        "profile_uuid": profile["UUID"], "endpoint_security": True,
    })


def verify_native_notarization(app, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    checked = subprocess.run(["xcrun", "stapler", "validate", str(app)], capture_output=True, text=True)
    require(checked.returncode == 0, "Missing or invalid stapled notarization ticket")
    paths = (app, *(app / "Contents/MacOS" / name for name in BINARIES))
    for path in paths:
        subprocess.run(["codesign", "--verify", "--strict", "--check-notarization",
                        "-R", "=notarized", str(path)], check=True)
    save(evidence / "notarization.json", {
        "stapled": True, "notarized": [str(path.relative_to(app.parent)) for path in paths],
    })


def stage_native_package(app, destination):
    destination.mkdir(parents=True)
    shutil.copytree(app, destination / "Box.app")
    (destination / "box").write_text(NATIVE_LAUNCHER)
    (destination / "box").chmod(0o755)
    for name, target in NATIVE_LINKS.items():
        (destination / name).symlink_to(target)


def native_inventory(package):
    require(package.is_dir() and not package.is_symlink(), "Native package is not a directory")
    result = {}
    for path in sorted(package.rglob("*")):
        name = path.relative_to(package).as_posix()
        require(name.split("/")[0] in {"Box.app", "box", *NATIVE_LINKS},
                "Unexpected native package entry")
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            require(name in NATIVE_LINKS and os.readlink(path) == NATIVE_LINKS[name],
                    "Unexpected native package alias")
            result[name] = {"link": os.readlink(path)}
        elif stat.S_ISDIR(mode):
            result[name] = {"directory": True}
        else:
            require(stat.S_ISREG(mode) and not mode & 0o7000, "Unexpected native package file type")
            result[name] = {"sha256": digest(path), "mode": stat.S_IMODE(mode)}
    require(all(result.get(name) == {"link": target} for name, target in NATIVE_LINKS.items()),
            "Missing native package alias")
    require(result.get("box") == {"sha256": hashlib.sha256(NATIVE_LAUNCHER.encode()).hexdigest(),
                                 "mode": 0o755}, "Unexpected native package launcher")
    for name in BINARIES:
        require(result.get(f"Box.app/Contents/MacOS/{name}", {}).get("mode") == 0o755,
                f"Native program is not executable: {name}")
    require((package / "Box.app/Contents/Resources/resources/packs").is_dir(), "Missing pack resources")
    return result


def archive_inventory(archive):
    result, total = {}, 0
    with tarfile.open(archive) as source:
        for member in source:
            path = PurePosixPath(member.name)
            if str(path) == "." and member.isdir():
                continue
            require(not path.is_absolute() and ".." not in path.parts and path.parts,
                    "Unsafe native archive path")
            name = str(path)
            require(name not in result, "Duplicate native archive path")
            if member.isdir():
                result[name] = {"directory": True}
            elif member.issym():
                require(name in NATIVE_LINKS and member.linkname == NATIVE_LINKS[name],
                        "Unexpected native archive alias")
                result[name] = {"link": member.linkname}
            else:
                require(member.isfile() and not member.mode & 0o7000, "Unexpected native archive file type")
                total += member.size
                require(total <= SIGNED_LIMIT, "Native archive exceeds 1 GiB")
                digest_value = hashlib.sha256()
                with source.extractfile(member) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest_value.update(chunk)
                result[name] = {"sha256": digest_value.hexdigest(), "mode": member.mode}
    return result


def verify_native_binding(package, archive, receipt_path, source_sha):
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha or ""), "Expected a full source SHA")
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get("native_filesystem_policy") is True, "Receipt is not a native package receipt")
    require(receipt.get("source_sha") == source_sha, "Receipt source mismatch")
    features = receipt.get("cargo_features")
    require(isinstance(features, list) and all(isinstance(value, str) for value in features)
            and len(features) == len(set(features)) and NATIVE_FEATURE in features,
            "Receipt missing native-filesystem-policy")
    require(receipt.get("output_sha256") == digest(archive), "Receipt archive SHA-256 mismatch")
    require(receipt.get("notarized") is True
            and re.fullmatch(SUBMISSION_ID, receipt.get("notarization_id", "")),
            "Receipt does not record notarization")
    inventory = native_inventory(package)
    require(inventory == archive_inventory(archive), "Extracted package differs from its archive")
    require(inventory == receipt.get("package_files"), "Package differs from its signing receipt")
    require(receipt.get("binaries") == {name: digest(package / "Box.app/Contents/MacOS" / name)
                                       for name in BINARIES}, "Binary hashes differ from receipt")
    resources = package / "Box.app/Contents/Resources"
    require(receipt.get("resources") == {path.relative_to(resources).as_posix(): digest(path)
                                         for path in resources.rglob("*") if path.is_file()},
            "Resource hashes differ from receipt")
    record = json.loads((package / "release.json").read_text())
    require(record.get("box_commit") == source_sha and record.get("box_version") == receipt.get("version")
            and record.get("target") == "aarch64-apple-darwin", "Package release source or version mismatch")
    info = plistlib.loads((package / "Box.app/Contents/Info.plist").read_bytes())
    require(info.get("CFBundleVersion") == receipt["version"].split("-")[0], "Bundle version mismatch")
    return receipt


def sign_native(signer, unsigned, kept, work, args, profile, auth):
    helpers = work / "helper-input" / SIGNED
    helpers.mkdir(parents=True)
    for name in BINARIES[1:]:
        shutil.copy2(unsigned / name, helpers / name)
    signed_helpers = signer.sign(helpers.parent, manifest(signer.team), work, "helpers") / SIGNED
    verify(signed_helpers, signer.team, work / "helper-verification",
           {name: IDENTIFIERS[name] for name in BINARIES[1:]})
    for name in BINARIES[1:]:
        shutil.copy2(signed_helpers / name, unsigned / name)
    helper_hashes = {name: digest(unsigned / name) for name in BINARIES[1:]}
    resource_hashes = {path.relative_to(kept).as_posix(): digest(path)
                       for path in kept.rglob("*") if path.is_file()}
    app_input = work / "app-input"
    prepare_native_bundle(unsigned, kept, app_input, args.version)
    app = signer.sign(app_input, manifest(signer.team, profile), work, "application") / "Box.app"
    require(all(digest(app / "Contents/MacOS" / name) == value for name, value in helper_hashes.items()),
            "Application signing changed a helper")
    resources = app / "Contents/Resources"
    require({path.relative_to(resources).as_posix(): digest(path) for path in resources.rglob("*")
             if path.is_file()} == resource_hashes, "Application signing changed resources or release metadata")
    verify_native(app, signer.team, profile, work / "verification")
    submission = notarize(app, auth, work / "notarization")
    for attempt in range(1, 6):
        stapled = subprocess.run(["xcrun", "stapler", "staple", str(app)], capture_output=True, text=True)
        if stapled.returncode == 0:
            break
        require(attempt < 5, "Stapling failed: " + (stapled.stdout + stapled.stderr)[-500:])
        time.sleep(30)
    verify_native_notarization(app, work / "verification")
    stage_native_package(app, work / "package")
    return app / "Contents/MacOS", submission, resource_hashes


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
    # A new session has no terminal, so notarytool reads the password from standard input.
    options = {"input": auth.password + "\n", "start_new_session": True} if auth.password else {}
    result = subprocess.run(["xcrun", "notarytool", *arguments, *auth.options],
                            capture_output=True, text=True, **options)
    if auth.apple_id:
        result.stdout, result.stderr = (
            text.replace(f"Password for {auth.apple_id}: ", "").replace(auth.password, "<password>")
            .replace(auth.apple_id, "<apple-id>")
            for text in (result.stdout, result.stderr))
    return result


def notarize(directory, auth, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    archive = evidence / "box.zip"
    subprocess.run(["ditto", "-c", "-k", "--keepParent", str(directory), str(archive)], check=True)
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
    return identifier


def verify_notarization(directory, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    for name in BINARIES:
        for attempt in range(1, 6):
            checked = subprocess.run(["codesign", "--verify", "--strict", "--check-notarization",
                                      "-R", "=notarized", str(directory / name)],
                                     capture_output=True, text=True)
            if checked.returncode == 0:
                break
            require(attempt < 5, f"{name} is not notarized: {(checked.stdout + checked.stderr)[-500:]}")
            time.sleep(30)
    save(evidence / "notarization.json", {"notarized": list(BINARIES)})


def stage_package(signed, kept, destination):
    shutil.copytree(kept, destination)
    for name in BINARIES:
        shutil.copy2(signed / name, destination / name)


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
        require(re.fullmatch(r"[A-Z0-9]{10}", self.team), "Invalid Apple team ID")
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
        key = f"{OBJECT_PREFIX}/{uuid.uuid4().hex}/{phase}"
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
    native = getattr(args, "native_filesystem_policy", False)
    profile = native_profile() if native else None
    metadata = native_build_metadata(args) if native else None
    require(native or not getattr(args, "build_metadata", None),
            "Build metadata requires --native-filesystem-policy")
    work = args.work.resolve()
    work.mkdir()
    # Check the build archive before any call to AWS or Apple.
    unsigned = work / "input" / SIGNED
    unsigned.parent.mkdir()
    kept = work / "kept"
    unpack_build(args.input, unsigned, kept)
    if native:
        record = json.loads((kept / "release.json").read_text())
        require(all(record.get(key) == metadata.get(key) for key in (
            "box_version", "box_commit", "core_version", "core_commit", "target")),
            "Packaged release metadata differs from build metadata")
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
    stage = work / "package"
    if native:
        with notary_auth(args.notary_keychain_profile, credential, signer.team) as auth:
            signed, submission, resources = sign_native(signer, unsigned, kept, work, args, profile, auth)
    else:
        signed = signer.sign(unsigned.parent, manifest(signer.team), work, "executables") / SIGNED
        verify(signed, signer.team, work / "verification")
        with notary_auth(args.notary_keychain_profile, credential, signer.team) as auth:
            submission = notarize(signed, auth, work / "notarization")
        verify_notarization(signed, work / "verification")
        stage_package(signed, kept, stage)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["gtar", "-czf", str(args.output.resolve()), "-C", str(stage), "."], check=True)
    receipt = {
        "source_sha": args.source_sha, "version": args.version,
        "input_sha256": digest(args.input), "output_sha256": digest(args.output),
        "binaries": {name: digest(signed / name) for name in BINARIES},
        "notarized": True, "notarization_id": submission,
    }
    if native:
        receipt.update(native_filesystem_policy=True, cargo_features=metadata["cargo_features"],
                       profile=profile, team=signer.team, resources=resources,
                       package_files=native_inventory(stage))
    save(work / "receipt.json", receipt)


def verify_package(args):
    if args.native_filesystem_policy:
        profile = native_profile()
        require(args.receipt is not None and args.archive is not None and args.source_sha,
                "Native verification requires --receipt, --archive, and --source-sha")
        receipt = verify_native_binding(args.package, args.archive, args.receipt, args.source_sha)
        team = os.environ["CD_SIGNER_TEAM_ID"]
        require(receipt.get("profile") == profile and receipt.get("team") == team,
                "Receipt signing profile or team mismatch")
        app = args.package / "Box.app"
        verify_native(app, team, profile, args.evidence)
        verify_native_notarization(app, args.evidence)
    else:
        require(not (args.package / "Box.app").exists(), "Native package requires --native-filesystem-policy")
        require((args.package / "resources/packs").is_dir(), "Missing pack resources")
        verify(args.package, os.environ["CD_SIGNER_TEAM_ID"], args.evidence)
        verify_notarization(args.package, args.evidence)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sign = sub.add_parser("sign")
    for name in ("input", "output", "work"):
        sign.add_argument("--" + name, required=True, type=Path)
    sign.add_argument("--version", required=True)
    sign.add_argument("--source-sha", required=True)
    sign.add_argument("--native-filesystem-policy", action="store_true")
    sign.add_argument("--build-metadata", type=Path)
    notary = sign.add_mutually_exclusive_group(required=True)
    notary.add_argument("--notary-secret",
                        help="ARN of a Secrets Manager secret that holds an App Store Connect API key, "
                             "or an Apple ID and an app-specific password")
    notary.add_argument("--notary-keychain-profile",
                        help="notarytool keychain profile for a local run")
    check = sub.add_parser("verify")
    check.add_argument("--package", required=True, type=Path)
    check.add_argument("--evidence", required=True, type=Path)
    check.add_argument("--native-filesystem-policy", action="store_true")
    check.add_argument("--receipt", type=Path)
    check.add_argument("--archive", type=Path)
    check.add_argument("--source-sha")
    args = parser.parse_args()
    if args.command == "sign":
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha), "Expected a full source SHA")
        require(re.fullmatch(VERSION, args.version), "Invalid release version")
        require(bool(args.notary_keychain_profile)
                or re.fullmatch(SECRET_ARN, args.notary_secret or ""),
                "Expected a notarization secret ARN or keychain profile")
        release(args)
    else:
        verify_package(args)
