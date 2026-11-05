#!/usr/bin/env python3
"""Create, inspect, and remove one temporary Google Cloud Box example."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

SOURCE_REVISION = "da4993143596d390e4e7525bc90339d10db23212"
IMAGE = "debian-12-bookworm-arm64-v20261102"
EXAMPLE = Path(__file__).resolve().parent


def gcloud(project, *arguments, optional=False, raw=False):
    result = subprocess.run(
        ["gcloud", *arguments, "--project", project, "--quiet"] + ([] if raw else ["--format", "json"]),
        text=True, capture_output=True,
    )
    if result.returncode:
        if optional and re.search(r"(?:NOT_FOUND|was not found|does not exist|notFound)", result.stderr):
            return None
        raise RuntimeError(result.stderr.strip())
    return result.stdout if raw else json.loads(result.stdout or "null")


def save(path, value, *, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".receipt-", dir=path.parent) as directory:
        temporary = Path(directory) / "value.json"
        temporary.write_text(json.dumps(value, indent=2) + "\n")
        if exclusive:
            path.hardlink_to(temporary)
        else:
            temporary.replace(path)


def resource_commands(state):
    name, zone, region = state["name"], state["zone"], state["region"]
    return {
        "network": ["compute", "networks", "describe", name],
        "subnet": ["compute", "networks", "subnets", "describe", name, "--region", region],
        "service_account": ["iam", "service-accounts", "list", "--filter=email=" + state["service_account"]],
        "role": ["iam", "roles", "describe", state["role"]],
        "disk": ["compute", "disks", "describe", name + "-boot", "--zone", zone],
        "instance": ["compute", "instances", "describe", name, "--zone", zone],
    }


def lookup_resource(state, kind):
    value = gcloud(state["project"], *resource_commands(state)[kind], optional=kind != "service_account")
    if kind == "service_account":
        if not isinstance(value, list) or len(value) > 1 or any(not isinstance(item, dict) for item in value):
            raise RuntimeError("The service account lookup returned an unexpected result.")
        return value[0] if value else None
    return value


def owned_resource(state, kind):
    value = lookup_resource(state, kind)
    if value is not None and value.get("description") != state["marker"]:
        raise RuntimeError(f"Refusing to change {kind}: its ownership marker does not match the receipt.")
    return value


def payload():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in ("run-demo.py", "agent.py", "requirements.txt", "dependency-lock.txt"):
            source = EXAMPLE / name
            if name == "dependency-lock.txt" and not source.exists():
                continue
            if not source.is_file() or source.is_symlink():
                raise RuntimeError(f"Expected a regular example file: {source}")
            archive.add(source, arcname=name, recursive=False)
    value = buffer.getvalue()
    return base64.b64encode(value).decode(), hashlib.sha256(value).hexdigest()


def deploy(args, receipt):
    if receipt.exists():
        raise RuntimeError(f"A deployment receipt already exists: {receipt}. Use status or cleanup; choose another --name for a new deployment.")
    if not args.model and not args.probe_only:
        raise RuntimeError("Supply --model with a currently available Vertex AI Gemini model, or use --probe-only.")
    encoded, digest = payload()
    owner = uuid.uuid4().hex
    state = {
        "project": args.project, "name": args.name, "zone": args.zone,
        "region": args.zone.rsplit("-", 1)[0], "owner": owner,
        "marker": "Strands Box GCP example " + owner,
        "service_account": f"{args.name}-vm@{args.project}.iam.gserviceaccount.com",
        "role": "boxGcp" + owner[:16], "source_revision": args.source_revision,
        "payload_sha256": digest, "location": args.location,
        "model": args.model, "probe_only": args.probe_only, "created": [],
    }
    gcloud(args.project, "services", "enable", "compute.googleapis.com", "iam.googleapis.com", "aiplatform.googleapis.com")
    for kind in resource_commands(state):
        if lookup_resource(state, kind) is not None:
            raise RuntimeError(f"The {kind} name already exists. Choose a different --name.")
    image = gcloud("debian-cloud", "compute", "images", "describe", args.image)
    state["image"] = image["name"]
    config = json.dumps({key: state[key] for key in (
        "owner", "project", "source_revision", "payload_sha256", "location", "model", "probe_only"
    )})
    startup = (EXAMPLE / "setup-vm.sh").read_text()
    if max(len(encoded), len(config), len(startup)) > 250_000 or sum(map(len, (encoded, config, startup))) > 500_000:
        raise RuntimeError("Example payload exceeds Compute Engine metadata limits.")
    save(receipt, state, exclusive=True)

    def create(kind, *command):
        state["created"].append(kind)
        save(receipt, state)
        print(f"Creating {kind} in project {args.project}...", flush=True)
        gcloud(args.project, *command)

    create("network", "compute", "networks", "create", args.name,
           "--subnet-mode=custom", "--description", state["marker"])
    create("subnet", "compute", "networks", "subnets", "create", args.name,
           "--network", args.name, "--region", state["region"], "--range=10.240.0.0/28",
           "--description", state["marker"])
    create("service_account", "iam", "service-accounts", "create", args.name + "-vm",
           "--display-name=Strands Box example VM", "--description", state["marker"])
    create("role", "iam", "roles", "create", state["role"], "--title=Strands Box example inference",
           "--description", state["marker"], "--stage=GA",
           "--permissions=aiplatform.endpoints.predict")
    gcloud(args.project, "projects", "add-iam-policy-binding", args.project,
           "--member=serviceAccount:" + state["service_account"],
           "--role=projects/" + args.project + "/roles/" + state["role"], "--condition=None")
    create("disk", "compute", "disks", "create", args.name + "-boot", "--zone", args.zone,
           "--type=pd-balanced", "--size=40GB", "--image", state["image"],
           "--image-project=debian-cloud", "--description", state["marker"])
    with tempfile.TemporaryDirectory(prefix="box-gcp-") as temporary:
        directory = Path(temporary)
        for name, value in (("startup", startup), ("config", config), ("payload", encoded)):
            (directory / name).write_text(value)
        create("instance", "compute", "instances", "create", args.name,
               "--zone", args.zone, "--machine-type", args.machine_type,
               "--description", state["marker"],
               "--disk=name=" + args.name + "-boot,boot=yes,auto-delete=yes",
               "--network-interface=subnet=" + args.name + ",nic-type=GVNIC",
               "--service-account", state["service_account"], "--scopes=cloud-platform",
               "--metadata=block-project-ssh-keys=TRUE,serial-port-enable=FALSE",
               "--metadata-from-file=" + ",".join((
                   "startup-script=" + str(directory / "startup"),
                   "box-config=" + str(directory / "config"),
                   "box-payload=" + str(directory / "payload"),
               )))
    print(f"VM created. The source build runs in its startup script. Receipt: {receipt}")
    print("Run status to save serial output and inspect the result. Run cleanup after saving the result.")


def serial_receipts(output):
    """Reassemble complete receipts from bounded serial lines."""
    groups = {}
    for line in output.splitlines():
        match = re.search(r"BOX_GCP_RECEIPT_CHUNK=([0-9a-f]{64}):([0-9]+):([0-9]+):([A-Za-z0-9+/=]{1,1000})$", line)
        if not match:
            continue
        digest, index, count, chunk = match.groups()
        index, count = int(index), int(count)
        if not 0 <= index < count <= 256:
            continue
        pieces = groups.setdefault((digest, count), {})
        pieces[index] = chunk
        if len(pieces) != count:
            continue
        encoded = "".join(pieces[number] for number in range(count))
        if hashlib.sha256(encoded.encode()).hexdigest() != digest:
            continue
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(encoded, validate=True))) as compressed:
                value = compressed.read(1_000_001)
            if len(value) <= 1_000_000:
                yield json.loads(value)
        except (OSError, ValueError, UnicodeError, EOFError):
            continue


def status(state, receipt):
    instance = owned_resource(state, "instance")
    if instance is None:
        print("The example VM does not exist. Saved evidence remains beside the deployment receipt.")
        return
    output = gcloud(state["project"], "compute", "instances", "get-serial-port-output",
                    state["name"], "--zone", state["zone"], "--port=1", "--start=0", raw=True)
    serial = receipt.parent / "serial.log"
    serial.write_text(output)
    (receipt.parent / f"serial-{time.time_ns()}.log").write_text(output)
    result = None
    for candidate in serial_receipts(output):
        if isinstance(candidate, dict) and all(candidate.get(key) == state[key] for key in ("owner", "source_revision", "payload_sha256")):
            result = candidate
    if result is not None:
        save(receipt.parent / "results.json", result)
    phases = re.findall(r"BOX_GCP_PHASE=([a-z]+)", output)
    exit_codes = re.findall(r"BOX_GCP_SETUP_EXIT=([0-9]+)", output)
    print(json.dumps({"vm_status": instance["status"], "phase": phases[-1] if phases else "booting",
                      "setup_exit_code": int(exit_codes[-1]) if exit_codes else None, "serial_log": str(serial),
                      "result": result, "receipt": str(receipt)}, indent=2))


def cleanup(state, receipt):
    project, name, zone = state["project"], state["name"], state["zone"]
    try:
        status(state, receipt)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Could not save results before cleanup: {error}. Continuing with ownership checks.", file=sys.stderr)
    for kind in reversed(state["created"]):
        resource = owned_resource(state, kind)
        if resource is None or resource.get("deleted"):
            continue
        if kind == "instance":
            command = ["compute", "instances", "delete", name, "--zone", zone, "--keep-disks=all"]
        elif kind == "disk":
            command = ["compute", "disks", "delete", name + "-boot", "--zone", zone]
        elif kind == "role":
            role = f"projects/{project}/roles/{state['role']}"
            policy = gcloud(project, "projects", "get-iam-policy", project)
            binding = next((entry for entry in policy.get("bindings", [])
                            if entry["role"] == role and "condition" not in entry), None)
            member = "serviceAccount:" + state["service_account"]
            if binding and member in binding["members"]:
                gcloud(project, "projects", "remove-iam-policy-binding", project,
                       "--member", member, "--role", role, "--condition=None")
            if any(entry["role"] == role and set(entry["members"]) - {member}
                   for entry in policy.get("bindings", [])):
                raise RuntimeError("The demo role has another member. Refusing to delete that role.")
            command = ["iam", "roles", "delete", state["role"]]
        elif kind == "service_account":
            command = ["iam", "service-accounts", "delete", state["service_account"]]
        elif kind == "subnet":
            command = ["compute", "networks", "subnets", "delete", name, "--region", state["region"]]
        else:
            command = ["compute", "networks", "delete", name]
        print(f"Deleting owned {kind}...", flush=True)
        gcloud(project, *command)
    state["cleaned_up"] = True
    save(receipt, state)
    print(f"Demo resources removed. Evidence retained at {receipt.parent}. Enabled project APIs remain enabled.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("deploy", "status", "cleanup"))
    parser.add_argument("--project", required=True)
    parser.add_argument("--name", default="box-gcp-demo")
    parser.add_argument("--zone", default="us-central1-a")
    parser.add_argument("--machine-type", default="t2a-standard-4")
    parser.add_argument("--source-revision", default=SOURCE_REVISION)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--location", default="global")
    parser.add_argument("--model")
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".cache" / "strands-box-gcp")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", args.project):
        parser.error("--project must be a Google Cloud project ID, not a display name or number")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,22}[a-z0-9]", args.name):
        parser.error("--name must contain 3-24 lowercase letters, digits, or hyphens")
    if not re.fullmatch(r"[a-z]+-[a-z]+[0-9]+-[a-z]", args.zone):
        parser.error("--zone must name a Compute Engine zone")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", args.image):
        parser.error("--image must name a Debian Compute Engine image")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        parser.error("--source-revision must be a full Git commit SHA")
    receipt = args.state_dir.resolve() / args.project / args.name / "deployment.json"
    try:
        if args.command == "deploy":
            deploy(args, receipt)
        else:
            state = json.loads(receipt.read_text())
            if (state["project"], state["name"]) != (args.project, args.name):
                raise RuntimeError("The receipt project and name do not match the request.")
            (status if args.command == "status" else cleanup)(state, receipt)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
