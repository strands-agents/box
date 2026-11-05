"""Read native Box policy records and their committed Box identity."""
import hashlib
import json
import re


def value(item):
    if "intValue" in item:
        return int(item["intValue"])
    if "arrayValue" in item:
        return [value(entry) for entry in item["arrayValue"]["values"]]
    return next(iter(item.values()))


def decisions(path):
    records = []
    for line in path.read_text().splitlines():
        for resource in json.loads(line).get("resourceLogs", []):
            owner = {entry["key"]: value(entry["value"])
                     for entry in resource.get("resource", {}).get("attributes", [])}
            for scope in resource.get("scopeLogs", []):
                if scope.get("scope", {}).get("name") != "strands-box.policy":
                    continue
                for record in scope.get("logRecords", []):
                    if record.get("eventName") != "strands.box.policy.decision":
                        continue
                    fields = {entry["key"]: value(entry["value"])
                              for entry in record.get("attributes", [])}
                    fields["timestamp_ns"] = int(record["timeUnixNano"])
                    fields["box_run_id"] = owner.get("strands.box.run.id")
                    fields["box_id"] = owner.get("strands.box.name")
                    records.append(fields)
    return records


def batch_identity(records, state, name, policy):
    """Bind a batch to the record committed by the pinned Box runtime."""
    record = (state / "private/box.toml").read_bytes()
    marker = (state / "private/configured").read_text().strip().split()
    if len(marker) != 2 or marker[1] != "sha256:" + hashlib.sha256(record).hexdigest():
        raise AssertionError("Box identity marker does not match its committed record")
    # These four values are strings emitted by Box's TOML serializer. Parse only
    # its top-level header; the sample does not interpret arbitrary TOML.
    header = record.decode().split("\n[", 1)[0]
    fields = {}
    for key in ("box_id", "box_dir", "name", "policy"):
        matches = re.findall(r"^" + key + r" = (\"[^\n]*\")$", header, re.MULTILINE)
        if len(matches) != 1:
            raise AssertionError("Missing or duplicate committed Box field: " + key)
        fields[key] = json.loads(matches[0])
    if (not re.fullmatch(r"box-[0-9a-f]{16}", marker[0])
            or fields != {"box_id": marker[0], "box_dir": str(state.resolve()),
                          "name": name, "policy": str(policy.resolve())}):
        raise AssertionError("Committed Box identity does not match this batch configuration")
    run_ids = {event.get("box_run_id") for event in records}
    if len(run_ids) != 1 or not all(isinstance(item, str) and item for item in run_ids):
        raise AssertionError("Batch decisions must have one nonempty Box run identifier")
    if not records or any(event.get("box_id") != marker[0] for event in records):
        raise AssertionError("Batch decision belongs to an unexpected Box identity")
    return marker[0], next(iter(run_ids))
