#!/usr/bin/env python3
"""Compare stored filesystem events from Strands Shell and native Linux calls."""
import argparse
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
EXPECTATIONS = REPO / "crates/box/tests/fixtures/shell_native_events.json"
PERMIT = 'permit(principal, action, resource);\n'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    with path.open("rb") as stream:
        result = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
        return result.hexdigest()


def copy_history(source, snapshot, working):
    """Keep an immutable snapshot because opening the reader's copy changes redb."""
    require(len({path.resolve() for path in (source, snapshot, working)}) == 3,
            "Source, immutable snapshot, and reader copy must be separate files")
    expected = digest(source)
    shutil.copy2(source, snapshot)
    require(digest(snapshot) == expected, "Snapshot differs from the original history")
    shutil.copy2(snapshot, working)
    require(digest(working) == expected, "Reader copy differs from the history snapshot")
    return expected


def execute(command, prefix, env=None, timeout=60):
    save(prefix.with_suffix(".command.json"), command)
    with prefix.with_suffix(".stdout").open("wb") as out, prefix.with_suffix(".stderr").open("wb") as err:
        child = subprocess.Popen(command, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                 stdout=out, stderr=err, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            save(prefix.with_suffix(".exit.json"), {"timeout_seconds": timeout})
            raise AssertionError(f"Timed out: {prefix}") from None
    save(prefix.with_suffix(".exit.json"), {"code": code})
    return code


def select_binaries(artifacts):
    binaries = []
    for name in ("strands-box", "strands-box-sock-alias", "strands-box-contain-trampoline"):
        matches = [Path(item["executable"]) for item in artifacts
                   if item.get("reason") == "compiler-artifact" and item.get("executable")
                   and item["target"]["name"] == name and "bin" in item["target"]["kind"]]
        require(len(matches) == 1, f"Build must identify exactly one {name} executable")
        require(matches[0].is_file(), f"Missing emitted executable: {matches[0]}")
        binaries.append(matches[0])
    require(len({p.parent.resolve() for p in binaries}) == 1,
            "Box and its emitted helper executables must share one directory")
    return binaries


def build(target, output):
    env = os.environ.copy()
    env.pop("RUSTFLAGS", None)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env.update(CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_BUILD_JOBS="2")
    prefix = output / "build"
    code = execute(["cargo", "build", "--locked", "-p", "strands-box", "-p",
                    "strands-box-containment", "--all-features", "--message-format=json"],
                   prefix, env, 1800)
    require(code == 0, f"Build failed: {prefix}.stderr")
    artifacts = [json.loads(line) for line in prefix.with_suffix(".stdout").read_text().splitlines()]
    libraries = [Path(name) for item in artifacts if item.get("reason") == "compiler-artifact"
                 and item["target"]["name"] == "dogwood_local_engine"
                 for name in item["filenames"] if name.endswith(".rlib")]
    require(len(libraries) == 1, "Build must identify one Dogwood library")
    library = libraries[0]
    reader = output / "read-events"
    code = execute(["rustc", "--edition=2024", str(REPO / "crates/box/tests/support/policy_event_reader.rs"),
                    "--extern", f"dogwood_local_engine={library}", "-L", f"dependency={library.parent}",
                    "-o", str(reader)], output / "reader-build", env)
    require(code == 0, "Event reader build failed")
    workload = output / "native-workload"
    code = execute(["cc", "-D_GNU_SOURCE", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-nostdlib", "-static", "-fno-builtin", "-fno-stack-protector", "-fno-pie",
                    "-no-pie", str(REPO / "crates/box/tests/support/shell_native_workload.c"),
                    "-o", str(workload)], output / "workload-build")
    require(code == 0, "Native workload build failed")
    emitted = select_binaries(artifacts)
    products = output / "bin"
    products.mkdir()
    binaries = []
    for source in emitted:
        destination = products / source.name
        shutil.copy2(source, destination)
        require(digest(source) == digest(destination), "Copied executable differs from Cargo artifact")
        binaries.append(destination)
    save(output / "manifest.json", {
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_status": subprocess.check_output(["git", "status", "--short"], cwd=REPO, text=True),
        "platform": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
        "compiler": subprocess.check_output(["rustc", "-Vv"], cwd=REPO, text=True),
        "rustflags": "", "cargo_features": "--all-features", "build_directory": str(target),
        "emitted_executables": {p.name: str(p) for p in emitted},
        "build_environment": {k: env[k] for k in ("CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
                                                    "CARGO_PROFILE_TEST_DEBUG", "CARGO_BUILD_JOBS")},
        "sha256": {str(p): digest(p) for p in [*binaries, reader, workload,
                    Path(__file__).resolve(), REPO / "crates/box/tests/support/policy_event_reader.rs",
                    REPO / "crates/box/tests/support/shell_native_workload.c", EXPECTATIONS,
                    REPO / "scripts/test_shell_native_policy_events.py", REPO / "Cargo.lock"]},
    })
    return binaries[0], reader, workload


def denial(action, operation=None, path=None):
    conditions = []
    if operation:
        conditions.append(f'context.input.operation == Box::FsReadOperation::"{operation}"')
    if path:
        conditions.append(f'context.input.path == "~/workspace/{path}"')
    condition = " when { " + " && ".join(conditions) + " }" if conditions else ""
    return PERMIT + f'@id("denied") forbid(principal, action == Box::Action::"{action}", resource){condition};\n'


def temporal(kind):
    if kind == "count":
        predicate = 'Box::Action::"fs:move"::response{ input.path: _, input.operation: Box::FsMoveOperation::"rename" }'
        clause = f'exists (total: Long). ((count for (t: Timepoint). where (formerly within 1h ({predicate} && tp(t)))) == total && total >= 2)'
    else:
        path = '"~/workspace/source"' if kind == "path" else "_"
        clause = f'formerly within 1h (Box::Action::"fs:read"::response{{ input.path: {path}, input.operation: Box::FsReadOperation::"read_content" }})'
    return PERMIT + '@id("denied") forbid(principal, action == Box::Action::"fs:read", resource)\n' + \
        'when { context.input.path == "~/workspace/probe" && context.input.operation == Box::FsReadOperation::"read_content" }\n' + \
        f'when temporal {{ {clause} }};\n'


def cases():
    rows = []
    for operation in ("directory_rename", "file_rename", "replacement", "list", "read"):
        rows.append((operation + "/permit", operation, PERMIT, True, True))
        if operation in ("directory_rename", "file_rename", "replacement"):
            for name, policy, allowed in [
                ("deny_content", denial("fs:read", "read_content"), False),
                ("deny_enumerate", denial("fs:read", "enumerate"), True),
                ("deny_source_move", denial("fs:move", path="source"), False),
                ("deny_destination_move", denial("fs:move", path="destination"), False),
                ("deny_destination_write", denial("fs:write", path="destination"), operation != "replacement"),
                ("deny_destination_delete", denial("fs:delete", path="destination"), operation != "replacement"),
            ]:
                shell_allowed = True if operation == "replacement" and name == "deny_destination_write" else allowed
                rows.append((operation + "/" + name, operation, policy, shell_allowed, allowed))
        else:
            for name, mode in (("deny_content", "read_content"), ("deny_enumerate", "enumerate")):
                allowed = (operation == "read") != (mode == "read_content")
                rows.append((operation + "/" + name, operation, denial("fs:read", mode), allowed, allowed))
    for kind in ("path", "wildcard", "count"):
        rows.append(("temporal/" + kind, "temporal", temporal(kind), kind == "count", kind == "count"))
        rows.append(("temporal/" + kind + "_unprimed", "unprimed", temporal(kind), True, True))
    return rows


def normalize(value, root):
    if isinstance(value, str):
        prefix = str(root)
        return "/<ROOT>" + value[len(prefix):] if value == prefix or value.startswith(prefix + "/") else value
    if isinstance(value, list):
        return [normalize(item, root) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item, root) for key, item in value.items()}
    return value


def filesystem_events(records, root):
    return [normalize(row["record"]["event"], root) for row in records
            if "event" in row["record"] and row["record"]["event"]["action"]["id"].startswith("fs:")]


def correlate(events):
    """Validate outcome pairing, then rename opaque IDs in first-request order."""
    requests = {}
    completed = set()
    result = copy.deepcopy(events)
    for event in result:
        value = event.get("logged", {}).get("requestId")
        require(isinstance(value, list) and len(value) == 2 and value[0] == "s"
                and isinstance(value[1], str) and value[1], "Missing or malformed requestId")
        identifier = value[1]
        identity = {key: event[key] for key in ("action", "principal", "resource")}
        identity["input"] = event["context"]["input"]
        require(event["logged"]["input"] == identity["input"], "Logged input differs from policy input")
        if event["kind"] == "request":
            require(identifier not in requests, "Duplicate requestId")
            requests[identifier] = (len(requests), identity)
        else:
            require(event["kind"] in ("response", "error"), "Unknown filesystem event kind")
            require(identifier in requests, "Outcome has no earlier request")
            require(identifier not in completed, "Request has multiple outcomes")
            require(requests[identifier][1] == identity, "Outcome identifies a different request")
            completed.add(identifier)
        event["logged"]["requestId"] = ["s", f"request-{requests[identifier][0]}"]
    return result


def compare(actual, expected, label):
    if actual != expected:
        diff = "\n".join(difflib.unified_diff(json.dumps(expected, indent=2).splitlines(),
                                            json.dumps(actual, indent=2).splitlines(),
                                            fromfile="expected", tofile="actual"))
        raise AssertionError(f"{label}: stored events changed\n{diff}")


def expected_event(row):
    action, kind, operation, path, result, request_id = row
    family = {"fs:read": "Read", "fs:write": "Write", "fs:move": "Move", "fs:delete": "Delete"}[action]
    context = {"input": ["o", {"operation": ["e", [f"Box::Fs{family}Operation", operation]],
                               "path": ["s", path]}]}
    if result is not None:
        context["output"] = ["o", {"result": ["e", ["Box::FsResponseResult", result]]}]
    logged = copy.deepcopy(context)
    logged["requestId"] = ["s", f"request-{request_id}"]
    return {"action": {"namespace": ["Box", "Action"], "id": action}, "kind": kind,
            "principal": 'Box::Agent::"self"', "resource": 'Box::Resource::"unused"',
            "logged": logged, "context": context, "entities": {}, "parents": {}}


def load_expectations(path=EXPECTATIONS):
    fixture = json.loads(path.read_text())
    streams = {name: [expected_event(row) for row in rows] for name, rows in fixture["streams"].items()}
    expected = {case: streams[name] for case, name in fixture["cases"].items()}
    required = {case[0] + "/" + adapter for case in cases() for adapter in ("shell", "native")}
    require(set(expected) == required, "Expected event cases must exactly match the live matrix")
    return expected


def snapshot(workspace):
    return {str(p.relative_to(workspace)): "directory" if p.is_dir() else p.read_bytes().hex()
            for p in sorted(workspace.rglob("*"))}


def exercise(case, adapter, binaries, output):
    name, operation, policy, shell_allowed, native_allowed = case
    allowed = shell_allowed if adapter == "shell" else native_allowed
    folder = output / name / adapter
    folder.mkdir(parents=True)
    root = Path(tempfile.mkdtemp(prefix="sn-", dir="/var/tmp")).resolve()
    workspace = root / "workspace"
    workspace.mkdir()
    source, destination, probe = [workspace / name for name in ("source", "destination", "probe")]
    directory = operation in ("directory_rename", "list", "temporal", "unprimed")
    if directory:
        source.mkdir()
        (source / "child").write_text("original\n")
    else:
        source.write_text("original\n")
    if operation == "replacement":
        destination.write_text("previous\n")
    probe.write_text("original\n")
    before = snapshot(workspace)
    box, reader, fixture = binaries
    if adapter == "native":
        staged = root / "native-workload"
        shutil.copy2(fixture, staged)
        mode = "temporal" if operation == "temporal" else "list" if operation == "list" else \
            "read" if operation in ("read", "unprimed") else "rename"
        command = [str(staged), mode, str(probe if operation == "unprimed" else source),
                   str(destination), str(probe), "allow" if allowed else "deny"]
    else:
        shell_command = f"mv {source} {destination}"
        if operation == "list":
            shell_command = f"ls -1 {source}"
        elif operation in ("read", "unprimed"):
            shell_command = f"cat {probe if operation == 'unprimed' else source}"
        elif operation == "temporal":
            shell_command += f" && cat {probe}"
        command = ["/bin/bash", "-c", 'exec zsh -c "$1"', "comparison", shell_command]
    config = f'name = "shell-native-events"\nbox_dir = {json.dumps(str(root / "state"))}\npolicy = "policy.dw"\n' + \
        f'[experimental-features]\nnative-filesystem-policy = {str(adapter == "native").lower()}\n' + \
        f'[agent]\ncommand = {json.dumps(command)}\nworkspace = {json.dumps(str(workspace))}\n' + \
        f'[agent.filesystem]\nread = [{json.dumps(str(workspace))}]\nwrite = [{json.dumps(str(workspace))}]\n'
    (root / "box.toml").write_text(config)
    (root / "policy.dw").write_text(policy)
    (folder / "box.toml").write_text(config)
    (folder / "policy.dw").write_text(policy)
    launch = ["sudo", "-n", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--clear-groups",
              "--bounding-set=-all,+bpf,+perfmon", "--inh-caps=-all,+bpf,+perfmon",
              "--ambient-caps=-all,+bpf,+perfmon", "--no-new-privs", "env", "-u", "BOX_NATIVE_TEST_FAULT",
              f"HOME={root}", "BOX_TELEMETRY=off", str(box), "run", "--config", str(root / "box.toml")]
    code = execute(launch, folder / "workload")
    stdout = (folder / "workload.stdout").read_text()
    stderr = (folder / "workload.stderr").read_text()
    after = snapshot(workspace)
    save(folder / "effects.json", {"root": str(root), "before": before, "after": after, "exit": code})
    histories = list((root / "state").rglob("*.redb"))
    require(len(histories) == 1, f"{folder}: expected one durable history, got {histories}")
    history_snapshot = folder / "history.snapshot.redb"
    history = folder / "history.redb"
    history_hash = copy_history(histories[0], history_snapshot, history)
    require(execute([str(reader), str(history)], folder / "records") == 0, f"{folder}: history reader failed")
    require(digest(history_snapshot) == history_hash, f"{folder}: immutable history snapshot changed")
    records = [json.loads(line) for line in (folder / "records.stdout").read_text().splitlines()]
    raw_events = [row["record"]["event"] for row in records
                  if "event" in row["record"] and row["record"]["event"]["action"]["id"].startswith("fs:")]
    save(folder / "filesystem-events.raw.json", raw_events)
    events = correlate(filesystem_events(records, root))
    save(folder / "filesystem-events.json", events)
    native_decisions = [json.loads(line.split("=", 1)[1]) for line in stderr.splitlines()
                        if line.startswith("NATIVE_RESEARCH_EVENT=")]
    save(folder / "decisions.json", {"expected_allowed": allowed, "native_diagnostics": native_decisions,
                                     "stdout": stdout, "exit": code, "history_sha256_before_read": history_hash})
    require(events, f"{folder}: no filesystem events")
    if adapter == "native":
        require(code == 0, f"{folder}: native workload failed ({code})")
        marker = "NATIVE_ALLOWED\n" if allowed else "NATIVE_DENIED\n"
        require(stdout.endswith(marker), f"{folder}: missing native verdict")
        require(bool(native_decisions), f"{folder}: no native decision evidence")
        require(any(d["outcome"] == "denied" for d in native_decisions) == (not allowed),
                f"{folder}: native policy verdict disagrees")
        if not allowed:
            denied = [d for row in native_decisions for d in row["decisions"] if not d["allow"]]
            require(denied and all('RuleId("policy_1")' in d["decision"] for d in denied),
                    f"{folder}: refusal must come from the authored forbid")
    else:
        expected_code = 0 if allowed else 2 if operation == "list" else 1
        require(code == expected_code, f"{folder}: unexpected Shell exit ({code})")
        require(("[policy: denied]" in stderr) == (not allowed), f"{folder}: missing Shell policy verdict")
    payload = ""
    if allowed and operation in ("read", "unprimed", "temporal"):
        payload = "original\n"
    if allowed and operation == "list":
        payload = "child\n"
    if adapter == "native":
        payload += "NATIVE_ALLOWED\n" if allowed else "NATIVE_DENIED\n"
    require(stdout == payload, f"{folder}: unexpected output or bytes from a denied operation")
    expected_after = copy.deepcopy(before)
    if operation == "temporal" or (allowed and operation in ("directory_rename", "file_rename", "replacement")):
        expected_after.pop("destination", None)
        for key in list(expected_after):
            if key == "source" or key.startswith("source/"):
                expected_after["destination" + key[len("source"):]] = expected_after.pop(key)
    compare(after, expected_after, str(folder) + " effects")
    return {"events": events, "allowed": allowed, "effects": after, "fixture": str(root)}


def differences(case, shell, native):
    entries = []

    def add(name, classification, reason):
        entries.append({"difference": name, "classification": classification,
                        "reason": reason})

    if shell["events"] == native["events"]:
        return entries
    if any(e["context"]["input"][1]["operation"][1][1] == "read_metadata" for e in shell["events"]):
        add("metadata_traffic", "characterized",
            "Shell checks metadata before its command; direct native calls omit that command-level check. Raw events retain both streams.")
    if any(e["action"]["id"] == "fs:write" for e in native["events"]):
        add("replacement_write_check", "documented_native_rule",
            "The native guide requires destination delete and write permission for replacement. Shell replacement does not request destination write; its authored write-denial control therefore succeeds.")
    if case[1] == "list" and shell["allowed"]:
        add("enumeration_result", "documented_stage_difference",
            "Shell records completed enumeration; native records issuance of the directory descriptor. The workload independently verifies the directory entries.")
    if not entries:
        add("unclassified_event_difference", "needs_triage",
            "Full filesystem streams differ beyond the characterized cases. Review the retained exact event diff.")
    return entries


def run(target, output):
    require(platform.system() == "Linux" and platform.machine() == "aarch64",
            "Unsupported: this suite requires ARM64 Linux and actual kernel enforcement")
    require(os.getuid() != 0, "Run as the operator; the launcher grants only loader capabilities")
    output.mkdir(parents=True, exist_ok=False)
    binaries = build(target, output)
    results = {}
    errors = []
    comparisons = []
    expected = load_expectations()
    for case in cases():
        pair = {}
        for adapter in ("shell", "native"):
            label = case[0] + "/" + adapter
            try:
                result = exercise(case, adapter, binaries, output)
                results[label] = result
                pair[adapter] = result
                compare(result["events"], expected[label], label)
                print("PASS " + label, flush=True)
            except Exception as error:
                errors.append({"case": label, "error": str(error)})
                print("FAIL " + label + ": " + str(error)[:200], flush=True)
        if len(pair) == 2:
            comparison = {
                "differences": differences(case, pair["shell"], pair["native"]),
                "boundary_traffic": {"classification": "expected", "reason": "Shell uses the hosted interpreter; native calls omit shell:exec. Full records retain both streams."},
                "decisions_agree": pair["shell"]["allowed"] == pair["native"]["allowed"],
                "effects_agree": pair["shell"]["effects"] == pair["native"]["effects"],
                "events_agree": pair["shell"]["events"] == pair["native"]["events"],
                "shell_count": len(pair["shell"]["events"]), "native_count": len(pair["native"]["events"]),
                "diff": list(difflib.unified_diff(json.dumps(pair["shell"]["events"], indent=2).splitlines(),
                                                 json.dumps(pair["native"]["events"], indent=2).splitlines(),
                                                 fromfile="shell", tofile="native")),
            }
            save(output / case[0] / "comparison.json", comparison)
            comparisons.append({"case": case[0], **comparison})
    save(output / "results.json", results)
    save(output / "errors.json", errors)
    summary = {"cases": len(cases()) * 2, "passed": len(cases()) * 2 - len(errors),
               "failed": len(errors), "parity_claimed": False,
               "decision_disagreements": [row["case"] for row in comparisons if not row["decisions_agree"]],
               "effect_disagreements": [row["case"] for row in comparisons if not row["effects_agree"]],
               "event_disagreements": [row["case"] for row in comparisons if not row["events_agree"]],
               "completed_pairs": len(comparisons)}
    save(output / "summary.json", summary)
    print(json.dumps(summary), flush=True)
    require(not errors, f"{len(errors)} failed cases; see {output / 'errors.json'}")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.build_dir.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
