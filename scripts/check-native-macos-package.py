#!/usr/bin/env python3
"""Check real native policy operations through an installed macOS package."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

from smoke_telemetry import prepare_installation

ORIGINAL = b"original\n"
RULE_ALLOW = "package_native_permit"
RULE_DENY = "package_native_write_deny"
PROGRAMS = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
NATIVE_SOURCE = r"""#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int fd = open(argv[1], O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        printf("NATIVE_DENIED errno=%d\n", e);
        return e == EACCES || e == EPERM ? 0 : 20;
    }
    const char value[] = "native workload wrote\n";
    ssize_t n = write(fd, value, sizeof(value) - 1);
    int e = errno;
    int closed = close(fd);
    if (n != (ssize_t)(sizeof(value) - 1) || closed) {
        printf("NATIVE_WRITE_FAILED errno=%d bytes=%zd\n", e, n);
        return 21;
    }
    puts("NATIVE_ALLOWED");
    return 0;
}
"""
SERVER_SOURCE = r"""import json, os, sys
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "native-package-probe", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "write", "description": "Write the package test target.",
                             "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call":
        try:
            with open(os.environ["NATIVE_TARGET"], "w") as target:
                target.write("changed\n")
            text = "NATIVE_ALLOWED"
        except PermissionError:
            text = "NATIVE_DENIED"
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result},
                     separators=(",", ":")), flush=True)
"""
MCP_DRIVER = r"""set -euo pipefail
printf entered > agent-entered.txt
replies=mcp-replies.jsonl
: > "$replies"
await() { local t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]]; do (( SECONDS - t < 20 )) || return 91; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"package-probe","version":"1"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write","arguments":{}}}'
await '"id":3'
printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/list"}'
await '"id":4'; } | native-server > "$replies"
printf '%s\n' "$(<"$replies")"
"""


class CheckFailure(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(argv, destination, cwd, environment, timeout=60):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with destination.with_suffix(".stdout").open("wb") as output, destination.with_suffix(".stderr").open("wb") as error:
        child = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=error, start_new_session=True)
        timed_out = False
        try:
            code = child.wait(timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait(timeout=10)
    receipt = {"argv": argv, "cwd": str(cwd), "environment": environment,
               "started_utc": started, "exit": code, "timed_out": timed_out,
               "timeout_seconds": timeout, "pid": child.pid}
    save(destination.with_suffix(".command.json"), receipt)
    require(not timed_out, f"command exceeded {timeout}s: {argv}")
    return code, destination.with_suffix(".stdout").read_text(), destination.with_suffix(".stderr").read_text()


def selection(value):
    return "" if value is None else "native-filesystem-policy = " + str(value).lower() + "\n"


def cases():
    result = [{"name": "agent_default_off", "kind": "agent", "global": None, "override": None, "allow": False},
              {"name": "agent_global_false", "kind": "agent", "global": False, "override": None, "allow": False}]
    for kind in ("agent", "tool", "mcp"):
        for suffix, override, allow in (("inherited_allow", None, True), ("inherited_deny", None, False),
                                         ("explicit_allow", True, True), ("explicit_deny", True, False),
                                         ("explicit_off", False, False)):
            result.append({"name": f"{kind}_{suffix}", "kind": kind, "global": True,
                           "override": override, "allow": allow})
    return result


def parse_toml(text):
    require(tomllib is not None, "runtime package checks require Python 3.11 or later (tomllib)")
    return tomllib.loads(text)


def make_profile(case, root, fixtures):
    home = root / "home"
    workspace = home / "project"
    workspace.mkdir(parents=True)
    target = workspace / "native-target.txt"
    target.write_bytes(ORIGINAL)
    native = fixtures["native"]
    if case["kind"] == "mcp":
        script = MCP_DRIVER
    else:
        operation = shlex.join([str(native), str(target)])
        if case["kind"] == "tool":
            operation = "zsh -c " + shlex.quote(operation)
        script = "printf entered > agent-entered.txt\nexec " + operation
    text = 'policies = ["policy.dw"]\n'
    if case["global"] is not None:
        text += "[experimental-features]\n" + selection(case["global"])
    text += '[project]\naccess = "write"\n[agent]\ncommand = ' + json.dumps(
        ["/bin/bash", "--noprofile", "--norc", "-c", script]) + "\n"
    text += selection(case["override"] if case["kind"] == "agent" else False)
    text += '[agent.env]\nPATH = "/usr/bin:/bin"\nTMPDIR = "${{ workspace }}"\n'
    if case["kind"] == "agent":
        text += '[agent.filesystem]\nread_file = ' + json.dumps([str(native)]) + "\n"
        text += "exec = " + json.dumps([str(native)]) + "\n"
    elif case["kind"] == "tool":
        text += '[tool.native]\ncommand = ' + json.dumps([str(native)]) + "\n" + selection(case["override"])
    else:
        text += '[mcp.native]\ntype = "stdio"\ncommand = ' + json.dumps([str(fixtures["server"])]) + "\n"
        text += selection(case["override"])
        text += '[mcp.native.env]\nNATIVE_TARGET = ' + json.dumps(str(target)) + '\nPYTHONDONTWRITEBYTECODE = "1"\n'
    if case["kind"] in ("tool", "mcp"):
        text += f'[{case["kind"]}.native.filesystem]\n'
        reads = ["${{ workspace }}"] + (fixtures["python_read"] if case["kind"] == "mcp" else [])
        text += "read = " + json.dumps(reads) + '\nwrite = ["${{ workspace }}"]\n'
        if case["kind"] == "mcp":
            read_files = [str(fixtures["server"])] if not any(
                fixtures["server"].resolve().is_relative_to(Path(parent))
                for parent in fixtures["python_read"]) else []
            text += "read_file = " + json.dumps(read_files) + "\n"
    policy = f'@id("{RULE_ALLOW}") permit(principal, action, resource);\n'
    if not case["allow"]:
        policy += (f'@id("{RULE_DENY}") forbid(principal, action == Box::Action::"fs:write", resource) '
                   'when { context.input.path like "*native-target.txt" };\n')
    profile = home / ".strands/box/profiles/probe"
    profile.mkdir(parents=True)
    (profile / "profile.toml").write_text(text)
    (profile / "policy.dw").write_text(policy)
    grants = {"project": {"access": "write"}, "agent": {}, "tool": {}, "mcp": {}}
    if case["kind"] == "agent":
        grants["agent"] = {"read_file": [str(native)], "exec": [str(native)]}
    else:
        selected_grants = {"read": reads, "write": ["${{ workspace }}"]}
        if case["kind"] == "mcp":
            selected_grants["read_file"] = read_files
        grants[case["kind"]] = {"native": selected_grants}
    return {"home": home, "workspace": workspace, "target": target, "profile": profile,
            "entry": workspace / "agent-entered.txt", "grants": grants}


def attributes(record):
    result = {}
    for item in record.get("attributes", []):
        value = item.get("value", {})
        result[item["key"]] = next((value[key] for key in ("stringValue", "boolValue", "intValue") if key in value), value)
    return result


def policy_decisions(batches):
    result = []
    for batch in batches:
        for resources, scopes, records in (("resourceLogs", "scopeLogs", "logRecords"),
                                           ("resourceSpans", "scopeSpans", "spans")):
            for resource in batch.get(resources, []):
                for scope in resource.get(scopes, []):
                    for record in scope.get(records, []):
                        values = attributes(record)
                        if (values.get("strands.box.policy.action") in ("fs:write", 'Box::Action::"fs:write"')
                                and str(values.get("strands.box.policy.resource", "")).endswith("/native-target.txt")):
                            result.append({"format": resources, "attributes": values,
                                           "trace_id": record.get("traceId"), "span_id": record.get("spanId"),
                                           "time": record.get("timeUnixNano", record.get("startTimeUnixNano"))})
    return result


def exact_target(resource, state):
    if not isinstance(resource, str):
        return False
    path = state["home"] / resource[2:] if resource.startswith("~/") else Path(resource)
    return path.is_absolute() and path.resolve() == state["target"].resolve()


def verify_compiled(case, config):
    require(config.get("experimental-features", {}).get("native-filesystem-policy", False) == (case["global"] is True),
            "compiled global selection differs")
    require(config.get("agent", {}).get("native-filesystem-policy") ==
            (case["override"] if case["kind"] == "agent" else False), "compiled agent selection differs")
    if case["kind"] != "agent":
        require(config.get(case["kind"], {}).get("native", {}).get("native-filesystem-policy") == case["override"],
                "compiled process selection differs")


def verify_case(case, state, observed):
    selected = case["global"] is True and case["override"] is not False
    allowed = case["allow"] or not selected
    require(observed["exit"] == 0, f'native workload exit {observed["exit"]}: {observed["stderr"][-2000:]}')
    require(observed["entered"] == b"entered", "selected workload never entered")
    expected = (b"changed\n" if case["kind"] == "mcp" else b"native workload wrote\n") if allowed else ORIGINAL
    require(observed["target_bytes"] == expected, "target bytes differ from actual operation outcome")
    if case["kind"] == "mcp":
        replies = [json.loads(line) for line in observed["stdout"].splitlines() if line.startswith("{")]
        require([row.get("id") for row in replies] == [1, 2, 3, 4], "MCP response sequence is incomplete or duplicated")
        require(all(row.get("jsonrpc") == "2.0" and "error" not in row and "result" in row for row in replies),
                "MCP response contains a protocol error")
        require(replies[0]["result"].get("protocolVersion") == "2024-11-05", "MCP initialize failed")
        listing = replies[1]["result"]
        require(any(row.get("name") == "write" for row in listing.get("tools", [])), "MCP tool list lacks write")
        call = replies[2]["result"]
        require(call.get("content") == [{"type": "text", "text": "NATIVE_ALLOWED" if allowed else "NATIVE_DENIED"}]
                and call.get("isError") is False, "MCP operation reply does not describe the expected operation")
        require(replies[3]["result"] == listing, "MCP no longer serves tools/list after the operation")
    else:
        require(observed["stdout"].strip() in (["NATIVE_ALLOWED"] if allowed else
                                               ["NATIVE_DENIED errno=1", "NATIVE_DENIED errno=13"]),
                "native workload did not report the expected operation")
    raw, public = observed["raw"], observed["public"]
    require(all(exact_target(row["attributes"].get("strands.box.policy.resource"), state) for row in raw)
            and all(exact_target(row.get("resource"), state) for row in public), "decision does not name the exact target")
    if not selected:
        require(not raw and not public, "default-off or process opt-out emitted native target decisions")
        return
    logs = [row for row in raw if row["format"] == "resourceLogs"]
    spans = [row for row in raw if row["format"] == "resourceSpans"]
    require(len(logs) == len(spans) == 1, "expected exactly one target decision log and span")
    require(all(logs[0].get(key) == spans[0].get(key) for key in ("trace_id", "span_id", "time", "attributes"))
            and bool(logs[0]["trace_id"]) and bool(logs[0]["span_id"]), "raw log/span identity differs")
    rules = {RULE_ALLOW, "project_write"} if allowed else {RULE_DENY}
    verdict = "permit" if allowed else "deny"
    for row in raw:
        attrs = row["attributes"]
        require(attrs.get("strands.box.policy.action") in ("fs:write", 'Box::Action::"fs:write"'), "raw action differs")
        require(attrs.get("strands.box.policy.principal") == "agent:self", "raw principal differs")
        require(attrs.get("strands.box.policy.rule") in rules and attrs.get("strands.box.policy.verdict") == verdict,
                "recorded rule/verdict differs")
        determining = attrs.get("strands.box.policy.determining.ids", {}).get("arrayValue", {}).get("values", [])
        require({item.get("stringValue") for item in determining} == rules, "determining rules differ")
    require(len(public) == 1 and public[0].get("action") == "fs:write"
            and public[0].get("result") == verdict
            and public[0].get("rule") == spans[0]["attributes"].get("strands.box.policy.rule"), "public decision differs")
    require(allowed or public[0].get("enforced") is not False, "policy denial was not enforced")


def verify_prerequisite(state, observed, kind):
    require(observed["exit"] != 0 and observed["entered"] is None, "prerequisite refusal did not precede workload entry")
    require(observed["target_bytes"] == ORIGINAL, "prerequisite refusal changed target bytes")
    require(not observed["raw"] and not observed["public"], "prerequisite refusal emitted target decisions")
    message = " ".join(observed["stderr"].split())
    if kind == "unsigned":
        require("Endpoint Security code 3" in message, "unsigned prerequisite lacks the exact authorization diagnostic")
    else:
        require("native-filesystem-policy" in message and "requires a supported" in message,
                "baseline prerequisite lacks the feature-disabled diagnostic")


def package_binding(package):
    require(package.is_dir(), f"package directory does not exist: {package}")
    for name in PROGRAMS:
        require((package / name).is_file() and os.access(package / name, os.X_OK), f"missing installed executable: {name}")
    require((package / "resources/config.toml").is_file(), "missing installed resource config")
    require((package / "resources/editing-box-profile.md").is_file(), "missing installed editing guide")
    manifest = json.loads((package / "release.json").read_text())
    require(all(manifest.get(key) for key in ("box_commit", "core_commit", "target")), "release metadata lacks source binding")
    files = {}
    for path in sorted(package.rglob("*")):
        name = str(path.relative_to(package))
        if path.is_symlink():
            require(path.resolve().is_relative_to(package), f"installed link escapes package: {name}")
            files[name] = {"link": os.readlink(path)}
        elif path.is_file():
            files[name] = {"sha256": digest(path), "size_bytes": path.stat().st_size}
    return {"package": str(package), "entry": str(package / "box"), "release": manifest, "files": files}


def python_read_roots(python, canonical):
    candidates = {Path(python[key]).resolve() for key in ("prefix", "base_prefix", "stdlib")}
    candidates.add(canonical.parent.parent)
    require(all(str(path) not in ("/", "/usr", "/Library") for path in candidates),
            "fixture Python requires an overly broad read grant")
    # Core refuses redundant grants. Each root already covers its descendants,
    # including the interpreter; only the separate server needs read_file.
    return sorted(str(path) for path in candidates
                  if not any(path != parent and path.is_relative_to(parent) for parent in candidates))


def prepare_fixtures(folder, interpreter):
    folder.mkdir()
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(folder), "PYTHONDONTWRITEBYTECODE": "1"}
    probe = "import json,sys,sysconfig; print(json.dumps(dict(executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,stdlib=sysconfig.get_path('stdlib'))))"
    code, output, error = command([str(interpreter), "-c", probe], folder / "python", folder, environment)
    require(code == 0, f"fixture Python failed: {error}")
    python = json.loads(output)
    canonical = Path(python["executable"]).resolve()
    require(canonical.is_file() and canonical.is_absolute(), "fixture Python is not an absolute executable")
    require("/CommandLineTools/usr/bin/" not in str(canonical),
            "select the canonical Python framework executable with --python; the developer-tools launcher fails inside containment")
    reads = python_read_roots(python, canonical)
    source, native, server = folder / "native-write.c", folder / "native-write", folder / "native-server"
    source.write_text(NATIVE_SOURCE)
    code, _, error = command(["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(native)],
                             folder / "compile-fixture", folder, environment)
    require(code == 0, f"native fixture compilation failed: {error}")
    server.write_text("#!" + str(canonical) + "\n" + SERVER_SOURCE)
    server.chmod(0o755)
    save(folder / "binding.json", {"python": python, "canonical_interpreter": str(canonical),
                                  "read_grants": reads, "fixtures": {p.name: digest(p) for p in (source, native, server)}})
    return {"native": native, "server": server, "python": str(canonical), "python_read": reads}


def environment(home):
    return {"HOME": str(home), "PATH": "/usr/bin:/bin", "TERM": "dumb", "NO_COLOR": "1"}


def startup(package, folder):
    folder.mkdir()
    temporary_root = "/private/var/tmp" if platform.system() == "Darwin" else "/tmp"
    fixture = Path(tempfile.mkdtemp(prefix="bnps-", dir=temporary_root)).resolve()
    home = fixture / "home"
    save(folder / "fixture.json", {"home": str(home), "purpose": "short paths for broker sockets"})
    workspace = home / "project"
    workspace.mkdir(parents=True)
    prepare_installation(home)
    env = environment(home)
    binary = str(package / "box")
    for label, args in (("version", ["--version"]), ("guide", ["help", "agent"]),
                        ("resources", ["profile", "create", "claude", "--with", "bedrock", "--policy", "open"])):
        code, output, error = command([binary, *args], folder / label, workspace, env)
        require(code == 0, f"installed entry point {label} failed: {error}")
        if label == "guide":
            guide = package / "resources/editing-box-profile.md"
            require(any(Path(line.strip()).resolve() == guide.resolve() for line in output.splitlines() if line.strip().startswith("/")),
                    "installed help did not find the packaged editing guide")
    created = home / ".strands/box/profiles/claude"
    require((created / "profile.toml").is_file() and (created / "policy.dw").is_file(), "installed packs did not create a profile")
    require("open_connect" in (created / "policy.dw").read_text(), "installed policy starter was not loaded")
    probe = home / ".strands/box/profiles/helper-probe"
    probe.mkdir()
    (probe / "profile.toml").write_text(
        'policies = ["policy.dw"]\n[project]\naccess = "write"\n[agent]\ncommand = '
        + json.dumps(["/bin/bash", "--noprofile", "--norc", "-c", "zsh -c 'printf PACKAGE_BROKER_OK'"])
        + '\n[agent.env]\nPATH = "/usr/bin:/bin"\n'
    )
    (probe / "policy.dw").write_text('permit(principal, action == Box::Action::"shell:exec", resource);\n')
    code, output, error = command([binary, "run", "helper-probe", "--no-banner"],
                                  folder / "helpers", workspace, env)
    require(code == 0 and output.strip() == "PACKAGE_BROKER_OK", f"installed helper startup failed: {error}")


def collect_history(binary, case, state, folder, prerequisite):
    runs = sorted((state["home"] / ".strands/box/r").glob("*"))
    require(len(runs) in (0, 1) if prerequisite else len(runs) == 1, "unexpected run count")
    raw, public, snapshots = [], [], []
    for index, run in enumerate(runs):
        saved = folder / f"saved-run-{index}"
        saved.mkdir()
        config = run / "box.toml"
        if config.is_file():
            verify_compiled(case, parse_toml(config.read_text()))
        else:
            require(bool(prerequisite), "compiled configuration is absent")
        for name in ("box.toml", "policy.dw", "records.jsonl"):
            path = run / name
            if path.is_file():
                shutil.copy2(path, saved / name)
                (saved / name).chmod(0o444)
        journal = run / "records.jsonl"
        if journal.is_file():
            raw += policy_decisions([json.loads(line) for line in journal.read_text().splitlines() if line.strip()])
            code, output, error = command([str(binary), "runs", "history", run.name, "--action", "fs:write",
                                           "--resource", "native-target.txt", "--format", "json"],
                                          folder / f"history-{index}", state["workspace"], environment(state["home"]))
            require(code == 0, f"installed history reader failed: {error}")
            values = json.loads(output)
            require(isinstance(values, list), "installed history is not a decision list")
            public += values
        else:
            require(bool(prerequisite), "policy journal is absent")
        for database in run.rglob("*.redb"):
            target = saved / database.name
            before = digest(database)
            shutil.copy2(database, target)
            require(before == digest(database) == digest(target), "history changed during snapshot")
            target.chmod(0o444)
            snapshots.append({"path": str(target), "sha256": before, "bytes": target.stat().st_size})
    require(bool(prerequisite) or (snapshots and all(row["bytes"] > 0 for row in snapshots)), "raw history snapshot is absent")
    save(folder / "raw-target-decisions.json", raw)
    save(folder / "public-target-decisions.json", public)
    save(folder / "history-snapshots.json", snapshots)
    return raw, public


def run_case(package, case, fixtures, root, folder, prerequisite=None):
    folder.mkdir()
    prepare_installation(root / "home")
    state = make_profile(case, root, fixtures)
    for name in ("profile.toml", "policy.dw"):
        shutil.copy2(state["profile"] / name, folder / name)
    env, binary = environment(state["home"]), package / "box"
    code, output, error = command([str(binary), "profile", "show", "--full", "probe"],
                                  folder / "profile-show", state["workspace"], env)
    if prerequisite == "baseline":
        require(code != 0 and "requires a supported" in " ".join(error.split()), "baseline profile preview did not refuse native selection")
    else:
        require(code == 0, f"profile preview failed: {error}")
    code, output, error = command([str(binary), "run", "probe", "--no-banner"], folder / "run", state["workspace"], env)
    try:
        raw, public = collect_history(binary, case, state, folder, prerequisite)
    except (OSError, ValueError, KeyError, TypeError) as history_error:
        if code != 0:
            raise CheckFailure(f"workload exit {code}: {error[-2000:]}; history: {history_error}") from history_error
        raise
    observed = {"exit": code, "stdout": output, "stderr": error, "raw": raw, "public": public,
                "entered": state["entry"].read_bytes() if state["entry"].exists() else None,
                "target_bytes": state["target"].read_bytes()}
    (folder / "target-before").write_bytes(ORIGINAL)
    (folder / "target-after").write_bytes(observed["target_bytes"])
    if prerequisite:
        verify_prerequisite(state, observed, prerequisite)
    else:
        verify_case(case, state, observed)
    return {"name": case["name"], "passed": True, "grants": state["grants"], "target": str(state["target"]),
            "entry": str(binary), "prerequisite": prerequisite, "raw_decisions": len(raw), "public_decisions": len(public)}


def check(args):
    require(tomllib is not None, "runtime package checks require Python 3.11 or later (tomllib)")
    require(platform.system() == "Darwin", "native macOS package checks require macOS")
    require(int(platform.mac_ver()[0].split(".")[0]) >= 27, "native macOS package checks require macOS 27 or later")
    package = args.package.resolve()
    evidence = args.evidence.resolve()
    require(not evidence.is_relative_to(package) and not package.is_relative_to(evidence),
            "package and evidence directories must be separate")
    evidence.mkdir(parents=True, exist_ok=False)
    summary = {"package": str(package), "platform": platform.platform(), "uid": os.getuid(), "cases": [],
               "optional_controls": {"unsigned_requested": args.unsigned_package is not None,
                                     "baseline_requested": args.baseline_package is not None},
               "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "Installed package native operations; no trusted-client-death or public-installer transport claim.",
               "native_attribution": "Hashed native fixtures, exact target events, compiled selection and same-grant opt-outs; recorded principal is agent:self."}
    try:
        binding = package_binding(package)
        summary["binding"] = binding
        save(evidence / "package-binding.json", binding)
        startup(package, evidence / "startup")
        fixtures = prepare_fixtures(evidence / "fixtures", args.python.resolve())
        plan = [(package, case, None, "native") for case in cases()]
        bindings = {str(package): binding}
        for option, kind in ((args.unsigned_package, "unsigned"), (args.baseline_package, "baseline")):
            if option:
                other = option.resolve()
                require(other != package, f"{kind} controls require a separate package")
                other_binding = package_binding(other)
                if kind == "unsigned":
                    require(other_binding["release"] == binding["release"], "unsigned package is not the same build")
                summary[kind + "_binding"] = other_binding
                bindings[str(other)] = other_binding
                plan.append((other, {"name": kind + "_selected", "kind": "agent", "global": True,
                                     "override": None, "allow": False}, kind, kind))
                if kind == "baseline":
                    plan.append((other, {"name": "baseline_default_off", "kind": "agent", "global": None,
                                         "override": None, "allow": False}, None, "baseline"))
        for selected_package, case, prerequisite, role in plan:
            require(package_binding(selected_package) == bindings[str(selected_package)], "installed package changed during checks")
            root = Path(tempfile.mkdtemp(prefix="bnp-", dir="/private/var/tmp")).resolve()
            try:
                result = run_case(selected_package, case, fixtures, root, evidence / case["name"], prerequisite)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                result = {"name": case["name"], "passed": False, "error": str(error), "fixture": str(root)}
            result["package_role"] = role
            summary["cases"].append(result)
            save(evidence / (case["name"] + ".json"), result)
            save(evidence / "summary.json", summary)
            print(json.dumps(result), flush=True)
        for kind in ("agent", "tool", "mcp"):
            pair = [next(row for row in summary["cases"] if row["name"] == kind + suffix)
                    for suffix in ("_explicit_deny", "_explicit_off")]
            require(all(row["passed"] for row in pair) and pair[0]["grants"] == pair[1]["grants"],
                    f"{kind} deny and opt-out did not pass with identical grants")
        require(all(package_binding(Path(path)) == expected for path, expected in bindings.items()),
                "installed package changed after checks")
        summary["installed_hashes_unchanged"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    summary["passed"] = sum(row["passed"] for row in summary["cases"])
    summary["failed"] = sum(not row["passed"] for row in summary["cases"])
    summary["counts_by_package_role"] = {role: {"passed": sum(row["passed"] for row in summary["cases"] if row["package_role"] == role),
                                                    "failed": sum(not row["passed"] for row in summary["cases"] if row["package_role"] == role)}
                                         for role in ("native", "unsigned", "baseline")}
    summary["success"] = bool(summary["cases"]) and not summary["failed"] and "error" not in summary
    save(evidence / "summary.json", summary)
    print(json.dumps({key: summary[key] for key in ("passed", "failed", "success")}), flush=True)
    return 0 if summary["success"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True, help="extracted package root with the installed box entry point")
    parser.add_argument("--evidence", type=Path, required=True, help="new directory for receipts and raw histories")
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="canonical Python 3 executable for the local MCP fixture")
    parser.add_argument("--unsigned-package", type=Path, help="same-build unsigned package for prerequisite refusal")
    parser.add_argument("--baseline-package", type=Path, help="separate feature-disabled package, recorded separately")
    args = parser.parse_args()
    try:
        return check(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"success": False, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
