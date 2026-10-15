#!/usr/bin/env python3
"""Check host files and native evidence; agent claims alone cannot pass."""
import json
import os
from pathlib import Path
import sys


def records(path):
    if not path.exists():
        return []
    result = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            result.append(json.loads(line))
        except ValueError:
            continue
    return result


def checks(run, agent):
    project = run / "project"
    rows = []

    def check(name, ok, evidence):
        rows.append(dict(id=name, ok=bool(ok), evidence=evidence))

    result = records(run / "agent-a.json")
    check("agent-completed", len(result) == 1 and result[0].get("exit_code") == 0
          and result[0].get("run_status") == "VALID",
          "agent must finish a valid model run with exit code 0")

    for name, expected in (("allowed.txt", "ready"),
                           ("protected.txt", "approved"),
                           ("continued.txt", "continued after protected edit")):
        path = project / name
        actual = path.read_text(errors="replace").strip() if path.is_file() else None
        matches = actual == expected
        if name == "protected.txt":
            matches = path.is_file() and path.read_bytes() == b"approved\n"
        check(name, matches, f"{name}: {actual!r}, expected {expected!r}")

    paths = json.loads((run / "paths.json").read_text()) if (run / "paths.json").exists() else {}
    home = paths.get("HOME", "").rstrip("/")
    protected = str(project / "protected.txt")
    reported = "~" + protected[len(home):] if home and protected.startswith(home + "/") else protected
    denials = []
    log = run / "agent-a.log"
    for line in log.read_text(errors="replace").splitlines() if log.exists() else []:
        if not line.startswith("MACOS_FILE_DIAGNOSTIC "):
            continue
        try:
            row = json.loads(line.partition(" ")[2])
        except ValueError:
            continue
        if (row.get("origin") == "dogwood" and row.get("verdict") == "deny"
                and reported in (row.get("path"), row.get("destination"))):
            denials.append(row)
    check("native-protected-denial", 1 <= len(denials) <= 4,
          f"{len(denials)} native Dogwood denials for {reported}; expected 1 to 4")

    decisions = []
    for document in records(run / "decisions.jsonl"):
        for resource in document.get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = {attr["key"]: attr.get("value", {}).get("stringValue")
                             for attr in record.get("attributes", [])}
                    decisions.append((attrs, int(record.get("timeUnixNano", "0"))))

    prefix = "strands.box.policy."

    def matching(name, verdict):
        resource = reported.rsplit("/", 1)[0] + "/" + name
        return [(attrs, stamp) for attrs, stamp in decisions
                if attrs.get(prefix + "resource") == resource
                and attrs.get(prefix + "verdict") == verdict
                and attrs.get(prefix + "action") in ("fs:write", "fs:move", "fs:delete")]

    blocked = [(attrs, stamp) for attrs, stamp in matching("protected.txt", "deny")
               if attrs.get(prefix + "rule") == "protected_file"]
    check("protected-policy-denial", bool(blocked),
          f"{len(blocked)} exact-path denials attributed to protected_file")
    for name in ("allowed.txt", "continued.txt"):
        matches = matching(name, "permit")
        check(name + "-policy-permit", bool(matches),
              f"{len(matches)} exact-path permits for {name}")
    last_denial = max((int(row["time_unix_ns"]) for row in denials), default=0)
    check("continued-after-denial", last_denial > 0 and any(
        stamp > last_denial for _, stamp in matching("continued.txt", "permit")),
        "continued.txt must receive a policy permit after the native denial")

    # Tool events supplement the trusted native diagnostic and disk checks.
    # Text in an assistant's closing report is not a tool invocation.
    events = records(run / "turns.jsonl")
    def is_protected(path):
        if not isinstance(path, str):
            return False
        if path.startswith("~/"):
            if not home:
                return False
            path = home + path[1:]
        if not os.path.isabs(path):
            path = str(project / path)
        return os.path.normpath(path) == protected

    attempts = []
    if agent == "claude":
        calls = [part for event in events if event.get("type") == "assistant"
                 for part in event.get("message", {}).get("content", [])
                 if isinstance(part, dict) and part.get("type") == "tool_use"]
        tools = [part.get("name") for part in calls]
        attempts = [part.get("id") for part in calls if part.get("name") in ("Edit", "Write")
                    and is_protected(part.get("input", {}).get("file_path"))]
        check("native-agent-tools", "Edit" in tools and "Write" in tools
              and set(tools) <= {"Read", "Edit", "Write"}, f"Claude tools: {tools}")
    elif agent == "codex":
        items = [event.get("item", {}) for event in events]
        changes = [item for item in items if item.get("type") == "file_change"]
        commands = [item for item in items if item.get("type") == "command_execution"]
        attempts = [item.get("id") for item in changes
                    if any(is_protected(change.get("path")) for change in item.get("changes", []))]
        check("native-agent-tools", bool(changes) and not commands,
              f"Codex file changes: {len(changes)}; command executions: {len(commands)}")
    else:
        check("native-agent-tools", False, f"unsupported agent: {agent}")
    attempt_ids = set(attempts)
    check("one-protected-attempt", len(attempt_ids) == 1 and all(attempt_ids),
          f"{len(attempt_ids)} distinct protected-edit tool calls; expected one with a recorded ID")
    return rows


if __name__ == "__main__":
    for row in checks(Path(sys.argv[1]), sys.argv[2]):
        print(json.dumps(row))
