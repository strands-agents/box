#!/usr/bin/env python3
"""journal_find.py — one structural query over a box's decision journal.

[telemetry.decisions] writes OTLP JSON: one object per flush, each carrying
resourceLogs -> scopeLogs -> logRecords. A decision's verdict, the action and the
resource it judged are attributes named `strands.box.policy.verdict`,
`strands.box.policy.action` and `strands.box.policy.resource`; a control-plane
record carries none of them and is skipped. Grepping that shape is unreliable, so
the oracle asks this instead.

Usage: journal_find.py <journal> <permit|deny> <action-substring> [resource-substring]
                       [--attr KEY=SUBSTRING]... [--count]
Prints `<action> <resource>` for the first match and exits 0; exits 1 if none.
With --count, prints how many records match and exits 0. `--attr` narrows on any
other attribute, such as `strands.box.policy.rule=write_budget` or
`process.command=mkdir`; an array attribute is matched as its values joined by
one space.
"""
import json
import sys

count_only = False
attr_filters = []
positional = []
args = iter(sys.argv[1:])
for arg in args:
    if arg == "--count":
        count_only = True
    elif arg == "--attr":
        value = next(args, None)
        if value is None or "=" not in value:
            sys.stderr.write("journal_find: --attr needs KEY=SUBSTRING\n")
            sys.exit(2)
        attr_filters.append(value.split("=", 1))
    elif arg.startswith("--attr=") and "=" in arg[len("--attr="):]:
        attr_filters.append(arg[len("--attr="):].split("=", 1))
    else:
        positional.append(arg)
if len(positional) < 3:
    sys.stderr.write(__doc__)
    sys.exit(2)
path, want, action_sub = positional[:3]
res_sub = positional[3] if len(positional) > 3 else ""


def text(value):
    if "stringValue" in value:
        return value["stringValue"]
    if "arrayValue" in value:
        return " ".join(text(v) for v in value["arrayValue"].get("values", []))
    for key in ("intValue", "boolValue", "doubleValue"):
        if key in value:
            return str(value[key])
    return ""


def records(journal):
    try:
        fh = open(journal)
    except OSError:
        return
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        for rl in doc.get("resourceLogs", []):
            for sl in rl.get("scopeLogs", []):
                for rec in sl.get("logRecords", []):
                    attrs = {}
                    for a in rec.get("attributes", []):
                        attrs[a.get("key")] = text(a.get("value", {}))
                    yield attrs


matched = 0
for attrs in records(path):
    verdict = attrs.get("strands.box.policy.verdict", "")
    action = attrs.get("strands.box.policy.action", "")
    resource = attrs.get("strands.box.policy.resource", "")
    if verdict != want or action_sub not in action:
        continue
    if res_sub and res_sub not in resource:
        continue
    if any(sub not in attrs.get(key, "") for key, sub in attr_filters):
        continue
    if not count_only:
        print("%s %s" % (action, resource))
        sys.exit(0)
    matched += 1
if count_only:
    print(matched)
    sys.exit(0)
sys.exit(1)
