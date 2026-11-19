#!/usr/bin/env python3
"""Run a bounded research task and its static-policy control through Box."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time

from fixture import RECORDS, ResearchFixture

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def decisions_from(path):
    decisions = []
    if not path.exists():
        return decisions
    for line in path.read_text().splitlines():
        for resource in json.loads(line).get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = {a["key"]: a["value"].get("stringValue", a["value"])
                             for a in record.get("attributes", [])}
                    if "strands.box.policy.verdict" in attrs:
                        decisions.append(attrs)
    return decisions


def python_grants(executable):
    roots = {str(Path(p).resolve()) for p in sys.path
             if p and Path(p).is_dir() and "python" in p and "site-packages" not in p}
    roots.update(p for p in ["/usr/lib64", "/usr/lib"] if Path(p).is_dir())
    roots = sorted(p for p in roots if not any(p != q and Path(q) in Path(p).parents for q in roots))
    probe = (
        "import runpy,sys,json; runpy.run_path(" + repr(str(ROOT / "client.py")) + "); "
        "print(json.dumps(sorted({m.__file__ for m in sys.modules.values() "
        "if getattr(m, '__file__', '') and m.__file__.endswith('.so')})))"
    )
    extensions = json.loads(subprocess.check_output([executable, "-I", "-B", "-c", probe], text=True))
    return roots, extensions


def run_case(name, output, binary, grants):
    run = output / name
    run.mkdir()
    (run / "workspace").mkdir()
    state = Path(tempfile.mkdtemp(prefix="box-research-")) / "state"
    with ResearchFixture() as fixture:
        template = "policy.dw" if name == "budgeted" else "policy-static.dw"
        (run / "policy.dw").write_text((ROOT / template).read_text().replace("port == 0", "port == " + str(fixture.port)).replace("port: 0", "port: " + str(fixture.port)))
        executable = str(Path(sys.executable).resolve())
        command = [executable, "-I", "-B", str(ROOT / "client.py"), "--service", fixture.base_url,
                   "--assignment", str(ROOT / "assignment.json")]
        (run / "box.toml").write_text("\n".join([
            'name = "research-' + name + '"',
            'box_dir = ' + json.dumps(str(state)),
            'policy = "policy.dw"',
            '[agent]',
            'command = ' + json.dumps(command),
            'workspace = ' + json.dumps(str(run / "workspace")),
            'env = { PATH = "/usr/bin:/bin" }',
            '[agent.filesystem]',
            'read = ' + json.dumps(grants[0]),
            'read_file = ' + json.dumps([str(ROOT / "client.py"), str(ROOT / "assignment.json")]),
            'exec = ' + json.dumps(grants[1]), '',
        ]))
        started = time.monotonic()
        process = subprocess.Popen(
            [str(binary), "run", "--config", str(run / "box.toml")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=dict(os.environ, EXPERIMENTAL_LINUX_SUPPORT="TRUE"), start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        duration = time.monotonic() - started
        (run / "stdout.txt").write_text(stdout)
        (run / "stderr.txt").write_text(stderr)
        snapshot = fixture.snapshot()
        write_json(run / "receiver.json", snapshot)
    telemetry = state / "private/telemetry/records.jsonl"
    if telemetry.exists():
        (run / "box-records.jsonl").write_bytes(telemetry.read_bytes())
    decisions = decisions_from(telemetry)
    try:
        workload = json.loads(stdout)
    except ValueError:
        workload = {}
    steps = workload.get("steps", [])
    sources = workload.get("sources", [])
    brief = workload.get("brief", "")
    (run / "brief.md").write_text(brief)
    expected_count = 3 if name == "budgeted" else 4
    topics = ["offline", "export", "platforms", "languages"][:expected_count]
    http = [d for d in decisions if d.get("strands.box.policy.action") == "http:request"]
    expected_verdicts = ["permit"] * expected_count + (["deny"] if name == "budgeted" else [])
    checks = {
        "workload_exit_zero": process.returncode == 0,
        "finished_within_history_window": not timed_out and duration < 300,
        "four_enrichment_attempts": len(steps) == 4,
        "first_three_permitted": len(steps) >= 3 and all(s.get("status") == 200 and not s.get("box_refused") for s in steps[:3]),
        "fourth_outcome": len(steps) == 4 and steps[3].get("status") == (403 if name == "budgeted" else 200)
                            and steps[3].get("box_refused") is (name == "budgeted"),
        "receiver_count": len(snapshot["requests"]) == expected_count,
        "receiver_topics": [r["topic"] for r in snapshot["requests"]] == topics,
        "receiver_only_valid_enrichments": all(r["status"] == 200 and r["method"] == "POST"
                                                  and r["path"] == "/research/enrich" for r in snapshot["requests"]),
        "source_ids_match_receiver": [s.get("source_id") for s in sources] == [r["source_id"] for r in snapshot["requests"]],
        "brief_cites_collected_sources": all("[" + RECORDS[t]["source_id"] + "]" in brief for t in topics),
        "brief_contains_collected_facts": all(RECORDS[t]["finding"] in brief for t in topics),
        "brief_completed_after_attempts": bool(brief) and workload.get("completion") == {"kind": "brief_completed", "after_call_count": 4},
        "four_http_decisions": len(http) == 4,
        "policy_verdicts_match": [d.get("strands.box.policy.verdict") for d in http] == expected_verdicts,
    }
    if name == "budgeted":
        checks.update({
            "denial_names_temporal_budget": len(http) == 4 and http[3].get("strands.box.policy.rule") == "research_attempt_budget",
            "blocked_fact_is_not_claimed": RECORDS["languages"]["finding"] not in brief and "[LANG-004]" not in brief,
            "remaining_question_is_explicit": "Unverified: Which interface languages are listed?" in brief,
        })
    return {
        "case": name, "status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
        "duration_seconds": duration, "exit_code": process.returncode, "box_state_dir": str(state),
        "workload": workload, "receiver": snapshot, "policy_decisions": decisions,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--box-binary", type=Path, default=ROOT.parent / "box-core/box")
    args = parser.parse_args()
    binary = args.box_binary.resolve()
    if platform.system() != "Linux":
        parser.error("this recipe is validated only on Linux; use a separate platform qualification")
    expected = json.loads((ROOT / "tested-build.json").read_text())
    observed = {}
    for relative, checksum in expected["files"].items():
        component = binary if Path(relative).name == "box" else binary.parent / Path(relative).name
        observed[relative] = digest(component)
        if observed[relative] != checksum:
            parser.error("binary archive differs from tested-build.json: " + str(component))
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    executable = str(Path(sys.executable).resolve())
    grants = python_grants(executable)
    result = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": "deterministic scripted research; no language model",
        "story": "A launch writer completes a sourced brief after three permitted enrichments; the fourth attempt is refused.",
        "platform": {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
                     "python": sys.version, "uid": os.getuid(),
                     "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else None},
        "box": {"revision": expected["box_revision"], "observed_sha256": observed},
        "source_sha256": {p.name: digest(p) for p in ROOT.iterdir() if p.is_file()},
        "python_library_reads": grants[0], "python_extension_exec": grants[1],
        "limits": ["Synthetic loopback HTTP service; no external research provider.",
                   "Attempt count within 300 seconds, not dollars or a lifetime quota.",
                   "Fresh Box state per case; no restart or cross-Box budget claim.",
                   "This receipt covers only the reported execution environment; no live-model, native filesystem interception, or production qualification claim."],
        "cases": [],
    }
    for name in ["budgeted", "static_control"]:
        entry = run_case(name, output, binary, grants)
        result["cases"].append(entry)
        print(name + ": " + entry["status"], flush=True)
        write_json(output / "result.json", result)
    result["status"] = "PASS" if all(case["status"] == "PASS" for case in result["cases"]) else "FAIL"
    result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write_json(output / "result.json", result)
    print(json.dumps({"status": result["status"], "result": str(output / "result.json")}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
