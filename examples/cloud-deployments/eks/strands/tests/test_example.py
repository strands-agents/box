"""Offline controls for the example; synthetic receipts do not establish isolation."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from urllib.parse import quote

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
import agent_program
import controller
import decisions
import verify


def fixture(mode="baseline"):
    root, program, box = "/synthetic/run", str(APP / "agent_program.py"), "/usr/local/bin/strands-box"
    note = json.loads((APP / "fixtures/release-note.json").read_text())
    if mode == "alternate":
        note["release_window"] = "Thursday at 10:00 UTC"
    child_final = {"project": note["project"], "release_window": note["release_window"], "summary": "A short release summary."}
    parent_final = {**child_final, "summary": "The child reviewed the release note."}
    identifier = "a" * 32
    envelope = {"status": "ok", "delegation_id": identifier, "child_role": "child",
                "child_result": child_final, "child_result_sha256": verify.digest(child_final)}
    receipt = {"run_id": "synthetic-run", "mode": mode, "run_root": root, "program": program,
               "program_sha256": hashlib.sha256(Path(program).read_bytes()).hexdigest(),
               "note_sha256": verify.digest(note), "box_binary": box, "broker_port": 8000,
               "protected_unchanged": True, "roles": {}, "parent_final": parent_final,
               "delegations": [{"delegation_id": identifier, "started_at": 6, "child_started_at": 9,
                                "child_ended_at": 21, "ended_at": 22, "envelope": envelope}]}
    for role in ("parent", "child"):
        work = root + "/" + role
        other = "child" if role == "parent" else "parent"
        other_input = "release-note.json" if other == "child" else "parent-only.txt"
        tool_name = "review_release" if role == "parent" else "read_release_note"
        result_value = envelope if role == "parent" else {"status": "ok", "note": note}
        final = parent_final if role == "parent" else child_final
        start, end = (1, 30) if role == "parent" else (10, 20)
        tool_start, tool_end = (5, 25) if role == "parent" else (13, 15)
        operation = {"name": tool_name, "arguments": {}, "started_at": tool_start,
                     "ended_at": tool_end, "result": result_value}
        if role == "parent":
            operation["delegation_id"] = identifier
        probes = []
        targets = {}
        for name, kind, path, allowed in (
            ("own_input", "read", work + "/in/job.json", True),
            ("own_output", "write", work + "/out/control.txt", True),
            ("other_input", "read", root + "/" + other + "/in/" + other_input, False),
            ("other_output", "write", root + "/" + other + "/out/private.txt", False),
            ("trusted_input", "read", root + "/trusted/private.txt", False),
            ("box_execute", "execute", box, False),
        ):
            probes.append({"name": name, "kind": kind, "path": path, "allowed": allowed,
                           "success": allowed, "errno": None if allowed else errno.EACCES})
            if not allowed:
                targets[name] = {"path": path, "kind": kind, "existed": True, "control": True}
        messages = [
            {"role": "user", "content": [{"text": agent_program.PARENT_PROMPT if role == "parent" else "Review your release note."}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": role + "-tool", "name": tool_name, "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": role + "-tool", "status": "success",
                                                        "content": [{"text": json.dumps(result_value)}]}}]},
            {"role": "assistant", "content": [{"text": json.dumps(final)}]},
        ]
        box_id = "box-" + ("1" if role == "parent" else "2") * 16
        result = {"run_id": receipt["run_id"], "role": role, "status": "complete", "model_id": "synthetic:model:0",
                  "region": "us-west-2", "messages": messages, "tools": [operation], "final": final,
                  "final_text": json.dumps(final), "model_calls": 2, "model_responses": 2,
                  "usage": {"inputTokens": 20, "outputTokens": 10}, "probes": probes}
        host = "bedrock-runtime.us-west-2.amazonaws.com"
        events = []
        for index, when in enumerate((2, 26) if role == "parent" else (11, 16)):
            events.append({"box_id": box_id, "box_run_id": role + "-run", "timestamp_ns": int(when * 1e9),
                           "strands.box.policy.principal": "agent:self", "strands.box.policy.verdict": "permit",
                           "strands.box.policy.action": "http:request", "server.address": host, "server.port": 443,
                           "http.request.method": "POST", "strands.box.request.id": role + "-request-" + str(index),
                           "strands.box.policy.resource": host + ":443/model/" + quote(result["model_id"], safe="") + "/converse-stream"})
        if role == "parent":
            events.append({**events[0], "server.address": "127.0.0.1", "server.port": 8000,
                           "strands.box.policy.resource": "127.0.0.1:8000/delegate/review",
                           "timestamp_ns": int(7e9), "strands.box.request.id": "delegate-request"})
        receipt["roles"][role] = {"box_id": box_id, "box_run_id": role + "-run", "started_at": start,
            "ended_at": end, "returncode": 0, "timed_out": False, "result": result, "decisions": events,
            "config": root + "/trusted/" + role + "/box.toml", "state": "/var/tmp/example/" + role + "/state",
            "command": [sys.executable, "-I", "-B", program, "--job", work + "/in/job.json"], "probe_targets": targets}
    return receipt


class VerifierTests(unittest.TestCase):
    def test_both_fixtures_with_identical_parent_input(self):
        baseline, alternate = fixture(), fixture("alternate")
        for value in (baseline, alternate):
            checked = verify.validate(value, expected_program=APP / "agent_program.py")
            self.assertTrue(checked["verified"])
            self.assertTrue(all(checked["checks"].values()))
        self.assertEqual(baseline["roles"]["parent"]["result"]["messages"][0], alternate["roles"]["parent"]["result"]["messages"][0])
        self.assertNotEqual(baseline["parent_final"]["release_window"], alternate["parent_final"]["release_window"])

    def test_native_identity_and_count_mutations_fail(self):
        mutations = [
            lambda r: r["roles"].pop("child"),
            lambda r: r.update(protected_unchanged=False),
            lambda r: r.update(program_sha256="0" * 64),
            lambda r: r.update(note_sha256="0" * 64),
            lambda r: r["roles"]["child"].update(box_id=r["roles"]["parent"]["box_id"]),
            lambda r: r["roles"]["child"].update(state=r["roles"]["parent"]["state"]),
            lambda r: r["roles"]["child"].update(config="/arbitrary/policy.toml"),
            lambda r: r["roles"]["parent"]["result"].update(model_calls=1),
            lambda r: r["roles"]["child"]["result"].update(usage={"inputTokens": 0, "outputTokens": 0}),
            lambda r: r["roles"]["child"]["decisions"].append(copy.deepcopy(r["roles"]["child"]["decisions"][0])),
            lambda r: r["roles"]["parent"]["decisions"][0].update({"strands.box.policy.resource": "unrelated"}),
            lambda r: r["roles"]["parent"]["decisions"][1].update(timestamp_ns=int(4e9)),
            lambda r: r["roles"]["parent"]["decisions"].pop(),
            lambda r: r["roles"]["child"].update(timed_out=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = fixture(); mutate(value)
                with self.assertRaises(verify.ValidationError):
                    verify.validate(value)

    def test_result_linkage_and_resumption_mutations_fail(self):
        mutations = [
            lambda r: r["roles"]["parent"]["result"]["messages"].pop(),
            lambda r: r["roles"]["parent"]["result"]["messages"][0]["content"][0].update(text="Changed parent prompt"),
            lambda r: r["roles"]["child"]["result"]["messages"][1]["content"][0]["toolUse"].update(input={"path": "/arbitrary"}),
            lambda r: r["roles"]["parent"]["result"]["messages"][2]["content"][0]["toolResult"].update(toolUseId="wrong"),
            lambda r: r["delegations"][0].update(child_started_at=26),
            lambda r: r["delegations"][0]["envelope"].update(child_result_sha256="0" * 64),
            lambda r: r["delegations"].append(copy.deepcopy(r["delegations"][0])),
            lambda r: r["parent_final"].update(release_window="Invented window"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = fixture(); mutate(value)
                with self.assertRaises(verify.ValidationError):
                    verify.validate(value)

    def test_existing_target_controls_are_required(self):
        for field, bad in (("existed", False), ("control", False), ("path", "/missing")):
            value = fixture()
            value["roles"]["parent"]["probe_targets"]["other_input"][field] = bad
            with self.assertRaises(verify.ValidationError):
                verify.validate(value)
        for mutation in (lambda p: p.update(success=True), lambda p: p.update(errno=errno.ETIMEDOUT),
                         lambda p: p.update(path="/missing")):
            value = fixture(); mutation(value["roles"]["child"]["result"]["probes"][2])
            with self.assertRaises(verify.ValidationError):
                verify.validate(value)

    def test_sdk_json_objects_are_supported_but_strings_are_not(self):
        value = fixture(); result = value["roles"]["parent"]["result"]
        content = result["messages"][2]["content"][0]["toolResult"]["content"]
        content[:] = [{"json": result["tools"][0]["result"]}]
        self.assertTrue(verify.validate(value)["verified"])
        content[0]["json"] = json.dumps(content[0]["json"])
        with self.assertRaises(verify.ValidationError):
            verify.validate(value)

    def test_error_shaped_finals_cannot_be_successful(self):
        value = fixture()
        result = value["roles"]["parent"]["result"]
        result["final"]["status"] = "error"
        result["final_text"] = json.dumps(result["final"])
        result["messages"][-1]["content"][0]["text"] = result["final_text"]
        with self.assertRaises(verify.ValidationError):
            verify.validate(value)


class ApplicationTests(unittest.TestCase):
    def test_final_parser_and_strict_tool_envelope(self):
        data = {"project": "Orion", "release_window": "Tuesday", "summary": "Summary"}
        for text in (json.dumps(data), "I reviewed the note.\n```json\n" + json.dumps(data) + "\n```"):
            self.assertEqual(agent_program.parse_final(text), data)
        for text in (json.dumps(json.dumps(data)), json.dumps({**data, "status": "error"}),
                     json.dumps(data) + "\n```json\n" + json.dumps(data) + "\n```",
                     "```json\n" + json.dumps(data) + "\n```\ntrailing"):
            with self.assertRaises(ValueError):
                agent_program.parse_final(text)
        with self.assertRaises(ValueError):
            agent_program.json_object("```json\n{}\n```")

    def test_file_tool_and_native_positive_controls(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / "in").mkdir(); (root / "out").mkdir()
            note = {"project": "Orion"}; (root / "in/release-note.json").write_text(json.dumps(note))
            tools = agent_program.Tools(root, {})
            self.assertEqual(json.loads(tools.read_release_note()), {"status": "ok", "note": note})
            self.assertEqual(json.loads(tools.read_release_note())["status"], "error")
            results = agent_program.boundary_probes([
                {"name": "read", "kind": "read", "path": str(root / "in/release-note.json"), "allowed": True},
                {"name": "write", "kind": "write", "path": str(root / "out/control.txt"), "allowed": True}])
            self.assertTrue(all(item["success"] for item in results))
            self.assertTrue((root / "out/control.txt").read_text())

    def launcher(self):
        launcher = controller.Launcher.__new__(controller.Launcher)
        launcher.receipt = {"delegations": []}
        launcher.lock = threading.Lock()
        launcher.note = {"project": "Orion", "release_window": "Tuesday"}
        launcher.launch = lambda role, port: {"final": {**launcher.note, "summary": "Summary"}}
        return launcher

    def test_fixed_child_and_one_delegation_only(self):
        launcher = self.launcher()
        result = launcher.delegate("/delegate/review", {}, "a" * 32, 8000)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["child_result_sha256"], controller.digest(result["child_result"]))
        with self.assertRaises(ValueError):
            launcher.delegate("/delegate/review", {}, "b" * 32, 8000)
        for path, payload, identifier in (("/delegate/arbitrary", {}, "a" * 32),
                ("/delegate/review", {"config": "/arbitrary"}, "a" * 32),
                ("/delegate/review", {}, "bad")):
            with self.assertRaises(ValueError):
                self.launcher().delegate(path, payload, identifier, 8000)

    def test_child_failure_and_wrong_fact_return_errors(self):
        launcher = self.launcher()
        launcher.launch = lambda role, port: {"final": {"status": "error", "error": "failed"}}
        self.assertEqual(launcher.delegate("/delegate/review", {}, "a" * 32, 8000)["status"], "error")
        launcher = self.launcher()
        launcher.launch = lambda role, port: {"final": {"project": "Orion", "release_window": "Wrong", "summary": "Summary"}}
        self.assertEqual(launcher.delegate("/delegate/review", {}, "a" * 32, 8000)["status"], "error")
        launcher = self.launcher()
        def failed(role, port):
            raise TimeoutError("synthetic child timeout")
        launcher.launch = failed
        self.assertEqual(launcher.delegate("/delegate/review", {}, "a" * 32, 8000)["status"], "error")
        self.assertIn("ended_at", launcher.receipt["delegations"][0])

    def test_startup_failure_keeps_receipt_and_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "new"
            args = ["--output", str(output), "--model", "synthetic:model:0", "--region", "us-west-2"]
            with patch.object(controller, "Launcher", side_effect=RuntimeError("synthetic startup failure")):
                self.assertEqual(controller.main(args), 1)
            before = (output / "receipt.json").read_bytes()
            self.assertFalse(json.loads(before)["passed"])
            with self.assertRaises(FileExistsError):
                controller.main(args)
            self.assertEqual((output / "receipt.json").read_bytes(), before)

    def test_configuration_keeps_roles_and_credential_environment_separate(self):
        with tempfile.TemporaryDirectory() as name:
            launcher = self.launcher(); launcher.root = Path(name) / "run"; launcher.root.mkdir()
            (launcher.root / "trusted").mkdir()
            launcher.receipt["run_id"] = "synthetic"
            launcher.state_root = Path(name) / "state"; launcher.state_root.mkdir()
            launcher.model, launcher.region, launcher.box = "synthetic:model:0", "us-west-2", Path(sys.executable)
            configs = []
            for role in ("parent", "child"):
                (launcher.root / role / "in").mkdir(parents=True)
                (launcher.root / role / "out").mkdir()
                with patch.object(controller, "runtime_grants", return_value=(["/synthetic/runtime"], ["/synthetic/extensions"])):
                    config, state, command = launcher.configure(role, 8000)
                content = config.read_text(); configs.append(content)
                environment = next(line for line in content.splitlines() if line.startswith("env="))
                self.assertNotIn("HOME", environment)
                self.assertNotIn("TOKEN", environment)
                self.assertNotIn("AWS_CONTAINER", environment)
                self.assertEqual(command[1:], ["-I", "-B", str(controller.PROGRAM), "--job", str(launcher.root / role / "in/job.json")])
                self.assertNotIn(str(launcher.root / ("child" if role == "parent" else "parent")), content)
                policy = (config.parent / "policy.dw").read_text()
                self.assertEqual("delegate_request" in policy, role == "parent")
                request_rule = policy.split('@id("model_request")', 1)[1].split(";", 1)[0]
                self.assertIn('context.input.port == 443', request_rule)
                self.assertIn('context.input.path == "/model/synthetic%3Amodel%3A0/converse-stream"', request_rule)
                self.assertIn('context.input.method == "POST"', request_rule)
            self.assertNotEqual(configs[0], configs[1])


class NativeProcessTests(unittest.TestCase):
    def test_broker_bounds_partial_body_and_accepts_complete_request(self):
        import socket
        launcher = controller.Launcher.__new__(controller.Launcher)
        launcher.receipt, launcher.protected = {}, {}
        delegated = []
        launcher.delegate = lambda *args: delegated.append(args) or {"status": "ok"}

        def parent(role, port):
            self.assertEqual(role, "parent")
            for body, declared, expected in ((b"{}", 2, b"200"), (b"{", 20, b"400")):
                with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                    headers = ("POST /delegate/review HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                               "Content-Length: " + str(declared) + "\r\nX-Delegation-Id: " + "d" * 32 + "\r\n\r\n")
                    connection.sendall(headers.encode() + body)
                    self.assertIn(expected, connection.recv(1024).split(b"\r\n", 1)[0])
            return {"final": {"synthetic": True}}

        launcher.launch = parent
        with patch.object(controller, "BROKER_READ_TIMEOUT", .1):
            launcher.run()
        self.assertEqual(len(delegated), 1)
        self.assertEqual(delegated[0][:2], ("/delegate/review", {}))

    def test_normal_process_positive_control(self):
        process = subprocess.Popen([sys.executable, "-c", "print('completed')"], text=True,
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _, timed_out = controller.wait_for_process(process, 5)
        self.assertEqual(stdout.strip(), "completed")
        self.assertFalse(timed_out)
        self.assertEqual(process.returncode, 0)

    def test_timeout_stops_descendant_after_leader_exit_and_keeps_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); child = root / "child.py"; heartbeat = root / "heartbeat"
            child.write_text("import signal,time\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM, lambda *args: None)\np=Path(" + repr(str(heartbeat)) + ")\nwhile True:\n with p.open('a') as out: out.write('x')\n time.sleep(.02)\n")
            program = ("import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-B'," + repr(str(child))
                       + "],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nprint('partial output',flush=True)\ntime.sleep(60)\n")
            process = subprocess.Popen([sys.executable, "-B", "-c", program], text=True, start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, _, timed_out = controller.wait_for_process(process, .5)
                self.assertTrue(timed_out)
                self.assertIn("partial output", stdout)
                self.assertTrue(heartbeat.exists())
                time.sleep(.05); before = heartbeat.read_bytes(); time.sleep(.15)
                self.assertEqual(heartbeat.read_bytes(), before)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)


class DecisionTests(unittest.TestCase):
    def test_native_scope_and_committed_identity(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); private = root / "private"; private.mkdir(); policy = root / "policy.dw"; policy.write_text("permit;")
            identity = "box-" + "1" * 16
            record = "\n".join(key + " = " + json.dumps(value) for key, value in {
                "box_id": identity, "box_dir": str(root), "name": "release-parent", "policy": str(policy)}.items()) + "\n"
            (private / "box.toml").write_text(record)
            (private / "configured").write_text(identity + " sha256:" + hashlib.sha256(record.encode()).hexdigest())
            def attributes(values):
                return [{"key": key, "value": {"stringValue": value}} for key, value in values.items()]
            event = {"eventName": "strands.box.policy.decision", "timeUnixNano": "1", "attributes": attributes({"strands.box.policy.action": "http:request"})}
            batch = {"resourceLogs": [{"resource": {"attributes": attributes({"strands.box.name": identity, "strands.box.run.id": "native-run"})},
                "scopeLogs": [{"scope": {"name": "workload"}, "logRecords": [event]},
                              {"scope": {"name": "strands-box.policy"}, "logRecords": [event]}]}]}
            log = root / "records.jsonl"; log.write_text(json.dumps(batch) + "\n")
            rows = decisions.decisions(log)
            self.assertEqual(len(rows), 1)
            self.assertEqual(decisions.batch_identity(rows, root, "release-parent", policy), (identity, "native-run"))
            (private / "configured").write_text(identity + " sha256:wrong")
            with self.assertRaises(AssertionError):
                decisions.batch_identity(rows, root, "release-parent", policy)


if __name__ == "__main__":
    unittest.main()
