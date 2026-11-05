"""Reject deployment claims without matching controller evidence."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("gcp_run_demo", HERE / "run-demo.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.agent = {
            "passed": True,
            "checks": {name: True for name in (
                "seven_model_selected_tools", "three_service_failures", "two_box_refusals",
                "diagnostics_available", "model_responses", "model_usage")},
            "credential_is_placeholder": True,
            "executor": "SequentialToolExecutor",
            "model_responses": 8,
            "usage": {"inputTokens": 40, "outputTokens": 16},
        }
        self.arrivals = [
            {"method": "POST", "path": "/deployments/checkout", "status": 503,
             "monotonic_ns": second * 1_000_000_000} for second in (1, 2, 3)
        ] + [{"method": "GET", "path": "/deployments/checkout/status", "status": 200,
              "monotonic_ns": 4_000_000_000}]
        self.audit = [
            {"action": "http:request", "verdict": "permit", "rule": "google_model_request"},
            {"action": "http:request", "verdict": "deny", "rule": "deployment_cooldown"},
            {"action": "http:request", "verdict": "deny", "rule": "deployment_cooldown"},
        ]

    def verify(self, *, agent=None, arrivals=None, audit=None, malformed=0):
        checks, _ = demo.verify_agent(
            "GCP_AGENT_RESULT " + json.dumps(self.agent if agent is None else agent),
            self.arrivals if arrivals is None else arrivals,
            self.audit if audit is None else audit, malformed, 0, False)
        return checks

    def test_matching_report_and_independent_evidence_pass(self):
        checks = self.verify()
        self.assertTrue(all(checks.values()), checks)

    def test_successful_process_cannot_override_false_agent_report(self):
        changes = (
            {"passed": False},
            {"checks": {"two_box_refusals": False}},
            {"checks": {}},
            {"checks": {"two_box_refusals": "true"}},
        )
        for change in changes:
            with self.subTest(change=change):
                agent = copy.deepcopy(self.agent)
                agent.update(change)
                checks = self.verify(agent=agent)
                self.assertFalse(all(checks.values()), checks)

    def test_agent_claim_cannot_replace_backend_receipts(self):
        for arrivals in ([], self.arrivals[1:], self.arrivals[:-1]):
            with self.subTest(arrivals=arrivals):
                checks = self.verify(arrivals=arrivals)
                self.assertFalse(all(checks.values()), checks)

    def test_agent_claim_cannot_replace_box_audit(self):
        for audit in ([], self.audit[:1], self.audit[1:]):
            with self.subTest(audit=audit):
                checks = self.verify(audit=audit)
                self.assertFalse(all(checks.values()), checks)
        checks = self.verify(malformed=1)
        self.assertFalse(all(checks.values()), checks)

    def test_service_failures_must_arrive_within_five_minutes(self):
        for span, expected in ((300_000_000_000, True), (300_000_000_001, False)):
            with self.subTest(span=span):
                arrivals = copy.deepcopy(self.arrivals)
                arrivals[2]["monotonic_ns"] = arrivals[0]["monotonic_ns"] + span
                arrivals[3]["monotonic_ns"] = arrivals[2]["monotonic_ns"] + 1
                checks = self.verify(arrivals=arrivals)
                self.assertEqual(all(checks.values()), expected, checks)


class ModelRouteTests(unittest.TestCase):
    def test_route_names_one_project_location_model_and_operation(self):
        for location, host in (("global", "aiplatform.googleapis.com"),
                               ("us-central1", "us-central1-aiplatform.googleapis.com")):
            with self.subTest(location=location):
                self.assertEqual(demo.model_endpoint("example-project", location, "gemini-test"),
                    (host, "/v1/projects/example-project/locations/" + location +
                     "/publishers/google/models/gemini-test:streamGenerateContent"))

    def test_inputs_cannot_add_another_route_or_policy_statement(self):
        attacks = (
            (0, "example-project/locations/other"),
            (0, 'example-project"; permit(principal, action, resource);'),
            (1, "global.evil.example"),
            (1, "global/other"),
            (2, "gemini-test:generateContent"),
            (2, "gemini-test?key=value"),
            (2, "gemini-test%2Fother"),
            (2, 'gemini-test"; permit(principal, action, resource);'),
        )
        for index, value in attacks:
            with self.subTest(index=index, value=value):
                arguments = ["example-project", "global", "gemini-test"]
                arguments[index] = value
                with self.assertRaises(ValueError):
                    demo.model_endpoint(*arguments)


class RuntimeGrantTests(unittest.TestCase):
    def test_native_module_grants_preserve_modes_and_keep_scratch_nonexecutable(self):
        with tempfile.TemporaryDirectory(prefix="box-gcp-library-test-") as temporary:
            root = Path(temporary).resolve()
            dynload = root / "runtime" / "lib-dynload"
            native = root / "runtime" / "native-package"
            dynload.mkdir(parents=True)
            native.mkdir(parents=True)
            modules = [dynload / "readonly.so", dynload / "executable.so", native / "module.so"]
            for module, mode in zip(modules, (0o644, 0o755, 0o755)):
                module.write_bytes(b"native module fixture")
                module.chmod(mode)
            alias = root / "readonly-alias.so"
            alias.symlink_to(modules[0])
            modes_before = [module.stat().st_mode for module in modules]
            discovered = [str(path) for path in modules + [alias]]
            with patch.object(demo.subprocess, "check_output", return_value=json.dumps(discovered)):
                demo.configure(root / "run", ["/usr/bin/python3", "-B", "fixture.py"],
                    "http://127.0.0.1:12345", "example-project", "global", "gemini-test")
            lines = (root / "run" / "box.toml").read_text().splitlines()
            grants = {key: json.loads(value) for key, _, value in
                      (line.partition("=") for line in lines) if key in ("exec", "write")}
            self.assertEqual(set(grants["exec"]), {str(dynload), str(modules[2])})
            self.assertEqual(len(grants["exec"]), 2, "Covered files and aliases must not duplicate grants")
            self.assertEqual([module.stat().st_mode for module in modules], modes_before)
            self.assertEqual(grants["write"], [str(root / "run" / "workspace")])
            for executable in map(Path, grants["exec"]):
                for writable in map(Path, grants["write"]):
                    self.assertFalse(executable.is_relative_to(writable) or writable.is_relative_to(executable))


class StartupEvidenceTests(unittest.TestCase):
    def run_startup_log_writer(self, setup_exit=0, writer_exit=0):
        source = (HERE / "setup-vm.sh").read_text()
        source = source[:source.index("\nmetadata() {")]
        system_tee = shutil.which("tee")
        self.assertIsNotNone(system_tee, "The startup log test requires tee")
        with tempfile.TemporaryDirectory(prefix="box-gcp-log-test-") as temporary:
            home = Path(temporary)
            logs = [home / "setup.log", home / "console.log"]
            source = source.replace("/var/log/box-gcp-setup.log", shlex.quote(str(logs[0])))
            source = source.replace("/dev/console", shlex.quote(str(logs[1])))
            binary = home / "bin"
            binary.mkdir()
            writer = binary / "tee"
            writer.write_text(
                f"#!{sys.executable}\n"
                "import subprocess, sys, time\n"
                "data = sys.stdin.buffer.read()\n"
                "time.sleep(0.2)\n"
                f"result = subprocess.run([{system_tee!r}, *sys.argv[1:]], input=data)\n"
                f"raise SystemExit({writer_exit} or result.returncode)\n"
            )
            writer.chmod(0o755)
            payload = "".join("BOX_GCP_RECEIPT_CHUNK=" + "a" * 64 +
                              f":{index}:6:" + "b" * 1000 + "\n" for index in range(6))
            program = source + "\nprintf '%s' " + shlex.quote(payload)
            program += "\nprintf '%s\\n' BOX_GCP_PHASE=complete\n"
            program += f"exit {setup_exit}\n"
            process = subprocess.Popen(
                ["bash", "-c", program], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": str(binary) + os.pathsep + "/usr/bin:/bin"}, start_new_session=True,
            )
            try:
                code = process.wait(timeout=4)
            finally:
                # The startup runner removes remaining children when its main process exits.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
            expected = payload + f"BOX_GCP_PHASE=complete\nBOX_GCP_SETUP_EXIT={setup_exit}\n"
            return code, [log.read_text() if log.exists() else "" for log in logs], expected

    def test_final_receipt_and_exit_reach_both_logs_before_cleanup(self):
        for setup_exit in (0, 7):
            code, logs, expected = self.run_startup_log_writer(setup_exit=setup_exit)
            self.assertEqual(code, setup_exit)
            self.assertEqual(logs, [expected, expected])

    def test_log_writer_failure_makes_setup_fail(self):
        code, logs, expected = self.run_startup_log_writer(writer_exit=23)
        self.assertEqual(code, 1)
        self.assertEqual(logs, [expected, expected])

    def test_failed_restart_cannot_reuse_previous_success(self):
        source = (HERE / "setup-vm.sh").read_text()
        runner = source.split("/usr/bin/python3 -I -B - <<'RUN'\n", 1)[1].split("\nRUN\n", 1)[0]
        with tempfile.TemporaryDirectory(prefix="box-gcp-startup-test-") as temporary:
            home = Path(temporary)
            config = home / "config.json"
            config.write_text(json.dumps({
                "owner": "test-owner", "source_revision": "a" * 40,
                "payload_sha256": "b" * 64, "project": "example-project",
                "location": "global", "model": None, "probe_only": True,
            }))
            runner = runner.replace("/var/lib/box-gcp/config.json", str(config))
            runner = runner.replace("/home/boxdemo", str(home))
            outputs, receipts = [], []

            def run_probe(command):
                output = Path(command[command.index("--output") + 1])
                self.assertFalse(output.exists(), "A startup attempt reused an existing result")
                outputs.append(output)
                if len(outputs) == 1:
                    output.write_text(json.dumps({"passed": True, "evidence_run": "first-startup"}))
                    return subprocess.CompletedProcess(command, 0)
                return subprocess.CompletedProcess(command, 2)

            with patch("subprocess.run", side_effect=run_probe):
                for expected_code in (0, 2):
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                        exec(compile(runner, "setup-vm.sh:RUN", "exec"), {})
                    self.assertEqual(stopped.exception.code, expected_code)
                    receipts.append(json.loads((home / "results.json").read_text()))
            self.assertNotEqual(receipts[0]["attempt"], receipts[1]["attempt"])
            self.assertTrue(json.loads(outputs[0].read_text())["passed"])
            self.assertFalse(outputs[1].exists())
            self.assertEqual(receipts[1]["probe"], {"exit_code": 2})
            self.assertEqual(receipts[1]["probe_exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
