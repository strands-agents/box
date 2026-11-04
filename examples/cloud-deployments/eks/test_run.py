"""Check generated configuration and Job receipts without cloud connections."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("eks_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class JobReceiptTests(unittest.TestCase):
    def run_case(self, polling_failure=False, workload_passed=True, polling_timeout=False,
                 diagnostic_timeouts=False, diagnostic_hook=None, job_pending=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        previous = Path.cwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, previous)
        created = {"metadata": {"name": "box-scripted-test"}}
        calls = []
        self.call_timeouts = []

        def kubectl(command, **kwargs):
            calls.append(command)
            self.call_timeouts.append((command, kwargs.get("timeout")))
            if "create" in command:
                return subprocess.CompletedProcess(command, 0, json.dumps(created), "")
            if "job" in command:
                if polling_timeout:
                    raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 99))
                if polling_failure:
                    return subprocess.CompletedProcess(command, 1, "", "Kubernetes API unavailable")
                status = {} if job_pending else {"succeeded": 1}
                return subprocess.CompletedProcess(command, 0, json.dumps({**created, "status": status}), "")
            if "logs" in command:
                if diagnostic_hook:
                    diagnostic_hook(stderr.getvalue())
                if diagnostic_timeouts:
                    raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 99),
                                                    output=b'{"passed":true,"checks":{"fixture":true}}')
                return subprocess.CompletedProcess(command, 0, json.dumps({"passed": workload_passed, "checks": {"fixture": workload_passed}}), "")
            if diagnostic_timeouts:
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 99))
            return subprocess.CompletedProcess(command, 0, '{"items": []}', "")

        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["run.py", "--image", "example:scripted", "--context", "test-context"]), \
                mock.patch.object(runner.subprocess, "run", side_effect=kubectl), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            status = runner.main()
        evidence = Path("evidence/box-scripted-test")
        receipt = json.loads((evidence / "receipt.json").read_text())
        return status, receipt, stderr.getvalue(), calls

    def test_success_records_the_completed_job(self):
        status, receipt, _, _ = self.run_case()
        self.assertEqual(status, 0)
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["checks"], {"fixture": True})

    def test_failed_workload_is_not_a_successful_job_receipt(self):
        status, receipt, _, _ = self.run_case(workload_passed=False)
        self.assertEqual(status, 1)
        self.assertFalse(receipt["passed"])

    def test_poll_failure_keeps_receipt_and_recovery_command_for_created_job(self):
        status, receipt, stderr, calls = self.run_case(polling_failure=True)
        self.assertEqual(status, 1)
        self.assertFalse(receipt["passed"])
        self.assertIn("Kubernetes API unavailable", receipt["error"])
        self.assertEqual(receipt["job"], "box-scripted-test")
        self.assertIn("kubectl --context test-context --namespace box-demo get job box-scripted-test", stderr)
        self.assertEqual(sum("create" in call for call in calls), 1)
        self.assertTrue(Path("evidence/box-scripted-test/submitted-job.json").is_file())


    def test_poll_failure_saves_receipt_and_prints_recovery_before_diagnostics(self):
        def inspect(stderr):
            receipt = json.loads(Path("evidence/box-scripted-test/receipt.json").read_text())
            self.assertTrue(receipt["incomplete"])
            self.assertFalse(receipt["passed"])
            self.assertIn("Kubernetes API unavailable", receipt["error"])
            self.assertIn("kubectl --context test-context --namespace box-demo get job box-scripted-test", stderr)
        self.run_case(polling_failure=True, diagnostic_hook=inspect)

    def test_poll_timeout_uses_the_remaining_job_deadline(self):
        with mock.patch.object(runner, "JOB_WAIT_SECONDS", {"scripted": 0.2}), \
                mock.patch.object(runner.time, "monotonic", return_value=0):
            status, receipt, stderr, calls = self.run_case(polling_timeout=True)
        self.assertEqual(status, 1)
        self.assertTrue(receipt["incomplete"])
        self.assertIn("timed out", receipt["error"])
        self.assertIn("Inspect it with:", stderr)
        self.assertEqual([timeout for command, timeout in self.call_timeouts if "job" in command], [0.2])
        self.assertEqual(sum("create" in call for call in calls), 1)

    def test_pending_job_at_deadline_keeps_an_incomplete_receipt(self):
        with mock.patch.object(runner, "JOB_WAIT_SECONDS", {"scripted": 0.2}), \
                mock.patch.object(runner.time, "monotonic", side_effect=[0, 0, 1, 1]):
            status, receipt, stderr, _ = self.run_case(job_pending=True)
        self.assertEqual(status, 1)
        self.assertTrue(receipt["incomplete"])
        self.assertIn("deadline expired", receipt["error"])
        self.assertIn("Inspect it with:", stderr)

    def test_diagnostic_timeouts_are_bounded_and_cannot_report_success(self):
        status, receipt, _, calls = self.run_case(diagnostic_timeouts=True)
        self.assertEqual(status, 1)
        self.assertFalse(receipt["passed"])
        self.assertIn("timed out", receipt["error"])
        diagnostics = Path("evidence/box-scripted-test/stderr.txt").read_text()
        self.assertIn("logs job/box-scripted-test", diagnostics)
        self.assertIn("get pods", diagnostics)
        self.assertTrue(Path("evidence/box-scripted-test/pods.json").is_file())
        self.assertEqual([timeout for command, timeout in self.call_timeouts
                          if "logs" in command or "pods" in command], [runner.DIAGNOSTIC_TIMEOUT_SECONDS] * 2)
        self.assertEqual(sum("create" in call for call in calls), 1)

    def test_real_hanging_kubectl_processes_finish_with_recovery_evidence(self):
        for phase in ("poll", "diagnostics"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                executable = root / "kubectl"
                executable.write_text("""#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with Path("calls.jsonl").open("a") as stream: stream.write(json.dumps(args) + "\\n")
if "create" in args:
    print(json.dumps({"metadata": {"name": "box-scripted-hang"}}))
elif "job" in args:
    if os.environ["HANG_PHASE"] == "poll": time.sleep(30)
    print("synthetic polling failure", file=sys.stderr)
    sys.exit(1)
else:
    label = "logs" if "logs" in args else "pods"
    receipt = json.loads(Path("evidence/box-scripted-hang/receipt.json").read_text())
    Path(label + "-observed.json").write_text(json.dumps({"incomplete": receipt["incomplete"],
        "recovery_printed": "Inspect it with:" in Path("runner.stderr").read_text()}))
    if os.environ["HANG_PHASE"] == "diagnostics": time.sleep(30)
    print(json.dumps({"passed": True, "checks": {"fixture": True}} if label == "logs" else {"items": []}))
""")
                executable.chmod(0o755)
                bootstrap = """import importlib.util, sys
spec = importlib.util.spec_from_file_location("runner", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.COMMAND_TIMEOUT_SECONDS = 0.5
module.DIAGNOSTIC_TIMEOUT_SECONDS = 0.5
module.JOB_WAIT_SECONDS = {"scripted": 0.5}
sys.argv = ["run.py", "--image", "example:scripted", "--context", "test-context"]
raise SystemExit(module.main())
"""
                env = dict(os.environ, HANG_PHASE=phase, PYTHONDONTWRITEBYTECODE="1")
                env["PATH"] = str(root) + os.pathsep + env["PATH"]
                with (root / "runner.stdout").open("w") as stdout, (root / "runner.stderr").open("w") as stderr:
                    process = subprocess.Popen([sys.executable, "-c", bootstrap, runner.__file__],
                                               cwd=root, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                        self.fail("The runner did not bound the hanging kubectl process")
                self.assertEqual(process.returncode, 1, (root / "runner.stderr").read_text())
                receipt = json.loads((root / "evidence/box-scripted-hang/receipt.json").read_text())
                self.assertTrue(receipt["incomplete"])
                self.assertFalse(receipt["passed"])
                for label in ("logs", "pods"):
                    observed = json.loads((root / (label + "-observed.json")).read_text())
                    self.assertEqual(observed, {"incomplete": True, "recovery_printed": True})
                calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
                self.assertEqual(sum("create" in call for call in calls), 1)
                self.assertEqual(len(calls), 4)


class ClaudeConfigurationTests(unittest.TestCase):
    def test_claude_server_grants_its_canonical_interpreter_only_to_the_server(self):
        source = Path(__file__).with_name("claude") / "claude_runtime.py"
        spec = importlib.util.spec_from_file_location("tested_claude_runtime", source)
        runtime = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            spec.loader.exec_module(runtime)
        interpreter = Path(sys.executable).resolve()
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                executable = root / "python-alias" if linked else interpreter
                if linked:
                    executable.symlink_to(interpreter)
                with mock.patch.object(runtime.sys, "executable", str(executable)):
                    directory = runtime.ClaudeRuntime("unused-box").configure(
                        Path("/usr/bin/true"), None, False, exercise=True,
                        directory=root / "configuration",
                    )
                config = tomllib.loads((directory / "box.toml").read_text())
                header = (directory / "runtime-demo-mcp").read_text().splitlines()[0]
                self.assertEqual(header, "#!" + str(interpreter))
                self.assertEqual(config["mcp"]["runtime_demo"]["filesystem"]["read_file"],
                                 [str(interpreter)])
                self.assertNotIn(str(interpreter), config["agent"]["filesystem"]["read_file"])
                self.assertNotIn("exec", config["agent"]["filesystem"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
