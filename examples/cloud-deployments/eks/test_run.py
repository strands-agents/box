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
                 diagnostic_timeouts=False, diagnostic_hook=None, job_pending=False, extra_args=(),
                 dry_run_edit=None, created_edit=None, pod_edit=None, no_pods=False,
                 dry_run_warning="", failed_create=None, event_failure=False,
                 pending_job_polls=0, empty_pod_polls=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        previous = Path.cwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, previous)
        pod_spec = {"hostUsers": False, "containers": [{"name": "workload", "securityContext": {
            "procMount": "Unmasked", "seccompProfile": {"type": "Unconfined"}}}]}
        created = {"metadata": {"name": "box-scripted-test", "uid": "job-test-uid"}, "spec": {"template": {"spec": pod_spec}}}
        self.calls = calls = []
        self.stderr = stderr = io.StringIO()
        self.observed_polls = 0
        self.job_polls = 0
        self.call_timeouts = []

        def kubectl(command, **kwargs):
            calls.append(command)
            self.call_timeouts.append((command, kwargs.get("timeout")))
            if "--dry-run=server" in command:
                preview = json.loads(kwargs["input"])
                if dry_run_edit:
                    dry_run_edit(preview["spec"]["template"]["spec"])
                return subprocess.CompletedProcess(command, 0, json.dumps(preview), dry_run_warning)
            if "create" in command:
                if created_edit:
                    created_edit(created["spec"]["template"]["spec"])
                return subprocess.CompletedProcess(command, 0, json.dumps(created), "")
            if "events" in command:
                if event_failure:
                    return subprocess.CompletedProcess(command, 1, "", "Forbidden: cannot list events")
                events = [{"message": failed_create}] if failed_create else []
                return subprocess.CompletedProcess(command, 0, json.dumps({"items": events}), "")
            if "job" in command:
                if polling_timeout:
                    raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 99))
                if polling_failure:
                    return subprocess.CompletedProcess(command, 1, "", "Kubernetes API unavailable")
                self.job_polls += 1
                status = {} if job_pending or self.job_polls <= pending_job_polls else {"succeeded": 1}
                return subprocess.CompletedProcess(command, 0, json.dumps({**created, "status": status}), "")
            if "pods" in command and not polling_failure and not polling_timeout and not any("logs" in previous for previous in calls):
                self.observed_polls += 1
                pod = {"metadata": {"name": "box-pod"}, "spec": json.loads(json.dumps(pod_spec))}
                if pod_edit:
                    pod_edit(pod["spec"])
                return subprocess.CompletedProcess(command, 0, json.dumps({"items": [] if no_pods or self.observed_polls <= empty_pod_polls else [pod]}), "")
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
        with mock.patch.object(sys, "argv", ["run.py", "--image", "example:scripted", "--context", "test-context", *extra_args]), \
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
        self.assertNotIn("exercise", receipt)

    def test_claude_receipts_identify_the_exercise_even_when_polling_fails(self):
        for exercise in ("deployment-cooldown", "boundaries"):
            for polling_failure in (False, True):
                with self.subTest(exercise=exercise, polling_failure=polling_failure):
                    status, receipt, _, _ = self.run_case(
                        polling_failure=polling_failure,
                        extra_args=("--mode", "claude", "--exercise", exercise,
                                    "--service-account", "box-example", "--region", "us-west-2"),
                    )
                    self.assertEqual(status, 1 if polling_failure else 0)
                    self.assertEqual(receipt["exercise"], exercise)

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
        self.assertEqual(sum("create" in call and "--dry-run=server" not in call for call in calls), 1)
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
        self.assertEqual(sum("create" in call and "--dry-run=server" not in call for call in calls), 1)

    def test_pending_job_at_deadline_keeps_an_incomplete_receipt(self):
        with mock.patch.object(runner, "JOB_WAIT_SECONDS", {"scripted": 0.2}), \
                mock.patch.object(runner.time, "monotonic", side_effect=[0, 0, 0, 1, 1]):
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
                          if "logs" in command or "pods" in command],
                         [runner.COMMAND_TIMEOUT_SECONDS] + [runner.DIAGNOSTIC_TIMEOUT_SECONDS] * 2)
        self.assertEqual(sum("create" in call and "--dry-run=server" not in call for call in calls), 1)

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
if "--dry-run=server" in args:
    print(sys.stdin.read())
elif "create" in args:
    job = json.load(sys.stdin)
    job["metadata"]["name"] = "box-scripted-hang"
    print(json.dumps(job))
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
                self.assertEqual(sum("create" in call and "--dry-run=server" not in call for call in calls), 1)
                self.assertEqual(len(calls), 5)

    def test_dry_run_rejects_stripped_settings_without_creating_a_job(self):
        def strip(pod):
            pod.pop("hostUsers")
            pod["containers"][0]["securityContext"]["procMount"] = "Default"
        with self.assertRaisesRegex(RuntimeError, "hostUsers: expected false") as error:
            self.run_case(dry_run_edit=strip)
        self.assertIn("procMount: expected Unmasked", str(error.exception))
        self.assertIn("no Job was created", str(error.exception))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--dry-run=server", self.calls[0])
        self.assertFalse(Path("evidence").exists())

    def test_dry_run_api_errors_and_timeouts_never_create_a_job(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as temporary:
                previous = Path.cwd()
                try:
                    os.chdir(temporary)
                    result = subprocess.CompletedProcess([], 1, "", "Forbidden: admission policy")
                    error = subprocess.TimeoutExpired(["kubectl"], 30) if timeout else None
                    with mock.patch.object(sys, "argv", ["run.py", "--image", "example:test"]), \
                            mock.patch.object(runner.subprocess, "run", return_value=result, side_effect=error) as call:
                        with self.assertRaisesRegex(RuntimeError, "timed out" if timeout else "Forbidden"):
                            runner.main()
                    call.assert_called_once()
                    self.assertIn("--dry-run=server", call.call_args.args[0])
                    self.assertEqual(call.call_args.kwargs["timeout"], runner.COMMAND_TIMEOUT_SECONDS)
                    self.assertFalse(Path("evidence").exists())
                finally:
                    os.chdir(previous)

    def test_pod_admission_rejection_reports_the_job_event_without_waiting(self):
        message = 'pods "box-pod" is forbidden: violates PodSecurity "baseline": procMount=Unmasked'
        status, receipt, stderr, calls = self.run_case(no_pods=True, job_pending=True, failed_create=message)
        self.assertEqual(status, 1)
        self.assertIn(message, receipt["error"])
        self.assertTrue(receipt["incomplete"])
        self.assertIn("Inspect it with:", stderr)
        event_calls = [call for call in calls if "events" in call]
        self.assertEqual(len(event_calls), 1)
        self.assertIn("involvedObject.uid=job-test-uid,reason=FailedCreate", event_calls[0])
        saved = json.loads(Path("evidence/box-scripted-test/pod-creation-events.json").read_text())
        self.assertEqual(saved["items"][0]["message"], message)
        self.assertFalse(any("delete" in call for call in calls))

    def test_dry_run_admission_warnings_reach_the_operator(self):
        warning = "Warning: would violate PodSecurity baseline"
        status, _, stderr, _ = self.run_case(dry_run_warning=warning)
        self.assertEqual(status, 0)
        self.assertIn(warning, stderr)

    def test_events_permission_failure_is_preserved_and_reported(self):
        status, receipt, stderr, _ = self.run_case(no_pods=True, event_failure=True)
        self.assertEqual(status, 1)
        self.assertIn("Could not inspect Pod creation events", stderr)
        self.assertIn("Forbidden", Path("evidence/box-scripted-test/pod-creation-events.stderr.txt").read_text())
        self.assertIn("no Pod configuration", receipt["error"])

    def test_missing_events_permission_does_not_block_a_later_valid_pod(self):
        with mock.patch.object(runner.time, "sleep"):
            status, receipt, stderr, calls = self.run_case(
                pending_job_polls=1, empty_pod_polls=1, event_failure=True)
        self.assertEqual(status, 0)
        self.assertTrue(receipt["passed"])
        self.assertIn("Could not inspect Pod creation events", stderr)
        self.assertEqual(sum("events" in call for call in calls), 1)

    def test_created_job_change_preserves_recovery_evidence(self):
        status, receipt, stderr, _ = self.run_case(created_edit=lambda pod: pod.pop("hostUsers"))
        self.assertEqual(status, 1)
        self.assertIn("created Job", receipt["error"])
        self.assertTrue(receipt["incomplete"])
        self.assertIn("Inspect it with:", stderr)
        self.assertTrue(Path("evidence/box-scripted-test/submitted-job.json").is_file())

    def test_actual_pod_change_cannot_be_hidden_by_successful_workload(self):
        status, receipt, stderr, calls = self.run_case(pod_edit=lambda pod: pod.pop("hostUsers"))
        self.assertEqual(status, 1)
        self.assertFalse(receipt["passed"])
        self.assertIn("Pod box-pod", receipt["error"])
        self.assertIn("Inspect it with:", stderr)
        snapshot = json.loads(Path("evidence/box-scripted-test/pod-configuration.json").read_text())
        self.assertNotIn("hostUsers", snapshot["items"][0]["spec"])
        self.assertFalse(any("delete" in call for call in calls))

    def test_completed_job_without_pod_evidence_is_not_success(self):
        status, receipt, _, _ = self.run_case(no_pods=True)
        self.assertEqual(status, 1)
        self.assertIn("no Pod configuration", receipt["error"])


class SandboxSettingsTests(unittest.TestCase):
    def pod(self):
        return {"hostUsers": False, "containers": [{"name": "workload", "securityContext": {
            "procMount": "Unmasked", "seccompProfile": {"type": "Unconfined"}}}]}

    def test_each_required_setting_is_checked_independently(self):
        for key, value in (("procMount", "Default"), ("seccompProfile", {"type": "RuntimeDefault"})):
            with self.subTest(key=key):
                pod = self.pod()
                pod["containers"][0]["securityContext"][key] = value
                with self.assertRaisesRegex(RuntimeError, key):
                    runner.require_sandbox_settings(pod, "fixture")
        for value in (None, True, 0, "false"):
            with self.subTest(hostUsers=value):
                pod = self.pod()
                pod["hostUsers"] = value
                with self.assertRaisesRegex(RuntimeError, "hostUsers"):
                    runner.require_sandbox_settings(pod, "fixture")

    def test_named_workload_is_required_even_when_a_sidecar_is_valid(self):
        pod = self.pod()
        pod["containers"][0]["name"] = "sidecar"
        with self.assertRaisesRegex(RuntimeError, "workload container is absent"):
            runner.require_sandbox_settings(pod, "fixture")

    def test_pod_seccomp_is_inherited_but_container_override_wins(self):
        pod = self.pod()
        pod["securityContext"] = {"seccompProfile": {"type": "Unconfined"}}
        del pod["containers"][0]["securityContext"]["seccompProfile"]
        runner.require_sandbox_settings(pod, "fixture")
        pod["containers"][0]["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
        with self.assertRaisesRegex(RuntimeError, "seccompProfile"):
            runner.require_sandbox_settings(pod, "fixture")


class JobManifestTests(unittest.TestCase):
    def render(self, *arguments):
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["run.py", "--image", "example:test", "--render", *arguments]), \
                mock.patch.object(runner.subprocess, "run") as subprocess_run, \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(runner.main(), 0)
        subprocess_run.assert_not_called()
        return json.loads(stdout.getvalue())["spec"]["template"]["spec"]["containers"][0]

    def test_claude_defaults_to_the_deployment_cooldown_exercise(self):
        container = self.render("--mode", "claude", "--service-account", "box-example", "--region", "us-west-2")
        self.assertEqual(container["command"], ["/usr/bin/python3.12"])
        self.assertEqual(container["args"], ["/demo/main.py", "--exercise", "deployment-cooldown"])

    def test_claude_can_select_the_boundary_exercise(self):
        container = self.render("--mode", "claude", "--exercise", "boundaries",
                                "--service-account", "box-example", "--region", "us-west-2")
        self.assertEqual(container["command"], ["/usr/bin/python3.12"])
        self.assertEqual(container["args"], ["/demo/main.py", "--exercise", "boundaries"])

    def test_scripted_mode_preserves_the_image_command(self):
        container = self.render()
        self.assertNotIn("command", container)
        self.assertNotIn("args", container)
        self.assertNotIn("env", container)

    def test_unknown_exercise_fails_before_any_cluster_operation(self):
        with mock.patch.object(sys, "argv", ["run.py", "--image", "example:test", "--exercise", "unknown"]), \
                mock.patch.object(runner.subprocess, "run") as subprocess_run, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            runner.main()
        self.assertEqual(result.exception.code, 2)
        subprocess_run.assert_not_called()


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
