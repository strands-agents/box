"""Check generated configuration and Job receipts without cloud connections."""
import argparse
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
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location("eks_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class JobReceiptTests(unittest.TestCase):
    def run_case(self, polling_failure=False, workload_passed=True, polling_timeout=False,
                 diagnostic_timeouts=False, diagnostic_hook=None, job_pending=False, mode="scripted", payload=None):
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
                return subprocess.CompletedProcess(command, 0, json.dumps(payload if payload is not None else {"passed": workload_passed, "checks": {"fixture": workload_passed}}), "")
            if diagnostic_timeouts:
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 99))
            return subprocess.CompletedProcess(command, 0, '{"items": []}', "")

        stderr = io.StringIO()
        arguments = ["run.py", "--image", "example:scripted", "--context", "test-context", "--mode", mode]
        if mode == "strands":
            arguments += ["--region", "us-west-2", "--service-account", "box-strands",
                          "--expected-role-arn", "arn:aws:iam::123456789012:role/test-role"]
        with mock.patch.object(sys, "argv", arguments), \
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


class StrandsConfigurationTests(unittest.TestCase):
    def arguments(self, **changes):
        values = dict(namespace="box-test", image="example:strands", mode="strands",
                      service_account="box-strands", region="us-west-2", image_pull_secret=None,
                      expected_role_arn="arn:aws:iam::123456789012:role/test-role",
                      model="global.anthropic.claude-sonnet-4-5-20250929-v1:0", fixture="baseline")
        values.update(changes)
        return argparse.Namespace(**values)

    def test_strands_uses_the_tested_user_and_writable_directories(self):
        pod = runner.manifest(self.arguments())['spec']['template']['spec']
        container = pod['containers'][0]
        self.assertFalse(pod['hostUsers'])
        self.assertEqual(pod['securityContext']['fsGroup'], 1000)
        self.assertEqual(container['securityContext'], {
            'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
            'allowPrivilegeEscalation': False, 'privileged': False,
            'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'Unconfined'},
            'procMount': 'Unmasked', 'readOnlyRootFilesystem': True,
        })
        self.assertEqual({item['mountPath'] for item in container['volumeMounts']},
                         {'/evidence', '/tmp', '/var/tmp', '/home/agent'})
        self.assertTrue(all(item['emptyDir'] == {} for item in pod['volumes']))
        self.assertEqual(container['args'], ['--mode', 'baseline', '--auth', 'pod-identity'])

    def test_alternate_fixture_reaches_the_image_entrypoint(self):
        container = runner.manifest(self.arguments(fixture='alternate'))['spec']['template']['spec']['containers'][0]
        self.assertEqual(container['args'], ['--mode', 'alternate', '--auth', 'pod-identity'])
        self.assertIn({'name': 'EXPECTED_ROLE_ARN', 'value': self.arguments().expected_role_arn}, container['env'])
        self.assertNotIn('AWS_BEARER_TOKEN_BEDROCK', {item['name'] for item in container['env']})

    def test_strands_requires_identity_inputs_before_any_cluster_call(self):
        for field in ('expected_role_arn', 'service_account', 'region'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.manifest(self.arguments(**{field: None}))
        with self.assertRaises(ValueError):
            runner.manifest(self.arguments(expected_role_arn='arn:aws:iam::123456789012:user/person'))

    def test_existing_modes_keep_their_uid_and_filesystem_settings(self):
        for mode in ('scripted', 'claude'):
            with self.subTest(mode=mode):
                pod = runner.manifest(self.arguments(mode=mode))['spec']['template']['spec']
                self.assertEqual(pod['securityContext']['fsGroup'], 991)
                self.assertEqual(pod['containers'][0]['securityContext']['runAsUser'], 991)
                self.assertNotIn('volumes', pod)
                self.assertNotIn('readOnlyRootFilesystem', pod['containers'][0]['securityContext'])

    def test_render_does_not_contact_kubernetes_and_selects_the_strands_model(self):
        arguments = ['run.py', '--mode', 'strands', '--image', 'example:strands', '--render',
                     '--service-account', 'box-strands', '--region', 'us-west-2',
                     '--expected-role-arn', self.arguments().expected_role_arn]
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(runner.subprocess, 'run') as call, \
                contextlib.redirect_stdout(output):
            self.assertEqual(runner.main(), 0)
        call.assert_not_called()
        pod = json.loads(output.getvalue())['spec']['template']['spec']
        self.assertIn({'name': 'BEDROCK_MODEL_ID', 'value': self.arguments().model}, pod['containers'][0]['env'])


class StrandsReceiptTests(unittest.TestCase):
    run_case = JobReceiptTests.run_case

    def test_strands_requires_the_full_successful_receipt(self):
        good = {'passed': True, 'checks': {'fixture': True}, 'receipt': {'passed': True}}
        self.assertEqual(self.run_case(mode='strands', payload=good)[0], 0)
        for bad in [dict(good, receipt=None), dict(good, passed='true'), dict(good, checks={}),
                    dict(good, checks={'fixture': False}), dict(good, receipt={'passed': False})]:
            with self.subTest(payload=bad):
                self.assertEqual(self.run_case(mode='strands', payload=bad)[0], 1)


class StrandsEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name('strands') / 'entrypoint.py'
        spec = importlib.util.spec_from_file_location('strands_entrypoint', path)
        cls.entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.entry)

    def execute(self, *, code=0, receipt=None, validation=None, validate_error=None, auth='bearer-token', token='synthetic-token'):
        if receipt is None:
            receipt = {'passed': True, 'run_id': 'synthetic-run'}
        if validation is None:
            validation = {'verified': True, 'checks': {'receipt_consistent': True}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def controller_main(arguments):
                output = Path(arguments[arguments.index('--output') + 1])
                output.mkdir()
                (output / 'receipt.json').write_text(json.dumps(receipt))
                print('controller diagnostic ' + token)
                return code
            controller = SimpleNamespace(main=mock.Mock(side_effect=controller_main))
            verifier = SimpleNamespace(validate=mock.Mock(return_value=validation, side_effect=validate_error))
            output, diagnostics = io.StringIO(), io.StringIO()
            with mock.patch.object(self.entry, 'EVIDENCE', directory), \
                    mock.patch.object(self.entry, 'build_facts', return_value={'fixture': 'synthetic'}), \
                    mock.patch.dict(os.environ, {'AWS_BEARER_TOKEN_BEDROCK': token}, clear=True), \
                    mock.patch.dict(sys.modules, {'controller': controller, 'verify': verifier}), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostics):
                result = self.entry.main(['--auth', auth, '--model', 'test-model', '--region', 'us-west-2'])
                self.assertNotIn('AWS_BEARER_TOKEN_BEDROCK', os.environ)
            return result, json.loads(output.getvalue()), diagnostics.getvalue(), controller, verifier

    def test_one_json_result_revalidates_receipt_and_redacts_diagnostics(self):
        code, result, diagnostics, controller, verifier = self.execute()
        self.assertEqual(code, 0)
        self.assertTrue(result['passed'])
        self.assertEqual(result['checks'], {'receipt_consistent': True})
        self.assertEqual(result['platform']['credential_provider'], 'caller-bearer-token')
        self.assertNotIn('synthetic-token', diagnostics)
        self.assertIn('[REDACTED]', diagnostics)
        verifier.validate.assert_called_once_with(result['receipt'], expected_program=self.entry.ROOT / 'agent_program.py')
        controller.main.assert_called_once()

    def test_exit_zero_alone_and_unverified_receipts_cannot_pass(self):
        for changes in ({'code': 1}, {'receipt': {'passed': False}}, {'receipt': {'passed': 'true'}},
                        {'validation': {'verified': True, 'checks': {}}},
                        {'validation': {'verified': True, 'checks': {'x': False}}},
                        {'validate_error': ValueError('synthetic verifier refusal')}):
            with self.subTest(changes=changes):
                code, result, _, _, _ = self.execute(**changes)
                self.assertEqual(code, 1)
                self.assertFalse(result['passed'])

    def test_missing_explicit_token_fails_before_controller(self):
        code, result, _, controller, _ = self.execute(token='')
        self.assertEqual(code, 1)
        self.assertIn('AWS_BEARER_TOKEN_BEDROCK', result['error'])
        controller.main.assert_not_called()

    def test_nonfinite_receipt_still_emits_one_failure_object(self):
        code, result, _, _, _ = self.execute(receipt={'passed': False, 'invalid': float('nan')})
        self.assertEqual(code, 1)
        self.assertFalse(result['passed'])
        self.assertIsNone(result['receipt'])

    def pod_identity(self, *, method='container-role', account='123456789012', arn=None, override=None,
                     role_arn='arn:aws:iam::123456789012:role/test-role'):
        credentials = SimpleNamespace(method=method)
        client = SimpleNamespace(get_caller_identity=mock.Mock(return_value={
            'Account': account, 'Arn': arn or 'arn:aws:sts::123456789012:assumed-role/test-role/pod'}))
        session = SimpleNamespace(get_credentials=lambda: credentials, client=mock.Mock(return_value=client))
        generator = mock.Mock(return_value='synthetic-generated-token')
        modules = {'boto3': SimpleNamespace(Session=mock.Mock(return_value=session)),
                   'botocore.config': SimpleNamespace(Config=lambda **kwargs: kwargs),
                   'aws_bedrock_token_generator': SimpleNamespace(provide_token=generator)}
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / 'token'
            token_path.write_text('synthetic-pod-token')
            env = {'AWS_CONTAINER_CREDENTIALS_FULL_URI': 'http://127.0.0.1:1234/unused',
                   'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE': str(token_path)}
            if override:
                env[override] = 'synthetic-override'
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.dict(sys.modules, modules):
                result = self.entry.pod_token('us-west-2', role_arn)
            self.assertIs(generator.call_args.kwargs['aws_credentials_provider'].load(), credentials)
            return result, generator

    def test_pod_identity_token_uses_the_verified_provider(self):
        (token, facts), generator = self.pod_identity()
        self.assertEqual(token, 'synthetic-generated-token')
        self.assertEqual(facts['credential_provider'], 'container-role')
        self.assertEqual(generator.call_args.kwargs['expiry'].total_seconds(), 900)
        self.pod_identity(role_arn='arn:aws:iam::123456789012:role/team/test-role')

    def test_pod_identity_refuses_wrong_provider_account_role_and_overrides(self):
        for changes in ({'method': 'env'}, {'account': '999999999999'},
                        {'arn': 'arn:aws:sts::123456789012:assumed-role/another-role/pod'},
                        {'override': 'AWS_PROFILE'}, {'override': 'AWS_BEARER_TOKEN_BEDROCK'}):
            with self.subTest(changes=changes), self.assertRaises(self.entry.ConfigurationError):
                self.pod_identity(**changes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
