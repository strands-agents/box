"""Offline contracts for optional Strands packaging and Runtime dispatch."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load_module("strands_test_deployer", "deploy-runtime.py")
runtime = load_module("strands_test_runtime", "runtime_app.py")
MODEL = "us.anthropic.claude-sonnet-4-6"
REGION = "us-west-2"


def policy_statements(template):
    role = template["Resources"]["ExecutionRole"]["Properties"]
    return [statement for policy in role["Policies"] for statement in policy["PolicyDocument"]["Statement"]]


def actions(statement):
    value = statement["Action"]
    return [value] if isinstance(value, str) else value


class StrandsTemplateTests(unittest.TestCase):
    def test_scripted_template_has_no_model_permissions_or_settings(self):
        template = helper.template()
        granted = [action for statement in policy_statements(template) for action in actions(statement)]
        self.assertFalse(any(action.startswith("bedrock:") for action in granted))
        properties = template["Resources"]["ShipmentRuntime"]["Properties"]
        self.assertNotIn("BOX_DEMO_MODEL_ID", properties.get("EnvironmentVariables", {}))
        self.assertNotIn("BOX_DEMO_REGION", properties.get("EnvironmentVariables", {}))

    def test_strands_template_scopes_model_invocation_and_sets_matching_route(self):
        template = helper.template(with_strands=True)
        statements = policy_statements(template)
        invocation = [statement for statement in statements if "bedrock:InvokeModel" in actions(statement)]
        self.assertEqual(len(invocation), 1)
        self.assertEqual(set(actions(invocation[0])), {"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"})
        resources = [resource["Fn::Sub"] for resource in invocation[0]["Resource"]]
        self.assertFalse(any("*" in resource for resource in resources))
        self.assertEqual(set(resources), {
            "arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:inference-profile/" + MODEL,
            *["arn:${AWS::Partition}:bedrock:" + region + "::foundation-model/anthropic.claude-sonnet-4-6"
              for region in ("us-east-1", "us-east-2", "us-west-2")],
        })
        bearer = [statement for statement in statements if "bedrock:CallWithBearerToken" in actions(statement)]
        self.assertEqual(len(bearer), 1)
        self.assertEqual(actions(bearer[0]), ["bedrock:CallWithBearerToken"])
        properties = template["Resources"]["ShipmentRuntime"]["Properties"]
        self.assertEqual(properties["EnvironmentVariables"], {
            "BOX_DEMO_MODEL_ID": MODEL, "BOX_DEMO_REGION": {"Ref": "AWS::Region"},
        })
        self.assertEqual(properties["AgentRuntimeArtifact"]["CodeConfiguration"]["Runtime"], "PYTHON_3_12")
        self.assertEqual(properties["PlatformVersion"], "V2")


class StrandsPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "source"
        self.source.mkdir()
        patch = mock.patch.object(helper, "ROOT", self.source)
        patch.start()
        self.addCleanup(patch.stop)
        paths = list(helper.SOURCES) + ["research/" + name for name in (
            "run-demo.py", "client.py", "fixture.py", "policy.dw", "policy-static.dw", "assignment.json", "tested-build.json",
        )] + ["sdk/" + name for name in ("agent.py", "run-demo.py", "requirements.txt", "dependency-lock.txt")]
        for name in paths:
            self.write(name, b"offline fixture\n")
        binary = bytearray(64)
        binary[:6] = b"\x7fELF\x02\x01"
        binary[18:20] = b"\xb7\x00"
        self.write("box-core/box", binary)
        self.write("binary-manifest.json", json.dumps({
            "box_revision": "offline-test-revision",
            "files": {"box-core/box": hashlib.sha256(binary).hexdigest()},
        }).encode())
        self.vendor_name = "sdk/vendor/strands/__init__.py"
        self.write(self.vendor_name, b"VERSION = 'offline-test'\n")
        self.manifest = {"python_minor": "3.12", "architecture": "aarch64", "files": {
            self.vendor_name: hashlib.sha256((self.source / self.vendor_name).read_bytes()).hexdigest(),
        }}
        self.write_manifest()

    def write(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def write_manifest(self):
        self.write("sdk/dependency-manifest.json", json.dumps(self.manifest).encode())

    def package(self, with_strands=True):
        return helper.package(self.directory / "output", with_strands=with_strands)

    def test_optional_package_contains_verified_dependencies_and_model_template(self):
        receipt = self.package()
        self.assertTrue(receipt["manifest"]["with_strands"])
        self.assertIn("Strands SDK", receipt["manifest"]["mode"])
        with zipfile.ZipFile(receipt["archive"]) as archive:
            self.assertEqual(archive.read(self.vendor_name), (self.source / self.vendor_name).read_bytes())
            for name in ("sdk/agent.py", "sdk/run-demo.py", "sdk/dependency-manifest.json", "sdk/dependency-lock.txt"):
                self.assertIn(name, archive.namelist())
            manifest = json.loads(archive.read("deployment-manifest.json"))
            self.assertEqual(manifest["files"][self.vendor_name], self.manifest["files"][self.vendor_name])
        template = json.loads((self.directory / "output/runtime.cloudformation.json").read_text())
        self.assertTrue(any("bedrock:InvokeModel" in actions(s) for s in policy_statements(template)))

    def test_scripted_package_ignores_sdk_and_keeps_model_access_disabled(self):
        (self.source / "sdk").rename(self.source / "unused-sdk")
        receipt = self.package(with_strands=False)
        self.assertFalse(receipt["manifest"]["with_strands"])
        self.assertIn("no language model", receipt["manifest"]["mode"])
        with zipfile.ZipFile(receipt["archive"]) as archive:
            self.assertFalse(any(name.startswith("sdk/") for name in archive.namelist()))
            self.assertIn("run-demo.py", archive.namelist())
            self.assertIn("research/run-demo.py", archive.namelist())

    def test_changed_dependency_is_rejected_before_archive_creation(self):
        self.write(self.vendor_name, b"changed dependency\n")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.package()
        self.assertFalse((self.directory / "output/runtime.zip").exists())

    def test_missing_dependency_is_rejected_before_archive_creation(self):
        path = self.source / self.vendor_name
        path.rename(path.with_suffix(".missing"))
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.package()
        self.assertFalse((self.directory / "output/runtime.zip").exists())

    def test_incompatible_python_or_architecture_is_rejected(self):
        for field, incompatible in (("python_minor", "3.11"), ("architecture", "x86_64")):
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = incompatible
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, "Python 3.12 on Linux ARM64"):
                    self.package()
                self.manifest[field] = original
        self.write_manifest()

    def test_dependency_path_outside_vendor_is_rejected(self):
        self.manifest["files"] = {"sdk/../outside.py": "0" * 64}
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "dependency path"):
            self.package()


class StrandsRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.application = self.directory / "application"
        (self.application / "sdk").mkdir(parents=True)
        (self.application / "sdk/run-demo.py").write_text("offline placeholder")
        self.output = self.directory / "output"
        self.output.mkdir()
        self.state = {"status": "idle", "mode": "deterministic scripted workload; no language model"}
        patches = [mock.patch.object(runtime, "APPLICATION", self.application),
                   mock.patch.object(runtime, "STATE", self.state),
                   mock.patch.object(runtime, "RUN_LOCK", threading.Lock()),
                   mock.patch.object(runtime, "STATE_LOCK", threading.Lock()),
                   mock.patch.object(runtime.tempfile, "mkdtemp", return_value=str(self.output)),
                   mock.patch.dict(runtime.os.environ, {"BOX_DEMO_MODEL_ID": MODEL, "BOX_DEMO_REGION": REGION})]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.process = mock.Mock(returncode=0)
        self.process.wait.return_value = 0

    def completed_process(self, command, **kwargs):
        self.assertEqual(self.state["status"], "running")
        (self.output / "result.json").write_text(json.dumps({"status": "PASS", "checks": {"offline": True}}))
        kwargs["stdout"].write("offline subprocess output")
        return self.process

    def request(self, payload):
        handler = object.__new__(runtime.Handler)
        handler.path = "/invocations"
        body = json.dumps(payload).encode()
        handler.headers = {"Content-Length": str(len(body))}
        handler.rfile = io.BytesIO(body)
        handler.reply = mock.Mock()
        handler.do_POST()
        return handler.reply.call_args.args

    def test_strands_dispatch_uses_model_settings_mode_and_240_second_limit(self):
        with mock.patch.object(runtime.subprocess, "Popen", side_effect=self.completed_process) as popen:
            status, body = runtime.run_demo("shipment-strands")
        self.assertEqual((status, body["status"]), (200, "PASS"))
        self.assertEqual(body["example"], "shipment-strands")
        self.assertIn("Strands SDK", body["mode"])
        self.assertIn("live Bedrock", body["mode"])
        command = popen.call_args.args[0]
        self.assertEqual(command[1], str(self.application / "sdk/run-demo.py"))
        self.assertEqual(command[command.index("--model") + 1], MODEL)
        self.assertEqual(command[command.index("--region") + 1], REGION)
        self.assertEqual(popen.call_args.kwargs["env"]["EXPERIMENTAL_LINUX_SUPPORT"], "TRUE")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.process.wait.assert_called_once_with(timeout=240)
        self.assertEqual(self.state["status"], "complete")
        self.assertEqual(self.state["mode"], body["mode"])
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_scripted_examples_keep_existing_paths_and_120_second_limit(self):
        for example, script in (("shipment", "run-demo.py"), ("research", "research/run-demo.py")):
            with self.subTest(example=example):
                self.process.wait.reset_mock()
                with mock.patch.object(runtime.subprocess, "Popen", side_effect=self.completed_process) as popen:
                    status, body = runtime.run_demo(example)
                self.assertEqual((status, body["status"]), (200, "PASS"))
                self.assertIn("no language model", body["mode"])
                command = popen.call_args.args[0]
                self.assertEqual(command[1], str(self.application / script))
                self.assertNotIn("--model", command)
                self.process.wait.assert_called_once_with(timeout=120)

    def test_strands_timeout_stops_process_and_reports_error(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired(cmd="offline", timeout=240)
        with mock.patch.object(runtime.subprocess, "Popen", return_value=self.process), \
                mock.patch.object(runtime, "stop_process_tree") as stop:
            status, body = runtime.run_demo("shipment-strands")
        self.assertEqual((status, body["status"]), (500, "FAIL"))
        self.assertIn("exceeded 240 seconds", body["error"])
        self.assertIn("Strands SDK", body["mode"])
        stop.assert_called_once_with(self.process)
        self.assertEqual(self.state["status"], "error")
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_directory_failure_releases_lock_and_allows_next_invocation(self):
        with mock.patch.object(runtime.tempfile, "mkdtemp", side_effect=OSError("No space left on device")), \
                mock.patch.object(runtime.subprocess, "Popen") as popen:
            status, body = self.request({"operation": "run"})
        self.assertEqual((status, body["status"]), (500, "FAIL"))
        self.assertIn("No space left on device", body["error"])
        self.assertEqual(self.state["status"], "error")
        self.assertFalse(runtime.RUN_LOCK.locked())
        popen.assert_not_called()
        with mock.patch.object(runtime.subprocess, "Popen", side_effect=self.completed_process):
            status, body = self.request({"operation": "run"})
        self.assertEqual((status, body["status"]), (200, "PASS"))
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_missing_runner_rejects_strands_before_starting_a_process(self):
        path = self.application / "sdk/run-demo.py"
        path.rename(path.with_suffix(".disabled"))
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            status, body = runtime.run_demo("shipment-strands")
        self.assertEqual(status, 400)
        self.assertIn("--with-strands", body["error"])
        popen.assert_not_called()
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_missing_model_or_region_rejects_strands_before_starting_a_process(self):
        for name in ("BOX_DEMO_MODEL_ID", "BOX_DEMO_REGION"):
            with self.subTest(setting=name), mock.patch.dict(runtime.os.environ, {name: ""}), \
                    mock.patch.object(runtime.subprocess, "Popen") as popen:
                status, _ = runtime.run_demo("shipment-strands")
                self.assertEqual(status, 400)
                popen.assert_not_called()

    def test_http_dispatch_accepts_fixed_examples_and_rejects_arbitrary_commands(self):
        for example in ("shipment", "research", "shipment-strands"):
            with self.subTest(example=example), mock.patch.object(runtime, "run_demo", return_value=(200, {"example": example})) as run:
                self.assertEqual(self.request({"operation": "run", "example": example}), (200, {"example": example}))
                run.assert_called_once_with(example)
        with mock.patch.object(runtime, "run_demo") as run:
            status, _ = self.request({"operation": "run", "example": "arbitrary-script"})
            self.assertEqual(status, 400)
            run.assert_not_called()

    def test_http_default_keeps_scripted_shipment_and_status_preserves_mode(self):
        with mock.patch.object(runtime, "run_demo", return_value=(200, {"status": "PASS"})) as run:
            self.assertEqual(self.request({"operation": "run"})[0], 200)
            run.assert_called_once_with("shipment")
        self.state.update(status="running", example="shipment-strands", mode="Strands SDK with live Bedrock responses")
        with mock.patch.object(runtime, "run_demo") as run:
            self.assertEqual(self.request({"operation": "status"}), (200, self.state))
            run.assert_not_called()


class RuntimeProcessCleanupTests(unittest.TestCase):
    def test_reparented_descendant_is_killed_but_reused_pid_is_preserved(self):
        process = mock.Mock(pid=100)
        initial = {100: (90, "1000"), 101: (100, "1010"), 102: (100, "1020"), 200: (90, "2000")}
        current = dict(initial)
        calls = []

        def killed(pid, sig):
            calls.append((pid, sig))
            if pid == 100 and sig == runtime.signal.SIGTERM:
                current.pop(100)
                current[101] = (1, "1010")
                current[102] = (1, "9999")

        with mock.patch.object(runtime.Path, "iterdir", return_value=[Path("/proc") / str(pid) for pid in initial]), \
                mock.patch.object(runtime, "process_identity", side_effect=lambda pid: current.get(pid)), \
                mock.patch.object(runtime.os, "kill", side_effect=killed), \
                mock.patch.object(runtime.time, "sleep"):
            runtime.stop_process_tree(process)
        self.assertIn((101, runtime.signal.SIGKILL), calls)
        self.assertNotIn((102, runtime.signal.SIGKILL), calls)
        self.assertFalse(any(pid == 200 for pid, _ in calls))
        process.wait.assert_called_once_with(timeout=5)


class RuntimePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "package"
        self.destination = self.directory / "application"
        self.destination.mkdir()
        self.files = {
            "box-core/box": (b"Box binary", 0o500),
            "box-core/strands-box-contain-trampoline": (b"Box helper", 0o500),
            "sdk/vendor/pydantic_core/_pydantic_core.cpython-312-aarch64-linux-gnu.so": (b"native extension", 0o500),
            "sdk/vendor/strands/__init__.py": (b"Python dependency", 0o400),
            "sdk/agent.py": (b"SDK client", 0o400),
            "sdk/outside-vendor.so": (b"Not a vendor dependency", 0o400),
            "run-demo.py": (b"Scripted shipment runner", 0o400),
            "research/run-demo.py": (b"Scripted research runner", 0o400),
            "policy.dw": (b"Shipment policy", 0o400),
        }
        for name, (data, _) in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.source / "deployment-manifest.json").write_text(json.dumps({
            "files": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in self.files.items()},
        }))

    def prepare(self):
        with mock.patch.object(runtime, "ROOT", self.source), \
                mock.patch.object(runtime.tempfile, "mkdtemp", return_value=str(self.destination)):
            return runtime.prepare_application()

    def test_preparation_keeps_native_execution_modes_and_scripted_file_modes(self):
        application = self.prepare()
        self.assertEqual(application, self.destination)
        for name, (data, mode) in self.files.items():
            with self.subTest(file=name):
                target = application / name
                self.assertEqual(target.read_bytes(), data)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)

    def test_operator_identity_assigns_application_and_home_to_runtime_user(self):
        application = self.prepare()
        home = self.directory / "operator-home"
        home.mkdir()
        expected_paths = {application, *application.rglob("*"), home}
        with mock.patch.object(runtime.tempfile, "mkdtemp", return_value=str(home)), \
                mock.patch.object(runtime.os, "getuid", side_effect=[0, 991]), \
                mock.patch.object(runtime.os, "chown") as chown, \
                mock.patch.object(runtime.os, "setgroups") as setgroups, \
                mock.patch.object(runtime.os, "setgid") as setgid, \
                mock.patch.object(runtime.os, "setuid") as setuid, \
                mock.patch.dict(runtime.os.environ, {}, clear=False):
            runtime.set_operator_identity(application)
            self.assertEqual(runtime.os.environ["HOME"], str(home))
        self.assertEqual(chown.call_count, len(expected_paths))
        chown.assert_has_calls([mock.call(path, 991, 991, follow_symlinks=False) for path in expected_paths],
                              any_order=True)
        setgroups.assert_called_once_with([])
        setgid.assert_called_once_with(991)
        setuid.assert_called_once_with(991)
        for name, (_, mode) in self.files.items():
            self.assertEqual(stat.S_IMODE((application / name).stat().st_mode), mode)


class StrandsInvocationTests(unittest.TestCase):
    def test_strands_invocation_uses_longer_client_timeout_and_saved_example(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            account = "123456789012"
            stack = "BoxShipmentDemoExample"
            arn = f"arn:aws:bedrock-agentcore:{REGION}:{account}:runtime/{stack}-Example123"
            (output / "deployment-receipt.json").write_text(json.dumps({"runtime_arn": arn}))
            args = SimpleNamespace(output_dir=output, account=account, region=REGION,
                                   stack_name=stack, example="shipment-strands")
            session = mock.Mock()
            client = session.client.return_value
            client.invoke_agent_runtime.return_value = {"response": io.BytesIO(b'{"status":"PASS"}')}
            with mock.patch.object(helper, "session_for", return_value=session), contextlib.redirect_stderr(io.StringIO()):
                receipt = helper.invoke(args)
            self.assertEqual(session.client.call_args.kwargs["config"].read_timeout, 300)
            request = client.invoke_agent_runtime.call_args.kwargs
            self.assertEqual(json.loads(request["payload"]), {"operation": "run", "example": "shipment-strands"})
            self.assertEqual(receipt["example"], "shipment-strands")
            self.assertEqual(receipt["result"]["status"], "PASS")
            self.assertTrue((output / "invocation-shipment-strands-receipt.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
