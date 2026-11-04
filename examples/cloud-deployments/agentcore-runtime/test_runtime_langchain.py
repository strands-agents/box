"""Offline contracts for the isolated LangChain Runtime package variant."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

import test_runtime_strands as baseline

helper = baseline.helper
runtime = baseline.runtime
MODEL = baseline.MODEL
REGION = baseline.REGION


class LangChainPackageTests(unittest.TestCase):
    write = baseline.StrandsPackageTests.write
    write_manifest = baseline.StrandsPackageTests.write_manifest

    def setUp(self):
        baseline.StrandsPackageTests.setUp(self)
        for name in ("agent.py", "run-demo.py", "requirements.txt", "dependency-lock.txt"):
            self.write("langchain-example/" + name, b"offline LangChain fixture\n")
        self.dependencies = {
            "langchain-example/vendor/langchain_core/__init__.py": b"offline module\n",
            "langchain-example/vendor/pydantic_core/_pydantic_core.cpython-312-aarch64-linux-gnu.so": b"offline native library\n",
            "langchain-example/vendor/numpy.libs/libgfortran.so.5.0.0": b"offline versioned native library\n",
        }
        for name, data in self.dependencies.items():
            self.write(name, data)
        self.write("langchain-example/vendor/unlisted.py", b"must not be packaged\n")
        self.langchain_manifest = {"python_minor": "3.12", "architecture": "aarch64", "platform": "Linux",
                                   "files": {name: hashlib.sha256(data).hexdigest()
                                             for name, data in self.dependencies.items()}}
        self.save_langchain_manifest()

    def save_langchain_manifest(self):
        self.write("langchain-example/dependency-manifest.json", json.dumps(self.langchain_manifest).encode())

    def package(self):
        return helper.package(self.directory / "output", with_langchain=True)

    def test_package_is_explicit_hashed_and_excludes_other_framework_and_unlisted_files(self):
        receipt = self.package()
        manifest = receipt["manifest"]
        self.assertEqual(manifest["example"], "shipment-langchain")
        self.assertTrue(manifest["with_langchain"])
        self.assertFalse(manifest["with_strands"])
        self.assertIn("LangChain", manifest["mode"])
        with zipfile.ZipFile(receipt["archive"]) as archive:
            self.assertFalse(any(name.startswith("sdk/") for name in archive.namelist()))
            self.assertNotIn("langchain-example/vendor/unlisted.py", archive.namelist())
            self.assertEqual(set(archive.namelist()), set(manifest["files"]) | {"deployment-manifest.json"})
            for name, expected in manifest["files"].items():
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected)
            for name in self.dependencies:
                expected_mode = 0o644 if name.endswith(".py") else 0o755
                self.assertEqual(stat.S_IMODE(archive.getinfo(name).external_attr >> 16), expected_mode)
            for name in ("requirements.txt", "dependency-lock.txt", "dependency-manifest.json"):
                self.assertIn("langchain-example/" + name, manifest["files"])
            self.assertIn("run-demo.py", manifest["files"])
            self.assertIn("research/run-demo.py", manifest["files"])

    def test_model_route_and_permissions_match_supported_strands_route(self):
        template = helper.template(with_langchain=True)
        old = helper.template(with_strands=True)
        policies = template["Resources"]["ExecutionRole"]["Properties"]["Policies"]
        self.assertEqual(policies[-1]["PolicyName"], "ShipmentLangChainModel")
        self.assertEqual(baseline.policy_statements(template), baseline.policy_statements(old))
        properties = template["Resources"]["ShipmentRuntime"]["Properties"]
        self.assertEqual(properties["EnvironmentVariables"], {
            "BOX_DEMO_MODEL_ID": MODEL, "BOX_DEMO_REGION": {"Ref": "AWS::Region"},
        })
        self.assertEqual(properties["AgentRuntimeArtifact"]["CodeConfiguration"]["Runtime"], "PYTHON_3_12")
        self.assertIn("LangChain", properties["Description"])

    def test_incompatible_python_architecture_or_platform_is_rejected(self):
        for field, incompatible in (("python_minor", "3.11"), ("architecture", "x86_64"), ("platform", "Darwin")):
            with self.subTest(field=field):
                original = self.langchain_manifest[field]
                self.langchain_manifest[field] = incompatible
                self.save_langchain_manifest()
                with self.assertRaisesRegex(ValueError, "Python 3.12 on Linux ARM64"):
                    self.package()
                self.assertFalse((self.directory / "output/runtime.zip").exists())
                self.langchain_manifest[field] = original

    def test_manifest_cannot_select_another_framework_or_escape_vendor(self):
        for name in ("sdk/vendor/strands/__init__.py", "langchain-example/agent.py",
                     "langchain-example/vendor/../../fixture.py", "/tmp/dependency.py"):
            with self.subTest(path=name):
                self.langchain_manifest["files"] = {name: "0" * 64}
                self.save_langchain_manifest()
                with self.assertRaisesRegex(ValueError, "dependency path"):
                    self.package()
                self.assertFalse((self.directory / "output/runtime.zip").exists())

    def test_changed_or_missing_dependency_does_not_create_an_archive(self):
        name = next(iter(self.dependencies))
        path = self.source / name
        self.write(name, b"changed dependency")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.package()
        path.rename(path.with_suffix(".missing"))
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.package()
        self.assertFalse((self.directory / "output/runtime.zip").exists())

    def test_manifest_rejects_symbolic_link_files_and_parent_directories(self):
        outside = self.source / "outside"
        outside.mkdir()
        data = b"dependency through symbolic link"
        (outside / "module.py").write_bytes(data)
        for leaf in (False, True):
            with self.subTest(leaf=leaf):
                relative = "langchain-example/vendor/" + ("linked.py" if leaf else "linked-directory/module.py")
                link = self.source / relative if leaf else self.source / "langchain-example/vendor/linked-directory"
                link.symlink_to(outside / "module.py" if leaf else outside, target_is_directory=not leaf)
                self.langchain_manifest["files"] = {relative: hashlib.sha256(data).hexdigest()}
                self.save_langchain_manifest()
                with self.assertRaisesRegex(ValueError, "dependency path: symbolic link"):
                    self.package()
        self.assertFalse((self.directory / "output/runtime.zip").exists())

    def test_mutually_exclusive_variants_fail_before_output_creation(self):
        with self.assertRaisesRegex(ValueError, "one live framework"):
            helper.package(self.directory / "uncreated", with_strands=True, with_langchain=True)
        self.assertFalse((self.directory / "uncreated").exists())
        with self.assertRaisesRegex(ValueError, "one live framework"):
            helper.template(with_strands=True, with_langchain=True)
        with mock.patch.object(sys, "argv", ["deploy-runtime.py", "package", "--with-strands", "--with-langchain"]), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            helper.main()
        self.assertEqual(error.exception.code, 2)

    def test_cli_selects_langchain_and_deterministic_package(self):
        first = self.package()
        second = helper.package(self.directory / "second", with_langchain=True)
        self.assertEqual(first["sha256"], second["sha256"])
        with mock.patch.object(sys, "argv", ["deploy-runtime.py", "package", "--with-langchain"]), \
                mock.patch.object(helper, "package", return_value=first) as package, \
                contextlib.redirect_stdout(io.StringIO()):
            helper.main()
        self.assertEqual(package.call_args.kwargs, {"with_strands": False, "with_langchain": True})


class LangChainRuntimeTests(unittest.TestCase):
    completed_process = baseline.StrandsRuntimeTests.completed_process
    request = baseline.StrandsRuntimeTests.request

    def setUp(self):
        baseline.StrandsRuntimeTests.setUp(self)
        (self.application / "langchain-example").mkdir()
        (self.application / "langchain-example/run-demo.py").write_text("offline LangChain runner")

    def test_fixed_runner_receives_selected_model_with_bounded_execution(self):
        with mock.patch.object(runtime.subprocess, "Popen", side_effect=self.completed_process) as popen:
            status, body = runtime.run_demo("shipment-langchain")
        self.assertEqual((status, body["status"]), (200, "PASS"))
        self.assertEqual(body["example"], "shipment-langchain")
        self.assertIn("LangChain with live Bedrock responses", body["mode"])
        command = popen.call_args.args[0]
        self.assertEqual(command, [sys.executable, str(self.application / "langchain-example/run-demo.py"),
                                  "--output-dir", str(self.output), "--box-binary", str(self.application / "box-core/box"),
                                  "--model", MODEL, "--region", REGION])
        self.assertEqual(popen.call_args.kwargs["env"]["EXPERIMENTAL_LINUX_SUPPORT"], "TRUE")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.process.wait.assert_called_once_with(timeout=240)
        self.assertEqual(self.state["status"], "complete")
        self.assertEqual(self.state["mode"], body["mode"])
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_missing_langchain_runner_does_not_fall_back_to_strands(self):
        path = self.application / "langchain-example/run-demo.py"
        path.rename(path.with_suffix(".disabled"))
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            status, body = runtime.run_demo("shipment-langchain")
        self.assertEqual(status, 400)
        self.assertIn("--with-langchain", body["error"])
        popen.assert_not_called()
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_missing_model_or_region_prevents_process_start(self):
        for name in ("BOX_DEMO_MODEL_ID", "BOX_DEMO_REGION"):
            with self.subTest(setting=name), mock.patch.dict(runtime.os.environ, {name: ""}), \
                    mock.patch.object(runtime.subprocess, "Popen") as popen:
                status, _ = runtime.run_demo("shipment-langchain")
                self.assertEqual(status, 400)
                popen.assert_not_called()

    def test_timeout_stops_process_tree_releases_lock_and_reports_failure(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired(cmd="offline", timeout=240)
        with mock.patch.object(runtime.subprocess, "Popen", return_value=self.process), \
                mock.patch.object(runtime, "stop_process_tree") as stop:
            status, body = runtime.run_demo("shipment-langchain")
        self.assertEqual((status, body["status"]), (500, "FAIL"))
        self.assertIn("exceeded 240 seconds", body["error"])
        self.assertIn("LangChain", body["mode"])
        stop.assert_called_once_with(self.process)
        self.assertEqual(self.state["status"], "error")
        self.assertFalse(runtime.RUN_LOCK.locked())

    def test_nonzero_runner_exit_cannot_pass_even_with_pass_result(self):
        self.process.returncode = 1
        with mock.patch.object(runtime.subprocess, "Popen", side_effect=self.completed_process):
            status, body = runtime.run_demo("shipment-langchain")
        self.assertEqual((status, body["status"]), (200, "FAIL"))
        self.assertEqual(self.state["result_status"], "FAIL")

    def test_http_allows_only_the_fixed_langchain_payload(self):
        payload = {"operation": "run", "example": "shipment-langchain"}
        with mock.patch.object(runtime, "run_demo", return_value=(200, {"status": "PASS"})) as run:
            self.assertEqual(self.request(payload)[0], 200)
            run.assert_called_once_with("shipment-langchain")
        for field in ("command", "model", "region"):
            with self.subTest(field=field), mock.patch.object(runtime, "run_demo") as run:
                self.assertEqual(self.request(dict(payload, **{field: "untrusted input"}))[0], 400)
                run.assert_not_called()

    def test_busy_runtime_does_not_start_another_runner(self):
        runtime.RUN_LOCK.acquire()
        self.addCleanup(runtime.RUN_LOCK.release)
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            self.assertEqual(runtime.run_demo("shipment-langchain")[0], 409)
        popen.assert_not_called()


class LangChainPreparationTests(unittest.TestCase):
    prepare = baseline.RuntimePreparationTests.prepare

    def test_native_mode_is_limited_to_the_framework_vendor_directory(self):
        baseline.RuntimePreparationTests.setUp(self)
        additions = {
            "langchain-example/vendor/pydantic_core/native.so": (b"native dependency", 0o500),
            "langchain-example/vendor/numpy.libs/libgfortran.so.5.0.0": (b"versioned native dependency", 0o500),
            "sdk/vendor/versioned.so.5.0.0": (b"unchanged SDK versioned library mode", 0o400),
            "langchain-example/outside-vendor.so.5.0.0": (b"outside vendor versioned library", 0o400),
            "langchain-example/vendor/langchain_core/__init__.py": (b"Python dependency", 0o400),
            "langchain-example/agent.py": (b"LangChain client", 0o400),
            "langchain-example/outside-vendor.so": (b"outside vendor", 0o400),
        }
        self.files.update(additions)
        for name, (data, _) in additions.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.source / "deployment-manifest.json").write_text(json.dumps({
            "files": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in self.files.items()},
        }))
        application = self.prepare()
        for name, (data, mode) in self.files.items():
            self.assertEqual((application / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((application / name).stat().st_mode), mode)


class LangChainInvocationTests(unittest.TestCase):
    def test_client_timeout_and_receipts_preserve_the_langchain_example_on_success_or_error(self):
        for outcome in ("success", "timeout"):
            with self.subTest(outcome=outcome), baseline.tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                account = "123456789012"
                stack = "BoxShipmentDemoLangChain"
                arn = f"arn:aws:bedrock-agentcore:{REGION}:{account}:runtime/{stack}-Example123"
                (output / "deployment-receipt.json").write_text(json.dumps({"runtime_arn": arn}))
                args = SimpleNamespace(output_dir=output, account=account, region=REGION,
                                       stack_name=stack, example="shipment-langchain")
                session = mock.Mock()
                client = session.client.return_value
                if outcome == "success":
                    client.invoke_agent_runtime.return_value = {"response": io.BytesIO(b'{"status":"PASS"}')}
                else:
                    client.invoke_agent_runtime.side_effect = TimeoutError("offline transport timeout")
                with mock.patch.object(helper, "session_for", return_value=session), contextlib.redirect_stderr(io.StringIO()):
                    if outcome == "success":
                        helper.invoke(args)
                    else:
                        with self.assertRaises(TimeoutError):
                            helper.invoke(args)
                self.assertEqual(session.client.call_args.kwargs["config"].read_timeout, 300)
                request = client.invoke_agent_runtime.call_args.kwargs
                self.assertEqual(json.loads(request["payload"]), {"operation": "run", "example": "shipment-langchain"})
                latest = json.loads((output / "invocation-shipment-langchain-receipt.json").read_text())
                canonical = json.loads(Path(latest["receipt_path"]).read_text())
                self.assertEqual(latest, canonical)
                self.assertEqual(latest["runtime_session_id"], request["runtimeSessionId"])
                self.assertEqual(latest["runtime_arn"], arn)
                self.assertEqual(latest["example"], "shipment-langchain")
                self.assertEqual(latest["invocation_status"], "passed" if outcome == "success" else "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
