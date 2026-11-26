"""Offline controls for the storage example; these do not qualify Box or AWS Runtime."""
import importlib.util
import errno
import os
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import types
import unittest
import urllib.request
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("storage_example_" + name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server, deploy = load("server"), load("deploy")


class ConfigurationTests(unittest.TestCase):
    def test_selection_has_whole_directory_grants_and_an_unrelated_deny(self):
        storage, scratch = Path("/mnt/storage"), Path("/var/tmp/example")
        text = server.box_config(storage, scratch, Path("/opt/workload"), "snapshot")
        filesystem = text.split("[agent.filesystem]\n")[1]
        values = {key.strip(): json.loads(value) for key, value in
                  (line.split("=", 1) for line in filesystem.splitlines())}
        self.assertEqual(values["receive_mounts"], [str(storage)])
        for permission in ["read", "write", "exec"]:
            self.assertIn(str(storage), values[permission])
        self.assertEqual(values["deny"], [str(scratch / "protected/denied")])
        self.assertNotIn("experimental-features", text)
        self.assertNotIn("linux-storage-mounts", text)

    def test_mount_records_retain_exact_root_and_propagation(self):
        text = "10 1 0:2 / / rw shared:1 - overlay overlay rw\n" \
               "12 10 0:3 / /mnt/data\\040set rw,nosuid shared:4 master:2 - tmpfs tmpfs rw\n"
        rows = server.mount_rows(text, Path("/mnt/data set"))
        self.assertEqual(rows[-1]["mountpoint"], "/mnt/data set")
        self.assertEqual(rows[-1]["propagation"], ["shared:4", "master:2"])
        self.assertEqual(rows[-1]["options"], ["rw", "nosuid"])

    def test_startup_refuses_plain_directory_alias_and_preexisting_provider(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            path = Path(directory)
            valid = {"dedicated_connected_mountpoint": True, "provider_mounted": False}
            server.require_initial_source(path, valid)
            with self.assertRaisesRegex(ValueError, "dedicated"):
                server.require_initial_source(path, dict(valid, dedicated_connected_mountpoint=False))
            with self.assertRaisesRegex(ValueError, "already mounted"):
                server.require_initial_source(path, dict(valid, provider_mounted=True))
            alias = path / "alias"
            alias.symlink_to(path, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "canonical"):
                server.require_initial_source(alias, valid)

    def test_failed_box_start_never_opens_the_http_listener(self):
        with patch.object(server, "Example", side_effect=RuntimeError("Box refused")), \
             patch.object(server, "ThreadingHTTPServer") as listener:
            with self.assertRaisesRegex(RuntimeError, "Box refused"):
                server.main()
            listener.assert_not_called()

    def test_missing_provider_is_unqualified_without_retry_or_workload_operation(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            example = server.Example.__new__(server.Example)
            example.storage = Path(directory)
            example.initial = {"runtime_source_before_box": {"mount_id": "12"}}
            example.command, example.outside = Mock(), Mock()
            observation = {"provider_mounted": False, "mount_id": "12"}
            with patch.object(server, "source_snapshot", return_value=observation) as snapshot:
                result = example.run()
            self.assertEqual(result["status"], "UNQUALIFIED")
            self.assertEqual(result["reason"], "A provider mount has not replaced the initial connected placeholder")
            self.assertEqual(result["runtime_source_now"], observation)
            self.assertEqual(list(example.storage.iterdir()), [])
            snapshot.assert_called_once()
            example.command.assert_not_called()
            example.outside.assert_not_called()

    def test_workload_response_must_keep_its_original_identity(self):
        example = server.Example.__new__(server.Example)
        original = {"pid": 7, "started_monotonic_ns": 10, "incarnation": "first"}
        example.initial = {"sandbox_before_listener": original}
        example.process = types.SimpleNamespace(stdin=Mock())
        for key, changed in [("pid", 8), ("started_monotonic_ns", 11), ("incarnation", "second")]:
            with self.subTest(changed_key=key):
                response = dict(original, request_id="request")
                response[key] = changed
                example.read_frame = Mock(return_value=response)
                with patch.object(server.uuid, "uuid4", return_value=types.SimpleNamespace(hex="request")):
                    with self.assertRaisesRegex(RuntimeError, "identity changed"):
                        example.command("READ", "/mnt/storage/marker")
        response = dict(original, request_id="request")
        example.read_frame = Mock(return_value=response)
        with patch.object(server.uuid, "uuid4", return_value=types.SimpleNamespace(hex="request")):
            self.assertEqual(example.command("READ", "/mnt/storage/marker"), response)

    def test_ping_accepts_small_writes_without_nagle_delay(self):
        observations = []
        class Handler(server.Handler):
            def setup(self):
                super().setup()
                observations.append(self.connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            def log_message(self, *args):
                pass
        listener = server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        listener.example = types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda: None))
        worker = threading.Thread(target=listener.serve_forever, daemon=True)
        worker.start()
        try:
            with urllib.request.urlopen("http://127.0.0.1:" + str(listener.server_port) + "/ping", timeout=3) as response:
                self.assertEqual(json.load(response)["status"], "Healthy")
            self.assertEqual(observations, [1])
        finally:
            listener.shutdown()
            listener.server_close()
            worker.join(timeout=3)


class DeploymentReceiptTests(unittest.TestCase):
    def payload(self, provider="sessionStorage", network="PUBLIC"):
        config = {"mountPath": "/mnt/storage"}
        if provider in {"efsAccessPoint", "s3FilesAccessPoint"}:
            config["accessPointArn"] = "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/fsap-example"
        if provider == "s3BucketMount":
            config.update(bucket="amzn-s3-demo-bucket", prefix="example/{runtimeSessionId}/")
        return {"platformVersion": "V2", "agentRuntimeName": "example", "roleArn": "borrowed-role",
                "agentRuntimeArtifact": {"containerConfiguration": {"containerUri": "borrowed-image"}},
                "networkConfiguration": {"networkMode": network},
                "filesystemConfigurations": [{provider: config}]}

    def test_access_points_require_vpc_but_bucket_mounts_do_not(self):
        for provider in ["efsAccessPoint", "s3FilesAccessPoint"]:
            with self.assertRaisesRegex(ValueError, "VPC"):
                deploy.validate_request(self.payload(provider))
            result = deploy.validate_request(self.payload(provider, "VPC"))
            self.assertEqual(result["environmentVariables"]["STORAGE_PATH"], "/mnt/storage")
        self.assertEqual(deploy.validate_request(self.payload("s3BucketMount"))["networkConfiguration"]["networkMode"], "PUBLIC")

    def test_unconfirmed_create_keeps_request_and_refuses_resource_actions(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            receipt = Path(directory) / "runtime.json"
            client = Mock()
            client.meta.service_model.service_id.hyphenize.return_value = "bedrock-agentcore-control"
            client.create_agent_runtime.side_effect = OSError("connection lost")
            with self.assertRaisesRegex(RuntimeError, "outcome may be unknown"):
                deploy.create_runtime(client, self.payload(), receipt, "us-west-2")
            saved = json.loads(receipt.read_text())
            self.assertEqual(saved["creation_status"], "PENDING")
            self.assertTrue(saved["request"]["clientToken"])
            with self.assertRaisesRegex(ValueError, "unconfirmed"):
                deploy.load_owned(receipt, "us-west-2")
            with self.assertRaises(FileExistsError):
                deploy.create_runtime(client, self.payload(), receipt, "us-west-2")
            self.assertEqual(client.create_agent_runtime.call_count, 1)

    def test_confirmed_receipt_identifies_borrowed_resources_and_region(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            receipt = Path(directory) / "runtime.json"
            client = Mock()
            client.meta.service_model.service_id.hyphenize.return_value = "bedrock-agentcore-control"
            client.create_agent_runtime.return_value = {"agentRuntimeId": "owned-runtime", "agentRuntimeArn": "owned-arn"}
            deploy.create_runtime(client, self.payload(), receipt, "us-west-2")
            saved = deploy.load_owned(receipt, "us-west-2")
            self.assertEqual(saved["borrowed_resources"]["roleArn"], "borrowed-role")
            self.assertEqual(saved["response"]["agentRuntimeId"], "owned-runtime")
            with self.assertRaisesRegex(ValueError, "Region"):
                deploy.load_owned(receipt, "us-east-1")


class WireRequestTests(unittest.TestCase):
    payload = DeploymentReceiptTests.payload

    def test_sdk_sends_and_signs_each_documented_provider_without_network(self):
        import boto3
        from botocore.awsrequest import AWSResponse
        from botocore.config import Config
        client = boto3.client("bedrock-agentcore-control", region_name="us-west-2",
                              aws_access_key_id="offline-test", aws_secret_access_key="offline-test",
                              config=Config(retries={"total_max_attempts": 1}))
        class ResponseBody:
            def stream(self, **_):
                yield b'{"agentRuntimeId":"owned-runtime","agentRuntimeArn":"owned-arn","status":"CREATING"}'
        response = AWSResponse("https://offline.invalid", 202, {"content-type": "application/json"}, ResponseBody())
        with patch.object(client._endpoint.http_session, "send", return_value=response) as send:
            for provider in ["sessionStorage", "efsAccessPoint", "s3FilesAccessPoint", "s3BucketMount"]:
                request = deploy.validate_request(self.payload(provider, "VPC"))
                request["roleArn"] = "arn:aws:iam::123456789012:role/ExampleRuntimeRole"
                request["clientToken"] = "offline-token-0000000000000000000000000000"
                self.assertEqual(deploy.send_create(client, request)["agentRuntimeId"], "owned-runtime")
                prepared = send.call_args.args[0]
                body = json.loads(prepared.body)
                for key in ["platformVersion", "architecture", "filesystemConfigurations", "clientToken"]:
                    self.assertEqual(body[key], request[key])
                self.assertIn("Authorization", prepared.headers)
                self.assertEqual(int(prepared.headers["Content-Length"]), len(prepared.body))
                self.assertEqual(prepared.method, "PUT")
                self.assertTrue(prepared.url.endswith("/runtimes/"))
            plain = {key: value for key, value in request.items()
                     if key not in {"platformVersion", "architecture", "filesystemConfigurations"}}
            client.create_agent_runtime(**plain)
            self.assertNotIn("platformVersion", json.loads(send.call_args.args[0].body))
            self.assertEqual(send.call_count, 5)

    def test_unsupported_fields_and_wrong_architecture_are_rejected(self):
        request = self.payload()
        request["filesystemConfigurations"][0]["sessionStorage"]["unexpected"] = "value"
        with self.assertRaisesRegex(ValueError, "Unexpected fields"):
            deploy.validate_request(request)
        request = self.payload()
        request["architecture"] = "X86_64"
        with self.assertRaisesRegex(ValueError, "ARM64"):
            deploy.validate_request(request)


class FrameTests(unittest.TestCase):
    def test_partial_frame_times_out_and_buffered_frames_remain_separate(self):
        read, write = os.pipe()
        example = server.Example.__new__(server.Example)
        example.output_buffer = b""
        with os.fdopen(read, "rb", buffering=0) as source, os.fdopen(write, "wb", buffering=0) as sink:
            example.process = types.SimpleNamespace(stdout=source)
            sink.write(b'{"first":')
            with self.assertRaises(TimeoutError):
                example.read_frame(timeout=0.02)
            sink.write(b'1}\n{"second":2}\n')
            self.assertEqual(example.read_frame(), {"first": 1})
            self.assertEqual(example.read_frame(), {"second": 2})


class NativeProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="runtime-storage-unit-", dir="/var/tmp")
        cls.binary = Path(cls.directory.name) / "workload"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "workload.c"), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def once(self, action, path, data=""):
        result = subprocess.run([str(self.binary), "--once", action, "id", str(path), data], check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    def test_real_create_read_duplicate_and_missing_file_controls(self):
        path = Path(self.directory.name) / "marker"
        self.assertEqual(self.once("CREATE", path, "marker-content")["rc"], 0)
        self.assertEqual(self.once("READ", path)["content"], "marker-content")
        self.assertEqual(self.once("CREATE", path, "replacement")["errno"], errno.EEXIST)
        self.assertEqual(self.once("READ", Path(self.directory.name) / "missing")["errno"], errno.ENOENT)
        self.assertEqual(path.read_text(), "marker-content")

    def test_executable_mapping_refuses_a_real_noexec_filesystem(self):
        root = Path("/dev/shm")
        try:
            flags = os.statvfs(root).f_flag
        except OSError as exc:
            self.skipTest("No writable noexec fixture filesystem: " + str(exc))
        if not flags & os.ST_NOEXEC:
            self.skipTest("/dev/shm is not mounted noexec; OS permission control not reached")
        try:
            directory = tempfile.TemporaryDirectory(prefix="runtime-storage-noexec-", dir=root)
        except OSError as exc:
            self.skipTest("Cannot create owned noexec fixture: " + str(exc))
        with directory:
            path = Path(directory.name) / "mapping.txt"
            self.assertEqual(self.once("CREATE", path, "harmless mapping bytes")["rc"], 0)
            self.assertEqual(self.once("READ", path)["content"], "harmless mapping bytes")
            result = self.once("EXEC_MAP", path)
            self.assertEqual(result["rc"], -1, result)
            self.assertIn(result["errno"], {errno.EACCES, errno.EPERM}, result)

    def test_executable_mapping_does_not_need_to_execute_the_program(self):
        self.assertEqual(self.once("EXEC_MAP", self.binary)["rc"], 0)


if __name__ == "__main__":
    unittest.main()
