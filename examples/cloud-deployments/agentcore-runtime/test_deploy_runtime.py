"""Invocation receipt and session-stop checks. AWS clients are mocked or stubbed."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import boto3
from botocore.exceptions import ClientError, ReadTimeoutError
from botocore.response import StreamingBody
from botocore.stub import ANY, Stubber

SPEC = importlib.util.spec_from_file_location("deploy_runtime", Path(__file__).with_name("deploy-runtime.py"))
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
SESSION_FOR = helper.session_for
ACCOUNT = "123456789012"
REGION = "us-west-2"
STACK = "BoxShipmentDemoExample"
ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{STACK}-Example123"


class RuntimeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.args = SimpleNamespace(output_dir=self.output, account=ACCOUNT, region=REGION,
                                    profile="test", stack_name=STACK, example="shipment", receipt=None)
        (self.output / "deployment-receipt.json").write_text(json.dumps({"runtime_arn": ARN}))
        self.client = boto3.client("bedrock-agentcore", region_name=REGION,
                                   aws_access_key_id="testing", aws_secret_access_key="testing")
        self.addCleanup(self.client.close)
        self.stub = Stubber(self.client)
        self.stub.activate()
        self.addCleanup(self.stub.deactivate)
        self.addCleanup(self.stub.assert_no_pending_responses)
        self.session = mock.Mock()
        self.session.client.return_value = self.client
        patch = mock.patch.object(helper, "session_for", return_value=self.session)
        self.session_for = patch.start()
        self.addCleanup(patch.stop)
        self.stderr = io.StringIO()
        redirect = contextlib.redirect_stderr(self.stderr)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def queue_invocation(self, payload=b'{"status":"PASS"}'):
        stream = io.BytesIO(payload)
        response = {"response": StreamingBody(stream, len(payload)), "statusCode": 200, "contentType": "application/json"}
        self.stub.add_response("invoke_agent_runtime", response, {
            "agentRuntimeArn": ARN, "qualifier": "DEFAULT", "runtimeSessionId": ANY,
            "contentType": "application/json", "payload": b'{"operation": "run", "example": "shipment"}',
        })
        return stream

    def canonical(self):
        files = list((self.output / "invocations").glob("*.json"))
        self.assertEqual(len(files), 1)
        return files[0], json.loads(files[0].read_text())

    def successful_invocation(self):
        self.queue_invocation()
        receipt = helper.invoke(self.args)
        self.args.receipt = Path(receipt["receipt_path"])
        return receipt

    def stop_parameters(self, receipt):
        return {"agentRuntimeArn": ARN, "runtimeSessionId": receipt["runtime_session_id"],
                "qualifier": "DEFAULT", "clientToken": ANY}

    def timeout_invocation(self):
        def fail(**kwargs):
            path, pending = self.canonical()
            self.assertEqual(pending["invocation_status"], "pending")
            self.assertEqual(pending["runtime_session_id"], kwargs["runtimeSessionId"])
            self.assertIn(str(path), self.stderr.getvalue())
            raise ReadTimeoutError(endpoint_url="https://example.invalid")
        with mock.patch.object(self.client, "invoke_agent_runtime", side_effect=fail):
            with self.assertRaises(ReadTimeoutError):
                helper.invoke(self.args)
        path, receipt = self.canonical()
        self.args.receipt = path
        return receipt

    def test_timeout_keeps_receipt_written_before_request(self):
        receipt = self.timeout_invocation()
        self.assertEqual(receipt["invocation_status"], "error")
        self.assertEqual(receipt["error"]["type"], "ReadTimeoutError")
        self.assertNotIn("result", receipt)
        self.assertIn("Runtime invocation failed; receipt:", self.stderr.getvalue())
        latest = json.loads((self.output / "invocation-shipment-receipt.json").read_text())
        self.assertEqual(latest, receipt)

    def test_malformed_response_keeps_identifier_and_closes_stream(self):
        stream = self.queue_invocation(b"not JSON")
        with self.assertRaises(json.JSONDecodeError):
            helper.invoke(self.args)
        _, receipt = self.canonical()
        self.assertEqual(receipt["invocation_status"], "error")
        self.assertEqual(receipt["error"]["type"], "JSONDecodeError")
        self.assertTrue(stream.closed)
        self.assertTrue(receipt["runtime_session_id"])

    def test_success_keeps_compatible_result_and_canonical_path(self):
        stream = self.queue_invocation()
        receipt = helper.invoke(self.args)
        path, saved = self.canonical()
        self.assertEqual(saved, receipt)
        self.assertEqual(receipt["invocation_status"], "passed")
        self.assertEqual(receipt["result"]["status"], "PASS")
        self.assertEqual(receipt["receipt_path"], str(path))
        self.assertTrue(stream.closed)
        self.assertEqual(json.loads((self.output / "invocation-shipment-receipt.json").read_text()), receipt)

    def test_repeated_invocations_preserve_prior_records(self):
        first = self.successful_invocation()
        first_bytes = Path(first["receipt_path"]).read_bytes()
        second = self.successful_invocation()
        self.assertNotEqual(first["runtime_session_id"], second["runtime_session_id"])
        self.assertEqual(len(list((self.output / "invocations").glob("*.json"))), 2)
        self.assertEqual(Path(first["receipt_path"]).read_bytes(), first_bytes)
        latest = json.loads((self.output / "invocation-shipment-receipt.json").read_text())
        self.assertEqual(latest["runtime_session_id"], second["runtime_session_id"])

    def test_failed_workload_preserves_result_and_returns_failure(self):
        self.queue_invocation(b'{"status":"FAIL","checks":{"expected":false}}')
        with self.assertRaisesRegex(RuntimeError, "demonstration failed"):
            helper.invoke(self.args)
        _, receipt = self.canonical()
        self.assertEqual(receipt["invocation_status"], "failed")
        self.assertEqual(receipt["result"]["status"], "FAIL")
        self.assertEqual(receipt["result"]["checks"], {"expected": False})

    def test_stop_after_timeout_uses_exact_recorded_identifiers(self):
        receipt = self.timeout_invocation()
        self.stub.add_response("stop_runtime_session", {
            "statusCode": 200, "runtimeSessionId": receipt["runtime_session_id"],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }, self.stop_parameters(receipt))
        original = self.args.receipt.read_bytes()
        attempt = helper.stop(self.args)
        self.assertEqual(attempt["status"], "request_accepted")
        self.assertEqual(attempt["response"]["runtimeSessionId"], receipt["runtime_session_id"])
        stop_path = Path(attempt["receipt_path"])
        self.assertEqual(stop_path.parent, self.output / "stops" / receipt["runtime_session_id"])
        self.assertEqual(json.loads(stop_path.read_text()), attempt)
        self.assertEqual(self.args.receipt.read_bytes(), original)
        self.assertEqual(self.session.client.call_args.args, ("bedrock-agentcore",))

    def test_stop_failure_is_saved_in_separate_receipt(self):
        receipt = self.successful_invocation()
        self.stub.add_client_error("stop_runtime_session", service_error_code="AccessDeniedException",
                                   service_message="Stop permission missing", http_status_code=403,
                                   expected_params=self.stop_parameters(receipt))
        with self.assertRaises(ClientError):
            helper.stop(self.args)
        paths = list((self.output / "stops" / receipt["runtime_session_id"]).glob("*.json"))
        self.assertEqual(len(paths), 1)
        result = json.loads(paths[0].read_text())
        self.assertEqual(result["status"], "error")
        self.assertIn("AccessDeniedException", result["error"]["message"])
        self.assertEqual(json.loads(self.args.receipt.read_text()), receipt)

    def test_stop_during_active_invocation_preserves_both_results(self):
        saved_stop = {}

        def invoke_and_stop(**kwargs):
            path, pending = self.canonical()
            self.assertEqual(pending["invocation_status"], "pending")
            self.args.receipt = path
            attempt = helper.stop(self.args)
            stop_path = Path(attempt["receipt_path"])
            saved_stop.update(path=stop_path, content=stop_path.read_bytes())
            self.assertEqual(json.loads(path.read_text()), pending)
            payload = b'{"status":"PASS"}'
            return {"response": StreamingBody(io.BytesIO(payload), len(payload))}

        def stop_response(**kwargs):
            return {"statusCode": 200, "runtimeSessionId": kwargs["runtimeSessionId"]}

        with mock.patch.object(self.client, "invoke_agent_runtime", side_effect=invoke_and_stop), \
                mock.patch.object(self.client, "stop_runtime_session", side_effect=stop_response):
            result = helper.invoke(self.args)
        self.assertEqual(result["invocation_status"], "passed")
        self.assertEqual(json.loads(self.args.receipt.read_text()), result)
        self.assertEqual(saved_stop["path"].read_bytes(), saved_stop["content"])
        self.assertEqual(json.loads(saved_stop["content"])["status"], "request_accepted")

    def test_keyboard_interrupt_preserves_session_and_interrupted_status(self):
        with mock.patch.object(self.client, "invoke_agent_runtime", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                helper.invoke(self.args)
        path, receipt = self.canonical()
        self.assertEqual(receipt["invocation_status"], "interrupted")
        self.assertEqual(receipt["error"]["type"], "KeyboardInterrupt")
        self.assertEqual(receipt["receipt_path"], str(path))
        self.assertTrue(receipt["runtime_session_id"])
        self.assertIn("Runtime invocation interrupted; receipt:", self.stderr.getvalue())

    def test_keyboard_interrupt_during_stop_preserves_separate_receipt(self):
        receipt = self.successful_invocation()
        original = self.args.receipt.read_bytes()
        with mock.patch.object(self.client, "stop_runtime_session", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                helper.stop(self.args)
        paths = list((self.output / "stops" / receipt["runtime_session_id"]).glob("*.json"))
        self.assertEqual(len(paths), 1)
        attempt = json.loads(paths[0].read_text())
        self.assertEqual(attempt["status"], "interrupted")
        self.assertEqual(attempt["error"]["type"], "KeyboardInterrupt")
        self.assertEqual(self.args.receipt.read_bytes(), original)

    def test_stop_rejects_latest_alias(self):
        self.successful_invocation()
        self.args.receipt = self.output / "invocation-shipment-receipt.json"
        self.session_for.reset_mock()
        with self.assertRaisesRegex(ValueError, "exact invocations"):
            helper.stop(self.args)
        self.session_for.assert_not_called()

    def test_stop_rejects_other_account_region_or_stack(self):
        self.successful_invocation()
        for field, bad in (("account", "999999999999"), ("region", "us-east-1"),
                           ("stack_name", "BoxShipmentDemoOther")):
            with self.subTest(field=field):
                original = getattr(self.args, field)
                setattr(self.args, field, bad)
                self.session_for.reset_mock()
                with self.assertRaises(ValueError):
                    helper.stop(self.args)
                self.session_for.assert_not_called()
                setattr(self.args, field, original)

    def test_stop_rejects_invalid_session_or_different_deployed_runtime(self):
        receipt = self.successful_invocation()
        changed = dict(receipt, runtime_session_id="not-a-session")
        self.args.receipt.write_text(json.dumps(changed))
        self.session_for.reset_mock()
        with self.assertRaisesRegex(ValueError, "exact UUID"):
            helper.stop(self.args)
        self.session_for.assert_not_called()
        self.args.receipt.write_text(json.dumps(receipt))
        (self.output / "deployment-receipt.json").write_text(json.dumps({"runtime_arn": ARN + "Other"}))
        with self.assertRaisesRegex(ValueError, "Runtime in this deployment"):
            helper.stop(self.args)
        self.session_for.assert_not_called()

    def test_stop_rejects_authenticated_profile_in_other_account(self):
        self.successful_invocation()
        identity_session = mock.Mock()
        identity_session.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}
        with mock.patch.object(helper, "session_for", SESSION_FOR), \
                mock.patch.object(boto3, "Session", return_value=identity_session):
            with self.assertRaisesRegex(ValueError, "selected profile"):
                helper.stop(self.args)
        identity_session.client.assert_called_once_with("sts")
        self.assertNotIn("stop_attempts", json.loads(self.args.receipt.read_text()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
