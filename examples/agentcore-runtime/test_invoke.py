#!/usr/bin/env python3
"""Check verifier output collection without AWS access."""
import argparse
import base64
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class VerifierTests(unittest.TestCase):
    invoke_path = Path(__file__).with_name("invoke.py")

    def setUp(self):
        spec = importlib.util.spec_from_file_location("review_invoke", self.invoke_path)
        self.invoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.invoke)
        self.temporary = tempfile.TemporaryDirectory(prefix="box-runtime-verifier-test-")
        self.addCleanup(self.temporary.cleanup)
        self.invoke.ROOT = Path(self.temporary.name)
        self.mode = "managed"
        self.reset = False
        self.output = b"x" * 150000
        self.poll_cursors = []
        self.starts = []
        self.args = SimpleNamespace(
            profile=None,
            arn="arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test",
            agent="claude",
        )
        self.events = SimpleNamespace(register=self.register_event)
        session = SimpleNamespace(client=self.client)
        session_patch = patch.object(self.invoke.boto3, "Session", return_value=session)
        sleep_patch = patch.object(self.invoke.time, "sleep")
        session_patch.start()
        sleep_patch.start()
        self.addCleanup(session_patch.stop)
        self.addCleanup(sleep_patch.stop)

    def register_event(self, event, callback):
        self.assertEqual(event, "after-call.bedrock-agentcore-control.GetAgentRuntime")
        self.after_call = callback

    def client(self, name, **kwargs):
        return {
            "sts": SimpleNamespace(
                get_caller_identity=lambda: {"Account": "123456789012"}
            ),
            "bedrock-agentcore-control": SimpleNamespace(
                meta=SimpleNamespace(events=self.events),
                get_agent_runtime=self.get_runtime,
                get_agent_runtime_endpoint=lambda **_: {
                    "status": "READY", "liveVersion": "1",
                },
            ),
            "bedrock-agentcore": SimpleNamespace(
                invoke_agent_runtime=self.invoke_runtime
            ),
        }[name]

    def get_runtime(self, **kwargs):
        target = {
            "platformVersion": "V2",
            "status": "READY",
            "agentRuntimeId": "test",
            "agentRuntimeVersion": "1",
            "environmentVariables": {"DEMO_MODE": self.mode},
            "agentRuntimeArtifact": {"codeConfiguration": {}},
        }
        self.after_call(SimpleNamespace(content=json.dumps(target).encode()))
        return target

    def invoke_runtime(self, **kwargs):
        payload = json.loads(kwargs["payload"])
        operation = payload["operation"]
        if operation == "start":
            self.starts.append(payload)
            response = {"status": "running"}
        elif operation == "poll":
            cursor = payload["cursor"]
            self.poll_cursors.append(cursor)
            end = min(len(self.output), cursor + 131072)
            response = {
                "status": "complete",
                "passed": True,
                "checks": {},
                "directory": "/var/tmp/claude-test",
                "output": base64.b64encode(self.output[cursor:end]).decode(),
                "cursor": end,
                "output_reset": self.reset,
            }
        elif operation == "audit":
            response = {"decisions": []}
        else:
            raise AssertionError(f"Unexpected operation: {operation}")
        return {"response": io.BytesIO(json.dumps(response).encode())}

    def test_completed_output_is_fully_collected(self):
        with redirect_stdout(io.StringIO()):
            result = self.invoke.verify(self.args)
        self.assertEqual(result, 0)
        terminal = next(self.invoke.ROOT.glob("results/*/terminal.log"))
        self.assertEqual(terminal.read_bytes(), self.output)
        self.assertEqual(self.poll_cursors, [0, 131072, 150000])

    def test_expired_output_history_fails(self):
        self.reset = True
        with self.assertRaisesRegex(RuntimeError, "evidence is incomplete"):
            self.invoke.verify(self.args)

    def test_unknown_deployment_mode_fails(self):
        self.mode = "unknown"
        with self.assertRaisesRegex(ValueError, "Unknown Runtime example mode"):
            self.invoke.verify(self.args)
        self.assertEqual(self.poll_cursors, [])

    def test_exercise_requires_native_attempts_even_when_server_reports_success(self):
        self.args.exercise = True
        with redirect_stdout(io.StringIO()):
            result = self.invoke.verify(self.args)
        self.assertEqual(result, 1)
        self.assertTrue(self.starts[0]["exercise"])
        self.assertIn("runtime_demo", self.starts[0]["task"])
        evidence = next(self.invoke.ROOT.glob("results/*/native-tool-checks.json"))
        self.assertFalse(any(json.loads(evidence.read_text()).values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--invoke-path", type=Path, default=VerifierTests.invoke_path,
        help="Verifier source path; defaults to invoke.py beside this test.",
    )
    args, remaining = parser.parse_known_args()
    VerifierTests.invoke_path = args.invoke_path
    unittest.main(argv=[__file__, *remaining])
