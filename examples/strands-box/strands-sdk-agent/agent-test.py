#!/usr/bin/env python3
"""Check shell failure output without a model call."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

sdk = types.ModuleType("strands")
sdk.Agent = object
sdk.tool = lambda function: function
models = types.ModuleType("strands.models")
models.BedrockModel = object
spec = importlib.util.spec_from_file_location("example_agent", Path(__file__).with_name("agent.py"))
agent = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {"strands": sdk, "strands.models": models}):
    spec.loader.exec_module(agent)


class ShellOutputTests(unittest.TestCase):
    def test_a_failed_command_keeps_both_output_streams(self):
        for stdout, stderr in [("assertion failed\n", ""), ("test details\n", "compiler error\n")]:
            with self.subTest(stdout=stdout, stderr=stderr):
                result = subprocess.CompletedProcess(["zsh"], 1, stdout, stderr)
                with mock.patch.object(agent.subprocess, "run", return_value=result), contextlib.redirect_stderr(io.StringIO()):
                    output = agent.shell("run tests")
                self.assertIn("exit 1", output)
                self.assertIn(stdout, output)
                self.assertIn(stderr, output)

    def test_a_successful_command_keeps_its_output(self):
        result = subprocess.CompletedProcess(["zsh"], 0, "passed\n", "")
        with mock.patch.object(agent.subprocess, "run", return_value=result), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(agent.shell("run tests"), "passed\n")


if __name__ == "__main__":
    unittest.main()
