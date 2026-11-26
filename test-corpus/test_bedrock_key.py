"""Hermetic tests for bedrock_key.py. A stand-in for aws-bedrock-token-generator records each call, so
the tests run without the package and make no AWS call."""
import datetime
import io
import os
import re
import stat
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import bedrock_key

ENV = {"AWS_ACCESS_KEY_ID": "TESTID", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "t"}
REQUIREMENTS = Path(__file__).resolve().parent / "bedrock-key-requirements.txt"


def generator(calls, key="bedrock-api-key-c3RhbmQtaW4="):
    module = types.ModuleType("aws_bedrock_token_generator")

    def provide_token(region=None, aws_credentials_provider=None, expiry=None):
        calls.append({"region": region, "expiry": expiry, "env": dict(os.environ)})
        return key

    module.provide_token = provide_token
    return module


class Main(unittest.TestCase):
    def run_main(self, argv, env, calls):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.dict(sys.modules, {"aws_bedrock_token_generator": generator(calls)}), \
                redirect_stdout(buf):
            bedrock_key.main(argv)
        return buf.getvalue()

    def test_the_key_goes_to_a_private_file_and_only_a_mask_line_to_stdout(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "key"
            said = self.run_main(["--region", "us-west-2", "--expires", "7200", "--out", str(out)], ENV, calls)
            self.assertEqual(out.read_text(), "bedrock-api-key-c3RhbmQtaW4=\n")
            self.assertEqual(said, "::add-mask::bedrock-api-key-c3RhbmQtaW4=\n")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_the_generator_gets_the_region_and_expiry_and_the_session_credentials(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            self.run_main(["--region", "us-east-1", "--expires", "7200", "--out", str(Path(d) / "key")], ENV, calls)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["region"], "us-east-1")
        self.assertEqual(calls[0]["expiry"], datetime.timedelta(seconds=7200))
        self.assertEqual({k: calls[0]["env"][k] for k in ENV}, ENV)

    def test_no_credentials_exits_with_a_message_and_writes_no_key(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "key"
            with self.assertRaises(SystemExit) as e:
                self.run_main(["--region", "us-west-2", "--out", str(out)], {}, calls)
            self.assertIn("credentials are missing", str(e.exception))
            self.assertFalse(out.exists())
        self.assertEqual(calls, [])

    def test_a_missing_region_or_a_bad_expiry_is_refused_before_the_generator_runs(self):
        for argv in (["--region", ""], ["--region", "us-west-2", "--expires", "0"],
                     ["--region", "us-west-2", "--expires", "43201"]):
            calls = []
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(SystemExit):
                    self.run_main(argv + ["--out", str(Path(d) / "key")], ENV, calls)
                self.assertEqual(calls, [])


class Requirements(unittest.TestCase):
    def test_every_package_is_pinned_to_one_version_and_a_hash(self):
        lines = [l for l in REQUIREMENTS.read_text().splitlines() if l.strip() and not l.startswith("#")]
        names = set()
        for line in lines:
            with self.subTest(line=line):
                self.assertRegex(line, r"^[a-z0-9-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}$")
                names.add(line.split("==")[0])
        self.assertIn("aws-bedrock-token-generator", names)
        self.assertIn("botocore", names)


if __name__ == "__main__":
    unittest.main()
