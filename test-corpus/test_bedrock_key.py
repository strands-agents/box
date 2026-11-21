"""Hermetic tests for bedrock_key.py. The two expected keys were made by aws-bedrock-token-generator 1.1.0
(botocore 1.44.2) at the same fixed time, with the same fake inputs."""
import base64
import datetime
import io
import os
import stat
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import bedrock_key

AT = datetime.datetime(2026, 11, 14, 1, 2, 3, tzinfo=datetime.timezone.utc)

# Not real keys. Each signs for a made-up access key id (TESTID, OTHERID) that isn't an AWS access key,
# with a made-up secret, so Bedrock refuses them. Both also expired on 2026-11-14 (X-Amz-Date is AT).
WITH_SESSION = (
    "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbiZYLUFtei1BbGdvcml0aG09"
    "QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPVRFU1RJRCUyRjIwMjYxMTE0JTJGdXMtd2VzdC0yJTJGYmVkcm9jayUyRmF3"
    "czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjYxMTE0VDAxMDIwM1omWC1BbXotRXhwaXJlcz03MjAwJlgtQW16LVNpZ25lZEhlYWRlcnM9"
    "aG9zdCZYLUFtei1TZWN1cml0eS1Ub2tlbj10ZXN0LXNlc3Npb24lMkZ0b2tlbiUyQnglM0QlM0QmWC1BbXotU2lnbmF0dXJlPWFiN2Zk"
    "ODc5ZjJkODE5ODIyMmIwYzMzM2IzNTRiZmI3MTAyZWQ2NWRkN2ViODZkZTI3ZGYzNDQ5YWMxNWFkODQmVmVyc2lvbj0x")
WITHOUT_SESSION = (
    "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbiZYLUFtei1BbGdvcml0aG09"
    "QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPU9USEVSSUQlMkYyMDI2MTExNCUyRnVzLWVhc3QtMSUyRmJlZHJvY2slMkZh"
    "d3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI2MTExNFQwMTAyMDNaJlgtQW16LUV4cGlyZXM9NDMyMDAmWC1BbXotU2lnbmVkSGVhZGVy"
    "cz1ob3N0JlgtQW16LVNpZ25hdHVyZT0wYjUxZDFmY2VkOGMwOTIxNWRkY2Q2MTc0YTMwOGViNTdmYWUzMTI5NTI1YjU1YTQ4NjA4Mjg3"
    "MjMzYTVkZjAwJlZlcnNpb249MQ==")


def query(key):
    url = base64.b64decode(key[len(bedrock_key.PREFIX):]).decode()
    return urllib.parse.parse_qs(urllib.parse.urlsplit("https://" + url).query)


class Mint(unittest.TestCase):
    def test_a_session_key_matches_the_official_generator(self):
        got = bedrock_key.mint("TESTID", "test/secret+value=", "test-session/token+x==", "us-west-2", 7200, AT)
        self.assertEqual(got, WITH_SESSION)

    def test_a_key_without_a_session_token_matches_the_official_generator(self):
        self.assertEqual(bedrock_key.mint("OTHERID", "other-secret", "", "us-east-1", 43200, AT), WITHOUT_SESSION)

    def test_the_key_names_its_region_expiry_and_action(self):
        q = query(bedrock_key.mint("TESTID", "s", "t", "us-west-2", 7200, AT))
        self.assertEqual(q["Action"], ["CallWithBearerToken"])
        self.assertEqual(q["X-Amz-Expires"], ["7200"])
        self.assertEqual(q["X-Amz-Date"], ["20261114T010203Z"])
        self.assertEqual(q["X-Amz-Credential"], ["TESTID/20261114/us-west-2/bedrock/aws4_request"])
        self.assertEqual(q["Version"], ["1"])

    def test_missing_credentials_a_region_or_a_bad_expiry_are_refused(self):
        for args in [("", "s", "", "us-west-2", 60), ("a", "", "", "us-west-2", 60), ("a", "s", "", "", 60),
                     ("a", "s", "", "us-west-2", 0), ("a", "s", "", "us-west-2", 43201)]:
            with self.assertRaises(ValueError, msg=args):
                bedrock_key.mint(*args, AT)


class Main(unittest.TestCase):
    def test_the_key_goes_to_a_private_file_and_only_a_mask_line_to_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "key"
            env = {"AWS_ACCESS_KEY_ID": "TESTID", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "t"}
            buf = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(buf):
                bedrock_key.main(["--region", "us-west-2", "--expires", "7200", "--out", str(out)])
            key = out.read_text().strip()
            self.assertTrue(key.startswith(bedrock_key.PREFIX))
            self.assertEqual(buf.getvalue(), "::add-mask::%s\n" % key)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_no_credentials_exits_with_a_message_and_writes_no_key(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "key"
            with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit) as e:
                bedrock_key.main(["--region", "us-west-2", "--out", str(out)])
            self.assertIn("credentials are missing", str(e.exception))
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
