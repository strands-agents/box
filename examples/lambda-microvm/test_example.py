"""Test package refusals, result validation, and complete terminal collection."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import demo
from client import Client, NoRedirect
from prepare import box_identity


class ExampleTests(unittest.TestCase):
    def bundle(self, root, name="box", data=None, link=False):
        path = root / "box.tar.gz"
        data = data or b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\x00" + bytes(44)
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            member.size = len(data)
            if link:
                member.type, member.linkname, member.size = tarfile.SYMTYPE, "/etc/passwd", 0
            archive.addfile(member, io.BytesIO(data) if not link else None)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_bundle_requires_digest_architecture_and_root_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, digest = self.bundle(root)
            self.assertEqual(box_identity(path, digest, "a" * 40)["sha256"], digest)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                box_identity(path, "0" * 64, "a" * 40)
            path, digest = self.bundle(root, data=b"not an ARM64 executable")
            with self.assertRaisesRegex(ValueError, "ARM64"):
                box_identity(path, digest, "a" * 40)
            path, digest = self.bundle(root, name="nested/box")
            with self.assertRaisesRegex(ValueError, "at its root"):
                box_identity(path, digest, "a" * 40)

    def test_bundle_refuses_links_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for options in ({"name": "../box"}, {"name": "/box"}, {"link": True}):
                path, digest = self.bundle(root, **options)
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    box_identity(path, digest, "a" * 40)

    def test_complete_status_still_drains_terminal_pages(self):
        chunks = [b"first page", b"last page", b""]
        requests = []
        def call(path, payload):
            requests.append(payload["cursor"])
            chunk = chunks.pop(0)
            return {"status": "complete", "output": base64.b64encode(chunk).decode(),
                    "cursor": payload["cursor"] + len(chunk)}
        with tempfile.TemporaryDirectory() as directory, patch("demo.time.sleep"):
            demo.collect(call, "/claude/test", Path(directory), claude=True)
            self.assertEqual((Path(directory) / "terminal.log").read_bytes(), b"first pagelast page")
            self.assertEqual(requests, [0, 10, 19])

    def test_history_reset_and_false_checks_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "expired"):
                demo.collect(lambda *args: {"output_reset": True}, "/", Path(directory), claude=True)
        for value in ({}, {"passed": True, "checks": {}},
                      {"passed": True, "checks": {"repair": False}},
                      {"passed": True, "checks": {"repair": 1}}):
            with self.assertRaises(RuntimeError):
                demo.require_pass(value)
        demo.require_pass({"passed": True, "checks": {"repair": True}})

    def test_redirect_and_oversized_request_refused(self):
        with self.assertRaisesRegex(ValueError, "redirect"):
            NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.com")
        client = Client.__new__(Client)
        with self.assertRaisesRegex(ValueError, "16384"):
            client.request("/claude/test", {"task": "\u2603" * 4000})

    def test_exact_request_size_boundary(self):
        client = Client.__new__(Client)
        client.expires = float("inf")
        client.headers = {}
        client.instance = {"endpoint": "https://example.com"}
        client.opener = Mock()
        client.opener.open.return_value = io.BytesIO(b"{}")
        body = {"task": "x" * (16384 - len(json.dumps({"task": ""}).encode()))}
        self.assertEqual(client.request("/claude/test", body), {})
        request = client.opener.open.call_args.args[0]
        self.assertEqual(len(request.data), 16384)
        with self.assertRaisesRegex(ValueError, "16384"):
            client.request("/claude/test", {"task": body["task"] + "x"})

    def test_source_and_profile_mismatches_refused(self):
        client = Client.__new__(Client)
        client.target = {"fingerprint": "expected", "package": {"binary_sha256": "box"}}
        info = {
            "manifest": {"fingerprint": "expected"}, "package": {"binary_sha256": "box"},
            "box_sha256": "box", "architecture": "aarch64", "uid": 0,
        }
        client.request = lambda path: info
        self.assertEqual(client.ready(), info)
        for field, wrong in (
            ("manifest", {"fingerprint": "wrong"}), ("package", {"binary_sha256": "other"}),
            ("box_sha256", "other"), ("architecture", "x86_64"), ("uid", 991),
        ):
            changed = copy.deepcopy(info)
            changed[field] = wrong
            client.request = lambda path: changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "recorded source"):
                client.ready()


if __name__ == "__main__":
    unittest.main()
