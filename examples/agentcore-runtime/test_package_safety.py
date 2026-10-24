"""Check package integrity and archive boundaries without cloud access."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare as package_prepare

DEMO = Path(__file__).resolve().parent / "app" / "demo"
sys.path.insert(0, str(DEMO))


class PackageSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.app = self.root / "app" / "demo"
        self.app.mkdir(parents=True)
        (self.root / "agentcore").mkdir()
        self.binary = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\xb7\x00"
        self.archive = self.root / "bundle.tar.gz"
        self.write_archive()
        self.claude = self.root / "claude-input.tar.gz"
        self.claude.write_bytes(b"synthetic locally supplied package")
        integrity = "sha512-" + base64.b64encode(
            hashlib.sha512(self.claude.read_bytes()).digest()
        ).decode()
        (self.app / "claude-package.json").write_text(json.dumps({
            "integrity": integrity, "url": "https://invalid.example/unused",
        }))
        self.args = SimpleNamespace(
            account="000000000000", box_revision="a" * 40,
            box_package=self.archive, box_sha256=self.digest(),
            claude_package=self.claude,
        )
        for name, value in (("ROOT", self.root), ("APP", self.app)):
            patcher = patch.object(package_prepare, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        network = patch.object(
            package_prepare.urllib.request, "urlopen",
            side_effect=AssertionError("The package tests must stay offline"),
        )
        network.start()
        self.addCleanup(network.stop)

    def digest(self):
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def write_archive(self, name="box", symlink=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "elsewhere"
                archive.addfile(member)
            else:
                member.size = len(self.binary)
                archive.addfile(member, io.BytesIO(self.binary))

    def test_prepare_accepts_valid_local_inputs(self):
        package_prepare.prepare(self.args)
        manifest = json.loads((self.app / "box-package.json").read_text())
        self.assertEqual(manifest["sha256"], self.digest())
        self.assertEqual(manifest["binary_sha256"], hashlib.sha256(self.binary).hexdigest())
        self.assertEqual((self.app / "box.tar.gz").read_bytes(), self.archive.read_bytes())

    def test_prepare_refuses_box_digest_mismatch(self):
        self.args.box_sha256 = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
            package_prepare.prepare(self.args)
        self.assertFalse((self.app / "box.tar.gz").exists())

    def test_prepare_refuses_wrong_architecture(self):
        self.binary = self.binary[:18] + b"\x3e\x00"
        self.write_archive()
        self.args.box_sha256 = self.digest()
        with self.assertRaisesRegex(ValueError, "Linux ARM64"):
            package_prepare.prepare(self.args)

    def test_prepare_refuses_traversal_and_links(self):
        for name, symlink in (("../box", False), ("box", True)):
            with self.subTest(name=name, symlink=symlink):
                self.write_archive(name, symlink)
                self.args.box_sha256 = self.digest()
                with self.assertRaisesRegex(ValueError, "unsupported entry"):
                    package_prepare.prepare(self.args)
        self.assertFalse((self.root / "box").exists())

    def test_prepare_refuses_claude_digest_mismatch(self):
        self.claude.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "integrity does not match"):
            package_prepare.prepare(self.args)
        self.assertFalse((self.app / "box.tar.gz").exists())

    def runtime(self, binary_digest=None, archive_digest=None):
        (self.app / "box.tar.gz").write_bytes(self.archive.read_bytes())
        manifest = {
            "revision": self.args.box_revision,
            "sha256": archive_digest or self.digest(),
            "binary_sha256": binary_digest or hashlib.sha256(self.binary).hexdigest(),
        }
        original_read = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == DEMO / "box-package.json":
                return json.dumps(manifest)
            return original_read(path, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("runtime_package_test", DEMO / "main.py")
        runtime = importlib.util.module_from_spec(spec)
        with patch.object(Path, "read_text", read_text):
            spec.loader.exec_module(runtime)
        runtime.HERE = self.app
        output = self.root / "installed"
        output.mkdir()
        patcher = patch.object(runtime.tempfile, "mkdtemp", return_value=str(output))
        patcher.start()
        self.addCleanup(patcher.stop)
        return runtime

    def test_runtime_install_accepts_verified_binary(self):
        self.assertEqual(self.runtime().install().read_bytes(), self.binary)

    def test_runtime_install_refuses_archive_digest_mismatch(self):
        with self.assertRaisesRegex(RuntimeError, "package digest mismatch"):
            self.runtime(archive_digest="0" * 64).install()

    def test_runtime_install_refuses_binary_digest_mismatch(self):
        with self.assertRaisesRegex(RuntimeError, "binary digest mismatch"):
            self.runtime(binary_digest="0" * 64).install()

    def test_runtime_install_refuses_traversal(self):
        self.write_archive("../box")
        with self.assertRaisesRegex(ValueError, "escapes destination"):
            self.runtime().install()
        self.assertFalse((self.root / "box").exists())

    def test_runtime_install_refuses_links(self):
        self.write_archive(symlink=True)
        with self.assertRaisesRegex(ValueError, "Unsupported archive entry"):
            self.runtime().install()


if __name__ == "__main__":
    unittest.main()
