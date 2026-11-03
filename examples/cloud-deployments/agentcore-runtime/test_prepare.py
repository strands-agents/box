"""Check binary preparation and dependency targeting without a Rust build."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("prepare_example", Path(__file__).with_name("prepare.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "research").mkdir()
        self.source = self.root / "release"
        self.source.mkdir()
        self.elf = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\xb7\x00" + b"test executable"
        for name in prepare.BINARIES:
            (self.source / name).write_bytes(self.elf)
        patcher = mock.patch.object(prepare, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_binaries_have_hashes_revision_and_executable_modes(self):
        manifest = prepare.install_binaries(self.source, prepare.BOX_REVISION)
        self.assertEqual(manifest["box_revision"], prepare.BOX_REVISION)
        self.assertEqual(len(manifest["files"]), 3)
        self.assertEqual(json.loads((self.root / "research/tested-build.json").read_text()), manifest)
        for name, digest in manifest["files"].items():
            path = self.root / name
            self.assertEqual(prepare.hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_wrong_architecture_is_refused_before_install(self):
        (self.source / "strands-box").write_bytes(b"not an ARM64 executable")
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)
        self.assertFalse((self.root / "binary-manifest.json").exists())

    def test_symlink_binary_is_refused(self):
        (self.source / "strands-box").rename(self.source / "saved-box")
        (self.source / "strands-box").symlink_to(self.source / "saved-box")
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)

    def test_existing_binary_is_not_replaced(self):
        prepare.install_binaries(self.source, prepare.BOX_REVISION)
        with self.assertRaises(ValueError):
            prepare.install_binaries(self.source, prepare.BOX_REVISION)

    def test_scripted_variant_installs_no_framework(self):
        with mock.patch.object(prepare.subprocess, "run") as run:
            prepare.install_framework("scripted")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
