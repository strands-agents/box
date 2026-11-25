"""Check the Box archive boundary used by the Linux package smoke test."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "smoke_linux_package", Path(__file__).with_name("smoke-linux-package-cli.py")
)
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class LinuxSmokeArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "box.tar.gz"
        self.package = self.root / "package"
        self.package.mkdir()
        self.entries = [
            (name, b"executable", 0o755, tarfile.REGTYPE)
            for name in ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
        ] + [
            ("release.json", b"{}", 0o644, tarfile.REGTYPE),
            ("resources/config.toml", b"[starters]\n", 0o644, tarfile.REGTYPE),
            ("resources/editing-box-profile.md", b"# Guide\n", 0o644, tarfile.REGTYPE),
            ("resources/packs/base/pack.toml", b"[pack]\n", 0o644, tarfile.REGTYPE),
        ]

    def unpack(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, contents, mode, kind in self.entries:
                member = tarfile.TarInfo("./" + name)
                member.mode = mode
                member.type = kind
                member.size = len(contents) if kind == tarfile.REGTYPE else 0
                member.linkname = "../../escaped"
                archive.addfile(member, io.BytesIO(contents))
        smoke.unpack(self.archive, self.package)

    def test_box_package_preserves_resources_and_binary_modes(self):
        self.unpack()
        self.assertEqual((self.package / "resources/packs/base/pack.toml").read_bytes(), b"[pack]\n")
        self.assertEqual((self.package / "box").stat().st_mode & 0o7777, 0o755)

    def test_missing_metadata_or_resources_is_refused(self):
        for name in ("release.json", "resources/config.toml", "resources/editing-box-profile.md",
                     "resources/packs/base/pack.toml"):
            with self.subTest(name=name):
                entries = self.entries
                self.entries = [entry for entry in entries if entry[0] != name]
                with self.assertRaisesRegex(ValueError, "missing package"):
                    self.unpack()
                self.entries = entries
                for path in sorted(self.package.rglob("*"), reverse=True):
                    path.rmdir() if path.is_dir() else path.unlink()

    def test_unsafe_resource_entries_are_refused(self):
        for name, kind in (
            ("resources/../../escaped", tarfile.REGTYPE),
            ("resources/alias", tarfile.SYMTYPE),
            ("resources/alias", tarfile.LNKTYPE),
            ("resources/config.toml", tarfile.DIRTYPE),
            ("resources/editing-box-profile.md", tarfile.DIRTYPE),
        ):
            with self.subTest(name=name, kind=kind):
                self.entries = [(name, b"bad", 0o644, kind)]
                with self.assertRaisesRegex(ValueError, "unexpected archive entry"):
                    self.unpack()
                self.assertFalse((self.root / "escaped").exists())

    def test_duplicate_resource_is_refused(self):
        self.entries += [self.entries[-1]]
        with self.assertRaisesRegex(ValueError, "unexpected archive entry"):
            self.unpack()

    def test_binary_with_setuid_mode_is_refused(self):
        self.entries[0] = ("box", b"executable", 0o4755, tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, "expected executable mode 0755"):
            self.unpack()


class LinuxSmokeIdentityTests(unittest.TestCase):
    def test_package_commands_copy_existing_installation_or_disable_capture(self):
        class Observed(Exception):
            pass

        for contents in ('installation_id = "fixture"\nextra = "preserved"\n', None):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                original = Path(directory) / ".strands/box/installation.toml"
                if contents is not None:
                    original.parent.mkdir(parents=True)
                    original.write_text(contents)

                def observe(command, **kwargs):
                    saved = Path(kwargs["env"]["HOME"]) / ".strands/box/installation.toml"
                    self.assertEqual(saved.read_text(), contents or 'installation_id = ""\n')
                    raise Observed

                with patch.object(smoke.Path, "home", return_value=Path(directory)), \
                     patch.object(smoke, "unpack"), \
                     patch.object(smoke.subprocess, "run", side_effect=observe):
                    with self.assertRaises(Observed):
                        smoke.check(Path(directory) / "archive.tar.gz", allow_root_operator=True)
                self.assertEqual(original.read_text() if original.exists() else None, contents)

    def test_package_paths_resolve_a_linked_home(self):
        class Observed(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory).resolve() / "real"
            real.mkdir()
            linked = Path(directory) / "linked"
            linked.symlink_to(real)

            def observe(command, **kwargs):
                home = Path(kwargs["env"]["HOME"])
                self.assertEqual(home.parent.parent, real)
                profile = (home / ".strands/box/profiles/probe/profile.toml").read_text()
                self.assertNotIn(str(linked), profile)
                self.assertIn(str(real), profile)
                raise Observed

            with patch.object(smoke.Path, "home", return_value=linked), \
                 patch.object(smoke, "unpack"), \
                 patch.object(smoke.subprocess, "run", side_effect=observe):
                with self.assertRaises(Observed):
                    smoke.check(Path(directory) / "archive.tar.gz", allow_root_operator=True)


if __name__ == "__main__":
    unittest.main()
