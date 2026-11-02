"""Check accepted and refused library version requirements."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "check_linux_package", Path(__file__).with_name("check-linux-package.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class LinuxPackageTests(unittest.TestCase):
    def inspect(self, *requirements):
        output = (
            "Machine: AArch64\n"
            "Requesting program interpreter: /lib/ld-linux-aarch64.so.1]\n"
            + "\n".join(f"Name: {requirement}" for requirement in requirements)
        )
        with patch.object(checker.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
            return checker.inspect(Path("box"))

    def test_supported_public_versions(self):
        self.assertEqual(
            self.inspect("GLIBC_2.17", "GLIBC_2.34")["glibc_requirements"],
            ["GLIBC_2.17", "GLIBC_2.34"],
        )

    def test_newer_version_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exceeds GLIBC_2.34"):
            self.inspect("GLIBC_2.35")

    def test_private_interfaces_are_refused_explicitly(self):
        with self.assertRaisesRegex(ValueError, "private glibc interfaces"):
            self.inspect("GLIBC_2.34", "GLIBC_PRIVATE")

    def test_unknown_version_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown glibc requirement"):
            self.inspect("GLIBC_UNEXPECTED")


if __name__ == "__main__":
    unittest.main()
