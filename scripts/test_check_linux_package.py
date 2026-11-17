"""Check Linux package targets and accepted library version requirements."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "check_linux_package", Path(__file__).with_name("check-linux-package.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


ARM64 = "aarch64-unknown-linux-gnu"
X86_64 = "x86_64-unknown-linux-gnu"
HEADERS = {
    ARM64: ("AArch64", "/lib/ld-linux-aarch64.so.1"),
    X86_64: ("Advanced Micro Devices X86-64", "/lib64/ld-linux-x86-64.so.2"),
}
BINARIES = (
    "box", "strands-box-sock-alias", "strands-box-contain-trampoline",
    "strands-box-dogwood-1-0-migrate",
)


def readelf_output(target, *requirements, machine=None, loader=None):
    expected_machine, expected_loader = HEADERS[target]
    return (
        f"Machine: {machine if machine is not None else expected_machine}\n"
        "Requesting program interpreter: "
        f"{loader if loader is not None else expected_loader}]\n"
        + "\n".join(f"Name: {requirement}" for requirement in requirements)
    )


class LinuxPackageTests(unittest.TestCase):
    def inspect(self, *requirements, target=ARM64, **headers):
        output = readelf_output(target, *requirements, **headers)
        with patch.object(checker.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
            return checker.inspect(Path("box"), target)

    def test_supported_public_versions(self):
        for target in HEADERS:
            with self.subTest(target=target):
                self.assertEqual(
                    self.inspect("GLIBC_2.17", "GLIBC_2.34", target=target)["glibc_requirements"],
                    ["GLIBC_2.17", "GLIBC_2.34"],
                )

    def test_newer_version_is_refused(self):
        for target in HEADERS:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "exceeds GLIBC_2.34"):
                    self.inspect("GLIBC_2.35", target=target)

    def test_private_interfaces_are_refused_explicitly(self):
        for target in HEADERS:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "private glibc interfaces"):
                    self.inspect("GLIBC_2.34", "GLIBC_PRIVATE", target=target)

    def test_unknown_version_is_refused(self):
        for target in HEADERS:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "unknown glibc requirement"):
                    self.inspect("GLIBC_UNEXPECTED", target=target)

    def test_other_architecture_is_refused(self):
        for target, other in [(ARM64, X86_64), (X86_64, ARM64)]:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "expected an .* executable"):
                    self.inspect("GLIBC_2.34", target=target, machine=HEADERS[other][0])

    def test_other_loader_is_refused(self):
        for target, other in [(ARM64, X86_64), (X86_64, ARM64)]:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "expected loader"):
                    self.inspect("GLIBC_2.34", target=target, loader=HEADERS[other][1])

    def run_main(self, arguments, output):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(checker.sys, "argv", ["check-linux-package.py", "package", *arguments]),
            patch.object(checker.subprocess, "run", return_value=SimpleNamespace(stdout=output)) as run,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = checker.main()
        return status, stdout.getvalue(), stderr.getvalue(), run

    def assert_package_report(self, result, architecture, loader):
        status, stdout, stderr, run = result
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stderr, "")
        records = json.loads(stdout)
        self.assertEqual([record["binary"] for record in records], list(BINARIES))
        self.assertEqual([record["architecture"] for record in records], [architecture] * len(BINARIES))
        self.assertEqual([record["loader"] for record in records], [loader] * len(BINARIES))
        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            [str(Path("package") / name) for name in BINARIES],
        )

    def test_cli_defaults_to_arm64(self):
        self.assert_package_report(
            self.run_main([], readelf_output(ARM64, "GLIBC_2.34")),
            "aarch64", HEADERS[ARM64][1],
        )

    def test_cli_selects_each_target(self):
        for target, architecture in [(ARM64, "aarch64"), (X86_64, "x86_64")]:
            with self.subTest(target=target):
                self.assert_package_report(
                    self.run_main(["--target", target], readelf_output(target, "GLIBC_2.34")),
                    architecture, HEADERS[target][1],
                )

    def test_cli_refuses_an_unsupported_target_before_inspection(self):
        with (
            patch.object(checker.sys, "argv", [
                "check-linux-package.py", "package", "--target", "unsupported-linux-target",
            ]),
            patch.object(checker.subprocess, "run") as run,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as error:
                checker.main()
        self.assertEqual(error.exception.code, 2)
        run.assert_not_called()

    def test_cli_refuses_incompatible_x86_helpers(self):
        for name, headers, message in [
            ("strands-box-sock-alias", {"machine": "AArch64"}, "expected an .* executable"),
            ("strands-box-contain-trampoline", {"loader": HEADERS[ARM64][1]}, "expected loader"),
            ("strands-box-dogwood-1-0-migrate", {"machine": "AArch64"}, "expected an .* executable"),
            ("strands-box-dogwood-1-0-migrate", {"loader": HEADERS[ARM64][1]}, "expected loader"),
        ]:
            with self.subTest(binary=name):
                def readelf(command, **kwargs):
                    overrides = headers if Path(command[-1]).name == name else {}
                    return SimpleNamespace(stdout=readelf_output(X86_64, "GLIBC_2.34", **overrides))

                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch.object(checker.sys, "argv", [
                        "check-linux-package.py", "package", "--target", X86_64,
                    ]),
                    patch.object(checker.subprocess, "run", side_effect=readelf),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(checker.main(), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertRegex(stderr.getvalue(), f"{name}: {message}")


if __name__ == "__main__":
    unittest.main()
