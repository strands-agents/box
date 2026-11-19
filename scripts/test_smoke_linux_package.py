"""Check the package smoke runner's environment with an executable fixture."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("smoke-linux-package.py")
spec = importlib.util.spec_from_file_location("smoke_linux_package", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokePackageEnvironmentTests(unittest.TestCase):
    def test_version_and_workload_start_without_retired_opt_ins(self):
        with tempfile.TemporaryDirectory(prefix="box-smoke-env-") as directory:
            root = Path(directory)
            archive = root / "package.tar.gz"
            log = root / "environment.log"
            program = b"""#!/bin/sh
printf '%s:%s:%s\n' "$1" "${EXPERIMENTAL_LINUX_SUPPORT-unset}" "${EXPERIMENTAL_X86_SUPPORT-unset}" >> "$SMOKE_ENV_LOG"
if [ "$1" = --version ]; then printf 'fixture 1.2.3\n'; fi
"""
            with tarfile.open(archive, "w:gz") as output:
                for name in smoke.BINARIES:
                    contents = program if name == "box" else b"#!/bin/sh\nexit 0\n"
                    member = tarfile.TarInfo(name)
                    member.mode = 0o755
                    member.size = len(contents)
                    output.addfile(member, io.BytesIO(contents))
            environment = {
                "EXPERIMENTAL_LINUX_SUPPORT": "TRUE",
                "EXPERIMENTAL_X86_SUPPORT": "TRUE",
                "SMOKE_ENV_LOG": str(log),
            }
            captured = io.StringIO()
            with patch.dict(os.environ, environment), patch.object(Path, "home", return_value=root):
                with redirect_stdout(captured):
                    result = smoke.check(archive, allow_root_operator=True)
            self.assertEqual(log.read_text().splitlines(), ["--version:unset:unset", "run:unset:unset"])
            # This fixture observes process environments; it does not simulate containment.
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(captured.getvalue())["version"], "fixture 1.2.3")


if __name__ == "__main__":
    unittest.main()
