#!/usr/bin/env python3
"""Check the generated TOML strings."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


class GeneratedTomlTests(unittest.TestCase):
    def test_strings_keep_quotes_backslashes_unicode_and_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest"
            manifest.write_text('name=quoted"name\\tail\nagent_path=/bin\\tools\n')
            paths = root / "paths.json"
            program = '/opt/測😀a"b\\tail/claude\x7f'
            paths.write_text(json.dumps({"HOME": "/home/operator", "PLATFORM": "macos", "CLAUDE": program}))
            project = str(root / 'project"name\\tail')
            box = str(root / 'box"name\\tail')
            journal = str(root / 'journal"name\\tail')
            subprocess.run([sys.executable, str(Path(__file__).with_name("boxgen.py")),
                            str(manifest), str(paths), "claude", project, str(root), journal, box],
                           check=True, capture_output=True)
            parsed = tomllib.loads((root / "box.toml").read_text())
            self.assertEqual(parsed["name"], 'quoted"name\\tail')
            self.assertEqual(parsed["box_dir"], box)
            self.assertEqual(parsed["agent"]["command"][0], program)
            self.assertEqual(parsed["agent"]["workspace"], project)
            self.assertEqual(parsed["agent"]["env"]["PATH"], '/bin\\tools')
            self.assertEqual(parsed["telemetry"]["decisions"]["destination"], journal)
            self.assertIn(project, parsed["agent"]["filesystem"]["write"])


if __name__ == "__main__":
    unittest.main()
