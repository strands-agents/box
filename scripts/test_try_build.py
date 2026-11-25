"""Check scripts/try-build.sh against a stubbed gh, uname, and CI build."""

import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().parent / "try-build.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"

GH = """#!/bin/sh
echo "$*" >> "$TRY_LOG"
case "$1 $2" in
  "pr view") echo "$TRY_SHA false" ;;
  "api repos/strands-agents/box/commits/main") echo "$TRY_SHA" ;;
  "run list") echo "7 completed https://example.invalid/run/7 success" ;;
  "api repos/strands-agents/box/actions/runs/7/artifacts?name=box-$TRY_SHA-aarch64-apple-darwin") echo false ;;
  "run download")
    while [ "$1" != "-D" ]; do shift; done
    mkdir -p "$2" && cp "$TRY_TARBALL" "$2/box.tar.gz" ;;
  *) echo "unexpected gh $*" >&2; exit 9 ;;
esac
"""

UNAME = """#!/bin/sh
case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin arm64 ;; esac
"""

# A box that reads BOX_HOME refuses a relative one, as the real one does.
BOX = """#!/bin/sh
if [ "$1" = profile ] && [ "$2" = list ] && {reads}; then
  case "$BOX_HOME" in /*) ;; *) echo "box: error: BOX_HOME must be a full path" >&2; exit 1 ;; esac
fi
echo "box test"
"""


class TryBuildTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.home = self.root / "it's home"
        self.home.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        self.log = self.root / "gh.log"
        self.write(self.stubs / "gh", GH)
        self.write(self.stubs / "uname", UNAME)
        self.build(reads_box_home=True)

    def write(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def build(self, reads_box_home):
        folder = self.root / "build"
        shutil.rmtree(folder, ignore_errors=True)
        (folder / "resources/packs").mkdir(parents=True)
        (folder / "resources/packs/pack.toml").write_text("")
        self.write(folder / "box", BOX.format(reads="true" if reads_box_home else "false"))
        with tarfile.open(self.root / "box.tar.gz", "w:gz") as tar:
            for entry in ["box", "resources"]:
                tar.add(folder / entry, arcname=entry)

    @property
    def cached(self):
        return self.tmp / "box-try" / SHA

    def box_home(self, sha=SHA):
        return self.home / ".box-try" / sha[:10]

    def run_script(self, *arguments, shell="/bin/zsh", env=None, command=None):
        environment = {
            "HOME": str(self.home),
            "PATH": f"{self.stubs}:/usr/bin:/bin",
            "SHELL": shell,
            "TRY_LOG": str(self.log),
            "TRY_SHA": SHA,
            "TMPDIR": f"{self.tmp}/",
            "TRY_TARBALL": str(self.root / "box.tar.gz"),
        }
        for name, value in (env or {}).items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return subprocess.run(
            command or [str(SCRIPT), *arguments],
            env=environment,
            capture_output=True,
            text=True,
        )

    def downloads(self):
        if not self.log.exists():
            return 0
        return sum(line.startswith("run download") for line in self.log.read_text().splitlines())

    def test_posix_env_puts_the_build_first_and_removes_an_alias(self):
        script = textwrap.dedent(
            f"""
            alias box=/usr/bin/false
            eval "$({SCRIPT} 329 --env)"
            command -v box
            printf '%s\\n' "$BOX_HOME" "$BOX_RESOURCES" "$BOX_TRY"
            """
        )
        result = self.run_script(command=["bash", "-O", "expand_aliases", "-c", script])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                str(self.cached / "bin/box"),
                str(self.box_home()),
                str(self.cached / "bin/resources"),
                f"329@{SHA[:10]}",
            ],
        )
        self.assertTrue(self.box_home().is_dir())

    def test_fish_env_puts_the_build_first_and_removes_an_alias(self):
        fish = shutil.which("fish")
        if fish is None:
            self.skipTest("fish is not installed")
        script = (
            "function box; echo alias; end; "
            f"{SCRIPT} 329 --env | source; "
            "command -v box; functions -q box; or echo no-function; echo $BOX_HOME"
        )
        result = self.run_script(shell=fish, command=[fish, "--no-config", "-c", script])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [str(self.cached / "bin/box"), "no-function", str(self.box_home())],
        )

    def test_fish_env_is_fish_syntax(self):
        result = self.run_script("329", "--env", shell="/opt/homebrew/bin/fish")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("set -gx PATH ", result.stdout)
        self.assertIn("functions -e box;", result.stdout)
        self.assertNotIn("export", result.stdout)

    def test_a_cached_build_is_not_downloaded_again(self):
        for _ in range(2):
            result = self.run_script("329", "--", "true")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.downloads(), 1)
        self.assertIn("using the build for PR 329", result.stderr)

    def test_the_command_form_gets_the_build_and_box_home(self):
        result = self.run_script(
            "main", "--", "sh", "-c", 'command -v box; echo "$BOX_HOME"; box'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [str(self.cached / "bin/box"), str(self.box_home()), "box test"],
        )

    def test_the_shell_form_starts_the_shell_with_the_build_and_box_home(self):
        shell = self.stubs / "fake-shell"
        self.write(shell, '#!/bin/sh\ncommand -v box\necho "$BOX_HOME"\n')
        result = self.run_script("329", shell=str(shell))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [str(self.cached / "bin/box"), str(self.box_home())],
        )
        self.assertIn("use --env", result.stderr)

    def test_a_new_commit_gets_a_new_empty_box_home(self):
        first = self.run_script("329", "--", "sh", "-c", 'touch "$BOX_HOME/profile"; echo "$BOX_HOME"')
        self.assertEqual(first.returncode, 0, first.stderr)
        other = "f" * 40
        second = self.run_script(
            "329", "--", "sh", "-c", 'ls -A "$BOX_HOME"; echo "$BOX_HOME"', env={"TRY_SHA": other}
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, f"{self.box_home()}\n")
        self.assertEqual(
            second.stdout, f"{self.box_home(other)}\n"
        )
        self.assertEqual(self.downloads(), 2)

    def test_env_again_in_the_same_shell_gives_a_new_commit_a_new_box_home(self):
        other = "f" * 40
        script = textwrap.dedent(
            f"""
            eval "$({SCRIPT} 329 --env)"
            touch "$BOX_HOME/profile"
            TRY_SHA={other} eval "$(TRY_SHA={other} {SCRIPT} 329 --env)"
            echo "$BOX_HOME"; ls -A "$BOX_HOME"
            """
        )
        result = self.run_script(command=["bash", "-c", script])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.box_home(other)}\n")

    def test_env_sh_prints_posix_lines_when_the_login_shell_is_fish(self):
        script = f'eval "$({SCRIPT} 329 --env sh)"; command -v box'
        result = self.run_script(shell="/opt/homebrew/bin/fish", command=["bash", "-c", script])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.cached / 'bin/box'}\n")
        self.assertIn("printed sh lines; for the other syntax, use --env fish", result.stderr)

    def test_env_names_the_syntax_it_printed(self):
        result = self.run_script("329", "--env", shell="/opt/homebrew/bin/fish")
        self.assertIn("printed fish lines; for the other syntax, use --env sh", result.stderr)

    def test_an_unset_tmpdir_stops_the_script(self):
        result = self.run_script("329", "--", "true", env={"TMPDIR": None})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TMPDIR is not set", result.stderr)
        self.assertEqual(self.downloads(), 0)

    def test_a_linked_cache_is_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.tmp / "box-try").symlink_to(elsewhere)
        result = self.run_script("329", "--", "true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a folder that you own", result.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_cached_build_that_lost_a_file_is_downloaded_again(self):
        self.assertEqual(self.run_script("329", "--", "true").returncode, 0)
        (self.cached / "bin/resources/packs/pack.toml").unlink()
        result = self.run_script("329", "--", "true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.downloads(), 2)
        self.assertTrue((self.cached / "bin/resources/packs/pack.toml").is_file())

    def test_an_operator_box_home_wins(self):
        own = self.root / "own"
        result = self.run_script(
            "329", "--", "sh", "-c", 'echo "$BOX_HOME"', env={"BOX_HOME": str(own)}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{own}\n")
        self.assertFalse(self.box_home().exists())

    def test_a_build_that_ignores_box_home_gets_a_warning(self):
        self.build(reads_box_home=False)
        result = self.run_script("329", "--", "true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("does not read BOX_HOME, so it uses your default Box home", result.stderr)

    def test_a_build_that_reads_box_home_gets_no_warning(self):
        result = self.run_script("329", "--", "true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("BOX_HOME", result.stderr.replace(str(self.box_home()), ""))

    def test_clean_removes_every_cached_build(self):
        self.assertEqual(self.run_script("329", "--", "true").returncode, 0)
        self.assertTrue(self.cached.is_dir())
        result = self.run_script("--clean")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.tmp / "box-try").exists())
        self.assertFalse((self.home / ".box-try").exists())

    def test_the_box_home_leaves_room_for_box_cores_socket_path(self):
        # Box Core refuses a broker socket path over 103 bytes: <BOX_HOME>/r/<box ID>/box/run/box.sock.
        tmpdir = f"{self.root}/var/folders/8l/48m77r0d1vzbb140_nz4mks40000gn/T"
        os.makedirs(tmpdir)
        result = self.run_script(
            "329", "--", "sh", "-c", 'echo "$BOX_HOME"', env={"TMPDIR": f"{tmpdir}/"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        box_home = result.stdout.strip()
        self.assertFalse(box_home.startswith(tmpdir), box_home)
        mac_home = "/Users/" + "u" * 20
        box_id = "b-" + "0" * 16
        socket = f"{box_home.replace(str(self.home), mac_home)}/r/{box_id}/box/run/box.sock"
        self.assertLessEqual(len(socket.encode()), 103, socket)

    def test_a_linked_box_home_folder_is_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.home / ".box-try").symlink_to(elsewhere)
        result = self.run_script("329", "--", "true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a folder that you own", result.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
