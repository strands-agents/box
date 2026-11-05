"""Exercise the release downloader with local archives and simulated HTTP clients."""

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "download.sh"
BINARIES = ("box", "strands-box-sock-alias", "strands-box-contain-trampoline")
CLIENT = r"""
import os
from pathlib import Path
import shutil
import signal
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "uname":
    print(os.environ["TEST_OS"] if args == ["-s"] else os.environ["TEST_ARCH"])
    sys.exit(0)
if os.environ.get("TEST_SIGNAL"):
    os.kill(os.getppid(), getattr(signal, os.environ["TEST_SIGNAL"]))
    sys.exit(0)
url = next(arg for arg in args if arg.startswith("https://"))
with open(os.environ["TEST_REQUESTS"], "a") as log:
    log.write(url + "\n")
if url.endswith("/releases/latest"):
    resolved = url.removesuffix("latest") + "tag/v9.9.9"
    if name == "curl":
        print(resolved)
    else:
        print("  Location: " + resolved, file=sys.stderr)
    sys.exit(0)
source = Path(os.environ["TEST_RELEASES"]) / url.split("/download/", 1)[1]
if not source.is_file():
    sys.exit(22)
flag = "-o" if name == "curl" else "-qO"
shutil.copyfile(source, args[args.index(flag) + 1])
"""


class DownloaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="box-download-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        # Use real archive/checksum tools, but prevent access to real HTTP clients.
        for command in ("sh", "tar", "gzip", "awk", "mktemp", "mkdir", "rm", "sha256sum", "shasum", "find", "dirname", "mount", "chmod"):
            executable = shutil.which(command)
            if executable:
                (self.tools / command).symlink_to(executable)
        for name in ("uname", "curl", "wget"):
            path = self.tools / name
            path.write_text(f"#!{sys.executable}\n" + CLIENT)
            path.chmod(0o755)
        self.releases = self.root / "releases"
        self.requests = self.root / "requests"
        self.destination = self.root / "download destination"
        self.destination.mkdir()
        (self.destination / "box").write_bytes(b"existing box")
        (self.destination / "keep.txt").write_bytes(b"user file")
        self.temp = self.root / "temporary"
        self.temp.mkdir()
        self.env = dict(os.environ, PATH=str(self.tools), TEST_OS="Linux", TEST_ARCH="aarch64",
                        TEST_RELEASES=str(self.releases), TEST_REQUESTS=str(self.requests),
                        BOX_VERSION="v1.2.3", BOX_REPO="example/box",
                        BOX_DOWNLOAD_DIR=str(self.destination), TMPDIR=str(self.temp))

    def archive(self, version="v1.2.3", triple="linux-arm64", omit=(),
                non_executable=(), symlink=None, marker="", mac_bundle=False, box_program=None, modes=None):
        folder = self.releases / version
        folder.mkdir(parents=True, exist_ok=True)
        asset = folder / f"box-{version}-{triple}.tar.gz"
        with tarfile.open(asset, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            def file(name, data, mode=0o755):
                info = tarfile.TarInfo("./" + name)
                info.size = len(data)
                info.mode = mode
                archive.addfile(info, io.BytesIO(data))
            def link(name, target):
                info = tarfile.TarInfo("./" + name)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                archive.addfile(info)
            for name in BINARIES:
                if name in omit:
                    continue
                data = f"#!/bin/sh\nprintf '%s\\n' 'fixture {version} {name}'\n".encode()
                if name == "box" and box_program is not None:
                    data = box_program
                if mac_bundle and name != "box":
                    target = "Box.app/Contents/MacOS/" + name
                    file(target, data)
                    link(name, target)
                elif name == symlink:
                    file("other-executable", data)
                    link(name, "other-executable")
                else:
                    file(name, data, (modes or {}).get(name, 0o644 if name in non_executable else 0o755))
            if mac_bundle:
                file("Box.app/Contents/embedded.provisionprofile", b"fixture profile", 0o644)
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        (folder / "SHA256SUMS.txt").write_text(f"{digest}  {marker}{asset.name}\n")
        return asset

    def run_script(self, noexec_tmp=False, noexec_destination=False):
        command = [str(self.tools / "sh"), str(SCRIPT)]
        if noexec_tmp or noexec_destination:
            self.env["TEST_NOEXEC_DESTINATION"] = str(self.destination) if noexec_destination else ""
            # The mount exists only in this child namespace and disappears on exit.
            self.assertIsNotNone(shutil.which("unshare"), "noexec tests require util-linux")
            command = [shutil.which("unshare"), "--user", "--map-root-user", "--mount",
                       str(self.tools / "sh"), "-c", r'''set -eu
if [ -n "$TEST_NOEXEC_DESTINATION" ]; then
    mount --bind "$TEST_NOEXEC_DESTINATION" "$TEST_NOEXEC_DESTINATION"
    mount -o remount,bind,noexec "$TEST_NOEXEC_DESTINATION"
    probe_dir="$TEST_NOEXEC_DESTINATION"
else
    mount -t tmpfs -o noexec,size=16m tmpfs "$TMPDIR"
    probe_dir="$TMPDIR"
fi
printf '#!/bin/sh\nexit 0\n' > "$probe_dir/exec-probe"
chmod 0755 "$probe_dir/exec-probe"
if [ -x "$probe_dir/exec-probe" ]; then
    echo "test requires a noexec mount" >&2
    exit 99
fi
rm "$probe_dir/exec-probe"
exec "$1" "$2"
''', "noexec-test", *command]
        result = subprocess.run(command, cwd=self.root,
                                env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(list(self.temp.iterdir()), [], "temporary downloads must be cleaned up")
        self.assertEqual(list(self.destination.parent.glob(".box-download.*")), [],
                         "candidate packages must be cleaned up")
        self.assertEqual(list(self.destination.glob(".box-download.*")), [],
                         "candidate packages inside the destination must be cleaned up")
        return result

    def urls(self):
        return self.requests.read_text().splitlines() if self.requests.exists() else []

    def assert_refused(self, message):
        before = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in self.destination.iterdir()}, before)
        return result

    def test_linux_arm64_aliases_download_all_helpers(self):
        self.archive()
        for arch in ("aarch64", "arm64"):
            with self.subTest(arch=arch):
                self.env["TEST_ARCH"] = arch
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in BINARIES:
                    self.assertIn(b"fixture v1.2.3", (self.destination / name).read_bytes())
                    self.assertTrue(os.access(self.destination / name, os.X_OK))
                self.assertEqual((self.destination / "keep.txt").read_bytes(), b"user file")
                self.assertTrue(self.urls()[-1].endswith("box-v1.2.3-linux-arm64.tar.gz"))
                self.assertIn("(Linux ARM64)", result.stderr)
                self.assertNotIn("unknown", result.stderr)

    def test_legacy_linux_archive_uses_the_same_release_checksum(self):
        asset = self.archive(triple="aarch64-unknown-linux-gnu")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.urls(), [
            "https://github.com/example/box/releases/download/v1.2.3/SHA256SUMS.txt",
            f"https://github.com/example/box/releases/download/v1.2.3/{asset.name}",
        ])
        self.assertIn("(Linux ARM64)", result.stderr)

    def both_linux_names(self):
        legacy = self.archive(triple="aarch64-unknown-linux-gnu")
        legacy_entry = (legacy.parent / "SHA256SUMS.txt").read_text()
        current = self.archive()
        sums = current.parent / "SHA256SUMS.txt"
        sums.write_text(sums.read_text() + legacy_entry)
        return current, legacy

    def test_friendly_name_wins_when_both_are_listed(self):
        current, legacy = self.both_linux_names()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.urls()[-1].endswith(current.name))
        self.assertFalse(any(url.endswith(legacy.name) for url in self.urls()))

    def test_invalid_preferred_archive_never_falls_back_to_legacy(self):
        for failure in ("missing", "corrupt"):
            with self.subTest(failure=failure):
                current, legacy = self.both_linux_names()
                if failure == "missing":
                    current.unlink()
                else:
                    current.write_bytes(b"corrupt")
                self.requests.write_text("")
                self.assert_refused("could not download" if failure == "missing" else "checksum mismatch")
                self.assertFalse(any(url.endswith(legacy.name) for url in self.urls()))

    def test_macos_bundle_and_helper_links_survive(self):
        self.archive(triple="aarch64-apple-darwin", mac_bundle=True)
        self.env.update(TEST_OS="Darwin", TEST_ARCH="arm64")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in BINARIES[1:]:
            self.assertTrue((self.destination / name).is_symlink())
            self.assertEqual(os.readlink(self.destination / name), "Box.app/Contents/MacOS/" + name)
            self.assertIn(b"fixture v1.2.3", (self.destination / name).read_bytes())
        self.assertEqual((self.destination / "Box.app/Contents/embedded.provisionprofile").read_bytes(),
                         b"fixture profile")
        self.assertIn("aarch64-apple-darwin.tar.gz", self.urls()[-1])
        self.assertIn("(macOS ARM64)", result.stderr)

    def test_unsupported_platforms_do_not_download(self):
        for system, arch in (("Linux", "x86_64"), ("Darwin", "x86_64"), ("FreeBSD", "aarch64")):
            with self.subTest(system=system, arch=arch):
                self.env.update(TEST_OS=system, TEST_ARCH=arch)
                self.assert_refused("unsupported platform")
                self.assertEqual(self.urls(), [])

    def test_explicit_version_does_not_resolve_latest(self):
        self.archive()
        self.archive(version="v9.9.9")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all("/download/v1.2.3/" in url for url in self.urls()))
        self.assertIn(b"fixture v1.2.3", (self.destination / "box").read_bytes())

    def test_latest_resolves_once_and_uses_that_version(self):
        self.archive(version="v9.9.9")
        self.env.pop("BOX_VERSION")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.urls()[0], "https://github.com/example/box/releases/latest")
        self.assertEqual(len(self.urls()), 3)
        self.assertTrue(all("/download/v9.9.9/" in url for url in self.urls()[1:]))
        self.assertIn(b"fixture v9.9.9", (self.destination / "box").read_bytes())

    def test_missing_release_gives_release_and_version_guidance(self):
        result = self.assert_refused("failed to download SHA256SUMS.txt")
        self.assertIn("https://github.com/example/box/releases/tag/v1.2.3", result.stderr)
        self.assertIn("BOX_VERSION=vX.Y.Z", result.stderr)
        self.assertEqual(self.urls(), [
            "https://github.com/example/box/releases/download/v1.2.3/SHA256SUMS.txt",
        ])

    def test_missing_asset_gives_release_and_version_guidance(self):
        self.archive().unlink()
        result = self.assert_refused("could not download")
        self.assertIn("https://github.com/example/box/releases/tag/v1.2.3", result.stderr)
        self.assertIn("BOX_VERSION=", result.stderr)

    def test_missing_checksum_file(self):
        asset = self.archive()
        (asset.parent / "SHA256SUMS.txt").unlink()
        self.assert_refused("failed to download SHA256SUMS.txt")

    def test_checksum_missing_entry(self):
        asset = self.archive()
        (asset.parent / "SHA256SUMS.txt").write_text("0" * 64 + "  another.tar.gz\n")
        self.assert_refused("no SHA256SUMS.txt entry")

    def test_checksum_mismatch_refuses_before_unpacking(self):
        asset = self.archive()
        asset.write_bytes(b"corrupted bytes")
        self.assert_refused("checksum mismatch")

    def test_checksum_binary_marker_is_accepted(self):
        self.archive(marker="*")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_each_executable_preserves_destination(self):
        for name in BINARIES:
            with self.subTest(name=name):
                self.archive(omit=(name,))
                self.assert_refused("executable")

    def test_non_executable_payload_preserves_destination(self):
        for name in BINARIES:
            with self.subTest(name=name):
                self.archive(non_executable=(name,))
                self.assert_refused("executable")

    @unittest.skipIf(os.geteuid() == 0, "root bypasses owner execute permissions")
    def test_linux_helpers_must_be_executable_by_current_user(self):
        for name in BINARIES[1:]:
            with self.subTest(name=name):
                self.archive(modes={name: 0o641})
                self.assert_refused("regular executable")

    def test_linux_symlinks_cannot_substitute_for_executables(self):
        for name in BINARIES:
            with self.subTest(name=name):
                self.archive(symlink=name)
                self.assert_refused("regular executable")

    def test_checksum_valid_malformed_archive_preserves_destination(self):
        asset = self.archive()
        asset.write_bytes(b"not a gzip archive")
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        (asset.parent / "SHA256SUMS.txt").write_text(f"{digest}  {asset.name}\n")
        self.assert_refused("could not unpack")

    def test_extraction_failure_after_writing_a_file_preserves_destination(self):
        self.archive()
        (self.tools / "tar").unlink()
        (self.tools / "tar").write_text(
            '#!/bin/sh\nprintf partial > "$2/box"\nexit 1\n'
        )
        (self.tools / "tar").chmod(0o755)
        self.assert_refused("could not unpack")

    def test_failed_validation_does_not_create_destination(self):
        self.archive(omit=(BINARIES[1],))
        destination = self.root / "new destination"
        self.env["BOX_DOWNLOAD_DIR"] = str(destination)
        self.assert_refused("regular executable")
        self.assertFalse(destination.exists())

    @unittest.skipIf(os.geteuid() == 0, "root bypasses parent write permissions")
    def test_writable_destination_with_read_only_parent(self):
        self.archive()
        self.requests.touch()
        self.root.chmod(0o555)
        try:
            result = self.run_script()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Downloaded box", result.stderr)
        finally:
            self.root.chmod(0o755)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux mount test")
    def test_noexec_symlink_destination_preserves_existing_files(self):
        self.archive()
        alias = self.root / "destination alias"
        alias.symlink_to(self.destination, target_is_directory=True)
        self.env["BOX_DOWNLOAD_DIR"] = str(alias)
        before = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        result = self.run_script(noexec_destination=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Downloaded box", result.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in self.destination.iterdir()}, before)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux mount test")
    def test_noexec_download_storage_allows_valid_packages(self):
        for system, triple in (("Linux", "linux-arm64"),
                               ("Darwin", "aarch64-apple-darwin")):
            with self.subTest(platform=system):
                self.archive(triple=triple, mac_bundle=system == "Darwin")
                self.env["TEST_OS"] = system
                result = self.run_script(noexec_tmp=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Downloaded box", result.stderr)

    def test_linux_loader_failure_preserves_destination_and_is_visible(self):
        self.archive(box_program=b"#!/bin/sh\necho 'GLIBC_2.34 not found' >&2\nexit 127\n")
        result = self.assert_refused("GLIBC_2.34 not found")
        self.assertIn("glibc 2.34", result.stderr)
        self.assertNotIn("Downloaded box", result.stderr)

    def test_linux_preflight_failure_does_not_create_destination(self):
        self.archive(box_program=b"#!/bin/sh\necho 'libgcc_s.so.1 missing' >&2\nexit 127\n")
        destination = self.root / "missing parent" / "new destination"
        self.env["BOX_DOWNLOAD_DIR"] = str(destination)
        self.assert_refused("libgcc_s.so.1 missing")
        self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.glob(".box-download.*")), [])

    def test_linux_final_execution_failure_does_not_report_success(self):
        self.archive(box_program=b'''#!/bin/sh
case "$0" in
    */.box-download.*/box) exit 0 ;;
    *) echo 'destination execution refused' >&2; exit 126 ;;
esac
''')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination execution refused", result.stderr)
        self.assertIn("Destination files have been extracted", result.stderr)
        self.assertNotIn("Downloaded box", result.stderr)

    def test_signals_stop_without_changing_destination(self):
        self.archive()
        for name, status in (("SIGHUP", 129), ("SIGINT", 130), ("SIGTERM", 143)):
            with self.subTest(signal=name):
                self.env["TEST_SIGNAL"] = name
                result = self.assert_refused("")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(self.urls(), [])

    def test_wget_latest_and_shasum_fallback(self):
        self.archive(version="v9.9.9")
        (self.tools / "curl").unlink()
        if (self.tools / "sha256sum").exists():
            (self.tools / "sha256sum").unlink()
        self.env.pop("BOX_VERSION")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"fixture v9.9.9", (self.destination / "box").read_bytes())


if __name__ == "__main__":
    unittest.main()
