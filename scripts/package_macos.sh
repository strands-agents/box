#!/bin/sh
# Signing and publication follow packaging.
set -eu
umask 077
LC_ALL=C
export LC_ALL

die() { printf 'package_macos.sh: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

box_native=false
if [ "${1-}" = --native-filesystem-policy ]; then
    box_native=true
    shift
fi
box_usage="usage: package_macos.sh [--native-filesystem-policy] <new output directory>"
[ "$#" -eq 1 ] || die "$box_usage"
case "$1" in --*) die "$box_usage" ;; esac
for box_tool in cargo git python3 uname lipo cp find chmod tar shasum mktemp mkdir rm; do need "$box_tool"; done
[ "$(uname -s)" = Darwin ] || die "a macOS build host is required"
box_repository=$(cd "$(dirname "$0")/.." && pwd -P)
case "$1" in /*) box_output=$1 ;; *) box_output="$(pwd -P)/$1" ;; esac
[ ! -e "$box_output" ] && [ ! -L "$box_output" ] || die "output directory already exists"
cd "$box_repository"
clean_source() {
    [ -z "$(git status --porcelain --untracked-files=normal --ignored=matching -- Cargo.toml Cargo.lock crates resources)" ] ||
        die "commit changes to Cargo files, crates, and resources before packaging"
}
clean_source
if [ "$box_native" = true ]; then
    need xcrun
    box_sdkroot=$(xcrun --sdk "${SDKROOT:-macosx}" --show-sdk-path) || die "could not resolve the macOS SDK"
    case "$box_sdkroot" in /*) ;; *) die "macOS SDK path must be absolute" ;; esac
    [ -d "$box_sdkroot" ] || die "macOS SDK directory is missing: $box_sdkroot"
    box_sdk_version=$(xcrun --sdk "$box_sdkroot" --show-sdk-version) || die "could not read the macOS SDK version"
    case "$box_sdk_version" in
        ''|*[!0-9.]*|.*|*.|*..*|*.*.*.*) die "invalid macOS SDK version: $box_sdk_version" ;;
    esac
    [ "${box_sdk_version%%.*}" -ge 27 ] || die "native filesystem policy requires macOS SDK 27 or later (found $box_sdk_version)"
    SDKROOT=$box_sdkroot
    export SDKROOT
fi
box_commit=$(git rev-parse HEAD)
box_work=$(mktemp -d /var/tmp/box-package.XXXXXXXX)
cleanup() {
    box_status=$?
    trap - 0 HUP INT TERM
    rm -rf "$box_work"
    exit "$box_status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
box_payload="$box_work/payload"
mkdir "$box_payload"
cargo metadata --locked --format-version 1 > "$box_work/cargo.json"
python3 - "$box_work" "$box_commit" <<'PY'
import json
from pathlib import Path
import re
import sys

work = Path(sys.argv[1])
metadata = json.loads((work / "cargo.json").read_text())
def package(name):
    found = [p for p in metadata["packages"] if p["name"] == name]
    if len(found) != 1:
        sys.exit(f"package_macos.sh: expected one resolved {name} package")
    return found[0]

box = package("strands-box-cli")
core = package("strands-box")
helper = package("strands-box-containment")
source = core["source"]
if helper["source"] != source:
    sys.exit("package_macos.sh: Core and helpers must use the same Core source")
if source is None:
    # A path dependency: Core is under this repository's crates/, which clean_source checks,
    # so its commit is the packaged commit.
    crates = Path.cwd().resolve() / "crates"
    if not all(Path(p["manifest_path"]).resolve().is_relative_to(crates) for p in (core, helper)):
        sys.exit("package_macos.sh: a path Core and its helpers must be under crates/ in this repository")
    core_commit = sys.argv[2]
else:
    pin = re.fullmatch(r"git\+https://github\.com/strands-agents/box(?:\?[^#]+)?#([0-9a-f]{40})", source)
    if not pin:
        sys.exit("package_macos.sh: Core and helpers must use the same locked public Core revision")
    core_commit = pin[1]
for version in (box["version"], core["version"]):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        sys.exit("package_macos.sh: release versions must use x.y.z")
record = dict(box_version=box["version"], box_commit=sys.argv[2],
              core_version=core["version"], core_commit=core_commit, target="aarch64-apple-darwin")
(work / "payload/release.json").write_text(json.dumps(record, indent=2) + "\n")
(work / "version").write_text(box["version"])
(work / "target").write_text(metadata["target_directory"])
PY
box_version=$(cat "$box_work/version")
box_target=$(cat "$box_work/target")
set --
if [ "$box_native" = true ]; then
    set -- --features strands-box-cli/native-filesystem-policy
fi
MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release --locked --target aarch64-apple-darwin \
    -p strands-box-cli -p strands-box -p strands-box-containment \
    --bin box --bin strands-box-sock-alias --bin strands-box-contain-trampoline "$@"
for box_binary in box strands-box-sock-alias strands-box-contain-trampoline; do
    box_source="$box_target/aarch64-apple-darwin/release/$box_binary"
    [ -f "$box_source" ] && [ -x "$box_source" ] && [ ! -L "$box_source" ] ||
        die "missing or linked executable: $box_binary"
    lipo "$box_source" -verify_arch arm64 || die "not an arm64 executable: $box_binary"
    cp -p "$box_source" "$box_payload/$box_binary"
done
[ -d resources/packs ] && [ ! -L resources ] && [ ! -L resources/packs ] || die "shipped packs are missing or linked"
[ -d resources/plugins ] && [ ! -L resources/plugins ] || die "shipped plugins are missing or linked"
[ -d resources/policies ] && [ ! -L resources/policies ] || die "shipped policies are missing or linked"
[ -d resources/starters ] && [ ! -L resources/starters ] || die "shipped starters are missing or linked"
[ -f resources/config.toml ] && [ ! -L resources/config.toml ] || die "shipped starter settings are missing or linked"
[ -f resources/editing-box-profile.md ] && [ ! -L resources/editing-box-profile.md ] || die "shipped profile guide is missing or linked"
find resources/packs resources/plugins resources/policies resources/starters ! -type f ! -type d -print > "$box_work/special"
[ ! -s "$box_work/special" ] || die "shipped packs, plugins, policies, or starters contain links or special files"
mkdir "$box_payload/resources"
cp resources/config.toml "$box_payload/resources/config.toml"
cp resources/editing-box-profile.md "$box_payload/resources/editing-box-profile.md"
cp -R resources/packs "$box_payload/resources/packs"
cp -R resources/plugins "$box_payload/resources/plugins"
cp -R resources/policies "$box_payload/resources/policies"
cp -R resources/starters "$box_payload/resources/starters"
[ "$("$box_payload/box" --version)" = "box $box_version" ] || die "Box version does not match Cargo"
clean_source
[ "$(git rev-parse HEAD)" = "$box_commit" ] || die "source commit changed during the build"
find "$box_payload" -type d -exec chmod 0755 {} +
find "$box_payload" -type f -exec chmod 0644 {} +
chmod 0755 "$box_payload/box" "$box_payload/strands-box-sock-alias" "$box_payload/strands-box-contain-trampoline"
box_asset="box-cli-v$box_version-aarch64-apple-darwin.tar.gz"
mkdir "$box_work/artifacts"
COPYFILE_DISABLE=1 tar -czf "$box_work/artifacts/$box_asset" -C "$box_payload" .
box_digest=$(shasum -a 256 "$box_work/artifacts/$box_asset")
printf '%s  %s\n' "${box_digest%% *}" "$box_asset" > "$box_work/artifacts/SHA256SUMS.txt"
if [ "$box_native" = true ]; then
    python3 - "$box_work" "$box_asset" "$box_sdk_version" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

work = Path(sys.argv[1])
archive = work / "artifacts" / sys.argv[2]
record = json.loads((work / "payload/release.json").read_text())
record.update(cargo_features=["strands-box-cli/native-filesystem-policy"], macos_sdk_version=sys.argv[3],
              archive=archive.name, archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              archive_stage="unsigned_build", runtime_qualified=False)
(work / "artifacts/native-filesystem-policy.json").write_text(json.dumps(record, indent=2) + "\n")
PY
fi
python3 - "$box_work/artifacts" "$box_output" <<'PY'
from pathlib import Path
import shutil
import sys

output = Path(sys.argv[2])
output.mkdir(parents=True, exist_ok=False)
for source in Path(sys.argv[1]).iterdir():
    shutil.copyfile(source, output / source.name)
PY
printf 'Built %s/%s\n' "$box_output" "$box_asset"
