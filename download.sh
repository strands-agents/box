#!/bin/sh
# Box release downloader.
#
# Downloads the prebuilt box tarball for macOS on Apple silicon or Linux ARM64 from the
# strands-agents/box GitHub Release, verifies it against SHA256SUMS.txt, and
# unpacks its files into a local directory (./box-core by default).
#
# It does not install anything: nothing is copied to a system directory, your
# PATH is not changed, and no shell startup file is edited. To run the box,
# call the downloaded binary by path, for example ./box-core/box run --config ./box.toml.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/strands-agents/box/main/download.sh | sh
#
# Environment overrides:
#   BOX_VERSION        Release tag to download (e.g. v0.1.0). Default: latest.
#   BOX_DOWNLOAD_DIR   Directory to unpack into. Default: ./box-core.
#   BOX_REPO           GitHub owner/name. Default: strands-agents/box.

set -eu

REPO="${BOX_REPO:-strands-agents/box}"
VERSION="${BOX_VERSION:-}"
DOWNLOAD_DIR="${BOX_DOWNLOAD_DIR:-./box-core}"

log() { printf '%s\n' "$*" >&2; }
die() { log "download.sh: error: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

host_os="$(uname -s)"
host_arch="$(uname -m)"
case "$host_os:$host_arch" in
    Darwin:arm64|Darwin:aarch64) package="aarch64-apple-darwin"; platform="macOS ARM64" ;;
    Linux:arm64|Linux:aarch64) package="linux-arm64"; platform="Linux ARM64" ;;
    *) die "unsupported platform: ${host_os}/${host_arch}. Downloads support macOS on Apple silicon and Linux ARM64." ;;
esac

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    latest_url() { curl -fsSIL -o /dev/null -w '%{url_effective}\n' "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
    latest_url() {
        wget --max-redirect=5 --server-response --spider "$1" 2>&1 \
            | awk '/^  Location:/ {loc=$2} END {print loc}'
    }
else
    die "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    die "need sha256sum or shasum"
fi

need tar
need awk
need mktemp
need find
need dirname

if [ -z "$VERSION" ]; then
    log "Resolving latest release from ${REPO}..."
    resolved="$(latest_url "https://github.com/${REPO}/releases/latest")"
    VERSION="${resolved##*/}"
    [ -n "$VERSION" ] || die "could not resolve latest release version"
fi
case "$VERSION" in
    v*) ;;
    *) die "version '$VERSION' must start with 'v' (e.g. v0.1.0)" ;;
esac

asset="box-${VERSION}-${package}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

staged=""
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; if [ -n "$staged" ]; then rm -rf "$staged"; fi' EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

log "Downloading SHA256SUMS.txt..."
fetch "${base_url}/SHA256SUMS.txt" "${tmp}/SHA256SUMS.txt" \
    || die "failed to download SHA256SUMS.txt.
Check connectivity and whether this release is published:
https://github.com/${REPO}/releases/tag/${VERSION}
To select another release, set BOX_VERSION=vX.Y.Z."

checksum_for() {
    awk -v a="$1" '{n=$2; sub(/^\*/, "", n); if (n==a) print $1}' "${tmp}/SHA256SUMS.txt"
}
expected="$(checksum_for "$asset")"
# Older releases use the Rust target name for the Linux archive.
if [ -z "$expected" ] && [ "$host_os" = Linux ]; then
    legacy_asset="box-${VERSION}-aarch64-unknown-linux-gnu.tar.gz"
    expected="$(checksum_for "$legacy_asset")"
    if [ -n "$expected" ]; then
        asset="$legacy_asset"
    fi
fi
[ -n "$expected" ] || die "no SHA256SUMS.txt entry for ${asset}.
Check whether this release includes ${platform}:
https://github.com/${REPO}/releases/tag/${VERSION}
To select another release, set BOX_VERSION=vX.Y.Z."

log "Downloading ${asset}..."
fetch "${base_url}/${asset}" "${tmp}/${asset}" \
    || die "could not download ${asset}.
Check connectivity and whether this release includes the asset:
https://github.com/${REPO}/releases/tag/${VERSION}
To select another release, set BOX_VERSION=vX.Y.Z."

actual="$(sha256_of "${tmp}/${asset}")"
[ "$expected" = "$actual" ] || die "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"
log "Checksum verified."

# Validate the extracted payload before replacing destination files.
if [ "$host_os" = Linux ]; then
    if [ -d "$DOWNLOAD_DIR" ]; then
        staging_parent="$DOWNLOAD_DIR"
    else
        staging_parent="$(dirname "$DOWNLOAD_DIR")"
        mkdir -p "$staging_parent"
    fi
    staged="$(mktemp -d "${staging_parent}/.box-download.XXXXXX")" \
        || die "cannot create temporary package storage in ${staging_parent}; check write permissions"
else
    staged="${tmp}/unpacked"
    mkdir "$staged"
fi
umask 022
tar -C "$staged" -xzf "${tmp}/${asset}" \
    || die "could not unpack ${asset}"
# File modes remain readable even when temporary storage prohibits execution.
has_execute_mode() {
    [ -n "$(find -L "$1" -prune -type f \( -perm -100 -o -perm -010 -o -perm -001 \) -print)" ]
}
has_execute_mode "${staged}/box" \
    || die "${asset} did not unpack an executable 'box'"
if [ "$host_os" = Linux ]; then
    for name in box strands-box-sock-alias strands-box-contain-trampoline; do
        file="${staged}/${name}"
        [ ! -L "$file" ] && has_execute_mode "$file" && [ -x "$file" ] \
            || die "${asset} is missing a regular executable: ${name}"
    done
    "${staged}/box" --version >/dev/null \
        || die "cannot run the Linux package. It requires glibc 2.34 or newer,
the GCC runtime library, and execution permission in the destination (or its parent when creating a new destination).
The existing destination files were not changed. See the error above."
fi

mkdir -p "$DOWNLOAD_DIR"
# Extract the verified archive to preserve the macOS bundle and its links.
tar -C "$DOWNLOAD_DIR" -xzf "${tmp}/${asset}" \
    || die "could not unpack ${asset} into ${DOWNLOAD_DIR}; files may be partially updated"

if [ "$host_os" = Linux ]; then
    "${DOWNLOAD_DIR}/box" --version \
        || die "cannot run box from ${DOWNLOAD_DIR}. Check library availability and execution permissions.
Destination files have been extracted; use a fresh BOX_DOWNLOAD_DIR to retain a previous installation."
fi

log ""
log "Downloaded box ${VERSION} (${platform}) into ${DOWNLOAD_DIR}."
log "Nothing was installed: your PATH and system directories are untouched."
log ""
log "Write a box.toml and a policy, then run the box by path:"
log "  ${DOWNLOAD_DIR}/box run --config ./box.toml"

if [ "$host_os" = Darwin ]; then
    "${DOWNLOAD_DIR}/box" --version 2>/dev/null || true
fi
