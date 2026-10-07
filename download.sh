#!/bin/sh
# Box release downloader.
#
# Downloads the prebuilt box tarball for macOS on Apple silicon from the
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
case "$host_os" in
    Darwin) ;;
    *) die "unsupported OS: $host_os. Box supports macOS on Apple silicon." ;;
esac
case "$host_arch" in
    arm64|aarch64) ;;
    *) die "unsupported architecture: $host_arch. Box supports macOS on Apple silicon." ;;
esac
triple="aarch64-apple-darwin"

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

asset="box-${VERSION}-${triple}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

log "Downloading ${asset}..."
fetch "${base_url}/${asset}" "${tmp}/${asset}" \
    || die "failed to download ${asset} from ${base_url}"

log "Downloading SHA256SUMS.txt..."
fetch "${base_url}/SHA256SUMS.txt" "${tmp}/SHA256SUMS.txt" \
    || die "failed to download SHA256SUMS.txt"

expected="$(awk -v a="$asset" '$2==a {print $1}' "${tmp}/SHA256SUMS.txt")"
[ -n "$expected" ] || die "no SHA256SUMS.txt entry for ${asset}"
actual="$(sha256_of "${tmp}/${asset}")"
[ "$expected" = "$actual" ] || die "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"
log "Checksum verified."

mkdir -p "$DOWNLOAD_DIR"
# umask 022 so tar restores predictable modes (0755) whatever the caller's umask.
umask 022
tar -C "$DOWNLOAD_DIR" -xzf "${tmp}/${asset}"
[ -x "${DOWNLOAD_DIR}/box" ] || die "${asset} did not unpack an executable 'box'"

log ""
log "Downloaded box ${VERSION} (${triple}) into ${DOWNLOAD_DIR}."
log "Nothing was installed: your PATH and system directories are untouched."
log ""
log "Write a box.toml and a policy, then run the box by path:"
log "  ${DOWNLOAD_DIR}/box run --config ./box.toml"

"${DOWNLOAD_DIR}/box" --version 2>/dev/null || true
