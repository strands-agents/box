# Release Box

Use the `Release Box` workflow in `.github/workflows/deploy-box-artifact.yml`.
Select upstream `main` and pin the product source with the `sha` input.
The source must belong to `main` history for publication.

## Choose a version

Both channels publish macOS Apple silicon. Set the workflow input `publish_linux=true` to include the Amazon Linux 2023 ARM64 archive.
The default, `publish_linux=false`, keeps stable releases macOS-only. Linux preview versions require `publish_linux=true`.
To add the x86-64 archive after target qualification, also set `publish_linux_x86=true`. This input defaults to `false` and requires `publish_linux=true`.
Linux x86-64 remains experimental. Its separate runtime opt-in is described below.

| Version input | GitHub release | Latest stable release |
|---|---|---|
| `0.1.1` | Stable | Replaced by this release |
| `0.1.1-linux-preview.1` | Prerelease | Unchanged |

These are examples, not reserved versions. Do not include the leading `v` in the input.
The workflow adds it to the tag and archive names.
The version must make one major, minor, or patch increment from the latest stable tag.
The tag must not already exist. Preview tags do not change the stable version baseline.
A Linux preview also includes the macOS archive. There is no separate macOS preview channel.

## Rehearse

Run the workflow with the selected `version` and `sha`, and these inputs:

- `dry_run=true`
- `publish_linux=true` for an ARM64 Linux release, or `false` for a macOS-only stable release
- `publish_linux_x86=true` to include the qualified x86-64 package, or `false` to omit it
- `sign_macos=true`
- `premerge_signing_test=false`
- `skip_tests=false`

Inspect the build, package checks, workspace tests, signing, signed-package tests, and archive inspection.
The [macOS release guide](macos-release.md) describes the signing prerequisites and evidence.
A dry run with `sign_macos=false` omits signing and signed-package verification.
It does not rehearse all publication prerequisites.

Linux ARM64 and x86-64 build in the existing Amazon Linux 2023 container, which provides GNU C library (glibc) 2.34.
Every build checks that the packaged `box --version` reports the selected release version.
For Linux ARM64 and x86-64, the package checker inspects all three executables for the selected architecture,
the matching program loader, and glibc requirements no newer than 2.34.
To repeat the x86-64 check after extracting its workflow archive into `stage/box-core`, run this command
from the repository root on a Linux host with Python 3 and `readelf` installed:

```sh
python3 scripts/check-linux-package.py stage/box-core --target x86_64-unknown-linux-gnu
```

Omit `--target` to check ARM64. These checks do not run workloads or qualify an installed x86-64 release.
Box workloads on Linux x86-64 still require the `EXPERIMENTAL_X86_SUPPORT=TRUE` environment setting.

## Publish

Complete security acceptance and target qualification before approving publication.
Run the same version, source, `publish_linux`, and `publish_linux_x86` selections from upstream `main` with `dry_run=false` and `skip_tests=false`.
Real releases require macOS signing and signed-package verification, including releases that introduce Linux support.
Approve the protected signing environment when requested, then approve `release-gate` after the checks pass.
The workflow creates the tag and publishes the verified bundle from that run.
A new run rebuilds the package. Keep the hashes from the publication run.

With `publish_linux=true` and `publish_linux_x86=false`, both channels publish these files, with the selected tag in place of `<tag>`:

- `box-<tag>-aarch64-apple-darwin.tar.gz`
- `box-<tag>-linux-arm64.tar.gz`
- `SHA256SUMS.txt`

Setting `publish_linux_x86=true` adds `box-<tag>-linux-x86_64.tar.gz` and its checksum entry.
With the default `false`, the x86-64 package remains a workflow artifact.

The Linux release archives use `linux-arm64` and `linux-x86_64` in their names.
Compilation and intermediate workflow artifacts retain the Rust targets `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`, respectively.
`SHA256SUMS.txt` contains a checksum for each published archive.
Build jobs display `Linux ARM64`, `Linux x86_64`, or `macOS ARM64`.

For a macOS-only stable release, the bundle omits both Linux archives and their checksum entries.
Its release notes omit Linux installation instructions. Linux builds and checks still run.
This choice omits Linux from the new release. It does not remove archives from older releases.

The final workflow check verifies asset names and prerelease metadata.
It does not download and execute the published Linux packages.

## Verify the Linux download

Run the downloader on the qualified Amazon Linux 2023 ARM64 host.
If the release includes x86-64, repeat these checks on the qualified Amazon Linux 2023 x86-64 host.
Set `release_tag` to the published tag you are verifying. The command below uses `v0.1.1` as an example.

```sh
release_tag=v0.1.1
curl -fsSL https://raw.githubusercontent.com/strands-agents/box/main/download.sh | BOX_VERSION="$release_tag" sh
./box-core/box --version
```

The downloader selects the archive for the host CPU and reads `SHA256SUMS.txt` before downloading it.
On ARM64, it prefers `box-<tag>-linux-arm64.tar.gz`. If that entry is absent, it accepts the older `box-<tag>-aarch64-unknown-linux-gnu.tar.gz` entry from the same release.
On x86-64, it selects `box-<tag>-linux-x86_64.tar.gz`. A missing x86-64 archive or checksum stops the download; it never substitutes an ARM64 archive.
A failed download or checksum for the selected archive stops the operation.
The downloader verifies the checksum and checks all three Linux executables before extracting into `./box-core`.
The package requires glibc 2.34 or newer and the GCC runtime library, `libgcc_s.so.1`.
Before replacing files, it runs the candidate's `box --version` inside an existing destination, or beside a new destination.
This staging location must be writable and permit execution. Temporary download storage can be `noexec`.
A failed candidate check preserves existing destination files and shows the loader error.
If execution fails after final extraction, the downloader reports failure and warns that destination files changed.
If the release omits your Linux architecture, select a tag that includes its archive and checksum entry.
The downloader does not fall back to an older release or a prerelease automatically.
For ARM64, manual checksum verification and extraction from the release notes remain an alternative.
Keep `box`, `strands-box-sock-alias`, and `strands-box-contain-trampoline` together.
On x86-64, set `EXPERIMENTAL_X86_SUPPORT=TRUE` in the environment before running workloads.
Verify the reported version, an allowed operation, and a denied operation on each published Linux architecture using the approved test configuration.
Record the release URL, source commit, archive hash, host baseline, commands, and results.

Linux ARM64 startup requires no environment opt-in.
A stable version does not establish security acceptance.
