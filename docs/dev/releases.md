# Release Box

Use the `Release Box` workflow in `.github/workflows/deploy-box-artifact.yml`.
Select upstream `main` and pin the product source with the `sha` input.
The source must belong to `main` history for publication.

One run publishes one tag with both products: Box Core and the `box` CLI.
`Release Box` builds and signs Box Core itself.
It calls the reusable `CLI release` workflow (`.github/workflows/cli-release.yml`) to build, sign, verify, and bundle the CLI.
Box Core's tests (`rust-test-lint.yml`) and the CLI's tests (`cli-test.yml`) both gate the release.
The workflow stamps the selected version into the crates of both products before it builds them.
The [CLI macOS release guide](macos-release-cli.md) describes the CLI's package, signing, and checks.

## Choose a version

Every release, stable or prerelease, publishes macOS Apple silicon and the Amazon Linux 2023 ARM64 archives of both products.
The workflow also publishes the Linux x86-64 archives of both products by default. Set `publish_linux_x86=false` to omit them.

| Version input | GitHub release | Latest stable release |
|---|---|---|
| `0.3.0` | Stable | Replaced by this release |
| `0.3.0-preview.1` | Prerelease | Unchanged |
| `0.3.0-linux-preview.1` | Prerelease | Unchanged |

These are examples, not reserved versions. Do not include the leading `v` in the input.
The workflow adds it to the tag and archive names.
The version must make one major, minor, or patch increment from the latest stable tag.
The tag must not already exist. Prerelease tags do not change the stable version baseline.
`N` in `-preview.N` and `-linux-preview.N` is greater than zero.
A prerelease publishes the same asset set as a stable release and is never marked latest.
The installer picks a prerelease only when `BOX_VERSION` names it exactly.
The first release that includes the CLI is `v0.3.0-preview.1`.

## Rehearse

Run the workflow with the selected `version` and `sha`, and these inputs:

- `dry_run=true`
- `publish_linux_x86=true` (the default) to include the qualified x86-64 package, or `false` to omit it
- `sign_macos=true`
- `premerge_signing_test=false`
- `skip_tests=false`

Inspect the build, package checks, workspace tests, signing, signed-package tests, and archive inspection for both products.
The [macOS release guide](macos-release.md) describes the signing prerequisites and Box Core's evidence.
The [CLI macOS release guide](macos-release-cli.md) describes the CLI's evidence.
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

Omit `--target` to check ARM64. This command checks binary metadata only.

Before the x86-64 package check, the workflow removes the retired `EXPERIMENTAL_LINUX_SUPPORT` and `EXPERIMENTAL_X86_SUPPORT` variables from the environment.
It requires the staged executable to reject a missing configuration, which catches a selected source that still requires an opt-in.
This startup check does not run a workload.

Each Linux build then runs `scripts/smoke-linux-package.py` against its packaged archive on a runner
with the matching CPU architecture. The checks run as a non-root user in the Amazon Linux 2023
container. They start a contained workload and verify file-access and process restrictions without
an experimental opt-in. A failed check stops the build and prevents publication. These checks do not
replace target qualification or verification of the published download.

## Publish

Complete security acceptance and target qualification before approving publication.
Run the same version, source, and `publish_linux_x86` selection from upstream `main` with `dry_run=false` and `skip_tests=false`.
Real releases require macOS signing and signed-package verification, including releases that introduce Linux support.
Box Core's signing job and the CLI's signing job both run in the protected `macos-signing` environment, which only `main` can use.
Approve the signing environment when requested, then approve `release-gate` after the checks pass.
The workflow creates the tag and publishes the verified bundle from that run.
A new run rebuilds the package. Keep the hashes from the publication run.

By default, every release publishes these files, with the selected tag in place of `<tag>`:

| Product | Archive |
|---|---|
| Box Core, macOS (`Box.app`) | `box-<tag>-aarch64-apple-darwin.tar.gz` |
| Box Core, Linux ARM64 | `box-<tag>-linux-arm64.tar.gz` |
| Box Core, Linux x86-64 | `box-<tag>-linux-x86_64.tar.gz` |
| CLI, macOS | `box-cli-<tag>-aarch64-apple-darwin.tar.gz` |
| CLI, Linux ARM64 | `box-cli-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| CLI, Linux x86-64 | `box-cli-<tag>-x86_64-unknown-linux-gnu.tar.gz` |

One `SHA256SUMS.txt` lists every published archive.
`download.sh` reads only Box Core's archives, and `install.sh` reads only the CLI's.

Setting `publish_linux_x86=false` omits both x86-64 archives and their checksum entries.
The x86-64 packages then remain workflow artifacts.
The x86-64 build and package checks run for either setting. A failure blocks publication of every selected archive.

Box Core's Linux release archives use `linux-arm64` and `linux-x86_64` in their names.
The CLI's archives, compilation, and intermediate workflow artifacts retain the Rust targets `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`.
`SHA256SUMS.txt` contains a checksum for each published archive.
Box Core's build jobs display `Linux ARM64`, `Linux x86_64`, or `macOS ARM64`.

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
Verify the reported version, an allowed operation, and a denied operation on each published Linux architecture using the approved test configuration.
Record the release URL, source commit, archive hash, host baseline, commands, and results.

Linux ARM64 and x86-64 startup require no environment opt-in.
A stable version does not establish security acceptance.
