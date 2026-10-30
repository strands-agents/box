# Release Box

Use the `Release Box` workflow in `.github/workflows/deploy-box-artifact.yml`.
Select upstream `main` and pin the product source with the `sha` input.
The source must belong to `main` history for publication.

## Choose a version

Both channels publish macOS Apple silicon and Amazon Linux 2023 ARM64 archives.
The x86_64 Linux build remains a workflow artifact and is not published as a release asset.

| Version input | GitHub release | Latest stable release |
|---|---|---|
| `0.1.1` | Stable | Replaced by this release |
| `0.1.1-linux-preview.1` | Prerelease | Unchanged |

These are examples, not reserved versions. Do not include the leading `v` in the input.
The workflow adds it to the tag and archive names.
The version must make one major, minor, or patch increment from the latest stable tag.
The tag must not already exist. Preview tags do not change the stable version baseline.
There is no separate macOS preview channel; a Linux preview includes the macOS archive too.

## Rehearse

Run the workflow with the selected `version` and `sha`, and these inputs:

- `dry_run=true`
- `sign_macos=true`
- `premerge_signing_test=false`
- `skip_tests=false`

Inspect the build, package checks, workspace tests, signing, signed-package tests, and archive inspection.
The [macOS release guide](macos-release.md) describes the signing prerequisites and evidence.
A dry run with `sign_macos=false` omits signing and signed-package verification.
It does not rehearse all publication prerequisites.

## Publish

Complete security acceptance and target qualification before approving publication.
Run the same version and source from upstream `main` with `dry_run=false` and `skip_tests=false`.
Real releases require macOS signing and signed-package verification, including releases that introduce Linux support.
Approve the protected signing environment when requested, then approve `release-gate` after the checks pass.
The workflow creates the tag and publishes the verified bundle from that run.
A new run rebuilds the package; retain the hashes from the publication run.

Both channels publish these files, with the selected tag in place of `<tag>`:

- `box-<tag>-aarch64-apple-darwin.tar.gz`
- `box-<tag>-aarch64-unknown-linux-gnu.tar.gz`
- `SHA256SUMS.txt`

The final workflow check verifies asset names and prerelease metadata.
It does not download and execute the published Linux package.

## Verify the Linux download

Download the Linux archive and checksum file from the release.
Follow the checksum and extraction commands in its release notes on the qualified Amazon Linux 2023 ARM64 host.
Keep `box`, `strands-box-sock-alias`, and `strands-box-contain-trampoline` together.
Verify the reported version, an allowed operation, and a denied operation using the approved test configuration.
Record the release URL, source commit, archive hash, host baseline, commands, and results.

Linux startup still requires `EXPERIMENTAL_LINUX_SUPPORT=TRUE`.
A stable version does not remove this runtime requirement or establish security acceptance.
Use manual checksum verification and extraction; this workflow change does not add Linux support to `download.sh`.
