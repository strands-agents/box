# Release the macOS CLI

The `Release Box` workflow (`.github/workflows/deploy-box-artifact.yml`) publishes the CLI in the
same release as Box Core. It calls the reusable `CLI release` workflow
(`.github/workflows/cli-release.yml`), which builds the CLI archives for Apple Silicon macOS,
ARM64 Linux, and x86_64 Linux. Each archive contains `box`, both Box Core helpers, shipped
resources, and `release.json`. The `sign-macos` job of `CLI release` signs with the configured Apple
team's Developer ID through the signing service, and notarizes the package with Apple. Default
packages contain native filesystem policy support in a signed app bundle that requests permission
to authorize file operations. Packages built with `native_filesystem_policy=false` contain three
signed programs. Profiles still opt into native enforcement. A real release always signs. A dry
run signs only when you set `sign_macos=true`.

`CLI release` takes the version, the tag, the commit, `native_filesystem_policy`, `sign`, and
whether to bundle the x86_64 Linux archive as inputs. It uploads the release archives as the
`cli-release-bundle` artifact, and its `signed` output is `true` when that bundle holds the
signed, checked macOS package. Every artifact it uploads starts with `cli-`.

[Release Box](releases.md) owns version selection, publication, and the asset list.
[Release signed and notarized macOS builds](macos-release.md) owns Box Core's package and the
`macos-signing` setup that both signing jobs share.

## Run a dry run

Run `Release Box` with `dry_run=true` to build and inspect without publishing.
Select the version as [Choose a version](releases.md#choose-a-version) describes.
The workflow stamps that version into the CLI's Cargo files for the build.

Set `sign_macos=true` to also sign, notarize, and check the package.
The CLI's signing job runs only from `main` of `strands-agents/box`, after a reviewer approves its
`macos-signing` request. Box Core's signing job asks for its own approval in the same run.
A dry run that does not sign inspects the unsigned archive.

## Build experimental native filesystem policy packages

`Release Box` and `CLI release` default `native_filesystem_policy` to `true`. Dry runs,
prereleases, and stable releases compile native filesystem policy support into the Apple Silicon
macOS and ARM64 Linux packages. Set the build input to `false` to produce packages without that
support. The x86_64 Linux job keeps its baseline build and does not include native policy support.

macOS packages require macOS 27 or later, including when native enforcement is off. Builds and
package checks use the `xcode-27` runner, and release binaries target macOS 27. The installer reads `macos_minimum_version`
from the selected archive's checksum-verified `release.json` before executing its programs.
Older archives without that field retain their macOS 15 minimum, so selecting an older
compatible release still works on macOS 15–26. When native support is selected, both the workflow and the
local package script require macOS software development kit (SDK) version 27 or later before they build. They resolve
the SDK named by `SDKROOT`, if set,
or `macosx` from the selected developer tools otherwise. They reject a missing SDK or an invalid
or older version, then export the resolved absolute `SDKROOT` for Cargo. This keeps the SDK check
and Core's C compilation on the same SDK, including when the caller sets `DEVELOPER_DIR`.
The same minimum applies when `native_filesystem_policy=false`. That input omits native support;
it does not select an older macOS baseline.

The option selects the CLI's `strands-box-cli/native-filesystem-policy` Cargo feature. It does
not enable policy enforcement for every run. Each `profile.toml` must still select
[`native-filesystem-policy`](../cli/profiles-reference.md#experimental-native-filesystem-policy),
and its resolved Core version and execution environment must support that selection. Package
inspection and the Linux container smoke check validate baseline packaging, not native policy
enforcement. Every signed native macOS build also checks actual file operations, policy records,
and an unsigned control. These checks fail if the host cannot use Endpoint Security, Apple's API
for authorizing file operations. Signing and notarization alone do not establish that permission.

Each build with native support uploads `cli-native-filesystem-policy-<target>`. Its
`native-filesystem-policy.json` records the explicit Cargo feature flags, source revisions, target,
and SHA-256 hash of the unsigned build archive. The macOS record also includes
`macos_sdk_version`, the SDK version checked and selected for the build. The x86_64 record has an
empty feature list.
The record sets `runtime_qualified` to `false`: it is build evidence, not an enforcement test
result. It stays outside the package, separate from the installation metadata in `release.json`. When `sign_macos=true`, the signing receipt records the signed archive's hash separately.
The existing signing environment and source restrictions still apply. The native signing path
uses the shared [distribution profile](macos-release.md#configure-access). Signing and verification
reject a missing or mismatched profile.

To build an unsigned experimental archive locally on an Apple Silicon Mac, use a new output
directory:

```sh
sh scripts/package_macos.sh --native-filesystem-policy /tmp/box-native-package
```

The script requires committed Cargo files, crates, and resources, and builds the three programs
from the same resolved dependencies. It writes the archive, `SHA256SUMS.txt`, and the feature
record into the output directory. Without `--native-filesystem-policy`, the script keeps the
baseline feature selection and writes only the archive and checksum file. A successful build
still needs separate native runtime validation and signing suitable for that runtime.

## Publish

Run `Release Box` from `main` of `strands-agents/box` with `dry_run=false`, as
[Publish](releases.md#publish) describes.
A reviewer approves each `macos-signing` request under **Review deployments**.
GitHub does not let a person approve their own run.
After both packages are signed, notarized, and checked, approve `release-gate` to publish.
The release job publishes the inspected package without rebuilding it.
A fork cannot sign, so a fork cannot publish a release.

## The package

`box-cli-<tag>-aarch64-apple-darwin.tar.gz` holds:

```text
box
strands-box-sock-alias
strands-box-contain-trampoline
release.json
resources/
```

`release.json` records the version and commit of `box` and of Box Core. Box Core builds from this
repository's `crates/`, so `core_commit` is the release commit. Packaging stops before it builds
when Box Core and its helpers come from different sources, and the release stops before it packages
or publishes.

`SHA256SUMS.txt` holds the checksum of each archive of both products. In `strands-agents/box`,
`box-<tag>-<triple>.tar.gz` names a Box Core archive, so `install.sh` takes only the `box-cli-`
name there. From another repository, it also takes an older `box-v<version>-<triple>.tar.gz` name
when `SHA256SUMS.txt` lists only that. The installer checks signatures and notarization, keeps the
package in a versioned folder, and configures PATH.

The ordinary package has this flat layout. Unpack it into one folder. Box Core finds the helpers
beside `box`, and `box` finds `resources/` beside itself.

Do not unpack it into a folder named `box`. macOS reads a folder as an app bundle if the folder
holds `resources/` and a program with the same name as the folder. The name check ignores case, so
a folder named `Box` is also a problem. In such a folder, `codesign --verify` reports that the
`Info.plist` of `box` is invalid, and macOS stops `box` when it starts. A folder with a
different name, for example `box-cli-v0.3.0-preview.1`, does not have this problem.

Apple cannot staple a notarization ticket to a bare program. A browser gives a downloaded copy the
quarantine attribute. The first time that macOS checks such a copy, it gets the ticket from Apple
online. If the Mac has no network connection at that time, macOS does not start the program. A copy
that `curl` downloads does not get the quarantine attribute, so macOS does not check it.

### Signed experimental native package

A signed native-policy package uses this layout:

```text
box                                      # Launcher
strands-box-sock-alias                    # Link to the bundled helper
strands-box-contain-trampoline            # Link to the bundled helper
resources                                # Link to the bundled resources
release.json                             # Link to the bundled release record
Box.app/
  Contents/
    Info.plist
    embedded.provisionprofile
    CodeResources                         # Attached notarization ticket
    MacOS/
      box
      strands-box-sock-alias
      strands-box-contain-trampoline
    Resources/
      resources/
      release.json
    _CodeSignature/
      CodeResources                       # Signed resource seal
```

The launcher follows the installed `bin/box` and `current` links, then starts the bundled CLI.
The CLI reads resources from `Contents/Resources`, and Core still finds its helpers beside the real
executable. Data files stay outside `Contents/MacOS` so Apple does not treat them as unsigned
nested code. The signing script seals the bundle after adding its profile, helpers, and resources.

The installer accepts only this layout's four exact relative links and fixed launcher. It rejects
links inside the app, links outside the package, and other launcher contents before execution.
It requires the attached notarization ticket at `Box.app/Contents/CodeResources` as a regular file.
It verifies the app and both real helper executables before switching the installed version.
`BOX_ALLOW_UNSIGNED=1` can bypass the installer's Apple checks, but it does not grant native-policy
permission at runtime.

## Identifiers

| Program | Identifier |
| --- | --- |
| `box` | `com.amazon.strands.box` |
| `strands-box-sock-alias`, `strands-box-contain-trampoline` | `com.amazon.strands.box` |

All signing requests use Box Core's application, `com.amazon.strands.box`. The native app request
also selects its authorized distribution profile. The signing service signs each program with the
identifier in its embedded `Info.plist`. `crates/cli/app/build.rs` embeds
`crates/cli/app/Info.plist` in the CLI, and Box Core embeds its own plist in the helpers.

New release verification requires `com.amazon.strands.box` for every program and the native app.
For older-release support and permission effects, see
[Upgrade or choose a version](../cli/install.md#upgrade-or-choose-a-version).
The [signing decision](../design/cli/decisions.md#box-signs-through-box-core) records why the CLI
shares Box Core's identity.

## What a signed run does

1. `Release Box` runs Box Core's tests (`rust-test-lint.yml`) and the CLI's tests
   (`cli-test.yml`) on the release commit. `CLI release`, and so its `sign-macos`, starts only
   after both pass.
2. `build` compiles the three programs for `aarch64-apple-darwin` and packs them with `resources/`
   and `release.json`. It packs with `COPYFILE_DISABLE=1`, so macOS `tar` adds no `._` file for an
   extended attribute. `build` has no AWS credentials.
3. `sign-macos` starts after `build` passes. It runs in the `macos-signing` environment and
   gets temporary credentials for `CD_SIGNER_CALLER_ROLE` through GitHub OIDC.
   `scripts/macos-release-cli.py sign` checks the archive first. It refuses an archive that holds a link,
   a `._` file at any level, or anything other than the three programs, `release.json`, and
   `resources/`. Then it checks the notarization credential with Apple, so a refused credential
   stops the run before any signing request. For an ordinary package, it sends the three programs
   to the signing service in one request and checks each signature. It submits the programs to Apple, waits for `Accepted`,
   and checks the ticket of each program. Last, it packs the signed programs with the unchanged
   `resources/` and `release.json`, under the name of the build's archive.
4. `verify-macos` has no AWS credentials. It unpacks the package into `box-package`, and checks
   each signature and ticket again. It creates a profile from the `claude` starter, which reads the
   shipped packs. Then it runs a box with the signed `box` and the probe profile in
   `test-corpus/profiles/probe`. `crates/cli/app/tests/engine.rs` uses the same profile, so a
   change to that profile also changes this check.
5. `bundle` puts the signed archive in place of the unsigned one, and checks that its SHA-256 hash
   is the one that `sign-macos` recorded. So the release publishes only the archive that
   `sign-macos` signed. A real release stops if `sign-macos` or `verify-macos` fails.
6. `Release Box` writes one `SHA256SUMS.txt` for Box Core's and the CLI's archives and checks the
   asset set. It takes the CLI bundle only when the bundle holds the signed package, or for a dry
   run without `sign_macos=true`.

`sign-macos` and `verify-macos` do not read or write the Actions cache.

### Additional checks for a native macOS package

Before calling the signing service, `sign-macos` checks the unsigned archive against its build
record: source, version, target, native Cargo feature, and SHA-256 hash must agree. It signs the
helpers first, then signs the CLI app with its provisioning profile and Endpoint Security
entitlement. It verifies the profile and signatures, notarizes and staples the app, and packs
the fixed launcher and aliases with it. The receipt binds both archive hashes, source revisions,
features, and package contents to that run.

For a native package, `verify-macos` uses `xcode-27` and requires macOS and SDK version 27 or later.
It starts the package directly as the runner user, matching the Core native verification path.
`verify-macos` receives the signed archive and receipt separately. It compares them with the
workflow's selected source and checks that the extracted files and links match the archive.
It verifies the app's signature, provisioning profile, entitlement, and notarization ticket.
The existing version, shipped-profile creation, and probe checks also run through the launcher.

The workflow then runs `install.sh` against that same signed archive in a temporary home.
Only the download command uses a local substitute, and Apple signature checks remain enabled.
It compares the installed files, modes, and package aliases with the signing receipt. It checks
the public `~/.local/bin/box` link in that home and runs its `--version` command, then passes
the installed release to the native package checker. Installation failures stop the workflow
before native-policy checks. The installation logs and receipt stay in
`macos-package-verification/install`.

The native package checker uses a real file-writing program in the agent, local tool, and
local Model Context Protocol (MCP) server paths. For each path, it checks an allowed write, a
forbidden write, and explicit native-policy opt-out. It requires the expected file bytes and
policy decision records. After a denied MCP tool call, the server must answer another request.
The same unsigned build must refuse selected native execution. Missing authorization or another
prerequisite is a failure, not a skipped success.

The checker keeps commands, outputs, records, package hashes, and a machine-readable report in
`cli-macos-package-verification`. To repeat it on a prepared Mac with Python 3.11 or later:

```sh
python3 scripts/check-native-macos-package.py \
  --package /tmp/signed-native-package \
  --unsigned-package /tmp/unsigned-native-package \
  --evidence /tmp/native-package-check
```

Use a new evidence directory. `--python` can name the canonical Python interpreter for the MCP
fixture. `--baseline-package` adds a separately built ordinary package as a comparison. Turning
the native setting off in the candidate does not count as that separate baseline.

Passing the local Python tests below establishes script behavior with controlled external tools.
A successful protected signing run and successful native package report are still required to
qualify an actual artifact. The workflow does not publish an experimental package as a stable release.

## Linux releases

Each release publishes the CLI's macOS archive and its ARM64 Linux archive. It also publishes the
x86_64 Linux archive when `publish_linux_x86` is `true`, the default. Both Linux architectures
build on every run, so with `publish_linux_x86=false` the x86_64 archive stays a workflow artifact.
A Linux build or package-check failure stops the release.

## Release smoke telemetry

Local package checks use `scripts/smoke_telemetry.py` to copy the caller's
`~/.strands/box/installation.toml` into their temporary home.
They preserve the original file and use the same installation ID as a normal developer run.
Without an existing installation file, the check writes an empty ID to prevent telemetry
capture and continues with the workload.

CI prepares that file from the repository Actions variable `BOX_TEST_INSTALLATION_ID`. Set it
to a lowercase, canonical RFC 4122 UUIDv4 to enable telemetry for package checks. The Linux
release workflow mounts only the prepared file into its container. The macOS workflows prepare
the file before they start their package checks. An unset or empty variable supplies an empty ID.
The CLI owns ID validation. An invalid ID disables
telemetry without failing the package check.

## The `macos-signing` variables

The CLI's `sign-macos` job uses the shared environment described in
[Configure access](macos-release.md#configure-access).

The signing script reads `CD_SIGNER_PROFILE_NAME` for a native-policy package.
The workflow passes the selected value to verification through its `cli_profile_name` output.
CLI packages built with `native_filesystem_policy=false` do not embed a provisioning profile.

For manual native signing or verification, replace `CD_SIGNER_CLI_PROFILE_NAME` with
`CD_SIGNER_PROFILE_NAME` in the process environment. The script no longer reads the legacy variable.

## Keep the evidence

Each signed run keeps two artifacts:

- `cli-macos-signing-evidence`: the signing request and result, the submission to Apple and its log,
  and `receipt.json`, which records the source commit, the package hash, and the submission ID.
- `cli-macos-package-verification`: the signature and ticket checks of the unpacked package, plus
  native runtime commands, records, and results for a signed native package.

A native run also transfers `cli-macos-native-receipt` to the verification job. That job checks the
receipt against the signed archive and the expected source before running the package.

## Run the script on a Mac

The script runs outside CI with AWS credentials that can call the signing service and write the
bucket, `gtar` (`brew install gnu-tar`), and a keychain profile from
`xcrun notarytool store-credentials`.

```sh
python3 -m venv /tmp/signing-venv
/tmp/signing-venv/bin/pip install boto3==1.42.61 requests==2.32.5
export AWS_REGION=<region> CD_SIGNER_ENDPOINT=<endpoint> CD_SIGNER_BUCKET=<bucket> \
  CD_SIGNER_BUCKET_ACCESS_ROLE=<role-arn> CD_SIGNER_TEAM_ID=<team>
/tmp/signing-venv/bin/python scripts/macos-release-cli.py sign \
  --input box-cli-v0.3.0-preview.1-aarch64-apple-darwin.tar.gz \
  --output signed/box-cli-v0.3.0-preview.1-aarch64-apple-darwin.tar.gz --work /tmp/box-signing \
  --version 0.3.0-preview.1 --source-sha "$(git rev-parse HEAD)" --notary-keychain-profile <profile>
```

The input is the archive that the `build` job of `CLI release` uploads. To make one by hand, put
the three programs, `release.json`, and `resources/` at the top level, and pack them with
`COPYFILE_DISABLE=1 tar`. Without the variable, macOS `tar` adds a `._` entry for each extended
attribute, and the script refuses the archive. The script also refuses a version that is not
`X.Y.Z`, `X.Y.Z-preview.N`, or `X.Y.Z-linux-preview.N` with `N` greater than zero, and a source
commit that is not a full SHA.

## How the two signing scripts relate

`scripts/macos-release-cli.py` follows `scripts/macos-release.py`. Ordinary packages use a flat
signing path. The native path follows Core's two-stage helper and app signing approach, with the
shared Box identifier and matching profile. It moves the unchanged resources and release record into the
app's resource directory before sealing it. The code that reads the notarization secret and calls
the signing service and Apple follows Box Core's script. Both jobs use the same notarization secret
and the same signing role, so a change to either one, for example a new field in the secret, needs
the same change in both scripts.

## Test changes to packaging

Run `python3 -m unittest discover -s scripts -p 'test_*.py' -v`.
These tests execute the workflow's shell commands for source selection, release assets, and
installer instructions. They also check the signing jobs of the workflow and test the signing script.
`test_experimental_package.py` executes both feature selections with controlled build tools and
checks release refusal, unchanged payloads, and archive-bound feature records. Those controls do
not compile Rust or prove native enforcement on macOS or Linux.
`test_native_release_workflow.py` checks that the workflow passes the build record, receipt,
expected source, and unsigned control to the native steps. It also checks that the shared profile
setting reaches the signing and verification processes. `test_macos_release_cli.py` checks bundle
construction and refusal of mismatched signing evidence. `test_check_native_macos_package.py`
checks the runtime report assertions. These Python tests require no signing credentials or Rust
build and do not establish that Apple authorizes a real package.
`crates/cli/app/tests/info_plist.rs` checks that the macOS `box` holds the shared Box identifier and its version.
